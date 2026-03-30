/** @file
  Gunyah IoMmu DXE driver — DMA bounce buffers through SHARE'd memory.

  In Gunyah protected VMs:
    LEND'd memory — guest-exclusive, executable, host CANNOT access
    SHARE'd memory (at top of guest RAM) — both guest and host can access, NX

  Both the SHARE'd region base address and size are discovered dynamically
  from the DTB's "restricted-dma-pool" reserved-memory node, which QEMU
  populates based on the user's -m and swiotlb-size settings.

  PCI virtio devices need DMA buffers the host (QEMU) can read/write.
  This driver installs EDKII_IOMMU_PROTOCOL so PciHostBridgeDxe routes
  all PCI DMA through bounce buffers allocated from the SHARE'd region.

  Copyright (c) 2026, Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Pi/PiDxeCis.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/IoMmu.h>

//
// Default SHARE'd region size (128 MB) used as fallback when the DTB
// does not contain a "restricted-dma-pool" node.
//
#define GH_SHARE_SIZE_DEFAULT  0x08000000ULL   // 128 MB

//
// Runtime-discovered SHARE'd region parameters.
// Set in GunyahIoMmuDxeEntryPoint from the DTB before any allocations.
//
STATIC EFI_PHYSICAL_ADDRESS  mShareBase;
STATIC UINT64                mShareSize;
STATIC UINTN                 mSharePages;

//
// Simple bitmap-based page allocator for the SHARE'd pool.
// Each bit represents one 4KB page.  1 = allocated, 0 = free.
// Dynamically allocated based on actual SHARE'd region size.
//
STATIC UINT8  *mBitmap;

//
// MAP_INFO tracks an active DMA mapping for Unmap().
//
#define GH_MAP_INFO_SIGNATURE  SIGNATURE_64 ('G','H','M','A','P','I','N','F')

typedef struct {
  UINT64                    Signature;
  EDKII_IOMMU_OPERATION     Operation;
  UINTN                     NumberOfBytes;
  UINTN                     NumberOfPages;
  EFI_PHYSICAL_ADDRESS      HostAddress;      // Original address (in LEND'd)
  EFI_PHYSICAL_ADDRESS      BounceAddress;    // Bounce buffer (in SHARE'd)
  BOOLEAN                   BounceAllocated;  // TRUE if we allocated the bounce
} GH_MAP_INFO;

//
// ============ Pool allocator ============
//

/**
  Allocate contiguous pages from the SHARE'd memory pool.

  @param[in]  Pages  Number of 4KB pages.

  @return  Physical address of allocation, or 0 on failure.
**/
STATIC
EFI_PHYSICAL_ADDRESS
SharePoolAllocatePages (
  IN UINTN  Pages
  )
{
  UINTN  i;
  UINTN  j;

  if ((Pages == 0) || (Pages > mSharePages)) {
    return 0;
  }

  //
  // First-fit search.
  //
  for (i = 0; i <= mSharePages - Pages; i++) {
    BOOLEAN  Found = TRUE;

    for (j = 0; j < Pages; j++) {
      if (mBitmap[(i + j) / 8] & (1U << ((i + j) % 8))) {
        Found = FALSE;
        i    += j;   // skip ahead past this occupied page
        break;
      }
    }

    if (Found) {
      for (j = 0; j < Pages; j++) {
        mBitmap[(i + j) / 8] |= (1U << ((i + j) % 8));
      }

      DEBUG ((
        DEBUG_VERBOSE,
        "GH-IoMmu: pool alloc %u pages @ 0x%lx\n",
        (UINT32)Pages,
        mShareBase + i * EFI_PAGE_SIZE
        ));
      return mShareBase + (UINT64)i * EFI_PAGE_SIZE;
    }
  }

  DEBUG ((DEBUG_ERROR, "GH-IoMmu: pool exhausted (wanted %u pages)\n", (UINT32)Pages));
  return 0;
}

/**
  Free pages back to the SHARE'd memory pool.

  @param[in]  Address  Physical address returned by SharePoolAllocatePages.
  @param[in]  Pages    Number of pages to free.
**/
STATIC
VOID
SharePoolFreePages (
  IN EFI_PHYSICAL_ADDRESS  Address,
  IN UINTN                 Pages
  )
{
  UINTN  Start;
  UINTN  j;

  if ((Address < mShareBase) ||
      (Address >= mShareBase + mShareSize))
  {
    DEBUG ((DEBUG_ERROR, "GH-IoMmu: free 0x%lx — not in SHARE'd pool!\n", Address));
    return;
  }

  Start = (UINTN)((Address - mShareBase) / EFI_PAGE_SIZE);

  for (j = 0; j < Pages; j++) {
    mBitmap[(Start + j) / 8] &= ~(1U << ((Start + j) % 8));
  }

  DEBUG ((
    DEBUG_VERBOSE,
    "GH-IoMmu: pool free  %u pages @ 0x%lx\n",
    (UINT32)Pages,
    Address
    ));
}

//
// ============ EDKII_IOMMU_PROTOCOL implementation ============
//

/**
  Set IOMMU attribute — no-op for Gunyah (no per-device IOMMU hardware).
**/
STATIC
EFI_STATUS
EFIAPI
GunyahIoMmuSetAttribute (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN EFI_HANDLE            DeviceHandle,
  IN VOID                  *Mapping,
  IN UINT64                IoMmuAccess
  )
{
  return EFI_SUCCESS;
}

/**
  Map — allocate a bounce buffer in SHARE'd memory and (for reads) copy data.

  BusMasterRead:         device reads from memory -> copy host->bounce
  BusMasterWrite:        device writes to memory  -> just allocate bounce
  BusMasterCommonBuffer: both sides access same buffer
                         -> HostAddress must already be in SHARE'd (from AllocateBuffer)
**/
STATIC
EFI_STATUS
EFIAPI
GunyahIoMmuMap (
  IN     EDKII_IOMMU_PROTOCOL  *This,
  IN     EDKII_IOMMU_OPERATION  Operation,
  IN     VOID                   *HostAddress,
  IN OUT UINTN                  *NumberOfBytes,
  OUT    EFI_PHYSICAL_ADDRESS   *DeviceAddress,
  OUT    VOID                   **Mapping
  )
{
  GH_MAP_INFO             *MapInfo;
  EFI_PHYSICAL_ADDRESS     BounceAddr;
  UINTN                    Pages;
  EFI_PHYSICAL_ADDRESS     HostPhys;

  if ((HostAddress == NULL) || (NumberOfBytes == NULL) ||
      (DeviceAddress == NULL) || (Mapping == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  HostPhys = (EFI_PHYSICAL_ADDRESS)(UINTN)HostAddress;

  //
  // If HostAddress is already in the SHARE'd region, no bounce needed.
  // This happens for CommonBuffer allocations from AllocateBuffer().
  //
  if ((HostPhys >= mShareBase) &&
      (HostPhys < mShareBase + mShareSize))
  {
    MapInfo = AllocateZeroPool (sizeof *MapInfo);
    if (MapInfo == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    MapInfo->Signature      = GH_MAP_INFO_SIGNATURE;
    MapInfo->Operation      = Operation;
    MapInfo->NumberOfBytes   = *NumberOfBytes;
    MapInfo->NumberOfPages   = 0;
    MapInfo->HostAddress     = HostPhys;
    MapInfo->BounceAddress   = HostPhys;  // same — already in SHARE'd
    MapInfo->BounceAllocated = FALSE;

    *DeviceAddress = HostPhys;
    *Mapping       = MapInfo;

    DEBUG ((
      DEBUG_VERBOSE,
      "GH-IoMmu: Map (already SHARE'd) host=0x%lx dev=0x%lx bytes=%u\n",
      HostPhys,
      *DeviceAddress,
      (UINT32)*NumberOfBytes
      ));
    return EFI_SUCCESS;
  }

  //
  // HostAddress is in LEND'd memory — need bounce buffer in SHARE'd.
  //
  Pages     = EFI_SIZE_TO_PAGES (*NumberOfBytes);
  BounceAddr = SharePoolAllocatePages (Pages);
  if (BounceAddr == 0) {
    return EFI_OUT_OF_RESOURCES;
  }

  MapInfo = AllocateZeroPool (sizeof *MapInfo);
  if (MapInfo == NULL) {
    SharePoolFreePages (BounceAddr, Pages);
    return EFI_OUT_OF_RESOURCES;
  }

  MapInfo->Signature      = GH_MAP_INFO_SIGNATURE;
  MapInfo->Operation      = Operation;
  MapInfo->NumberOfBytes   = *NumberOfBytes;
  MapInfo->NumberOfPages   = Pages;
  MapInfo->HostAddress     = HostPhys;
  MapInfo->BounceAddress   = BounceAddr;
  MapInfo->BounceAllocated = TRUE;

  //
  // For BusMasterRead (device reads from memory), copy data to bounce now.
  // For BusMasterWrite (device writes to memory), zero the bounce buffer.
  // For CommonBuffer, copy data so device sees current state.
  //
  switch (Operation) {
    case EdkiiIoMmuOperationBusMasterRead:
    case EdkiiIoMmuOperationBusMasterRead64:
      CopyMem ((VOID *)(UINTN)BounceAddr, HostAddress, *NumberOfBytes);
      break;

    case EdkiiIoMmuOperationBusMasterWrite:
    case EdkiiIoMmuOperationBusMasterWrite64:
      ZeroMem ((VOID *)(UINTN)BounceAddr, EFI_PAGES_TO_SIZE (Pages));
      break;

    case EdkiiIoMmuOperationBusMasterCommonBuffer:
    case EdkiiIoMmuOperationBusMasterCommonBuffer64:
      CopyMem ((VOID *)(UINTN)BounceAddr, HostAddress, *NumberOfBytes);
      break;

    default:
      SharePoolFreePages (BounceAddr, Pages);
      FreePool (MapInfo);
      return EFI_INVALID_PARAMETER;
  }

  *DeviceAddress = BounceAddr;
  *Mapping       = MapInfo;

  DEBUG ((
    DEBUG_VERBOSE,
    "GH-IoMmu: Map op=%d host=0x%lx → bounce=0x%lx bytes=%u pages=%u\n",
    (INT32)Operation,
    HostPhys,
    BounceAddr,
    (UINT32)*NumberOfBytes,
    (UINT32)Pages
    ));

  return EFI_SUCCESS;
}

/**
  Unmap — for device-writes, copy bounce data back; then free bounce buffer.
**/
STATIC
EFI_STATUS
EFIAPI
GunyahIoMmuUnmap (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN VOID                   *Mapping
  )
{
  GH_MAP_INFO  *MapInfo;

  if (Mapping == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  MapInfo = (GH_MAP_INFO *)Mapping;
  if (MapInfo->Signature != GH_MAP_INFO_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  if (MapInfo->BounceAllocated) {
    //
    // Copy data back from bounce for write & common-buffer operations.
    //
    switch (MapInfo->Operation) {
      case EdkiiIoMmuOperationBusMasterWrite:
      case EdkiiIoMmuOperationBusMasterWrite64:
      case EdkiiIoMmuOperationBusMasterCommonBuffer:
      case EdkiiIoMmuOperationBusMasterCommonBuffer64:
        CopyMem (
          (VOID *)(UINTN)MapInfo->HostAddress,
          (VOID *)(UINTN)MapInfo->BounceAddress,
          MapInfo->NumberOfBytes
          );
        break;

      default:
        break;
    }

    SharePoolFreePages (MapInfo->BounceAddress, MapInfo->NumberOfPages);

    DEBUG ((
      DEBUG_VERBOSE,
      "GH-IoMmu: Unmap bounce=0x%lx → host=0x%lx bytes=%u\n",
      MapInfo->BounceAddress,
      MapInfo->HostAddress,
      (UINT32)MapInfo->NumberOfBytes
      ));
  }

  ZeroMem (MapInfo, sizeof *MapInfo);
  FreePool (MapInfo);
  return EFI_SUCCESS;
}

/**
  AllocateBuffer — allocate DMA-safe memory from the SHARE'd pool.
**/
STATIC
EFI_STATUS
EFIAPI
GunyahIoMmuAllocateBuffer (
  IN     EDKII_IOMMU_PROTOCOL  *This,
  IN     EFI_ALLOCATE_TYPE      Type,
  IN     EFI_MEMORY_TYPE        MemoryType,
  IN     UINTN                  Pages,
  IN OUT VOID                   **HostAddress,
  IN     UINT64                 Attributes
  )
{
  EFI_PHYSICAL_ADDRESS  Addr;

  if (HostAddress == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Addr = SharePoolAllocatePages (Pages);
  if (Addr == 0) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem ((VOID *)(UINTN)Addr, EFI_PAGES_TO_SIZE (Pages));
  *HostAddress = (VOID *)(UINTN)Addr;

  DEBUG ((
    DEBUG_VERBOSE,
    "GH-IoMmu: AllocateBuffer %u pages @ 0x%lx\n",
    (UINT32)Pages,
    Addr
    ));

  return EFI_SUCCESS;
}

/**
  FreeBuffer — return pages to the SHARE'd pool.
**/
STATIC
EFI_STATUS
EFIAPI
GunyahIoMmuFreeBuffer (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN UINTN                  Pages,
  IN VOID                   *HostAddress
  )
{
  if (HostAddress == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  SharePoolFreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)HostAddress, Pages);
  return EFI_SUCCESS;
}

//
// Protocol instance
//
STATIC EDKII_IOMMU_PROTOCOL  mGunyahIoMmu = {
  EDKII_IOMMU_PROTOCOL_REVISION,
  GunyahIoMmuSetAttribute,
  GunyahIoMmuMap,
  GunyahIoMmuUnmap,
  GunyahIoMmuAllocateBuffer,
  GunyahIoMmuFreeBuffer,
};

/**
  Entry point — install the IOMMU protocol.
**/
EFI_STATUS
EFIAPI
GunyahIoMmuDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           Handle;
  UINTN                BitmapBytes;
  VOID                 *DeviceTreeBase;
  INT32                Node;
  INT32                Prev;

  //
  // Discover the SHARE'd region from the DTB's "restricted-dma-pool" node.
  // We parse the DTB directly (like the PEI constructor) instead of using
  // FdtClient protocol. This allows [Depex] TRUE so we load BEFORE
  // HighMemDxe and claim the SHARE'd region first.
  //
  mShareBase  = 0;
  mShareSize  = 0;

  //
  // Get the DTB from the HOB (same source FdtClientDxe uses).
  // The PEI phase copies the DTB and stores its address in gFdtHobGuid.
  //
  {
    VOID  *Hob;
    Hob = GetFirstGuidHob (&gFdtHobGuid);
    if ((Hob != NULL) && (GET_GUID_HOB_DATA_SIZE (Hob) == sizeof (UINT64))) {
      DeviceTreeBase = (VOID *)(UINTN)*(UINT64 *)GET_GUID_HOB_DATA (Hob);
    } else {
      DeviceTreeBase = NULL;
    }
  }

  if ((DeviceTreeBase != NULL) && (FdtCheckHeader (DeviceTreeBase) == 0)) {
    for (Prev = 0; ; Prev = Node) {
      Node = FdtNextNode (DeviceTreeBase, Prev, NULL);
      if (Node < 0) {
        break;
      }

      {
        CONST CHAR8   *Compat;
        INT32          CompatLen;
        CONST UINT64  *DmaReg;
        INT32          DmaRegLen;

        Compat = FdtGetProp (DeviceTreeBase, Node, "compatible", &CompatLen);
        if ((Compat != NULL) && (AsciiStrCmp (Compat, "restricted-dma-pool") == 0)) {
          DmaReg = FdtGetProp (DeviceTreeBase, Node, "reg", &DmaRegLen);
          if ((DmaReg != NULL) && (DmaRegLen >= (INT32)(2 * sizeof (UINT64)))) {
            mShareBase = Fdt64ToCpu (ReadUnaligned64 (DmaReg));
            mShareSize = Fdt64ToCpu (ReadUnaligned64 (DmaReg + 1));
            DEBUG ((
              DEBUG_INFO,
              "GH-IoMmu: DTB restricted-dma-pool @ 0x%lx size 0x%lx\n",
              (UINT64)mShareBase,
              (UINT64)mShareSize
              ));
          }

          break;
        }
      }
    }
  }

  if ((mShareBase == 0) || (mShareSize == 0)) {
    DEBUG ((DEBUG_WARN, "GH-IoMmu: restricted-dma-pool not found, using PCD fallback\n"));
    mShareBase  = PcdGet64 (PcdSystemMemoryBase) + PcdGet64 (PcdSystemMemorySize);
    mShareSize  = GH_SHARE_SIZE_DEFAULT;
  }

  mSharePages = (UINTN)(mShareSize / EFI_PAGE_SIZE);

  //
  // Allocate the bitmap for the page allocator.
  // Each bit represents one 4KB page.
  //
  BitmapBytes = (mSharePages + 7) / 8;
  mBitmap = AllocateZeroPool (BitmapBytes);
  if (mBitmap == NULL) {
    DEBUG ((DEBUG_ERROR, "GH-IoMmu: failed to allocate bitmap (%u bytes)\n", (UINT32)BitmapBytes));
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((
    DEBUG_INFO,
    "GH-IoMmu: SHARE'd pool at 0x%lx, size 0x%lx (%u pages)\n",
    (UINT64)mShareBase,
    (UINT64)mShareSize,
    (UINT32)mSharePages
    ));

  //
  // Add the SHARE'd region to GCD and set page table attributes.
  // With [Depex] TRUE we load before HighMemDxe, so this should succeed.
  //
  Status = gDS->AddMemorySpace (
                  EfiGcdMemoryTypeSystemMemory,
                  mShareBase,
                  mShareSize,
                  EFI_MEMORY_WB | EFI_MEMORY_XP
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "GH-IoMmu: AddMemorySpace failed: %r (may already exist)\n", Status));
  }

  Status = gDS->SetMemorySpaceAttributes (
                  mShareBase,
                  mShareSize,
                  EFI_MEMORY_WB | EFI_MEMORY_XP
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GH-IoMmu: SetMemorySpaceAttributes failed: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "GH-IoMmu: page tables created for SHARE'd region\n"));

  //
  // Mark the SHARE'd region as Reserved so the general-purpose page
  // allocator never hands out pages from it.  Under Gunyah, SHARE'd
  // memory is non-executable (lend=0), so code loaded here would
  // cause a silent page fault.  Only GunyahIoMmuDxe's internal bitmap
  // allocator should hand out pages from this pool (for DMA bounce
  // buffers).
  //
  {
    EFI_PHYSICAL_ADDRESS  ResvAddr = mShareBase;
    Status = gBS->AllocatePages (
                    AllocateAddress,
                    EfiReservedMemoryType,
                    mSharePages,
                    &ResvAddr
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "GH-IoMmu: failed to reserve SHARE'd pool: %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "GH-IoMmu: SHARE'd pool reserved (%u pages)\n",
              (UINT32)mSharePages));
    }
  }

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEdkiiIoMmuProtocolGuid,
                  &mGunyahIoMmu,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GH-IoMmu: install protocol failed: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "GH-IoMmu: EDKII_IOMMU_PROTOCOL installed\n"));
  return EFI_SUCCESS;
}
