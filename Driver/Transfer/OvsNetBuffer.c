/*
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "OvsNetBuffer.h"
#include "Frame.h"
#include "PacketInfo.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "NblsIngress.h"
#include "SendIngressBasic.h"
#include "Checksum.h"
#include "Tcp.h"
#include "Udp.h"
#include "Nbls.h"

extern NDIS_HANDLE g_ndisFilterHandle;

extern NDIS_HANDLE g_hNblPool;
extern NDIS_HANDLE g_hNbPool;

extern NDIS_SPIN_LOCK g_nbPoolLock;

BOOLEAN NblIsLso(_In_ NET_BUFFER_LIST* pNbl)
{
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO* pLsoInfo = NULL;
    OVS_CHECK(pNbl);

    //break the first time we have an LSO NBL. Just to see it happen.

    pLsoInfo = (NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO*)&
        (NET_BUFFER_LIST_INFO(pNbl, TcpLargeSendNetBufferListInfo));

    if (pLsoInfo->Value)
    {
        OVS_CHECK(0);
        if (pLsoInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE ||
            pLsoInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE)
        {
            return TRUE;
        }
        else
        {
            //TODO: if there is no LSO, should NET_BUFFER_LIST_INFO return a NULL ptr or set some invalid value?
            OVS_CHECK(0);
        }
    }
    else
    {
        return FALSE;//no LSO
    }

    return FALSE;
}

_Use_decl_annotations_
VOID ONB_DestroyNbl(OVS_NET_BUFFER* pOvsNb)
{
    MDL* pMdl = NULL;
    VOID* buffer = NULL, *onbBuffer = NULL;
    NET_BUFFER* pNb = NULL;
    ULONG dataOffset = 0;

    pOvsNb->pSwitchInfo->switchHandlers.FreeNetBufferListForwardingContext(pOvsNb->pSwitchInfo->switchContext, pOvsNb->pNbl);

    pNb = ONB_GetNetBuffer(pOvsNb);
    onbBuffer = ONB_GetData(pOvsNb);

    pMdl = NET_BUFFER_CURRENT_MDL(pNb);
    dataOffset = ONB_GetDataOffset(pOvsNb);

    buffer = MmGetMdlVirtualAddress(pMdl);
    OVS_CHECK((BYTE*)buffer == (BYTE*)onbBuffer - dataOffset);
    KFree(buffer);

    IoFreeMdl(pMdl);
    NdisFreeNetBuffer(pNb);

    NdisFreeNetBufferList(pOvsNb->pNbl);
    pOvsNb->pNbl = NULL;
}

_Use_decl_annotations_
void ONB_Destroy(const OVS_SWITCH_INFO* pSwitchInfo, OVS_NET_BUFFER** ppOvsNb)
{
    MDL* pMdl = NULL;
    OVS_NET_BUFFER* pOvsNb = *ppOvsNb;
    VOID* buffer = NULL, *onbBuffer = NULL;
    NET_BUFFER* pNb = NULL;
    ULONG dataOffset = 0;

    pSwitchInfo->switchHandlers.FreeNetBufferListForwardingContext(pSwitchInfo->switchContext, pOvsNb->pNbl);

    OVS_CHECK(NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl)->Next == NULL);

    pNb = ONB_GetNetBuffer(pOvsNb);
    onbBuffer = ONB_GetData(pOvsNb);

    pMdl = NET_BUFFER_CURRENT_MDL(pNb);
    dataOffset = ONB_GetDataOffset(pOvsNb);

    buffer = MmGetMdlVirtualAddress(pMdl);
    OVS_CHECK((BYTE*)buffer == (BYTE*)onbBuffer - dataOffset);
    KFree(buffer);

    IoFreeMdl(pMdl);
    NdisFreeNetBuffer(pNb);

    NdisFreeNetBufferList(pOvsNb->pNbl);

    pOvsNb->pActions = NULL;
    pOvsNb->pOriginalPacketInfo = NULL;
    pOvsNb->pTunnelInfo = NULL;

    pOvsNb->packetPriority = pOvsNb->packetMark = 0;

    KFree(pOvsNb);

    *ppOvsNb = NULL;
}

_Use_decl_annotations_
OVS_NET_BUFFER* ONB_CreateFromNbAndNbl(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl, NET_BUFFER* pNb, ULONG addSize)
{
    ULONG nbLen = 0;
    USHORT contextSize = NET_BUFFER_LIST_CONTEXT_DATA_SIZE(pNbl);
    NET_BUFFER_LIST* pDuplicateNbl = NULL;
    NET_BUFFER* pDuplicateNb = NULL;
    VOID* pSrcNbBuffer = NULL, *pResBuffer = NULL;
    NDIS_STATUS status = 0;
    BYTE* pDestBuffer = NULL;
    MDL* pDuplicateMdl = NULL;
    OVS_NET_BUFFER* pOvsNetBuffer = NULL;

    //"The ContextSize must be a multiple of the value defined by MEMORY_ALLOCATION_ALIGNMENT"
    if (contextSize % MEMORY_ALLOCATION_ALIGNMENT != 0)
    {
        contextSize = (contextSize / MEMORY_ALLOCATION_ALIGNMENT) * MEMORY_ALLOCATION_ALIGNMENT + MEMORY_ALLOCATION_ALIGNMENT;
    }

    //1. Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pDuplicateNbl)
    {
        return NULL;
    }

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    nbLen = NET_BUFFER_DATA_LENGTH(pNb);
    pDestBuffer = KAlloc(nbLen + addSize);
    OVS_CHECK(pDestBuffer);

    //3. Allocate MDL
    pDuplicateMdl = IoAllocateMdl(pDestBuffer, nbLen + addSize, FALSE, FALSE, NULL);
    OVS_CHECK(pDuplicateMdl);
    MmBuildMdlForNonPagedPool(pDuplicateMdl);
    OVS_CHECK(pDestBuffer == MmGetMdlVirtualAddress(pDuplicateMdl));

    //4. Allocate / Create NB
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNb = NdisAllocateNetBuffer(g_hNbPool, pDuplicateMdl, addSize, nbLen);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pDuplicateNb)
    {
        return NULL;
    }

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pDuplicateNb;

    //6. Copy the pNb buffer into the pDuplicateNb buffer.
    pSrcNbBuffer = NdisGetDataBuffer(pNb, nbLen, NULL, 1, 0);
    if (!pSrcNbBuffer)
    {
        pSrcNbBuffer = KAlloc(nbLen);
        OVS_CHECK(pSrcNbBuffer);

        pResBuffer = NdisGetDataBuffer(pNb, nbLen, pSrcNbBuffer, 1, 0);
        if (!pResBuffer)
        {
            return NULL;
        }

        OVS_CHECK(pSrcNbBuffer == pResBuffer);
    }

    if (!pSrcNbBuffer)
    {
        return NULL;
    }

    RtlCopyMemory(pDestBuffer + addSize, pSrcNbBuffer, nbLen);

    KFree(pResBuffer);

    //7. Set the rest of NBL stuff
    pDuplicateNbl->SourceHandle = pSwitchInfo->filterHandle;

    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
        return FALSE;
    }

    status = pSwitchInfo->switchHandlers.CopyNetBufferListInfo(pSwitchInfo->switchContext, pDuplicateNbl, pNbl, 0);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
        return FALSE;
    }

    //8. Create the OVS_NET_BUFFER
    pOvsNetBuffer = KAlloc(sizeof(OVS_NET_BUFFER));
    if (!pOvsNetBuffer)
    {
        OVS_CHECK(pOvsNetBuffer);
        return FALSE;
    }

    RtlZeroMemory(pOvsNetBuffer, sizeof(OVS_NET_BUFFER));

    pOvsNetBuffer->packetMark = pOvsNetBuffer->packetPriority = 0;

    pOvsNetBuffer->pNbl = pDuplicateNbl;
    pOvsNetBuffer->pSwitchInfo = (OVS_SWITCH_INFO*)pSwitchInfo;

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    pSrcNbBuffer = NdisGetDataBuffer(pDuplicateNb, nbLen, NULL, 1, 0);
    OVS_CHECK(pSrcNbBuffer);

    if (!pSrcNbBuffer)
    {
        return NULL;
    }

    return pOvsNetBuffer;
}

_Use_decl_annotations_
OVS_NET_BUFFER* ONB_Duplicate(const OVS_NET_BUFFER* pOriginalOnb)
{
    OVS_NET_BUFFER* pDuplicateOnb = NULL;

    pDuplicateOnb = ONB_CreateFromNbAndNbl(pOriginalOnb->pSwitchInfo, pOriginalOnb->pNbl, pOriginalOnb->pNbl->FirstNetBuffer, pOriginalOnb->pNbl->FirstNetBuffer->DataOffset);
    if (!pDuplicateOnb)
    {
        return NULL;
    }

    pDuplicateOnb->packetMark = pOriginalOnb->packetMark;
    pDuplicateOnb->packetPriority = pOriginalOnb->packetPriority;

    pDuplicateOnb->pActions = pOriginalOnb->pActions;
    pDuplicateOnb->pOriginalPacketInfo = pOriginalOnb->pOriginalPacketInfo;
    pDuplicateOnb->pTunnelInfo = pOriginalOnb->pTunnelInfo;
    //pSource can be shared: it is used as a ptr to a local variable
    pDuplicateOnb->pSourceNic = pOriginalOnb->pSourceNic;
    pDuplicateOnb->pSourcePort = pOriginalOnb->pSourcePort;

    return pDuplicateOnb;
}

OVS_NET_BUFFER* ONB_CreateFromBuffer(_In_ const OVS_BUFFER* pBuffer, ULONG addSize)
{
    ULONG nbLen = 0;
    USHORT contextSize = MEMORY_ALLOCATION_ALIGNMENT;
    NET_BUFFER_LIST* pDuplicateNbl = NULL;
    NET_BUFFER* pDuplicateNb = NULL;
    NDIS_STATUS status = 0;
    BYTE* pDestBuffer = NULL;
    MDL* pDuplicateMdl = NULL;
    OVS_NET_BUFFER* pOvsNetBuffer = NULL;
    VOID* buffer = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN ok = TRUE;

    OVS_CHECK(pBuffer);
    OVS_CHECK(pBuffer->p);
    OVS_CHECK(pBuffer->size);
    OVS_CHECK(!pBuffer->offset);

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        return NULL;
    }

    //1. Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pDuplicateNbl);
    if (!pDuplicateNbl)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    nbLen = pBuffer->size;
    pDestBuffer = KAlloc(nbLen + addSize);
    OVS_CHECK(pDestBuffer);

    //3. Allocate MDL
    pDuplicateMdl = IoAllocateMdl(pDestBuffer, nbLen + addSize, FALSE, FALSE, NULL);
    OVS_CHECK(pDuplicateMdl);
    MmBuildMdlForNonPagedPool(pDuplicateMdl);
    OVS_CHECK(pDestBuffer == MmGetMdlVirtualAddress(pDuplicateMdl));

    //4. Allocate / Create NB
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNb = NdisAllocateNetBuffer(g_hNbPool, pDuplicateMdl, addSize, nbLen);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pDuplicateNb)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pDuplicateNb;

    //6. Copy the pNb buffer into the pDuplicateNb buffer.

    RtlCopyMemory(pDestBuffer + addSize, pBuffer->p, nbLen);

    //7. Set the rest of NBL stuff
    //TODO: must lock
    pDuplicateNbl->SourceHandle = pSwitchInfo->filterHandle;

    //TODO: must lock g_pSwitchInfo
    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

    //8. Create the OVS_NET_BUFFER
    pOvsNetBuffer = KAlloc(sizeof(OVS_NET_BUFFER));
    if (!pOvsNetBuffer)
    {
        ok = FALSE;
        goto Cleanup;
    }

    RtlZeroMemory(pOvsNetBuffer, sizeof(OVS_NET_BUFFER));

    pOvsNetBuffer->packetMark = pOvsNetBuffer->packetPriority = 0;

    pOvsNetBuffer->pNbl = pDuplicateNbl;

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    buffer = NdisGetDataBuffer(pDuplicateNb, nbLen, NULL, 1, 0);
    OVS_CHECK(buffer);

Cleanup:
    if (pSwitchInfo)
    {
        OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);
    }

    if (!ok)
    {
        //TODO: cleanup pOvsNetBuffer, pDuplicateNbl, pDuplicateNb, pDuplicateMdl, pDestBuffer
    }

    return (ok ? pOvsNetBuffer : NULL);
}

OVS_NET_BUFFER* ONB_Create(ULONG bufSize)
{
    USHORT contextSize = MEMORY_ALLOCATION_ALIGNMENT;
    NET_BUFFER_LIST* pDuplicateNbl = NULL;
    NET_BUFFER* pDuplicateNb = NULL;
    NDIS_STATUS status = 0;
    BYTE* pDestBuffer = NULL;
    MDL* pDuplicateMdl = NULL;
    OVS_NET_BUFFER* pOvsNetBuffer = NULL;
    VOID* buffer = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN ok = TRUE;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        return NULL;
    }

    //1. Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pDuplicateNbl);

    if (!pDuplicateNbl)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    pDestBuffer = KAlloc(bufSize);
    OVS_CHECK(pDestBuffer);

    //3. Allocate MDL
    pDuplicateMdl = IoAllocateMdl(pDestBuffer, bufSize, FALSE, FALSE, NULL);
    OVS_CHECK(pDuplicateMdl);
    MmBuildMdlForNonPagedPool(pDuplicateMdl);
    OVS_CHECK(pDestBuffer == MmGetMdlVirtualAddress(pDuplicateMdl));

    //4. Allocate / Create NB
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNb = NdisAllocateNetBuffer(g_hNbPool, pDuplicateMdl, 0, bufSize);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pDuplicateNb)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pDuplicateNb;

    //6. Set the rest of NBL stuff
    //TODO: must lock
    pDuplicateNbl->SourceHandle = pSwitchInfo->filterHandle;

    //TODO: must lock g_pSwitchInfo
    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

    //7. Create the OVS_NET_BUFFER
    pOvsNetBuffer = KAlloc(sizeof(OVS_NET_BUFFER));
    if (!pOvsNetBuffer)
    {
        ok = FALSE;
        goto Cleanup;
    }

    RtlZeroMemory(pOvsNetBuffer, sizeof(OVS_NET_BUFFER));

    pOvsNetBuffer->packetMark = pOvsNetBuffer->packetPriority = 0;

    pOvsNetBuffer->pNbl = pDuplicateNbl;

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    buffer = NdisGetDataBuffer(pDuplicateNb, bufSize, NULL, 1, 0);
    OVS_CHECK(buffer);

Cleanup:
    if (pSwitchInfo)
    {
        OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);
    }

    if (!ok)
    {
        //TODO: cleanup pOvsNetBuffer, pDuplicateNbl, pDuplicateNb, pDuplicateMdl, pDestBuffer
    }

    return pOvsNetBuffer;
}

NET_BUFFER* ONB_CreateNb(ULONG dataLen, ULONG dataOffset)
{
    NET_BUFFER* pDuplicateNb = NULL;
    BYTE* pDestBuffer = NULL;
    MDL* pDuplicateMdl = NULL;
    VOID* buffer = NULL;

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    pDestBuffer = KAlloc(dataLen + dataOffset);
    OVS_CHECK(pDestBuffer);

    //3. Allocate MDL
    pDuplicateMdl = IoAllocateMdl(pDestBuffer, dataLen + dataOffset, FALSE, FALSE, NULL);
    OVS_CHECK(pDuplicateMdl);
    MmBuildMdlForNonPagedPool(pDuplicateMdl);
    OVS_CHECK(pDestBuffer == MmGetMdlVirtualAddress(pDuplicateMdl));

    //4. Allocate / Create NB
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNb = NdisAllocateNetBuffer(g_hNbPool, pDuplicateMdl, dataOffset, dataLen);
    NdisReleaseSpinLock(&g_nbPoolLock);

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    buffer = NdisGetDataBuffer(pDuplicateNb, dataLen, NULL, 1, 0);
    OVS_CHECK(buffer);
    if (!buffer)
    {
        return NULL;
    }

    DEBUGP(LOG_INFO, "nb: %p; mdl: %p; buf: %p\n", pDuplicateNb, pDuplicateMdl, pDestBuffer);

    return pDuplicateNb;
}

NET_BUFFER_LIST* ONB_CreateNblFromNb(_In_ NET_BUFFER* pNb, USHORT contextSize)
{
    NET_BUFFER_LIST* pNbl = NULL;
    NDIS_STATUS status = STATUS_SUCCESS;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        return NULL;
    }

    OVS_CHECK(pNb);

    //Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, /*backfill*/contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pNbl);

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pNbl) = pNb;

    //6. Set the rest of NBL stuff
    //TODO: must lock
    pNbl->SourceHandle = pSwitchInfo->filterHandle;

    //TODO: must lock g_pSwitchInfo
    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

//Cleanup:
    if (pSwitchInfo)
    {
        OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);
    }

    return pNbl;
}

_Use_decl_annotations_
BOOLEAN ONB_OriginateIcmpPacket_Ipv4_Type3Code4(OVS_NET_BUFFER* pOvsNb, ULONG mtu, OVS_NIC_INFO* pDestinationNic)
{
    OVS_NET_BUFFER* pIcmpPacket = NULL;
    OVS_NBL_FAIL_REASON failReason = { 0 };
    BOOLEAN mustTransfer = FALSE;
    BYTE* originalBuffer = NULL, *newBuffer = NULL;
    OVS_ETHERNET_HEADER* pOriginalEthHeader = NULL, *pNewEthHeader = NULL;
    OVS_IPV4_HEADER* pOriginalIpv4Header = NULL, *pNewIpv4Header = NULL, *pAttachedIpv4Header = NULL;
    OVS_ICMP_MESSAGE_DEST_UNREACH* pIcmpHeader = NULL;
    ULONG ethSize = 0;
    LE16 ethType = 0;
    const BYTE* pOriginalTpLayer = NULL;
    BYTE* pNewTpLayer = NULL;
    ULONG icmpHeaderSize = 0;

    ULONG bufSize = sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_IPV4_HEADER) + OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE + 8;

    OVS_CHECK(pDestinationNic);

    originalBuffer = ONB_GetData(pOvsNb);
    pOriginalEthHeader = GetEthernetHeader(originalBuffer, &ethSize);
    ethType = ReadEthernetType(pOriginalEthHeader);
    pOriginalIpv4Header = AdvanceEthernetHeader((OVS_ETHERNET_HEADER*)originalBuffer, ethSize);

    bufSize += pOriginalIpv4Header->HeaderLength * sizeof(DWORD);

    OVS_CHECK(pOriginalEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4));

    pIcmpPacket = ONB_Create(bufSize);
    newBuffer = ONB_GetData(pIcmpPacket);

    //1. fill eth
    pNewEthHeader = (OVS_ETHERNET_HEADER*)newBuffer;
    pNewEthHeader->type = RtlUshortByteSwap(ethType);
    RtlCopyMemory(pNewEthHeader->destination_addr, pOriginalEthHeader->source_addr, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pNewEthHeader->source_addr, pOriginalEthHeader->destination_addr, OVS_ETHERNET_ADDRESS_LENGTH);

    //2. fill ipv4
    pNewIpv4Header = AdvanceEthernetHeader(pNewEthHeader, sizeof(OVS_ETHERNET_HEADER));

    pNewIpv4Header->HeaderLength = 5;
    pNewIpv4Header->Version = 4;
    pNewIpv4Header->TypeOfServiceAndEcnField = 0;
    pNewIpv4Header->TotalLength = RtlUshortByteSwap(bufSize - sizeof(OVS_ETHERNET_HEADER));
    pNewIpv4Header->Identification = 0;
    pNewIpv4Header->FlagsAndOffset = 0;
    pNewIpv4Header->TimeToLive = 0x80;
    pNewIpv4Header->Protocol = OVS_IPPROTO_ICMP;
    pNewIpv4Header->HeaderChecksum = 0;

    RtlCopyMemory(&pNewIpv4Header->SourceAddress, &pOriginalIpv4Header->DestinationAddress, sizeof(IN_ADDR));
    RtlCopyMemory(&pNewIpv4Header->DestinationAddress, &pOriginalIpv4Header->SourceAddress, sizeof(IN_ADDR));

    pNewIpv4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pNewIpv4Header, sizeof(OVS_IPV4_HEADER));
    pNewIpv4Header->HeaderChecksum = RtlUshortByteSwap(pNewIpv4Header->HeaderChecksum);

    //3. fill icmpv4
    pIcmpHeader = (OVS_ICMP_MESSAGE_DEST_UNREACH*)AdvanceIpv4Header(pNewIpv4Header);

    pIcmpHeader->header.type = 3;
    pIcmpHeader->header.code = 4;
    /*
    The checksum is the 16-bit ones's complement of the one's
    complement sum of the ICMP message starting with the ICMP Type.
    For computing the checksum , the checksum field should be zero.
    This checksum may be replaced in the future.
    */
    pIcmpHeader->header.checksum = 0;

    pIcmpHeader->unused = 0;
    pIcmpHeader->length = pOriginalIpv4Header->HeaderLength * sizeof(DWORD) + 8;
    pIcmpHeader->nextHopMtu = (UINT16)mtu;
    pIcmpHeader->nextHopMtu = RtlUshortByteSwap(pIcmpHeader->nextHopMtu);

    //4. fill with original ipv4 header
    pAttachedIpv4Header = (OVS_IPV4_HEADER*)((UINT8*)(pIcmpHeader)+OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE);
    RtlCopyMemory(pAttachedIpv4Header, pOriginalIpv4Header, pOriginalIpv4Header->HeaderLength * sizeof(DWORD));

    //5. fill 8 bytes after it
    pOriginalTpLayer = AdvanceIpv4Header(pOriginalIpv4Header);
    pNewTpLayer = (BYTE*)AdvanceIpv4Header(pAttachedIpv4Header);

    RtlCopyMemory(pNewTpLayer, pOriginalTpLayer, 8);

    icmpHeaderSize = OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE + pOriginalIpv4Header->HeaderLength * sizeof(DWORD) + 8;
    pIcmpHeader->header.checksum = (UINT16)ComputeIpChecksum((BYTE*)pIcmpHeader, icmpHeaderSize);
    pIcmpHeader->header.checksum = RtlUshortByteSwap(pIcmpHeader->header.checksum);

    //6. set destination
    mustTransfer = SetOneDestination(pOvsNb->pSwitchInfo, pIcmpPacket->pNbl, &failReason, pDestinationNic);
    if (!mustTransfer)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    if (mustTransfer)
    {
        Nbls_SendIngressBasic(pOvsNb->pSwitchInfo, pIcmpPacket->pNbl, 0, 1);

        KFree(pIcmpPacket);
    }
    else
    {
        ONB_Destroy(pOvsNb->pSwitchInfo, &pIcmpPacket);
    }

    return mustTransfer;
}

_Use_decl_annotations_
BOOLEAN ONB_OriginateIcmp6Packet_Type2Code0(OVS_NET_BUFFER* pOvsNb, ULONG mtu, _In_ const OVS_NIC_INFO* pDestinationNic)
{
    OVS_NET_BUFFER* pIcmp6Packet = NULL;
    OVS_NBL_FAIL_REASON failReason = { 0 };
    BOOLEAN mustTransfer = FALSE;
    BYTE* originalBuffer = NULL, *newBuffer = NULL;
    OVS_ETHERNET_HEADER* pOriginalEthHeader = NULL, *pNewEthHeader = NULL;
    OVS_IPV6_HEADER* pOriginalIpv6Header = NULL, *pNewIpv6Header = NULL, *pAttachedIpv6Header = NULL;
    OVS_ICMP6_PACKET_TOO_BIG* pIcmp6Header = NULL;
    ULONG ethSize = 0;
    LE16 ethType = 0;
    OVS_SWITCH_INFO* pSwitchInfo = pOvsNb->pSwitchInfo;

    //the payload of the "icmp6 packet too big" must be:
    //As much of invoking packet as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU
    ULONG destBufSize = sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_IPV6_HEADER) + OVS_ICMP6_PACKET_TOO_BIG_SIZE_BARE;
    //payload to attached ipv6 frame
    ULONG payloadSize = 0;

    OVS_CHECK(pDestinationNic);

    originalBuffer = ONB_GetData(pOvsNb);
    pOriginalEthHeader = GetEthernetHeader(originalBuffer, &ethSize);
    ethType = ReadEthernetType(pOriginalEthHeader);
    pOriginalIpv6Header = AdvanceEthernetHeader((OVS_ETHERNET_HEADER*)originalBuffer, ethSize);

    //attached ipv6 header (in icmp6)
    destBufSize += sizeof(OVS_IPV6_HEADER);
    OVS_CHECK(OVS_IPV6_MINIMUM_MTU > destBufSize);
    payloadSize = min(RtlUshortByteSwap(pOriginalIpv6Header->payloadLength), OVS_IPV6_MINIMUM_MTU - destBufSize);

    //ATM destBufSize is size of: eth + ipv6 + icmp6 + attached ipv6 headers.
    //we need to add the payload of the attached ipv6 frame
    destBufSize += payloadSize;

    OVS_CHECK(pOriginalEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6));

    pIcmp6Packet = ONB_Create(destBufSize);
    newBuffer = ONB_GetData(pIcmp6Packet);

    //1. fill eth
    pNewEthHeader = (OVS_ETHERNET_HEADER*)newBuffer;
    pNewEthHeader->type = RtlUshortByteSwap(ethType);
    RtlCopyMemory(pNewEthHeader->destination_addr, pOriginalEthHeader->source_addr, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pNewEthHeader->source_addr, pOriginalEthHeader->destination_addr, OVS_ETHERNET_ADDRESS_LENGTH);

    //2. fill ipv6
    pNewIpv6Header = AdvanceEthernetHeader(pNewEthHeader, sizeof(OVS_ETHERNET_HEADER));

    pNewIpv6Header->vcf = 0;
    SetIpv6Version(6, &pNewIpv6Header->vcf);

    pNewIpv6Header->payloadLength = RtlUshortByteSwap(destBufSize - sizeof(OVS_ETHERNET_HEADER)-sizeof(OVS_IPV6_HEADER));
    pNewIpv6Header->nextHeader = OVS_IPV6_EXTH_ICMP6;
    pNewIpv6Header->hopLimit = pOriginalIpv6Header->hopLimit;//TODO

    RtlCopyMemory(&pNewIpv6Header->sourceAddress, &pOriginalIpv6Header->destinationAddress, sizeof(IN6_ADDR));
    RtlCopyMemory(&pNewIpv6Header->destinationAddress, &pOriginalIpv6Header->sourceAddress, sizeof(IN6_ADDR));

    //3. fill icmpv6
    pIcmp6Header = AdvanceIpv6Header(pNewIpv6Header);

    pIcmp6Header->type = 2;
    pIcmp6Header->code = 0;
    /*
    The checksum is the 16-bit one's complement of the one's complement
    sum of the entire ICMPv6 message, starting with the ICMPv6 message
    type field, and prepended with a "pseudo-header" of IPv6 header
    fields, as specified in [IPv6, Section 8.1].  The Next Header value
    used in the pseudo-header is 58.
    */
    pIcmp6Header->checksum = 0;

    pIcmp6Header->mtu = mtu;

    //4. fill with original ipv4 header
    pAttachedIpv6Header = (OVS_IPV6_HEADER*)((UINT8*)(pIcmp6Header)+OVS_ICMP6_PACKET_TOO_BIG_SIZE_BARE);
    RtlCopyMemory(pAttachedIpv6Header, pOriginalIpv6Header, sizeof(OVS_IPV6_HEADER) + payloadSize);

    pIcmp6Header->checksum = ComputeTransportChecksum(pIcmp6Header, pNewIpv6Header, OVS_ETHERTYPE_IPV6);
    pIcmp6Header->checksum = RtlUshortByteSwap(pIcmp6Header->checksum);

    OVS_CHECK(pDestinationNic);

    //6. set destination
    mustTransfer = SetOneDestination(pSwitchInfo, pIcmp6Packet->pNbl, &failReason, pDestinationNic);
    if (!mustTransfer)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    if (mustTransfer)
    {
        Nbls_SendIngressBasic(pSwitchInfo, pIcmp6Packet->pNbl, 0, 1);

        KFree(pIcmp6Packet);
    }
    else
    {
        ONB_Destroy(pSwitchInfo, &pIcmp6Packet);
    }

    return mustTransfer;
}

/* RFC 791
To produce the first fragment :
(1)  Copy the original internet header;
(2)  OIHL <-IHL; OTL <-TL; OFO <-FO; OMF <-MF;
(3)  NFB <-(MTU - IHL * 4) / 8;
(4)  Attach the first NFB * 8 data octets;
(5)  Correct the header :
MF <-1;  TL <-(IHL * 4) + (NFB * 8);
Recompute Checksum;
(6)  Submit this fragment to the next step in
datagram processing;
*/
NET_BUFFER* _Ipv4_CreateFirstFragment(_In_ const OVS_IPV4_HEADER* pOldIpv4Header, ULONG maxIpPacketSize, _Out_ ULONG* pBytesRemaining, ULONG dataOffsetAdd,
    _Inout_ ULONG* pNextSrcOffset)
{
    //resulting NB
    NET_BUFFER* pNb = NULL;
    //packet size, excluding ipv4 header size
    ULONG ipFragmentSize = 0;
    ULONG ipv4HeaderSize = 0;
    //packet size, including ipv4 header size
    ULONG curPacketSize = 0;
    ULONG oldIpv4TotalLength = 0;
    //the buffer of the resulting NB
    VOID* buffer = NULL;
    OVS_IPV4_HEADER* pFragIpv4Header = NULL;

    oldIpv4TotalLength = RtlUshortByteSwap(pOldIpv4Header->TotalLength);
    ipv4HeaderSize = Ipv4_GetHeaderSize(pOldIpv4Header);

    //a LSO packet may have TL == 0.
    //TODO: we currently have no support for fragmentation of LSO packets
    //(LSO packets appear to have ipv4 total length == 0)
    OVS_CHECK(oldIpv4TotalLength > 0);
    //we can only fragment if the size of the current packet is too big
    OVS_CHECK(oldIpv4TotalLength > maxIpPacketSize);
    OVS_CHECK(*pNextSrcOffset == 0);

    //the ipv4 packet size must be <= maxIpPacketSize, but packet size (excluding ipv4 header) must be multiple of 8
    //(because of frag offset, which is in units of 8 bytes)
    ipFragmentSize = ((maxIpPacketSize - ipv4HeaderSize) / 8) * 8;
    curPacketSize = ipFragmentSize + ipv4HeaderSize;

    pNb = ONB_CreateNb(curPacketSize, dataOffsetAdd);

    //the buffer was allocated by us, so its data is contiguous => NdisGetDataBuffer will succeed
    buffer = NdisGetDataBuffer(pNb, curPacketSize, NULL, 1, 0);
    OVS_CHECK(buffer);

    //1. Copy the ipv4 packet
    RtlCopyMemory(buffer, pOldIpv4Header, curPacketSize);
    pFragIpv4Header = (OVS_IPV4_HEADER*)buffer;

    //2. correct the header: MF and TL, recompute checksum
    pFragIpv4Header->MoreFragments = 1;
    pFragIpv4Header->TotalLength = RtlUshortByteSwap((UINT16)curPacketSize);

    pFragIpv4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pFragIpv4Header, ipv4HeaderSize);
    pFragIpv4Header->HeaderChecksum = RtlUshortByteSwap(pFragIpv4Header->HeaderChecksum);

    *pBytesRemaining = oldIpv4TotalLength - curPacketSize;
    *pNextSrcOffset = ipFragmentSize / 8;

    return pNb;
}

/* To produce the second fragment :
(7)  Selectively copy the internet header(some options
    are not copied, see option definitions);
(8)  Append the remaining data;
(9)  Correct the header :
IHL <-(((OIHL * 4) - (length of options not copied)) + 3) / 4;
TL <-OTL - NFB * 8 - (OIHL - IHL) * 4);
FO <-OFO + NFB;  MF <-OMF;  Recompute Checksum;
(10) Submit this fragment to the fragmentation test; DONE.
*/

NET_BUFFER* _Ipv4_CreateNextFragment(_In_ const OVS_IPV4_HEADER* pOldIpv4Header, _In_opt_ const BYTE* pOptions, ULONG optionsSize,
    ULONG maxIpPacketSize, _Inout_ ULONG* pBytesRemaining, ULONG dataOffsetAdd, _Inout_ ULONG* pSrcOffset)
{
    //resulting NB
    NET_BUFFER* pNb = NULL;
    //packet size, excluding ipv4 header
    ULONG ipFragmentSize = 0;
    //the whole ipv4 packet for the current fragment: i.e., including ipv4 header
    ULONG curPacketSize = 0;
    ULONG ipv4HeaderSize = 0;
    //the buffer of the resulting NB
    VOID* buffer = NULL;
    //the buffer of the source packet, the packet that is being fragmented
    BYTE* pSrcBuffer = NULL;
    OVS_IPV4_HEADER* pFragIpv4Header = NULL;
    //where to copy from, and where to copy to
    ULONG srcOffset = 0, destOffset = 0;
    //the ipv4's fragment offset, in units of 8 bytes
    UINT16 oldFragOffset = 0;

    srcOffset = *pSrcOffset;
    OVS_CHECK(srcOffset > 0);

    ipv4HeaderSize = sizeof(OVS_IPV4_HEADER) + optionsSize;

    //the ipv4 packet size must be <= maxIpPacketSize, but packet size (excluding ipv4 header) must be multiple of 8
    //(because of frag offset, which is in units of 8 bytes)
    ipFragmentSize = ((maxIpPacketSize - ipv4HeaderSize) / 8) * 8;
    curPacketSize = ipFragmentSize + ipv4HeaderSize;

    //however, we may have left to copy only a few bytes
    if (*pBytesRemaining + ipv4HeaderSize <= maxIpPacketSize)
    {
        ipFragmentSize = *pBytesRemaining;
        curPacketSize = ipFragmentSize + ipv4HeaderSize;
    }

    pNb = ONB_CreateNb(curPacketSize, dataOffsetAdd);

    //the buffer was allocated by us, so its data is contiguous => NdisGetDataBuffer will succeed
    buffer = NdisGetDataBuffer(pNb, curPacketSize, NULL, 1, 0);
    OVS_CHECK(buffer);

    //1. Copy the ipv4 header
    RtlCopyMemory(buffer, pOldIpv4Header, sizeof(OVS_IPV4_HEADER));
    pFragIpv4Header = (OVS_IPV4_HEADER*)buffer;

    destOffset = sizeof(OVS_IPV4_HEADER);

    //2. copy the options
    if (optionsSize)
    {
        OVS_CHECK(pOptions);
        //make sure the options size is a multiple of 4 bytes (requirement from header length, which is in 4 bytes)
        OVS_CHECK(optionsSize == (optionsSize / 4) * 4);

        RtlCopyMemory((BYTE*)buffer + destOffset, pOptions, optionsSize);
        destOffset += optionsSize;
    }

    //3. copy payload, from last offset
    //NOTE: offset in src packet is relative to the beginning of the payload of the ipv4 header
    //therefore, we must compute the src offset as old ipv4 header size + computed src offset for this fragment
    pSrcBuffer = (BYTE*)pOldIpv4Header + (pOldIpv4Header->HeaderLength * sizeof(DWORD)) + (srcOffset * 8);

    RtlCopyMemory((BYTE*)buffer + destOffset, pSrcBuffer, ipFragmentSize);
    //the fragment size must either be multiple of 8 bytes, or, if it is the last fragment, it can be of any size, if it is small.
    OVS_CHECK(ipFragmentSize == (ipFragmentSize / 8) * 8 || *pBytesRemaining == ipFragmentSize && curPacketSize <= maxIpPacketSize);

    //increase source offset, so that next time we copy, we'll copy from the next byte in the original packet, onward
    *pSrcOffset += (ipFragmentSize / 8);

    OVS_CHECK(*pBytesRemaining >= ipFragmentSize);
    *pBytesRemaining -= ipFragmentSize;

    //4. correct the header: IHL, MF, Fragment Offset, TL
    //ipv4 header's header length must be given in DWORDs
    ipv4HeaderSize = ipv4HeaderSize / sizeof(DWORD);
    //the header size is made of 4 bits
    OVS_CHECK(ipv4HeaderSize <= 0xF);

    pFragIpv4Header->HeaderLength = (UINT8)ipv4HeaderSize;
    //if we have more bytes to copy in further fragments, MF = TRUE. Else, if we have fragmented a fragment other than the last fragment
    //(a packet that had MF set), then we need to set MF.
    pFragIpv4Header->MoreFragments = (*pBytesRemaining > 0 || pOldIpv4Header->MoreFragments ? 1 : 0);

    //we must take into account the old ipv4 offset, for the case where we further fragment a packet that had previously been fragmented.
    oldFragOffset = Ipv4_GetFragmentOffset(pOldIpv4Header);
    Ipv4_SetFragmentOffset(pFragIpv4Header, (UINT16)srcOffset + oldFragOffset);
    pFragIpv4Header->TotalLength = RtlUshortByteSwap((UINT16)curPacketSize);

    //5. recompute checksum
    pFragIpv4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pFragIpv4Header, ipv4HeaderSize);
    pFragIpv4Header->HeaderChecksum = RtlUshortByteSwap(pFragIpv4Header->HeaderChecksum);

    return pNb;
}

VOID _ONB_AddEthHeader(_In_ NET_BUFFER* pNb, ULONG ethSize, _In_ const OVS_ETHERNET_HEADER* pEthHeader)
{
    VOID* buffer = NULL;

    //1. insert eth header
    if (NDIS_STATUS_SUCCESS != NdisRetreatNetBufferDataStart(pNb, ethSize, 0, NULL))
    {
        OVS_CHECK(__UNEXPECTED__);
    }

    buffer = NdisGetDataBuffer(pNb, ethSize, NULL, 1, 0);
    OVS_CHECK(buffer);

    RtlCopyMemory(buffer, pEthHeader, ethSize);

#if OVS_DBGPRINT_FRAMES
    buffer = NdisGetDataBuffer(pNb, NET_BUFFER_DATA_LENGTH(pNb), NULL, 1, 0);
    DbgPrintNb(pNb, "fragment: ");
#endif
}

/* RFC 791
To better understand ipv4 fragmentation, read RFC791
Also, http://www.tcpipguide.com/free/t_IPMessageFragmentationProcess.htm might be useful
*/

//pOvsNb:                the net buffer to be fragmented. Must contain only one NET_BUFFER_LIST, with only one NET_BUFFER.
//                       the net buffer must have it's first byte == the first byte of the eth header
//maxIpPacketSize:       max size allowed for a packet, excluding the eth header, but considered such as maxIpPacketSize + encaps bytes <= mtu
//pOldEthHeader          copy of the ethernet header
//dataOffsetAdd:         how much space to allocate before the beginning of the buffer. This will be used to add the eth header + the encapsulation headers.
//NOTE: checksum offloading must have been dealt with before.
//NOTE: at the end, each resulting fragment will have its frist byte == the first byte of the eth header.
NET_BUFFER_LIST* ONB_FragmentBuffer_Ipv4(_Inout_ OVS_NET_BUFFER* pOvsNb, ULONG maxIpPacketSize, const OVS_ETHERNET_HEADER* pOldEthHeader, ULONG dataOffsetAdd)
{
    //the buffer before fragmentation
    VOID* oldPacketBuffer = NULL;
    //the amount of bytes that remain to be copied in further ipv4 fragments
    ULONG bytesRemaining = 0;
    //resulting NBL
    NET_BUFFER_LIST* pNbl = NULL;
    USHORT contextSize = MEMORY_ALLOCATION_ALIGNMENT;
    //the total size of the options that must be copied in the 2nd to the n-th fragment
    ULONG optionsSize = 0;
    //the buffer where ipv4 "copied" options are put
    BYTE* pOptionsBuffer = NULL;
    //NOTE: we assume - and it must be this way - that the eth size == size of simple eth header
    ULONG ethSize = sizeof(OVS_ETHERNET_HEADER);
    //the offset in the source packet, from where to copy bytes for the next fragment, in units of 8 bytes
    ULONG srcOffset = 0;
    //the ipv4 header of the original / old packet
    OVS_IPV4_HEADER* pOldIpv4Header = NULL;
    NET_BUFFER* pNb = NULL, *pCurNb = NULL, *pFirstNb = NULL;

    ONB_Advance(pOvsNb, sizeof(OVS_ETHERNET_HEADER));

    oldPacketBuffer = ONB_GetData(pOvsNb);
    pOldIpv4Header = (OVS_IPV4_HEADER*)oldPacketBuffer;

    //we assume non-vlan fragmes are being fragmented - and thus, eth size == sizeof(sizeof(OVS_ETHERNET_HEADER))
    OVS_CHECK(pOldEthHeader->type != OVS_ETHERTYPE_QTAG);
    //a simple check to make sure that pOldIpv4Header does indeed point to the ipv4 header
    OVS_CHECK(pOldIpv4Header->Version == 4);
    OVS_CHECK(pOldIpv4Header->HeaderLength >= 5);

    pNb = _Ipv4_CreateFirstFragment(pOldIpv4Header, maxIpPacketSize, &bytesRemaining, dataOffsetAdd, &srcOffset);
    if (!pNb)
    {
        ONB_Retreat(pOvsNb, sizeof(OVS_ETHERNET_HEADER));
        return NULL;
    }

    _ONB_AddEthHeader(pNb, ethSize, pOldEthHeader);

    pOptionsBuffer = Ipv4_CopyHeaderOptions(pOldIpv4Header, &optionsSize);

    pFirstNb = pNb;
    pCurNb = pFirstNb;

    while (bytesRemaining > 0)
    {
        pNb = _Ipv4_CreateNextFragment(pOldIpv4Header, pOptionsBuffer, optionsSize, maxIpPacketSize, &bytesRemaining, dataOffsetAdd, &srcOffset);
        _ONB_AddEthHeader(pNb, ethSize, pOldEthHeader);

        OVS_CHECK(pNb->Next == NULL);
        pCurNb->Next = pNb;
        pCurNb = pCurNb->Next;
    }

    if (pOptionsBuffer)
    {
        KFree(pOptionsBuffer);
    }

    ONB_Retreat(pOvsNb, sizeof(OVS_ETHERNET_HEADER));

    OVS_CHECK(pFirstNb);
    pNbl = ONB_CreateNblFromNb(pFirstNb, contextSize);

    DEBUGP(LOG_INFO, "NBL: %p\n", pNbl);

    return pNbl;
}

BOOLEAN ONB_OriginateArpRequest(const BYTE targetIp[4])
{
    OVS_NET_BUFFER* pArpPacket = NULL;
    OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;
    BOOLEAN mustTransfer = FALSE;
    BYTE* newBuffer = NULL;
    OVS_ETHERNET_HEADER* pNewEthHeader = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;
    OVS_NIC_INFO externalNicAndPort = { 0 };
    OVS_ARP_HEADER* pArpHeader = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    ULONG bufSize = sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_ARP_HEADER);

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        DEBUGP(LOG_ERROR, "failed to originate arp request: the extension appears not to be attached to any switch!\n");
        return FALSE;
    }

    pForwardInfo = pSwitchInfo->pForwardInfo;

    mustTransfer = GetExternalDestinationInfo(pForwardInfo, 0, &externalNicAndPort, &failReason);
    if (!mustTransfer)
    {
        if (failReason != OVS_NBL_FAIL_DESTINATION_IS_SOURCE)
        {
            DEBUGP(LOG_ERROR, "Get destination failed: %s\n", FailReasonMessageA(failReason));
        }

        mustTransfer = FALSE;
        goto Cleanup;
    }

    pArpPacket = ONB_Create(bufSize);
    newBuffer = ONB_GetData(pArpPacket);

    //1. fill eth
    pNewEthHeader = (OVS_ETHERNET_HEADER*)newBuffer;
    pNewEthHeader->type = RtlUshortByteSwap(OVS_ETHERTYPE_ARP);
    memset(pNewEthHeader->destination_addr, 0xFF, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pNewEthHeader->source_addr, externalNicAndPort.mac, OVS_ETHERNET_ADDRESS_LENGTH);

    //2. fill ipv4
    pArpHeader = AdvanceEthernetHeader(pNewEthHeader, sizeof(OVS_ETHERNET_HEADER));
    pArpHeader->hardwareType = RtlUshortByteSwap(OVS_ARP_HARDWARE_TYPE_ETHERNET);
    pArpHeader->protocolType = RtlUshortByteSwap(OVS_ETHERTYPE_IPV4);
    pArpHeader->harwareLength = OVS_ETHERNET_ADDRESS_LENGTH;
    pArpHeader->protocolLength = OVS_IPV4_ADDRESS_LENGTH;
    pArpHeader->operation = RtlUshortByteSwap(OVS_ARP_OPERATION_REQUEST);

    RtlCopyMemory(pArpHeader->senderHardwareAddress, externalNicAndPort.mac, OVS_ETHERNET_ADDRESS_LENGTH);
    memset(pArpHeader->senderProtocolAddress, 0, OVS_IPV4_ADDRESS_LENGTH);

    memset(pArpHeader->targetHardwareAddress, 0, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pArpHeader->targetProtocolAddress, targetIp, OVS_IPV4_ADDRESS_LENGTH);

    //6. set destination
    mustTransfer = SetOneDestination(pSwitchInfo, pArpPacket->pNbl, &failReason, /*in*/ &externalNicAndPort);
    if (!mustTransfer)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        goto Cleanup;
    }

Cleanup:
    if (mustTransfer)
    {
        Nbls_SendIngressBasic(pSwitchInfo, pArpPacket->pNbl, /*sendFlags*/0, 1);

        KFree(pArpPacket);
    }
    else
    {
        ONB_Destroy(pSwitchInfo, &pArpPacket);
    }

    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return mustTransfer;
}

BOOLEAN ONB_NblEqual(_In_ NET_BUFFER_LIST* pLhsNbl, _In_ NET_BUFFER_LIST* pRhsNbl)
{
    VOID* pLhBuffer = NULL, *pRhBuffer = NULL;
    NET_BUFFER* pNb = NULL;
    ULONG nbLen = 0;

    if (memcmp(pLhsNbl, pRhsNbl, sizeof(NET_BUFFER_LIST)))
    {
        return FALSE;
    }

    if (memcmp(NET_BUFFER_LIST_FIRST_NB(pLhsNbl), NET_BUFFER_LIST_FIRST_NB(pRhsNbl), sizeof(NET_BUFFER)))
    {
        return FALSE;
    }

    pNb = NET_BUFFER_LIST_FIRST_NB(pLhsNbl);
    nbLen = NET_BUFFER_DATA_LENGTH(pNb);
    pLhBuffer = NdisGetDataBuffer(pNb, nbLen, NULL, 1, 0);
    OVS_CHECK(pLhBuffer);

    pNb = NET_BUFFER_LIST_FIRST_NB(pRhsNbl);
    pRhBuffer = NdisGetDataBuffer(pNb, nbLen, NULL, 1, 0);
    OVS_CHECK(pRhBuffer);

    return !memcmp(pLhBuffer, pRhBuffer, nbLen);
}