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
extern OVS_SWITCH_INFO* g_pSwitchInfo;

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
    else {
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
    ExFreePoolWithTag(buffer, g_extAllocationTag);

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
    ExFreePoolWithTag(buffer, g_extAllocationTag);

    IoFreeMdl(pMdl);
    NdisFreeNetBuffer(pNb);

    NdisFreeNetBufferList(pOvsNb->pNbl);

    pOvsNb->pFlow = NULL;
    pOvsNb->pOriginalPacketInfo = NULL;
    pOvsNb->pTunnelInfo = NULL;

    pOvsNb->packetPriority = pOvsNb->packetMark = 0;

    ExFreePoolWithTag(pOvsNb, g_extAllocationTag);

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
    pDestBuffer = ExAllocatePoolWithTag(NonPagedPool, nbLen + addSize, g_extAllocationTag);
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
        pSrcNbBuffer = ExAllocatePoolWithTag(NonPagedPool, nbLen, g_extAllocationTag);
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

    if (pResBuffer)
    {
        ExFreePoolWithTag(pResBuffer, g_extAllocationTag);
    }

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
    pOvsNetBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_NET_BUFFER), g_extAllocationTag);

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

    pDuplicateOnb->pFlow = pOriginalOnb->pFlow;
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

    OVS_CHECK(pBuffer);
    OVS_CHECK(pBuffer->p);
    OVS_CHECK(pBuffer->size);
    OVS_CHECK(!pBuffer->offset);

    //TODO: must lock
    OVS_CHECK(g_ndisFilterHandle);

    //1. Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pDuplicateNbl);
    if (!pDuplicateNbl)
    {
        return NULL;
    }

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    nbLen = pBuffer->size;
    pDestBuffer = ExAllocatePoolWithTag(NonPagedPool, nbLen + addSize, g_extAllocationTag);
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

    RtlCopyMemory(pDestBuffer + addSize, pBuffer->p, nbLen);

    //7. Set the rest of NBL stuff
    //TODO: must lock
    pDuplicateNbl->SourceHandle = g_ndisFilterHandle;

    //TODO: must lock g_pSwitchInfo
    status = g_pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(g_pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

    //8. Create the OVS_NET_BUFFER
    pOvsNetBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_NET_BUFFER), g_extAllocationTag);

    if (!pOvsNetBuffer)
    {
        return NULL;
    }

    RtlZeroMemory(pOvsNetBuffer, sizeof(OVS_NET_BUFFER));

    pOvsNetBuffer->packetMark = pOvsNetBuffer->packetPriority = 0;

    pOvsNetBuffer->pNbl = pDuplicateNbl;

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    buffer = NdisGetDataBuffer(pDuplicateNb, nbLen, NULL, 1, 0);
    OVS_CHECK(buffer);

    if (!buffer)
    {
        return NULL;
    }

    return pOvsNetBuffer;
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

    //TODO: must lock
    OVS_CHECK(g_ndisFilterHandle);

    //1. Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pDuplicateNbl);

    if (!pDuplicateNbl)
    {
        return NULL;
    }

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    pDestBuffer = ExAllocatePoolWithTag(NonPagedPool, bufSize, g_extAllocationTag);
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
        return NULL;
    }

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pDuplicateNb;

    //6. Set the rest of NBL stuff
    //TODO: must lock
    pDuplicateNbl->SourceHandle = g_ndisFilterHandle;

    //TODO: must lock g_pSwitchInfo
    status = g_pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(g_pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

    //7. Create the OVS_NET_BUFFER
    pOvsNetBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_NET_BUFFER), g_extAllocationTag);

    if (!pOvsNetBuffer)
    {
        return NULL;
    }

    RtlZeroMemory(pOvsNetBuffer, sizeof(OVS_NET_BUFFER));

    pOvsNetBuffer->packetMark = pOvsNetBuffer->packetPriority = 0;

    pOvsNetBuffer->pNbl = pDuplicateNbl;

    //TODO: read about NDIS_NET_BUFFER_LIST_8021Q_INFO... setting VLAN info for NBLs using NET_BUFFER_LIST_INFO macro?
    //the miniport driver reads this setting and applies the info.

    buffer = NdisGetDataBuffer(pDuplicateNb, bufSize, NULL, 1, 0);
    OVS_CHECK(buffer);

    if (!buffer)
    {
        return NULL;
    }

    return pOvsNetBuffer;
}

NET_BUFFER* ONB_CreateNb(ULONG dataLen, ULONG dataOffset)
{
    NET_BUFFER* pDuplicateNb = NULL;
    BYTE* pDestBuffer = NULL;
    MDL* pDuplicateMdl = NULL;
    VOID* buffer = NULL;

    //TODO: must lock
    OVS_CHECK(g_ndisFilterHandle);

    //2. Allocate buffer
    //assume there is no mdl size > 1500
    pDestBuffer = ExAllocatePoolWithTag(NonPagedPool, dataLen + dataOffset, g_extAllocationTag);
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

    return pDuplicateNb;
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

        ExFreePoolWithTag(pIcmpPacket, g_extAllocationTag);
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

        ExFreePoolWithTag(pIcmp6Packet, g_extAllocationTag);
    }

    else
    {
        ONB_Destroy(pSwitchInfo, &pIcmp6Packet);
    }

    return mustTransfer;
}

//TODO: we currently assume that all Ipv4 frames have no options!
// when performing ipv4 fragmentation, we MUST take into account the ipv4 options as well!
NET_BUFFER_LIST* ONB_FragmentBuffer_Ipv4(_Inout_ OVS_NET_BUFFER* pOvsNb, ULONG mtu, const OVS_ETHERNET_HEADER* pEthHeader, ULONG ethSize, ULONG dataOffsetAdd)
{
    VOID* originalPacketBuffer = ONB_GetData(pOvsNb);
    ULONG packetSize = 0;
    NET_BUFFER_LIST* pDuplicateNbl = NULL;
    USHORT contextSize = MEMORY_ALLOCATION_ALIGNMENT;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG ipv4HeaderSize, ipv4HeaderSizeFragment, optionsSize = 0;
    BYTE* pOptionsBuffer = NULL;

    //1. compute how many fragments to create, based on buffer size and mtu
    OVS_IPV4_HEADER* pIpv4Header = (OVS_IPV4_HEADER*)originalPacketBuffer;

    //must have eth header advanced
    OVS_CHECK(ONB_GetDataOffset(pOvsNb) > 0);

    if (pIpv4Header->HeaderLength > 5)
    {
        //TODO
        OVS_CHECK(0);
    }

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pChecksumOffload = NULL;

    //if have tcp / udp csum offloading and we need to encapsulate: disable tcp / udp csum offloading, compute checksum for tcp / udp
    pChecksumOffload = GetChecksumOffloadInfo(pOvsNb->pNbl);

    if (pChecksumOffload->Value)
    {
        if (pChecksumOffload->Transmit.IsIPv4 || pChecksumOffload->Transmit.IsIPv6)
        {
            if (pIpv4Header->Protocol == OVS_IPPROTO_TCP)
            {
                OVS_TCP_HEADER* pTcpHeader = (OVS_TCP_HEADER*)AdvanceIpv4Header(pIpv4Header);
                UINT16 checksum = 0, checksumTcp = 0, checksumPseudo = 0;
                ULONG transportLen = GetTransportLength_FromIpv4(pIpv4Header);

                checksumPseudo = RtlUshortByteSwap(pTcpHeader->checksum);
                OVS_CHECK(checksumPseudo);
                checksumPseudo = ~checksumPseudo;

                pTcpHeader->checksum = 0;

                checksumTcp = (UINT16)ComputeIpChecksum((BYTE*)pTcpHeader, transportLen);
                checksumTcp = ~checksumTcp;

                checksum = (UINT16)ChecksumAddCsum(checksumTcp, checksumPseudo);
                checksum = ~checksum;

                pTcpHeader->checksum = RtlUshortByteSwap(checksum);

                pChecksumOffload->Transmit.TcpChecksum = 0;
                pChecksumOffload->Transmit.TcpHeaderOffset = 0;
            }

            else if (pIpv4Header->Protocol == OVS_IPPROTO_UDP)
            {
                OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)AdvanceIpv4Header(pIpv4Header);
                UINT16 checksum = 0, checksumUdp = 0, checksumPseudo = 0, checksum2 = 0;
                ULONG transportLen = GetTransportLength_FromIpv4(pIpv4Header);

                checksumPseudo = RtlUshortByteSwap(pUdpHeader->checksum);
                OVS_CHECK(checksumPseudo);

                pUdpHeader->checksum = 0;

                checksumUdp = (UINT16)ComputeIpChecksum((BYTE*)pUdpHeader, transportLen);
                checksumUdp = ~checksumUdp;

                checksum = (UINT16)ChecksumAddCsum(checksumUdp, checksumPseudo);
                checksum = ~checksum;

                checksum2 = ComputeTransportChecksum(pUdpHeader, pIpv4Header, OVS_ETHERTYPE_IPV4);

                pUdpHeader->checksum = RtlUshortByteSwap(checksum);

                pChecksumOffload->Transmit.UdpChecksum = 0;
                pChecksumOffload->Transmit.TcpHeaderOffset = 0;
            }
        }
    }

    packetSize = ONB_GetDataLength(pOvsNb);
    ipv4HeaderSize = sizeof(OVS_IPV4_HEADER);
    packetSize -= ipv4HeaderSize;
    pOptionsBuffer = Ipv4_CopyHeaderOptions(pIpv4Header, &optionsSize);
    if (!pOptionsBuffer)
    {
        ipv4HeaderSizeFragment = ipv4HeaderSize;
    }

    else
    {
        ipv4HeaderSizeFragment = sizeof(OVS_IPV4_HEADER) + optionsSize;

        OVS_CHECK(ipv4HeaderSizeFragment % 4 == 0);
        OVS_CHECK(optionsSize < 0xFFFF);
    }

    ULONG offset = 0;

    NET_BUFFER* pFirstNb = NULL, *pCurNb = NULL;

    //TODO: try NdisAllocateFragmentNetBufferList

    while (packetSize > 0)
    {
        ULONG curPacketSize = 0;
        NET_BUFFER* pNb = NULL;
        VOID* buffer = NULL;
        OVS_ETHERNET_HEADER* pFragEthHeader = NULL;
        OVS_IPV4_HEADER* pFragIpv4Header = NULL;
        ULONG dataSize = 0;
        UINT16 totalLength = 0;

        if (packetSize + ipv4HeaderSize > mtu)
        {
            curPacketSize = ((mtu - ipv4HeaderSize) / 8) * 8 + ipv4HeaderSize;
        }

        else
        {
            curPacketSize = packetSize + ipv4HeaderSize;
        }

        dataSize = curPacketSize;
        dataSize -= ipv4HeaderSize;

        pNb = ONB_CreateNb(curPacketSize, ethSize + dataOffsetAdd);
        buffer = NdisGetDataBuffer(pNb, curPacketSize, NULL, 1, 0);

        OVS_CHECK(buffer);

        ULONG destOffset = ipv4HeaderSize; //TODO

        pFragIpv4Header = (OVS_IPV4_HEADER*)buffer;
        RtlCopyMemory(pFragIpv4Header, pIpv4Header, ipv4HeaderSize); // TODO: what size exactly??

        BYTE* copyFrom = (BYTE*)originalPacketBuffer + offset;
        BYTE* copyTo = NULL;
        ULONG copySize = 0;

        if (offset == 0)
        {
            copyFrom += ipv4HeaderSize;
        }

        copyTo = (BYTE*)buffer + destOffset;

        copySize = dataSize;

        RtlCopyMemory(copyTo, copyFrom, copySize);

        totalLength = (UINT16)curPacketSize;

        OVS_CHECK(offset % 8 == 0);
        Ipv4_SetFragmentOffset(pFragIpv4Header, (UINT16)(offset / 8));

        if (packetSize > dataSize)
        {
            pFragIpv4Header->MoreFragments = 1;
        }

        else
        {
            pFragIpv4Header->MoreFragments = 0;
        }

        if (ipv4HeaderSize > sizeof(OVS_IPV4_HEADER))
        {
            //copy the options that have the copied flag set
            RtlCopyMemory((BYTE*)pFragIpv4Header + sizeof(OVS_IPV4_HEADER), pOptionsBuffer, optionsSize);

            totalLength += (UINT16)optionsSize;

            pIpv4Header->HeaderLength = (UINT8)(ipv4HeaderSizeFragment / 4);
        }

        pFragIpv4Header->TotalLength = RtlUshortByteSwap(totalLength);

        pFragIpv4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pFragIpv4Header, ipv4HeaderSize);
        pFragIpv4Header->HeaderChecksum = RtlUshortByteSwap(pFragIpv4Header->HeaderChecksum);

        offset += dataSize;
        packetSize -= dataSize;

        if (NDIS_STATUS_SUCCESS != NdisRetreatNetBufferDataStart(pNb, ethSize, 0, NULL))
        {
            OVS_CHECK(0);
        }

        buffer = NdisGetDataBuffer(pNb, curPacketSize + ethSize, NULL, 1, 0);
        OVS_CHECK(buffer);

        pFragEthHeader = GetEthernetHeader(buffer, &ethSize);
        RtlCopyMemory(pFragEthHeader, pEthHeader, sizeof(OVS_ETHERNET_HEADER));

        DbgPrintNb(pNb, "fragment: ");

        if (!pFirstNb)
        {
            pFirstNb = pNb;
            pCurNb = pFirstNb;
        }

        else
        {
            pCurNb->Next = pNb;
            pCurNb = pCurNb->Next;
        }

        ipv4HeaderSize = ipv4HeaderSizeFragment;
    }

    //2. create an OVS_NET_BUFFER, with one NBL, with N NBs: first with size mtu, i with size mtu, where i = [1, n - 1]; n with size = left bytes.
    //3. copy first mtu bytes from source to destination
    //4. change ipv4 header, to specify fragments
    //5. for each other fragment, create an ipv4 header (20 bytes?), and write the rest of the bytes, and see the offset field.
    //6. the last fragment has 'More Fragments' = 0

    //NOTE: for options: if an option has the flag 'Copied' = 1, then the option must be copied to each fragment!

    //Allocate NBL
    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, /*backfill*/contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);
    OVS_CHECK(pDuplicateNbl);

    //5. Set NB as the first NB in the NBL
    NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pFirstNb;

    //6. Set the rest of NBL stuff
    //TODO: must lock
    pDuplicateNbl->SourceHandle = g_ndisFilterHandle;

    //TODO: must lock g_pSwitchInfo
    status = g_pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(g_pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
    }

    if (pOptionsBuffer)
    {
        ExFreePoolWithTag(pOptionsBuffer, g_extAllocationTag);
    }

    return pDuplicateNbl;
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

    ULONG bufSize = sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_ARP_HEADER);

    if (!g_pSwitchInfo)
    {
        DEBUGP(LOG_ERROR, "failed to originate arp request: the extension appears not to be attached to any switch!\n");
        return FALSE;
    }

    pForwardInfo = g_pSwitchInfo->pForwardInfo;

    mustTransfer = GetExternalDestinationInfo(pForwardInfo, 0, &externalNicAndPort, &failReason);
    if (!mustTransfer)
    {
        if (failReason != OVS_NBL_FAIL_DESTINATION_IS_SOURCE)
        {
            DEBUGP(LOG_ERROR, "Get destination failed: %s\n", FailReasonMessageA(failReason));
        }

        return FALSE;
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
    mustTransfer = SetOneDestination(g_pSwitchInfo, pArpPacket->pNbl, &failReason, /*in*/ &externalNicAndPort);
    if (!mustTransfer)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    if (mustTransfer)
    {
        Nbls_SendIngressBasic(g_pSwitchInfo, pArpPacket->pNbl, /*sendFlags*/0, 1);

        ExFreePoolWithTag(pArpPacket, g_extAllocationTag);
    }

    else
    {
        ONB_Destroy(g_pSwitchInfo, &pArpPacket);
    }

    return mustTransfer;
}