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

#include "precomp.h"
#include "Frame.h"
#include "NblsIngress.h"
#include "Nbls.h"
#include "Gre.h"
#include "Ipv6.h"
#include "Arp.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Igmp.h"
#include "Sctp.h"
#include "Tcp.h"

extern NDIS_HANDLE g_hNblPool;
extern NDIS_HANDLE g_hNbPool;

extern NDIS_SPIN_LOCK g_nbPoolLock;

VOID* ReadNb_Alloc(_In_ NET_BUFFER* net_buffer)
{
    VOID* buffer = NULL, *allocBuffer = NULL;
    ULONG bufferSize = NET_BUFFER_DATA_LENGTH(net_buffer);

    buffer = NdisGetDataBuffer(net_buffer, bufferSize, NULL, 1, 0);
    if (buffer)
    {
        allocBuffer = KAlloc(bufferSize);
        if (!allocBuffer)
        {
            return NULL;
        }

        RtlCopyMemory(allocBuffer, buffer, bufferSize);
        return allocBuffer;
    }
    else
    {
        allocBuffer = KAlloc(bufferSize);
        OVS_CHECK(allocBuffer);

        buffer = NdisGetDataBuffer(net_buffer, bufferSize, allocBuffer, 1, 0);
        if (buffer)
        {
            return buffer;
        }
        else
        {
            DEBUGP(LOG_ERROR, "could not retrieve mac header: should have allocated storage in NdisGetDataBuffer!\n");
        }
    }

    return NULL;
}

_Use_decl_annotations_
VOID* GetNbBufferData(NET_BUFFER* pNb, void** pAllocBuffer)
{
    return GetNbBufferData_OfSize(pNb, NET_BUFFER_DATA_LENGTH(pNb), pAllocBuffer);
}

_Use_decl_annotations_
VOID* GetNbBufferData_OfSize(NET_BUFFER* pNb, ULONG size, void** pAllocBuffer)
{
    void* buffer = NULL;

    OVS_CHECK(pAllocBuffer);
    *pAllocBuffer = NULL;

    buffer = NdisGetDataBuffer(pNb, size, NULL, 1, 0);
    if (buffer)
    {
        return buffer;
    }

    *pAllocBuffer = KAlloc(size);
    OVS_CHECK(*pAllocBuffer);

    buffer = NdisGetDataBuffer(pNb, size, *pAllocBuffer, 1, 0);
    if (buffer)
    {
        OVS_CHECK(buffer == *pAllocBuffer);

        return buffer;
    }
    else
    {
        DEBUGP(LOG_ERROR, "could not retrieve mac header: should have allocated storage in NdisGetDataBuffer!\n");
        return NULL;
    }
}

VOID FreeNbBufferData(VOID* allocBuffer)
{
    DEBUGP(LOG_INFO, "calling FreeNbBufferData... hopefully");
    KFree(allocBuffer);
}

ULONG CountNbls(_In_ NET_BUFFER_LIST* pNbl)
{
    UINT count = 0;
    while (pNbl)
    {
        pNbl = NET_BUFFER_LIST_NEXT_NBL(pNbl);
        ++count;
    }

    return count;
}

ULONG CountNbs(_In_ NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER* pNb = NULL;
    ULONG count = 0;

    for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        ++count;
    }

    return count;
}

BOOLEAN _SetCloneData(_In_ NET_BUFFER_LIST* pNbl, _In_ const OVS_SWITCH_INFO* pSwitchInfo, _Inout_ NET_BUFFER_LIST* pClonedNbl)
{
    NDIS_STATUS status = 0;

    pClonedNbl->SourceHandle = pSwitchInfo->filterHandle;

    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pClonedNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
        return FALSE;
    }

    status = pSwitchInfo->switchHandlers.CopyNetBufferListInfo(pSwitchInfo->switchContext, pClonedNbl, pNbl, 0);

    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
        return FALSE;
    }

    pClonedNbl->ParentNetBufferList = pNbl;
    return TRUE;
}

_Use_decl_annotations_
NET_BUFFER_LIST* CloneNblNormal(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER_LIST* pClonedNbl = NULL;

    NdisAcquireSpinLock(&g_nbPoolLock);
    pClonedNbl = NdisAllocateCloneNetBufferList(pNbl, g_hNblPool, g_hNbPool, NDIS_CLONE_FLAGS_USE_ORIGINAL_MDLS);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pClonedNbl)
    {
        DEBUGP(LOG_ERROR, "CloneNbl: NdisAllocateFragmentNetBufferList failed");
        OVS_CHECK(pClonedNbl);
        return NULL;
    }

    _SetCloneData(pNbl, pSwitchInfo, pClonedNbl);

    return pClonedNbl;
}

_Use_decl_annotations_
NET_BUFFER_LIST* CloneNblFragment(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl, ULONG maxNbLength)
{
    NET_BUFFER_LIST* pClonedNbl = NULL;
    //must clone NBL (fragment / simple clone?)
    //must check against used / unused space. how much do we need?
    //ULONG maxNbLength = OVS_ETHERNETV2_MTU - bytesMore;

    //TODO/NOTE:
    //The new fragment NET_BUFFER_LIST structure that NdisAllocateFragmentNetBufferList creates does not include an initial NET_BUFFER_LIST_CONTEXT structure.
    NdisAcquireSpinLock(&g_nbPoolLock);
    pClonedNbl = NdisAllocateFragmentNetBufferList(pNbl, g_hNblPool, g_hNbPool, 0, maxNbLength, /*dataOffsetDelta*/ 0, /*dataBackFill*/0, 0);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pClonedNbl)
    {
        DEBUGP(LOG_ERROR, "CloneNbl: NdisAllocateFragmentNetBufferList failed");
        OVS_CHECK(pClonedNbl);
        return NULL;
    }

    _SetCloneData(pNbl, pSwitchInfo, pClonedNbl);

    //TODO: allocate context! (must we?) context for NBL I think is optional.

    return pClonedNbl;
    /*
    fragmenting buffers: if you know the new size (old size + sizeof(ip) + sizeof(gre)) will be > MTU
    find MTU: OID_GEN_MAXIMUM_FRAME_SIZE or OID_GEN_MAXIMUM_TOTAL_SIZE
    then you must fragment the buffers
    http://msdn.microsoft.com/en-us/library/windows/hardware/ff560707(v=vs.85).aspx
    NdisAllocateFragmentNetBufferList

    de-fragment/reassamble (on receive):
    NdisAllocateReassembledNetBufferList
    */
}

_Use_decl_annotations_
NET_BUFFER_LIST* DuplicateNbl(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER* pNb = NULL;
    ULONG nbLen = 0;
    USHORT contextSize = NET_BUFFER_LIST_CONTEXT_DATA_SIZE(pNbl);
    NET_BUFFER_LIST* pDuplicateNbl = NULL;
    NET_BUFFER* pDuplicateNb = NULL, *pLastNb = NULL;
    VOID* pSrcNbBuffer = NULL, *pResBuffer = NULL;
    NDIS_STATUS status = 0;
    VOID* pBuffer = NULL;
    MDL* pDuplicateMdl = NULL;

    if (contextSize % MEMORY_ALLOCATION_ALIGNMENT != 0)
    {
        contextSize = (contextSize / MEMORY_ALLOCATION_ALIGNMENT) * MEMORY_ALLOCATION_ALIGNMENT + MEMORY_ALLOCATION_ALIGNMENT;
    }

    NdisAcquireSpinLock(&g_nbPoolLock);
    pDuplicateNbl = NdisAllocateNetBufferList(g_hNblPool, contextSize, /*backfill*/contextSize);
    NdisReleaseSpinLock(&g_nbPoolLock);

    if (!pDuplicateNbl)
    {
        return NULL;
    }

    //assume there is no mdl size > 1500
    for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        nbLen = NET_BUFFER_DATA_LENGTH(pNb);

        pBuffer = KAlloc(nbLen);
        if (!pBuffer)
        {
            break;
        }

        pDuplicateMdl = IoAllocateMdl(pBuffer, nbLen, FALSE, FALSE, NULL);
        OVS_CHECK(pDuplicateMdl);
        MmBuildMdlForNonPagedPool(pDuplicateMdl);

        OVS_CHECK(pBuffer == MmGetMdlVirtualAddress(pDuplicateMdl));

        NdisAcquireSpinLock(&g_nbPoolLock);
        pDuplicateNb = NdisAllocateNetBuffer(g_hNbPool, pDuplicateMdl, 0, nbLen);
        NdisReleaseSpinLock(&g_nbPoolLock);

        if (!pDuplicateNb)
        {
            return NULL;
        }

        if (!pLastNb)
        {
            NET_BUFFER_LIST_FIRST_NB(pDuplicateNbl) = pDuplicateNb;
        }
        else
        {
            NET_BUFFER_NEXT_NB(pLastNb) = pDuplicateNb;
        }

        pLastNb = pDuplicateNb;
        pSrcNbBuffer = NdisGetDataBuffer(pNb, nbLen, NULL, 1, 0);
        if (!pSrcNbBuffer)
        {
            pSrcNbBuffer = KAlloc(nbLen);
            OVS_CHECK(pSrcNbBuffer);

            if (!pSrcNbBuffer)
            {
                return NULL;
            }

            pResBuffer = NdisGetDataBuffer(pNb, nbLen, pSrcNbBuffer, 1, 0);
            OVS_CHECK(pResBuffer);
            OVS_CHECK(pSrcNbBuffer == pResBuffer);

            if (!pResBuffer)
            {
                return NULL;
            }
        }

        OVS_CHECK(pBuffer);
        RtlCopyMemory(pBuffer, pSrcNbBuffer, nbLen);

        KFree(pResBuffer);

        pResBuffer = NULL;
    }

    pDuplicateNbl->SourceHandle = pSwitchInfo->filterHandle;

    status = pSwitchInfo->switchHandlers.AllocateNetBufferListForwardingContext(pSwitchInfo->switchContext, pDuplicateNbl);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);

        //TODO: free pDuplicateNb
        return NULL;
    }

    status = pSwitchInfo->switchHandlers.CopyNetBufferListInfo(pSwitchInfo->switchContext, pDuplicateNbl, pNbl, 0);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);

        //TODO: free pDuplicateNb
        return NULL;
    }

    return pDuplicateNbl;
}

_Use_decl_annotations_
VOID FreeDuplicateNbl(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER* pNb = NULL, *pNextNb = NULL;
    MDL* pMdl = NULL;
    VOID* buffer = NULL;

    pSwitchInfo->switchHandlers.FreeNetBufferListForwardingContext(pSwitchInfo->switchContext, pNbl);

    for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = pNextNb)
    {
        pNextNb = NET_BUFFER_NEXT_NB(pNb);
        pMdl = NET_BUFFER_CURRENT_MDL(pNb);

        OVS_CHECK(pMdl->Next == NULL);

        buffer = MmGetMdlVirtualAddress(pMdl);
        KFree(buffer);

        IoFreeMdl(pMdl);
        NdisFreeNetBuffer(pNb);
    }

    NdisFreeNetBufferList(pNbl);
}

VOID FreeClonedNblFragment(_In_ NET_BUFFER_LIST* pNbl, _In_ ULONG dataOffsetDelta)
{
    NdisAcquireSpinLock(&g_nbPoolLock);
    NdisFreeFragmentNetBufferList(pNbl, dataOffsetDelta, 0);
    NdisReleaseSpinLock(&g_nbPoolLock);
}

VOID FreeClonedNblNormal(_In_ NET_BUFFER_LIST* pNbl)
{
    NdisAcquireSpinLock(&g_nbPoolLock);
    NdisFreeCloneNetBufferList(pNbl, NDIS_CLONE_FLAGS_USE_ORIGINAL_MDLS);
    NdisReleaseSpinLock(&g_nbPoolLock);
}

/***************************/

//#define BUFFER_PRINT

#ifdef DBG

VOID DbgPrintMdl(MDL* pMdl)
{
#ifndef BUFFER_PRINT
    UNREFERENCED_PARAMETER(pMdl);
#else
    //UINT i = 0;
    BYTE* buffer = NULL;

    DEBUGP("MDL: 0x%x; count=%d; offset=%d;\nmdl data:", pMdl, MmGetMdlByteCount(pMdl), MmGetMdlByteOffset(pMdl));

    buffer = (BYTE*)MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
    OVS_CHECK(buffer);

    /*for (i = 0; i < MmGetMdlByteCount(pMdl); ++i)
    {
        if (i % 16 == 0)
        {
        DEBUGP("\n");
        }

        DEBUGP("%02x ", buffer[i]);
    }*/

    DEBUGP("\n--end MDL--\n");
#endif
}

static ULONG _CountMdls(NET_BUFFER* pNb)
{
    MDL* pMdl = NULL;
    UINT count = 0;

    for (pMdl = NET_BUFFER_CURRENT_MDL(pNb); pMdl != NULL; pMdl = pMdl->Next)
    {
        ++count;
    }

    return count;
}

VOID DbgPrintNb(NET_BUFFER* pNb, LPCSTR msg)
{
    //#ifndef BUFFER_PRINT
    //UNREFERENCED_PARAMETER(pNb);
    //UNREFERENCED_PARAMETER(msg);
    //#else
    //MDL* pMdl = NULL;
    BYTE* buffer = NULL, *bufferAlloc = NULL;
    ULONG bufPrintLen = 0;
    ULONG i = 0;

    if (msg)
    {
        DEBUGP(LOG_INFO, msg);
        DEBUGP(LOG_INFO, "----------");
    }

    DEBUGP(LOG_INFO, "NB: 0x%x; data len=%d; data offset=%d; cur mdl=0x%x; cur mdl offset=%d; count mdls=%d\n", pNb,
        NET_BUFFER_DATA_LENGTH(pNb), NET_BUFFER_DATA_OFFSET(pNb), NET_BUFFER_CURRENT_MDL(pNb), NET_BUFFER_CURRENT_MDL_OFFSET(pNb), _CountMdls(pNb));

    /*for (pMdl = NET_BUFFER_CURRENT_MDL(pNb); pMdl != NULL; pMdl = pMdl->Next)
    {
        DbgPrintMdl(pMdl);
    }*/

    //BYTE* NdisGetDataBuffer(pNb, NET_BUFFER_DATA_LENGTH(pNb), 0, 0, 1);

    bufPrintLen = min(NET_BUFFER_DATA_LENGTH(pNb), 256);

    buffer = (BYTE*)NdisGetDataBuffer(pNb, bufPrintLen, NULL, 1, 0);
    if (!buffer)
    {
        bufferAlloc = (BYTE*)KAlloc(bufPrintLen);

        buffer = (BYTE*)NdisGetDataBuffer(pNb, bufPrintLen, bufferAlloc, 1, 0);
        OVS_CHECK(buffer);
        if (!buffer)
        {
            return;
        }
    }

    for (i = 0; i < bufPrintLen; ++i)
    {
        if (i && i % 16 == 0)
        {
            DEBUGP(LOG_INFO, "\n");
        }

        DEBUGP(LOG_INFO, "%02x ", buffer[i]);
    }

    KFree(bufferAlloc);

    DEBUGP(LOG_INFO, "\n--end NB--\n");
}

static ULONG _CountNbs(NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER* pNb = NET_BUFFER_LIST_FIRST_NB(pNbl);
    UINT count = 0;

    while (pNb)
    {
        ++count;
        pNb = NET_BUFFER_NEXT_NB(pNb);
    }

    return count;
}

VOID DbgPrintMacMsg(OVS_ETHERNET_HEADER* pEth, const char* msg)
{
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(pEth);

    DEBUGP(LOG_INFO, "%s: mac address: %x.%x.%x.%x.%x.%x -> %x.%x.%x.%x.%x.%x; type: 0x%x\n", msg,
        pEth->source_addr[0], pEth->source_addr[1], pEth->source_addr[2],
        pEth->source_addr[3], pEth->source_addr[4], pEth->source_addr[5],

        pEth->destination_addr[0], pEth->destination_addr[1], pEth->destination_addr[2],
        pEth->destination_addr[3], pEth->destination_addr[4], pEth->destination_addr[5],

        RtlUshortByteSwap(pEth->type));
}

VOID DbgPrintMac(OVS_ETHERNET_HEADER* pEth)
{
    UNREFERENCED_PARAMETER(pEth);

    DEBUGP(LOG_INFO, "mac address: %x.%x.%x.%x.%x.%x -> %x.%x.%x.%x.%x.%x; type: 0x%x\n", pEth->source_addr[0], pEth->source_addr[1], pEth->source_addr[2],
        pEth->source_addr[3], pEth->source_addr[4], pEth->source_addr[5],

        pEth->destination_addr[0], pEth->destination_addr[1], pEth->destination_addr[2],
        pEth->destination_addr[3], pEth->destination_addr[4], pEth->destination_addr[5],

        RtlUshortByteSwap(pEth->type));
}

VOID DbgPrintNbl(NET_BUFFER_LIST* pNbl, LPCSTR msg)
{
#ifndef BUFFER_PRINT
    UNREFERENCED_PARAMETER(pNbl);
    UNREFERENCED_PARAMETER(msg);
#else
    NET_BUFFER* pNb = NULL;

    if (msg)
    {
        DEBUGP(msg);
        DEBUGP("----------");
    }

    DEBUGP("NBL: 0x%x; context=0x%x; context data start=0x%x; context data size=%d\n; count nbs:%d\n", pNbl,
        pNbl->Context, NET_BUFFER_LIST_CONTEXT_DATA_START(pNbl), NET_BUFFER_LIST_CONTEXT_DATA_SIZE(pNbl), _CountNbs(pNbl));

    for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        DbgPrintNb(pNb, NULL);
    }

    DEBUGP("\n--end NB--\n");
#endif
}

VOID DbgPrintNblCount(NET_BUFFER_LIST* pNbl)
{
    UINT count = CountNbls(pNbl);

    UNREFERENCED_PARAMETER(count);

    DEBUGP(LOG_LOUD, "count nbls: %d\n", count);
}

VOID DbgPrintNbCount(NET_BUFFER_LIST* pNbl)
{
    UINT count = CountNbs(pNbl);

    UNREFERENCED_PARAMETER(count);

    DEBUGP(LOG_LOUD, "count nbs: %d\n", count);
}

VOID DbgPrintNblList(NET_BUFFER_LIST* pNbl)
{
    DEBUGP(LOG_LOUD, "NBL list: ");

    while (pNbl != NULL)
    {
        DEBUGP(LOG_LOUD, "%p -> ", pNbl);
        pNbl = NET_BUFFER_LIST_NEXT_NBL(pNbl);
    }

    DEBUGP(LOG_LOUD, "NULL\n");
}

#endif //DBG

const char* Ipv4ProtoToString(UINT8 proto)
{
    switch (proto)
    {
    case OVS_IPPROTO_ICMP: return "ICMP";
    case OVS_IPPROTO_IGMP: return "IGMP";
    case OVS_IPPROTO_TCP: return "TCP";
    case OVS_IPPROTO_UDP: return "UDP";
    case OVS_IPPROTO_GRE: return "GRE";
    default:
        OVS_CHECK(0);
    }

    return "";
}

const char* Ipv6NextHeaderToString(UINT8 nextHeader)
{
    switch (nextHeader)
    {
    case OVS_IPV6_EXTH_HOPBYHOP: return "Hop-By-Hop Options Extension Header";
    case OVS_IPV6_EXTH_ICMP4: return "ICMPv4";
    case OVS_IPV6_EXTH_IGMP4: return "IGMPv4";
    case OVS_IPV6_EXTH_IPIP: return "IP in IP Encapsulation";
    case OVS_IPV6_EXTH_TCP: return "TCP";
    case OVS_IPV6_EXTH_EGP: return "EGP";
    case OVS_IPV6_EXTH_UDP: return "UDP";
    case OVS_IPV6_EXTH_IP6: return "IPv6";
    case OVS_IPV6_EXTH_ROUTING: return "Routing Extension Header";
    case OVS_IPV6_EXTH_FRAGMENTATION: return "Fragmentation Extension Header";
    case OVS_IPV6_EXTH_RSVP: return "Resource Reservation Protocol (RSVP)";
    case OVS_IPV6_EXTH_ESP: return "Encrypted Security Payload (ESP) Extension Header";
    case OVS_IPV6_EXTH_AH: return "Authentication Header (AH) Extension Header";
    case OVS_IPV6_EXTH_ICMP6: return "ICMPv6";
    case OVS_IPV6_EXTH_NONE: return "No Next Header";
    case OVS_IPV6_EXTH_DESTINATION_OPTS: return "Destination Options Extension Header";
    default:
        OVS_CHECK(0);
    }

    return "";
}

#ifdef DBG
_Use_decl_annotations_
void DbgPrintIpv4(const OVS_IPV4_HEADER* pIpv4Header)
{
    UNREFERENCED_PARAMETER(pIpv4Header);

    DEBUGP(LOG_INFO, "ip: %d.%d.%d.%d -> %d.%d.%d.%d; proto: %s; IHL: %d; TL: %d\n",
        pIpv4Header->SourceAddress.S_un.S_un_b.s_b1,
        pIpv4Header->SourceAddress.S_un.S_un_b.s_b2,
        pIpv4Header->SourceAddress.S_un.S_un_b.s_b3,
        pIpv4Header->SourceAddress.S_un.S_un_b.s_b4,

        pIpv4Header->DestinationAddress.S_un.S_un_b.s_b1,
        pIpv4Header->DestinationAddress.S_un.S_un_b.s_b2,
        pIpv4Header->DestinationAddress.S_un.S_un_b.s_b3,
        pIpv4Header->DestinationAddress.S_un.S_un_b.s_b4,

        Ipv4ProtoToString(pIpv4Header->Protocol),

        pIpv4Header->HeaderLength,
        RtlUshortByteSwap(pIpv4Header->TotalLength));
}

void DbgPrintIpv6(OVS_IPV6_HEADER* pIpv6Header)
{
    UNREFERENCED_PARAMETER(pIpv6Header);

    DEBUGP(LOG_INFO, "ip6: %x:%x:%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x:%x:%x; next header: %s\n",
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[0]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[1]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[2]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[3]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[4]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[5]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[6]),
        RtlUshortByteSwap(pIpv6Header->sourceAddress.u.Word[7]),

        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[0]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[1]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[2]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[3]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[4]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[5]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[6]),
        RtlUshortByteSwap(pIpv6Header->destinationAddress.u.Word[7]),

        Ipv6NextHeaderToString(pIpv6Header->nextHeader));
}
#endif

void DbgPrintArp(OVS_ARP_HEADER* pArpHeader)
{
    OVS_CHECK(pArpHeader);

    if (RtlUshortByteSwap(pArpHeader->operation) == 1)
    {
        DEBUGP(LOG_INFO, "ARP request: from mac = %02x-%02x-%02x-%02x-%02x-%02x; ip = %d.%d.%d.%d: who has %d.%d.%d.%d?\n",
            pArpHeader->senderHardwareAddress[0],
            pArpHeader->senderHardwareAddress[1],
            pArpHeader->senderHardwareAddress[2],
            pArpHeader->senderHardwareAddress[3],
            pArpHeader->senderHardwareAddress[4],
            pArpHeader->senderHardwareAddress[5],

            pArpHeader->senderProtocolAddress[0],
            pArpHeader->senderProtocolAddress[1],
            pArpHeader->senderProtocolAddress[2],
            pArpHeader->senderProtocolAddress[3],

            pArpHeader->targetProtocolAddress[0],
            pArpHeader->targetProtocolAddress[1],
            pArpHeader->targetProtocolAddress[2],
            pArpHeader->targetProtocolAddress[3]);
    }
    else
    {
        OVS_CHECK(RtlUshortByteSwap(pArpHeader->operation) == 2);

        DEBUGP(LOG_INFO, "ARP reply: from mac = %02x-%02x-%02x-%02x-%02x-%02x; ip = %d.%d.%d.%d; target: mac = %02x-%02x-%02x-%02x-%02x-%02x; ip = %d.%d.%d.%d\n",
            pArpHeader->senderHardwareAddress[0],
            pArpHeader->senderHardwareAddress[1],
            pArpHeader->senderHardwareAddress[2],
            pArpHeader->senderHardwareAddress[3],
            pArpHeader->senderHardwareAddress[4],
            pArpHeader->senderHardwareAddress[5],

            pArpHeader->senderProtocolAddress[0],
            pArpHeader->senderProtocolAddress[1],
            pArpHeader->senderProtocolAddress[2],
            pArpHeader->senderProtocolAddress[3],

            pArpHeader->targetHardwareAddress[0],
            pArpHeader->targetHardwareAddress[1],
            pArpHeader->targetHardwareAddress[2],
            pArpHeader->targetHardwareAddress[3],
            pArpHeader->targetHardwareAddress[4],
            pArpHeader->targetHardwareAddress[5],

            pArpHeader->targetProtocolAddress[0],
            pArpHeader->targetProtocolAddress[1],
            pArpHeader->targetProtocolAddress[2],
            pArpHeader->targetProtocolAddress[3]);
    }
}

static BOOLEAN _VerifyTransportHeader(VOID* buffer, ULONG* pLength, UINT16 ethType, BYTE protoType);

BOOLEAN VerifyProtocolHeader(BYTE* buffer, ULONG* pLength, UINT16* pEthType)
{
    BYTE* nextHeader = NULL;
    BYTE protoType = 0;

    switch (RtlUshortByteSwap(*pEthType))
    {
    case OVS_ETHERTYPE_ARP:
    case OVS_ETHERTYPE_RARP:
        nextHeader = VerifyArpFrame(buffer, pLength);
        if (!nextHeader)
        {
            return FALSE;
        }

        if (*pLength > 0)
        {
            /*DEBUGP(LOG_ERROR, "size left=0x%x > 0", *pLength);
            return FALSE;*/
        }

        break;

    case OVS_ETHERTYPE_IPV4:
    {
        OVS_IPV4_HEADER* pIpv4Header = (OVS_IPV4_HEADER*)buffer;
        UINT16 offset = 0;

        nextHeader = VerifyIpv4Frame(buffer, pLength, &protoType);
        if (!nextHeader)
        {
            return FALSE;
        }

        offset = Ipv4_GetFragmentOffset(pIpv4Header);

        if (offset == 0)
        {
            if (!_VerifyTransportHeader(nextHeader, pLength, *pEthType, protoType))
            {
                return FALSE;
            }
        }
    }
        break;

    case OVS_ETHERTYPE_IPV6:
        nextHeader = VerifyIpv6Frame(buffer, pLength, &protoType);
        if (!nextHeader)
        {
            return FALSE;
        }

        if (!_VerifyTransportHeader(nextHeader, pLength, *pEthType, protoType))
        {
            return FALSE;
        }

        break;

    case OVS_ETHERTYPE_QTAG:
        //should never be qtag: VerifyEthernetFrame must return the client eth type
        OVS_CHECK(0);
        break;

    default:
        DEBUGP(LOG_ERROR, "invalid / unknown eth type: 0x%x", RtlUshortByteSwap(*pEthType));
    }

    return TRUE;
}

static BOOLEAN _VerifyTransportHeader(VOID* buffer, ULONG* pLength, UINT16 ethType, BYTE protoType)
{
    BYTE* advancedBuffer = buffer;

    if (IsIpv6Extension(protoType))
    {
        advancedBuffer = VerifyIpv6Extension(buffer, pLength, &protoType);
        if (!advancedBuffer)
        {
            return FALSE;
        }
    }

    switch (protoType)
    {
    case OVS_IPPROTO_GRE:
        advancedBuffer = VerifyGreHeader(advancedBuffer, pLength, &ethType);
        if (!advancedBuffer)
        {
            return FALSE;
        }

        return VerifyProtocolHeader(advancedBuffer, pLength, &ethType);

    case OVS_IPPROTO_ICMP:
        if (RtlUshortByteSwap(ethType) != OVS_ETHERTYPE_IPV4)
        {
            DEBUGP(LOG_ERROR, "ethtype=0x%x. Only ipv4 should have proto=icmp", RtlUshortByteSwap(ethType));
            return FALSE;
        }

        if (!VerifyIcmpHeader(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;

    case OVS_IPV6_EXTH_ICMP6:
        if (RtlUshortByteSwap(ethType) != OVS_ETHERTYPE_IPV6)
        {
            DEBUGP(LOG_ERROR, "ethtype=0x%x. Only ipv6 should have proto=icmp6", RtlUshortByteSwap(ethType));
            return FALSE;
        }

        if (!VerifyIcmp6Header(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;

    case OVS_IPPROTO_IGMP:
        if (!VerifyIgmpHeader(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;

    case OVS_IPPROTO_SCTP:
        if (!VerifySctpHeader(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;

    case OVS_IPPROTO_TCP:
        if (!VerifyTcpHeader(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;

    case OVS_IPPROTO_UDP:
        if (!VerifyTcpHeader(advancedBuffer, pLength))
        {
            return FALSE;
        }

        break;
    }

    return TRUE;
}

BOOLEAN VerifyNetBuffer(VOID* buffer, ULONG length)
{
    BYTE* nextHeader = NULL;
    ULONG sizeLeft = length;
    UINT16 ethType = 0;

    nextHeader = VerifyEthernetFrame(buffer, &sizeLeft, &ethType);

    if (!nextHeader)
    {
        return FALSE;
    }

    return VerifyProtocolHeader(nextHeader, &length, &ethType);
}

NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* GetChecksumOffloadInfo(_In_ NET_BUFFER_LIST* pNbl)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pTcpIpChecksumNetBufferListInfo =
        (NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO*)&(NET_BUFFER_LIST_INFO(pNbl, TcpIpChecksumNetBufferListInfo));

    return pTcpIpChecksumNetBufferListInfo;
}

VOID DbgPrintNblInfo(NET_BUFFER_LIST* pNbl)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pTcpIpChecksumNetBufferListInfo = NULL;
    ULONG tcpOffloadBytesTransferred = 0;
    NDIS_IPSEC_OFFLOAD_V1_NET_BUFFER_LIST_INFO* pIPsecOffloadV1NetBufferListInfo = NULL;
    NDIS_IPSEC_OFFLOAD_V2_NET_BUFFER_LIST_INFO* pIPsecOffloadV2NetBufferListInfo = NULL;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO* pTcpLargeSendNetBufferListInfo = NULL;
    BOOLEAN tcpReceiveNoPush = FALSE;
    VOID* pIeee8021QNetBufferListInfoValue = NULL;
    ULONG_PTR netBufferListCancelId = 0;
    VOID* pMediaSpecificInformation = NULL;
    USHORT netBufferListFrameType = 0;
    UCHAR netBufferListProtocolId = 0;
    ULONG netBufferListHashValue = 0;
    ULONG netBufferListHashInfo = 0;
    NDIS_IPSEC_OFFLOAD_V2_TUNNEL_NET_BUFFER_LIST_INFO* pIPsecOffloadV2TunnelNetBufferListInfo = NULL;
    NDIS_IPSEC_OFFLOAD_V2_HEADER_NET_BUFFER_LIST_INFO* pIPsecOffloadV2HeaderNetBufferListInfo = NULL;
    NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pSwitchForwardingDetail = NULL;
    NDIS_NET_BUFFER_LIST_FILTERING_INFO* pNetBufferListFilteringInfo = NULL;
    ULONG tcpReceiveBytesTransferred = 0;
    NDIS_NET_BUFFER_LIST_VIRTUAL_SUBNET_INFO* pVirtualSubnetInfo = NULL;
    NDIS_RSC_NBL_INFO* pTcpRecvSegCoalesceInfo = NULL;
    NDIS_RSC_NBL_INFO* pRscTcpTimestampDelta = NULL;
    NDIS_TCP_SEND_OFFLOADS_SUPPLEMENTAL_NET_BUFFER_LIST_INFO* pTcpSendOffloadsSupplementalNetBufferListInfo = NULL;

    // = pTcpOffloadBytesTransferred
    pTcpIpChecksumNetBufferListInfo = (NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, TcpIpChecksumNetBufferListInfo));
    if (pTcpIpChecksumNetBufferListInfo->Value)
    {
        DEBUGP(LOG_INFO, "have tcp checksum offload\n");//TcpHeaderOffset
    }

    //= pTcpIpChecksumNetBufferListInfo
    tcpOffloadBytesTransferred = (ULONG)NET_BUFFER_LIST_INFO(pNbl, TcpOffloadBytesTransferred);
    if (tcpOffloadBytesTransferred)
    {
        DEBUGP(LOG_INFO, "have tcp checksum offload bytes transferred\n");
    }

    //= pIPsecOffloadV2NetBufferListInfo
    pIPsecOffloadV1NetBufferListInfo = (NDIS_IPSEC_OFFLOAD_V1_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, IPsecOffloadV1NetBufferListInfo));
    if (pIPsecOffloadV1NetBufferListInfo->Transmit.OffloadHandle)
    {
        DEBUGP(LOG_INFO, "have ipsec offload v1\n");
    }

    //=IPsecOffloadV1NetBufferListInfo
    pIPsecOffloadV2NetBufferListInfo = (NDIS_IPSEC_OFFLOAD_V2_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, IPsecOffloadV2NetBufferListInfo));
    if (pIPsecOffloadV1NetBufferListInfo->Transmit.OffloadHandle)
    {
        DEBUGP(LOG_INFO, "have ipsec offload v2\n");
    }

    //= pTcpReceiveNoPush
    pTcpLargeSendNetBufferListInfo = (NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, TcpLargeSendNetBufferListInfo));
    if (pTcpLargeSendNetBufferListInfo->Value)
    {
        DEBUGP(LOG_INFO, "have tcp LSO\n");
    }

    //= pTcpLargeSendNetBufferListInfo
    tcpReceiveNoPush = (BOOLEAN)(ULONG)NET_BUFFER_LIST_INFO(pNbl, TcpReceiveNoPush);
    if (tcpReceiveNoPush)
    {
        DEBUGP(LOG_INFO, "have tcp receive no push\n");
    }

    //returns the Value member of an NDIS_NET_BUFFER_LIST_8021Q_INFO structure
    pIeee8021QNetBufferListInfoValue = NET_BUFFER_LIST_INFO(pNbl, Ieee8021QNetBufferListInfo);
    if (pIeee8021QNetBufferListInfoValue)
    {
        DEBUGP(LOG_INFO, "have 802.1q\n");
    }

    netBufferListCancelId = (ULONG_PTR)NET_BUFFER_LIST_INFO(pNbl, NetBufferListCancelId);
    if (netBufferListCancelId)
    {
        DEBUGP(LOG_INFO, "have cancel id\n");
    }

    //VOID*
    pMediaSpecificInformation = NET_BUFFER_LIST_INFO(pNbl, MediaSpecificInformation);
    if (pMediaSpecificInformation)
    {
        DEBUGP(LOG_INFO, "have media specific info\n");
    }

    //= pNetBufferListProtocolId
    netBufferListFrameType = (USHORT)(ULONG)NET_BUFFER_LIST_INFO(pNbl, NetBufferListFrameType);
    if (netBufferListFrameType)
    {
        DEBUGP(LOG_INFO, "have frame type\n");
    }

    //= pNetBufferListFrameType
    netBufferListProtocolId = (UCHAR)(ULONG)NET_BUFFER_LIST_INFO(pNbl, NetBufferListProtocolId);
    if (netBufferListProtocolId)
    {
        switch (netBufferListProtocolId)
        {
        case NDIS_PROTOCOL_ID_DEFAULT:
            DEBUGP(LOG_INFO, "have proto id: default\n");
            break;

        case NDIS_PROTOCOL_ID_TCP_IP:
            DEBUGP(LOG_INFO, "have proto id: tcp/ip\n");
            break;

        case NDIS_PROTOCOL_ID_IPX:
            DEBUGP(LOG_INFO, "have proto id: ipx\n");
            break;

        case NDIS_PROTOCOL_ID_NBF:
            DEBUGP(LOG_INFO, "have proto id: nbf\n");
            break;

        default:
            DEBUGP(LOG_INFO, "have proto id: <invalid>\n");
            break;
        }
    }

    netBufferListHashValue = (ULONG)NET_BUFFER_LIST_INFO(pNbl, NetBufferListHashValue);
    if (netBufferListHashValue)
    {
        DEBUGP(LOG_INFO, "have hash value\n");
    }

    netBufferListHashInfo = (ULONG)NET_BUFFER_LIST_INFO(pNbl, NetBufferListHashInfo);
    if (netBufferListHashInfo)
    {
        DEBUGP(LOG_INFO, "have hash info\n");
    }

    pIPsecOffloadV2TunnelNetBufferListInfo = (NDIS_IPSEC_OFFLOAD_V2_TUNNEL_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, IPsecOffloadV2TunnelNetBufferListInfo));
    if (pIPsecOffloadV2TunnelNetBufferListInfo->Transmit.TunnelHandle)
    {
        DEBUGP(LOG_INFO, "have ipsec offload v2 tunnel\n");
    }

    pIPsecOffloadV2HeaderNetBufferListInfo = (NDIS_IPSEC_OFFLOAD_V2_HEADER_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, IPsecOffloadV2HeaderNetBufferListInfo));
    if (*(UINT64*)pIPsecOffloadV2HeaderNetBufferListInfo)
    {
        DEBUGP(LOG_INFO, "have ipsec offload v2 header\n");
    }

    pNetBufferListFilteringInfo = (NDIS_NET_BUFFER_LIST_FILTERING_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, NetBufferListFilteringInfo));
    if (pNetBufferListFilteringInfo->Value)
    {
        DEBUGP(LOG_INFO, "have filtering info\n");
    }

    tcpReceiveBytesTransferred = (ULONG)NET_BUFFER_LIST_INFO(pNbl, TcpReceiveBytesTransferred);
    if (tcpReceiveBytesTransferred)
    {
        DEBUGP(LOG_INFO, "have tcp receive bytes transferred\n");
    }

    //ptr to driver allocated
    pSwitchForwardingDetail = (NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, SwitchForwardingDetail));
    if (pSwitchForwardingDetail->AsUINT64)
    {
        DEBUGP(LOG_INFO, "have switch fwd detail\n");
    }

    //ptr to driver allocated
    pVirtualSubnetInfo = (NDIS_NET_BUFFER_LIST_VIRTUAL_SUBNET_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, VirtualSubnetInfo));
    if (pVirtualSubnetInfo->Value)
    {
        DEBUGP(LOG_INFO, "have virtual subnet info\n");
    }

    //ptr to driver allocated
    pTcpRecvSegCoalesceInfo = (NDIS_RSC_NBL_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, TcpRecvSegCoalesceInfo));
    if (pTcpRecvSegCoalesceInfo->Value)
    {
        DEBUGP(LOG_INFO, "have tcp recv seg coalesce\n");
    }

    //ptr to driver allocated
    pRscTcpTimestampDelta = (NDIS_RSC_NBL_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, RscTcpTimestampDelta));
    if (pRscTcpTimestampDelta->Value)
    {
        DEBUGP(LOG_INFO, "have rsc tcp timestamp delta\n");
    }

    //ptr to driver allocated
    pTcpSendOffloadsSupplementalNetBufferListInfo = (NDIS_TCP_SEND_OFFLOADS_SUPPLEMENTAL_NET_BUFFER_LIST_INFO*)
        &(NET_BUFFER_LIST_INFO(pNbl, TcpSendOffloadsSupplementalNetBufferListInfo));
    if (pTcpSendOffloadsSupplementalNetBufferListInfo->Value)
    {
        DEBUGP(LOG_INFO, "have tcp send offload supplemental\n");
    }
}