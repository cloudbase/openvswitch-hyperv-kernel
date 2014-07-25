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

#include "OFFlow.h"
#include "Nbls.h"
#include "Frame.h"
#include "Tcp.h"
#include "Udp.h"
#include "Sctp.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Arp.h"
#include "List.h"
#include "Types.h"
#include "PacketInfo.h"
#include "OFDatapath.h"
#include "OvsCore.h"
#include "WinlFlow.h"
#include "OFAction.h"
#include "OvsNetBuffer.h"
#include "WinlDevice.h"
#include "Argument.h"
#include "Gre.h"
#include "Checksum.h"
#include "OFFlowTable.h"

#include "PersistentPort.h"

#include <ntstrsafe.h>

/***********************************************/

VOID FlowMask_DeleteReference(OVS_FLOW_MASK* pFlowMask)
{
    if (!pFlowMask)
    {
        return;
    }

    OVS_CHECK(pFlowMask->refCount);
    pFlowMask->refCount--;

    if (!pFlowMask->refCount)
    {
        RemoveEntryList(&pFlowMask->listEntry);

        KFree(pFlowMask);
    }
}

VOID Flow_DestroyNow_Unsafe(OVS_FLOW* pFlow)
{
    if (!pFlow)
    {
        return;
    }

    FlowMask_DeleteReference(pFlow->pMask);

    OVS_REFCOUNT_DESTROY(pFlow->pActions);

    KFree(pFlow);
}

void FlowMatch_Initialize(OVS_FLOW_MATCH* pFlowMatch, OVS_OFPACKET_INFO* pPacketInfo, OVS_FLOW_MASK* pFlowMask)
{
    RtlZeroMemory(pFlowMatch, sizeof(OVS_FLOW_MATCH));
    RtlZeroMemory(pPacketInfo, sizeof(OVS_OFPACKET_INFO));

    pPacketInfo->physical.ovsInPort = OVS_INVALID_PORT_NUMBER;

    pFlowMatch->pPacketInfo = pPacketInfo;
    pFlowMatch->pFlowMask = pFlowMask;

    if (pFlowMask)
    {
        memset(&pFlowMask->packetInfo, OVS_PI_MASK_MATCH_WILDCARD(UINT8), sizeof(OVS_OFPACKET_INFO));
        pFlowMask->piRange.startRange = pFlowMask->piRange.endRange = 0;
    }
}

OVS_FLOW* Flow_Create()
{
    OVS_FLOW* pFlow = NULL;

    pFlow = KZAlloc(sizeof(OVS_FLOW));
    if (!pFlow)
    {
        return NULL;
    }

    pFlow->statsArray = KZAlloc(1 * sizeof(OVS_FLOW_STATS));
    if (!pFlow->statsArray)
    {
        KFree(pFlow);
        return NULL;
    }

    pFlow->pRwLock = NdisAllocateRWLock(NULL);
    pFlow->refCount.Destroy = Flow_DestroyNow_Unsafe;

    return pFlow;
}

void Flow_ClearStats_Unsafe(OVS_FLOW* pFlow)
{
#if OVS_VERSION == OVS_VERSION_1_11
    pFlow->stats.lastUsedTime = 0;
    pFlow->stats.tcpFlags = 0;
    pFlow->stats.packetsMached = 0;
    pFlow->stats.bytesMatched = 0;
#elif OVS_VERSION >= OVS_VERSION_2_3

    USHORT maxNodeNumber = 0;

    maxNodeNumber = KeQueryHighestNodeNumber();
    OVS_CHECK(maxNodeNumber == 0);

    for (USHORT i = 0; i <= maxNodeNumber; ++i)
    {
        OVS_FLOW_STATS* pFlowStats = NULL;

        pFlowStats = pFlow->statsArray[i];

        if (pFlowStats)
            RtlZeroMemory(pFlowStats, sizeof(OVS_FLOW_STATS));
    }

#endif
}

BOOLEAN FlowMask_Equal(const OVS_FLOW_MASK* pLhs, const OVS_FLOW_MASK* pRhs)
{
    UINT8* pLeftPI = (UINT8*)&pLhs->packetInfo + pLhs->piRange.startRange;
    UINT8* pRightPI = (UINT8*)&pRhs->packetInfo + pRhs->piRange.startRange;
    UINT16 piSize = (UINT16)(pLhs->piRange.endRange - pLhs->piRange.startRange);
    BOOLEAN isEqual = FALSE;

    if (pLhs->piRange.endRange != pRhs->piRange.endRange ||
        pLhs->piRange.startRange != pRhs->piRange.startRange)
    {
        return FALSE;
    }

    isEqual = (RtlCompareMemory(pLeftPI, pRightPI, piSize) == piSize);

    return isEqual;
}

OVS_FLOW_MASK* FlowMask_Create()
{
    OVS_FLOW_MASK* pFlowMask = NULL;

    pFlowMask = KZAlloc(sizeof(OVS_FLOW_MASK));
    if (!pFlowMask)
    {
        return NULL;
    }

    return pFlowMask;
}

#if OVS_VERSION == OVS_VERSION_1_11

void Flow_UpdateTimeUsed_Unsafe(OVS_FLOW* pFlow, OVS_NET_BUFFER* pOvsNb)
{
    UINT8 tcpFlags = 0;
    ULONG bufferLen = 0;

    if (pFlow->maskedPacketInfo.ipInfo.protocol == OVS_IPPROTO_TCP &&
        (pFlow->maskedPacketInfo.ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) ||
        pFlow->maskedPacketInfo.ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6)))
    {
        VOID* buffer = ONB_GetData(pOvsNb);

        OVS_TCP_HEADER* pTcpHeader = GetTcpHeader(buffer);
        tcpFlags = (UINT8)GetTcpFlags(pTcpHeader->flagsAndOffset);
    }

    bufferLen = ONB_GetDataLength(pOvsNb);

    //NdisAcquireSpinLock(&pFlow->spinLock);
    pFlow->stats.packetsMached++;
    pFlow->stats.bytesMatched += bufferLen;

    pFlow->stats.lastUsedTime = KeQueryPerformanceCounter(NULL).QuadPart;
    pFlow->stats.tcpFlags |= tcpFlags;

    //NdisReleaseSpinLock(&pFlow->spinLock);
}

#elif OVS_VERSION >= OVS_VERSION_2_3

void Flow_UpdateStats_Unsafe(OVS_FLOW* pFlow, OVS_NET_BUFFER* pOvsNb)
{
    OVS_FLOW_STATS* pFlowStats = NULL;
    USHORT numaNodeId = 0;
    ULONG bufferLen = 0;

    bufferLen = ONB_GetDataLength(pOvsNb);

    numaNodeId = KeGetCurrentNodeNumber();

    pFlowStats = pFlow->statsArray[numaNodeId];

    if (pFlowStats)
    {
        //TODO
    }

    else
    {
        //TODO
    }

    pFlowStats->packetsMached++;
    pFlowStats->bytesMatched += bufferLen;

    pFlowStats->lastUsedTime = KeQueryPerformanceCounter(NULL).QuadPart;
    pFlowStats->tcpFlags |= pOvsNb->pOriginalPacketInfo->tpInfo.tcpFlags;
}

void Flow_GetStats_Unsafe(_In_ const OVS_FLOW* pFlow, _Out_ OVS_FLOW_STATS* pFlowStats)
{
    USHORT maxNodeNumber = 0;

    pFlowStats->tcpFlags = 0;
    pFlowStats->lastUsedTime = 0;

    maxNodeNumber = KeQueryHighestNodeNumber();

    for (USHORT i = 0; i <= maxNodeNumber; ++i)
    {
        OVS_FLOW_STATS* pCurFlowStats = NULL;

        pCurFlowStats = pFlow->statsArray[i];

        if (pCurFlowStats)
        {
            UINT64 lastUsedTime = pFlowStats->lastUsedTime;

            pFlowStats->packetsMached += pCurFlowStats->packetsMached;
            pFlowStats->bytesMatched += pCurFlowStats->bytesMatched;

            pFlowStats->tcpFlags |= pCurFlowStats->tcpFlags;

            if (!lastUsedTime || pCurFlowStats->lastUsedTime > lastUsedTime)
            {
                pFlowStats->lastUsedTime = pCurFlowStats->lastUsedTime;
            }
        }
    }
}

#endif

#if OVS_DBGPRINT_FLOW

static void _DbgPrintFlow_Tunnel(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    BYTE* ip = NULL;
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    if (!pMask || pMask->tunnelInfo.ipv4Destination != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        ip = (BYTE*)&pPacketInfo->tunnelInfo.ipv4Destination;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_dst: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tunnelInfo.ipv4Source != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        ip = (BYTE*)&pPacketInfo->tunnelInfo.ipv4Source;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_src: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tunnelInfo.ipv4TimeToLive != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG ttl = pPacketInfo->tunnelInfo.ipv4TimeToLive;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_ttl: %u; ", ttl);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tunnelInfo.ipv4TypeOfService != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG tos = pPacketInfo->tunnelInfo.ipv4TypeOfService;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_tos: %u; ", tos);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tunnelInfo.tunnelFlags != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG tnlFlags = pPacketInfo->tunnelInfo.tunnelFlags;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_flags: 0x%x; ", tnlFlags);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tunnelInfo.tunnelId != OVS_PI_MASK_MATCH_WILDCARD(UINT64))
    {
        RtlStringCchPrintfA(tempDest, maxTempLen, "tnl_id: %016llx; ", pPacketInfo->tunnelInfo.tunnelId);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_Physical(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    if (!pMask || pMask->physical.ovsInPort != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG inPort = pPacketInfo->physical.ovsInPort;

        RtlStringCchPrintfA(tempDest, maxTempLen, "in_port: %u; ", inPort);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->physical.packetMark != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        ULONG mark = pPacketInfo->physical.packetMark;

        RtlStringCchPrintfA(tempDest, maxTempLen, "mark: %u; ", mark);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->physical.packetPriority != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        ULONG prio = pPacketInfo->physical.packetPriority;

        RtlStringCchPrintfA(tempDest, maxTempLen, "priority: %u; ", prio);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_Eth(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    BYTE exactMac[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    if (!pMask || !memcmp(pMask->ethInfo.destination, exactMac, OVS_ETHERNET_ADDRESS_LENGTH))
    {
        const BYTE* mac = pPacketInfo->ethInfo.destination;

        RtlStringCchPrintfA(tempDest, maxTempLen, "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x; ; ",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || !memcmp(pMask->ethInfo.source, exactMac, OVS_ETHERNET_ADDRESS_LENGTH))
    {
        const BYTE* mac = pPacketInfo->ethInfo.source;

        RtlStringCchPrintfA(tempDest, maxTempLen, "src_mac: %02x:%02x:%02x:%02x:%02x:%02x; ; ",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ethInfo.tci != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG tci = pPacketInfo->ethInfo.tci;

        RtlStringCchPrintfA(tempDest, maxTempLen, "vlan_tci: %u; ", tci);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ethInfo.type != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG ethType = RtlUshortByteSwap(pPacketInfo->ethInfo.type);

        RtlStringCchPrintfA(tempDest, maxTempLen, "eth_type: 0x%x; ", ethType);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_IpInfo(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    if (!pMask || pMask->ipInfo.fragment != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG frag = pPacketInfo->ipInfo.fragment;

        RtlStringCchPrintfA(tempDest, maxTempLen, "frag: %u; ", frag);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ipInfo.protocol != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG proto = pPacketInfo->ipInfo.protocol;

        RtlStringCchPrintfA(tempDest, maxTempLen, "proto: %u; ", proto);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ipInfo.timeToLive != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG ttl = pPacketInfo->ipInfo.timeToLive;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ttl: %u; ", ttl);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ipInfo.typeOfService != OVS_PI_MASK_MATCH_WILDCARD(UINT8))
    {
        ULONG tos = pPacketInfo->ipInfo.typeOfService;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tos: %u; ", tos);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_Arp(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    BYTE exactMac[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    if (!pMask || !memcmp(pMask->netProto.arpInfo.destinationMac, exactMac, OVS_ETHERNET_ADDRESS_LENGTH))
    {
        const BYTE* mac = pPacketInfo->netProto.arpInfo.destinationMac;

        RtlStringCchPrintfA(tempDest, maxTempLen, "arp_dest_mac: %02x:%02x:%02x:%02x:%02x:%02x; ; ",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || !memcmp(pMask->netProto.arpInfo.sourceMac, exactMac, OVS_ETHERNET_ADDRESS_LENGTH))
    {
        const BYTE* mac = pPacketInfo->netProto.arpInfo.sourceMac;

        RtlStringCchPrintfA(tempDest, maxTempLen, "arp_src_mac: %02x:%02x:%02x:%02x:%02x:%02x; ; ",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->netProto.arpInfo.destination.S_un.S_addr != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BYTE* ip = (BYTE*)&pPacketInfo->netProto.arpInfo.destination;

        RtlStringCchPrintfA(tempDest, maxTempLen, "arp_dst_ip: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->netProto.arpInfo.source.S_un.S_addr != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BYTE* ip = (BYTE*)&pPacketInfo->netProto.arpInfo.source;

        RtlStringCchPrintfA(tempDest, maxTempLen, "arp_src_ip: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_Ipv4(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    if (!pMask || pMask->netProto.ipv4Info.destination.S_un.S_addr != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BYTE* ip = (BYTE*)&pPacketInfo->netProto.ipv4Info.destination;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ipv4_dst_ip: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->netProto.ipv4Info.source.S_un.S_addr != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BYTE* ip = (BYTE*)&pPacketInfo->netProto.ipv4Info.source;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ipv4_src_ip: %u.%u.%u.%u; ", ip[0], ip[1], ip[2], ip[3]);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tpInfo.destinationPort != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG dstPort = pPacketInfo->tpInfo.destinationPort;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ipv4_dst_port: %u; ", dstPort);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->tpInfo.sourcePort != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        ULONG srcPort = pPacketInfo->tpInfo.sourcePort;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ipv4_src_port: %u; ", srcPort);
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    *pLen = len;
}

static void _DbgPrintFlow_Ipv6(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    //TODO
    UNREFERENCED_PARAMETER(pPacketInfo);
    UNREFERENCED_PARAMETER(pMask);
    UNREFERENCED_PARAMETER(maxLen);
    UNREFERENCED_PARAMETER(str);
    UNREFERENCED_PARAMETER(pLen);

    //DEBUGP(LOG_WARN, __FUNCTION__ " have no dbgprint for flow/ipv6!\n");
}

static void _DbgPrintFlow_Encap(_In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, _In_ ULONG maxLen, _Inout_ CHAR* str, _Inout_ size_t* pLen)
{
    size_t len = *pLen;

    enum { maxTempLen = 100 };
    CHAR tempDest[maxTempLen + 1];

    RtlStringCchCopyA(tempDest, maxTempLen, "encap: {");
    RtlStringCchCopyA(str + len, maxLen - len, tempDest);

    len += strlen(tempDest);

    if (!pMask || pMask->ethInfo.type != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BE16 ethType = pPacketInfo->ethInfo.type;

        RtlStringCchPrintfA(tempDest, maxTempLen, "ethType=%u; ", RtlUshortByteSwap(ethType));
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    if (!pMask || pMask->ethInfo.tci != OVS_PI_MASK_MATCH_WILDCARD(UINT32))
    {
        BE16 tci = pPacketInfo->ethInfo.tci;

        RtlStringCchPrintfA(tempDest, maxTempLen, "tci=%u; ", RtlUshortByteSwap(tci));
        RtlStringCchCopyA(str + len, maxLen - len, tempDest);

        len += strlen(tempDest);
    }

    RtlStringCchCopyA(tempDest, maxTempLen, "}");
    RtlStringCchCopyA(str + len, maxLen - len, tempDest);

    len += strlen(tempDest);

    *pLen = len;
}

static void _DbgPrintFlow_Set(_In_ const OVS_ARGUMENT_GROUP* pArgs, _In_ ULONG maxLen, _Inout_ CHAR* str)
{
    OVS_ARGUMENT* pArg;
    OVS_ARGTYPE argType = OVS_ARGTYPE_INVALID;
    CHAR tempStr[100];

    OVS_CHECK(pArgs->count == 1);

    pArg = pArgs->args;
    argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_DATAPATH_HASH:
    {
        UINT32 hash = GET_ARG_DATA(pArg, UINT32);
        RtlStringCchPrintfA(tempStr, 100, "dp hash=%u; ", hash);
        RtlStringCchCatA(str, maxLen, tempStr);
    }
        break;

    case OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID:
    {
        UINT32 id = GET_ARG_DATA(pArg, UINT32);
        RtlStringCchPrintfA(tempStr, 100, "dp recirc id=%u; ", id);
        RtlStringCchCatA(str, maxLen, tempStr);
    }
        break;

    case OVS_ARGTYPE_PI_PACKET_PRIORITY:
    {
        UINT32 priority = GET_ARG_DATA(pArg, UINT32);
        RtlStringCchPrintfA(tempStr, 100, "priority=%u; ", priority);
        RtlStringCchCatA(str, maxLen, tempStr);
    }
        break;

    case OVS_ARGTYPE_PI_PACKET_MARK:
    {
        UINT32 mark = GET_ARG_DATA(pArg, UINT32);
        RtlStringCchPrintfA(tempStr, 100, "mark=%u; ", mark);
        RtlStringCchCatA(str, maxLen, tempStr);
    }
        break;

    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
    {
        OF_PI_IPV4_TUNNEL* pTunnel = pArg->data;
        RtlStringCchPrintfA(tempStr, 100, "tunnel={id=%016llx,src=%u.%u.%u.%u, dst=%u.%u.%u.%u, tos=%u, ttl=%u, %flags=0x%x;}; ",
            pTunnel->tunnelId,
            OVS_IPV4_U32_TO_4_BYTES(pTunnel->ipv4Source), OVS_IPV4_U32_TO_4_BYTES(pTunnel->ipv4Destination),
            (UINT32)pTunnel->ipv4TypeOfService, (UINT32)pTunnel->ipv4TimeToLive, (UINT32)pTunnel->tunnelFlags);

        RtlStringCchCatA(str, maxLen, tempStr);
    }
        break;

    case OVS_ARGTYPE_PI_ETH_ADDRESS:
        RtlStringCchCatA(str, maxLen, "eth_addr; ");
        break;

    case OVS_ARGTYPE_PI_IPV4:
        RtlStringCchCatA(str, maxLen, "ipv4; ");
        break;

    case OVS_ARGTYPE_PI_IPV6:
        RtlStringCchCatA(str, maxLen, "ipv6; ");
        break;

    case OVS_ARGTYPE_PI_TCP:
        RtlStringCchCatA(str, maxLen, "tcp; ");
        break;

    case OVS_ARGTYPE_PI_UDP:
        RtlStringCchCatA(str, maxLen, "udp; ");
        break;

    case OVS_ARGTYPE_PI_SCTP:
        RtlStringCchCatA(str, maxLen, "sctp; ");
        break;

    case OVS_ARGTYPE_PI_MPLS:
        RtlStringCchCatA(str, maxLen, "mpls; ");
        break;

    default:
        OVS_CHECK(__UNEXPECTED__);
    }
}

void FlowWithActions_ToString(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions, CHAR str[501])
{
    enum { maxLen = 501 };
    size_t len = 0;
    CHAR sRange[50];

    str[0] = 0;

    OVS_CHECK(pPacketInfo);

    if (msg)
    {
        RtlStringCchCopyA(str, maxLen - 1, msg);
    }

    if (start != end)
    {
        RtlStringCchPrintfA(sRange, 49, "[%u-%u] ", start, end);
        RtlStringCchCatA(str, maxLen - 1, sRange);
    }

    len = strlen(str);

    _DbgPrintFlow_Tunnel(pPacketInfo, pMask, maxLen, str, &len);

    _DbgPrintFlow_Physical(pPacketInfo, pMask, maxLen, str, &len);

    _DbgPrintFlow_Eth(pPacketInfo, pMask, maxLen, str, &len);

    _DbgPrintFlow_IpInfo(pPacketInfo, pMask, maxLen, str, &len);

    //netproto
    switch (RtlUshortByteSwap(pPacketInfo->ethInfo.type))
    {
    case OVS_ETHERTYPE_ARP:
        _DbgPrintFlow_Arp(pPacketInfo, pMask, maxLen, str, &len);
        break;

    case OVS_ETHERTYPE_IPV4:
        _DbgPrintFlow_Ipv4(pPacketInfo, pMask, maxLen, str, &len);
        break;

    case OVS_ETHERTYPE_IPV6:
        _DbgPrintFlow_Ipv6(pPacketInfo, pMask, maxLen, str, &len);
        break;

    case OVS_ETHERTYPE_802_2:
        _DbgPrintFlow_Encap(pPacketInfo, pMask, maxLen, str, &len);
        break;

    default:
        OVS_CHECK(0);
        break;
    }

    if (pActions)
    {
        enum { tempStrSize = 100 };
        CHAR tempStr[tempStrSize + 1];

        RtlStringCchCatA(str, maxLen - 1, "actions: (");

        for (UINT i = 0; i < pActions->count; ++i)
        {
            OVS_ARGUMENT* pArg = pActions->args + i;
            OVS_ARGTYPE argType = pArg->type;

            switch (argType)
            {
            case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
            {
                UINT32 persPortNumber = GET_ARG_DATA(pArg, UINT32);

                RtlStringCchPrintfA(tempStr, tempStrSize, "out: %u; ", persPortNumber);

                RtlStringCchCatA(str, maxLen - 1, tempStr);
            }
                break;

            case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
                RtlStringCchCatA(str, maxLen - 1, "upcall; ");
                break;

            case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
                _DbgPrintFlow_Set(pArg->data, maxLen, str);
                break;

            case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
                RtlStringCchCatA(str, maxLen - 1, "sample; ");
                break;

            case OVS_ARGTYPE_ACTION_PUSH_VLAN:
                RtlStringCchCatA(str, maxLen - 1, "push vlan; ");
                break;

            case OVS_ARGTYPE_ACTION_POP_VLAN:
                RtlStringCchCatA(str, maxLen - 1, "pop vlan; ");
                break;

            case OVS_ARGTYPE_ACTION_PUSH_MPLS:
                RtlStringCchCatA(str, maxLen - 1, "push mpls; ");
                break;

            case OVS_ARGTYPE_ACTION_POP_MPLS:
                RtlStringCchCatA(str, maxLen - 1, "pop mpls; ");
                break;

            case OVS_ARGTYPE_ACTION_RECIRCULATION:
                RtlStringCchCatA(str, maxLen - 1, "recirc; ");
                break;

            case OVS_ARGTYPE_ACTION_HASH:
                RtlStringCchCatA(str, maxLen - 1, "hash; ");
                break;
            }
        }

        RtlStringCchCatA(str, maxLen - 1, " ) ");
    }

    RtlStringCchCatA(str, maxLen - 1, "\n");
}

void DbgPrintFlowWithActions(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions)
{
    enum { maxLen = 501 };
    CHAR str[maxLen] = { 0 };

    FlowWithActions_ToString(msg, pPacketInfo, pMask, start, end, pActions, str);

    DEBUGP(LOG_WARN, str);
}

void DbgPrintFlow(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end)
{
    DbgPrintFlowWithActions(msg, pPacketInfo, pMask, start, end, NULL);
}

void DbgPrintAllFlows()
{
    OVS_DATAPATH *pDatapath;
    OVS_FLOW_TABLE *pFlowTable;
    LOCK_STATE_EX lockState;
    UINT countMsgs = 0;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

    if (pFlowTable->countFlows > 0)
    {
        LIST_ENTRY* pCurItem = pFlowTable->pFlowList->Flink;
        UINT i = 0;

        countMsgs = pFlowTable->countFlows + 1;

        while (pCurItem != pFlowTable->pFlowList)
        {
            OVS_FLOW* pFlow = CONTAINING_RECORD(pCurItem, OVS_FLOW, listEntry);

            ULONG startRange = (ULONG)pFlow->pMask->piRange.startRange;
            ULONG endRange = (ULONG)pFlow->pMask->piRange.endRange;

            FLOW_LOCK_READ(pFlow, &lockState);
            DbgPrintFlowWithActions("flow dump: ", &pFlow->unmaskedPacketInfo, &pFlow->pMask->packetInfo, startRange, endRange, pFlow->pActions->pActionGroup);
            FLOW_UNLOCK(pFlow, &lockState);

            ++i;
            pCurItem = pCurItem->Flink;
        }
    }
    else
    {
        DEBUGP(LOG_INFO, "flow table empty!\n");
    }

    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);
}

#endif