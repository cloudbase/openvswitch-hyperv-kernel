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

#include "FlowToMessage.h"
#include "OFAction.h"
#include "Message.h"
#include "WinlFlow.h"

#include "OFDatapath.h"
#include "PacketInfo.h"

#include "Ipv6.h"
#include "Ipv4.h"
#include "Icmp.h"
#include "ArgumentType.h"
#include "PersistentPort.h"

static BOOLEAN _CreateIpv4Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_IPV4 ipv4PI = { 0 };

    ipv4PI.source = pPacketInfo->netProto.ipv4Info.source.S_un.S_addr;
    ipv4PI.destination = pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr;
    ipv4PI.protocol = pPacketInfo->ipInfo.protocol;
    ipv4PI.tos = pPacketInfo->ipInfo.typeOfService;
    ipv4PI.ttl = pPacketInfo->ipInfo.timeToLive;
    ipv4PI.fragmentType = pPacketInfo->ipInfo.fragment;

    if (!CreateArgInList(OVS_ARGTYPE_PI_IPV4, &ipv4PI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending ipv4 packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateIpv6Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_IPV6 ipv6PI = { 0 };

    RtlCopyMemory(ipv6PI.source, &pPacketInfo->netProto.ipv6Info.source, sizeof(ipv6PI.source));
    RtlCopyMemory(ipv6PI.destination, &pPacketInfo->netProto.ipv6Info.destination, sizeof(ipv6PI.destination));

    ipv6PI.label = pPacketInfo->netProto.ipv6Info.flowLabel;
    ipv6PI.protocol = pPacketInfo->ipInfo.protocol;
    ipv6PI.trafficClass = pPacketInfo->ipInfo.typeOfService;
    ipv6PI.highLimit = pPacketInfo->ipInfo.timeToLive;
    ipv6PI.fragmentType = pPacketInfo->ipInfo.fragment;

    if (!CreateArgInList(OVS_ARGTYPE_PI_IPV6, &ipv6PI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending ipv6 packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateArpArgs(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_ARP arpPI = { 0 };

    arpPI.sourceIp = pPacketInfo->netProto.ipv4Info.source.S_un.S_addr;
    arpPI.targetIp = pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr;
    arpPI.operation = RtlUshortByteSwap(pPacketInfo->ipInfo.protocol);

    RtlCopyMemory(arpPI.sourceMac, pPacketInfo->netProto.arpInfo.sourceMac, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(arpPI.targetMac, pPacketInfo->netProto.arpInfo.destinationMac, OVS_ETHERNET_ADDRESS_LENGTH);

    if (!CreateArgInList(OVS_ARGTYPE_PI_ARP, &arpPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending arp packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateTcpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_TCP tcpPI = { 0 };

    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IP4_INFO* pIpv4Info = (pMask ? &pMask->netProto.ipv4Info : &pPacketInfo->netProto.ipv4Info);

        tcpPI.source = pIpv4Info->sourcePort;
        tcpPI.destination = pIpv4Info->destinationPort;
    }
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        const OVS_IPV6_INFO* pIpv6Info = (pMask ? &pMask->netProto.ipv6Info : &pPacketInfo->netProto.ipv6Info);

        tcpPI.source = pIpv6Info->sourcePort;
        tcpPI.destination = pIpv6Info->destinationPort;
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_TCP, &tcpPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending tcp packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateUdpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_UDP udpPI = { 0 };

    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IP4_INFO* pIpv4Info = (pMask ? &pMask->netProto.ipv4Info : &pPacketInfo->netProto.ipv4Info);

        udpPI.source = pIpv4Info->sourcePort;
        udpPI.destination = pIpv4Info->destinationPort;
    }
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        const OVS_IPV6_INFO* pIpv6Info = (pMask ? &pMask->netProto.ipv6Info : &pPacketInfo->netProto.ipv6Info);

        udpPI.source = pIpv6Info->sourcePort;
        udpPI.destination = pIpv6Info->destinationPort;
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_UDP, &udpPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending udp packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateSctpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_SCTP sctpPI = { 0 };

    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IP4_INFO* pIpv4Info = (pMask ? &pMask->netProto.ipv4Info : &pPacketInfo->netProto.ipv4Info);

        sctpPI.source = pIpv4Info->sourcePort;
        sctpPI.destination = pIpv4Info->destinationPort;
    }
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        const OVS_IPV6_INFO* pIpv6Info = (pMask ? &pMask->netProto.ipv6Info : &pPacketInfo->netProto.ipv6Info);

        sctpPI.source = pIpv6Info->sourcePort;
        sctpPI.destination = pIpv6Info->destinationPort;
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_SCTP, &sctpPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending sctp packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateIcmp4Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_ICMP icmpPI = { 0 };

    icmpPI.type = (UINT8)RtlUshortByteSwap(pPacketInfo->netProto.ipv4Info.sourcePort);
    icmpPI.code = (UINT8)RtlUshortByteSwap(pPacketInfo->netProto.ipv4Info.destinationPort);

    if (!CreateArgInList(OVS_ARGTYPE_PI_ICMP, &icmpPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending icmp packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateIcmp6Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList, _Out_ OVS_PI_ICMP6* pIcmp6PI)
{
    OVS_CHECK(pIcmp6PI);

    pIcmp6PI->type = (UINT8)RtlUshortByteSwap(pPacketInfo->netProto.ipv6Info.sourcePort);
    pIcmp6PI->code = (UINT8)RtlUshortByteSwap(pPacketInfo->netProto.ipv6Info.destinationPort);

    if (!CreateArgInList(OVS_ARGTYPE_PI_ICMP6, pIcmp6PI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending icmp6 packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateIp6NeighborDiscoveryArgs(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_NEIGHBOR_DISCOVERY neighborDiscoveryPI = { 0 };

    RtlCopyMemory(neighborDiscoveryPI.targetIp, &pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp, sizeof(neighborDiscoveryPI.targetIp));
    RtlCopyMemory(neighborDiscoveryPI.sourceMac, pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndSourceMac, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(neighborDiscoveryPI.targetMac, pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetMac, OVS_ETHERNET_ADDRESS_LENGTH);

    if (!CreateArgInList(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY, &neighborDiscoveryPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending icmp6 nd packet info\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateArgsFromLayer3And4InList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    BOOLEAN ok = TRUE;
    const OVS_OFPACKET_INFO* pInfoToWrite = NULL;

    pInfoToWrite = (pMask ? pMask : pPacketInfo);

    //IPV4
    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        if (!_CreateIpv4Args(pInfoToWrite, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create ipv4 args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }
    //IPV6
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        if (!_CreateIpv6Args(pInfoToWrite, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create ipv6 args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }
    //ARP
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_ARP) ||
        pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_RARP))
    {
        if (!_CreateArpArgs(pInfoToWrite, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create arp args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }

    //TRANSPORT LAYER: AVAILABLE ONLY FOR IPV4 / IPV6 AND WHEN THE PACKET IS NOT FRAGMENTED
    if (pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) &&
        pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6) ||
        pPacketInfo->ipInfo.fragment == OVS_FRAGMENT_TYPE_FRAG_N)
    {
        return TRUE;
    }

    //TCP
    if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_TCP)
    {
        if (!_CreateTcpArgs(pPacketInfo, pMask, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create tcp args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }
    //UDP
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_UDP)
    {
        if (!_CreateUdpArgs(pPacketInfo, pMask, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create udp args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }
    //SCTP
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_SCTP)
    {
        if (!_CreateSctpArgs(pPacketInfo, pMask, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " create sctp args failed\n");
            ok = FALSE;
            return FALSE;
        }
    }
    //ICMP4
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_ICMP)
    {
        if ((pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4)))
        {
            if (!_CreateIcmp4Args(pInfoToWrite, ppArgList))
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " create icmp args failed\n");
                ok = FALSE;
                return FALSE;
            }
        }
    }
    //ICMP6 & ND
    else if (pPacketInfo->ipInfo.protocol == OVS_IPV6_EXTH_ICMP6)
    {
        if ((pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6)))
        {
            OVS_PI_ICMP6 icmp6PI = { 0 };

            //ICMP6
            if (!_CreateIcmp6Args(pInfoToWrite, ppArgList, &icmp6PI))
            {
                ok = FALSE;
                DEBUGP(LOG_ERROR, __FUNCTION__ " create icmp6 args failed\n");
                return FALSE;
            }

            //NET DISCOVERY
            if (icmp6PI.type == OVS_NDISC_NEIGHBOUR_SOLICITATION || icmp6PI.type == OVS_NDISC_NEIGHBOUR_ADVERTISEMENT)
            {
                if (!_CreateIp6NeighborDiscoveryArgs(pInfoToWrite, ppArgList))
                {
                    DEBUGP(LOG_ERROR, __FUNCTION__ " create icmp6 nd args failed\n");
                    ok = FALSE;
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}

static BOOLEAN _CreateActionsArgsToList(const OVS_ARGUMENT_GROUP* pArguments, OVS_ARGUMENT_SLIST_ENTRY** ppArgList);

static BOOLEAN _CreateActionsGroupToList(OVS_ARGTYPE groupType, const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT_SLIST_ENTRY* pCurListArg = NULL, *pHeadArg = NULL;
    OVS_ARGUMENT* pGroupArg = NULL;
    BOOLEAN ok = TRUE;

    pHeadArg = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pHeadArg)
    {
        return FALSE;
    }

    pCurListArg = pHeadArg;
    ok = _CreateActionsArgsToList(pArgGroup, &pCurListArg);
    if (!ok)
    {
        return FALSE;
    }

    pGroupArg = CreateGroupArgFromList(groupType, &pHeadArg);
    if (!pGroupArg)
    {
        KFree(pHeadArg);
        return FALSE;
    }

    ok = AppendArgumentToList(pGroupArg, ppArgList);
    if (!ok)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _SampleActionToList(const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    BOOLEAN ok = TRUE;

    OVS_ARGUMENT_SLIST_ENTRY* pCurListArg = NULL, *pHeadArg = NULL;

    pHeadArg = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pHeadArg)
    {
        return FALSE;
    }

    pCurListArg = pHeadArg;
    OVS_ARGUMENT* pGroupArg = NULL;

    for (UINT i = 0; i < pArgGroup->count; ++i)
    {
        const OVS_ARGUMENT* pArg = pArgGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
            if (!CreateArgInList_WithSize(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY, pArg->data, pArg->length, &pCurListArg))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_GROUP_ACTIONS:
            _CreateActionsGroupToList(OVS_ARGTYPE_GROUP_ACTIONS, pArg->data, &pCurListArg);
            break;
        }
    }

    pGroupArg = CreateGroupArgFromList(OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE, &pHeadArg);
    if (!pGroupArg)
    {
        KFree(pHeadArg);
        return FALSE;
    }

    ok = AppendArgumentToList(pGroupArg, ppArgList);
    if (!ok)
    {
        DestroyArgument(pGroupArg);
    }

    return ok;
}

static OVS_ARGUMENT* _CreateIpv4TunnelGroup(const OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    OVS_ARGUMENT_GROUP* pTunnelGroup = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;
    OVS_ARGUMENT* argArray = NULL, *pTunnelArg = NULL;
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    BOOLEAN ok = TRUE;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListCur)
    {
        return FALSE;
    }

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_KEY)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_ID, &pTunnelInfo->tunnelId, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_DONT_FRAGMENT)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT, NULL, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_CHECKSUM)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM, NULL, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    //ipv4 addr 0.0.0.0 is invalid
    if (pTunnelInfo->ipv4Source)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC, &pTunnelInfo->ipv4Source, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    //ipv4 addr 0.0.0.0 is invalid
    if (pTunnelInfo->ipv4Destination)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST, &pTunnelInfo->ipv4Destination, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    //ipv4 TOS 0x00 is invalid!
    if (pTunnelInfo->ipv4TypeOfService)
    {
        if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_TOS, &pTunnelInfo->ipv4TypeOfService, &pArgListCur))
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_TTL, &pTunnelInfo->ipv4TimeToLive, &pArgListCur))
    {
        ok = FALSE;
        goto Cleanup;
    }

    //OVS_ARGUMENT-s
    argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);

    //OVS_ARGUMENT_GROUP
    pTunnelGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pTunnelGroup)
    {
        return NULL;
    }

    pTunnelGroup->args = argArray;
    pTunnelGroup->count = countArgs;
    pTunnelGroup->groupSize = (UINT16)totalSize;

    //parent OVS_ARGUMENT
    pTunnelArg = KAlloc(sizeof(OVS_ARGUMENT));
    if (!pTunnelArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pTunnelArg->data = pTunnelGroup;
    pTunnelArg->length = pTunnelGroup->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
    pTunnelArg->type = OVS_ARGTYPE_GROUP_PI_TUNNEL;

    VerifyArgGroupSize(pTunnelArg->data);

Cleanup:

    if (ok)
    {
        FreeArgList(&pArgHead);
    }
    else
    {
        if (pTunnelArg)
        {
            DestroyArgument(pTunnelArg);
        }
        else if (pTunnelGroup)
        {
            DestroyArgumentGroup(pTunnelGroup);
        }
        else if (argArray)
        {
            DestroyArguments(argArray, countArgs);
        }
        else
        {
            DestroyArgList(&pArgHead);
        }

        if (pArgHead)
        {
            FreeArgList(&pArgHead);
        }

        return NULL;
    }

    return pTunnelArg;
}

static OVS_ARGUMENT* _CreateSetActionArg(const OVS_ARGUMENT* pArgument)
{
    const OVS_ARGUMENT_GROUP* pGroupArg = NULL;
    OVS_ARGTYPE argType = OVS_ARGTYPE_INVALID;

    OVS_CHECK(IsArgTypeGroup(pArgument->type));
    pGroupArg = pArgument->data;

    OVS_CHECK(pGroupArg->count == 1);
    pArgument = pGroupArg->args;
    argType = pArgument->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
    {
        OVS_ARGUMENT* pArg = _CreateIpv4TunnelGroup(pArgument->data);
        return pArg;
    }
        break;

    default:
    {
        OVS_ARGUMENT* pPacketInfoArg = KZAlloc(sizeof(OVS_ARGUMENT));
        if (!pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, "could not alloc key arg\n");
            return NULL;
        }

        CopyArgument(pPacketInfoArg, pArgument);

        return pPacketInfoArg;
    }
        break;
    }
}

static BOOLEAN _CreateActionsArgsToList(const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    BOOLEAN ok = TRUE;

    for (UINT i = 0; i < pArgGroup->count; ++i)
    {
        const OVS_ARGUMENT* pArg = pArgGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
        {
            OVS_ARGUMENT_GROUP* pSetGroup = NULL;
            OVS_ARGUMENT* pPacketInfoArg = NULL, *pSetArg = NULL;

            pPacketInfoArg = _CreateSetActionArg(pArg);
            if (!pPacketInfoArg)
            {
                return FALSE;
            }

            pSetGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
            if (!pSetGroup)
            {
                return FALSE;
            }

            pSetGroup->args = pPacketInfoArg;
            pSetGroup->count = 1;
            pSetGroup->groupSize = pPacketInfoArg->length + OVS_ARGUMENT_HEADER_SIZE;

            pSetArg = KZAlloc(sizeof(OVS_ARGUMENT));
            pSetArg->data = pSetGroup;
            pSetArg->type = OVS_ARGTYPE_GROUP_ACTIONS_SETINFO;
            pSetArg->length = pSetGroup->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;

            if (!AppendArgumentToList(pSetArg, ppArgList))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
            ok = _SampleActionToList(pArg->data, ppArgList);
            if (!ok)
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
        {
            OVS_ARGUMENT_GROUP* pUpcallGroup = NULL;
            OVS_ARGUMENT* pUpcallArg = NULL;
            BOOLEAN ok = TRUE;

            pUpcallGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
            if (NULL == pUpcallGroup)
            {
                return FALSE;
            }

            ok = CopyArgumentGroup(pUpcallGroup, pArg->data, /*actionsToAdd*/0);
            if (!ok)
            {
                DestroyArgumentGroup(pUpcallGroup);
                return FALSE;
            }

            pUpcallArg = CreateArgumentFromGroup(argType, pUpcallGroup);

            if (!AppendArgumentToList(pUpcallArg, ppArgList))
            {
                return FALSE;
            }
        }
            break;

        default:
        {
            OVS_ARGUMENT* pDestArg = KAlloc(sizeof(OVS_ARGUMENT));
            if (!pDestArg)
            {
                return FALSE;
            }

            CopyArgument(pDestArg, pArg);

            if (!AppendArgumentToList(pDestArg, ppArgList))
            {
                return FALSE;
            }
        }
            break;
        }
    }

    return TRUE;
}

static OVS_ARGUMENT* _CreateActionsGroup(const OVS_ARGUMENT_GROUP* pActions)
{
    OVS_ARGUMENT_GROUP* pActionsGroup = NULL;
    OVS_ARGUMENT* argArray = NULL, *pActionsArg = NULL;

    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;

    BOOLEAN ok = TRUE;
    UINT16 countArgs = 0;
    UINT totalSize = 0;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListCur)
    {
        return FALSE;
    }

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;
    pArgHead->pNext = NULL;

    if (pActions->count > 0)
    {
        ok = _CreateActionsArgsToList(pActions, &pArgListCur);
        if (!ok)
        {
            goto Cleanup;
        }

        argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);
        if (!argArray)
        {
            ok = FALSE;
            goto Cleanup;
        }
    }

    pActionsGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pActionsGroup)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pActionsGroup->args = argArray;
    pActionsGroup->count = countArgs;
    pActionsGroup->groupSize = (UINT16)totalSize;

    pActionsArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pActionsArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pActionsArg->data = pActionsGroup;
    pActionsArg->length = pActionsGroup->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
    pActionsArg->type = OVS_ARGTYPE_GROUP_ACTIONS;

Cleanup:
    if (ok)
    {
        FreeArgList(&pArgHead);
    }
    else
    {
        if (pActionsArg)
        {
            DestroyArgument(pActionsArg);
        }
        else if (pActionsGroup)
        {
            DestroyArgumentGroup(pActionsGroup);
        }
        else if (argArray)
        {
            DestroyArguments(argArray, countArgs);
            FreeArgList(&pArgHead);
        }
        else if (pArgHead)
        {
            DestroyArgList(&pArgHead);
        }

        return NULL;
    }

    return pActionsArg;
}

static BOOLEAN _CreateArgsFromLayer3And4InList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList);

static OVS_ARGUMENT* _CreateEncapsulationArg(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask)
{
    OVS_ARGUMENT_GROUP* pEncapsGroup = NULL;
    OVS_ARGUMENT* argArray = NULL, *pEncapsArg = NULL;

    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;

    BOOLEAN ok = TRUE;
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    BE16 ethType = 0;

    ethType = (pMask ? pMask->ethInfo.type : pPacketInfo->ethInfo.type);

    pEncapsGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pEncapsGroup)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed allocating group\n");
        return FALSE;
    }

    pEncapsArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pEncapsArg)
    {
        ok = FALSE;
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed allocating encaps arg\n");
        goto Cleanup;
    }

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListCur)
    {
        ok = FALSE;
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed allocating arg list item\n");
        goto Cleanup;
    }

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    OVS_CHECK(pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_802_2));

    if (!CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethType, &pArgListCur)) //UINT16

    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending enc eth type\n");

        ok = FALSE;
        goto Cleanup;
    }

    if (!_CreateArgsFromLayer3And4InList(pPacketInfo, pMask, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending layer 4 / 4 to list\n");
        ok = FALSE;
        goto Cleanup;
    }

    argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);
    if (!argArray)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed converting list to array\n");
        ok = FALSE;
        goto Cleanup;
    }

    pEncapsGroup->args = argArray;
    pEncapsGroup->count = countArgs;
    pEncapsGroup->groupSize = (UINT16)totalSize;

    pEncapsArg->data = pEncapsGroup;
    pEncapsArg->length = (UINT16)totalSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
    pEncapsArg->type = OVS_ARGTYPE_GROUP_PI_ENCAPSULATION;

    VerifyArgGroupSize(pEncapsArg->data);

Cleanup:

    if (ok)
    {
        FreeArgList(&pArgHead);
    }
    else
    {
        if (pEncapsArg)
        {
            DestroyArgument(pEncapsArg);

            if (pArgHead)
            {
                FreeArgList(&pArgHead);
            }
        }
        else if (pEncapsGroup)
        {
            DestroyArgumentGroup(pEncapsGroup);

            if (pArgHead)
            {
                FreeArgList(&pArgHead);
            }
        }
        else if (argArray)
        {
            OVS_CHECK(countArgs > 0);
            DestroyArguments(argArray, countArgs);

            if (pArgHead)
            {
                FreeArgList(&pArgHead);
            }
        }
        else
        {
            DestroyArgList(&pArgHead);
        }

        return NULL;
    }

    return pEncapsArg;
}

static BOOLEAN _CreateEncapsulationGroupToList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT* pArg = _CreateEncapsulationArg(pPacketInfo, pMask);

    if (!pArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " function _CreateEncapsulationArg failed\n");
        return FALSE;
    }

    if (!AppendArgumentToList(pArg, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending pEncapArg to list\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateEthernetArgsInList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList, BOOLEAN* pEncapsulated)
{
    OVS_PI_ETH_ADDRESS ethAddrPI = { 0 };
    OVS_ETH_INFO ethInfo = { 0 };

    OVS_CHECK(pEncapsulated);
    *pEncapsulated = FALSE;

    ethInfo = (pMask ? pMask->ethInfo : pPacketInfo->ethInfo);

    RtlCopyMemory(ethAddrPI.source, ethInfo.source, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(ethAddrPI.destination, ethInfo.destination, OVS_ETHERNET_ADDRESS_LENGTH);

    //ETH ADDRESS
    if (!CreateArgInList(OVS_ARGTYPE_PI_ETH_ADDRESS, &ethAddrPI, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending eth addr key\n");
        return FALSE;
    }

    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG) ||
        pPacketInfo->ethInfo.tci != 0)
    {
        BE16 ethType = 0;

        DEBUGP(LOG_INFO, "using encapsulation!\n");
        *pEncapsulated = TRUE;

        if (!pMask)
        {
            ethType = RtlUshortByteSwap(OVS_ETHERTYPE_QTAG);
        }
        else
        {
            ethType = OVS_PI_MASK_MATCH_EXACT(UINT16);
        }

        //ETH TYPE
        if (!CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethType, ppArgList)) //BE16

        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending vlan eth type\n");
            return FALSE;
        }

        //VLAN TCI
        if (!CreateArgInList(OVS_ARGTYPE_PI_VLAN_TCI, &ethInfo.tci, ppArgList)) //UINT16

        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending vlan tci\n");
            return FALSE;
        }

        if (!pPacketInfo->ethInfo.tci)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " -- have vlan tci but it is 0\n");
            return FALSE;
        }

        if (!_CreateEncapsulationGroupToList(pPacketInfo, pMask, ppArgList))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending encapsulation group\n");
            return FALSE;
        }

        return TRUE;
    }

    OVS_CHECK(pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_802_2));

    if (!CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethInfo.type, ppArgList)) //UINT16

    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending non-encaps eth type\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateInPortArgInList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    UINT32 inputPortValue = 0;

    if (pPacketInfo->physical.ovsInPort == OVS_INVALID_PORT_NUMBER)
    {
        if (pMask)
        {
            if (pMask->physical.ovsInPort == OVS_PI_MASK_MATCH_EXACT(UINT16))
            {
                inputPortValue = OVS_PI_MASK_MATCH_EXACT(UINT32);
            }
            else
            {
                OVS_CHECK(__UNEXPECTED__);
                return TRUE;
            }
        }
        else
        {
            OVS_CHECK(__UNEXPECTED__);
            return TRUE;
        }
    }
    else
    {
        UINT16 highBits = 0;
        UINT16 ovsPortNumber = 0;

        if (pMask)
        {
            highBits = OVS_PI_MASK_MATCH_EXACT(UINT16);
            ovsPortNumber = pMask->physical.ovsInPort;
        }
        else
        {
            highBits = 0;
            ovsPortNumber = pPacketInfo->physical.ovsInPort;
        }

        inputPortValue = ovsPortNumber | (highBits << 16);
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_DP_INPUT_PORT, &inputPortValue, ppArgList))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateTunnelArgInList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    //if we have mask, then we need to put "tunnel key" anyway, because we ALWAYS need to set tunnel packet info's TTL
    if (pMask || pPacketInfo->tunnelInfo.ipv4Destination)
    {
        OF_PI_IPV4_TUNNEL tunnelInfo = { 0 };
        OVS_ARGUMENT* pArg = NULL;

        tunnelInfo = (pMask ? pMask->tunnelInfo : pPacketInfo->tunnelInfo);

        pArg = _CreateIpv4TunnelGroup(&tunnelInfo);
        if (!pArg)
        {
            return FALSE;
        }

        DbgPrintArg(pArg, 0, 0);

        if (!AppendArgumentToList(pArg, ppArgList))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static OVS_ARGUMENT_SLIST_ENTRY* _CreateArgListFromPacketInfo(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;
    BOOLEAN ok = TRUE;
    BOOLEAN encapsulated = FALSE;
    UINT32 packetPriority = 0, packetMark = 0;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListCur)
    {
        return NULL;
    }

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    packetPriority = (pMask ? pMask->physical.packetPriority : pPacketInfo->physical.packetPriority);
    packetMark = (pMask ? pMask->physical.packetMark : pPacketInfo->physical.packetMark);

    if (!CreateArgInList(OVS_ARGTYPE_PI_PACKET_PRIORITY, &packetPriority, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending packet priority\n");
        return NULL;
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_PACKET_MARK, &packetMark, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending packet mark\n");
        ok = FALSE;
        goto Cleanup;
    }

    //TUNNEL
    if (!_CreateTunnelArgInList(pPacketInfo, pMask, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending tunnel key\n");
        ok = FALSE;
        goto Cleanup;
    }

    //INPUT OF PORT
    if (!_CreateInPortArgInList(pPacketInfo, pMask, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending in port\n");
        ok = FALSE;
        goto Cleanup;
    }

    if (!_CreateEthernetArgsInList(pPacketInfo, pMask, &pArgListCur, &encapsulated))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending eth args\n");
        ok = FALSE;
        goto Cleanup;
    }

    if (encapsulated)
    {
        goto Cleanup;
    }

    if (!_CreateArgsFromLayer3And4InList(pPacketInfo, pMask, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending layer3 / 4 args\n");
        ok = FALSE;
        goto Cleanup;
    }

Cleanup:
    if (!ok)
    {
        DestroyArgList(&pArgHead);
        return NULL;
    }

    return pArgHead;
}

OVS_ARGUMENT* CreateArgFromPacketInfo(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, UINT16 groupType)
{
    OVS_ARGUMENT_SLIST_ENTRY* pList = NULL;
    UINT16 count = 0;
    UINT size = 0;
    OVS_ARGUMENT* args = NULL, *pResult = NULL;
    OVS_ARGUMENT_GROUP* pArgGroup = NULL;

    pList = _CreateArgListFromPacketInfo(pPacketInfo, pMask);
    if (!pList)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " _CreateArgListFromPacketInfo failed\n");
        return NULL;
    }

    args = ArgumentListToArray(pList, &count, &size);
    if (!args)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " could not convert arg list to array\n");
        DestroyArgList(&pList);
        return NULL;
    }

    OVS_CHECK(size <= MAXUINT16);

    pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pArgGroup)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed allocating arg group\n");

        DestroyArgList(&pList);
        KFree(args);
        return NULL;
    }

    pArgGroup->args = args;
    pArgGroup->count = count;
    pArgGroup->groupSize = (UINT16)size;

    pResult = CreateArgumentFromGroup(groupType, pArgGroup);
    if (!pResult)
    {
        DEBUGP(LOG_ERROR, "CreateArgumentFromGroup failed\n");
        DestroyArgList(&pList);
        KFree(args);
        return NULL;
    }

    DbgPrintArg(pResult, 0, 0);

    FreeArgList(&pList);

    VerifyArgGroupSize(pArgGroup);

    return pResult;
}

static UINT64 _TicksToMiliseconds(UINT64 tickCount)
{
    UINT64 timeInMs = 0, timeInSeconds = 0, countsInLastSecond = 0;
    LARGE_INTEGER liFrequency = { 0 };

    KeQueryPerformanceCounter(&liFrequency);

    timeInSeconds = tickCount / liFrequency.QuadPart;
    timeInMs = timeInSeconds * 1000;

    countsInLastSecond = tickCount - (timeInSeconds * liFrequency.QuadPart);
    timeInMs += (countsInLastSecond * 1000 / liFrequency.QuadPart);

    return timeInMs;
}

//TODO: should we put OVS_MESSAGE_FLAG_MULTIPART for Flow_Dump?
BOOLEAN CreateMsgFromFlow(_In_ const OVS_FLOW* pFlow, UINT8 command, _Inout_ OVS_MESSAGE* pMsg, UINT32 sequence, UINT32 dpIfIndex, UINT32 portId)
{
    OVS_ARGUMENT_GROUP* pFlowGroup = NULL;
    OVS_ARGUMENT* pPIArg, *pMasksArg, *pTimeUsedArg, *pFlowStats, *pTcpFlags, *pActionsArg;
    BOOLEAN ok = TRUE;
    UINT16 flowArgCount = 0;
    UINT16 curArg = 0;
    OVS_WINL_FLOW_STATS stats = { 0 };
    UINT64 tickCount = 0;
    UINT8 tcpFlags = 0;
    UINT16 argsDataSize = 0;
    LOCK_STATE_EX lockState = { 0 };

    OVS_OFPACKET_INFO unmaskedPacketInfo = { 0 };
    OVS_OFPACKET_INFO maskedPacketInfo = { 0 };
    OVS_OFPACKET_INFO packetInfoMask = { 0 };

    OVS_CHECK(pMsg);

    pPIArg = pMasksArg = pTimeUsedArg = pFlowStats = pTcpFlags = pActionsArg = NULL;

    FLOW_LOCK_READ(pFlow, &lockState);

    unmaskedPacketInfo = pFlow->unmaskedPacketInfo;
    maskedPacketInfo = pFlow->maskedPacketInfo;
    packetInfoMask = pFlow->pMask->packetInfo;

    tickCount = pFlow->stats.lastUsedTime;
    stats.noOfMatchedPackets = pFlow->stats.packetsMached;
    stats.noOfMatchedBytes = pFlow->stats.bytesMatched;
    tcpFlags = pFlow->stats.tcpFlags;

    FLOW_UNLOCK(pFlow, &lockState);

    //2. INIT OVS_MESSAGE
    pMsg->length = sizeof(OVS_MESSAGE);
    pMsg->type = OVS_MESSAGE_TARGET_FLOW;
    pMsg->flags = 0;
    pMsg->sequence = sequence;
    pMsg->pid = portId;

    pMsg->command = command;
    pMsg->version = 1;
    pMsg->reserved = 0;

    pMsg->dpIfIndex = dpIfIndex;

    //3. OVS_ARGUMENT_GROUP
    pFlowGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pFlowGroup)
    {
        return FALSE;
    }

    //3.1. Packet Info
    pPIArg = CreateArgFromPacketInfo(&unmaskedPacketInfo, NULL, OVS_ARGTYPE_GROUP_PI);
    if (!pPIArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsDataSize += pPIArg->length;
    ++curArg;

    //3.2. Packet Info Mask
    pMasksArg = CreateArgFromPacketInfo(&maskedPacketInfo, &packetInfoMask, OVS_ARGTYPE_GROUP_MASK);
    if (!pMasksArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsDataSize += pMasksArg->length;
    ++curArg;

    //3.3. Flow Time Used
    if (tickCount > 0)
    {
        UINT64 usedTimeInMs = 0, curTimeInMs = 0;

        usedTimeInMs = _TicksToMiliseconds(tickCount);
        curTimeInMs = _TicksToMiliseconds(KeQueryPerformanceCounter(NULL).QuadPart);

        pTimeUsedArg = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_TIME_USED, &usedTimeInMs);
        if (!pTimeUsedArg)
        {
            ok = FALSE;
            goto Cleanup;
        }

        argsDataSize += pTimeUsedArg->length;
        ++curArg;
    }

    //3.4. Flow Stats
    if (stats.noOfMatchedPackets > 0)
    {
        pFlowStats = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_STATS, &stats);
        if (!pFlowStats)
        {
            ok = FALSE;
            goto Cleanup;
        }

        argsDataSize += pFlowStats->length;
        ++curArg;
    }

    //3.5. Flow Tcp Flags
    if (tcpFlags)
    {
        pTcpFlags = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_TCP_FLAGS, &tcpFlags);
        if (!pTcpFlags)
        {
            ok = FALSE;
            goto Cleanup;
        }

        argsDataSize += pTcpFlags->length;
        ++curArg;
    }

    FLOW_LOCK_READ(pFlow, &lockState);
    //NOTE: we don't need to use OVS_REFERENCE for pFlow->pActions here
    //because the actions cannot be deleted while under the lock of pFlow
    //pFlow is here referenced, so it and its Actions cannot be deleted
    pActionsArg = _CreateActionsGroup(pFlow->pActions->pActionGroup);
    FLOW_UNLOCK(pFlow, &lockState);

    if (!pActionsArg)
    {
        return FALSE;
    }

    DbgPrintArg(pActionsArg, 0, 0);

    argsDataSize += pActionsArg->length;
    ++curArg;

    flowArgCount = curArg;
    if (!AllocateArgumentsToGroup(flowArgCount, pFlowGroup))
    {
        ok = FALSE;
        goto Cleanup;
    }

    pFlowGroup->args[0] = *pPIArg;
    pFlowGroup->args[1] = *pMasksArg;

    curArg = 2;

    if (pTimeUsedArg)
    {
        pFlowGroup->args[curArg] = *pTimeUsedArg;
        curArg++;
    }

    if (pFlowStats)
    {
        pFlowGroup->args[curArg] = *pFlowStats;
        curArg++;
    }

    if (pTcpFlags)
    {
        pFlowGroup->args[curArg] = *pTcpFlags;
        curArg++;
    }

    pFlowGroup->args[curArg] = *pActionsArg;
    ++curArg;

    pFlowGroup->groupSize += argsDataSize;
    pMsg->pArgGroup = pFlowGroup;

Cleanup:
    VerifyArgGroupSize(pMsg->pArgGroup);

    if (ok)
    {
        KFree(pPIArg);
        KFree(pMasksArg);
        KFree(pTimeUsedArg);
        KFree(pFlowStats);
        KFree(pTcpFlags);
        KFree(pActionsArg);
    }
    else
    {
        FreeGroupWithArgs(pFlowGroup);

        DestroyArgument(pPIArg);
        DestroyArgument(pMasksArg);
        DestroyArgument(pTimeUsedArg);
        DestroyArgument(pFlowStats);
        DestroyArgument(pTcpFlags);
        DestroyArgument(pActionsArg);
    }

    return ok;
}