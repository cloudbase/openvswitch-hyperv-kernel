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
#include "OFPort.h"

#include "ArgVerification.h"
#include "MsgVerification.h"
#include "ArgumentList.h"

static BOOLEAN _CreateIpv4Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_IPV4 ipv4PI = { 0 };

    ipv4PI.source = pPacketInfo->netProto.ipv4Info.source.S_un.S_addr;
    ipv4PI.destination = pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr;
    ipv4PI.protocol = pPacketInfo->ipInfo.protocol;
    ipv4PI.tos = pPacketInfo->ipInfo.typeOfService;
    ipv4PI.ttl = pPacketInfo->ipInfo.timeToLive;
    ipv4PI.fragmentType = pPacketInfo->ipInfo.fragment;

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_IPV4, &ipv4PI, ppArgList));

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

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_IPV6, &ipv6PI, ppArgList));

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

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ARP, &arpPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateMplsArgs(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_MPLS mplsPI = { 0 };

    mplsPI.mplsLse = pPacketInfo->ipInfo.mplsTopLabelStackEntry;

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_MPLS, &mplsPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateTcpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_TCP tcpPI = { 0 };
    BE16 tcpFlags = 0;

    const OVS_TRANSPORT_LAYER_INFO* pTransportInfo = (pMask ? &pMask->tpInfo : &pPacketInfo->tpInfo);

    tcpPI.source = pTransportInfo->sourcePort;
    tcpPI.destination = pTransportInfo->destinationPort;
    tcpFlags = pTransportInfo->tcpFlags;

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_TCP, &tcpPI, ppArgList));

    if (!CreateArgInList(OVS_ARGTYPE_PI_TCP_FLAGS, &tcpFlags, ppArgList))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending tcp flags\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _CreateUdpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_UDP udpPI = { 0 };

    const OVS_TRANSPORT_LAYER_INFO* pTransportInfo = (pMask ? &pMask->tpInfo : &pPacketInfo->tpInfo);

    udpPI.source = pTransportInfo->sourcePort;
    udpPI.destination = pTransportInfo->destinationPort;

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_UDP, &udpPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateSctpArgs(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_SCTP sctpPI = { 0 };

    const OVS_TRANSPORT_LAYER_INFO* pTransportInfo = (pMask ? &pMask->tpInfo : &pPacketInfo->tpInfo);

    sctpPI.source = pTransportInfo->sourcePort;
    sctpPI.destination = pTransportInfo->destinationPort;

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_SCTP, &sctpPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateIcmp4Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_ICMP icmpPI = { 0 };

    icmpPI.type = (UINT8)RtlUshortByteSwap(pPacketInfo->tpInfo.sourcePort);
    icmpPI.code = (UINT8)RtlUshortByteSwap(pPacketInfo->tpInfo.destinationPort);

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ICMP, &icmpPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateIcmp6Args(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList, _Out_ OVS_PI_ICMP6* pIcmp6PI)
{
    OVS_CHECK(pIcmp6PI);

    pIcmp6PI->type = (UINT8)RtlUshortByteSwap(pPacketInfo->tpInfo.sourcePort);
    pIcmp6PI->code = (UINT8)RtlUshortByteSwap(pPacketInfo->tpInfo.destinationPort);

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ICMP6, pIcmp6PI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateIp6NeighborDiscoveryArgs(const OVS_OFPACKET_INFO* pPacketInfo, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_PI_NEIGHBOR_DISCOVERY neighborDiscoveryPI = { 0 };

    RtlCopyMemory(neighborDiscoveryPI.targetIp, &pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp, sizeof(neighborDiscoveryPI.targetIp));
    RtlCopyMemory(neighborDiscoveryPI.sourceMac, pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndSourceMac, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(neighborDiscoveryPI.targetMac, pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetMac, OVS_ETHERNET_ADDRESS_LENGTH);

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY, &neighborDiscoveryPI, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateArgsFromLayer3And4InList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    const OVS_OFPACKET_INFO* pInfoToWrite = NULL;

    pInfoToWrite = (pMask ? pMask : pPacketInfo);

    switch (RtlUshortByteSwap(pPacketInfo->ethInfo.type))
    {
    case OVS_ETHERTYPE_IPV4:
        EXPECT(_CreateIpv4Args(pInfoToWrite, ppArgList));
        break;

    case OVS_ETHERTYPE_IPV6:
        EXPECT(_CreateIpv6Args(pInfoToWrite, ppArgList));
        break;

    case OVS_ETHERTYPE_ARP:
        EXPECT(_CreateArpArgs(pInfoToWrite, ppArgList));
        break;

    case OVS_ETHERTYPE_MPLS_UNICAST:
    case OVS_ETHERTYPE_MPLS_MULTICAST:
        EXPECT(_CreateMplsArgs(pInfoToWrite, ppArgList));
        break;
    }

    //TRANSPORT LAYER: AVAILABLE ONLY FOR IPV4 / IPV6 AND WHEN THE PACKET IS NOT FRAGMENTED
    if (pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) &&
        pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6) ||
        pPacketInfo->ipInfo.fragment == OVS_FRAGMENT_TYPE_FRAG_N)
    {
        return TRUE;
    }

    switch (pPacketInfo->ipInfo.protocol)
    {
    case OVS_IPPROTO_TCP:
        EXPECT(_CreateTcpArgs(pPacketInfo, pMask, ppArgList));
        break;

    case OVS_IPPROTO_UDP:
        EXPECT(_CreateUdpArgs(pPacketInfo, pMask, ppArgList));
        break;

    case OVS_IPPROTO_SCTP:
        EXPECT(_CreateSctpArgs(pPacketInfo, pMask, ppArgList));
        break;

    case OVS_IPPROTO_ICMP:
        EXPECT(_CreateIcmp4Args(pInfoToWrite, ppArgList));
        break;

    case OVS_IPV6_EXTH_ICMP6:
    {
        OVS_PI_ICMP6 icmp6PI = { 0 };

        //ICMP6
        EXPECT(_CreateIcmp6Args(pInfoToWrite, ppArgList, &icmp6PI));

        //NET DISCOVERY
        if (icmp6PI.type == OVS_NDISC_NEIGHBOUR_SOLICITATION || icmp6PI.type == OVS_NDISC_NEIGHBOUR_ADVERTISEMENT)
        {
            EXPECT(_CreateIp6NeighborDiscoveryArgs(pInfoToWrite, ppArgList));
        }
    }
        break;

    default:
        OVS_CHECK(__UNEXPECTED__);
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
    EXPECT(pHeadArg);

    pCurListArg = pHeadArg;
    CHECK_B(_CreateActionsArgsToList(pArgGroup, &pCurListArg));
    pGroupArg = CreateGroupArgFromList(groupType, &pHeadArg);

    CHECK_B(pGroupArg);
    CHECK_B(AppendArgumentToList(pGroupArg, ppArgList));

Cleanup:
    if (!ok)
    {
        KFree(pHeadArg);
    }

    return ok;
}

static BOOLEAN _SampleActionToList(const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT_SLIST_ENTRY* pCurListArg = NULL, *pHeadArg = NULL;
    OVS_ARGUMENT* pGroupArg = NULL;
    BOOLEAN ok = TRUE;

    pHeadArg = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    EXPECT(pHeadArg);

    pCurListArg = pHeadArg;

    for (UINT i = 0; i < pArgGroup->count; ++i)
    {
        const OVS_ARGUMENT* pArg = pArgGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
            EXPECT(CreateArgInList_WithSize(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY, pArg->data, pArg->length, &pCurListArg));
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
            EXPECT(_CreateActionsGroupToList(OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP, pArg->data, &pCurListArg));
            break;
        }
    }

    pGroupArg = CreateGroupArgFromList(OVS_ARGTYPE_ACTION_SAMPLE_GROUP, &pHeadArg);

    CHECK_B(pGroupArg);
    CHECK_B(AppendArgumentToList(pGroupArg, ppArgList));

Cleanup:
    if (!ok)
    {
        KFree(pHeadArg);
        DestroyArgument(pGroupArg);
    }

    return ok;
}

static OVS_ARGUMENT* _CreateIpv4TunnelGroup(const OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;
    OVS_ARGUMENT* argArray = NULL, *pTunnelArg = NULL;
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT_GROUP* pTunnelGroup = NULL;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    EXPECT(pArgListCur);

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_KEY)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_ID, &pTunnelInfo->tunnelId, &pArgListCur));
    }

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_DONT_FRAGMENT)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT, NULL, &pArgListCur));
    }

    if (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_CHECKSUM)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM, NULL, &pArgListCur));
    }

    //ipv4 addr 0.0.0.0 is invalid
    if (pTunnelInfo->ipv4Source)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC, &pTunnelInfo->ipv4Source, &pArgListCur));
    }

    //ipv4 addr 0.0.0.0 is invalid
    if (pTunnelInfo->ipv4Destination)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST, &pTunnelInfo->ipv4Destination, &pArgListCur));
    }

    //ipv4 TOS 0x00 is invalid!
    if (pTunnelInfo->ipv4TypeOfService)
    {
        CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_TOS, &pTunnelInfo->ipv4TypeOfService, &pArgListCur));
    }

    CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_TUNNEL_TTL, &pTunnelInfo->ipv4TimeToLive, &pArgListCur));

    //OVS_ARGUMENT-s
    argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);
    CHECK_B(argArray);

    pTunnelGroup = CreateGroupFromArgArray(argArray, countArgs, (UINT16)totalSize);
    CHECK_B(pTunnelGroup);

    pTunnelArg = CreateArgumentFromGroup(OVS_ARGTYPE_PI_TUNNEL_GROUP, pTunnelGroup);
    CHECK_B(pTunnelArg);

Cleanup:
    if (ok)
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ FALSE);
    }
    else
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ TRUE);
        KFree(argArray);
        KFree(pTunnelArg);

        return NULL;
    }

    return pTunnelArg;
}

static OVS_ARGUMENT* _CreateSetActionArg(const OVS_ARGUMENT_GROUP* pGroup)
{
    OVS_ARGTYPE argType = OVS_ARGTYPE_INVALID;
    OVS_ARGUMENT* pCreatedArg = NULL, *pArg = NULL;

    OVS_CHECK(pGroup->count == 1);
    pArg = pGroup->args;
    argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
        pCreatedArg = _CreateIpv4TunnelGroup(pArg->data);
        return pCreatedArg;

    default:
        pCreatedArg = KZAlloc(sizeof(OVS_ARGUMENT));
        EXPECT(pCreatedArg);

        CopyArgument(pCreatedArg, pArg);

        return pCreatedArg;
    }
}

static BOOLEAN _CreateActionsArgsToList_SetInfo(OVS_ARGUMENT_GROUP* pGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT* pPacketInfoArg = NULL, *pSetArg = NULL;
    UINT16 piArgLen = 0;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT_GROUP* pSetGroup = NULL;

    pPacketInfoArg = _CreateSetActionArg(pGroup);
    CHECK_B(pPacketInfoArg);

    piArgLen = pPacketInfoArg->length + OVS_ARGUMENT_HEADER_SIZE;
    pSetGroup = CreateGroupFromArgArray(pPacketInfoArg, 1, piArgLen);
    CHECK_B(pSetGroup);
    
    pSetArg = CreateArgumentFromGroup(OVS_ARGTYPE_ACTION_SETINFO_GROUP, pSetGroup);
    CHECK_B(pSetArg);

    CHECK_B(AppendArgumentToList(pSetArg, ppArgList));

Cleanup:
    if (!ok)
    {
        if (pSetArg)
        {
            FreeGroupWithArgs(pSetArg->data);
        }

        KFree(pSetArg);
        DestroyArgument(pPacketInfoArg);
    }

    return ok;
}

static BOOLEAN _CreateActionsArgsToList_Upcall(OVS_ARGTYPE argType, OVS_ARGUMENT_GROUP* pGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT_GROUP* pUpcallGroup = NULL;
    OVS_ARGUMENT* pUpcallArg = NULL;
    BOOLEAN ok = TRUE;

    pUpcallGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    EXPECT(pUpcallGroup);

    CHECK_B(CopyArgumentGroup(pUpcallGroup, pGroup, /*actionsToAdd*/0));

    pUpcallArg = CreateArgumentFromGroup(argType, pUpcallGroup);

    CHECK_B(pUpcallArg);
    CHECK_B(AppendArgumentToList(pUpcallArg, ppArgList));

Cleanup:
    if (!ok)
    {
        DestroyArgumentGroup(pUpcallGroup);
        KFree(pUpcallArg);
    }

    return ok;
}

static BOOLEAN _CreateActionsArgsToList_Default(const OVS_ARGUMENT* pArg, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OVS_ARGUMENT* pDestArg = KAlloc(sizeof(OVS_ARGUMENT));
    BOOLEAN ok = TRUE;

    EXPECT(pDestArg);

    CHECK_B(CopyArgument(pDestArg, pArg));
    CHECK_B(AppendArgumentToList(pDestArg, ppArgList));

Cleanup:
    if (!ok)
    {
        DestroyArgument(pDestArg);
    }

    return ok;
}

static BOOLEAN _CreateActionsArgsToList(const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    for (UINT i = 0; i < pArgGroup->count; ++i)
    {
        const OVS_ARGUMENT* pArg = pArgGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            EXPECT(_CreateActionsArgsToList_SetInfo(pArg->data, ppArgList));
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            EXPECT(_SampleActionToList(pArg->data, ppArgList));
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            EXPECT(_CreateActionsArgsToList_Upcall(argType, pArg->data, ppArgList));
            break;

        default:
            EXPECT(_CreateActionsArgsToList_Default(pArg, ppArgList));
            break;
        }
    }

    return TRUE;
}

static OVS_ARGUMENT* _CreateFlowActionsGroup(const OVS_ARGUMENT_GROUP* pActions)
{
    OVS_ARGUMENT_GROUP* pActionsGroup = NULL;
    OVS_ARGUMENT* argArray = NULL, *pActionsArg = NULL;

    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;

    BOOLEAN ok = TRUE;
    UINT16 countArgs = 0;
    UINT totalSize = 0;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    EXPECT(pArgListCur);

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;
    pArgHead->pNext = NULL;

    if (pActions->count > 0)
    {
        CHECK_B(_CreateActionsArgsToList(pActions, &pArgListCur));
        argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);
        CHECK_B(argArray);
    }

    pActionsGroup = CreateGroupFromArgArray(argArray, countArgs, (UINT16)totalSize);
    CHECK_B(pActionsGroup);

    pActionsArg = CreateArgumentFromGroup(OVS_ARGTYPE_FLOW_ACTIONS_GROUP, pActionsGroup);
    CHECK_B(pActionsArg);

Cleanup:
    if (ok)
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ FALSE);
    }
    else
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ TRUE);
        KFree(argArray);
        KFree(pActionsGroup);
        KFree(pActionsArg);

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

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    CHECK_B(pArgListCur);

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    //NOTE: 802.2 frames are represented in ovs messages as:
    //packet info eth type = missing (=> filled by us)
    //mask eth info = exact match 
    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_802_2) &&
        pMask && pMask->ethInfo.type)
    {
        CHECK_B(pMask->ethInfo.type == OVS_PI_MASK_MATCH_EXACT(BE16));
    }

    CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethType, &pArgListCur));
    CHECK_B(_CreateArgsFromLayer3And4InList(pPacketInfo, pMask, &pArgListCur));

    argArray = ArgumentListToArray(pArgHead, &countArgs, &totalSize);
    CHECK_B(argArray);

    pEncapsGroup = CreateGroupFromArgArray(argArray, countArgs, (UINT16)totalSize);
    CHECK_B(pEncapsGroup);

    pEncapsArg = CreateArgumentFromGroup(OVS_ARGTYPE_PI_ENCAP_GROUP, pEncapsGroup);
    CHECK_B(pEncapsArg);

Cleanup:
    if (ok)
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ FALSE);
        return pEncapsArg;
    }
    
    DestroyOrFreeArgList(&pArgHead, /*destroy*/ TRUE);
    KFree(argArray);
    KFree(pEncapsGroup);
    KFree(pEncapsArg);

    return NULL;
}

static BOOLEAN _CreateEncapsulationGroupToList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT* pArg = _CreateEncapsulationArg(pPacketInfo, pMask);
    EXPECT(pArg);

    CHECK_B(AppendArgumentToList(pArg, ppArgList));

Cleanup:
    if (!ok)
    {
        DestroyArgument(pArg);
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
    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ETH_ADDRESS, &ethAddrPI, ppArgList));

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

        EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethType, ppArgList));
        EXPECT(CreateArgInList(OVS_ARGTYPE_PI_VLAN_TCI, &ethInfo.tci, ppArgList));
        EXPECT(pPacketInfo->ethInfo.tci);
        EXPECT(_CreateEncapsulationGroupToList(pPacketInfo, pMask, ppArgList));

        return TRUE;
    }

    OVS_CHECK(pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_802_2));

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_ETH_TYPE, &ethInfo.type, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateInPortArgInList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    UINT32 inputPortValue = 0;

    if (pPacketInfo->physical.ofInPort == OVS_INVALID_PORT_NUMBER)
    {
        EXPECT(pMask);
        
        EXPECT(pMask->physical.ofInPort == OVS_PI_MASK_MATCH_EXACT(UINT16));
        inputPortValue = OVS_PI_MASK_MATCH_EXACT(UINT32);
    }
    else
    {
        UINT16 highBits = 0;
        UINT16 ofPortNumber = 0;

        if (pMask)
        {
            highBits = OVS_PI_MASK_MATCH_EXACT(UINT16);
            ofPortNumber = pMask->physical.ofInPort;
        }
        else
        {
            highBits = 0;
            ofPortNumber = pPacketInfo->physical.ofInPort;
        }

        inputPortValue = ofPortNumber | (highBits << 16);
    }

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_DP_INPUT_PORT, &inputPortValue, ppArgList));

    return TRUE;
}

static BOOLEAN _CreateTunnelArgInList(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, OVS_ARGUMENT_SLIST_ENTRY** ppArgList)
{
    OF_PI_IPV4_TUNNEL tunnelInfo = { 0 };
    OVS_ARGUMENT* pArg = NULL;

    if (!(pMask || pPacketInfo->tunnelInfo.ipv4Destination))
    {
        return TRUE;
    }

    //if we have mask, then we need to put "tunnel key" anyway, because we ALWAYS need to set tunnel packet info's TTL
    tunnelInfo = (pMask ? pMask->tunnelInfo : pPacketInfo->tunnelInfo);

    pArg = _CreateIpv4TunnelGroup(&tunnelInfo);
    EXPECT(pArg);

    DBGPRINT_ARG(LOG_INFO, pArg, 0, 0);

    if (!AppendArgumentToList(pArg, ppArgList))
    {
        DestroyArgument(pArg);
        return FALSE;
    }

    return TRUE;
}

static OVS_ARGUMENT_SLIST_ENTRY* _CreateArgListFromPacketInfo(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgHead = NULL;
    BOOLEAN ok = TRUE;
    BOOLEAN encapsulated = FALSE;
    UINT32 packetPriority = 0, packetMark = 0, datapathHash = 0, recircId = 0;

    pArgListCur = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    EXPECT(pArgListCur);

    pArgHead = pArgListCur;
    pArgHead->pArg = NULL;

    packetPriority = (pMask ? pMask->physical.packetPriority : pPacketInfo->physical.packetPriority);
    packetMark = (pMask ? pMask->physical.packetMark : pPacketInfo->physical.packetMark);
    datapathHash = (pMask ? pMask->flowHash : pPacketInfo->flowHash);
    recircId = (pMask ? pMask->recirculationId : pPacketInfo->recirculationId);

    if (!CreateArgInList(OVS_ARGTYPE_PI_DATAPATH_HASH, &datapathHash, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending datapath hash\n");
        return NULL;
    }

    if (!CreateArgInList(OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID, &recircId, &pArgListCur))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed appending datapath recirculation id\n");
        return NULL;
    }

    EXPECT(CreateArgInList(OVS_ARGTYPE_PI_PACKET_PRIORITY, &packetPriority, &pArgListCur));
    CHECK_B(CreateArgInList(OVS_ARGTYPE_PI_PACKET_MARK, &packetMark, &pArgListCur));

    CHECK_B(_CreateTunnelArgInList(pPacketInfo, pMask, &pArgListCur));
    CHECK_B(_CreateInPortArgInList(pPacketInfo, pMask, &pArgListCur));
    CHECK_B(_CreateEthernetArgsInList(pPacketInfo, pMask, &pArgListCur, &encapsulated));

    if (encapsulated)
    {
        goto Cleanup;
    }

    CHECK_B(_CreateArgsFromLayer3And4InList(pPacketInfo, pMask, &pArgListCur));

Cleanup:
    if (!ok)
    {
        DestroyOrFreeArgList(&pArgHead, /*destroy*/ TRUE);
        return NULL;
    }

    return pArgHead;
}

OVS_ARGUMENT* CreateArgFromPacketInfo(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, UINT16 groupType)
{
    OVS_ARGUMENT_SLIST_ENTRY* pList = NULL;
    UINT16 count = 0;
    UINT size = 0;
    OVS_ARGUMENT* args = NULL, *pPIArg = NULL;
    OVS_ARGUMENT_GROUP* pArgGroup = NULL;
    BOOLEAN ok = TRUE;

    pList = _CreateArgListFromPacketInfo(pPacketInfo, pMask);
    EXPECT(pList);

    args = ArgumentListToArray(pList, &count, &size);
    CHECK_B(args);

    OVS_CHECK(size <= MAXUINT16);

    pArgGroup = CreateGroupFromArgArray(args, count, (UINT16)size);
    CHECK_B(pArgGroup);

    pPIArg = CreateArgumentFromGroup(groupType, pArgGroup);
    CHECK_B(pPIArg);

    DBGPRINT_ARG(LOG_INFO, pResult, 0, 0);

    DestroyOrFreeArgList(&pList, /*destroy*/ FALSE);

Cleanup:
    if (!ok)
    {
        DestroyOrFreeArgList(&pList, /*destroy*/ TRUE);
        KFree(args);
        KFree(pArgGroup);
        KFree(pPIArg);
        
        return NULL;
    }

    return pPIArg;
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
OVS_ERROR CreateMsgFromFlow(const OVS_FLOW* pFlow, const OVS_MESSAGE* pInMsg, _Out_ OVS_MESSAGE* pOutMsg, UINT8 command)
{
    OVS_ARGUMENT_GROUP* pFlowGroup = NULL;
    OVS_ARGUMENT* pPIArg, *pMasksArg, *pTimeUsedArg, *pFlowStats, *pTcpFlags, *pActionsArg;
    UINT16 flowArgCount = 0;
    UINT16 curArg = 0;
    OVS_WINL_FLOW_STATS winlStats = { 0 };
    OVS_FLOW_STATS stats = { 0 };
    UINT64 tickCount = 0;
    UINT8 tcpFlags = 0;
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    ULONG i = 0;

    OVS_OFPACKET_INFO unmaskedPacketInfo = { 0 };
    OVS_OFPACKET_INFO maskedPacketInfo = { 0 };
    OVS_OFPACKET_INFO packetInfoMask = { 0 };

    UINT16 countArgs = 0;

    OVS_CHECK(pOutMsg);

    pPIArg = pMasksArg = pTimeUsedArg = pFlowStats = pTcpFlags = pActionsArg = NULL;

    FLOW_LOCK_READ(pFlow, &lockState);

    unmaskedPacketInfo = pFlow->unmaskedPacketInfo;
    maskedPacketInfo = pFlow->maskedPacketInfo;
    packetInfoMask = pFlow->pMask->packetInfo;

    Flow_GetStats_Unsafe(pFlow, &stats);
    winlStats.noOfMatchedBytes = stats.bytesMatched;
    winlStats.noOfMatchedPackets = stats.packetsMached;

    FLOW_UNLOCK(pFlow, &lockState);

    countArgs = 3;//PacketInfo, Mask, Actions
    if (tickCount > 0)
    {
        ++countArgs;
    }

    if (winlStats.noOfMatchedPackets > 0)
    {
        ++countArgs;
    }

    if (tcpFlags)
    {
        ++countArgs;
    }

    CHECK_E(CreateReplyMsg(pInMsg, pOutMsg, sizeof(OVS_MESSAGE), command, countArgs));
    OVS_CHECK(pOutMsg->type == OVS_MESSAGE_TARGET_FLOW);

    //3.1. Packet Info
    pPIArg = CreateArgFromPacketInfo(&unmaskedPacketInfo, NULL, OVS_ARGTYPE_FLOW_PI_GROUP);
    CHECK_B_E(pPIArg, OVS_ERROR_INVAL);
    AddArgToArgGroup(pOutMsg->pArgGroup, pPIArg, &i);

    //3.2. Packet Info Mask
    pMasksArg = CreateArgFromPacketInfo(&maskedPacketInfo, &packetInfoMask, OVS_ARGTYPE_FLOW_MASK_GROUP);
    CHECK_B_E(pPIArg, OVS_ERROR_INVAL);
    AddArgToArgGroup(pOutMsg->pArgGroup, pMasksArg, &i);

    //3.3. Flow Time Used
    if (tickCount > 0)
    {
        UINT64 usedTimeInMs = 0, curTimeInMs = 0;

        usedTimeInMs = _TicksToMiliseconds(tickCount);
        curTimeInMs = _TicksToMiliseconds(KeQueryPerformanceCounter(NULL).QuadPart);

        pTimeUsedArg = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_TIME_USED, &usedTimeInMs);
        CHECK_B_E(pPIArg, OVS_ERROR_INVAL);
        AddArgToArgGroup(pOutMsg->pArgGroup, pTimeUsedArg, &i);
    }

    //3.4. Flow Stats
    if (winlStats.noOfMatchedPackets > 0)
    {
        pFlowStats = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_STATS, &stats);
        CHECK_B_E(pPIArg, OVS_ERROR_INVAL);
        AddArgToArgGroup(pOutMsg->pArgGroup, pFlowStats, &i);
    }

    //3.5. Flow Tcp Flags
    if (tcpFlags)
    {
        pTcpFlags = CreateArgument_Alloc(OVS_ARGTYPE_FLOW_TCP_FLAGS, &tcpFlags);
        CHECK_B_E(pPIArg, OVS_ERROR_INVAL);
        AddArgToArgGroup(pOutMsg->pArgGroup, pTcpFlags, &i);
    }

    FLOW_LOCK_READ(pFlow, &lockState);
    //NOTE: we don't need to use OVS_REFERENCE for pFlow->pActions here
    //because the actions cannot be deleted while under the lock of pFlow
    //pFlow is here referenced, so it and its Actions cannot be deleted
    pActionsArg = _CreateFlowActionsGroup(pFlow->pActions->pActionGroup);
    FLOW_UNLOCK(pFlow, &lockState);

    CHECK_B_E(pActionsArg, OVS_ERROR_INVAL);
    AddArgToArgGroup(pOutMsg->pArgGroup, pActionsArg, &i);
    DBGPRINT_ARG(LOG_INFO, pActionsArg, 0, 0);

    flowArgCount = curArg;

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        KFree(pPIArg); KFree(pMasksArg);
        KFree(pTimeUsedArg); KFree(pFlowStats);
        KFree(pTcpFlags); KFree(pActionsArg);
    }
    else
    {
        FreeGroupWithArgs(pFlowGroup);

        DestroyArgument(pPIArg); DestroyArgument(pMasksArg);
        DestroyArgument(pTimeUsedArg); DestroyArgument(pFlowStats);
        DestroyArgument(pTcpFlags); DestroyArgument(pActionsArg);
    }

    return error;
}