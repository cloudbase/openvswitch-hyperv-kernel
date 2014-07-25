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

#include "PacketInfo.h"
#include "OFFlow.h"
#include "OFDatapath.h"
#include "Argument.h"
#include "WinlFlow.h"
#include "ArgumentType.h"
#include "PersistentPort.h"
#include "Ipv4.h"
#include "Tcp.h"
#include "Udp.h"
#include "Sctp.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Gre.h"
#include "Checksum.h"

static void _UpdateRange(_Inout_ OVS_PI_RANGE* pPiRange, SIZE_T offset, SIZE_T size)
{
    SIZE_T startPos = 0;
    SIZE_T endPos = 0;

    OVS_CHECK(pPiRange);

    startPos = RoundDown(offset, sizeof(UINT64));
    endPos = RoundUp(offset + size, sizeof(UINT64));

    if (!pPiRange)
    {
        return;
    }

    //i.e. in the beginning
    if (pPiRange->startRange == pPiRange->endRange)
    {
        pPiRange->startRange = startPos;
        pPiRange->endRange = endPos;
    }
    else
    {
        //i.e. if it was set before
        if (pPiRange->startRange > startPos)
        {
            pPiRange->startRange = startPos;
        }

        if (pPiRange->endRange < endPos)
        {
            pPiRange->endRange = endPos;
        }
    }
}

static BOOLEAN _ExtractIpv4(VOID* pNbBuffer, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pNbBuffer;
    //assuming ipv4 is ok (in length, that is not corrupted, etc.)
    const OVS_IPV4_HEADER* pIpv4Header = NULL;
    UINT16 offset = 0;

    pIpv4Header = ReadIpv4Header(pEthHeader);

    pPacketInfo->netProto.ipv4Info.source = pIpv4Header->SourceAddress;
    pPacketInfo->netProto.ipv4Info.destination = pIpv4Header->DestinationAddress;
    pPacketInfo->ipInfo.protocol = pIpv4Header->Protocol;
    //TypeOfService = TypeOfServiceAndEcnField
    pPacketInfo->ipInfo.typeOfService = pIpv4Header->TypeOfService;
    pPacketInfo->ipInfo.timeToLive = pIpv4Header->TimeToLive;

    offset = Ipv4_GetFragmentOffset(pIpv4Header);
    if (offset)
    {
        pPacketInfo->ipInfo.fragment = OVS_FRAGMENT_TYPE_FRAG_N;
        return TRUE;
    }

    if (pIpv4Header->MoreFragments)
    {
        pPacketInfo->ipInfo.fragment = OVS_FRAGMENT_TYPE_FIRST_FRAG;
    }

    //TRANSPORT LAYER
    if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_TCP)
    {
        OVS_TCP_HEADER* pTcpHeader = (OVS_TCP_HEADER*)AdvanceIpv4Header(pIpv4Header);

        pPacketInfo->tpInfo.sourcePort = pTcpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pTcpHeader->destinationPort;

        pPacketInfo->tpInfo.tcpFlags = GetTcpFlags(pTcpHeader->flagsAndOffset);
    }
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_UDP)
    {
        OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)AdvanceIpv4Header(pIpv4Header);

        pPacketInfo->tpInfo.sourcePort = pUdpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pUdpHeader->destinationPort;
    }
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_SCTP)
    {
        OVS_SCTP_HEADER* pSctpHeader = (OVS_SCTP_HEADER*)AdvanceIpv4Header(pIpv4Header);

        pPacketInfo->tpInfo.sourcePort = pSctpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pSctpHeader->destinationPort;
    }
    else if (pPacketInfo->ipInfo.protocol == OVS_IPPROTO_ICMP)
    {
        OVS_ICMP_HEADER* pIcmpHeader = (OVS_ICMP_HEADER*)AdvanceIpv4Header(pIpv4Header);

        //packet too big and DF is set:
        //if the packet that arrived was encapsulated in GRE (i.e. the packet, encapsulated, was too big for mtu),
        //then we must update the ICMP's nextHopMtu in the packet, to account for the encapsulation bytes overhead
        //(i.e. the protocol driver does not know we intend to encapsulate the packet, when considering the mtu)
        //TODO: we should do similar for VXLAN!
        if (pIcmpHeader->type == 3 && pIcmpHeader->code == 4)
        {
            OVS_ICMP_MESSAGE_DEST_UNREACH* pIcmpT3C4 = (OVS_ICMP_MESSAGE_DEST_UNREACH*)pIcmpHeader;

            if (pIcmpT3C4->ipv4Header.Protocol == OVS_IPPROTO_GRE)
            {
                UINT16 nextHopMtu = pIcmpT3C4->nextHopMtu;
                nextHopMtu = RtlUshortByteSwap(nextHopMtu);

                if (nextHopMtu)
                {
                    const OVS_GRE_HEADER_2890* pGre = AdvanceIpv4Header(&pIcmpT3C4->ipv4Header);
                    ULONG greSize = Gre_FrameHeaderSize(pGre);
                    OVS_CHECK(greSize <= OVS_MAX_GRE_HEADER_SIZE);

                    if (nextHopMtu > greSize + pIcmpT3C4->ipv4Header.HeaderLength * sizeof(DWORD))
                    {
                        ULONG icmpHeaderSize;
                        nextHopMtu -= (UINT16)greSize;

                        pIcmpT3C4->nextHopMtu = RtlUshortByteSwap(nextHopMtu);

                        icmpHeaderSize = OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE + pIcmpT3C4->ipv4Header.HeaderLength * sizeof(DWORD) + 8;
                        pIcmpT3C4->header.checksum = (UINT16)ComputeIpChecksum((BYTE*)pIcmpT3C4, icmpHeaderSize);
                        pIcmpT3C4->header.checksum = RtlUshortByteSwap(pIcmpT3C4->header.checksum);
                    }
                }
            }
        }

        //turn each byte as word & turn to BE
        pPacketInfo->tpInfo.sourcePort = RtlUshortByteSwap(pIcmpHeader->type);
        pPacketInfo->tpInfo.destinationPort = RtlUshortByteSwap(pIcmpHeader->code);
    }

    return TRUE;
}

static VOID _ExtractIcmp6(VOID* pNbBuffer, ULONG nbLen, OVS_ICMP_HEADER* pIcmpHeader, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    if (pIcmpHeader->code == 0)
    {
        if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_ADVERTISMENT ||
            pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_SOLICITATION)
        {
            OVS_ICMP6_ND_OPTION* pOption = NULL;
            UINT offset = (UINT)((BYTE*)pIcmpHeader - (BYTE*)pNbBuffer);
            UINT icmpLen = nbLen - offset;

            if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_SOLICITATION)
            {
                OVS_ICMP6_NEIGHBOR_SOLICITATION* pNS = (OVS_ICMP6_NEIGHBOR_SOLICITATION*)pIcmpHeader;
                BOOLEAN haveSourceMac = FALSE;
                UINT optionLen = 0;
                pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp = pNS->targetIp;
                pOption = (OVS_ICMP6_ND_OPTION*)((BYTE*)pNS + sizeof(OVS_ICMP6_NEIGHBOR_SOLICITATION));

                icmpLen -= sizeof(OVS_ICMP6_NEIGHBOR_SOLICITATION);

                while (icmpLen > 0)
                {
                    OVS_CHECK(icmpLen >= 8);

                    if (pOption->type == OVS_ICMP6_ND_OPTION_SOURCE_LINK_ADDRESS)
                    {
                        haveSourceMac = TRUE;

                        OVS_ICMP6_ND_OPTION_LINK_ADDRESS* pLinkAddrOption = (OVS_ICMP6_ND_OPTION_LINK_ADDRESS*)pOption;
                        RtlCopyMemory(pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndSourceMac, pLinkAddrOption->macAddress, OVS_ETHERNET_ADDRESS_LENGTH);

                        break;
                    }

                    optionLen = pOption->length * 8;
                    icmpLen -= optionLen;
                    pOption = (OVS_ICMP6_ND_OPTION*)((BYTE*)pOption + optionLen);
                }
            }
            else if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_ADVERTISMENT)
            {
                OVS_ICMP6_NEIGHBOR_ADVERTISMENT* pNA = (OVS_ICMP6_NEIGHBOR_ADVERTISMENT*)pIcmpHeader;
                BOOLEAN haveTargetMac = FALSE;
                UINT optionLen = 0;
                pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp = pNA->targetIp;
                pOption = (OVS_ICMP6_ND_OPTION*)((BYTE*)pNA + sizeof(OVS_ICMP6_NEIGHBOR_ADVERTISMENT));

                icmpLen -= sizeof(OVS_ICMP6_NEIGHBOR_ADVERTISMENT);

                while (icmpLen > 0)
                {
                    OVS_CHECK(icmpLen >= 8);

                    if (pOption->type == OVS_ICMP6_ND_OPTION_TARGET_LINK_ADDRESS)
                    {
                        haveTargetMac = TRUE;

                        OVS_ICMP6_ND_OPTION_LINK_ADDRESS* pLinkAddrOption = (OVS_ICMP6_ND_OPTION_LINK_ADDRESS*)pOption;
                        RtlCopyMemory(pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetMac, pLinkAddrOption->macAddress, OVS_ETHERNET_ADDRESS_LENGTH);

                        break;
                    }

                    optionLen = pOption->length * 8;
                    icmpLen -= optionLen;
                    pOption = (OVS_ICMP6_ND_OPTION*)((BYTE*)pOption + optionLen);
                }
            }
        }
    }

    //turn each byte as word & turn to BE
    pPacketInfo->tpInfo.sourcePort = RtlUshortByteSwap(pIcmpHeader->type);
    pPacketInfo->tpInfo.destinationPort = RtlUshortByteSwap(pIcmpHeader->code);
}

static BOOLEAN _ExtractIpv6(VOID* pNbBuffer, ULONG nbLen, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pNbBuffer;

    OVS_IPV6_HEADER* pIpv6Header = NULL;
    BYTE extensionType = 0;
    VOID* buffer = NULL;

    pIpv6Header = ReadIpv6Header(pEthHeader);

    pPacketInfo->netProto.ipv6Info.source = pIpv6Header->sourceAddress;
    pPacketInfo->netProto.ipv6Info.destination = pIpv6Header->destinationAddress;
    pPacketInfo->netProto.ipv6Info.flowLabel = GetIpv6FlowLabel(pIpv6Header->vcf);

    pPacketInfo->ipInfo.protocol = OVS_IPV6_EXTH_NONE;
    pPacketInfo->ipInfo.typeOfService = (UINT8)GetIpv6TrafficClass(pIpv6Header->vcf);
    pPacketInfo->ipInfo.timeToLive = pIpv6Header->hopLimit;

    buffer = GetFirstIpv6Extension(pIpv6Header, &extensionType);
    while (IsIpv6Extension(extensionType))
    {
        if (extensionType == OVS_IPV6_EXTH_FRAGMENTATION)
        {
            UINT16 fragOff = 0;
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //| Next Header | Reserved | Fragment Offset | Res | M |
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            OVS_IPV6_FRAGMENT_HEADER* pFragmentHeader = (OVS_IPV6_FRAGMENT_HEADER*)buffer;

            fragOff = GetIpv6FragmentHeader_Offset(pFragmentHeader);
            if (fragOff == 0)
            {
                UINT16 M = GetIpv6FragmentHeader_MoreFragments(pFragmentHeader);
                if (M)
                {
                    pPacketInfo->ipInfo.fragment = OVS_FRAGMENT_TYPE_FIRST_FRAG;
                }
                else
                {
                    pPacketInfo->ipInfo.fragment = OVS_FRAGMENT_TYPE_NOT_FRAG;
                }
            }
            else
            {
                pPacketInfo->ipInfo.fragment = OVS_FRAGMENT_TYPE_FRAG_N;
                //It is NOT an error if we have Ipv6 fragment N.
                //It simply means we cannot check for the TCP / UDP / ICMP6 headers
                //so we must return now.
                return TRUE;
            }
        }

        buffer = GetNextIpv6Extension(buffer, &extensionType);
    }

    pPacketInfo->ipInfo.protocol = extensionType;

    if (extensionType == OVS_IPV6_EXTH_TCP)
    {
        OVS_TCP_HEADER* pTcpHeader = (OVS_TCP_HEADER*)buffer;

        pPacketInfo->tpInfo.sourcePort = pTcpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pTcpHeader->destinationPort;

        pPacketInfo->tpInfo.tcpFlags = GetTcpFlags(pTcpHeader->flagsAndOffset);
    }
    else if (extensionType == OVS_IPV6_EXTH_UDP)
    {
        OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)buffer;

        pPacketInfo->tpInfo.sourcePort = pUdpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pUdpHeader->destinationPort;
    }
    else if (extensionType == OVS_IPV6_EXTH_SCTP)
    {
        OVS_SCTP_HEADER* pSctpHeader = (OVS_SCTP_HEADER*)buffer;

        pPacketInfo->tpInfo.sourcePort = pSctpHeader->sourcePort;
        pPacketInfo->tpInfo.destinationPort = pSctpHeader->destinationPort;
    }
    else if (extensionType == OVS_IPV6_EXTH_ICMP6)
    {
        OVS_ICMP_HEADER* pIcmpHeader = (OVS_ICMP_HEADER*)buffer;

        _ExtractIcmp6(pNbBuffer, nbLen, pIcmpHeader, pPacketInfo);
    }

    return TRUE;
}

BOOLEAN PacketInfo_Extract(_In_ VOID* pNbBuffer, ULONG nbLen, UINT16 ovsSourcePort, _Out_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    OVS_ETHERNET_HEADER_TAGGED* pEthHeaderTagged = NULL;

    OVS_CHECK(pPacketInfo);
    RtlZeroMemory(pPacketInfo, sizeof(OVS_OFPACKET_INFO));

    //OVS SPECIFIC / PHYSICAL LAYER
    //NOTE: on windows, we don't have "packet priority" and "packet mark" associated with a NET_BUFFER / NET_BUFFER_LIST
    pPacketInfo->physical.ovsInPort = ovsSourcePort;

    //I. LINK LAYER
    pEthHeader = (OVS_ETHERNET_HEADER*)pNbBuffer;
    RtlCopyMemory(pPacketInfo->ethInfo.source, pEthHeader->source_addr, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pPacketInfo->ethInfo.destination, pEthHeader->destination_addr, OVS_ETHERNET_ADDRESS_LENGTH);

    //vlan
    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        pEthHeaderTagged = (OVS_ETHERNET_HEADER_TAGGED*)pEthHeader;
        pPacketInfo->ethInfo.tci = pEthHeaderTagged->tci;

        OVS_CHECK(RtlUshortByteSwap(pPacketInfo->ethInfo.tci) & OVS_VLAN_TAG_PRESENT);

        pEthHeader = (OVS_ETHERNET_HEADER*)((BYTE*)pEthHeader + OVS_ETHERNET_VLAN_LEN);
    }

    //TODO: we don't support 802.2 frames (LLC). We may need to support them, in the future.
    //The NDIS filter part only cares about the 802.3 frames (ATM)
    pPacketInfo->ethInfo.type = pEthHeader->type;

    //II. NETWORK LAYER
    if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        BOOLEAN ok = _ExtractIpv4(pNbBuffer, pPacketInfo);

        return ok;
    }
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_ARP))
    {
        OVS_ARP_HEADER* pArp = GetArpHeader(pEthHeader);

        if (pArp->hardwareType == RtlUshortByteSwap(OVS_ARP_HARDWARE_TYPE_ETHERNET) &&
            pArp->protocolType == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) &&
            pArp->harwareLength == OVS_ETHERNET_ADDRESS_LENGTH &&
            pArp->protocolLength == OVS_IPV4_ADDRESS_LENGTH)
        {
            pPacketInfo->ipInfo.protocol = (UINT8)RtlUshortByteSwap(pArp->operation);

            RtlCopyMemory(&pPacketInfo->netProto.arpInfo.source, pArp->senderProtocolAddress, OVS_IPV4_ADDRESS_LENGTH);
            RtlCopyMemory(&pPacketInfo->netProto.arpInfo.destination, pArp->targetProtocolAddress, OVS_IPV4_ADDRESS_LENGTH);

            RtlCopyMemory(&pPacketInfo->netProto.arpInfo.sourceMac, pArp->senderHardwareAddress, OVS_ETHERNET_ADDRESS_LENGTH);
            RtlCopyMemory(&pPacketInfo->netProto.arpInfo.destinationMac, pArp->targetHardwareAddress, OVS_ETHERNET_ADDRESS_LENGTH);

            if (RtlUshortByteSwap(pArp->operation) == OVS_ARP_OPERATION_REPLY)
            {
                //we must update our arp table, to be able to find dest eth addresses, given dest ipv4 addresses (for tunneling)
                Arp_InsertTableEntry(pArp->senderProtocolAddress, pArp->senderHardwareAddress);
            }
        }
    }
    else if (pPacketInfo->ethInfo.type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        return _ExtractIpv6(pNbBuffer, nbLen, pPacketInfo);
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN PIFromArg_Tunnel(const OVS_ARGUMENT_GROUP* pArgs, _Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, BOOLEAN isMask)
{
    BOOLEAN haveTtl = FALSE;
    BE16 tunnelFlags = 0;
    SIZE_T offset = 0;
    SIZE_T size = 0;

    for (UINT i = 0; i < pArgs->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgs->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_TUNNEL_ID:
            offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, tunnelId);
            size = sizeof(pPacketInfo->tunnelInfo.tunnelId);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->tunnelInfo.tunnelId = GET_ARG_DATA(pArg, BE64);

            tunnelFlags |= OVS_TUNNEL_FLAG_KEY;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
            offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, ipv4Source);
            size = sizeof(pPacketInfo->tunnelInfo.ipv4Source);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->tunnelInfo.ipv4Source = GET_ARG_DATA(pArg, BE32);

            break;
        case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
            offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, ipv4Destination);
            size = sizeof(pPacketInfo->tunnelInfo.ipv4Destination);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->tunnelInfo.ipv4Destination = GET_ARG_DATA(pArg, BE32);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TOS:
            offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, ipv4TypeOfService);
            size = sizeof(pPacketInfo->tunnelInfo.ipv4TypeOfService);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->tunnelInfo.ipv4TypeOfService = GET_ARG_DATA(pArg, UINT8);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TTL:
            offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, ipv4TimeToLive);
            size = sizeof(pPacketInfo->tunnelInfo.ipv4TimeToLive);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->tunnelInfo.ipv4TimeToLive = GET_ARG_DATA(pArg, UINT8);

            haveTtl = TRUE;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
            tunnelFlags |= OVS_TUNNEL_FLAG_DONT_FRAGMENT;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
            tunnelFlags |= OVS_TUNNEL_FLAG_CHECKSUM;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_OAM:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GENEVE_OPTIONS:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        default:
            return FALSE;
        }
    }

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tunnelInfo, OF_PI_IPV4_TUNNEL, tunnelFlags);
    size = sizeof(pPacketInfo->tunnelInfo.tunnelFlags);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tunnelInfo.tunnelFlags = tunnelFlags;

    if (!isMask)
    {
        if (!haveTtl)
        {
            DEBUGP(LOG_ERROR, "IPV4 TUNNEL: TTL WAS NOT SPECIFIED! IT IS A REQUIRED FIELD.\n");
            return FALSE;
        }

        if (!pPacketInfo->tunnelInfo.ipv4Destination)
        {
            DEBUGP(LOG_ERROR, "IPV4 TUNNEL: DESTINATION IP ADDRESS == 0.0.0.0! \n");
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN GetIpv4TunnelFromArgumentsSimple(const OVS_ARGUMENT_GROUP* pArgs, _Inout_ OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    BE16 tunnelFlags = 0;

    for (UINT i = 0; i < pArgs->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgs->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_TUNNEL_ID:
            pTunnelInfo->tunnelId = GET_ARG_DATA(pArg, BE64);

            tunnelFlags |= OVS_TUNNEL_FLAG_KEY;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
            pTunnelInfo->ipv4Source = GET_ARG_DATA(pArg, BE32);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
            pTunnelInfo->ipv4Destination = GET_ARG_DATA(pArg, BE32);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TOS:
            pTunnelInfo->ipv4TypeOfService = GET_ARG_DATA(pArg, UINT8);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TTL:
            pTunnelInfo->ipv4TimeToLive = GET_ARG_DATA(pArg, UINT8);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
            tunnelFlags |= OVS_TUNNEL_FLAG_DONT_FRAGMENT;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
            tunnelFlags |= OVS_TUNNEL_FLAG_CHECKSUM;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_OAM:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GENEVE_OPTIONS:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        default:
            return FALSE;
        }
    }

    pTunnelInfo->tunnelFlags = tunnelFlags;

    return TRUE;
}

VOID PIFromArg_PacketPriority(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    SIZE_T offset = 0, size = 0;

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, physical, OVS_PHYSICAL, packetPriority);
    size = sizeof(pPacketInfo->physical.packetPriority);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->physical.packetPriority = GET_ARG_DATA(pArg, UINT32);
}

VOID PIFromArg_DatapathHash(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    SIZE_T offset = 0, size = 0;

    offset = OFFSET_OF(OVS_OFPACKET_INFO, flowHash);
    size = sizeof(pPacketInfo->flowHash);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->flowHash = GET_ARG_DATA(pArg, UINT32);
}

VOID PIFromArg_DatapathRecirculationId(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    SIZE_T offset = 0, size = 0;

    offset = OFFSET_OF(OVS_OFPACKET_INFO, recirculationId);
    size = sizeof(pPacketInfo->recirculationId);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->recirculationId = GET_ARG_DATA(pArg, UINT32);
}

BOOLEAN PIFromArg_DatapathInPort(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    SIZE_T offset = 0, size = 0;
    UINT32 inPort = GET_ARG_DATA(pArg, UINT32);

    if (isMask)
    {
        inPort = OVS_PI_MASK_MATCH_EXACT(UINT32);
    }
    else if (inPort >= OVS_MAX_PORTS)
    {
        return FALSE;
    }

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, physical, OVS_PHYSICAL, ovsInPort);
    size = sizeof(pPacketInfo->physical.ovsInPort);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->physical.ovsInPort = (UINT16)inPort;

    return TRUE;
}

VOID PIFromArg_PacketMark(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    SIZE_T offset = 0, size = 0;
    UINT32 packetMark = GET_ARG_DATA(pArg, UINT32);

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, physical, OVS_PHYSICAL, packetMark);
    size = sizeof(pPacketInfo->physical.packetMark);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->physical.packetMark = packetMark;
}

VOID PIFromArg_SetDefaultDatapathInPort(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, BOOLEAN isMask)
{
    SIZE_T offset = 0, size = 0;

    if (isMask)
    {
        //if isMask and mask attr not specified, we assume it's 'any'
    }
    else
    {
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, physical, OVS_PHYSICAL, ovsInPort);
        size = sizeof(pPacketInfo->physical.ovsInPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->physical.ovsInPort = OVS_INVALID_PORT_NUMBER;
    }
}

static VOID _GetPIFromArg_EthAddress(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pEthAddressArg)
{
    SIZE_T offset = 0;
    const OVS_PI_ETH_ADDRESS* pEthAddressPI = NULL;

    pEthAddressPI = pEthAddressArg->data;

    //mem copy packet info: eth source
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, source);
    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->ethInfo.source, pEthAddressPI->source, OVS_ETHERNET_ADDRESS_LENGTH);

    //mem copy packet info: eth destination
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, destination);
    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->ethInfo.destination, pEthAddressPI->destination, OVS_ETHERNET_ADDRESS_LENGTH);
}

static BOOLEAN _GetPIFromArg_VlanTci(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pVlanTciArg, _In_ BOOLEAN isMask)
{
    BE16 tci = GET_ARG_DATA(pVlanTciArg, BE16);
    SIZE_T offset = 0, size = 0;

    if (!(tci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        if (isMask)
        {
            DEBUGP(LOG_ERROR, "VLAN TCI MASK: EXPECTED EXACT MATCH FOR THE OVS_VLAN_TAG_PRESENT BIT.\n");
        }
        else
        {
            DEBUGP(LOG_ERROR, "VLAN TCI PI: EXPECTED OVS_VLAN_TAG_PRESENT BIT TO BE SET.\n");
        }

        return FALSE;
    }

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, tci);
    size = sizeof(pPacketInfo->ethInfo.tci);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ethInfo.tci = tci;

    return TRUE;
}

static BOOLEAN _GetPIFromArg_EthType(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pEthTypeArg, _In_ BOOLEAN isMask)
{
    BE16 ethType = GET_ARG_DATA(pEthTypeArg, BE16);
    SIZE_T offset = 0, size = 0;

    if (isMask)
    {
        ethType = OVS_PI_MASK_MATCH_EXACT(UINT16);
    }
    else if (RtlUshortByteSwap(ethType) < OVS_ETHERTYPE_802_3_MIN)
    {
        DEBUGP(LOG_ERROR, "INVALID ETH TYPE: %X. MINIMUM ACCEPTABLE IS 802.3 (I.E. 0X0600)\n", RtlUshortByteSwap(ethType));
        return FALSE;
    }

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, type);
    size = sizeof(pPacketInfo->ethInfo.type);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ethInfo.type = ethType;

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Ipv4(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIpv4Arg, _In_ BOOLEAN isMask)
{
    const OVS_PI_IPV4* pIpv4Info = pIpv4Arg->data;
    SIZE_T offset, size;

    if (!isMask)
    {
        if (pIpv4Info->fragmentType > OVS_FRAGMENT_TYPE_MAX)
        {
            DEBUGP(LOG_ERROR, "IPV4 PI: INVALID FRAGMENT TYPE: %d\n", pIpv4Info->fragmentType);
            return FALSE;
        }
    }

    //1. ip protocol
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, protocol);
    size = sizeof(pPacketInfo->ipInfo.protocol);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.protocol = pIpv4Info->protocol;

    //2. TOS
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, typeOfService);
    size = sizeof(pPacketInfo->ipInfo.typeOfService);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.typeOfService = pIpv4Info->tos;

    //TTL
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, timeToLive);
    size = sizeof(pPacketInfo->ipInfo.timeToLive);
    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.timeToLive = pIpv4Info->ttl;

    //fragmentation type
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, fragment);
    size = sizeof(pPacketInfo->ipInfo.fragment);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.fragment = pIpv4Info->fragmentType;

    //ip addr src
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv4Info, OVS_IP4_INFO, source.S_un.S_addr);
    size = sizeof(pPacketInfo->netProto.ipv4Info.source.S_un.S_addr);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->netProto.ipv4Info.source.S_un.S_addr = pIpv4Info->source;

    //ip addr dest
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv4Info, OVS_IP4_INFO, destination.S_un.S_addr);
    size = sizeof(pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr = pIpv4Info->destination;

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Ipv6(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIpv4Arg, _In_ BOOLEAN isMask)
{
    const OVS_PI_IPV6* pIpv6Info = pIpv4Arg->data;
    SIZE_T offset, size;

    if (!isMask)
    {
        if (pIpv6Info->fragmentType > OVS_FRAGMENT_TYPE_MAX)
        {
            DEBUGP(LOG_ERROR, "IPV6: INVALID FRAGMENT TYPE: %d\n", pIpv6Info->fragmentType);
            return FALSE;
        }
    }

    //ip6 label
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, flowLabel);
    size = sizeof(pPacketInfo->netProto.ipv6Info.flowLabel);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->netProto.ipv6Info.flowLabel = pIpv6Info->label;

    //ip proto
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, protocol);
    size = sizeof(pPacketInfo->ipInfo.protocol);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.protocol = pIpv6Info->protocol;

    //TOS
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, typeOfService);
    size = sizeof(pPacketInfo->ipInfo.typeOfService);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.typeOfService = pIpv6Info->trafficClass;

    //TTL
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, timeToLive);
    size = sizeof(pPacketInfo->ipInfo.timeToLive);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.timeToLive = pIpv6Info->highLimit;

    //fragmentation
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, fragment);
    size = sizeof(pPacketInfo->ipInfo.fragment);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.fragment = pIpv6Info->fragmentType;

    //mem copy: ip6 src addr
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, source);
    size = sizeof(pPacketInfo->netProto.ipv6Info.source);

    _UpdateRange(pPiRange, offset, size);
    RtlCopyMemory(&pPacketInfo->netProto.ipv6Info.source, pIpv6Info->source, sizeof(pPacketInfo->netProto.ipv6Info.source));

    //mem copy: ip6 dest addr
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, destination);
    size = sizeof(pPacketInfo->netProto.ipv6Info.destination);

    _UpdateRange(pPiRange, offset, size);
    RtlCopyMemory(&pPacketInfo->netProto.ipv6Info.destination, pIpv6Info->destination, sizeof(pPacketInfo->netProto.ipv6Info.destination));

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Arp(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArpArg, _In_ BOOLEAN isMask)
{
    const OVS_PI_ARP* pArpPI = pArpArg->data;
    SIZE_T size = 0, offset = 0;

    if (!isMask)
    {
        if (RtlUshortByteSwap(pArpPI->operation) > MAXUINT8)
        {
            DEBUGP(LOG_ERROR, "ARP PI: UNKNOWN OPERATION CODE: %d.\n", pArpPI->operation);
            return FALSE;
        }
    }

    //src ip
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv4Info, OVS_IP4_INFO, source.S_un.S_addr);
    size = sizeof(pPacketInfo->netProto.ipv4Info.source.S_un.S_addr);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->netProto.ipv4Info.source.S_un.S_addr = pArpPI->sourceIp;

    //dest ip
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv4Info, OVS_IP4_INFO, destination.S_un.S_addr);
    size = sizeof(pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->netProto.ipv4Info.destination.S_un.S_addr = pArpPI->targetIp;

    //proto
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, protocol);
    size = sizeof(pPacketInfo->ipInfo.protocol);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.protocol = (UINT8)RtlUshortByteSwap(pArpPI->operation);

    //mem copy: mac src addr
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.arpInfo, OVS_ARP_INFO, sourceMac);

    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->netProto.arpInfo.sourceMac, pArpPI->sourceMac, OVS_ETHERNET_ADDRESS_LENGTH);

    //mem copy: mac dest addr
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.arpInfo, OVS_ARP_INFO, destinationMac);
    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->netProto.arpInfo.destinationMac, pArpPI->targetMac, OVS_ETHERNET_ADDRESS_LENGTH);

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Mpls(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    const OVS_PI_MPLS* pMplsPI = pArg->data;
    SIZE_T size = 0, offset = 0;

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ipInfo, OVS_NET_LAYER_INFO, mplsTopLabelStackEntry);
    size = sizeof(pPacketInfo->ipInfo.mplsTopLabelStackEntry);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->ipInfo.mplsTopLabelStackEntry = pMplsPI->mplsLse;

    return TRUE;
}

static BOOLEAN _GetPIFromArg_TcpFlags(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg)
{
    BE16 tcpFlags = GET_ARG_DATA(pArg, BE16);
    SIZE_T size = 0, offset = 0;

    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, tcpFlags);
    size = sizeof(pPacketInfo->tpInfo.tcpFlags);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tpInfo.tcpFlags = tcpFlags;

    return TRUE;
}

static VOID _GetPIFromArg_Tcp(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pTcpArg, BOOLEAN haveIpv4)
{
    const OVS_PI_TCP* pTcpPI = pTcpArg->data;
    SIZE_T offset = 0, size = 0;

    if (haveIpv4)
    {
        //src port
        NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pTcpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pTcpPI->destination;
    }
    else
    {
        //src port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pTcpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pTcpPI->destination;
    }
}

static VOID _GetPIFromArg_Udp(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pUdpArg, BOOLEAN haveIpv4)
{
    const OVS_PI_UDP* pUdpPI = pUdpArg->data;
    SIZE_T offset = 0, size = 0;

    if (haveIpv4)
    {
        //src port
        NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pUdpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pUdpPI->destination;
    }
    else
    {
        //src port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pUdpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pUdpPI->destination;
    }
}

static VOID _GetPIFromArg_Sctp(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pSctpArg, BOOLEAN haveIpv4)
{
    const OVS_PI_SCTP* pSctpPI = pSctpArg->data;
    SIZE_T offset = 0, size = 0;

    if (haveIpv4)
    {
        //src port
        NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pSctpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pSctpPI->destination;
    }
    else
    {
        //src port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
        size = sizeof(pPacketInfo->tpInfo.sourcePort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.sourcePort = pSctpPI->source;

        //dest port
        offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
        size = sizeof(pPacketInfo->tpInfo.destinationPort);

        _UpdateRange(pPiRange, offset, size);
        pPacketInfo->tpInfo.destinationPort = pSctpPI->destination;
    }
}

static VOID _GetPIFromArg_Icmp4(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIcmp4Arg)
{
    const OVS_PI_ICMP* pIcmpPI = pIcmp4Arg->data;
    SIZE_T offset = 0, size = 0;

    //type
    NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
    size = sizeof(pPacketInfo->tpInfo.sourcePort);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tpInfo.sourcePort = RtlUshortByteSwap(pIcmpPI->type);

    //code
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
    size = sizeof(pPacketInfo->tpInfo.destinationPort);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tpInfo.destinationPort = RtlUshortByteSwap(pIcmpPI->code);
}

static VOID _GetPIFromArg_Icmp6(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIcmp6Arg)
{
    const OVS_PI_ICMP6* pIcmpv6PI = pIcmp6Arg->data;
    SIZE_T offset = 0, size = 0;

    //type
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, sourcePort);
    size = sizeof(pPacketInfo->tpInfo.sourcePort);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tpInfo.sourcePort = RtlUshortByteSwap(pIcmpv6PI->type);

    //code
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, tpInfo, OVS_TRANSPORT_LAYER_INFO, destinationPort);
    size = sizeof(pPacketInfo->tpInfo.destinationPort);

    _UpdateRange(pPiRange, offset, size);
    pPacketInfo->tpInfo.destinationPort = RtlUshortByteSwap(pIcmpv6PI->code);
}

static VOID _GetPIFromArg_NeighborDiscovery(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIcmp6NdArg)
{
    const OVS_PI_NEIGHBOR_DISCOVERY* pNdPacketInfo = pIcmp6NdArg->data;
    SIZE_T sizeToCopy = 0;
    SIZE_T offset = 0;

    sizeToCopy = sizeof(pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp);

    //mem copy: ip6 net discovery target ip
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, neighborDiscovery.ndTargetIp);

    _UpdateRange(pPiRange, offset, sizeToCopy);
    RtlCopyMemory(&pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetIp, pNdPacketInfo->targetIp, sizeToCopy);

    //mem copy: ip6 net discovery src mac
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, neighborDiscovery.ndSourceMac);
    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndSourceMac, pNdPacketInfo->sourceMac, OVS_ETHERNET_ADDRESS_LENGTH);

    //mem copy: ip6 net discovery target mac
    offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, netProto.ipv6Info, OVS_IPV6_INFO, neighborDiscovery.ndTargetMac);

    _UpdateRange(pPiRange, offset, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(&pPacketInfo->netProto.ipv6Info.neighborDiscovery.ndTargetMac, pNdPacketInfo->targetMac, OVS_ETHERNET_ADDRESS_LENGTH);
}

BOOLEAN GetPacketInfoFromArguments(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, _In_ BOOLEAN isMask)
{
    BOOLEAN haveIpv4 = FALSE;
    OVS_ARGUMENT* pVlanTciArg = NULL, *pEthTypeArg = NULL, *pDatapathInPortArg = NULL;

    OVS_CHECK(pPacketInfo);
    OVS_CHECK(pPiRange);

    for (UINT i = 0; i < pPIGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pPIGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_DATAPATH_HASH:
            PIFromArg_DatapathHash(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID:
            PIFromArg_DatapathRecirculationId(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_PACKET_PRIORITY:
            PIFromArg_PacketPriority(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_DP_INPUT_PORT:
            pDatapathInPortArg = pArg;
            if (!PIFromArg_DatapathInPort(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_PACKET_MARK:
            PIFromArg_PacketMark(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            OVS_CHECK(IsArgTypeGroup(pArg->type));

            if (!PIFromArg_Tunnel(pArg->data, pPacketInfo, pPiRange, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_ETH_ADDRESS:
            _GetPIFromArg_EthAddress(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_VLAN_TCI:
            pVlanTciArg = pArg;
            if (!_GetPIFromArg_VlanTci(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_ETH_TYPE:
            pEthTypeArg = pArg;
            if (!_GetPIFromArg_EthType(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_IPV4:
            haveIpv4 = TRUE;

            if (!_GetPIFromArg_Ipv4(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV6:
            if (!_GetPIFromArg_Ipv6(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_ARP:
            if (!_GetPIFromArg_Arp(pPacketInfo, pPiRange, pArg, isMask))
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_PI_MPLS:
            _GetPIFromArg_Mpls(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_TCP:
            _GetPIFromArg_Tcp(pPacketInfo, pPiRange, pArg, haveIpv4);
            break;

        case OVS_ARGTYPE_PI_TCP_FLAGS:
            _GetPIFromArg_TcpFlags(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_UDP:
            _GetPIFromArg_Udp(pPacketInfo, pPiRange, pArg, haveIpv4);
            break;

        case OVS_ARGTYPE_PI_SCTP:
            _GetPIFromArg_Sctp(pPacketInfo, pPiRange, pArg, haveIpv4);
            break;

        case OVS_ARGTYPE_PI_ICMP:
            _GetPIFromArg_Icmp4(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_ICMP6:
            _GetPIFromArg_Icmp6(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            _GetPIFromArg_NeighborDiscovery(pPacketInfo, pPiRange, pArg);
            break;

        default:
            DEBUGP(LOG_ERROR, __FUNCTION__ " unexpected key / mask arg type: %u\n", pArg->type);
            return FALSE;
        }
    }

    if (!pDatapathInPortArg)
    {
        PIFromArg_SetDefaultDatapathInPort(pPacketInfo, pPiRange, isMask);
    }

    if (!pVlanTciArg)
    {
        if (!isMask)
        {
            SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, tci);
            SIZE_T size = sizeof(pPacketInfo->ethInfo.tci);

            _UpdateRange(pPiRange, offset, size);

            //TODO: we should normally set vlan tci to 0xFFFF in this case.
            pPacketInfo->ethInfo.tci = 0;
        }
    }

    if (!pEthTypeArg)
    {
        if (isMask)
        {
            SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, type);
            SIZE_T size = sizeof(pPacketInfo->ethInfo.type);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->ethInfo.type = OVS_PI_MASK_MATCH_EXACT(UINT16);
        }
        else
        {
            /*//TODO: in the future, we might need to support OVS_ETHERTYPE_802_2. i.e. here, to set ethInfo.type == OVS_ETHERTYPE_802_2
            DEBUGP(LOG_ERROR, "WE ONLY DEAL WITH 802.3 ETHERNET FRAMES!\n");
            return FALSE;*/
            SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, ethInfo, OVS_ETH_INFO, type);
            SIZE_T size = sizeof(pPacketInfo->ethInfo.type);

            _UpdateRange(pPiRange, offset, size);
            pPacketInfo->ethInfo.type = RtlUshortByteSwap(OVS_ETHERTYPE_802_2);
        }
    }

    return TRUE;
}

void ApplyMaskToPacketInfo(_Inout_ OVS_OFPACKET_INFO* pDestinationPI, _In_ const OVS_OFPACKET_INFO* pSourcePI, _In_ const OVS_FLOW_MASK* pMask)
{
    const UINT64* pMask_QWord = (UINT64*)((UINT8*)&pMask->packetInfo + pMask->piRange.startRange);
    const UINT64* pUnmaskedPI_QWord = (UINT64*)((UINT8*)pSourcePI + pMask->piRange.startRange);

    UINT64* pMaskedPI_QWord = NULL;
    UINT16 range = 0;

    pMaskedPI_QWord = (UINT64*)((UINT8*)pDestinationPI + pMask->piRange.startRange);
    range = (UINT16)(pMask->piRange.endRange - pMask->piRange.startRange);

    for (SIZE_T i = 0; i < range; i += sizeof(UINT64))
    {
        *pMaskedPI_QWord = *pUnmaskedPI_QWord & *pMask_QWord;

        ++pMaskedPI_QWord;
        ++pUnmaskedPI_QWord;
        ++pMask_QWord;
    }
}

BOOLEAN PacketInfo_EqualAtRange(const OVS_OFPACKET_INFO* pLhsPI, const OVS_OFPACKET_INFO* pRhsPI, SIZE_T startRange, SIZE_T endRange)
{
    BYTE* pLhs = (UINT8*)pLhsPI + startRange;
    BYTE* pRhs = (UINT8*)pRhsPI + startRange;
    SIZE_T range = endRange - startRange;

    return !memcmp(pLhs, pRhs, range);
}

BOOLEAN PacketInfo_Equal(const OVS_OFPACKET_INFO* pLhs, const OVS_OFPACKET_INFO* pRhs, SIZE_T endRange)
{
    SIZE_T startRange = 0;

    //if we have tunnelInfo.ipv4Destination, it means that we have a valid tunnel key.
    //This means that this packet (for which we have extracted packet info) is encapsulated (e.g. in GRE)
    //So the flow that is constructed must match flows against the tunnelInfo part as well.
    //And the tunnelInfo part starts at offset 0 in a packet info.
    if (pRhs->tunnelInfo.ipv4Destination)
    {
        startRange = 0;
    }
    else
    {
        startRange = RoundDown(OFFSET_OF(OVS_OFPACKET_INFO, physical), sizeof(INT64));
    }

    return PacketInfo_EqualAtRange(pLhs, pRhs, startRange, endRange);
}