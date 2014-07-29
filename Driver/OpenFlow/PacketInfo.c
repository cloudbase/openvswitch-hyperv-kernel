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
#include "OFPort.h"
#include "Ipv4.h"
#include "Tcp.h"
#include "Udp.h"
#include "Sctp.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Gre.h"
#include "Checksum.h"

#define OVS_PI_ARG_IN_ARRAY(args, argType) args[OVS_ARG_TOINDEX(argType, PI)]

#define OVS_PI_SET_TP(pPacketInfo, pTpHeader)                                       \
{                                                                                   \
    (pPacketInfo)->tpInfo.sourcePort = (pTpHeader)->sourcePort;                     \
    (pPacketInfo)->tpInfo.destinationPort = (pTpHeader)->destinationPort;           \
}

#define _OVS_PI_SET_IPV4_TP(Type, pTpHeader, pIpv4Head, pPacketInfo)            \
Type* pTpHeader = (Type*)AdvanceIpv4Header((pIpv4Header));                      \
                                                                                \
OVS_PI_SET_TP((pPacketInfo), (pTpHeader))                                       \

#define OVS_PI_SET_IPV4_TP(Type, pIpv4Head, pPacketInfo)                            \
{                                                                                   \
    _OVS_PI_SET_IPV4_TP(Type, pTpHeader, pIpv4Head, pPacketInfo)                    \
}

#define OVS_PI_SET_IPV6_TP_TCP(pPacketInfo, pTpHeader)                          \
{                                                                               \
    OVS_PI_SET_TP(pPacketInfo, pTpHeader)                                       \
    (pPacketInfo)->tpInfo.tcpFlags = GetTcpFlags((pTpHeader)->flagsAndOffset);  \
}

#define OVS_PI_SET_IPV4_TP_TCP(pIpv4Head, pPacketInfo)                              \
{                                                                                   \
    _OVS_PI_SET_IPV4_TP(OVS_TCP_HEADER, pTpHeader, pIpv4Head, pPacketInfo)          \
    (pPacketInfo)->tpInfo.tcpFlags = GetTcpFlags(pTpHeader->flagsAndOffset);        \
}

/*************************************************/

#define OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, ElemType, elem, field, value)           \
{                                                                                               \
    SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, elem, ElemType, field);                 \
    SIZE_T size = sizeof((pPacketInfo)->elem.field);                                            \
                                                                                                \
    _UpdateRange((pPiRange), offset, size);                                                     \
    (pPacketInfo)->elem.field = (value);                                                        \
}

#define OVS_PI_UPDATE_MAIN_VALUE(pPacketInfo, pPiRange, field, value)                           \
{                                                                                               \
    SIZE_T offset = OFFSET_OF(OVS_OFPACKET_INFO, field);                                        \
    SIZE_T size = sizeof((pPacketInfo)->field);                                                 \
                                                                                                \
    _UpdateRange(pPiRange, offset, size);                                                       \
    (pPacketInfo)->field = (value);                                                             \
}

#define OVS_PI_UPDATE_ELEM_BYTES(pPacketInfo, pPiRange, ElemType, elem, field, data, size)      \
{                                                                                               \
    SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, elem, ElemType, field);                 \
                                                                                                \
    _UpdateRange(pPiRange, offset, (size));                                                     \
    RtlCopyMemory((pPacketInfo)->elem.field, (data), (size));                                   \
}

#define OVS_PI_UPDATE_ELEM_BYTES_FIELD(pPacketInfo, pPiRange, ElemType, elem, field, data, size)    \
{                                                                                                   \
    SIZE_T offset = NESTED_OFFSET_OF(OVS_OFPACKET_INFO, elem, ElemType, field);                     \
                                                                                                    \
    _UpdateRange(pPiRange, offset, (size));                                                         \
    RtlCopyMemory(&((pPacketInfo)->elem.field), (data), (size));                                    \
}

/*************************************************/

#define OVS_PI_UPDATE_TUNNEL_FIELD_VALUE(pPacketInfo, pPiRange, field, value)               \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OF_PI_IPV4_TUNNEL, tunnelInfo, field, value)

#define OVS_PI_UPDATE_PHYSICAL_FIELD_VALUE(pPacketInfo, pPiRange, field, value)             \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_PHYSICAL, physical, field, value)

#define OVS_PI_UPDATE_ETHINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                        \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_ETH_INFO, ethInfo, field, value)

#define OVS_PI_UPDATE_IPV4INFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                       \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_IP4_INFO, netProto.ipv4Info, field, value)

#define OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                        \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_NET_LAYER_INFO, ipInfo, field, value)

#define OVS_PI_UPDATE_IPV6INFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                       \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_IPV6_INFO, netProto.ipv6Info, field, value)

#define OVS_PI_UPDATE_ARPINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                        \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_ARP_INFO, netProto.arpInfo, field, value)

#define OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, value)                         \
    OVS_PI_UPDATE_ELEM_VALUE(pPacketInfo, pPiRange, OVS_TRANSPORT_LAYER_INFO, tpInfo, field, value)

/*************************************************/

#define OVS_PI_UPDATE_ETHINFO_ADDRESS(pPacketInfo, pPiRange, field, data)                         \
    OVS_PI_UPDATE_ELEM_BYTES(pPacketInfo, pPiRange, OVS_ETH_INFO, ethInfo, field, data, OVS_ETHERNET_ADDRESS_LENGTH)

#define OVS_PI_UPDATE_IPV6INFO_ADDRESS(pPacketInfo, pPiRange, field, data)                         \
    OVS_PI_UPDATE_ELEM_BYTES_FIELD(pPacketInfo, pPiRange, OVS_IPV6_INFO, netProto.ipv6Info, field, data, sizeof(IN6_ADDR))

#define OVS_PI_UPDATE_IPV6INFO_BYTES(pPacketInfo, pPiRange, field, size, data)                         \
    OVS_PI_UPDATE_ELEM_BYTES(pPacketInfo, pPiRange, OVS_IPV6_INFO, netProto.ipv6Info, field, data, size)

#define OVS_PI_UPDATE_ARPINFO_ADDRESS(pPacketInfo, pPiRange, field, data)                         \
    OVS_PI_UPDATE_ELEM_BYTES(pPacketInfo, pPiRange, OVS_ARP_INFO, netProto.arpInfo, field, data, OVS_ETHERNET_ADDRESS_LENGTH)

/*************************************************/

#define OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, Type, field)                          \
    OVS_PI_UPDATE_TUNNEL_FIELD_VALUE(pPacketInfo, pPiRange, field, GET_ARG_DATA(pArg, Type))

#define OVS_PI_UPDATE_PHYSICAL_FIELD(pPacketInfo, pPiRange, pArg, Type, field)                        \
    OVS_PI_UPDATE_PHYSICAL_FIELD_VALUE(pPacketInfo, pPiRange, field, GET_ARG_DATA(pArg, Type))

#define OVS_PI_UPDATE_ETHINFO_FIELD(pPacketInfo, pPiRange, pArg, Type, field)                         \
    OVS_PI_UPDATE_ETHINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, GET_ARG_DATA(pArg, Type))

#define OVS_PI_UPDATE_TPINFO_FIELD(pPacketInfo, pPiRange, pArg, Type, field)                          \
    OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, field, GET_ARG_DATA(pArg, Type))

#define OVS_PI_UPDATE_MAIN_FIELD(pPacketInfo, pPiRange, pArg, Type, field)                            \
    OVS_PI_UPDATE_MAIN_VALUE(pPacketInfo, pPiRange, field, (Type)GET_ARG_DATA(pArg, Type))


/****************************************************************/

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

static VOID _ExtractIpv4_Icmp(const OVS_IPV4_HEADER* pIpv4Header, OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ICMP_HEADER* const pIcmpHeader = (OVS_ICMP_HEADER*)AdvanceIpv4Header(pIpv4Header);

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

                    icmpHeaderSize = OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE + pIcmpT3C4->ipv4Header.HeaderLength * sizeof(DWORD)+8;
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

    switch (pPacketInfo->ipInfo.protocol)
    {
    case OVS_IPPROTO_TCP:
        OVS_PI_SET_IPV4_TP_TCP(pIpv4Header, pPacketInfo);
        break;

    case OVS_IPPROTO_UDP:
        OVS_PI_SET_IPV4_TP(OVS_UDP_HEADER, pIpv4Header, pPacketInfo);
        break;

    case OVS_IPPROTO_SCTP:
        OVS_PI_SET_IPV4_TP(OVS_SCTP_HEADER, pIpv4Header, pPacketInfo);
        break;

    case OVS_IPPROTO_ICMP:
        _ExtractIpv4_Icmp(pIpv4Header, pPacketInfo);
        break;
    }

    return TRUE;
}

static VOID _ExtractIcmp6_NeighborSolicitation(OVS_ICMP_HEADER* pIcmpHeader, OVS_OFPACKET_INFO* pPacketInfo, ULONG icmpLen)
{
    OVS_ICMP6_ND_OPTION* pOption = NULL;
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

static VOID _ExtractIcmp6_NeighborAdvertisment(OVS_ICMP_HEADER* pIcmpHeader, OVS_OFPACKET_INFO* pPacketInfo, ULONG icmpLen)
{
    OVS_ICMP6_ND_OPTION* pOption = NULL;
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

static VOID _ExtractIcmp6(VOID* pNbBuffer, ULONG nbLen, OVS_ICMP_HEADER* pIcmpHeader, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    if (pIcmpHeader->code == 0)
    {
        if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_ADVERTISMENT ||
            pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_SOLICITATION)
        {
            ULONG offset = (ULONG)((BYTE*)pIcmpHeader - (BYTE*)pNbBuffer);
            ULONG icmpLen = nbLen - offset;

            if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_SOLICITATION)
            {
                _ExtractIcmp6_NeighborSolicitation(pIcmpHeader, pPacketInfo, icmpLen);
            }
            else if (pIcmpHeader->type == OVS_ICMP6_ND_NEIGHBOR_ADVERTISMENT)
            {
                _ExtractIcmp6_NeighborAdvertisment(pIcmpHeader, pPacketInfo, icmpLen);
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

    switch (extensionType)
    {
    case OVS_IPV6_EXTH_TCP:
        OVS_PI_SET_IPV6_TP_TCP(pPacketInfo, (OVS_TCP_HEADER*)buffer);
        break;

    case OVS_IPV6_EXTH_UDP:
        OVS_PI_SET_TP(pPacketInfo, (OVS_TCP_HEADER*)buffer);
        break;

    case OVS_IPV6_EXTH_SCTP:
        OVS_PI_SET_TP(pPacketInfo, (OVS_TCP_HEADER*)buffer);
        break;

    case OVS_IPV6_EXTH_ICMP6:
        _ExtractIcmp6(pNbBuffer, nbLen, buffer, pPacketInfo);
        break;
    }

    return TRUE;
}

static VOID _ExtractArp(OVS_ETHERNET_HEADER* pEthHeader, OVS_OFPACKET_INFO* pPacketInfo)
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

BOOLEAN PacketInfo_Extract(_In_ VOID* pNbBuffer, ULONG nbLen, UINT16 ofSourcePort, _Out_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    OVS_ETHERNET_HEADER_TAGGED* pEthHeaderTagged = NULL;

    OVS_CHECK(pPacketInfo);
    RtlZeroMemory(pPacketInfo, sizeof(OVS_OFPACKET_INFO));

    //OVS SPECIFIC / PHYSICAL LAYER
    //NOTE: on windows, we don't have "packet priority" and "packet mark" associated with a NET_BUFFER / NET_BUFFER_LIST
    pPacketInfo->physical.ofInPort = ofSourcePort;

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

    switch (RtlUshortByteSwap(pPacketInfo->ethInfo.type))
    {
    case OVS_ETHERTYPE_IPV4:
        return _ExtractIpv4(pNbBuffer, pPacketInfo);

    case OVS_ETHERTYPE_IPV6:
        return _ExtractIpv6(pNbBuffer, nbLen, pPacketInfo);

    case OVS_ETHERTYPE_ARP:
        _ExtractArp(pEthHeader, pPacketInfo);
        break;

    default:
        OVS_CHECK(__UNEXPECTED__);
    }

    return TRUE;
}

static BOOLEAN _PIFromArg_Tunnel(const OVS_ARGUMENT_GROUP* pArgs, _Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, BOOLEAN isMask)
{
    BOOLEAN haveTtl = FALSE;
    BE16 tunnelFlags = 0;

    for (UINT i = 0; i < pArgs->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgs->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_TUNNEL_ID:
            OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, BE64, tunnelId);
            tunnelFlags |= OVS_TUNNEL_FLAG_KEY;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
            OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, BE32, ipv4Source);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
            OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, BE32, ipv4Destination);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TOS:
            OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, UINT8, ipv4TypeOfService);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TTL:
            OVS_PI_UPDATE_TUNNEL_FIELD(pPacketInfo, pPiRange, pArg, UINT8, ipv4TimeToLive);

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

    OVS_PI_UPDATE_TUNNEL_FIELD_VALUE(pPacketInfo, pPiRange, tunnelFlags, tunnelFlags);

    if (!isMask)
    {
        EXPECT(haveTtl);
        EXPECT(pPacketInfo->tunnelInfo.ipv4Destination);
    }

    return TRUE;
}

static BOOLEAN _PIFromArg_DatapathInPort(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UINT16 inPort = (UINT16)GET_ARG_DATA(pArg, UINT32);

    if (isMask)
    {
        inPort = OVS_PI_MASK_MATCH_EXACT(UINT16);
    }

    if (!isMask)
    {
        EXPECT(inPort < OVS_MAX_PORTS);
    }

    OVS_PI_UPDATE_PHYSICAL_FIELD_VALUE(pPacketInfo, pPiRange, ofInPort, inPort);

    return TRUE;
}

static BOOLEAN _GetPIFromArg_EthType(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pEthTypeArg, _In_ BOOLEAN isMask)
{
    BE16 ethType = GET_ARG_DATA(pEthTypeArg, BE16);

    if (isMask)
    {
        ethType = OVS_PI_MASK_MATCH_EXACT(UINT16);
    }

    if (!isMask)
    {
        EXPECT(RtlUshortByteSwap(ethType) >= OVS_ETHERTYPE_802_3_MIN);
    }

    OVS_PI_UPDATE_ETHINFO_FIELD(pPacketInfo, pPiRange, pEthTypeArg, BE16, type);

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Ipv4(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIpv4Arg, _In_ BOOLEAN isMask)
{
    const OVS_PI_IPV4* pIpv4Info = pIpv4Arg->data;

    if (!isMask)
    {
        EXPECT(pIpv4Info->fragmentType <= OVS_FRAGMENT_TYPE_MAX);
    }

    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, protocol, pIpv4Info->protocol);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, typeOfService, pIpv4Info->tos);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, timeToLive, pIpv4Info->ttl);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, fragment, pIpv4Info->fragmentType);

    OVS_PI_UPDATE_IPV4INFO_FIELD_VALUE(pPacketInfo, pPiRange, source.S_un.S_addr, pIpv4Info->source);
    OVS_PI_UPDATE_IPV4INFO_FIELD_VALUE(pPacketInfo, pPiRange, destination.S_un.S_addr, pIpv4Info->destination);

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Ipv6(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIpv6Arg, _In_ BOOLEAN isMask)
{
    const OVS_PI_IPV6* pIpv6Info = pIpv6Arg->data;

    if (!isMask)
    {
        EXPECT(pIpv6Info->fragmentType <= OVS_FRAGMENT_TYPE_MAX);
    }

    OVS_PI_UPDATE_IPV6INFO_FIELD_VALUE(pPacketInfo, pPiRange, flowLabel, pIpv6Info->label);
    OVS_PI_UPDATE_IPV6INFO_ADDRESS(pPacketInfo, pPiRange, source, pIpv6Info->source);
    OVS_PI_UPDATE_IPV6INFO_ADDRESS(pPacketInfo, pPiRange, destination, pIpv6Info->destination);

    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, protocol, pIpv6Info->protocol);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, typeOfService, pIpv6Info->trafficClass);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, timeToLive, pIpv6Info->highLimit);
    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, fragment, pIpv6Info->fragmentType);

    return TRUE;
}

static BOOLEAN _GetPIFromArg_Arp(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArpArg, _In_ BOOLEAN isMask)
{
    const OVS_PI_ARP* pArpPI = pArpArg->data;

    if (!isMask)
    {
        EXPECT(RtlUshortByteSwap(pArpPI->operation) <= MAXUINT8);
    }

    OVS_PI_UPDATE_ARPINFO_FIELD_VALUE(pPacketInfo, pPiRange, source.S_un.S_addr, pArpPI->sourceIp);
    OVS_PI_UPDATE_ARPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destination.S_un.S_addr, pArpPI->targetIp);

    OVS_PI_UPDATE_ARPINFO_ADDRESS(pPacketInfo, pPiRange, sourceMac, pArpPI->sourceMac);
    OVS_PI_UPDATE_ARPINFO_ADDRESS(pPacketInfo, pPiRange, destinationMac, pArpPI->targetMac);

    OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, protocol, (UINT8)RtlUshortByteSwap(pArpPI->operation));

    return TRUE;
}

static VOID _GetPIFromArg_NeighborDiscovery(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pIcmp6NdArg)
{
    const OVS_PI_NEIGHBOR_DISCOVERY* pNdPacketInfo = pIcmp6NdArg->data;

    OVS_PI_UPDATE_IPV6INFO_ADDRESS(pPacketInfo, pPiRange, neighborDiscovery.ndTargetIp, pNdPacketInfo->targetIp);

    OVS_PI_UPDATE_IPV6INFO_BYTES(pPacketInfo, pPiRange, neighborDiscovery.ndSourceMac, OVS_ETHERNET_ADDRESS_LENGTH, pNdPacketInfo->sourceMac);
    OVS_PI_UPDATE_IPV6INFO_BYTES(pPacketInfo, pPiRange, neighborDiscovery.ndTargetMac, OVS_ETHERNET_ADDRESS_LENGTH, pNdPacketInfo->targetMac);

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
            OVS_PI_UPDATE_MAIN_FIELD(pPacketInfo, pPiRange, pArg, UINT32, flowHash);
            break;

        case OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID:
            OVS_PI_UPDATE_MAIN_FIELD(pPacketInfo, pPiRange, pArg, UINT32, recirculationId);
            break;

        case OVS_ARGTYPE_PI_PACKET_PRIORITY:
            OVS_PI_UPDATE_PHYSICAL_FIELD(pPacketInfo, pPiRange, pArg, UINT32, packetPriority);
            break;

        case OVS_ARGTYPE_PI_DP_INPUT_PORT:
            pDatapathInPortArg = pArg;
            EXPECT(_PIFromArg_DatapathInPort(pPacketInfo, pPiRange, pArg, isMask));
            break;

        case OVS_ARGTYPE_PI_PACKET_MARK:
            OVS_PI_UPDATE_PHYSICAL_FIELD(pPacketInfo, pPiRange, pArg, UINT32, packetMark);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            OVS_CHECK(IsArgTypeGroup(pArg->type));
            EXPECT(_PIFromArg_Tunnel(pArg->data, pPacketInfo, pPiRange, isMask));
            break;

        case OVS_ARGTYPE_PI_ETH_ADDRESS:
        {
            const OVS_PI_ETH_ADDRESS* pEthAddressPI = pArg->data;

            OVS_PI_UPDATE_ETHINFO_ADDRESS(pPacketInfo, pPiRange, source, pEthAddressPI->source);
            OVS_PI_UPDATE_ETHINFO_ADDRESS(pPacketInfo, pPiRange, destination, pEthAddressPI->destination);
        }
            break;

        case OVS_ARGTYPE_PI_VLAN_TCI:
            pVlanTciArg = pArg;
            {
                BE16 tci = GET_ARG_DATA(pVlanTciArg, BE16);

                EXPECT(tci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT));
                OVS_PI_UPDATE_ETHINFO_FIELD(pPacketInfo, pPiRange, pVlanTciArg, BE16, tci);
            }
            break;

        case OVS_ARGTYPE_PI_ETH_TYPE:
            pEthTypeArg = pArg;
            EXPECT(_GetPIFromArg_EthType(pPacketInfo, pPiRange, pArg, isMask));
            break;

        case OVS_ARGTYPE_PI_IPV4:
            haveIpv4 = TRUE;
            EXPECT(_GetPIFromArg_Ipv4(pPacketInfo, pPiRange, pArg, isMask));
            break;

        case OVS_ARGTYPE_PI_IPV6:
            EXPECT(_GetPIFromArg_Ipv6(pPacketInfo, pPiRange, pArg, isMask));
            break;

        case OVS_ARGTYPE_PI_ARP:
            EXPECT(_GetPIFromArg_Arp(pPacketInfo, pPiRange, pArg, isMask));
            break;

        case OVS_ARGTYPE_PI_MPLS:
        {
            const OVS_PI_MPLS* pMplsPI = pArg->data;

            OVS_PI_UPDATE_NETINFO_FIELD_VALUE(pPacketInfo, pPiRange, mplsTopLabelStackEntry, pMplsPI->mplsLse);
        }
            break;

        case OVS_ARGTYPE_PI_TCP:
        {
            const OVS_PI_TCP* pTcpPI = pArg->data;

            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, sourcePort, pTcpPI->source);
            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destinationPort, pTcpPI->destination);
        }
            break;

        case OVS_ARGTYPE_PI_TCP_FLAGS:
            OVS_PI_UPDATE_TPINFO_FIELD(pPacketInfo, pPiRange, pArg, BE16, tcpFlags);
            break;

        case OVS_ARGTYPE_PI_UDP:
        {
            const OVS_PI_UDP* pUdpPI = pArg->data;

            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, sourcePort, pUdpPI->source);
            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destinationPort, pUdpPI->destination);
        }
            break;

        case OVS_ARGTYPE_PI_SCTP:
        {
            const OVS_PI_SCTP* pSctpPI = pArg->data;

            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, sourcePort, pSctpPI->source);
            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destinationPort, pSctpPI->destination);
        }
            break;

        case OVS_ARGTYPE_PI_ICMP:
        {
            const OVS_PI_ICMP* pIcmpPI = pArg->data;

            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, sourcePort, RtlUshortByteSwap(pIcmpPI->type));
            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destinationPort, RtlUshortByteSwap(pIcmpPI->code));
        }
            break;

        case OVS_ARGTYPE_PI_ICMP6:
        {
            const OVS_PI_ICMP6* pIcmpv6PI = pArg->data;

            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, sourcePort, RtlUshortByteSwap(pIcmpv6PI->type));
            OVS_PI_UPDATE_TPINFO_FIELD_VALUE(pPacketInfo, pPiRange, destinationPort, RtlUshortByteSwap(pIcmpv6PI->code));
        }
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            _GetPIFromArg_NeighborDiscovery(pPacketInfo, pPiRange, pArg);
            break;

        default:
            DEBUGP(LOG_ERROR, __FUNCTION__ " unexpected key / mask arg type: %u\n", pArg->type);
            return FALSE;
        }
    }

    if (!pDatapathInPortArg && !isMask)
    {
        OVS_PI_UPDATE_PHYSICAL_FIELD_VALUE(pPacketInfo, pPiRange, packetMark, OVS_INVALID_PORT_NUMBER);
    }

    if (!pVlanTciArg)
    {
        if (!isMask)
        {
            //TODO: we should normally set vlan tci to 0xFFFF in this case.
            //but it used to work with 0 only
            OVS_PI_UPDATE_ETHINFO_FIELD_VALUE(pPacketInfo, pPiRange, tci, 0);
        }
    }

    if (!pEthTypeArg)
    {
        if (isMask)
        {
            OVS_PI_UPDATE_ETHINFO_FIELD_VALUE(pPacketInfo, pPiRange, type, OVS_PI_MASK_MATCH_EXACT(UINT16));
        }
        else
        {
            OVS_PI_UPDATE_ETHINFO_FIELD_VALUE(pPacketInfo, pPiRange, type, RtlUshortByteSwap(OVS_ETHERTYPE_802_2));
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

BOOLEAN GetPacketContextFromPIArgs(_In_ const OVS_ARGUMENT_GROUP* pArgGroup, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OF_PI_IPV4_TUNNEL* pTunnelInfo = &pPacketInfo->tunnelInfo;
    OVS_PI_RANGE piRange = { 0 };
    OVS_ARGUMENT* pArg = NULL;

    pPacketInfo->physical.ofInPort = OVS_INVALID_PORT_NUMBER;
    pPacketInfo->physical.packetPriority = 0;
    pPacketInfo->physical.packetMark = 0;

    RtlZeroMemory(pTunnelInfo, sizeof(OF_PI_IPV4_TUNNEL));

    OVS_PARSE_ARGS_QUICK(PI, pArgGroup, args);

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_DATAPATH_HASH);
    if (pArg)
    {
        OVS_PI_UPDATE_MAIN_FIELD(pPacketInfo, &piRange, pArg, UINT32, flowHash);
    }

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID);
    if (pArg)
    {
        OVS_PI_UPDATE_MAIN_FIELD(pPacketInfo, &piRange, pArg, UINT32, recirculationId);
    }

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_PACKET_PRIORITY);
    if (pArg)
    {
        OVS_PI_UPDATE_PHYSICAL_FIELD(pPacketInfo, &piRange, pArg, UINT32, packetPriority);
    }

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_PACKET_MARK);
    if (pArg)
    {
        OVS_PI_UPDATE_PHYSICAL_FIELD(pPacketInfo, &piRange, pArg, UINT32, packetMark);
    }

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_DP_INPUT_PORT);
    if (pArg)
    {
        EXPECT(_PIFromArg_DatapathInPort(pPacketInfo, &piRange, pArg, /*is mask*/FALSE));
    }
    else
    {
        OVS_PI_UPDATE_PHYSICAL_FIELD_VALUE(pPacketInfo, &piRange, packetMark, OVS_INVALID_PORT_NUMBER);
    }

    pArg = OVS_PI_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_TUNNEL_GROUP);
    if (pArg)
    {
        EXPECT(_PIFromArg_Tunnel(pArg->data, pPacketInfo, &piRange, /*is mask*/ FALSE));
    }

    return TRUE;
}