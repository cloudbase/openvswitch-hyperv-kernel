#include "ArgVerification.h"

#include "PacketInfo.h"
#include "PersistentPort.h"
#include "Icmp.h"
#include "Ipv6.h"
#include "OFFlow.h"
#include "OFAction.h"

UINT VerifyArgGroupSize(OVS_ARGUMENT_GROUP* pGroup)
{
    UINT expectedSize = 0;

    OVS_CHECK(pGroup);
    //group count can be zero, but in this case, group size must also be zero

    expectedSize = pGroup->count * OVS_ARGUMENT_HEADER_SIZE;

    for (UINT i = 0; i != pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;
        OVS_CHECK(pArg->data && pArg->length || !pArg->data && !pArg->length);

        if (IsArgTypeGroup(argType))
        {
            UINT groupSize;

            DEBUGP_ARG(LOG_INFO, "checking subgroup: ");
            DbgPrintArgType(pArg->type, "", i);

            groupSize = VerifyArgGroupSize(pArg->data);
            OVS_CHECK(pArg->length == groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE);
        }

        expectedSize += pArg->length;
    }

    OVS_CHECK(expectedSize == pGroup->groupSize);

    return pGroup->groupSize;
}

/********************************* FLOW / KEY / TUNNEL *********************************/

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelChecksum(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    //data type: no data
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelDontFragment(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    //data type: no data
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelFlags(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT16 flags = GET_ARG_DATA(pArg, UINT16);

    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (flags == OVS_PI_MASK_MATCH_WILDCARD(UINT16))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel flag is default\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelId(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE64 tunnelId = GET_ARG_DATA(pArg, BE64);

    //data type: BE64
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (tunnelId == OVS_PI_MASK_MATCH_WILDCARD(UINT64))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel id is default. no need to be set\n");
        }
    }

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelIpv4Dst(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 destAddr = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
        if (destAddr == 0)
        {
            return FALSE;
        }
    }
    //is mask
    else if (isRequest)
    {
        if (destAddr == OVS_PI_MASK_MATCH_WILDCARD(UINT32))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ipv4 dest is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelIpv4Src(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE32 ipv4Src = GET_ARG_DATA(pArg, BE32);

    //data type: BE64
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (ipv4Src == OVS_PI_MASK_MATCH_WILDCARD(UINT32))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ipv4 src is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelTos(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT8 tos = GET_ARG_DATA(pArg, UINT8);

    //data type: UINT8
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (tos == OVS_PI_MASK_MATCH_WILDCARD(UINT8))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel tos is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelTtl(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT8 ttl = GET_ARG_DATA(pArg, UINT8);

    if (!isMask)
    {
        if (ttl == 0)
        {
            return FALSE;
        }
    }
    else if (isRequest)
    {
        if (ttl == OVS_PI_MASK_MATCH_WILDCARD(UINT8))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ttl is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_FlowKeyTunnel(OVS_ARGUMENT* pParentArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = pParentArg->data;
    BOOLEAN haveDest = FALSE, haveTtl = FALSE;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
            if (!_VerifyArg_PacketInfoTunnelChecksum(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
            if (!_VerifyArg_PacketInfoTunnelDontFragment(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_ID:
            if (!_VerifyArg_PacketInfoTunnelId(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
            if (!_VerifyArg_PacketInfoTunnelIpv4Dst(pArg, isMask, isRequest))
            {
                return FALSE;
            }

            haveDest = TRUE;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
            if (!_VerifyArg_PacketInfoTunnelIpv4Src(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TOS:
            if (!_VerifyArg_PacketInfoTunnelTos(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TTL:
            if (!_VerifyArg_PacketInfoTunnelTtl(pArg, isMask, isRequest))
            {
                return FALSE;
            }

            haveTtl = TRUE;
            break;

        default:
            return FALSE;
        }
    }

    if (!isMask)
    {
        if (!haveDest || !haveTtl)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* FLOW / KEY  *********************************/

static __inline BOOLEAN _VerifyArg_PacketInfo_DpInputPort(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 inPort = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
        if (inPort > OVS_MAX_PORTS)
        {
            DEBUGP_ARG(LOG_ERROR, "the in port id is too big. max is: 0x%x; given is: 0x%x\n", OVS_MAX_PORTS, inPort);
        }
    }
    else if (isRequest)
    {
        DEBUGP_ARG(LOG_INFO, "the mask shouldn't be set for dp in port: it is always set as exact match (~0)\n");
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_EthAddress(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OVS_PI_ETH_ADDRESS* pEthAddrInfo = pArg->data;

    if (!isMask)
    {
    }
    //mask
    else if (isRequest)
    {
        OVS_PI_ETH_ADDRESS wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pEthAddrInfo, &wildcard, sizeof(OVS_PI_ETH_ADDRESS)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for eth addr is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_EthType(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    UINT16 ethType = RtlUshortByteSwap(GET_ARG_DATA(pArg, UINT16));

    UNREFERENCED_PARAMETER(isRequest);

    if (!isMask)
    {
        if (ethType < OVS_ETHERTYPE_802_3_MIN)
        {
            return FALSE;
        }

        switch (ethType)
        {
        case OVS_ETHERTYPE_ARP:
        case OVS_ETHERTYPE_RARP:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ARP))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as (r)arp, but no arp key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_IPV4:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as ipv4, but no ipv4 key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_IPV6:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as ipv6, but no ipv6 key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_QTAG:
            //must have vlan tci & encapsulation
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_VLAN_TCI))
            {
                return FALSE;
            }

            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ENCAP_GROUP))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "we don't handle ether type: 0x%x\n", ethType);
            return FALSE;
        }
    }

    //is mask & !request
    else
    {
        if (ethType != OVS_PI_MASK_MATCH_EXACT(UINT16))
        {
            DEBUGP_ARG(LOG_ERROR, "the mask for eth type should be exact match.\n");
            return FALSE;
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Icmp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ICMP* pIcmpInfo = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4))
        {
            return FALSE;
        }
    }

    //mask
    else if (isRequest)
    {
        OVS_PI_ICMP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIcmpInfo, &wildcard, sizeof(OVS_PI_ICMP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for icmp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Icmp6(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ICMP6* pIcmp6Info = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
        {
            return FALSE;
        }

        if (pIcmp6Info->type == OVS_NDISC_NEIGHBOUR_SOLICITATION ||
            pIcmp6Info->code == OVS_NDISC_NEIGHBOUR_ADVERTISEMENT)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY))
            {
                return FALSE;
            }
        }
    }

    //mask
    else if (isRequest)
    {
        OVS_PI_ICMP6 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIcmp6Info, &wildcard, sizeof(OVS_PI_ICMP6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for icmp6 is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv4(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer)
{
    OVS_PI_IPV4* pIpv4Info = pArg->data;

    if (!isMask)
    {
        if (checkTransportLayer)
        {
            if (pIpv4Info->fragmentType != OVS_FRAGMENT_TYPE_FRAG_N)
            {
                switch (pIpv4Info->protocol)
                {
                case OVS_IPPROTO_TCP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_TCP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_UDP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_UDP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_SCTP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_SCTP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_ICMP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ICMP))
                    {
                        return FALSE;
                    }
                    break;
                }
            }
        }

        switch (pIpv4Info->fragmentType)
        {
        case OVS_FRAGMENT_TYPE_NOT_FRAG:
        case OVS_FRAGMENT_TYPE_FIRST_FRAG:
        case OVS_FRAGMENT_TYPE_FRAG_N:
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "fragment type is not an enum constant!\n");
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_IPV4 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };
        int res = memcmp(pIpv4Info, &wildcard, sizeof(OVS_PI_IPV4));

        if (0 == res)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv4Tunnel(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OF_PI_IPV4_TUNNEL* pTunnelInfo = pArg->data;

    if (!isMask)
    {
    }

    //mask
    else if (isRequest)
    {
        OF_PI_IPV4_TUNNEL wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pTunnelInfo, &wildcard, sizeof(OF_PI_IPV4_TUNNEL)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ipv4 tunnel is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv6(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer)
{
    OVS_PI_IPV6* pIpv6Info = pArg->data;

    if (!isMask)
    {
        if (checkTransportLayer)
        {
            if (pIpv6Info->fragmentType != OVS_FRAGMENT_TYPE_FRAG_N)
            {
                switch (pIpv6Info->protocol)
                {
                case OVS_IPPROTO_TCP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_TCP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_UDP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_UDP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_SCTP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_SCTP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPV6_EXTH_ICMP6:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ICMP6))
                    {
                        return FALSE;
                    }
                    break;
                }
            }
        }

        switch (pIpv6Info->fragmentType)
        {
        case OVS_FRAGMENT_TYPE_NOT_FRAG:
        case OVS_FRAGMENT_TYPE_FIRST_FRAG:
        case OVS_FRAGMENT_TYPE_FRAG_N:
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "fragment type is not an enum constant!\n");
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_IPV6 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIpv6Info, &wildcard, sizeof(OVS_PI_IPV6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ipv6 is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Mpls(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented -- mpls not (yet) supported\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_NeighborDiscovery(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_NEIGHBOR_DISCOVERY* pNd = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
        {
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_NEIGHBOR_DISCOVERY wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pNd, &wildcard, sizeof(OVS_PI_IPV6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ip6 net discovery is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_PacketMark(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 packetMark = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
    }
    else
    {
        if (isRequest && packetMark == OVS_PI_MASK_MATCH_WILDCARD(UINT))
        {
            DEBUGP_ARG(LOG_LOUD, "default value is 0 / wildcard match; setting default value manually is useless overhead\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_PacketPriority(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 packetPriority = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
    }
    else
    {
        if (isRequest && packetPriority == OVS_PI_MASK_MATCH_WILDCARD(UINT))
        {
            DEBUGP_ARG(LOG_LOUD, "default value is 0 / wildcard match; setting default value manually would be useless overhead\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Sctp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_SCTP* pSctpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_SCTP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pSctpInfo, &wildcard, sizeof(OVS_PI_SCTP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for sctp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Tcp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_TCP* pTcpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_TCP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pTcpInfo, &wildcard, sizeof(OVS_PI_TCP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tcp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Udp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_UDP* pUdpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_UDP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pUdpInfo, &wildcard, sizeof(OVS_PI_UDP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for udp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Arp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ARP* pArpInfo = pArg->data;

    UNREFERENCED_PARAMETER(pParentArg);

    if (!isMask)
    {
        UINT16 op = RtlUshortByteSwap(pArpInfo->operation);

        if (op != 1 && op != 2)
        {
            DEBUGP_ARG(LOG_ERROR, "packet info / arp: unknown op code %d\n", op);
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_ARP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pArpInfo, &wildcard, sizeof(OVS_PI_ARP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for arp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_VlanTci(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE16 tci = GET_ARG_DATA(pArg, BE16);

    //it is possible we shouldn't allow to specify tci = 0 as key

    if (!isMask)
    {
    }
    else if (isRequest)
    {
        if (tci == OVS_PI_MASK_MATCH_WILDCARD(UINT16))
        {
            DEBUGP_ARG(LOG_LOUD, "tci mask should not be set as wildcard. it's the default\n");
        }
    }

    if (!(tci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        DEBUGP_ARG(LOG_ERROR, "if you set vlan tci, you must set 'tag present' = 1!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Encap(OVS_ARGUMENT* pEncArg, BOOLEAN isMask, BOOLEAN isRequest, BOOLEAN checkTransportLayer, BOOLEAN seekIp)
{
    OVS_ARGUMENT_GROUP* pGroup = pEncArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_ETH_TYPE:
            if (!_VerifyArg_PacketInfo_EthType(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP:
            if (!_VerifyArg_PacketInfo_Icmp(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP6:
            if (!_VerifyArg_PacketInfo_Icmp6(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4:
            if (!_VerifyArg_PacketInfo_Ipv4(pArg, isMask, isRequest, pEncArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV6:
            if (!_VerifyArg_PacketInfo_Ipv6(pArg, isMask, isRequest, pEncArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            if (!_VerifyArg_PacketInfo_NeighborDiscovery(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_SCTP:
            if (!_VerifyArg_PacketInfo_Sctp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TCP:
            if (!_VerifyArg_PacketInfo_Tcp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_UDP:
            if (!_VerifyArg_PacketInfo_Udp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

//pArg = FLOW/KEY
BOOLEAN VerifyGroup_PacketInfo(BOOLEAN isMask, BOOLEAN isRequest, _In_ OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer, BOOLEAN seekIp)
{
    OVS_ARGUMENT_GROUP* pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_ENCAP_GROUP:
            if (!_VerifyArg_PacketInfo_Encap(pArg, isMask, isRequest, checkTransportLayer, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            if (!_VerifyGroup_FlowKeyTunnel(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_DP_INPUT_PORT:
            if (!_VerifyArg_PacketInfo_DpInputPort(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ETH_ADDRESS:
            if (!_VerifyArg_PacketInfo_EthAddress(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ETH_TYPE:
            if (!_VerifyArg_PacketInfo_EthType(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP:
            if (!_VerifyArg_PacketInfo_Icmp(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP6:
            if (!_VerifyArg_PacketInfo_Icmp6(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4:
            if (!_VerifyArg_PacketInfo_Ipv4(pArg, isMask, isRequest, pParentArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4_TUNNEL:
            if (!_VerifyArg_PacketInfo_Ipv4Tunnel(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV6:
            if (!_VerifyArg_PacketInfo_Ipv6(pArg, isMask, isRequest, pParentArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_MPLS:
            if (!_VerifyArg_PacketInfo_Mpls(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            if (!_VerifyArg_PacketInfo_NeighborDiscovery(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_PACKET_MARK:
            if (!_VerifyArg_PacketInfo_PacketMark(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_PACKET_PRIORITY:
            if (!_VerifyArg_PacketInfo_PacketPriority(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_SCTP:
            if (!_VerifyArg_PacketInfo_Sctp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TCP:
            if (!_VerifyArg_PacketInfo_Tcp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_UDP:
            if (!_VerifyArg_PacketInfo_Udp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ARP:
            if (!_VerifyArg_PacketInfo_Arp(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_VLAN_TCI:
            if (!_VerifyArg_PacketInfo_VlanTci(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* FLOW  *********************************/
BOOLEAN VerifyArg_Flow_Clear(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    //data type: no data

    return TRUE;
}

BOOLEAN VerifyArg_Flow_Stats(OVS_ARGUMENT* pArg)
{
    OVS_WINL_FLOW_STATS* pStats = pArg->data;

    UNREFERENCED_PARAMETER(pStats);

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

BOOLEAN VerifyArg_Flow_TcpFlags(OVS_ARGUMENT* pArg)
{
    UINT8 flags = GET_ARG_DATA(pArg, UINT8);

    //data type: UINT8

    UNREFERENCED_PARAMETER(flags);

    //tcp flags / ctrl bits, without the ECN bits (because we have data type of 1 byte = 8 bits)
    //0x3f = (binary) 0011 1111, i.e. 6 bits that can be set for flags
    if (flags > 0x3F)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " tcp flags: only bits [0, 5] can be set\n");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN VerifyArg_Flow_TimeUsed(OVS_ARGUMENT* pArg)
{
    UINT64 timeUsed = GET_ARG_DATA(pArg, UINT64);

    UNREFERENCED_PARAMETER(timeUsed);

    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_Flow(OVS_ARGUMENT* pArg, BOOLEAN isRequest)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_FLOW_PI_GROUP:
        return VerifyGroup_PacketInfo(FALSE, isRequest, pArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE);

    case OVS_ARGTYPE_FLOW_MASK_GROUP:
        return VerifyGroup_PacketInfo(TRUE, isRequest, pArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE);

    case OVS_ARGTYPE_FLOW_CLEAR:
        return VerifyArg_Flow_Clear(pArg->data);

    case OVS_ARGTYPE_FLOW_STATS:
        return VerifyArg_Flow_Stats(pArg->data);

    case OVS_ARGTYPE_FLOW_TCP_FLAGS:
        return VerifyArg_Flow_TcpFlags(pArg->data);

    case OVS_ARGTYPE_FLOW_TIME_USED:
        return VerifyArg_Flow_TimeUsed(pArg->data);

    default:
        return FALSE;
    }
}

/********************************* PACKET / ACTIONS / UPCALL  *********************************/

static __inline BOOLEAN _VerifyArg_PacketActionUpcall_PortId(OVS_ARGUMENT* pArg)
{
    UINT32 pid = GET_ARG_DATA(pArg, UINT32);
    if (pid == 0)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " port id 0 is invalid!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActionUpcall_Data(OVS_ARGUMENT* pArg)
{
    typedef VOID* PCOOKIE;

    PCOOKIE pCookie = pArg->data;
    UNREFERENCED_PARAMETER(pCookie);

    //NOTE: THERE IS NO WAY TO CHECK THE COOKIE!
    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_PacketActionsUpcall(OVS_ARGUMENT* pParentArg)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
            if (!_VerifyArg_PacketActionUpcall_PortId(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_DATA:
            if (!_VerifyArg_PacketActionUpcall_Data(pArg))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "PACKET/ACTIONS/SAMPLE should not have argtype = 0x%x\n", pArg->type);
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* PACKET / ACTIONS / SAMPLE  *********************************/

static __inline BOOLEAN _VerifyArg_PacketAction_Sample_Probability(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyGroup_PacketActionsSample(OVS_ARGUMENT* pParentArg, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
            if (!VerifyGroup_PacketActions(pArg->data, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
            if (!_VerifyArg_PacketAction_Sample_Probability(pArg->data))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "PACKET/ACTIONS/SAMPLE should not have argtype = 0x%x\n", pArg->type);
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* PACKET / ACTIONS  *********************************/

static __inline BOOLEAN _VerifyArg_PacketActions_OutToPort(OVS_ARGUMENT* pArg)
{
    UINT32 portNumber = GET_ARG_DATA(pArg, UINT32);

    if (portNumber >= OVS_MAX_PORTS)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " invalid port number!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PopMpls(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PushMpls(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PushVlan(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    const OVS_ACTION_PUSH_VLAN* pPushVlanAction = pArg->data;
    if (pPushVlanAction->protocol != RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        return FALSE;
    }

    if (!(pPushVlanAction->vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        return FALSE;
    }

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PopVlan(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    if (pArg->length > 0)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg len > 0\n");
        return FALSE;
    }

    if (pArg->data)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg data != null\n");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN VerifyGroup_PacketActions(OVS_ARGUMENT* pParentArg, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            if (!_VerifyGroup_PacketActionsUpcall(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            if (!_VerifyGroup_PacketActionsSample(pArg, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
        {
            OVS_ARGUMENT_GROUP* pSetGroup = pArg->data;
            if (pSetGroup->count > 1)
            {
                DEBUGP_ARG(LOG_ERROR, "only one key can be set using a set action. count keys to set: %d\n", pSetGroup->count);
                return FALSE;
            }

            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, isRequest, /*parent*/ pArg, /*check transport layer*/ FALSE, /*seek ip*/ FALSE))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
            if (!_VerifyArg_PacketActions_OutToPort(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_POP_MPLS:
            if (!_VerifyArg_PacketActions_PopMpls(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_POP_VLAN:
            if (!_VerifyArg_PacketActions_PopVlan(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_PUSH_MPLS:
            if (!_VerifyArg_PacketActions_PushMpls(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_PUSH_VLAN:
            if (!_VerifyArg_PacketActions_PushVlan(pArg))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN VerifyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    OVS_CHECK(pGroup);

    VerifyArgGroupSize(pGroup);
    if (!VerifyArgNoDuplicates(pGroup, groupType))
    {
        return FALSE;
    }

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;

        if (IsArgTypeGroup(pArg->type))
        {
            if (!VerifyArgumentGroup(pArg->data, pArg->type))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOLEAN VerifyArgNoDuplicates(OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    UNREFERENCED_PARAMETER(groupType);

    if (0 == pGroup->count)
    {
        return TRUE;
    }

    for (UINT16 i = 0; i < pGroup->count - 1; ++i)
    {
        OVS_ARGUMENT* pArgL = pGroup->args + i;

        for (UINT16 j = i + 1; j < pGroup->count; ++j)
        {
            OVS_ARGUMENT* pArgR = pGroup->args + j;

            if (pArgL->type == pArgR->type)
            {
                //we allow multiple 'out to port' and 'set info' actions.
                //we do not allow other duplicate arguments.
                if (pArgL->type != OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT ||
                    pArgL->type == OVS_ARGTYPE_ACTION_SETINFO_GROUP)
                {
                    DEBUGP_ARG(LOG_ERROR, "found duplicate: arg type: 0x%x; group: 0x%x\n", pArgL->type, groupType);
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}