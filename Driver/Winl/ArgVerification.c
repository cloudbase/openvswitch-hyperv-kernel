#include "ArgVerification.h"

#include "PacketInfo.h"
#include "PersistentPort.h"
#include "Icmp.h"
#include "Ipv6.h"
#include "OFFlow.h"
#include "OFAction.h"
#include "OFDatapath.h"

#include "Message.h"
#include "Nbls.h"

#define OVS_MUST_HAVE_ARG_IN_ARRAY(argArray, argType)    \
    if (!OVS_ARG_HAVE_IN_ARRAY(argArray, argType))        \
{                                                                \
    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " does not have arg: 0x%x\n", argType);    \
    OVS_CHECK_RET(__UNEXPECTED__, FALSE);                                                        \
}

#define OVS_MUST_HAVE_ARG_IN_ARRAY_2(argArray, argType1, argType2)    \
    OVS_MUST_HAVE_ARG_IN_ARRAY(argArray, argType1);        \
    OVS_MUST_HAVE_ARG_IN_ARRAY(argArray, argType2);

#define OVS_PARSE_ARGS_QUICK(group, pGroup, args)                                    \
    OVS_ARGUMENT* args[OVS_ARGTYPE_COUNT(group)];                    \
    \
    OVS_FOR_EACH_ARG((pGroup),                                        \
    \
    OVS_ARGUMENT** ppCurArg = args + OVS_ARG_TOINDEX(argType, group);    \
    OVS_CHECK(!*ppCurArg);                                            \
    *ppCurArg = pArg                                                \
    );

#define OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(Type, pObj)                                      \
{                                                                                           \
    Type wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };                                   \
    \
    if (0 == memcmp(pObj, &wildcard, sizeof(Type)))                                             \
{                                                                                           \
    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " mask wildcard is default. no need to be set\n");   \
    OVS_CHECK_RET(__UNEXPECTED__, FALSE);                                                   \
}                                                                                           \
}

#define OVS_VERIFY_BUILTIN_WILDCARD_DEFAULT(Type, var)          \
    if (var == OVS_PI_MASK_MATCH_WILDCARD(Type))                \
{                                                                                       \
    DEBUGP_ARG(LOG_LOUD, "mask should not be set as wildcard. it's the default\n");     \
    OVS_CHECK_RET(__UNEXPECTED__, FALSE);                                               \
}

#define _VERIFY_ARG_PI_TP(Type, pParentArg, argData, options)           \
{                                                                       \
    Type* pTpInfo = (argData);                                          \
                                                                        \
    if (!(options & OVS_VERIFY_OPTION_ISMASK) &&                        \
    options & OVS_VERIFY_OPTION_SEEK_IP)                                \
{                                                                       \
    EXPECT(FindArgument((pParentArg)->data, OVS_ARGTYPE_PI_IPV4) ||     \
    FindArgument((pParentArg)->data, OVS_ARGTYPE_PI_IPV6));             \
}                                                                       \
else if (options & OVS_VERIFY_OPTION_ISREQUEST)                         \
{                                                                       \
    OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(Type, pTpInfo);                  \
}                                                                       \
}

/**************************************************/

static BOOLEAN _IsStringPrintableA(const char* str, UINT16 len)
{
    for (UINT16 i = 0; i < len; ++i)
    {
        if (str[i] == 0)
        {
            break;
        }

        //verify that all chars are printable chars
        if (!(str[i] >= 0x20 && str[i] <= 0x7e))
        {
            DEBUGP_ARG(LOG_ERROR, "name not printable: %s", str);
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }

    return TRUE;
}

/********************************* PI / TUNNEL *********************************/

static __inline BOOLEAN _VerifyGroup_PI_Tunnel(OVS_ARGUMENT* pTunArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_ARGUMENT_GROUP* pGroup = pTunArg->data;
    const OVS_ARG_VERIFY_INFO* pVerify = FindArgVerificationGroup(pTunArg->type);
    BOOLEAN haveDest = FALSE, haveTtl = FALSE;

    OVS_CHECK(pVerify);

    OVS_FOR_EACH_ARG(pGroup,
    {
        OVS_ARGTYPE first = pVerify->firstChildArgType;
        Func f = pVerify->f[OVS_ARG_TOINDEX_FIRST(argType, first)];

        if (argType == OVS_ARGTYPE_PI_TUNNEL_IPV4_DST)
        {
            haveDest = TRUE;
        }

        if (argType == OVS_ARGTYPE_PI_TUNNEL_TTL)
        {
            haveTtl = TRUE;
        }

        if (f && !f(pArg, pParentArg, options))
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    });

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        if (!haveDest || !haveTtl)
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }

    return TRUE;
}

/********************************* Packet Info  *********************************/

static __inline BOOLEAN _VerifyArg_PI_InputPort(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT32 inPort = GET_ARG_DATA(pArg, UINT32);

    UNREFERENCED_PARAMETER(pParentArg);

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        if (inPort > OVS_MAX_PORTS)
        {
            DEBUGP_ARG(LOG_ERROR, "the in port id is too big. max is: 0x%x; given is: 0x%x\n", OVS_MAX_PORTS, inPort);
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        DEBUGP_ARG(LOG_INFO, "the mask shouldn't be set for dp in port: it is always set as exact match (~0)\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_EthAddress(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_ETH_ADDRESS* pEthAddrInfo = pArg->data;

    UNREFERENCED_PARAMETER(pParentArg);

    if (options & OVS_VERIFY_OPTION_ISMASK &&
        options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_ETH_ADDRESS, pEthAddrInfo);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_EthType(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT16 ethType = RtlUshortByteSwap(GET_ARG_DATA(pArg, UINT16));

    if (!(options && OVS_VERIFY_OPTION_ISMASK))
    {
        OVS_ARGUMENT_GROUP* pPIGroup = pParentArg->data;

        OVS_PARSE_ARGS_QUICK(PI, pPIGroup, args);

        if (ethType < OVS_ETHERTYPE_802_3_MIN)
        {
            if (ethType == OVS_ETHERTYPE_802_2)
            {
                //TODO
                OVS_CHECK(__NOT_IMPLEMENTED__);
                return TRUE;
            }

            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
        
        switch (ethType)
        {
        case OVS_ETHERTYPE_ARP:
            OVS_MUST_HAVE_ARG_IN_ARRAY(args, OVS_ETHERTYPE_ARP);
            break;

        case OVS_ETHERTYPE_IPV4:
            OVS_MUST_HAVE_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_IPV4);
            break;

        case OVS_ETHERTYPE_IPV6:
            OVS_MUST_HAVE_ARG_IN_ARRAY(args, OVS_ARGTYPE_PI_IPV6);
            break;

        case OVS_ETHERTYPE_QTAG:
            OVS_MUST_HAVE_ARG_IN_ARRAY_2(args, 
                OVS_ARGTYPE_PI_VLAN_TCI, OVS_ARGTYPE_PI_ENCAP_GROUP);
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "we don't handle ether type: 0x%x\n", ethType);
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }
    //is mask, request or reply
    else
    {
        EXPECT(ethType == OVS_PI_MASK_MATCH_EXACT(BE16));
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Icmp(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_ICMP* pIcmpInfo = pArg->data;

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        EXPECT(FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4));
    }
    //mask
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_ICMP, pIcmpInfo);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Icmp6(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_ICMP6* pIcmp6Info = pArg->data;

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        EXPECT(FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6));

        if (pIcmp6Info->type == OVS_NDISC_NEIGHBOUR_SOLICITATION ||
            pIcmp6Info->code == OVS_NDISC_NEIGHBOUR_ADVERTISEMENT)
        {
            EXPECT(FindArgument(pParentArg->data, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY));
        }
    }
    //mask
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_ICMP6, pIcmp6Info);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Net_NotMask(UINT8 fragmentType, UINT8 protocol, OVS_ARGUMENT_GROUP* pPIGroup, OVS_VERIFY_OPTIONS options)
{
    if (options & OVS_VERIFY_OPTION_CHECK_TP_LAYER &&
        fragmentType != OVS_FRAGMENT_TYPE_FRAG_N)
    {
        switch (protocol)
        {
        case OVS_IPPROTO_TCP:
            EXPECT(FindArgument(pPIGroup, OVS_ARGTYPE_PI_TCP));
            break;

        case OVS_IPPROTO_UDP:
            EXPECT(FindArgument(pPIGroup, OVS_ARGTYPE_PI_UDP));
            break;

        case OVS_IPPROTO_SCTP:
            EXPECT(FindArgument(pPIGroup, OVS_ARGTYPE_PI_SCTP));
            break;

        case OVS_IPPROTO_ICMP:
            EXPECT(FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP));
            break;

        case OVS_IPV6_EXTH_ICMP6:
            EXPECT(FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP6));
            break;
        }
    }

    switch (fragmentType)
    {
    case OVS_FRAGMENT_TYPE_NOT_FRAG:
    case OVS_FRAGMENT_TYPE_FIRST_FRAG:
    case OVS_FRAGMENT_TYPE_FRAG_N:
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "fragment type is not an enum constant!\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Ipv4(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_IPV4* pIpv4Info = pArg->data;

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        if (!_VerifyArg_PI_Net_NotMask(pIpv4Info->fragmentType, pIpv4Info->protocol, pParentArg->data, options))
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_IPV4, pIpv4Info);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Ipv6(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_IPV6* pIpv6Info = pArg->data;

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        if (!_VerifyArg_PI_Net_NotMask(pIpv6Info->fragmentType, pIpv6Info->protocol, pParentArg->data, options))
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_IPV6, pIpv6Info);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_NeighborDiscovery(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_NEIGHBOR_DISCOVERY* pNd = pArg->data;

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        EXPECT(FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6));
    }
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_NEIGHBOR_DISCOVERY, pNd);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Sctp(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    _VERIFY_ARG_PI_TP(OVS_PI_SCTP, pParentArg, pArg->data, options);

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Tcp(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    _VERIFY_ARG_PI_TP(OVS_PI_TCP, pParentArg, pArg->data, options);

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Udp(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    _VERIFY_ARG_PI_TP(OVS_PI_UDP, pParentArg, pArg->data, options);

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_Arp(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_PI_ARP* pArpInfo = pArg->data;

    UNREFERENCED_PARAMETER(pParentArg);

    if (!(options & OVS_VERIFY_OPTION_ISMASK))
    {
        UINT16 op = RtlUshortByteSwap(pArpInfo->operation);

        if (op != 1 && op != 2)
        {
            DEBUGP_ARG(LOG_ERROR, "packet info / arp: unknown op code %d\n", op);
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    }
    else if (options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_STRUCT_WILDCARD_DEFAULT(OVS_PI_ARP, pArpInfo);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PI_VlanTci(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    BE16 tci = GET_ARG_DATA(pArg, BE16);

    UNREFERENCED_PARAMETER(pParentArg);

    //it is possible we shouldn't allow to specify tci = 0 as key
    if (options & OVS_VERIFY_OPTION_ISMASK &&
        options & OVS_VERIFY_OPTION_ISREQUEST)
    {
        OVS_VERIFY_BUILTIN_WILDCARD_DEFAULT(UINT16, tci);
    }

    if (!(tci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        DEBUGP_ARG(LOG_ERROR, "if you set vlan tci, you must set 'tag present' = 1!\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

/********************************* FLOW  *********************************/

BOOLEAN VerifyArg_Flow_TcpFlags(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT8 flags = GET_ARG_DATA(pArg, UINT8);

    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    //tcp flags / ctrl bits, without the ECN bits (because we have data type of 1 byte = 8 bits)
    //0x3f = (binary) 0011 1111, i.e. 6 bits that can be set for flags
    if (flags > 0x3F)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " tcp flags: only bits [0, 5] can be set\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

/********************************* ACTIONS / UPCALL  *********************************/

static __inline BOOLEAN _VerifyArg_ActionUpcall_PortId(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT32 pid = GET_ARG_DATA(pArg, UINT32);

    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    if (pid == 0)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " port id 0 is invalid!\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

/*********************************  ACTIONS  *********************************/

static __inline BOOLEAN _VerifyArg_Action_OutToPort(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT32 portNumber = GET_ARG_DATA(pArg, UINT32);

    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    if (portNumber >= OVS_MAX_PORTS)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " invalid port number!\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_Action_PushVlan(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    const OVS_ACTION_PUSH_VLAN* pPushVlanAction = pArg->data;

    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    if (pPushVlanAction->protocol != RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    if (!(pPushVlanAction->vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_Action_PopVlan(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    if (pArg->length > 0)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg len > 0\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    if (pArg->data)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg data != null\n");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}


/***********************************************************************/

static BOOLEAN _VerifyArg_Datapath_Features(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UINT32 features = GET_ARG_DATA(pArg, UINT32);
    UINT32 allFeatures = (OVS_DATAPATH_FEATURE_LAST_NLA_UNALIGNED | OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT);

    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    OVS_CHECK_RET(features == (features & allFeatures), FALSE);

    return TRUE;
}

static BOOLEAN _VerifyArg_Packet_Buffer(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    if (!VerifyNetBuffer(pArg->data, pArg->length))
    {
        DEBUGP_ARG(LOG_ERROR, "invalid packet buffer!");
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

/***********************************************************************/

static BOOLEAN _VerifyGroup_Default(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options);
static BOOLEAN _VerifyArg_NotImplemented(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options);

static const Func s_verifyArgTunnel[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_ID, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_TOS, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_TTL, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT, PI_TUNNEL)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM, PI_TUNNEL)] = _VerifyArg_NotImplemented,
};

static const Func s_verifyArgPI[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_PACKET_PRIORITY, PI)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_DP_INPUT_PORT, PI)] = _VerifyArg_PI_InputPort,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ETH_ADDRESS, PI)] = _VerifyArg_PI_EthAddress,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ETH_TYPE, PI)] = _VerifyArg_PI_EthType,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_VLAN_TCI, PI)] = _VerifyArg_PI_VlanTci,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_IPV4, PI)] = _VerifyArg_PI_Ipv4,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_IPV6, PI)] = _VerifyArg_PI_Ipv6,

    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TCP, PI)] = _VerifyArg_PI_Tcp,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TCP_FLAGS, PI)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_UDP, PI)] = _VerifyArg_PI_Udp,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_SCTP, PI)] = _VerifyArg_PI_Sctp,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ICMP, PI)] = _VerifyArg_PI_Icmp,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ICMP6, PI)] = _VerifyArg_PI_Icmp6,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ARP, PI)] = _VerifyArg_PI_Arp,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY, PI)] = _VerifyArg_PI_NeighborDiscovery,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_DATAPATH_HASH, PI)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID, PI)] = _VerifyArg_NotImplemented,

    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_PACKET_MARK, PI)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_GROUP, PI)] = _VerifyGroup_PI_Tunnel,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_MPLS, PI)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ENCAP_GROUP, PI)] = _VerifyGroup_Default,
};

static const Func s_verifyArgFlow[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_STATS, FLOW)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_TCP_FLAGS, FLOW)] = VerifyArg_Flow_TcpFlags,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_TIME_USED, FLOW)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_CLEAR, FLOW)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_PI_GROUP, FLOW)] = _VerifyGroup_Default,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_ACTIONS_GROUP, FLOW)] = _VerifyGroup_Default,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_MASK_GROUP, FLOW)] = _VerifyGroup_Default
};

static const Func s_verifyArgDatapath[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_NAME, DATAPATH)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_STATS, DATAPATH)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID, DATAPATH)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_USER_FEATURES, DATAPATH)] = _VerifyArg_Datapath_Features,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_MEGAFLOW_STATS, DATAPATH)] = _VerifyArg_NotImplemented,
};

static const Func s_verifyToAttribsUpcall[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_PORT_ID, ACTION_UPCALL)] = _VerifyArg_ActionUpcall_PortId,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_DATA, ACTION_UPCALL)] = NULL,
};

static const Func s_argsToAttribsSample[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY, ACTION_SAMPLE)] = NULL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP, ACTION_SAMPLE)] = _VerifyGroup_Default,
};

static const Func s_argsToAttribsActions[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT, ACTION)] = _VerifyArg_Action_OutToPort,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_GROUP, ACTION)] = _VerifyGroup_Default,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SETINFO_GROUP, ACTION)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_PUSH_VLAN, ACTION)] = _VerifyArg_Action_PushVlan,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_POP_VLAN, ACTION)] = _VerifyArg_Action_PopVlan,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_GROUP, ACTION)] = _VerifyGroup_Default,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_PUSH_MPLS, ACTION)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_POP_MPLS, ACTION)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_RECIRCULATION, ACTION)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_HASH, ACTION)] = _VerifyArg_NotImplemented
};

static const Func s_argsToAttribsPacket[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_BUFFER, PACKET)] = _VerifyArg_Packet_Buffer,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_PI_GROUP, PACKET)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_ACTIONS_GROUP, PACKET)] = _VerifyGroup_Default,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_USERDATA, PACKET)] = NULL
};

static const Func s_argsToAttribsPortOptions[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, OFPORT_OPTION)] = _VerifyArg_NotImplemented,
};

static const Func s_argsToAttribsPort[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_NUMBER, OFPORT)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_NAME, OFPORT)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_STATS, OFPORT)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_TYPE, OFPORT)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, OFPORT)] = _VerifyArg_NotImplemented,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, OFPORT)] = _VerifyArg_NotImplemented,
};

static const OVS_ARG_VERIFY_INFO s_verifyArg[] =
{
    { OVS_ARGTYPE_PI_TUNNEL_GROUP, OVS_ARGTYPE_FIRST_PI_TUNNEL, s_verifyArgTunnel },
    { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FIRST_PI, s_verifyArgPI },
    { OVS_ARGTYPE_PSEUDOGROUP_FLOW, OVS_ARGTYPE_FIRST_FLOW, s_verifyArgFlow },
    { OVS_ARGTYPE_PSEUDOGROUP_DATAPATH, OVS_ARGTYPE_FIRST_DATAPATH, s_verifyArgDatapath },
};

const OVS_ARG_VERIFY_INFO* FindArgVerificationGroup(OVS_ARGTYPE parentArgType)
{
    for (int i = 0; i < OVS_ARG_GROUP_COUNT; ++i)
    {
        const OVS_ARG_VERIFY_INFO* pGroup = s_verifyArg + i;

        if (parentArgType == pGroup->parentArgType)
        {
            return pGroup;
        }
    }

    OVS_CHECK(__UNEXPECTED__);
    return NULL;
}

static BOOLEAN _VerifyArg_NotImplemented(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(pParentArg);
    UNREFERENCED_PARAMETER(options);

    OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
}

static BOOLEAN _VerifyGroup_Default(OVS_ARGUMENT* pArg, OVS_ARGUMENT* pParentArg, OVS_VERIFY_OPTIONS options)
{
    OVS_ARGUMENT_GROUP* pGroup = pArg->data;
    const OVS_ARG_VERIFY_INFO* pVerify = FindArgVerificationGroup(pArg->type);

    UNREFERENCED_PARAMETER(pParentArg);

    OVS_CHECK(pVerify);

    OVS_FOR_EACH_ARG(pGroup,
    {
        OVS_ARGTYPE first = pVerify->firstChildArgType;
        Func f = pVerify->f[argType - first + 1];

        if (f && !f(pArg, pArg, options))
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    });

    return TRUE;
}