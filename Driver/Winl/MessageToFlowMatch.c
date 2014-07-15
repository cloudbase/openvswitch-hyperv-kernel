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

#include "MessageToFlowMatch.h"
#include "Argument.h"
#include "OFDatapath.h"
#include "PacketInfo.h"
#include "WinlDevice.h"
#include "WinlFlow.h"
#include "Icmp.h"
#include "Message.h"
#include "Ipv6.h"
#include "OFAction.h"
#include "ArgumentType.h"
#include "PersistentPort.h"

BOOLEAN GetPacketContextFromPIArgs(_In_ const OVS_ARGUMENT_GROUP* pArgGroup, _Inout_ OVS_OFPACKET_INFO* pPacketInfo)
{
    OF_PI_IPV4_TUNNEL* pTunnelInfo = &pPacketInfo->tunnelInfo;
    OVS_PI_RANGE* pPiRange = NULL;
    OVS_ARGUMENT* pDatapathInPortArg = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };

    pPacketInfo->physical.ovsInPort = OVS_INVALID_PORT_NUMBER;
    pPacketInfo->physical.packetPriority = 0;
    pPacketInfo->physical.packetMark = 0;

    RtlZeroMemory(pTunnelInfo, sizeof(OF_PI_IPV4_TUNNEL));
    RtlZeroMemory(&flowMatch, sizeof(flowMatch));
    flowMatch.pPacketInfo = pPacketInfo;

    OVS_CHECK(pArgGroup);

    pPiRange = &flowMatch.piRange;
    pPacketInfo = flowMatch.pPacketInfo;

    for (UINT i = 0; i < pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_PACKET_PRIORITY:
            PIFromArg_PacketPriority(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_PACKET_MARK:
            PIFromArg_PacketMark(pPacketInfo, pPiRange, pArg);
            break;

        case OVS_ARGTYPE_PI_DP_INPUT_PORT:
            pDatapathInPortArg = pArg;
            if (!PIFromArg_DatapathInPort(pPacketInfo, pPiRange, pArg, /*is mask*/FALSE))
			{
                return FALSE;
			}

            break;

        case OVS_ARGTYPE_GROUP_PI_TUNNEL:
            OVS_CHECK(IsArgTypeGroup(pArg->type));

            if (!PIFromArg_Tunnel(pArg->data, pPacketInfo, pPiRange, /*is mask*/ FALSE))
            {
                return FALSE;
            }

            break;

        default:
            //nothing to do here: the rest are non-context / non-metadata keys
            break;
        }
    }

    if (!pDatapathInPortArg)
    {
        PIFromArg_SetDefaultDatapathInPort(pPacketInfo, pPiRange, FALSE);
    }

    return TRUE;
}

static BOOLEAN _VerifyMasks(_In_ const OVS_FLOW_MATCH* pFlowMatch, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, _In_ const OVS_ARGUMENT_GROUP* pMaskGroup)
{
    OVS_ARGUMENT* pMaskArg = NULL, *pPacketInfoArg = NULL;
    BOOLEAN isIpv4 = FALSE;
    BOOLEAN isIpv6 = FALSE;
    BOOLEAN isWildcard = FALSE;
    BOOLEAN isIcmp6 = FALSE;

    OVS_OFPACKET_INFO* pPacketInfo = NULL, *pMask = NULL;

    OVS_CHECK(pFlowMatch);

    if (!pMaskGroup)
    {
        return TRUE;
    }

    pPacketInfo = pFlowMatch->pPacketInfo;
    pMask = (pFlowMatch->pFlowMask ? &pFlowMatch->pFlowMask->packetInfo : NULL);

    //NOTE: we must have key, but we need not have mask!
    OVS_CHECK(pPacketInfo);

    //ETHERNET TYPE
    isWildcard = (pMask ? (pMask->ethInfo.type == OVS_PI_MASK_MATCH_WILDCARD(UINT16)) : FALSE);

    switch (RtlUshortByteSwap(pPacketInfo->ethInfo.type))
    {
    case OVS_ETHERTYPE_ARP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ARP);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ARP);

        if (isWildcard && pMaskArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " cannot have mask arg type %u: eth type is wildcard!\n", OVS_ARGTYPE_PI_ARP);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for eth type is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_ARP);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }

        break;

    case OVS_ETHERTYPE_IPV4:
        isIpv4 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_IPV4);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_IPV4);

        if (isWildcard && pMaskArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " cannot have mask arg type %u: eth type is wildcard!\n", OVS_ARGTYPE_PI_IPV4);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for eth type is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_IPV4);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }

        break;

    case OVS_ETHERTYPE_IPV6:
        isIpv6 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_IPV6);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_IPV6);

        if (isWildcard && pMaskArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " cannot have mask arg type %u: eth type is wildcard!\n", OVS_ARGTYPE_PI_IPV6);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for eth type is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_IPV6);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        break;

    default:
        if (!isWildcard)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " invalid eth type, when eth type mask = exact!\n");
            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        //ignore: we have eth type wildcarded
    }

    if (pMask)
    {
        isWildcard = (pMask->ipInfo.protocol == OVS_PI_MASK_MATCH_WILDCARD(UINT8) ? TRUE : FALSE);
    }
    else
    {
        isWildcard = FALSE;
    }

    isWildcard = (pMask ? (pMask->ipInfo.protocol == OVS_PI_MASK_MATCH_WILDCARD(UINT8)) : FALSE);

    switch (pPacketInfo->ipInfo.protocol)
    {
    case OVS_IPPROTO_TCP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_TCP);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_TCP);

        if (pMaskArg && !isIpv4 && !isIpv6)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we have neither ipv4, nor ipv6, but have mask for tcp? (bad)\n", OVS_ARGTYPE_PI_TCP);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }
        else if (isWildcard && pMaskArg)
        {
            //the userspace actually sets mask this way
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for proto is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_TCP);

            //remove the assert and the 'return FALSE' if it fails, and it also looks to be a valid scenario
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }

        break;

    case OVS_IPPROTO_UDP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_UDP);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_UDP);

        if (pMaskArg && !isIpv4 && !isIpv6)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we have neither ipv4, nor ipv6, but have mask for udp? (bad)\n", OVS_ARGTYPE_PI_UDP);

            return FALSE;
        }
        else if (isWildcard && pMaskArg)
        {
            //the userspace actually sets mask this way
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for proto is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_UDP);

            return FALSE;
        }
        break;

    case OVS_IPPROTO_SCTP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_SCTP);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_SCTP);

        if (pMaskArg && !isIpv4 && !isIpv6)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we have neither ipv4, nor ipv6, but have mask for sctp? (bad)\n", OVS_ARGTYPE_PI_SCTP);

            return FALSE;
        }
        else if (isWildcard && pMaskArg)
        {
            //the userspace actually sets mask this way
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for proto is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_SCTP);

            return FALSE;
        }

        break;

    case OVS_IPPROTO_ICMP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ICMP);

        if (pMaskArg && !isIpv4)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we don't have ipv4, but have mask for icmp4? (bad)\n", OVS_ARGTYPE_PI_ICMP);

            return FALSE;
        }
        else if (isWildcard && pMaskArg)
        {
            //the userspace actually sets mask this way
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for proto is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_ICMP);

            return FALSE;
        }

        break;

    case OVS_IPV6_EXTH_ICMP6:
        isIcmp6 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP6);

        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ICMP6);

        if (pMaskArg && !isIpv6)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we don't have ipv6, but have mask for icmp6? (bad)\n", OVS_ARGTYPE_PI_ICMP6);

            return FALSE;
        }
        else if (isWildcard && pMaskArg)
        {
            //the userspace actually sets mask this way
        }
        else if (!isWildcard && !pPacketInfoArg)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for proto is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_ICMP6);

            return FALSE;
        }

        break;

    default:
        //ignore: we have ipv4 proto wildcarded
        if (!isWildcard)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " invalid ipv4/ipv6 proto, when proto mask = exact!\n");
            return FALSE;
        }
        //ignore: we have eth type wildcarded
    }

    //IPV6 / ICMP6 / ND
    isWildcard = (pMask ? (pMask->netProto.ipv6Info.sourcePort == OVS_PI_MASK_MATCH_WILDCARD(UINT8)) : FALSE);

    pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

    pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

    if (pMaskArg && !isIcmp6)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we don't have icmp6, but have mask for icmp6/nd? (bad)\n", OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

        return FALSE;
    }

    if (pMaskArg && !isIpv6)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u: we don't have ipv6, but have mask for icmp6/nd? (bad)\n", OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

        return FALSE;
    }

    if (isWildcard && pMaskArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " cannot have mask arg type %u: ipv6 src port is wildcard!\n", OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

        return FALSE;
    }
    else if (!isWildcard && !pPacketInfoArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " arg type %u -- mask for ipv6 src port is 'exact', but we don't have the key!\n", OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _PIFromArgs_HandleEncap(_In_ const OVS_ARGUMENT_GROUP* pPIGroup, _Inout_ OVS_ARGUMENT* pEthTypeArg, _Out_ BOOLEAN* pEncapValid)
{
    BE16 vlanTci = 0;

    OVS_ARGUMENT* pVlanTciArg = NULL, *pEncapArg = NULL;

    OVS_CHECK(pEncapValid);
    OVS_CHECK(pEthTypeArg);

    *pEncapValid = FALSE;

    pVlanTciArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_VLAN_TCI);

    pEncapArg = FindArgument(pPIGroup, OVS_ARGTYPE_GROUP_PI_ENCAPSULATION);

    if (!pVlanTciArg || !pEncapArg)
    {
        DEBUGP(LOG_ERROR, "the vlan frame is invalid!\n");
        return FALSE;
    }

    pEthTypeArg->isDisabled = TRUE;

    vlanTci = GET_ARG_DATA(pVlanTciArg, BE16);
    pEncapArg->isDisabled = TRUE;

    *pEncapValid = TRUE;

    if (!vlanTci)
    {
        if (pEncapArg->length > 0)
        {
            DEBUGP(LOG_ERROR, "The truncated vlan header has vlan tci != 0!\n");
            return FALSE;
        }
    }
    else
    {
        DEBUGP(LOG_ERROR, "Tried to set encapsulation data to a non-vlan frame!\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _MasksFromArgs_HandleEncap(_In_ const OVS_ARGUMENT_GROUP* pMaskGroup, _Inout_ OVS_ARGUMENT* pEncapArg, _Inout_ OVS_ARGUMENT* pEtherTypeArg)
{
    BE16 ethType = 0;
    BE16 vlanTci = 0;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT* pVlanTciArg = NULL;

    OVS_CHECK(pEncapArg);

    pEncapArg->isDisabled = TRUE;

    if (pEtherTypeArg)
    {
        ethType = GET_ARG_DATA(pEtherTypeArg, BE16);
    }
    else
    {
        DEBUGP(LOG_ERROR, "The eth type argument was not found\n");
        return FALSE;
    }

    if (ethType == OVS_PI_MASK_MATCH_EXACT(UINT16))
    {
        pEtherTypeArg->isDisabled = TRUE;
    }
    else
    {
        DEBUGP(LOG_ERROR, "The vlan frame must have an exact match for ethType. Mask value: %x.\n", RtlUshortByteSwap(ethType));
        return FALSE;
    }

    pVlanTciArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_VLAN_TCI);

    if (pVlanTciArg)
    {
        vlanTci = GET_ARG_DATA(pVlanTciArg, BE16);
    }
    else
    {
        DEBUGP(LOG_ERROR, "vlan tci arg not given");
        return FALSE;
    }

    if (!(vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        DEBUGP(LOG_ERROR, "The vlan field 'tag present' bit must be exact match! Mask value: %x.\n", RtlUshortByteSwap(vlanTci));
        return FALSE;
    }

    return ok;
}

BOOLEAN GetFlowMatchFromArguments(_Inout_ OVS_FLOW_MATCH* pFlowMatch, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, const OVS_ARGUMENT_GROUP* pPIMaskGroup)
{
    BOOLEAN encapIsValid = FALSE;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT* pEthTypeArg = NULL, *pEthAddrArg = NULL;
    OVS_PI_RANGE* pPiRange = NULL;
    OVS_OFPACKET_INFO* pPacketInfo = NULL;

    OVS_CHECK(pFlowMatch);

    if (!pFlowMatch)
    {
        return FALSE;
    }

    pEthTypeArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ETH_TYPE);

    if (!pEthTypeArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " expected key: %u\n", OVS_ARGTYPE_PI_ETH_TYPE);

        return FALSE;
    }

    pEthAddrArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ETH_ADDRESS);

    if (!pEthAddrArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " expected key: %u\n", OVS_ARGTYPE_PI_ETH_ADDRESS);

        return FALSE;
    }

    if (RtlUshortByteSwap(OVS_ETHERTYPE_QTAG) == GET_ARG_DATA(pEthTypeArg, BE16))
    {
        if (!_PIFromArgs_HandleEncap(pPIGroup, pEthAddrArg, &encapIsValid))
        {
            return FALSE;
        }
    }

    pPiRange = &pFlowMatch->piRange;
    pPacketInfo = pFlowMatch->pPacketInfo;

    ok = GetPacketInfoFromArguments(pPacketInfo, pPiRange, pPIGroup, /*isMask*/ FALSE);
    if (!ok)
    {
        return FALSE;
    }

    if (!pPIMaskGroup)
    {
        if (pFlowMatch->pFlowMask)
        {
            UINT8* pStart = (UINT8*)&pFlowMatch->pFlowMask->packetInfo + pPiRange->startRange;
            UINT16 range = (UINT16)(pPiRange->endRange - pPiRange->startRange);

            pFlowMatch->pFlowMask->piRange = *pPiRange;
            memset(pStart, OVS_PI_MASK_MATCH_EXACT(UINT8), range);
        }
    }
    else
    {
        OVS_ARGUMENT* pEncapArg = NULL;

        pEncapArg = FindArgument(pPIMaskGroup, OVS_ARGTYPE_GROUP_PI_ENCAPSULATION);

        if (pEncapArg)
        {
            if (!encapIsValid)
            {
                DEBUGP(LOG_ERROR, "Tryed to set encapsulation to non-vlan frame!\n");
                return FALSE;
            }

            if (!_MasksFromArgs_HandleEncap(pPIMaskGroup, pEncapArg, pEthTypeArg))
            {
                return FALSE;
            }
        }

        OVS_CHECK(pFlowMatch->pFlowMask);
        pPiRange = &pFlowMatch->pFlowMask->piRange;
        pPacketInfo = &pFlowMatch->pFlowMask->packetInfo;

        ok = GetPacketInfoFromArguments(pPacketInfo, pPiRange, pPIMaskGroup, /*is mask*/TRUE);
        if (!ok)
        {
            return FALSE;
        }
    }

    //if the userspace gives us bad / unexpected args, we cannot simply deny the flow:
    //a) this might not be a bug (i.e. the userspace intends to set flows like this)
    //b) if it is a bug, we can do little in the kernel to help it.
#if __VERIFY_MASKS
    if (!_VerifyMasks(pFlowMatch, pPIGroup, pPIMaskGroup))
	{
        return FALSE;
	}
#endif

    return TRUE;
}