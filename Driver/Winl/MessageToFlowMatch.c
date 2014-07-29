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
#include "OFPort.h"

static BOOLEAN _VerifyMasks(_In_ const OVS_FLOW_MATCH* pFlowMatch, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, _In_ const OVS_ARGUMENT_GROUP* pMaskGroup)
{
    OVS_ARGUMENT* pMaskArg = NULL, *pPacketInfoArg = NULL;
    BOOLEAN isIpv4 = FALSE;
    BOOLEAN isIpv6 = FALSE;
    BOOLEAN isWildcard = FALSE;
    BOOLEAN isIcmp6 = FALSE;

    const OVS_OFPACKET_INFO* pPacketInfo = NULL, *pMask = NULL;

    OVS_CHECK(pFlowMatch);

    if (!pMaskGroup)
    {
        return TRUE;
    }

    pPacketInfo = &(pFlowMatch->packetInfo);
    pMask = (pFlowMatch->haveMask ? &(pFlowMatch->flowMask.packetInfo) : NULL);

    //NOTE: we must have key, but we need not have mask!
    OVS_CHECK(pPacketInfo);

    //ETHERNET TYPE
    isWildcard = (pMask ? (pMask->ethInfo.type == OVS_PI_MASK_MATCH_WILDCARD(UINT16)) : FALSE);

    switch (RtlUshortByteSwap(pPacketInfo->ethInfo.type))
    {
    case OVS_ETHERTYPE_ARP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ARP);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ARP);

        EXPECT(!isWildcard || !pMaskArg);
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    case OVS_ETHERTYPE_IPV4:
        isIpv4 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_IPV4);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_IPV4);

        EXPECT(!isWildcard || !pMaskArg);
        EXPECT(isWildcard || pPacketInfoArg);

        break;

    case OVS_ETHERTYPE_IPV6:
        isIpv6 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_IPV6);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_IPV6);

        EXPECT(!isWildcard || !pMaskArg);
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    default:
        EXPECT(isWildcard);
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

        EXPECT(!(pMaskArg && !isIpv4 && !isIpv6));
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    case OVS_IPPROTO_UDP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_UDP);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_UDP);

        EXPECT(!(pMaskArg && !isIpv4 && !isIpv6));
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    case OVS_IPPROTO_SCTP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_SCTP);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_SCTP);

        EXPECT(!(pMaskArg && !isIpv4 && !isIpv6));
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    case OVS_IPPROTO_ICMP:
        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ICMP);

        EXPECT(!(pMaskArg && !isIpv4));
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    case OVS_IPV6_EXTH_ICMP6:
        isIcmp6 = TRUE;

        pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ICMP6);
        pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_ICMP6);

        EXPECT(!(pMaskArg && !isIpv6));
        EXPECT(isWildcard || pPacketInfoArg);
        break;

    default:
        //ignore: we have ipv4 proto wildcarded
        EXPECT(isWildcard);
        //ignore: we have eth type wildcarded
    }

    //IPV6 / ICMP6 / ND
    isWildcard = (pMask ? (pMask->tpInfo.sourcePort == OVS_PI_MASK_MATCH_WILDCARD(UINT8)) : FALSE);

    pPacketInfoArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);
    pMaskArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY);

    EXPECT(pMaskArg || isIcmp6);
    EXPECT(pMaskArg || isIpv6);

    EXPECT(isWildcard || pMaskArg);
    EXPECT(isWildcard || pPacketInfoArg);

    return TRUE;
}

static BOOLEAN _PIFromArgs_HandleEncap(_In_ const OVS_ARGUMENT_GROUP* pPIGroup, _Inout_ OVS_ARGUMENT* pEthTypeArg, _Out_ BOOLEAN* pEncapValid)
{
    BE16 vlanTci = 0;

    OVS_ARGUMENT* pVlanTciArg = NULL, *pEncapArg = NULL;

    *pEncapValid = FALSE;

    pVlanTciArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_VLAN_TCI);
    pEncapArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ENCAP_GROUP);

    EXPECT(pVlanTciArg && pEncapArg);

    pEthTypeArg->isDisabled = TRUE;
    vlanTci = GET_ARG_DATA(pVlanTciArg, BE16);
    pEncapArg->isDisabled = TRUE;

    *pEncapValid = TRUE;

    EXPECT(vlanTci);
    EXPECT(pEncapArg->length == 0);

    return TRUE;
}

static BOOLEAN _MasksFromArgs_HandleEncap(_In_ const OVS_ARGUMENT_GROUP* pMaskGroup, _Inout_ OVS_ARGUMENT* pEncapArg, _Inout_ OVS_ARGUMENT* pEtherTypeArg)
{
    BE16 ethType = 0;
    BE16 vlanTci = 0;
    OVS_ARGUMENT* pVlanTciArg = NULL;

    pEncapArg->isDisabled = TRUE;

    EXPECT(pEtherTypeArg);
    ethType = GET_ARG_DATA(pEtherTypeArg, BE16);

    EXPECT(ethType == OVS_PI_MASK_MATCH_EXACT(UINT16));
    pEtherTypeArg->isDisabled = TRUE;

    pVlanTciArg = FindArgument(pMaskGroup, OVS_ARGTYPE_PI_VLAN_TCI);
    EXPECT(pVlanTciArg);
    vlanTci = GET_ARG_DATA(pVlanTciArg, BE16);

    EXPECT(vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT));

    return TRUE;
}

BOOLEAN GetFlowMatchFromArguments(_Inout_ OVS_FLOW_MATCH* pFlowMatch, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, const OVS_ARGUMENT_GROUP* pPIMaskGroup)
{
    BOOLEAN encapIsValid = FALSE;
    OVS_ARGUMENT* pEthTypeArg = NULL, *pEthAddrArg = NULL;
    OVS_PI_RANGE* pPiRange = NULL;
    OVS_OFPACKET_INFO* pPacketInfo = NULL;

    OVS_CHECK(pFlowMatch);

    pEthTypeArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ETH_TYPE);
    EXPECT(pEthAddrArg);
    
    pEthAddrArg = FindArgument(pPIGroup, OVS_ARGTYPE_PI_ETH_ADDRESS);
    EXPECT(pEthAddrArg);

    if (pEthTypeArg && RtlUshortByteSwap(OVS_ETHERTYPE_QTAG) == GET_ARG_DATA(pEthTypeArg, BE16))
    {
        EXPECT(_PIFromArgs_HandleEncap(pPIGroup, pEthAddrArg, &encapIsValid));
    }

    pPiRange = &(pFlowMatch->piRange);
    pPacketInfo = &(pFlowMatch->packetInfo);

    EXPECT(GetPacketInfoFromArguments(pPacketInfo, pPiRange, pPIGroup, /*isMask*/ FALSE));

    if (!pPIMaskGroup)
    {
        if (pFlowMatch->haveMask)
        {
            //TODO: this is buggy - create exact match args instead of exact match packet info!
            //Also, do not wildcard tunnel info!
            UINT8* pStart = (UINT8*)&pFlowMatch->flowMask.packetInfo + pPiRange->startRange;
            UINT16 range = (UINT16)(pPiRange->endRange - pPiRange->startRange);

            pFlowMatch->flowMask.piRange = *pPiRange;
            memset(pStart, OVS_PI_MASK_MATCH_EXACT(UINT8), range);
        }
    }
    else
    {
        OVS_ARGUMENT* pEncapArg = NULL;

        pEncapArg = FindArgument(pPIMaskGroup, OVS_ARGTYPE_PI_ENCAP_GROUP);
        if (pEncapArg)
        {
            EXPECT(encapIsValid);

            if (pEthTypeArg)
            {
                EXPECT(_MasksFromArgs_HandleEncap(pPIMaskGroup, pEncapArg, pEthTypeArg));
            }
        }

        OVS_CHECK(pFlowMatch->haveMask);
        pPiRange = &pFlowMatch->flowMask.piRange;
        pPacketInfo = &pFlowMatch->flowMask.packetInfo;

        EXPECT(GetPacketInfoFromArguments(pPacketInfo, pPiRange, pPIMaskGroup, /*is mask*/TRUE));
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