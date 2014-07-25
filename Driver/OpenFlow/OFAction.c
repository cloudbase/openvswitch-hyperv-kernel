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

#include "OFAction.h"
#include "OFFlow.h"
#include "PacketInfo.h"
#include "OFDatapath.h"
#include "OvsNetBuffer.h"
#include "OFPort.h"
#include "WinlPacket.h"
#include "Ipv4.h"
#include "Ipv6.h"
#include "Tcp.h"
#include "Udp.h"
#include "Sctp.h"
#include "Random.h"
#include "Argument.h"
#include "WinlFlow.h"
#include "Upcall.h"
#include "ArgumentType.h"
#include "OFPort.h"
#include "Sctx_Nic.h"
#include "Message.h"
#include "NblsIngress.h"
#include "Arp.h"
#include "PersistentPort.h"
#include "ArgToAttribute.h"
#include "Nbls.h"
#include "Vlan.h"
#include "ArgVerification.h"

#define OVS_ACTION_SAMPLE_MAX_DEPTH        3

static BOOLEAN _ExecuteAction_OutToUserspace(_In_ NET_BUFFER* pNb, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_ARGUMENT_GROUP* pArguments)
{
    OVS_UPCALL_INFO upcallInfo = { 0 };
    BOOLEAN ok = FALSE;

    OVS_CHECK(pPacketInfo);

    upcallInfo.command = OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION;
    upcallInfo.pPacketInfo = pPacketInfo;
    upcallInfo.pUserData = NULL;
    upcallInfo.portId = 0;

    for (UINT i = 0; i < pArguments->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArguments->args + i;
        BOOLEAN ok = IsArgumentValid(pArg);
        OVS_ARGTYPE argType = pArg->type;

        if (!ok)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ "packet upcall action: arg of argtype %u is invalid!\n", argType);
            OVS_CHECK(__UNEXPECTED__);
            return FALSE;
        }

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_UPCALL_DATA:
            //it is released in send packet to userspace
            upcallInfo.pUserData = pArg;
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
            upcallInfo.portId = GET_ARG_DATA(pArg, UINT32);
            break;
        }
    }

    ok = QueuePacketToUserspace(pNb, &upcallInfo);

    return ok;
}

static BOOLEAN _ExecuteAction_Set(OVS_NET_BUFFER* pONb, const OVS_ARGUMENT_GROUP* pArgs)
{
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGTYPE argType = OVS_ARGTYPE_INVALID;

    OVS_CHECK(pArgs->count == 1);

    pArg = pArgs->args;
    argType = pArg->type;

    switch (argType)
    {
        //NOTE FOR OVS 2.3: 
        //OVS_ARGTYPE_PI_TCP_FLAGS and OVS_ARGTYPE_PI_DATAPATH_HASH and OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID
        //are not settable
    case OVS_ARGTYPE_PI_PACKET_MARK:
        pONb->packetMark = GET_ARG_DATA(pArg, UINT32);
        break;

    case OVS_ARGTYPE_PI_PACKET_PRIORITY:
        pONb->packetPriority = GET_ARG_DATA(pArg, UINT32);
        break;

    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
        pONb->pTunnelInfo = pArg->data;
        break;

    case OVS_ARGTYPE_PI_ETH_ADDRESS:
        ok = ONB_SetEthernetAddress(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_IPV4:
        ok = ONB_SetIpv4(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_IPV6:
        ok = ONB_SetIpv6(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_TCP:
        ok = ONB_SetTcp(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_UDP:
        ok = ONB_SetUdp(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_SCTP:
        ok = ONB_SetSctp(pONb, pArg->data);
        break;

    case OVS_ARGTYPE_PI_MPLS:
        OVS_CHECK(__NOT_IMPLEMENTED__);
        //TODO:
        //ok = ONB_SetMpls(pOvsNb, pArg->data);
        break;
    }

    return ok;
}

//TODO: this function was never tested, and is likely to contain errors
static BOOLEAN _ExecuteAction_Sample(_Inout_ OVS_NET_BUFFER *pOvsNb, _In_ const OVS_ARGUMENT_GROUP* pArguments,
    _In_ const OutputToPortCallback outputToPort)
{
    OVS_ARGUMENT_GROUP* pSampleActionsArgs = NULL;
    OVS_ARGUMENT_GROUP* pOldActionsArgs = NULL;
    BOOLEAN ok = TRUE;

    for (UINT i = 0; i < pArguments->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArguments->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
        {
            UINT32 value = GET_ARG_DATA(pArg, UINT32);

            if ((UINT32)QuickRandom(100) >= value)
                return TRUE;
        }
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
            pSampleActionsArgs = pArg->data;
            break;
        }
    }

    //we must execute the actions in pSampleActionsArgs, so we must save the original
    //actions arg group, and put it back later (to have a correct cleanup at the end)
    if (pSampleActionsArgs)
    {
        pOldActionsArgs = pOvsNb->pActions->pActionGroup;
        pOvsNb->pActions->pActionGroup = pSampleActionsArgs;
    }

    //TODO: the actions in the sample are expected to be:
    // a) no actions (i.e. pSampleActionsArgs count = 0 and size = 0)
    // b) send to userspace
    //In the cases above, it is safe to use this net buffer.
    //An unexpected case is, if there is an action that modified the ONB. In this case,
    //we should duplicate the ONB and send the ONB. OR, we might be able to implement 
    //some copy-on-write functionality for OVS_NET_BUFFER
    ok = ExecuteActions(pOvsNb, outputToPort);

    if (pSampleActionsArgs)
    {
        pOvsNb->pActions->pActionGroup = pOldActionsArgs;
    }

    return ok;
}

static BOOLEAN _ExecuteAction_Hash(_Inout_ OVS_NET_BUFFER *pOvsNb, _In_ const OVS_ARGUMENT_GROUP* pArguments)
{
    UNREFERENCED_PARAMETER(pOvsNb);
    UNREFERENCED_PARAMETER(pArguments);

    OVS_CHECK(__NOT_IMPLEMENTED__);

    return FALSE;
}

static BOOLEAN _ExecuteAction_Recirculation(_Inout_ OVS_NET_BUFFER *pOvsNb, _In_ const OVS_ARGUMENT_GROUP* pArguments)
{
    UNREFERENCED_PARAMETER(pOvsNb);
    UNREFERENCED_PARAMETER(pArguments);

    OVS_CHECK(__NOT_IMPLEMENTED__);

    return FALSE;
}

static OVS_PERSISTENT_PORT* _FindDestPort_Ref(_In_ const OVS_PERSISTENT_PORT* pSourcePort, UINT32 persPortNumber)
{
    UINT16 validPortNumber = OVS_INVALID_PORT_NUMBER;
    OVS_PERSISTENT_PORT* pDestPersPort = NULL;

    //NOTE: we don't need to lock neither pSourcePort, nor pDestPort, because these fields (id, type, isExternal) never change
    if (persPortNumber >= OVS_MAX_PORTS)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number from userspace: %u\n", persPortNumber);
        return NULL;
    }

    validPortNumber = (UINT16)persPortNumber;

    pDestPersPort = PersPort_FindByNumber_Ref(validPortNumber);
    if (!pDestPersPort)
    {
        DEBUGP(LOG_ERROR, "could not find pers port: %u!\n", validPortNumber);
        return NULL;
    }

    //if we know from now that the dest port is not connected (i.e. has no associated NIC), we won't attempt to send through the port
    if (pDestPersPort->portId == NDIS_SWITCH_DEFAULT_PORT_ID &&
        (pDestPersPort->ofPortType == OVS_OFPORT_TYPE_PHYSICAL || pDestPersPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS))
    {
        OVS_REFCOUNT_DEREFERENCE(pDestPersPort);

        return NULL;
    }

    //if the src port = internal / external, we won't output to gre / vxlan:
    //for external: we would be sending the packet back whence it came
    //for internal: when outputting via NORMAL from hypervisor to hypervisor, we don't want to send to the hypervisor both via external and gre
    if (pDestPersPort->ofPortType == OVS_OFPORT_TYPE_GRE || pDestPersPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        if (pSourcePort->portId != NDIS_SWITCH_DEFAULT_PORT_ID &&
            pSourcePort->isExternal ||
            pSourcePort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS)
        {
            OVS_REFCOUNT_DEREFERENCE(pDestPersPort);

            return NULL;
        }
    }

    //if the src port = gre / vxlan, we must not send to internal, nor to external (we would be sending back to the same hyper-v switch port)
    if (pSourcePort->ofPortType == OVS_OFPORT_TYPE_GRE ||
        pSourcePort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        if (pDestPersPort && pDestPersPort->portId != NDIS_SWITCH_DEFAULT_PORT_ID)
        {
            if (pDestPersPort->isExternal ||
                pDestPersPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS)
            {
                OVS_REFCOUNT_DEREFERENCE(pDestPersPort);

                return NULL;
            }
        }
    }

    return pDestPersPort;
}

BOOLEAN ExecuteActions(_Inout_ OVS_NET_BUFFER* pOvsNb, _In_ const OutputToPortCallback outputToPort)
{
    BOOLEAN ok = TRUE;
    const OVS_ARGUMENT_GROUP* pActionArgs = pOvsNb->pActions->pActionGroup;
    OVS_PERSISTENT_PORT* pDestPersPort = NULL;
    UINT32 persPortNumber = (UINT32)-1;

    for (UINT i = 0; i < pActionArgs->count; ++i)
    {
        const OVS_ARGUMENT* pArg = pActionArgs->args + i;
        OVS_ARGTYPE argType = pArg->type;

        ok = TRUE;

        if (pDestPersPort)
        {
            OVS_NET_BUFFER* pDuplicateOnb = ONB_Duplicate(pOvsNb);
            OVS_CHECK(pDuplicateOnb);

            if (pDuplicateOnb)
            {
                pDuplicateOnb->pDestinationPort = pDestPersPort;
                pDuplicateOnb->sendToPortNormal = FALSE;

                //output = output packet to port
                ok = (*outputToPort)(pDuplicateOnb);

                if (ok)
                {
                    KFree(pDuplicateOnb);
                }
                else
                {
                    ONB_Destroy(pDuplicateOnb->pSwitchInfo, &pDuplicateOnb);
                }

                ok = TRUE;

                OVS_REFCOUNT_DEREFERENCE(pDestPersPort);
                pDestPersPort = NULL;
            }
        }

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
            persPortNumber = GET_ARG_DATA(pArg, UINT32);

            if (persPortNumber < OVS_MAX_PORTS)
            {
                pDestPersPort = _FindDestPort_Ref(pOvsNb->pSourcePort, persPortNumber);
            }
            else
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number from userspace: %u\n", persPortNumber);
                ok = FALSE;
            }

            break;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            _ExecuteAction_OutToUserspace(ONB_GetNetBuffer(pOvsNb), pOvsNb->pOriginalPacketInfo, pArg->data);
            break;

        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            ok = _ExecuteAction_Set(pOvsNb, pArg->data);
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            ok = _ExecuteAction_Sample(pOvsNb, pArg->data, outputToPort);
            break;

        case OVS_ARGTYPE_ACTION_PUSH_VLAN:
            ok = Vlan_Push(pOvsNb, pArg->data);
            if (!ok)
            {
                goto Cleanup;
            }
            break;

        case OVS_ARGTYPE_ACTION_POP_VLAN:
            ok = Vlan_Pop(pOvsNb);
            break;

        case OVS_ARGTYPE_ACTION_PUSH_MPLS:
            OVS_CHECK(__NOT_IMPLEMENTED__);
            break;

        case OVS_ARGTYPE_ACTION_POP_MPLS:
            OVS_CHECK(__NOT_IMPLEMENTED__);
            break;

        case OVS_ARGTYPE_ACTION_HASH:
            ok = _ExecuteAction_Hash(pOvsNb, pArg->data);
#if !OVS_ACTION_HASH_IMPLEMENTED
            ok = TRUE;
#endif
            break;

        case OVS_ARGTYPE_ACTION_RECIRCULATION:
            //TODO: use copy-on-write for OVS_NET_BUFFER, OR
            //copy the ONB only if there are more arguments in pArg->data
            ok = _ExecuteAction_Recirculation(pOvsNb, pArg->data);
#if !OVS_ACTION_RECIRCULATION_IMPLEMENTED
            ok = TRUE;
#endif
            break;
        }

        if (!ok)
        {
            goto Cleanup;
        }
    }

    if (pDestPersPort)
    {
        pOvsNb->pDestinationPort = pDestPersPort;
        pOvsNb->sendToPortNormal = FALSE;

        ok = (*outputToPort)(pOvsNb);

        OVS_REFCOUNT_DEREFERENCE(pDestPersPort);
        pDestPersPort = NULL;
    }
    else
    {
        //i.e. did not send pOvsNb, _ProcessAllNblsIngress will destroy it.
        ok = FALSE;
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDestPersPort);

    return ok;
}

/********************************************************************************************/

static BOOLEAN _VerifyAction_Upcall(const OVS_ARGUMENT* pArg)
{
    UINT32 pid = 0;

    OVS_CHECK(IsArgTypeGroup(pArg->type));

    OVS_ARGUMENT* pPidArg = FindArgument(pArg->data, OVS_ARGTYPE_ACTION_UPCALL_PORT_ID);
    if (!pPidArg)
    {
        return FALSE;
    }

    pid = GET_ARG_DATA(pPidArg, UINT32);
    if (pid == 0)
    {
        return FALSE;
    }

    OVS_ARGUMENT* pData = FindArgument(pArg->data, OVS_ARGTYPE_ACTION_UPCALL_DATA);

    //if pData == FALSE, it means we don't have upcall data in upcall group - this is a valid state
    if (pData && ((pData->length && !pData->data) || (!pData->length && pData->data)))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _ValidateTransportPort(const OVS_OFPACKET_INFO* pPacketInfo)
{
    if (pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) &&
        pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        DEBUGP(LOG_ERROR, "packet info's eth type != ipv4 & != ipv6\n");
        return FALSE;
    }

    if (pPacketInfo->tpInfo.sourcePort != OVS_PI_MASK_MATCH_WILDCARD(UINT16) ||
        pPacketInfo->tpInfo.destinationPort != OVS_PI_MASK_MATCH_WILDCARD(UINT16))
    {
        return TRUE;
    }

    else
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " src port == wildcard & dest port == wildcard: invalid\n");
        return FALSE;
    }
}

static BOOLEAN _CreateActionIpv4Tunnel(const OVS_ARGUMENT_GROUP* pTunnelGroup, OVS_ARGUMENT** ppIpv4TunnelArg)
{
    BOOLEAN ok = FALSE;
    OVS_ARGUMENT* pIpv4Tunnel = NULL;
    OF_PI_IPV4_TUNNEL* pTunnelInfo = NULL;
    
    pTunnelInfo = KZAlloc(sizeof(OF_PI_IPV4_TUNNEL));
    if (!pTunnelInfo)
    {
        return FALSE;
    }

    RtlZeroMemory(pTunnelInfo, sizeof(OF_PI_IPV4_TUNNEL));

    ok = GetIpv4TunnelFromArgumentsSimple(pTunnelGroup, pTunnelInfo);
    if (!ok)
    {
        KFree(pTunnelInfo);
        return FALSE;
    }

    pIpv4Tunnel = CreateArgument(OVS_ARGTYPE_PI_IPV4_TUNNEL, pTunnelInfo);

    if (!pIpv4Tunnel)
    {
        return FALSE;
    }

    *ppIpv4TunnelArg = pIpv4Tunnel;

    return ok;
}

static BOOLEAN _Action_SetInfo(_Inout_ OVS_ARGUMENT_GROUP* pActionGroup, const OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_ARGUMENT* pPacketInfoArg = NULL;;
    OVS_ARGTYPE argType = OVS_ARGTYPE_INVALID;
    OVS_ARGUMENT* pTunnelArg = NULL;
    OF_PI_IPV4_TUNNEL* pTunnel;
    const BYTE* pMac = NULL;
    const OVS_PI_IPV4* pIpv4Info = NULL;
    const OVS_PI_IPV6* pIpv6Info = NULL;
    BOOLEAN ok = FALSE;

    if (pActionGroup->count != 1)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " pActionGroup->count != 1\n");
        return FALSE;
    }

    pPacketInfoArg = pActionGroup->args;
    argType = pPacketInfoArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_PACKET_PRIORITY:
    case OVS_ARGTYPE_PI_PACKET_MARK:
    case OVS_ARGTYPE_PI_ETH_ADDRESS:
    case OVS_ARGTYPE_PI_DATAPATH_HASH:
    case OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID:
        //nothing to do here
        break;

    case OVS_ARGTYPE_PI_TUNNEL_GROUP:
        ok = _CreateActionIpv4Tunnel(pPacketInfoArg->data, &pTunnelArg);
        DestroyArgument(pPacketInfoArg);
        pActionGroup->args = pTunnelArg;

        if (!ok)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " _CreateActionIpv4Tunnel failed\n");
            return FALSE;
        }

        pTunnel = pTunnelArg->data;
        pMac = Arp_FindTableEntry((const BYTE*)&pTunnel->ipv4Destination);
        if (!pMac)
        {
            ONB_OriginateArpRequest((const BYTE*)&pTunnel->ipv4Destination);
        }

        break;

    case OVS_ARGTYPE_PI_IPV4:
        if (pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's eth type != ipv4\n");
            return FALSE;
        }

        if (!pPacketInfo->ipInfo.protocol)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto == NULL\n");
            return FALSE;
        }

        pIpv4Info = pPacketInfoArg->data;
        if (pIpv4Info->protocol != pPacketInfo->ipInfo.protocol)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " ipv4 packet info's proto != packet info's proto\n");
            return FALSE;
        }

        if (pIpv4Info->fragmentType != pPacketInfo->ipInfo.fragment)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " ipv4 packet info's frag type != packet info's frag type\n");
            return FALSE;
        }

        break;

    case OVS_ARGTYPE_PI_IPV6:
        if (pPacketInfo->ethInfo.type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's eth type != ipv6\n");
            return FALSE;
        }

        if (!pPacketInfo->ipInfo.protocol)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto == NULL\n");
            return FALSE;
        }

        pIpv6Info = pPacketInfoArg->data;
        if (pIpv6Info->protocol != pPacketInfo->ipInfo.protocol)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " ipv4 packet info's proto != packet info's proto\n");
            return FALSE;
        }

        if (pIpv6Info->fragmentType != pPacketInfo->ipInfo.fragment){
            DEBUGP(LOG_ERROR, __FUNCTION__ " ipv6 packet info's frag type != packet info's frag type\n");
            return FALSE;
        }

        //the flow label is 20 bits long, so the label in ipv6 PI must be max 0xFFFFF
        if (RtlUshortByteSwap(pIpv6Info->label) > 0x000FFFFF)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " ipv6 packet info's label invalid\n");
            return FALSE;
        }

        break;

    case OVS_ARGTYPE_PI_TCP:
        if (pPacketInfo->ipInfo.protocol != IPPROTO_TCP)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto != tcp\n");
            return FALSE;
        }

        return _ValidateTransportPort(pPacketInfo);

    case OVS_ARGTYPE_PI_TCP_FLAGS:
        if (pPacketInfo->ipInfo.protocol != IPPROTO_TCP)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto != tcp\n");
            return FALSE;
        }

        return TRUE;

    case OVS_ARGTYPE_PI_UDP:
        if (pPacketInfo->ipInfo.protocol != IPPROTO_UDP)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto != udp\n");
            return FALSE;
        }

        return _ValidateTransportPort(pPacketInfo);

    case OVS_ARGTYPE_PI_SCTP:
        if (pPacketInfo->ipInfo.protocol != IPPROTO_SCTP)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " packet info's proto != sctp\n");
            return FALSE;
        }

        return _ValidateTransportPort(pPacketInfo);

    case OVS_ARGTYPE_PI_MPLS:
        if (RtlUshortByteSwap(pPacketInfo->ethInfo.type) != OVS_ETHERTYPE_MPLS_UNICAST ||
            RtlUshortByteSwap(pPacketInfo->ethInfo.type) != OVS_ETHERTYPE_MPLS_MULTICAST)
        {
            return FALSE;
        }

        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " invalid PI type to set: 0x%x\n", argType);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN ProcessReceivedActions(_Inout_ OVS_ARGUMENT_GROUP* pActionGroup, const OVS_OFPACKET_INFO* pPacketInfo, int recursivityDepth)
{
    BOOLEAN ok = TRUE;

    if (recursivityDepth >= OVS_ACTION_SAMPLE_MAX_DEPTH)
    {
        return FALSE;
    }

    for (UINT i = 0; i < pActionGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pActionGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_INVALID:
            return FALSE;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            ok = _VerifyAction_Upcall(pArg);
            if (!ok)
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        case OVS_ARGTYPE_ACTION_RECIRCULATION:
            break;

        case OVS_ARGTYPE_ACTION_HASH:
        {
            OVS_ACTION_FLOW_HASH* pHashAction = pArg->data;
            if (pHashAction->hashAlgorithm != OVS_HASH_ALGORITHM_TRANSPORT)
                return FALSE;
        }
            break;

        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            OVS_CHECK(IsArgTypeGroup(pArg->type));
            ok = _Action_SetInfo(pArg->data, pPacketInfo);
            if (!ok)
            {
                return FALSE;
            }

            break;

        case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
        {
            UINT32 portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_ACTION_PUSH_VLAN:
        {
            const OVS_ACTION_PUSH_VLAN* pPushVlanAction;
            pPushVlanAction = pArg->data;
            if (pPushVlanAction->protocol != RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
            {
                return FALSE;
            }

            if (!(pPushVlanAction->vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_ACTION_POP_VLAN:
            break;

        case OVS_ARGTYPE_ACTION_PUSH_MPLS:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        case OVS_ARGTYPE_ACTION_POP_MPLS:
            OVS_CHECK_RET(__NOT_IMPLEMENTED__, FALSE);
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

VOID Actions_DestroyNow_Unsafe(_Inout_ OVS_ACTIONS* pActions)
{
    OVS_CHECK(pActions);

    DestroyArgumentGroup(pActions->pActionGroup);

    KFree(pActions);
}

OVS_ACTIONS* Actions_Create()
{
    OVS_ACTIONS* pActions = KZAlloc(sizeof(OVS_ACTIONS));

    if (!pActions)
    {
        return NULL;
    }

    pActions->pActionGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pActions->pActionGroup)
    {
        KFree(pActions);
        return NULL;
    }

    pActions->refCount.Destroy = Actions_DestroyNow_Unsafe;

    return pActions;
}
