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

#include "ArgToAttribute.h"
#include "ArgumentType.h"
#include "Argument.h"
#include "Message.h"
#include "Attribute.h"

static BOOLEAN _Reply_SetAttrType_Datapath_New(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE parentArgType)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(parentArgType);
    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_STATS:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_STATS;
        break;

    case OVS_ARGTYPE_DATAPATH_NAME:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_NAME;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Datapath_Set(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE parentArgType)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(parentArgType);
    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_STATS:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_STATS;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Datapath_Get(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE parentArgType)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(parentArgType);

    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_STATS:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_STATS;
        break;

    case OVS_ARGTYPE_DATAPATH_NAME:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_NAME;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Datapath_Delete(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE parentArgType)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(parentArgType);
    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_STATS:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_STATS;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Datapath_Dump(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE parentArgType)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(parentArgType);
    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_STATS:
        pArg->type = OVS_USPACE_DP_ATTRIBUTE_STATS;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Datapath(OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
        return _Reply_SetAttrType_Datapath_New(pArg, parentArgType);

    case OVS_MESSAGE_COMMAND_SET:
        return _Reply_SetAttrType_Datapath_Set(pArg, parentArgType);

    case OVS_MESSAGE_COMMAND_GET:
        return _Reply_SetAttrType_Datapath_Get(pArg, parentArgType);

    case OVS_MESSAGE_COMMAND_DELETE:
        return _Reply_SetAttrType_Datapath_Delete(pArg, parentArgType);

    case OVS_MESSAGE_COMMAND_DUMP:
        return _Reply_SetAttrType_Datapath_Dump(pArg, parentArgType);

    default:
        return FALSE;
    }
}

static BOOLEAN _Reply_SetAttrType_PITunnel(OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_TUNNEL_ID:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_ID;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_SRC;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_DST;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_TOS:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TOS;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_TTL:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TTL;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_DONT_FRAGMENT;
        break;

    case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:

        pArg->type = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_CSUM;
        break;

    default:
    {
        DEBUGP(LOG_ERROR, "unexpected flow/key/tunnel arg: %u\n", pArg->type);
        return FALSE;
    }
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_PacketInfo(OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_PI_PACKET_PRIORITY:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_PRIORITY;
        break;

    case OVS_ARGTYPE_PI_DP_INPUT_PORT:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_IN_PORT;
        break;

    case OVS_ARGTYPE_PI_ETH_ADDRESS:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ETHERNET;
        break;

    case OVS_ARGTYPE_PI_ETH_TYPE:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ETHERTYPE;
        break;

    case OVS_ARGTYPE_PI_VLAN_TCI:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_VLAN;
        break;

    case OVS_ARGTYPE_PI_IPV4:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_IPV4;
        break;

    case OVS_ARGTYPE_PI_IPV6:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_IPV6;
        break;

    case OVS_ARGTYPE_PI_TCP:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_TCP;
        break;

    case OVS_ARGTYPE_PI_UDP:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_UDP;
        break;

    case OVS_ARGTYPE_PI_SCTP:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_SCTP;
        break;

    case OVS_ARGTYPE_PI_ICMP:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ICMP;
        break;

    case OVS_ARGTYPE_PI_ICMP6:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ICMPV6;
        break;

    case OVS_ARGTYPE_PI_ARP:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ARP;
        break;

    case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ND;
        break;

    case OVS_ARGTYPE_PI_PACKET_MARK:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_SKB_MARK;
        break;

    case OVS_ARGTYPE_GROUP_PI_TUNNEL:
        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_TUNNEL;
        break;

    case OVS_ARGTYPE_PI_IPV4_TUNNEL:

        //NOT SUPPORTED - it's a kernel attr only!
        OVS_CHECK(__UNEXPECTED__);
        break;

    case OVS_ARGTYPE_PI_MPLS:

        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_MPLS;
        OVS_CHECK(__NOT_IMPLEMENTED__);
        break;

    case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
        pArg->type = OVS_USPACE_KEY_ATTRIBUTE_ENCAP;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected flow/key arg: %u", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_PacketActions(_Inout_ OVS_ARGUMENT* pArg);
static BOOLEAN _Reply_SetAttrType_PacketActionsSample(_Inout_ OVS_ARGUMENT* pArg);
static BOOLEAN _Reply_SetAttrType_PacketActionsUpcall(_Inout_ OVS_ARGUMENT* pArg);

static BOOLEAN _Reply_SetAttrType_Flow(OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(cmd);
    OVS_CHECK(cmd == OVS_MESSAGE_COMMAND_NEW || 
		cmd == OVS_MESSAGE_COMMAND_DELETE);

    if (parentArgType == OVS_ARGTYPE_GROUP_PI)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_PI_TUNNEL)
    {
        return _Reply_SetAttrType_PITunnel(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_PI_ENCAPSULATION)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS)
    {
        return _Reply_SetAttrType_PacketActions(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE)
    {
        return _Reply_SetAttrType_PacketActionsSample(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SETINFO)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_UPCALL)
    {
        return _Reply_SetAttrType_PacketActionsUpcall(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_MASK)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }

    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_FLOW_STATS:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_STATS;
        break;

    case OVS_ARGTYPE_FLOW_TCP_FLAGS:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_TCP_FLAGS;
        break;

    case OVS_ARGTYPE_FLOW_TIME_USED:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_USED;
        break;

    case OVS_ARGTYPE_FLOW_CLEAR:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_CLEAR;
        break;

    case OVS_ARGTYPE_GROUP_PI:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_KEY;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_ACTIONS;
        break;

    case OVS_ARGTYPE_GROUP_MASK:
        pArg->type = OVS_USPACE_FLOW_ATTRIBUTE_MASK;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected flow arg: %u\n", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_PacketActionsUpcall(_Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
        pArg->type = OVS_USPACE_UPCALL_ATTRIBUTE_PID;
        break;

    case OVS_ARGTYPE_ACTION_UPCALL_DATA:
        pArg->type = OVS_USPACE_UPCALL_ATTRIBUTE_USERDATA;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected packet/actions/upcall arg: %u\n", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_PacketActionsSample(_Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
        pArg->type = OVS_USPACE_SAMPLE_ATTRIBUTE_PROBABILITY;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS:
        pArg->type = OVS_USPACE_SAMPLE_ATTRIBUTE_ACTIONS;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected packet/actions/sample arg: %u\n", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_PacketActions(_Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_OUTPUT;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_USERSPACE;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_SET;
        break;

    case OVS_ARGTYPE_ACTION_PUSH_VLAN:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_PUSH_VLAN;
        break;

    case OVS_ARGTYPE_ACTION_POP_VLAN:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_POP_VLAN;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
        pArg->type = OVS_USPACE_ACTION_ATTRIBUTE_SAMPLE;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected packet/actions arg: %u\n", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Packet(OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(cmd);

    if (parentArgType == OVS_ARGTYPE_GROUP_PI)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_PI_TUNNEL)
    {
        return _Reply_SetAttrType_PITunnel(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_PI_ENCAPSULATION)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS)
    {
        return _Reply_SetAttrType_PacketActions(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_UPCALL)
    {
        return _Reply_SetAttrType_PacketActionsUpcall(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SETINFO)
    {
        return _Reply_SetAttrType_PacketInfo(pArg);
    }
    else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE)
    {
        return _Reply_SetAttrType_PacketActionsSample(pArg);
    }

    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_NETBUFFER:
        pArg->type = OVS_USPACE_PACKET_ATTRIBUTE_PACKET;
        break;

    case OVS_ARGTYPE_GROUP_PI:
        pArg->type = OVS_USPACE_PACKET_ATTRIBUTE_KEY;
        break;

    case OVS_ARGTYPE_GROUP_ACTIONS:
        pArg->type = OVS_USPACE_PACKET_ATTRIBUTE_ACTIONS;
        break;

    case OVS_ARGTYPE_NETBUFFER_USERDATA:
        pArg->type = OVS_USPACE_PACKET_ATTRIBUTE_USERDATA;
        break;

    default:
        DEBUGP(LOG_ERROR, "unexpected packet arg: %u\n", pArg->type);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Port_Options(_Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT:
        pArg->type = OVS_USPACE_TUNNEL_ATTRIBUTE_DST_PORT;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _Reply_SetAttrType_Port(OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    OVS_ARGTYPE argType = pArg->type;

    UNREFERENCED_PARAMETER(cmd);
    OVS_CHECK(cmd == OVS_MESSAGE_COMMAND_NEW);

    if (parentArgType == OVS_ARGTYPE_GROUP_OFPORT_OPTIONS)
    {
        return _Reply_SetAttrType_Port_Options(pArg);
    }

    OVS_CHECK(parentArgType == OVS_ARGTYPE_GROUP_MAIN);

    switch (argType)
    {
    case OVS_ARGTYPE_OFPORT_NUMBER:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_PORT_NO;
        break;

    case OVS_ARGTYPE_OFPORT_NAME:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_NAME;
        break;

    case OVS_ARGTYPE_OFPORT_STATS:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_STATS;
        break;

    case OVS_ARGTYPE_OFPORT_TYPE:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_TYPE;
        break;

    case OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_UPCALL_PID;
        break;

    case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
        pArg->type = OVS_USPACE_VPORT_ATTRIBUTE_OPTIONS;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

BOOLEAN Reply_SetAttrType(OVS_MESSAGE_TARGET_TYPE targetType, OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    switch (targetType)
    {
    case OVS_MESSAGE_TARGET_DATAPATH:
        return _Reply_SetAttrType_Datapath(cmd, parentArgType, pArg);

    case OVS_MESSAGE_TARGET_FLOW:
        return _Reply_SetAttrType_Flow(cmd, parentArgType, pArg);

    case OVS_MESSAGE_TARGET_PACKET:
        return _Reply_SetAttrType_Packet(cmd, parentArgType, pArg);

    case OVS_MESSAGE_TARGET_PORT:
        return _Reply_SetAttrType_Port(cmd, parentArgType, pArg);

    default:
        return FALSE;
    }
}