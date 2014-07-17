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

#include "AttrToArgument.h"
#include "Message.h"
#include "Attribute.h"

static BOOLEAN _AttrType_To_ArgType_Datapath(OVS_ARGTYPE parentArgType, UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    *pTypeAsArg = OVS_ARGTYPE_GROUP_MAIN;

    if (parentArgType != OVS_ARGTYPE_GROUP_MAIN)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected parrent attr type: %u\n", parentArgType);
        return FALSE;
    }

    switch (attrType)
    {
    case OVS_USPACE_DP_ATTRIBUTE_NAME:
        *pTypeAsArg = OVS_ARGTYPE_DATAPATH_NAME;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_DATAPATH_NAME\n");
        return TRUE;

    case OVS_USPACE_DP_ATTRIBUTE_UPCALL_PID:
        *pTypeAsArg = OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID\n");
        return TRUE;

    case OVS_USPACE_DP_ATTRIBUTE_STATS:
        *pTypeAsArg = OVS_ARGTYPE_DATAPATH_STATS;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_DATAPATH_STATS\n");
        return TRUE;

    default:
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_Port(OVS_ARGTYPE parentArgType, UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    *pTypeAsArg = OVS_ARGTYPE_GROUP_MAIN;

    if (parentArgType == OVS_ARGTYPE_GROUP_MAIN)
    {
        switch (attrType)
        {
            //NESTED
        case OVS_USPACE_VPORT_ATTRIBUTE_OPTIONS:
            *pTypeAsArg = OVS_ARGTYPE_GROUP_OFPORT_OPTIONS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_OPTIONS_GROUP\n");
            return TRUE;

            //NOT NESTED
        case OVS_USPACE_VPORT_ATTRIBUTE_PORT_NO:
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_NUMBER;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_NUMBER\n");
            return TRUE;

        case OVS_USPACE_VPORT_ATTRIBUTE_TYPE:
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_TYPE;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_TYPE\n");
            return TRUE;

        case OVS_USPACE_VPORT_ATTRIBUTE_NAME:
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_NAME;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_NAME\n");
            return TRUE;

        case OVS_USPACE_VPORT_ATTRIBUTE_UPCALL_PID:
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID\n");
            return TRUE;

        case OVS_USPACE_VPORT_ATTRIBUTE_STATS:
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_STATS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_OFPORT_STATS\n");
            return TRUE;

        default:
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
            return FALSE;
        }
    }
    else
    {
        if (parentArgType != OVS_ARGTYPE_GROUP_OFPORT_OPTIONS)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected parrent attr type: %u\n", parentArgType);
            return FALSE;
        }

        if (attrType == OVS_USPACE_TUNNEL_ATTRIBUTE_DST_PORT)
        {
            *pTypeAsArg = OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PORT_OPTION_DESTINATION_PORT\n");
            return TRUE;
        }
        else
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
            return FALSE;
        }
    }
}

static BOOLEAN _AttrType_To_ArgType_PacketInfo(UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (attrType)
    {
        //NESTED
    case OVS_USPACE_KEY_ATTRIBUTE_ENCAP:
        *pTypeAsArg = OVS_ARGTYPE_PI_ENCAP_GROUP;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ENCAPSULATION_GROUP\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_TUNNEL:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_GROUP;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_GROUP\n");
        return TRUE;

        //NOT NESTED
    case OVS_USPACE_KEY_ATTRIBUTE_PRIORITY:
        *pTypeAsArg = OVS_ARGTYPE_PI_PACKET_PRIORITY;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_PACKET_PRIORITY\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_IN_PORT:
        *pTypeAsArg = OVS_ARGTYPE_PI_DP_INPUT_PORT;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_DP_INPUT_PORT\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ETHERNET:
        *pTypeAsArg = OVS_ARGTYPE_PI_ETH_ADDRESS;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ETH_ADDRESS\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_VLAN:
        *pTypeAsArg = OVS_ARGTYPE_PI_VLAN_TCI;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_VLAN_TCI\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ETHERTYPE:
        *pTypeAsArg = OVS_ARGTYPE_PI_ETH_TYPE;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ETH_TYPE\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_IPV4:
        *pTypeAsArg = OVS_ARGTYPE_PI_IPV4;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_IPV4\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_IPV6:
        *pTypeAsArg = OVS_ARGTYPE_PI_IPV6;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_IPV6\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_TCP:
        *pTypeAsArg = OVS_ARGTYPE_PI_TCP;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TCP\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_UDP:
        *pTypeAsArg = OVS_ARGTYPE_PI_UDP;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_UDP\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ICMP:
        *pTypeAsArg = OVS_ARGTYPE_PI_ICMP;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ICMP\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ICMPV6:
        *pTypeAsArg = OVS_ARGTYPE_PI_ICMP6;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ICMP6\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ARP:
        *pTypeAsArg = OVS_ARGTYPE_PI_ARP;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_ARP\n");
        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_ND:
        *pTypeAsArg = OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY\n");

        return TRUE;

    case OVS_USPACE_KEY_ATTRIBUTE_SKB_MARK:
        *pTypeAsArg = OVS_ARGTYPE_PI_PACKET_MARK;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_PACKET_MARK\n");
        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_FlowKeyTunnel(UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (attrType)
    {
        //NOT NESTED
    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_ID:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_ID;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_ID\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_SRC:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_IPV4_SRC\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_DST:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_IPV4_DST;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_IPV4_DST\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TOS:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_TOS;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_TOS\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TTL:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_TTL;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_TTL\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_DONT_FRAGMENT:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_DONT_FRAGMENT\n");
        return TRUE;

    case OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_CSUM:
        *pTypeAsArg = OVS_ARGTYPE_PI_TUNNEL_CHECKSUM;

        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_KEY_TUNNEL_CHECKSUM\n");
        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_Actions(UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (attrType)
    {
        //NOT NESTED
    case OVS_USPACE_ACTION_ATTRIBUTE_OUTPUT:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTION_OUTPUT_TO_PORT\n");
        return TRUE;

    case OVS_USPACE_ACTION_ATTRIBUTE_PUSH_VLAN:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_PUSH_VLAN;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTION_PUSH_VLAN\n");
        return TRUE;

    case OVS_USPACE_ACTION_ATTRIBUTE_POP_VLAN:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_POP_VLAN;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTION_POP_VLAN\n");
        return TRUE;

        //NESTED
    case OVS_USPACE_ACTION_ATTRIBUTE_USERSPACE:
        *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS_UPCALL;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_UPCALL_GROUP\n");
        return TRUE;

    case OVS_USPACE_ACTION_ATTRIBUTE_SAMPLE:
        *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_SAMPLE_GROUP\n");
        return TRUE;

    case OVS_USPACE_ACTION_ATTRIBUTE_SET:
        *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS_SETINFO;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_SETINFO_GROUP\n");
        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_ActionsUserspace(UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (attrType)
    {
    case OVS_USPACE_UPCALL_ATTRIBUTE_PID:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_UPCALL_PORT_ID;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_ACTION_UPCALL_PORT_ID\n");
        return TRUE;

    case OVS_USPACE_UPCALL_ATTRIBUTE_USERDATA:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_UPCALL_DATA;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_ACTION_UPCALL_DATA\n");
        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_ActionsSample(UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (attrType)
    {
        //NESTED
    case OVS_USPACE_SAMPLE_ATTRIBUTE_ACTIONS:
        *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_GROUP\n");
        return TRUE;

        //NOT NESTED
    case OVS_USPACE_SAMPLE_ATTRIBUTE_PROBABILITY:
        *pTypeAsArg = OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY;
        DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTION_SAMPLE_PROBABILITY\n");
        return TRUE;

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
        return FALSE;
    }
}

static BOOLEAN _AttrType_To_ArgType_Packet(OVS_ARGTYPE parentArgType, UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    *pTypeAsArg = OVS_ARGTYPE_GROUP_MAIN;

    if (parentArgType == OVS_ARGTYPE_GROUP_MAIN)
    {
        switch (attrType)
        {
            //NESTED
        case OVS_USPACE_PACKET_ATTRIBUTE_KEY:
            *pTypeAsArg = OVS_ARGTYPE_NETBUFFER_PI_GROUP;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_GROUP_PI\n");
            return TRUE;

        case OVS_USPACE_PACKET_ATTRIBUTE_ACTIONS:
            *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_GROUP\n");
            return TRUE;

            //NOT NESTED
        case OVS_USPACE_PACKET_ATTRIBUTE_PACKET:
            *pTypeAsArg = OVS_ARGTYPE_NETBUFFER;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_BUFFER\n");
            return TRUE;

        case OVS_USPACE_PACKET_ATTRIBUTE_USERDATA:
            *pTypeAsArg = OVS_ARGTYPE_NETBUFFER_USERDATA;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_USERDATA\n");
            return TRUE;

        default:
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
            return FALSE;
        }
    }
    else
    {
        //main -> packet info; the attr is a key of flow group
        if (parentArgType == OVS_ARGTYPE_NETBUFFER_PI_GROUP)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //main -> packet info mask; the attr is a key of flow group

        if (parentArgType == OVS_ARGTYPE_GROUP_MASK)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //flow / key -> encap keys; the attr is a key in the flow (encap) group
        else if (parentArgType == OVS_ARGTYPE_PI_ENCAP_GROUP)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //flow / key / tunnel -> tunnel keys; the attr is a key in the flow / key / tunnel group
        else if (parentArgType == OVS_ARGTYPE_PI_TUNNEL_GROUP)
        {
            return _AttrType_To_ArgType_FlowKeyTunnel(attrType, pTypeAsArg);
        }
        //actions - the attr is an action
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS)
        {
            return _AttrType_To_ArgType_Actions(attrType, pTypeAsArg);
        }
        //actions / userspace -> userspace actions; the attr is a userspace info in the upcall group
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_UPCALL)
        {
            return _AttrType_To_ArgType_ActionsUserspace(attrType, pTypeAsArg);
        }
        //actions / sample -> actions; the attr is an action
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE)
        {
            return _AttrType_To_ArgType_ActionsSample(attrType, pTypeAsArg);
        }
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SETINFO)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        else
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected parrent attr type: %u\n", parentArgType);
            return FALSE;
        }
    }
}

static BOOLEAN _AttrType_To_ArgType_Flow(OVS_ARGTYPE parentArgType, UINT16 attrType, OVS_ARGTYPE* pTypeAsArg)
{
    *pTypeAsArg = OVS_ARGTYPE_GROUP_MAIN;

    if (parentArgType == OVS_ARGTYPE_GROUP_MAIN)
    {
        switch (attrType)
        {
            //NESTED
        case OVS_USPACE_FLOW_ATTRIBUTE_KEY:
            *pTypeAsArg = OVS_ARGTYPE_FLOW_PI_GROUP;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_GROUP_PI\n");
            return TRUE;

        case OVS_USPACE_FLOW_ATTRIBUTE_MASK:
            *pTypeAsArg = OVS_ARGTYPE_GROUP_MASK;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_GROUP_MASK\n");
            return TRUE;

        case OVS_USPACE_FLOW_ATTRIBUTE_ACTIONS:
            *pTypeAsArg = OVS_ARGTYPE_GROUP_ACTIONS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_PACKET_ACTIONS_GROUP\n");
            return TRUE;

            //NOT NESTED
        case OVS_USPACE_FLOW_ATTRIBUTE_STATS:
            *pTypeAsArg = OVS_ARGTYPE_FLOW_STATS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_STATS\n");
            return TRUE;

        case OVS_USPACE_FLOW_ATTRIBUTE_TCP_FLAGS:
            *pTypeAsArg = OVS_ARGTYPE_FLOW_TCP_FLAGS;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_TCP_FLAGS\n");
            return TRUE;

        case OVS_USPACE_FLOW_ATTRIBUTE_USED:
            *pTypeAsArg = OVS_ARGTYPE_FLOW_TIME_USED;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_TIME_USED\n");
            return TRUE;

        case OVS_USPACE_FLOW_ATTRIBUTE_CLEAR:
            *pTypeAsArg = OVS_ARGTYPE_FLOW_CLEAR;
            DEBUGP_ARG(LOG_INFO, "rcv arg: OVS_ARGTYPE_FLOW_CLEAR\n");
            return TRUE;

        default:
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected attr type: %u\n", attrType);
            return FALSE;
        }
    }
    else
    {
        //main -> packet info; the attr is a key of flow group
        if (parentArgType == OVS_ARGTYPE_FLOW_PI_GROUP)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //main -> packet info mask; the attr is a key of flow group
        else if (parentArgType == OVS_ARGTYPE_GROUP_MASK)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //flow / key -> encap keys; the attr is a key in the flow (encap) group
        else if (parentArgType == OVS_ARGTYPE_PI_ENCAP_GROUP)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        //flow / key / tunnel -> tunnel keys; the attr is a key in the flow / key / tunnel group
        else if (parentArgType == OVS_ARGTYPE_PI_TUNNEL_GROUP)
        {
            return _AttrType_To_ArgType_FlowKeyTunnel(attrType, pTypeAsArg);
        }
        //actions - the attr is an action
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS)
        {
            return _AttrType_To_ArgType_Actions(attrType, pTypeAsArg);
        }
        //actions / userspace -> userspace actions; the attr is a userspace info in the upcall group
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_UPCALL)
        {
            return _AttrType_To_ArgType_ActionsUserspace(attrType, pTypeAsArg);
        }
        //actions / sample -> actions; the attr is an action
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE)
        {
            return _AttrType_To_ArgType_Actions(attrType, pTypeAsArg);
        }
        else if (parentArgType == OVS_ARGTYPE_GROUP_ACTIONS_SETINFO)
        {
            return _AttrType_To_ArgType_PacketInfo(attrType, pTypeAsArg);
        }
        else
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected parrent attr type: %u\n", parentArgType);
            return FALSE;
        }
    }
}

BOOLEAN AttrType_To_ArgType(UINT16 targetType, UINT16 attrType, OVS_ARGTYPE parentType, OVS_ARGTYPE* pTypeAsArg)
{
    switch (targetType)
    {
    case OVS_MESSAGE_TARGET_DATAPATH:
        return _AttrType_To_ArgType_Datapath(parentType, attrType, pTypeAsArg);

    case OVS_MESSAGE_TARGET_FLOW:
        return _AttrType_To_ArgType_Flow(parentType, attrType, pTypeAsArg);

    case OVS_MESSAGE_TARGET_PACKET:
        return _AttrType_To_ArgType_Packet(parentType, attrType, pTypeAsArg);

    case OVS_MESSAGE_TARGET_PORT:
        return _AttrType_To_ArgType_Port(parentType, attrType, pTypeAsArg);

    default:
        DEBUGP(LOG_ERROR, __FUNCTION__ " - unexpected / unknown target type: %u\n", targetType);
        return FALSE;
    }
}