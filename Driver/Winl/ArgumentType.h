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

#pragma once

#define OVS_DRIVER_FLOW_VERSION                1
#define OVS_DRIVER_DATAPATH_VERSION            1
#define OVS_DRIVER_VPORT_VERSION               1
#define OVS_DRIVER_PACKET_VERSION              1

/******************************************/

typedef enum _OVS_ARGTYPE
{
    OVS_ARGTYPE_GROUP_MAIN = 0x00D,
    OVS_ARGTYPE_FIRST_GROUP = OVS_ARGTYPE_GROUP_MAIN,

    OVS_ARGTYPE_PSEUDOGROUP_FLOW = 0x00E,
    OVS_ARGTYPE_FIRST_PSEUDOGROUP = OVS_ARGTYPE_PSEUDOGROUP_FLOW,
    OVS_ARGTYPE_PSEUDOGROUP_DATAPATH = 0x00F,
    OVS_ARGTYPE_PSEUDOGROUP_OFPORT = 0x010,
    OVS_ARGTYPE_PSEUDOGROUP_PACKET = 0x011,
    OVS_ARGTYPE_LAST_PSEUDOGROUP = OVS_ARGTYPE_PSEUDOGROUP_PACKET,

    OVS_ARGTYPE_LAST_GROUP = OVS_ARGTYPE_PSEUDOGROUP_PACKET,

    OVS_ARGTYPE_INVALID = 0x000,

    /********************************************** TARGET: FLOW; GROUP: MAIN *******************************************/

    OVS_ARGTYPE_FLOW_PI_GROUP = 0x21,
    OVS_ARGTYPE_FIRST_FLOW = OVS_ARGTYPE_FLOW_PI_GROUP,

    //actions to apply to packets matching the flow
    OVS_ARGTYPE_FLOW_ACTIONS_GROUP,             //0x22

    //Flow request: ignored
    //Flow reply: only if there have been packets matched by the flow
    //Data Type: OVS_WINL_FLOW_STATS
    OVS_ARGTYPE_FLOW_STATS,                     //0x23

    //All tcp control bits / flags that were on packets matched by this flow
    //Flow request: ignored
    //Flow reply: only if tcpFlags != 0
    //data type: UINT8
    OVS_ARGTYPE_FLOW_TCP_FLAGS,                //0x024

    //The time at which the last packet was matched by this flow. The time is given by performance counter
    //(i.e. by windows' system monotonic clock), in miliseconds
    //Flow request: ignored
    //Flow reply: only if there have been packets matched by the flow
    //data type: UINT64
    OVS_ARGTYPE_FLOW_TIME_USED,                //0x025

    //Used to clear from the flow: last used time, tcpFlags, and statistics.
    //Flow request: for Flow_Set or Flow_New with override (i.e. when flow already exists)
    //Flow reply: not used
    //data type: no data
    OVS_ARGTYPE_FLOW_CLEAR,                    //0x026

    OVS_ARGTYPE_FLOW_MASK_GROUP,               //0x027

    OVS_ARGTYPE_LAST_FLOW = OVS_ARGTYPE_FLOW_MASK_GROUP,

    /************************************ TARGET: FLOW / PACKET; group: KEY **********************************************/
    //GROUP NOTE: This group represents attributes: OVS_USPACE_PACKET_ATTRIBUTE_KEY and OVS_USPACE_FLOW_ATTRIBUTE_KEY and
    //                                                OVS_USPACE_FLOW_ATTRIBUTE_MASK
    //NOTE: The PI Masks belongs here as well

    //-- Packet priority.
    //NOTE: might be QoS priority; might have no meaning for windows.
    //data type: UINT32
    OVS_ARGTYPE_PI_PACKET_PRIORITY = 0x041,
    OVS_ARGTYPE_FIRST_PI = OVS_ARGTYPE_PI_PACKET_PRIORITY,

    //source port / input port, given as the ovs port number (not hyper-v switch port id)
    //data type: UINT32
    OVS_ARGTYPE_PI_DP_INPUT_PORT,            //0x042

    //data type: OVS_PI_ETH_ADDRESS
    OVS_ARGTYPE_PI_ETH_ADDRESS,            //0x043

    //data type: BE16; values: enum constants of: OVS_ETHERNET_TYPE
    OVS_ARGTYPE_PI_ETH_TYPE,                //0x044

    //VLAN tag control information (Q-Tagged frames). Includes: User Priority, CFI, Vlan Identifier
    //data type: BE16.
    OVS_ARGTYPE_PI_VLAN_TCI,                //0x045

    //data type: OVS_PI_IPV4
    OVS_ARGTYPE_PI_IPV4,                    //0x046

    //data type: OVS_PI_IPV6
    OVS_ARGTYPE_PI_IPV6,                    //0x047

    //data type: OVS_PI_TCP
    OVS_ARGTYPE_PI_TCP,                    //0x048

    //data type: OVS_PI_UDP
    OVS_ARGTYPE_PI_UDP,                    //0x049

    //data type: OVS_PI_SCTP
    OVS_ARGTYPE_PI_SCTP,                    //0x04A

    //data type: OVS_PI_ICMP
    OVS_ARGTYPE_PI_ICMP,                    //0x04B

    //data type: OVS_PI_ICMP6
    OVS_ARGTYPE_PI_ICMP6,                    //0x04C

    //data type: OVS_PI_ARP
    OVS_ARGTYPE_PI_ARP,                    //0x04D

    //data type: OVS_PI_NEIGHBOR_DISCOVERY
    OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY,        //0x04E

    //data type: UINT32;
    OVS_ARGTYPE_PI_PACKET_MARK,            //0x04F,

    //data type: OF_PI_IPV4_TUNNEL
    //NOTE: OVS_ARGTYPE_FLOW_KEY_IPV4_TUNNEL is used only in kernel. IT IS NOT USED in userspace!
    OVS_ARGTYPE_PI_IPV4_TUNNEL,            //0x050

    //-- Multi Protocol Label Switching
    //http://www.networkworld.com/community/node/18007
    //data type: OVS_PI_MPLS, see FlowKey.h
    OVS_ARGTYPE_PI_MPLS,                    //0x051

    //Encapsulation Group = another set of packet info-s, for the encapsulation. contains: eth type, ip layer PI, transport layer PI
    //might have been an older version of "tunnel info". The encapsulation group does not appear to be used in latest versions of ovs
    OVS_ARGTYPE_PI_ENCAP_GROUP,             //0x52

    //received from userspace
    OVS_ARGTYPE_PI_TUNNEL_GROUP,            //0x53
    OVS_ARGTYPE_LAST_PI = OVS_ARGTYPE_PI_TUNNEL_GROUP,

    /******************************************* TARGET: FLOW: group = KEY / TUNNEL (FROM USERSPACE ONLY!) **********************************************/

    //GROUP NOTE: this group represents the OVS_USPACE_TUNNEL_KEY_ATTRIBUTE

    //data type: BE64
    OVS_ARGTYPE_PI_TUNNEL_ID = 0x061,

    OVS_ARGTYPE_FIRST_PI_TUNNEL = OVS_ARGTYPE_PI_TUNNEL_ID,

    //data type: BE32
    OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC,        //0x062

    //data type: BE32
    OVS_ARGTYPE_PI_TUNNEL_IPV4_DST,        //0x063

    //data type: UINT8
    OVS_ARGTYPE_PI_TUNNEL_TOS,                //0x064

    //data type: UINT8
    OVS_ARGTYPE_PI_TUNNEL_TTL,                //0x065

    //data type: no data (it's a flag)
    OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT,    //0x066

    //data type: no data (it's a flag)
    OVS_ARGTYPE_PI_TUNNEL_CHECKSUM,        //0x067

    OVS_ARGTYPE_LAST_PI_TUNNEL = OVS_ARGTYPE_PI_TUNNEL_CHECKSUM,

    /************************************* TARGET: PACKET; GROUP: MAIN *****************************************************/

    //GROUP NOTE: This group represents OVS_USPACE_PACKET_ATTRIBUTE
    OVS_ARGTYPE_PACKET_PI_GROUP = 0x81,

    OVS_ARGTYPE_FIRST_PACKET = OVS_ARGTYPE_PACKET_PI_GROUP,

    //Packet notifications (queue to userspace). It is the NET_BUFFER data.
    //data type: "void*", i.e. data opaque to the user
    OVS_ARGTYPE_PACKET_BUFFER,                      //0x82

    //actions to apply to packets being executed
    OVS_ARGTYPE_PACKET_ACTIONS_GROUP,        //0x83

    //data type: OVS_ARGUMENT; it is set from userspace only.
    OVS_ARGTYPE_PACKET_USERDATA,            //0x084

    OVS_ARGTYPE_LAST_PACKET = OVS_ARGTYPE_PACKET_USERDATA,

    /************************************ TARGET: FLOW / PACKET; group = ACTIONS **********************************************/

    //GROUP NOTE: this group represents OVS_USPACE_PACKET_ATTRIBUTE_ACTIONS and OVS_USPACE_FLOW_ATTRIBUTE_ACTIONS

    //ovs port number to which to send the packet to (no hyper-v switch port id)
    //data type: UINT32 (however, it is used as UINT16)
    OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT = 0x0A1,
    OVS_ARGTYPE_FIRST_ACTION = OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT,

    OVS_ARGTYPE_ACTION_UPCALL_GROUP,         //0x0A2

    //contains packet info args to set
    OVS_ARGTYPE_ACTION_SETINFO_GROUP,        //0x0A3

    //Insert Vlan header into the packet
    //data type: OVS_ACTION_PUSH_VLAN
    OVS_ARGTYPE_ACTION_PUSH_VLAN,            //0x0A4

    //Remove the Vlan header from the packet.
    //TODO: it might be possible for a packet to be wrapped into multiple Vlan headers
    //data type: no data
    OVS_ARGTYPE_ACTION_POP_VLAN,            //0x0A5

    OVS_ARGTYPE_ACTION_SAMPLE_GROUP,        //0x0A6

    //TODO: NOT IMPLEMENTED!
    OVS_ARGTYPE_ACTION_PUSH_MPLS,            //0x0A7

    //TODO: NOT IMPLEMENTED!
    OVS_ARGTYPE_ACTION_POP_MPLS,            //0x0A8

    OVS_ARGTYPE_LAST_ACTION = OVS_ARGTYPE_ACTION_POP_MPLS,

    /************************************ TARGET: FLOW / PACKET; group = ACTIONS / UPCALL **********************************************/

    //GROUP NOTE: this group represents OVS_USPACE_UPCALL_ATTRIBUTE

    //Port Id associated with the file HANDLE
    //data type: UINT32
    OVS_ARGTYPE_ACTION_UPCALL_PORT_ID = 0x0C1,
    OVS_ARGTYPE_FIRST_ACTION_UPCALL = OVS_ARGTYPE_ACTION_UPCALL_PORT_ID,

    //Sent from userspace (optionally). It comes as Action / Output to Userspace
    //data type: OVS_ARGUMENT
    OVS_ARGTYPE_ACTION_UPCALL_DATA,            //0x0C2

    OVS_ARGTYPE_LAST_ACTION_UPCALL = OVS_ARGTYPE_ACTION_UPCALL_DATA,

    /************************************ TARGET: FLOW / PACKET; group: ACTIONS / SAMPLE **********************************************/

    //GROUP NOTE: this group represents OVS_USPACE_SAMPLE_ATTRIBUTE

    //The fraction of packets to sample (i.e. execute actions upon). Values:
    //    a) 0            = do not sample
    //    b) MAXUINT32    = sample all packets
    //    c) other value

    //data type: UINT32
    OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY = 0x0E1,
    OVS_ARGTYPE_FIRST_ACTION_SAMPLE = OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY,

    //actions to apply to packets (being executed / matched by flow) in a sample action
    OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP,        //0x0E2

    OVS_ARGTYPE_LAST_ACTION_SAMPLE = OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP,

    /******************************************** TARGET: DATAPATH; group: MAIN *********************************************/

    //Datapath request: required in Datapath_New
    //Datapath reply: always present
    //data type: null-terminated ASCII string
    OVS_ARGTYPE_DATAPATH_NAME = 0x101,
    OVS_ARGTYPE_FIRST_DATAPATH = OVS_ARGTYPE_DATAPATH_NAME,

    //The userspace port id associated with the file HANDLE, by which upcalls should be read from userspace
    //Datapath request: required in Datapath_New
    //if (Datapath port Id == 0) => do not queue upcall message.
    //data type: UINT32
    OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID,    //0x102

    //Datapath request: never
    //Datapath reply: always
    //data type: OVS_DATAPATH_STATS
    OVS_ARGTYPE_DATAPATH_STATS,                //0x103

    OVS_ARGTYPE_LAST_DATAPATH = OVS_ARGTYPE_DATAPATH_STATS,

    /****************************************** TARGET: OFPORT; group: MAIN ************************************************/

    //ovs port number (not hyper-v switch port id)
    //data type: UINT32. It is used in code as UINT16
    OVS_ARGTYPE_OFPORT_NUMBER = 0x121,
    OVS_ARGTYPE_FIRST_OFPORT = OVS_ARGTYPE_OFPORT_NUMBER,

    //data type: UINT32; values: constants of enum OVS_OFPORT_TYPE
    OVS_ARGTYPE_OFPORT_TYPE,                //0x122

    //data type: null-terminated ASCII string. max size should be 17.
    OVS_ARGTYPE_OFPORT_NAME,                //0x123

    OVS_ARGTYPE_OFPORT_OPTIONS_GROUP,       //0x124

    //The Port Id associated with the file HANDLE that handles the upcalls coming from this ovs port.
    //if (portId == 0) => do not queue upcall
    //data type: UINT32
    OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID,        //0x125

    //data type: OVS_OFPORT_STATS
    OVS_ARGTYPE_OFPORT_STATS,                //0x126

    OVS_ARGTYPE_LAST_OFPORT = OVS_ARGTYPE_OFPORT_STATS,

    /************************************ TARGET: FLOW / PACKET; GROUP: PORT / OPTIONS **********************************************/

    //UINT16
    OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT = 0x141,
    OVS_ARGTYPE_FIRST_OFPORT_OPTION = OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT,

    OVS_ARGTYPE_LAST_OFPORT_OPTION = OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT,
} OVS_ARGTYPE;

static __inline BOOLEAN IsArgTypeGroup(OVS_ARGTYPE argType)
{
    //invalid is 0x20; all non-group args are > 0x21; all groups are < 0x20
    return (argType < OVS_ARGTYPE_INVALID);
}

//given an arg type, returns the index of the arg within its group, starting from 1
#define OVS_ARG_TOINDEX(argType, group) (argType - OVS_ARGTYPE_FIRST_##group + 1)