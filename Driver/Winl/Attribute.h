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

/***** datapath *****/
#define OVS_USPACE_DP_ATTRIBUTE_UNSPEC        0
#define OVS_USPACE_DP_ATTRIBUTE_NAME          1
#define OVS_USPACE_DP_ATTRIBUTE_UPCALL_PID    2
#define OVS_USPACE_DP_ATTRIBUTE_STATS         3
#define OVS_USPACE_DP_ATTRIBUTE_MEGAFLOW_STATS    4
#define OVS_USPACE_DP_ATTRIBUTE_USER_FEATURES    5

#define OVS_USPACE_DP_ATTRIBUTE_MAX         OVS_USPACE_DP_ATTRIBUTE_USER_FEATURES

/***** vport *****/
#define OVS_USPACE_VPORT_ATTRIBUTE_UNSPEC     0
#define OVS_USPACE_VPORT_ATTRIBUTE_PORT_NO    1
#define OVS_USPACE_VPORT_ATTRIBUTE_TYPE       2
#define OVS_USPACE_VPORT_ATTRIBUTE_NAME       3
#define OVS_USPACE_VPORT_ATTRIBUTE_OPTIONS    4
#define OVS_USPACE_VPORT_ATTRIBUTE_UPCALL_PID 5
#define OVS_USPACE_VPORT_ATTRIBUTE_STATS      6

#define OVS_USPACE_VPORT_ATTRIBUTE_MAX        OVS_USPACE_VPORT_ATTRIBUTE_STATS

/***** vport / options *****/
#define OVS_USPACE_TUNNEL_ATTRIBUTE_UNSPEC    0
#define OVS_USPACE_TUNNEL_ATTRIBUTE_DST_PORT  1

#define OVS_USPACE_TUNNEL_ATTRIBUTE_MAX      OVS_USPACE_TUNNEL_ATTRIBUTE_DST_PORT

/***** packet *****/
#define OVS_USPACE_PACKET_ATTRIBUTE_UNSPEC    0
#define OVS_USPACE_PACKET_ATTRIBUTE_PACKET    1
#define OVS_USPACE_PACKET_ATTRIBUTE_KEY       2
#define OVS_USPACE_PACKET_ATTRIBUTE_ACTIONS   3
#define OVS_USPACE_PACKET_ATTRIBUTE_USERDATA  4

#define OVS_USPACE_PACKET_ATTRIBUTE_MAX       OVS_USPACE_PACKET_ATTRIBUTE_USERDATA

/***** flow *****/
#define OVS_USPACE_FLOW_ATTRIBUTE_UNSPEC      0
#define OVS_USPACE_FLOW_ATTRIBUTE_KEY         1
#define OVS_USPACE_FLOW_ATTRIBUTE_ACTIONS     2
#define OVS_USPACE_FLOW_ATTRIBUTE_STATS       3
#define OVS_USPACE_FLOW_ATTRIBUTE_TCP_FLAGS   4
#define OVS_USPACE_FLOW_ATTRIBUTE_USED        5
#define OVS_USPACE_FLOW_ATTRIBUTE_CLEAR       6
#define OVS_USPACE_FLOW_ATTRIBUTE_MASK        7

#define OVS_USPACE_FLOW_ATTRIBUTE_MAX         OVS_USPACE_FLOW_ATTRIBUTE_MASK

/***** flow / key ****/
#define OVS_USPACE_KEY_ATTRIBUTE_UNSPEC       0
#define OVS_USPACE_KEY_ATTRIBUTE_ENCAP        1
#define OVS_USPACE_KEY_ATTRIBUTE_PRIORITY     2
#define OVS_USPACE_KEY_ATTRIBUTE_IN_PORT      3
#define OVS_USPACE_KEY_ATTRIBUTE_ETHERNET     4
#define OVS_USPACE_KEY_ATTRIBUTE_VLAN         5
#define OVS_USPACE_KEY_ATTRIBUTE_ETHERTYPE    6
#define OVS_USPACE_KEY_ATTRIBUTE_IPV4         7
#define OVS_USPACE_KEY_ATTRIBUTE_IPV6         8
#define OVS_USPACE_KEY_ATTRIBUTE_TCP          9
#define OVS_USPACE_KEY_ATTRIBUTE_UDP          10
#define OVS_USPACE_KEY_ATTRIBUTE_ICMP         11
#define OVS_USPACE_KEY_ATTRIBUTE_ICMPV6       12
#define OVS_USPACE_KEY_ATTRIBUTE_ARP          13
#define OVS_USPACE_KEY_ATTRIBUTE_ND           14
#define OVS_USPACE_KEY_ATTRIBUTE_SKB_MARK     15
#define OVS_USPACE_KEY_ATTRIBUTE_TUNNEL       16
#define OVS_USPACE_KEY_ATTRIBUTE_SCTP         17
#define OVS_USPACE_KEY_ATTRIBUTE_TCP_FLAGS    18
#define OVS_USPACE_KEY_ATTRIBUTE_DP_HASH      19
#define OVS_USPACE_KEY_ATTRIBUTE_RECIRC_ID    20
#define OVS_USPACE_KEY_ATTRIBUTE_MPLS         62

#define OVS_USPACE_KEY_ATTRIBUTE_MAX          OVS_USPACE_KEY_ATTRIBUTE_MPLS

/***** flow / key / tunnel *****/
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_ID              0
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_SRC        1
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_DST        2
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TOS             3
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TTL             4
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_DONT_FRAGMENT   5
#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_CSUM            6

#define OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_MAX             OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_CSUM

/***** actions ****/
#define OVS_USPACE_ACTION_ATTRIBUTE_UNSPEC        0
#define OVS_USPACE_ACTION_ATTRIBUTE_OUTPUT        1
#define OVS_USPACE_ACTION_ATTRIBUTE_USERSPACE     2
#define OVS_USPACE_ACTION_ATTRIBUTE_SET           3
#define OVS_USPACE_ACTION_ATTRIBUTE_PUSH_VLAN     4
#define OVS_USPACE_ACTION_ATTRIBUTE_POP_VLAN      5
#define OVS_USPACE_ACTION_ATTRIBUTE_SAMPLE        6
#define OVS_USPACE_ACTION_ATTRIBUTE_PUSH_MPLS      7
#define OVS_USPACE_ACTION_ATTRIBUTE_POP_MPLS      8
#define OVS_USPACE_ACTION_ATTRIBUTE_RECIRC          9
#define OVS_USPACE_ACTION_ATTRIBUTE_HASH          10

#define OVS_USPACE_ACTION_ATTRIBUTE_MAX           OVS_USPACE_ACTION_ATTRIBUTE_HASH

/***** actions / sample ****/
#define OVS_USPACE_SAMPLE_ATTRIBUTE_UNSPEC         0
#define OVS_USPACE_SAMPLE_ATTRIBUTE_PROBABILITY    1
#define OVS_USPACE_SAMPLE_ATTRIBUTE_ACTIONS        3

#define OVS_USPACE_SAMPLE_ATTRIBUTE_MAX            OVS_USPACE_SAMPLE_ATTRIBUTE_ACTIONS

/***** actions / userspace *****/
#define OVS_USPACE_UPCALL_ATTRIBUTE_UNSPEC         0
#define OVS_USPACE_UPCALL_ATTRIBUTE_PID            1
#define OVS_USPACE_UPCALL_ATTRIBUTE_USERDATA       2

#define OVS_USPACE_UPCALL_ATTRIBUTE_MAX            OVS_USPACE_UPCALL_ATTRIBUTE_USERDATA