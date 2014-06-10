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

#include "precomp.h"

typedef struct _OVS_TUNNELING_PORT_OPTIONS OVS_TUNNELING_PORT_OPTIONS;

//http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-00 (and 06)
/*FRAMES:
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

Outer Ethernet Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Outer Destination MAC Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Outer Destination MAC Address | Outer Source MAC Address      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Outer Source MAC Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|OptnlEthtype = C-Tag 802.1Q    | Outer.VLAN Tag Information    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethertype = 0x0800            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Outer IPv4 Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |Protocl=17(UDP)|   Header Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Outer Source IPv4 Address               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Outer Destination IPv4 Address              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Outer UDP Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Source Port = xxxx      |       Dest Port = VXLAN Port  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           UDP Length          |        UDP Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

VXLAN Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|R|R|R|I|R|R|R|            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                VXLAN Network Identifier (VNI) |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Inner Ethernet Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Inner Destination MAC Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Inner Destination MAC Address | Inner Source MAC Address      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Inner Source MAC Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|OptnlEthtype = C-Tag 802.1Q    | Inner.VLAN Tag Information    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Payload:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethertype of Original Payload |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                                  Original Ethernet Payload    |
|                                                               |
|(Note that the original Ethernet Frame's FCS is not included)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Frame Check Sequence:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   New FCS (Frame Check Sequence) for Outer Ethernet Frame     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 1 VXLAN Frame Format with IPv4 Outer Header
*/

/*
O Outer UDP Header:  This is the outer UDP header with a source
port provided by the VTEP and the destination port being a well-
known UDP port.  IANA has assigned the value 4789 for the VXLAN UDP
port and this value SHOULD be used by default as the destination UDP
port.  Some early implementations of VXLAN have used other values
for the destination port.  To enable interoperability with these
implementations, the destination port SHOULD be configurable.  It is
recommended that the source port number be calculated using a hash
of fields from the inner packet - one example being a hash of the
inner Ethernet frame`s headers. This is to enable a level of entropy
for ECMP/load balancing of the VM to VM traffic across the VXLAN
overlay.

The UDP checksum field SHOULD be transmitted as zero.  When a packet
is received with a UDP checksum of zero, it MUST be accepted for
decapsulation.  Optionally, if the encapsulating endpoint includes a
non-zero UDP checksum, it MUST be correctly calculated across the
entire packet including the IP header, UDP header, VXLAN header and
encapsulated MAC frame.  When a decapsulating endpoint receives a
packet with a non-zero checksum it MAY choose to verify the checksum
value.  If it chooses to perform such verification, and the
verification fails, the packet MUST be dropped.  If the
decapsulating destination chooses not to perform the verification,
or performs it successfully, the packet MUST be accepted for
decapsulation.

O Outer IP Header:  This is the outer IP header with the source IP
address indicating the IP address of the VTEP over which the
communicating VM (as represented by the inner source MAC address) is
running.  The destination IP address can be a unicast or multicast
IP address (see Sections 4.1 and 4.2). When it is a unicast IP
address, it represents the IP address of the VTEP connecting the
communicating VM as represented by the inner destination MAC
address. For multicast destination IP addresses, please refer to the
scenarios detailed in Section 4.2.

O Outer Ethernet Header (example):  Figure 1 is an example of an
inner Ethernet frame encapsulated within an outer Ethernet + IP +
UDP + VXLAN header. The outer destination MAC address in this frame
may be the address of the target VTEP or of an intermediate Layer 3
router. The outer VLAN tag is optional. If present, it may be used
for delineating VXLAN traffic on the LAN.
*/

/*
Consider Figure 4 for the following discussion. For incoming frames
on the VXLAN connected interface, the gateway strips out the VXLAN
header and forwards to a physical port based on the destination MAC
address of the inner Ethernet frame. Decapsulated frames with the
inner VLAN ID SHOULD be discarded unless configured explicitly to be
passed on to the non-VXLAN interface. In the reverse direction,
incoming frames for the non-VXLAN interfaces are mapped to a
specific VXLAN overlay network based on the VLAN ID in the frame.
Unless configured explicitly to be passed on in the encapsulated
VXLAN frame, this VLAN ID is removed before the frame is
encapsulated for VXLAN.

These gateways which provide VXLAN tunnel termination functions
could be ToR/access switches or switches higher up in the data
center network topology -  e.g. core or even WAN edge devices. The
last case (WAN edge) could involve a Provider Edge (PE) router which
terminates VXLAN tunnels in a hybrid cloud environment. Note that in
all these instances, the gateway functionality could be implemented
in software or hardware.

+---+-----+---+                                    +---+-----+---+
|    Server 1 |                                    |  Non VXLAN  |
(VXLAN enabled)<-----+                       +---->|  server     |
+-------------+      |                       |     +-------------+
|                       |
+---+-----+---+      |                       |     +---+-----+---+
|Server 2     |      |                       |     |  Non VXLAN  |
(VXLAN enabled)<-----+   +---+-----+---+     +---->|    server   |
+-------------+      |   |Switch acting|     |     +-------------+
|---|  as VXLAN   |-----|
+---+-----+---+      |   |   Gateway   |
| Server 3    |      |   +-------------+
(VXLAN enabled)<-----+
+-------------+      |
|
+---+-----+---+      |
| Server 4    |      |
(VXLAN enabled)<-----+
+-------------+
Figure 4   VXLAN Deployment - VXLAN Gateway
*/

/*
6.1. Inner VLAN Tag Handling

Inner VLAN Tag Handling in VTEP and VXLAN Gateway should conform to
the following:

Decapsulated VXLAN frames with the inner VLAN tag SHOULD be
discarded unless configured otherwise.  On the encapsulation side, a
VTEP SHOULD NOT include an inner VLAN tag on tunnel packets unless
configured otherwise.  When a VLAN-tagged packet is a candidate for
VXLAN tunneling, the encapsulating VTEP SHOULD strip the VLAN tag
unless configured otherwise.
*/

typedef struct _OVS_VXLAN_HEADER {
    //|R|R|R|R|I|R|R|R|  -- the bit I must be 1, the rest must be 0, i.e. flags & 0x8 == 1
    BYTE flags;
    //reserved 24 bits
    BYTE reserved0[3];
    //VXLAN network id / segment id.
    BYTE vni[3];
    //reserved 8 bits
    BYTE reserved1;
}OVS_VXLAN_HEADER, *POVS_VXLAN_HEADER;

//http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-03

/*
Use of VXLAN with IPv6 transport is detailed below.  (updated by 06)

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

Outer Ethernet Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Outer Destination MAC Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Outer Destination MAC Address | Outer Source MAC Address      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Outer Source MAC Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|OptnlEthtype = C-Tag 802.1Q    | Outer.VLAN Tag Information    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethertype = 0x86DD            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Outer IPv6 Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        | NxtHdr=17(UDP)|   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                     Outer Source IPv6 Address                 +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                  Outer Destination IPv6 Address               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Outer UDP Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Source Port = xxxx      |       Dest Port = VXLAN Port  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           UDP Length          |        UDP Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

VXLAN Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|R|R|R|I|R|R|R|            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                VXLAN Network Identifier (VNI) |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Inner Ethernet Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Inner Destination MAC Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Inner Destination MAC Address | Inner Source MAC Address      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Inner Source MAC Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|OptnlEthtype = C-Tag 802.1Q    | Inner.VLAN Tag Information    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Payload:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethertype of Original Payload |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                                  Original Ethernet Payload    |
|                                                               |
|(Note that the original Ethernet Frame's FCS is not included)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Frame Check Sequence:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   New FCS (Frame Check Sequence) for Outer Ethernet Frame     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 2 VXLAN Frame Format with IPv6 Outer Header
*/

//http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-04
/*
IANA has assigned the value 4789 for the VXLAN UDP
port and this value SHOULD be used by default as the destination UDP
port.
*/

//from: http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-04
//(but also existed in prev versions)
/*
Consider the VM on the source host attempting to communicate with
the destination VM using IP.  Assuming that they are both on the
same subnet, the VM sends out an ARP broadcast frame. In the non-
VXLAN environment, this frame would be sent out using MAC broadcast
across all switches carrying that VLAN.

With VXLAN, a header including the VXLAN VNI is inserted at the
beginning of the packet along with the IP header and UDP header.
However, this broadcast packet is sent out to the IP multicast group
on which that VXLAN overlay network is realized.

To effect this, we need to have a mapping between the VXLAN VNI and
the IP multicast group that it will use. This mapping is done at the
management layer and provided to the individual VTEPs through a
management channel. Using this mapping, the VTEP can provide IGMP
membership reports to the upstream switch/router to join/leave the
VXLAN related IP multicast groups as needed. This will enable
pruning of the leaf nodes for specific multicast traffic addresses
based on whether a member is available on this host using the
specific multicast address (see [RFC4541]).
*/

/*
* UDP port for VXLAN traffic.
* The IANA assigned port is 4789, but the Linux default is 8472
* for compatibility with early adopters.
*/
//TODO: the vxlan udp port must be made configurable
enum { OVS_VXLAN_UDP_PORT_DEFAULT = 8472 /*4789*/ };

//encapsulation size in bytes required by Vxlan (i.e. vxlan + ipv4 + ethernet + udp headers)
ULONG Vxlan_BytesNeeded(UINT16 tunnelFlags);
VOID* Vxlan_BuildHeader(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _In_ const OVS_TUNNELING_PORT_OPTIONS* pOptions,
    ULONG payloadLength, ULONG vxlanHeaderSize, _Out_ BOOLEAN* pHaveChecksum);

BOOLEAN Vxlan_ReadHeader(_In_ const VOID* pDecapHeader, _Inout_ ULONG* pOffset, ULONG outerIpPayloadLen, _Inout_ OF_PI_IPV4_TUNNEL* pTunnelInfo);
