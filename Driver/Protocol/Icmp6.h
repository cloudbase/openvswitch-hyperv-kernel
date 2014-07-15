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
#include "Icmp.h"
#include "Ipv6.h"
#include "Ethernet.h"

enum
{
    OVS_ICMP6_ND_NEIGHBOR_SOLICITATION = 135,
    OVS_ICMP6_ND_NEIGHBOR_ADVERTISMENT = 136
};

//NEIGHBOR SOLICITATION
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+ -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
| Type         | Code          | Checksum                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reserved                                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Target Address                                             |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Options ...                                                   |
+ -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/

typedef struct _OVS_ICMP6_NEIGHBOR_SOLICITATION
{
    BYTE          type;
    BYTE          code;
    UINT16        checksum;
    UINT32        reserved;
    //The IP address of the target of the solicitation. It MUST NOT be a multicast address.
    IN6_ADDR      targetIp;

    /*
    OPTIONS
    Possible options:

    Source link-layer address
    The link-layer address for the sender.  MUST NOT be
    included when the source IP address is the
    unspecified address.  Otherwise, on link layers
    that have addresses this option MUST be included in
    multicast solicitations and SHOULD be included in
    unicast solicitations.
    */
}OVS_ICMP6_NEIGHBOR_SOLICITATION;

C_ASSERT(sizeof(OVS_ICMP6_NEIGHBOR_SOLICITATION) == 24);

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type        | Code          | Checksum                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|S|O| Reserved                                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Target Address                         +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Options ...                                                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct _OVS_ICMP6_NEIGHBOR_ADVERTISMENT
{
    BYTE        type;
    BYTE        code;
    UINT16      checksum;

    //1st bit of reserved: Router flag;
    //2nd bit of reserved: Solicited flag;
    //3rd bit of reserved: Override flag;
    //29 bits are reserved
    UINT32      reserved;
    //The IP address of the target of the solicitation. It MUST NOT be a multicast address.
    IN6_ADDR    targetIp;

    /*
    OPTIONS
    Possible options:

    Target link-layer address
    The link-layer address for the target, i.e., the sender of the advertisement.
    This option MUST be included on link layers that have addresses when responding to multicast solicitations.
    When responding to a unicast Neighbor Solicitation this option SHOULD be included.
    */
}OVS_ICMP6_NEIGHBOR_ADVERTISMENT;

C_ASSERT(sizeof(OVS_ICMP6_NEIGHBOR_SOLICITATION) == 24);

/***********************************************************/

/*

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             MTU                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    As much of invoking packet                 |
+               as possible without the ICMPv6 packet           +
|               exceeding the minimum IPv6 MTU [IPv6]           |

minimum Ipv6 MTU: 1280 (RFC2460)
*/
typedef struct _OVS_ICMP6_PACKET_TOO_BIG
{
    BYTE          type;
    BYTE          code;
    UINT16        checksum;

    UINT32        mtu;
    OVS_IPV6_HEADER    ipv6Header;
}OVS_ICMP6_PACKET_TOO_BIG;

C_ASSERT(sizeof(OVS_ICMP6_PACKET_TOO_BIG) == 48);

#define OVS_ICMP6_PACKET_TOO_BIG_SIZE_BARE 8

/***********************************************************/

typedef enum
{
    OVS_ICMP6_ND_OPTION_SOURCE_LINK_ADDRESS = 1,
    OVS_ICMP6_ND_OPTION_TARGET_LINK_ADDRESS = 2
} OVS_ICMP6_ND_OPTION_TYPE;

typedef struct _OVS_ICMP6_ND_OPTION
{
    BYTE type;
    BYTE length;
}OVS_ICMP6_ND_OPTION, *POVS_ICMP6_ND_OPTION;

C_ASSERT(sizeof(OVS_ICMP6_ND_OPTION) == 2);

typedef struct _OVS_ICMP6_ND_OPTION_LINK_ADDRESS
{
    //1 for Source Link-layer Address
    //2 for Target Link - layer Address
    BYTE type;

    //The length of the option (including the type and length fields) in units of 8 octets.
    //For example, the length for IEEE 802 addresses is 1
    BYTE length;

    BYTE macAddress[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_ICMP6_ND_OPTION_LINK_ADDRESS, *POVS_ICMP6_ND_OPTION_LINK_ADDRESS;

C_ASSERT(sizeof(OVS_ICMP6_ND_OPTION) == 2);

/*********************************************************/

const char* ReadIcmp6(_In_ OVS_ICMP_HEADER* pIcmpHeader);

//buffer - net buffer starting with the icmp6 protocol
//dbg prints icmp6 frame by calling ReadIcmp6
void ReadIcmp6Header(VOID* buffer);

BOOLEAN VerifyIcmp6Header(BYTE* buffer, ULONG* pLength);