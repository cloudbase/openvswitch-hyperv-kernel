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
#include "Ipv4.h"

//ICMP codes for neighbour discovery messages
#define OVS_NDISC_ROUTER_SOLICITATION       133
#define OVS_NDISC_ROUTER_ADVERTISEMENT      134
#define OVS_NDISC_NEIGHBOUR_SOLICITATION    135
#define OVS_NDISC_NEIGHBOUR_ADVERTISEMENT   136
#define OVS_NDISC_REDIRECT                  137

//rtt = round-trip time
//This is ICMPv4 [RFC0792]; see ICMPv6 in RFC4443

typedef struct _OVS_ICMP_HEADER {
    UINT8 type;         // Type of message (high bit zero for error messages).
    UINT8 code;         // Type-specific differentiater.
    UINT16 checksum;    // Calculated over ICMP message and IPvx pseudo-header.
    //contents depended on type & code
}OVS_ICMP_HEADER, *POVS_ICMP_HEADER;

typedef struct _OVS_ICMP_MESSAGE_DEST_UNREACH {
    OVS_ICMP_HEADER header;
    UINT8 unused;
    //length of the padded "original datagram" field, measured in 32-bit words.
    UINT8 length;
    UINT16 nextHopMtu;

    OVS_IPV4_HEADER ipv4Header;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_DEST_UNREACH, *POVS_ICMP_MESSAGE_DEST_UNREACH;

#define OVS_ICMP_MESSAGE_DEST_UNREACH_SIZE_BARE        8
C_ASSERT(sizeof(OVS_ICMP_MESSAGE_DEST_UNREACH) == 28);

typedef struct _OVS_ICMP_MESSAGE_TIME_EXCEEDED {
    OVS_ICMP_HEADER header;
    UINT8 unused0;
    //length of the padded "original datagram" field, measured in 32-bit words.
    UINT8 length;
    UINT16 unused1;

    OVS_IPV4_HEADER ipv4Header;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_TIME_EXCEEDED, *POVS_ICMP_MESSAGE_TIME_EXCEEDED;

typedef struct _OVS_ICMP_MESSAGE_PARAM_PROBLEM {
    OVS_ICMP_HEADER header;
    //If code = 0, identifies the octet where an error was detected.
    UINT8 pointer;
    //length of the padded "original datagram" field, measured in 32-bit words.
    UINT8 length;
    UINT16 unused;

    OVS_IPV4_HEADER ipv4Header;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_PARAM_PROBLEM, *POVS_ICMP_MESSAGE_PARAM_PROBLEM;

typedef struct _OVS_ICMP_MESSAGE_REDIRECT {
    OVS_ICMP_HEADER header;

    //Address of the gateway to which traffic for the network specified in the internet destination network field of the original
    //datagram's data should be sent.
    BYTE gatewayIp[4];

    OVS_IPV4_HEADER ipv4Header;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_REDIRECT, *POVS_ICMP_MESSAGE_REDIRECT;

typedef struct _OVS_ICMP_MESSAGE_ECHO {
    OVS_ICMP_HEADER header;

    UINT16 identifier;
    UINT16 sequenceNumber;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_ECHO, *POVS_ICMP_MESSAGE_ECHO;

typedef struct _OVS_ICMP_MESSAGE_TIMESTAMP {
    OVS_ICMP_HEADER header;

    UINT16 identifier;
    UINT16 sequenceNumber;

    //The timestamp is 32 bits of milliseconds since midnight UT
    UINT32 originateTimestamp;
    UINT32 receiveTimestamp;
    UINT32 transmitTimestamp;

    //followed by 8 bytes of original datagram
}OVS_ICMP_MESSAGE_TIMESTAMP, *POVS_ICMP_MESSAGE_TIMESTAMP;

const char* ReadIcmp(_In_ OVS_ICMP_HEADER* pIcmpHeader);

//buffer: net buffer starting with the icmp header
//dbg prints icmp4 header by calling ReadIcmp
void DbgPrintIcmpHeader(_In_ const VOID* buffer);

BOOLEAN VerifyIcmpHeader(_In_ const BYTE* buffer, _Inout_ ULONG* pLength);