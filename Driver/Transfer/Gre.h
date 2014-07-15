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

#include "Frame.h"
#include "OFFlow.h"

/*http://tools.ietf.org/html/rfc1701
http://tools.ietf.org/html/rfc1702
http://tools.ietf.org/html/rfc2784*/

typedef struct _OVS_TUNNELING_PORT_OPTIONS OVS_TUNNELING_PORT_OPTIONS;

/*In RFC 1701, the field described here as Reserved0 contained a number
   of flag bits which this specification deprecates. In particular, the
   Routing Present, Key Present, Sequence Number Present, and Strict
   Source Route bits have been deprecated, along with the Recursion
   Control field. As a result, the GRE header will never contain the
   Key, Sequence Number or Routing fields specified in RFC 1701.
   */

//NOTE: deprecated; use 2784 for send, but receive 1701 as well, for interoperability.
typedef struct _OVS_GRE_HEADER_1701
{
    struct
    {
        //the number of additional encapsulations which are permissible.  This SHOULD default to zero.
        UINT8 recursionControl : 3;
        //Should be set to 1 if all of the the Routing Information consists of Strict Source Routes.
        UINT8 strictSourceRoute : 1;
        //if set => sequenceNumber is present.
        UINT8 haveSeqNumber : 1;
        //if set => key is present.
        UINT8 haveKey : 1;
        //if set => both routing and offset and checksum fields are present
        UINT8 haveRouting : 1;
        //if set => both checksum and offset fields are present
        UINT8 haveChecksum : 1;
    };

    struct
    {
        //MUST contain the value 0
        UINT8 versionNumber : 3;

        UINT8 flags : 5;
    };

    //contains the protocol type of the payload packet.
    //In general, the value will be the Ethernet protocol type field for the packet.
    UINT16 protocolType;
}OVS_GRE_HEADER_1701, *POVS_GRE_HEADER_1701;

typedef UINT16 OVS_GRE1701_HEADER_OPT_OFFSET;
typedef UINT16 OVS_GRE1701_HEADER_OPT_CHECKSUM;
typedef UINT32 OVS_GRE1701_HEADER_OPT_KEY;
typedef UINT32 OVS_GRE1701_HEADER_OPT_SEQNUMBER;

//OPTIONAL GRE FIELDS:
/*
Offset (2 octets)

The offset field indicates the octet offset from the start of the
Routing field to the first octet of the active Source Route Entry
to be examined.  This field is present if the Routing Present or
the Checksum Present bit is set to 1, and contains valid
information only if the Routing Present bit is set to 1.

Checksum (2 octets)

The Checksum field contains the IP (one's complement) checksum of
the GRE header and the payload packet.  This field is present if
the Routing Present or the Checksum Present bit is set to 1, and
contains valid information only if the Checksum Present bit is set
to 1.

Key (4 octets)

The Key field contains a four octet number which was inserted by
the encapsulator.  It may be used by the receiver to authenticate
the source of the packet.  The techniques for determining
authenticity are outside of the scope of this document.  The Key
field is only present if the Key Present field is set to 1.

Sequence Number (4 octets)

The Sequence Number field contains an unsigned 32 bit integer
which is inserted by the encapsulator.  It may be used by the
receiver to establish the order in which packets have been
transmitted from the encapsulator to the receiver.  The exact
algorithms for the generation of the Sequence Number and the
semantics of their reception is outside of the scope of this
document.

Routing (variable)

The Routing field is optional and is present only if the Routing
Present bit is set to 1.

The Routing field is a list of Source Route Entries (SREs).
The routing field is terminated with a "NULL" SRE containing an
address family of type 0x0000 and a length of 0.
*/

C_ASSERT(sizeof(OVS_GRE_HEADER_1701) == 4);

typedef struct _OVS_GRE_SOURCE_ROUTE_ENTRY
{
    //the syntax and semantics of the Routing Information field
    //for payload protocol = ipv4: value = 0x800
    /*
    For the Address Family value of 0x800, the Routing Information field
    will consist of a list of IP addresses and indicates an IP source
    route.  The first octet of the Routing Information field constitute a
    8 bit integer offset from the start of the Source Route Entry (SRE),
    called the SRE Offset.  The SRE Offset indicates the first octet of
    the next IP address.  The SRE Length field consists of the total
    length of the IP Address List in octets.
    */
    /*we don't bother with address family = 0xfffe =  Autonomous System numbers*/
    UINT16 addressFamily;
    //the octet offset from the start of the Routing Information field to the first octet of the active entry
    UINT8 offset;
    //the number of octets in the SRE. If the SRE Length is 0, this indicates this is the last SRE in the Routing field.
    UINT8 length;
    /*
    Routing Information (variable)

    The Routing Information field contains data which may be used in
    routing this packet.  The exact semantics of this field is defined in
    other documents.
    */
}OVS_GRE_SOURCE_ROUTE_ENTRY, *POVS_GRE_SOURCE_ROUTE_ENTRY;

C_ASSERT(sizeof(OVS_GRE_SOURCE_ROUTE_ENTRY) == 4);

/**********************************************************/

typedef struct _OVS_GRE_HEADER_2784
{
    struct
    {
        /*A receiver MUST discard a packet where any of bits 1-5 are non-zero,
        unless that receiver implements RFC 1701.*/
        UINT8 reserved0_b6_7 : 2; //bits 6->7
        UINT8 reserved0_b1_5 : 5; //bits 1->5

        //if set => both checksum and offset fields are present
        /*If the Checksum Present bit is set to one, then the Checksum and the
        reserved fields are present and the Checksum field contains valid
        information.*/
        UINT8 haveChecksum : 1; // bit 0

        //MUST contain the value zero.
        UINT8 versionNumber : 3;        // bits 13-15

        /*Bits 6-12 are reserved for future use.
        These bits MUST be sent as zero and MUST be ignored on receipt*/
        UINT8 reserved0_b8_12 : 5; //bits 8->12
    };

    //contains the protocol type of the payload packet.
    //In general, the value will be the Ethernet protocol type field for the packet.
    UINT16 protocolType;
}OVS_GRE_HEADER_2784, *POVS_GRE_HEADER_2784;

typedef UINT16 OVS_GRE2784_HEADER_OPT_CHECKSUM;
typedef UINT16 OVS_GRE2784_HEADER_OPT_RESERVED1;

/*OPTIONAL FIELDS:

2.5. Checksum (2 octets)

The Checksum field contains the IP (one's complement) checksum sum of
the all the 16 bit words in the GRE header and the payload packet.
For purposes of computing the checksum, the value of the checksum
field is zero. This field is present only if the Checksum Present bit
is set to one.

2.6. Reserved1 (2 octets)

The Reserved1 field is reserved for future use, and if present, MUST
be transmitted as zero. The Reserved1 field is present only when the
Checksum field is present (that is, Checksum Present bit is set to
one).
*/

C_ASSERT(sizeof(OVS_GRE_HEADER_2784) == 4);

typedef struct _OVS_GRE_HEADER_2890
{
    struct
    {
        UINT8 reserved0_bit7 : 1;
        UINT8 reserved0_bit6 : 1;
        UINT8 reserved0_bit5 : 1;

        UINT8 reserved0_bit4 : 1;
        //if set => sequenceNumber is present.
        UINT8 haveSeqNumber : 1; //bit 3
        //if set => key is present.
        UINT8 haveKey : 1;//bit 2

        UINT8 reserved0_bit1 : 1;
        //if set => both checksum and offset fields are present
        UINT8 haveChecksum : 1;//bit 0
    };

    struct
    {
        //MUST contain the value 0
        UINT8 versionNumber : 3;//bits 13->15

        UINT8 reserved0_bit8_12 : 5;
    };

    //contains the protocol type of the payload packet.
    //In general, the value will be the Ethernet protocol type field for the packet.
    UINT16 protocolType;
}OVS_GRE_HEADER_2890, *POVS_GRE_HEADER_2890;

//key, sequence: optional

C_ASSERT(sizeof(OVS_GRE_HEADER_2890) == 4);

//i.e. if all flags are set, how big is the GRE header?
//NOTE: the fields: checksum, key, etc. follow the base gre header
#define OVS_MAX_GRE_HEADER_SIZE 16

/****************************************/

//encapsulation size in bytes required by Gre (i.e. gre + ipv4 + ethernet headers)
ULONG Gre_BytesNeeded(UINT16 tunnelFlags);

//the total size of the Gre header, based on the given flags (i.e. the optional fields for GRE)
ULONG Gre_HeaderSize(UINT16 tunnelFlags);

//computes the size in bytes of the GRE frame, where pGre is the position in the packet where the GRE frame starts
ULONG Gre_FrameHeaderSize(_In_ const OVS_GRE_HEADER_2890* pGre);

/****************************/

BYTE* VerifyGreHeader(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ UINT16* ethType);

OVS_GRE_HEADER_2890* Gre_BuildHeader(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _In_ const OVS_TUNNELING_PORT_OPTIONS* pPortOptions,
    ULONG payloadLength, ULONG greHeaderSize, _Out_ BOOLEAN* pHaveChecksum);

BOOLEAN Gre_ReadHeader(_In_ const VOID* pEncapHeader, _Inout_ ULONG* pOffset, ULONG outerIpPayloadLen, _Out_ OF_PI_IPV4_TUNNEL* pTunnelInfo);

//buffer: the net buffer starting with the GRE protocol
//dbg prints GRE info and calls ReadIpv4ProtocolFrame
void DbgPrintGreHeader(_In_ const VOID* buffer);