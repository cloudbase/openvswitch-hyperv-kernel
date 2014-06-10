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

///"Fragment Offset" part of FlagsAndOffset
#define OVS_IPV4_OFFSET       0x1FFF
#define OVS_IPV4_ADDRESS_LENGTH		4

#define IPV4_GET_OPTION_COPIED(optionType) (optionType & 0x80) /*1000 0000*/
#define IPV4_GET_OPTION_CLASS(optionType) (optionType & 0x60) /*0110 0000*/
#define IPV4_GET_OPTION_NUMBER(optionType) (optionType & 0x1F) /*0001 1111*/

typedef struct _OVS_ETHERNET_HEADER OVS_ETHERNET_HEADER;
typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_PI_IPV4 OVS_PI_IPV4;
typedef struct _OVS_TRANSPORT_PSEUDO_HEADER_IPV4 OVS_TRANSPORT_PSEUDO_HEADER_IPV4;

//TODO: check
//http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xml
//tcp/udp port numbers:
//http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

//
// IPV4_HEADER
//
// Define the structure of an IPv4 header.
// The field names match those in section 3.1 of RFC 791.
// RFC 2474 redefines type of service to the 6 bit DSCP value. RFC 2780 and
// 3168 redefine the unused 2 bits in the traffic class octet as used by
// ECN.
//
typedef struct _OVS_IPV4_HEADER {
    union {
        UINT8 VersionAndHeaderLength;   // Version and header length.
        struct {
            UINT8 HeaderLength : 4;
            UINT8 Version : 4;
        };
    };
    union {
        UINT8 TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct {
            UINT8 EcnField : 2;
            UINT8 TypeOfService : 6;
        };
    };
    UINT16 TotalLength;                 // Total length of datagram.
    UINT16 Identification;
    union {
        UINT16 FlagsAndOffset;          // Flags and fragment offset.
        struct {
            UINT16 DontUse1 : 5;        // High bits of fragment offset.
            UINT16 MoreFragments : 1;
            UINT16 DontFragment : 1;
            UINT16 Reserved : 1;
            UINT16 DontUse2 : 8;        // Low bits of fragment offset.
        };
    };
    UINT8 TimeToLive;
    UINT8 Protocol;
    UINT16 HeaderChecksum;
    IN_ADDR SourceAddress;
    IN_ADDR DestinationAddress;
} OVS_IPV4_HEADER, *POVS_IPV4_HEADER;

C_ASSERT(sizeof(OVS_IPV4_HEADER) == 20);

/*********************************/

enum { OVS_IPPROTO_ICMP = 0x01, OVS_IPPROTO_IGMP = 0x02, OVS_IPPROTO_TCP = 0x06, OVS_IPPROTO_UDP = 0x11, OVS_IPPROTO_GRE = 0x2F, OVS_IPPROTO_SCTP = 0x84 };
enum { OVS_IPPROTO_VERSION_4 = 0x04 };

/*********************************/

const char* Ipv4ProtoToString(UINT8 proto);

static __inline ULONG Ipv4_GetOptionLength(BYTE* pOption)
{
    BYTE optionType = *pOption;

    optionType &= 0xEF; //remove the copy flag

    switch (optionType)
    {
        //End of Options
    case 0:
        return 1;

        //No op
    case 1:
        return 1;

        // Security.
    case 2:
        return 11;

        //Stream ID
    case 8:
        return 4;

    default:
        return *(pOption + 1);
    }
}

BOOLEAN ONB_SetIpv4(OVS_NET_BUFFER* pNb, const OVS_PI_IPV4* pIpv4Info);

OVS_IPV4_HEADER* GetIpv4Header(VOID* pPacketBuffer);

//TODO: issue request for OID_TCP_TASK_OFFLOAD - if enabled, we do not need to compute the OUTER ip checksum,
//but the inner ip checksum MUST be computed!
//NOTE: if you compute inner checksum for payload ip, you don't need to recompute for tcp or udp:, when only encapsulating:
//the pseudo header tcp & udp are using include only: src addr, dest addr, proto, tcp / udp byte-computed length.
//for OF, when setting stuff into the ip layer / transport layer, the checksum of the transport layer must be recomputed.

static __inline const VOID* AdvanceIpv4Header(_In_ const OVS_IPV4_HEADER* pIpv4Header)
{
    return (UINT8*)(pIpv4Header)+pIpv4Header->HeaderLength * sizeof(DWORD);
}

const OVS_IPV4_HEADER* ReadIpv4Header(_In_ const OVS_ETHERNET_HEADER* pEthHeader);

void ReadIpv4ProtocolFrame(_In_ const OVS_IPV4_HEADER* pIpv4Header);

BYTE* VerifyIpv4Frame(BYTE* buffer, ULONG* pLength, BYTE* pProtoType);

VOID FillTransportPseudoHeader_FromIpv4(_In_ const OVS_IPV4_HEADER* pIpv4Header, _Out_ OVS_TRANSPORT_PSEUDO_HEADER_IPV4* pPseudoHeader);

static __inline ULONG GetTransportLength_FromIpv4(_In_ const OVS_IPV4_HEADER* pIpv4Header)
{
    ULONG tcpLen = 0;

    OVS_CHECK(pIpv4Header);

    tcpLen = RtlUshortByteSwap(pIpv4Header->TotalLength) - pIpv4Header->HeaderLength * sizeof(DWORD);

    return tcpLen;
}

static __inline VOID Ipv4_SetFragmentOffset(OVS_IPV4_HEADER* pIpv4Header, UINT16 offset)
{
    OVS_CHECK(offset <= 0x1FFF); //i.e. 13 bits

    //cccb bbba 000d dddc -> 000d dddc cccb bbba
    offset = RtlUshortByteSwap(offset);

    pIpv4Header->FlagsAndOffset |= offset;
}

static __inline UINT16 Ipv4_GetFragmentOffset(_In_ const OVS_IPV4_HEADER* pIpv4Header)
{
    UINT16 offset = pIpv4Header->FlagsAndOffset;

    //cccb bbba FFFd dddc -> FFFd dddc cccb bbba
    offset = RtlUshortByteSwap(offset);
    offset &= 0x1FFF; //i.e. remove flags: FFFd -> 000d

    return offset;
}

//copies the header options that have the copied flag set. returns ptr to buffer; pFragHeaderSize = on return it is the size of the buffer
BYTE* Ipv4_CopyHeaderOptions(_In_ const OVS_IPV4_HEADER* pIpv4Header, _Inout_ ULONG* pFragHeaderSize);

#ifdef DBG
void DbgPrintIpv4(_In_ const OVS_IPV4_HEADER* pIpv4Header);
#else
#define DbgPrintIpv4(pIpv4Header)
#endif