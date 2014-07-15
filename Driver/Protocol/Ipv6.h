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
#include "Types.h"

#define OVS_IPV6_MINIMUM_MTU 1280

typedef struct _OVS_ETHERNET_HEADER OVS_ETHERNET_HEADER;
typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_PI_IPV6 OVS_PI_IPV6;
typedef struct _OVS_TRANSPORT_PSEUDO_HEADER_IPV6 OVS_TRANSPORT_PSEUDO_HEADER_IPV6;

/******************************/

typedef struct _OVS_IPV6_HEADER {
    //4 bits version; 8 traffic class (= 6 traffic class + 2 ECN); 20 flow label
    UINT32        vcf;// 4 bits Version, 8 Traffic Class, 20 Flow Label.

    UINT16        payloadLength;   // Zero indicates Jumbo Payload hop-by-hop option.
    UINT8         nextHeader;       // Values are superset of IPv4's Protocol field.
    UINT8         hopLimit;
    IN6_ADDR      sourceAddress;
    IN6_ADDR      destinationAddress;
} OVS_IPV6_HEADER, *POVS_IPV6_HEADER;

C_ASSERT(40 == sizeof(OVS_IPV6_HEADER));

typedef struct _OVS_IPV6_FRAGMENT_HEADER
{
    UINT8         nextHeaderType;
    UINT8         reserved;
    UINT16        fragmentOffset; //13 bit fragment offset, 2bit reserved, 1bit M flag (more fragments)
    UINT32        identification;
}OVS_IPV6_FRAGMENT_HEADER, *POVS_IPV6_FRAGMENT_HEADER;

typedef struct _OVS_IPV6_ROUTING_HEADER
{
    UINT8         nextHeaderType;
    UINT8         headerExtLength;
    UINT8         routingType;
    UINT8         segmentsLeft;
    /* type specific data - variable length field */
}OVS_IPV6_ROUTING_HEADER, *POVS_IPV6_ROUTING_HEADER;

/*********************************/

enum {
    OVS_IPV6_EXTH_HOPBYHOP = 0,
    OVS_IPV6_EXTH_ICMP4 = 1,
    OVS_IPV6_EXTH_IGMP4 = 2,
    OVS_IPV6_EXTH_IPIP = 4,
    OVS_IPV6_EXTH_TCP = 6,
    OVS_IPV6_EXTH_EGP = 8,
    OVS_IPV6_EXTH_UDP = 17,
    OVS_IPV6_EXTH_IP6 = 41,
    OVS_IPV6_EXTH_ROUTING = 43,
    OVS_IPV6_EXTH_FRAGMENTATION = 44,
    OVS_IPV6_EXTH_RSVP = 46,
    OVS_IPV6_EXTH_ESP = 50,
    OVS_IPV6_EXTH_AH = 51,
    OVS_IPV6_EXTH_ICMP6 = 58,
    OVS_IPV6_EXTH_NONE = 59,
    OVS_IPV6_EXTH_DESTINATION_OPTS = 60,
    OVS_IPV6_EXTH_SCTP = 0x84
};

/************************************/

const char* Ipv6NextHeaderToString(UINT8 nextHeader);

static __inline BOOLEAN IsIpv6Extension(BYTE extensionOrProto)
{
    return extensionOrProto == OVS_IPV6_EXTH_HOPBYHOP ||
        extensionOrProto == OVS_IPV6_EXTH_ROUTING ||
        extensionOrProto == OVS_IPV6_EXTH_FRAGMENTATION ||
        extensionOrProto == OVS_IPV6_EXTH_AH ||
        extensionOrProto == OVS_IPV6_EXTH_NONE ||
        extensionOrProto == OVS_IPV6_EXTH_DESTINATION_OPTS;
}

static __inline UINT32 GetIpv6Version(UINT32 vcf)
{
    UINT32 x = vcf & 0x000000F0; //byte swap of 0xF0000000

    return x >> 4;
}

static __inline VOID SetIpv6Version(UINT32 value, UINT32* pVcf)
{
    OVS_CHECK(value <= 0xFF);

    *pVcf |= (value << 4);
}

static __inline UINT32 GetIpv6TrafficClass(UINT32 vcf)
{
    UINT32 x = vcf & 0x0000F00F; //byte swap of 0x0FF00000

    //now have 0x0000L00H
    //makebyte(l,h): turn x to L00H, then set L0 >> 4 = L as low order and 0H as high order
    x = MAKEBYTE(HIBYTE(x) >> 4, LOBYTE(x));
    return x;
}

static __inline VOID SetIpv6TrafficClass(UINT32 value, UINT32* pVcf)
{
    WORD tclass = MAKEWORD(LONIBBLE(value) << 4, HINIBBLE(value));
    *pVcf |= RtlUshortByteSwap(tclass);
}

static __inline UINT32 GetIpv6FlowLabel(UINT32 vcf)
{
    UINT32 x = vcf & 0xFFFF0F00; //byte swap of 0x000FFFFF

    return RtlUlongByteSwap(x);
}

static __inline VOID SetIpv6FlowLabel(UINT32 value, UINT32* pVcf)
{
    *pVcf |= RtlUlongByteSwap(value);
}

BOOLEAN ONB_SetIpv6(OVS_NET_BUFFER *pNb, const OVS_PI_IPV6* pIpv6Info);
OVS_IPV6_HEADER* GetIpv6Header(VOID* pPacketBuffer);

//length: in - size of buffer; out - size of the buffer that starts after the ipv6 extensions
//proto type: in - first ipv6 extension; out - last ipv6 extension, which is the transport protocol
BYTE* VerifyIpv6Extension(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ BYTE* pProtoType);

static __inline VOID* AdvanceIpv6Header(_In_ const OVS_IPV6_HEADER* pIpv6Header)
{
    return (UINT8*)(pIpv6Header)+sizeof(OVS_IPV6_HEADER);
}

OVS_IPV6_HEADER* ReadIpv6Header(_In_ OVS_ETHERNET_HEADER* pEthHeader);
void ReadIpv6ProtocolFrame(_In_ OVS_IPV6_HEADER* pIpv6Header);
BYTE* VerifyIpv6Frame(BYTE* buffer, ULONG* pLength, BYTE* pProtoType);

VOID* GetFirstIpv6Extension(_In_ const OVS_IPV6_HEADER* pIpv6Header, _Out_ BYTE* pNextExtensionType);
VOID* GetNextIpv6Extension(_In_ VOID* buffer, _Inout_ BYTE* pExtensionType);

static __inline UINT16 GetIpv6FragmentHeader_Offset(OVS_IPV6_FRAGMENT_HEADER* pIpv6FragmentHeader)
{
    //fragment offset = first 13 bits of the fragmentOffset field => max frag offset value = 0x1FFF
    UINT16 fragOff = RtlUshortByteSwap(pIpv6FragmentHeader->fragmentOffset);
    fragOff >>= 3;

    return fragOff;
}

static __inline UINT16 GetIpv6FragmentHeader_MoreFragments(OVS_IPV6_FRAGMENT_HEADER* pIpv6FragmentHeader)
{
    //bit field More Fragments = the 15th bit (BE) in the fragmentOffset field
    UINT16 M = RtlUshortByteSwap(pIpv6FragmentHeader->fragmentOffset);

    M = M & 1;

    return M;
}

static __inline BYTE GetIpv6ExtensionLength(_In_ const VOID* extBuffer)
{
    BYTE type = *(BYTE*)extBuffer;
    BYTE len = 0;

    OVS_CHECK(IsIpv6Extension(type));

    if (type == OVS_IPV6_EXTH_FRAGMENTATION)
    {
        return 8;
    }

    len = *((BYTE*)extBuffer + 1);

    return len;
}

VOID FillTransportPseudoHeader_FromIpv6(_In_ const BYTE srcIp[16], _In_ const BYTE dstIp[16], BYTE proto, ULONG tcpLen, _Out_ OVS_TRANSPORT_PSEUDO_HEADER_IPV6* pPseudoHeader);
VOID* Ipv6_FindExtensionHeader(_In_ const OVS_IPV6_HEADER* pIpv6Header, BYTE extType, ULONG* pExtensionsLength);
ULONG Ipv6_HeaderSize(_In_ const OVS_IPV6_HEADER* pIpv6Header);

#ifdef DBG
void DbgPrintIpv6(OVS_IPV6_HEADER* pIpv6Header);
#else
#define DbgPrintIpv6(pIpv6Header)
#endif