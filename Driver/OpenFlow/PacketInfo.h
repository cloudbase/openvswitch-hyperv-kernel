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
#include "Ethernet.h"
#include "Types.h"

#define OFFSET_OF(Type, member) ((SIZE_T) &((Type *)0)->member)
#define NESTED_OFFSET_OF(Type1, member1, Type2, member2) (OFFSET_OF(Type1, member1) + OFFSET_OF(Type2, member2))

#define OVS_PI_MASK_MATCH_EXACT(type)        ((type)~0)
#define OVS_PI_MASK_MATCH_WILDCARD(type)     ((type)0)

typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_ARGUMENT OVS_ARGUMENT;
typedef struct _OVS_PI_RANGE OVS_PI_RANGE;
typedef struct _OVS_FLOW_MASK OVS_FLOW_MASK;

/*************************************/

__declspec(align(8))
typedef struct _OVS_PHYSICAL
{
    UINT32    packetPriority;
    UINT32    packetMark;
    UINT16    ovsInPort;
}OVS_PHYSICAL, *POVS_PHYSICAL;
C_ASSERT(sizeof(OVS_PHYSICAL) == 16);

__declspec(align(8))
typedef struct _OVS_ETH_INFO
{
    UINT8   source[OVS_ETHERNET_ADDRESS_LENGTH];
    UINT8   destination[OVS_ETHERNET_ADDRESS_LENGTH];
    //tag control information: 0 = no VLAN; otherwise OVS_VLAN_TAG_PRESENT is set
    BE16    tci;
    BE16    type;
}OVS_ETH_INFO, *POVS_ETH_INFO;
C_ASSERT(sizeof(OVS_ETH_INFO) == 16);

typedef enum
{
    //not a fragment
    OVS_FRAGMENT_TYPE_NOT_FRAG,
    //first fragment
    OVS_FRAGMENT_TYPE_FIRST_FRAG,
    //2nd or 3rd or ... fragment
    OVS_FRAGMENT_TYPE_FRAG_N,
    OVS_FRAGMENT_TYPE_MAX = OVS_FRAGMENT_TYPE_FRAG_N
}OVS_FRAGMENT_TYPE;

__declspec(align(8))
typedef struct _OVS_NET_LAYER_INFO
{
    union
    {
        struct
        {
            //eth type = ipv4/ipv6: IP protocol; ARP: lower 8 bits of operation code.
            UINT8 protocol;
            UINT8 typeOfService;
            UINT8 timeToLive;
            //OVS_FRAGMENT_TYPE: 0 = not fragmented; 1 = first fragment; 2 = fragment with offset != 0
            UINT8 fragment;
        };

        BE32 mplsTopLabelStackEntry;
    };
}OVS_NET_LAYER_INFO, *POVS_NET_LAYER_INFO;
C_ASSERT(sizeof(OVS_NET_LAYER_INFO) == 8);

__declspec(align(4))
typedef struct _OVS_TRANSPORT_LAYER_INFO {
    //source port for TCP & UDP. For ICMP it is Type; BE
    BE16 sourcePort;
    //destination port for TCP & UDP. For ICMP it is Code; BE
    BE16 destinationPort;
}OVS_TRANSPORT_LAYER_INFO, *POVS_TRANSPORT_LAYER_INFO;

C_ASSERT(sizeof(OVS_TRANSPORT_LAYER_INFO) == 4);

__declspec(align(8))
typedef struct _OVS_IP4_INFO
{
    //TODO: consider using BE32 instead of IN_ADDR
    IN_ADDR source;
    IN_ADDR destination;
}OVS_IP4_INFO, *POVS_IP4_INFO;
C_ASSERT(sizeof(OVS_IP4_INFO) == 8);

__declspec(align(8))
typedef struct _OVS_ARP_INFO
{
    //TODO: consider using BE32 instead of IN_ADDR
    IN_ADDR source;
    IN_ADDR destination;

    UINT8 sourceMac[OVS_ETHERNET_ADDRESS_LENGTH];
    UINT8 destinationMac[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_ARP_INFO, *POVS_ARP_INFO;
C_ASSERT(sizeof(OVS_ARP_INFO) == 24);

__declspec(align(8))
typedef struct _OVS_IPV6_INFO
{
    // 16 bytes
    IN6_ADDR source;
    // 16 bytes
    IN6_ADDR destination;

    UINT32 flowLabel;

    //ND refers to Neighbor Discovery
    //see RFC4861 + its updates
    struct
    {
        // 16 bytes
        IN6_ADDR ndTargetIp;
        UINT8 ndSourceMac[OVS_ETHERNET_ADDRESS_LENGTH];
        UINT8 ndTargetMac[OVS_ETHERNET_ADDRESS_LENGTH];
    }neighborDiscovery;
}OVS_IPV6_INFO, *POVS_IPV6_INFO;
C_ASSERT(sizeof(OVS_IPV6_INFO) == 64);

//PI = PacketInfo
__declspec(align(8))
typedef struct _OF_PI_IPV4_TUNNEL
{
    BE64      tunnelId;
    UINT32    ipv4Source;
    UINT32    ipv4Destination;
    UINT16    tunnelFlags;
    UINT8     ipv4TypeOfService;
    UINT8     ipv4TimeToLive;
}OF_PI_IPV4_TUNNEL, *POF_PI_IPV4_TUNNEL;

C_ASSERT(sizeof(OF_PI_IPV4_TUNNEL) == 24);

#define OVS_TUNNEL_FLAG_CHECKSUM        RtlUshortByteSwap(0x01)
#define OVS_TUNNEL_FLAG_KEY             RtlUshortByteSwap(0x04)
#define OVS_TUNNEL_FLAG_SEQ             RtlUshortByteSwap(0x08)
#define OVS_TUNNEL_FLAG_DONT_FRAGMENT   RtlUshortByteSwap(0x0100)

__declspec(align(8))
typedef struct _OVS_OFPACKET_INFO
{
    OF_PI_IPV4_TUNNEL tunnelInfo;        //24 bytes

    OVS_PHYSICAL physical;                    //16 bytes
    OVS_ETH_INFO ethInfo;                    //16 bytes
    OVS_NET_LAYER_INFO ipInfo;                //8 bytes
    OVS_TRANSPORT_LAYER_INFO tpInfo;

    union
    {
        OVS_IP4_INFO ipv4Info;
        OVS_ARP_INFO arpInfo;
        OVS_IPV6_INFO ipv6Info;                //72 bytes
    } netProto;
}OVS_OFPACKET_INFO, *POVS_OFPACKET_INFO;
C_ASSERT(sizeof(OVS_OFPACKET_INFO) == 136);

/*******************************/

//multiprotocol label switching
typedef struct _OVS_PI_MPLS
{
    BE32 mplsLse;
}OVS_PI_MPLS, *POVS_PI_MPLS;

typedef struct _OVS_PI_ETH_ADDRESS
{
    UINT8     source[OVS_ETHERNET_ADDRESS_LENGTH];
    UINT8     destination[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_PI_ETH_ADDRESS, *POVS_PI_ETH_ADDRESS;

typedef struct _OVS_PI_IPV4
{
    BE32    source;
    BE32    destination;
    UINT8   protocol;
    UINT8   tos;
    UINT8   ttl;
    // an OVS_FRAGMENT_TYPE value
    UINT8   fragmentType;
}OVS_PI_IPV4, *POVS_PI_IPV4;

typedef struct _OVS_PI_IPV6
{
    BE32    source[4];
    BE32    destination[4];
    BE32    label;
    UINT8   protocol;
    UINT8   trafficClass;
    UINT8   highLimit;
    // an OVS_FRAGMENT_TYPE value
    UINT8   fragmentType;
}OVS_PI_IPV6, *POVS_PI_IPV6;

typedef struct _OVS_PI_TCP
{
    BE16 source;
    BE16 destination;
}OVS_PI_TCP, *POVS_PI_TCP;

typedef struct _OVS_PI_UDP
{
    BE16 source;
    BE16 destination;
}OVS_PI_UDP, *POVS_PI_UDP;

typedef struct _OVS_PI_SCTP
{
    BE16 source;
    BE16 destination;
}OVS_PI_SCTP, *POVS_PI_SCTP;

typedef struct _OVS_PI_ICMP
{
    UINT8 type;
    UINT8 code;
}OVS_PI_ICMP, *POVS_PI_ICMP;

typedef struct _OVS_PI_ICMP6
{
    UINT8 type;
    UINT8 code;
}OVS_PI_ICMP6, *POVS_PI_ICMP6;

typedef struct _OVS_PI_ARP
{
    BE32    sourceIp;
    BE32    targetIp;
    BE16    operation;
    UINT8   sourceMac[OVS_ETHERNET_ADDRESS_LENGTH];
    UINT8   targetMac[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_PI_ARP, *POVS_PI_ARP;

//Ipv6 Neighbor Discovery
typedef struct _OVS_PI_NEIGHBOR_DISCOVERY
{
    UINT32 targetIp[4];
    UINT8  sourceMac[OVS_ETHERNET_ADDRESS_LENGTH];
    UINT8  targetMac[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_PI_NEIGHBOR_DISCOVERY, *POVS_PI_NEIGHBOR_DISCOVERY;

/**************************************************************/

BOOLEAN GetPacketInfoFromArguments(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT_GROUP* pPIGroup, _In_ BOOLEAN isMask);
BOOLEAN GetIpv4TunnelFromArgumentsSimple(const OVS_ARGUMENT_GROUP* pArgs, _Inout_ OF_PI_IPV4_TUNNEL* pTunnelInfo);

VOID ApplyMaskToPacketInfo(_Inout_ OVS_OFPACKET_INFO* pDestinationPI, _In_ const OVS_OFPACKET_INFO* pSourcePI, _In_ const OVS_FLOW_MASK* pMask);

VOID PIFromArg_PacketPriority(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg);
BOOLEAN PIFromArg_DatapathInPort(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg, BOOLEAN isMask);
VOID PIFromArg_PacketMark(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, _In_ const OVS_ARGUMENT* pArg);
BOOLEAN PIFromArg_Tunnel(const OVS_ARGUMENT_GROUP* pArgs, _Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, BOOLEAN isMask);
VOID PIFromArg_SetDefaultDatapathInPort(_Inout_ OVS_OFPACKET_INFO* pPacketInfo, _Inout_ OVS_PI_RANGE* pPiRange, BOOLEAN isMask);

BOOLEAN PacketInfo_Extract(_In_ VOID* pNbBuffer, ULONG nbLen, UINT16 ovsSourcePort, _Out_ OVS_OFPACKET_INFO* pPacketInfo);

BOOLEAN PacketInfo_Equal(const OVS_OFPACKET_INFO* pLhs, const OVS_OFPACKET_INFO* pRhs, SIZE_T endRange);
BOOLEAN PacketInfo_EqualAtRange(const OVS_OFPACKET_INFO* pLhsPI, const OVS_OFPACKET_INFO* pRhsPI, SIZE_T startRange, SIZE_T endRange);
