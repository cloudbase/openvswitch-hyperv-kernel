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

#define OVS_ETHERNET_ADDRESS_LENGTH 6

//The additional bytes (on top of the Ethernet header) that VLAN requires
#define OVS_ETHERNET_VLAN_LEN    4

//Canonical Format Indicator
#define OVS_VLAN_CFI_MASK           0x1000
#define OVS_VLAN_TAG_PRESENT        OVS_VLAN_CFI_MASK

//If the value in the ethernet type is less than this value then the frame is Ethernet II. Else it is 802.3
//we use 802.3, so all should be >= 0x600
#define OVS_ETHERTYPE_802_3_MIN 0x0600

//802.2 / LLC frames
#define OVS_ETHERTYPE_802_2     0x0004

/********************************/

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_PI_ETH_ADDRESS OVS_PI_ETH_ADDRESS;

//see windows netiodef.h for more structs for frames and protocols
//(go to definition of IPV4_HEADER)

//TODO: see about 802.1Q frames.
typedef struct _OVS_ETHERNET_HEADER
{
    BYTE    destination_addr[OVS_ETHERNET_ADDRESS_LENGTH];
    BYTE    source_addr[OVS_ETHERNET_ADDRESS_LENGTH];
    WORD    type;
}OVS_ETHERNET_HEADER, *POVS_ETHERNET_HEADER;

C_ASSERT(sizeof(OVS_ETHERNET_HEADER) == 14);

typedef struct _OVS_ETHERNET_HEADER_TAGGED
{
    BYTE    destination_addr[OVS_ETHERNET_ADDRESS_LENGTH];
    BYTE    source_addr[OVS_ETHERNET_ADDRESS_LENGTH];
    //protocol type = 0x8100
    WORD    type;
    //tag control information: 3-bit user priority; 1-bit canonical format indicator (CFI); 12-bit VLAN indicator.
    WORD    tci;

    WORD clientType;
}OVS_ETHERNET_HEADER_TAGGED, *POVS_ETHERNET_HEADER_TAGGED;

C_ASSERT(sizeof(OVS_ETHERNET_HEADER_TAGGED) == 18);

//TEB = Transparent Ethernet Bridging
typedef enum
{
    OVS_ETHERTYPE_TEB = 0x6558,
    OVS_ETHERTYPE_IPV4 = 0x800,
    OVS_ETHERTYPE_IPV6 = 0x86DD,
    OVS_ETHERTYPE_QTAG = 0x8100,
    OVS_ETHERTYPE_ARP = 0x0806,
    OVS_ETHERTYPE_RARP = 0x8035
} OVS_ETHERNET_TYPE;

#ifdef DBG
VOID DbgPrintMac(OVS_ETHERNET_HEADER* pEthernetFrame);
VOID DbgPrintMacMsg(OVS_ETHERNET_HEADER* pEthernetFrame, const char* msg);
#else
#define DbgPrintMac(pEthernetFrame)
#define DbgPrintMacMsg(pEthernetFrame, msg)
#endif

static __inline WORD GetQTaggedUserPriority(WORD vlan)
{
    BYTE priority = (BYTE)vlan;
    priority >>= 5;

    return priority;
}

static __inline VOID SetQTaggedUserPriority(BYTE value, WORD* pVlan)
{
    OVS_CHECK(value <= 7);

    *pVlan |= (value << 5);
}

static __inline WORD GetQTaggedCfi(WORD vlan)
{
    WORD cfi = _byteswap_ushort(vlan);
    cfi >>= 12;
    return (BYTE)cfi;
}

static __inline VOID SetQTaggedCfi(BYTE value, WORD* pVlan)
{
    OVS_CHECK(value <= 1);

    *pVlan |= value << 4;
}

static __inline WORD GetQTaggedIdentifier(WORD vlan)
{
    WORD vid = vlan & 0xFF0F; //byte swap of 0x0FFF
    vid = RtlUshortByteSwap(vid);

    return vid;
}

static __inline VOID SetQTaggedIdentifier(WORD vid, WORD* pVlan)
{
    OVS_CHECK(vid <= 0xFFF);

    *pVlan |= RtlUshortByteSwap(vid);
}

BOOLEAN ONB_SetEthernetAddress(OVS_NET_BUFFER *pOvsNetBuffer, const OVS_PI_ETH_ADDRESS* pEthAddressPI);

//returns ptr to next frame, if ok; otherwise, NULL
//pLength: in - the size of the buffer; out - size of the buffer starting after the eth header
BYTE* VerifyEthernetFrame(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ UINT16* pEthType);
OVS_ETHERNET_HEADER* ReadEthernetHeader_Alloc(_In_ NET_BUFFER* net_buffer, _Out_ void** allocBuffer);

//if we don't need the ip from it: we know that the eth frame is in contiguous memory and the same in every NET_BUFFER in a nbl.
OVS_ETHERNET_HEADER* ReadEthernetHeaderOnly(_In_ NET_BUFFER* net_buffer);

OVS_ETHERNET_HEADER* GetEthernetHeader(_In_ VOID* buffer, _Out_ ULONG* pEthSize);
LE16 ReadEthernetType(_In_ const OVS_ETHERNET_HEADER* pEthHeader);

static __inline VOID* AdvanceEthernetHeader(_In_ const OVS_ETHERNET_HEADER* pEthHeader, ULONG ethSize)
{
    VOID* buffer = (VOID*)((BYTE*)pEthHeader + ethSize);
    return buffer;
}