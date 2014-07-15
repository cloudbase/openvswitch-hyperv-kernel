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

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_ETHERNET_HEADER OVS_ETHERNET_HEADER;
typedef struct _OF_PI_IPV4_TUNNEL OF_PI_IPV4_TUNNEL;
typedef struct _OVS_TUNNELING_PORT_OPTIONS OVS_TUNNELING_PORT_OPTIONS;

typedef struct _OVS_INNER_ENCAPSULATOR_DATA
{
    //inout
    NET_BUFFER* pNb;
    //in
    const OF_PI_IPV4_TUNNEL* pTunnelInfo;
    const OVS_TUNNELING_PORT_OPTIONS* pPortOptions;

    //in, must be copy, not ptr to eth header in the buffer
    const OVS_ETHERNET_HEADER* pPayloadEthHeader;

    //in
    BOOLEAN isFromExternal;

    //in
    const OVS_ETHERNET_HEADER* pDeliveryEthHeader;

    ULONG encBytesNeeded;

    //in
    BYTE encapProtocol;
}OVS_INNER_ENCAPSULATOR_DATA, *POVS_INNER_ENCAPSULATOR_DATA;

typedef struct _OVS_OUTER_ENCAPSULATION_DATA
{
    //inout
    OVS_NET_BUFFER* pOvsNb;

    ULONG mtu;

    //in, copy of the payload eth header
    const OVS_ETHERNET_HEADER* pPayloadEthHeader;

    //ULONG payloadEthSize;
    BOOLEAN isFromExternal;

    //in
    const OVS_ETHERNET_HEADER* pDeliveryEthHeader;

    //e.g. gre_h size + outer_ip4_h size + outer_eth_h size
    ULONG encapsHeadersSize;

    //in
    BYTE encapProtocol;
}OVS_OUTER_ENCAPSULATION_DATA, *POVS_OUTER_ENCAPSULATION_DATA;

typedef struct _OVS_DECAPSULATION_DATA
{
    //inout
    OVS_NET_BUFFER* pOvsNb;

    //in, copy of the outer eth header
    const OVS_ETHERNET_HEADER* pOuterEthHeader;

    //out: should not be dynamically allocated
    OF_PI_IPV4_TUNNEL* pTunnelInfo;

    BYTE encapProtocolType;
}OVS_DECAPSULATION_DATA, *POVS_DECAPSULATION_DATA;

typedef struct _OVS_ENCAPSULATOR
{
    ULONG(*BytesNeeded)(UINT16 tunnelFlags);

    VOID* (*BuildEncapsulationHeader)(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _In_ const OVS_TUNNELING_PORT_OPTIONS* pOptions,
        ULONG payloadLength, ULONG encapHeaderSize, _Out_ BOOLEAN* pHaveChecksum);

    VOID(*ComputeChecksum)(VOID* pEncapsulationHeader, ULONG encapHeaderSize, ULONG encapPayloadSize);
}OVS_ENCAPSULATOR, *POVS_ENCAPSULATOR;

typedef struct _OVS_DECAPSULATOR
{
    BOOLEAN(*ReadEncapsHeader)(_In_ const VOID* pEncapHeader, _Inout_ ULONG* pOffset, ULONG ipPayloadLen, _Out_ OF_PI_IPV4_TUNNEL* pTunnelInfo);
}OVS_DECAPSULATOR, *POVS_DECAPSULATOR;

/*************************************/

BOOLEAN Encaps_EncapsulateOnb(_In_ const OVS_ENCAPSULATOR* pEncapsulator, _Inout_ OVS_OUTER_ENCAPSULATION_DATA* pData);
VOID Gre_ComputeChecksum(VOID* pGreHeader, ULONG greHeaderSize, ULONG grePayloadSize);

BOOLEAN Encaps_ComputeOuterEthHeader(_In_ const BYTE externalMacAddress[OVS_ETHERNET_ADDRESS_LENGTH], _In_ BYTE ipTargetOuter[4], _Inout_ OVS_ETHERNET_HEADER* pEthHeader);

BOOLEAN Encaps_DecapsulateOnb(_In_ const OVS_DECAPSULATOR* pDecapsulator, _Inout_ OVS_NET_BUFFER* pOvsNb, _Out_ OF_PI_IPV4_TUNNEL* pTunnelInfo, BYTE encapProtocolType);

const OVS_DECAPSULATOR* Encap_FindDecapsulator(_In_ NET_BUFFER* pNb, _Inout_ BYTE* pEncapProtoType, _Inout_opt_ LE16* pUdpDestPort);

const OVS_DECAPSULATOR* Encap_GetDecapsulator_Gre();
const OVS_DECAPSULATOR* Encap_GetDecapsulator_Vxlan();