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
#include "OvsCore.h"
#include "Types.h"
#include "Ethernet.h"
#include "Buffer.h"
#include "OFPort.h"

typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;
typedef struct _OVS_NIC_INFO OVS_NIC_INFO;
typedef struct _OVS_PERSISTENT_PORT OVS_PERSISTENT_PORT;

typedef struct _OVS_NET_BUFFER
{
    OVS_SWITCH_INFO*		pSwitchInfo;
    OVS_NIC_INFO*			pSourceNic;
    OVS_PERSISTENT_PORT*	pSourcePort;
    OVS_PERSISTENT_PORT*	pDestinationPort;

    BOOLEAN					sendToPortNormal;
    ULONG					sendFlags;

    //The flow associated with this packet. Can be NULL.
    OVS_FLOW*		pFlow;

    //The flow information extracted from the packet (overwriting packet headers do not affect it). Must not be null.
    OVS_OFPACKET_INFO*	pOriginalPacketInfo;

    //Key for the tunnel that encapsulated this packet. Can be NULL if the packet is not being tunneled.
    OF_PI_IPV4_TUNNEL*	pTunnelInfo;

    //TODO: packetPriority & packetMark should be removed in the future
    //on windows, we cannot affect QoS with the field priority
    UINT32	packetPriority;
    UINT32	packetMark;

    NET_BUFFER_LIST* pNbl;
} OVS_NET_BUFFER, *POVS_NET_BUFFER;

static __inline VOID* ONB_GetData(OVS_NET_BUFFER* pOvsNb)
{
    NET_BUFFER* pNb = NULL;
    VOID* buffer = NULL;
    ULONG len = 0;

    OVS_CHECK(pOvsNb);
    OVS_CHECK(pOvsNb->pNbl);
    OVS_CHECK(pOvsNb->pNbl->Next == NULL);

    pNb = NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl);

    len = NET_BUFFER_DATA_LENGTH(pNb);

    buffer = NdisGetDataBuffer(pNb, len, NULL, 1, 0);
    OVS_CHECK(buffer);

    return buffer;
}

static __inline VOID* ONB_GetDataOfSize(OVS_NET_BUFFER* pOvsNb, ULONG size)
{
    NET_BUFFER* pNb = NULL;
    VOID* buffer = NULL;

    OVS_CHECK(pOvsNb);
    OVS_CHECK(pOvsNb->pNbl);
    OVS_CHECK(pOvsNb->pNbl->Next == NULL);

    pNb = NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl);
    OVS_CHECK(pNb->Next == NULL);

    buffer = NdisGetDataBuffer(pNb, size, NULL, 1, 0);
    OVS_CHECK(buffer);

    return buffer;
}

static __inline NET_BUFFER* ONB_GetNetBuffer(OVS_NET_BUFFER* pOvsNb)
{
    NET_BUFFER* pNb = NULL;

    OVS_CHECK(pOvsNb);
    OVS_CHECK(pOvsNb->pNbl);
    OVS_CHECK(pOvsNb->pNbl->Next == NULL);

    pNb = NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl);

    return pNb;
}

static __inline NET_BUFFER_LIST* ONB_GetNetBufferList(OVS_NET_BUFFER* pOvsNb)
{
    OVS_CHECK(pOvsNb);
    OVS_CHECK(pOvsNb->pNbl);
    OVS_CHECK(pOvsNb->pNbl->Next == NULL);

    return pOvsNb->pNbl;
}

static __inline VOID ONB_Advance(OVS_NET_BUFFER* pOvsNb, ULONG offset)
{
    NET_BUFFER* pNb = ONB_GetNetBuffer(pOvsNb);

    NdisAdvanceNetBufferDataStart(pNb, offset, FALSE, NULL);
}

static __inline NDIS_STATUS ONB_Retreat(OVS_NET_BUFFER* pOvsNb, ULONG offset)
{
    NET_BUFFER* pNb = ONB_GetNetBuffer(pOvsNb);
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    status = NdisRetreatNetBufferDataStart(pNb, offset, 0, NULL);

    return status;
}

static __inline ULONG ONB_GetDataLength(OVS_NET_BUFFER* pOvsNb)
{
    NET_BUFFER* pNb = ONB_GetNetBuffer(pOvsNb);
    ULONG len = NET_BUFFER_DATA_LENGTH(pNb);

    return len;
}

static __inline ULONG ONB_GetDataOffset(OVS_NET_BUFFER* pOvsNb)
{
    NET_BUFFER* pNb = ONB_GetNetBuffer(pOvsNb);
    ULONG len = NET_BUFFER_DATA_OFFSET(pNb);

    return len;
}

VOID ONB_Destroy(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _Inout_ OVS_NET_BUFFER** ppOvsNb);
VOID ONB_DestroyNbl(_Inout_ OVS_NET_BUFFER* pOvsNb);

BOOLEAN NblIsLso(_In_ NET_BUFFER_LIST* pNbl);

//create an ovs net buffer as a duplicate of an (nbl, nb).
//NOTE: must not be freed with FreeOvsNetBuffer! ReallocateOvsNetBuffer should also be changed for this.
OVS_NET_BUFFER* ONB_CreateFromNbAndNbl(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl, _In_ NET_BUFFER* pNb, ULONG addSize);
OVS_NET_BUFFER* ONB_CreateFromBuffer(_In_ const OVS_BUFFER* pBuffer, ULONG addSize);

OVS_NET_BUFFER* ONB_Duplicate(_In_ const OVS_NET_BUFFER* pOriginalOnb);

BOOLEAN ONB_OriginateIcmpPacket_Ipv4_Type3Code4(_Inout_ OVS_NET_BUFFER* pOvsNb, ULONG mtu, OVS_NIC_INFO* pDestinationNic);
BOOLEAN ONB_OriginateIcmp6Packet_Type2Code0(_Inout_ OVS_NET_BUFFER* pOvsNb, ULONG mtu, _In_ const OVS_NIC_INFO* pDestinationNic);

OVS_NET_BUFFER* ONB_Create(ULONG bufSize);

NET_BUFFER_LIST* ONB_FragmentBuffer_Ipv4(_Inout_ OVS_NET_BUFFER* pOvsNb, ULONG mtu, const OVS_ETHERNET_HEADER* pEthHeader, ULONG ethSize, ULONG dataOffsetAdd);
NET_BUFFER* ONB_CreateNb(ULONG dataLen, ULONG dataOffset);

BOOLEAN ONB_OriginateArpRequest(const BYTE targetIp[4]);