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

#include "Ethernet.h"
#include "OvsNetBuffer.h"
#include "PacketInfo.h"
#include "Frame.h"
#include "Nbls.h"

BOOLEAN ONB_SetEthernetAddress(OVS_NET_BUFFER* pOvsNetBuffer, const OVS_PI_ETH_ADDRESS* pEthAddressPI)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)ONB_GetData(pOvsNetBuffer);

    memcpy(pEthHeader->source_addr, pEthAddressPI->source, OVS_ETHERNET_ADDRESS_LENGTH);
    memcpy(pEthHeader->destination_addr, pEthAddressPI->destination, OVS_ETHERNET_ADDRESS_LENGTH);

    return TRUE;
}

BYTE* VerifyEthernetFrame(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ UINT16* pEthType)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)buffer;
    OVS_ETHERNET_HEADER_TAGGED* pEthTagged = (OVS_ETHERNET_HEADER_TAGGED*)buffer;
    ULONG offset = sizeof(OVS_ETHERNET_HEADER);

    OVS_CHECK(buffer);
    OVS_CHECK(pLength);
    OVS_CHECK(pEthType);

    if (RtlUshortByteSwap(pEthHeader->type) < OVS_ETHERTYPE_802_3_MIN)
    {
        DEBUGP(LOG_ERROR, "ethertype is < 802.3 min: 0x%x\n", RtlUshortByteSwap(pEthHeader->type));
        return NULL;
    }

    switch (RtlUshortByteSwap(pEthHeader->type))
    {
    case OVS_ETHERTYPE_ARP:
    case OVS_ETHERTYPE_IPV4:
    case OVS_ETHERTYPE_IPV6:
    case OVS_ETHERTYPE_QTAG:
    case OVS_ETHERTYPE_RARP:
        break;

    default:
        DEBUGP(LOG_ERROR, "unknown ethertype: 0x%x\n", RtlUshortByteSwap(pEthHeader->type));
        return NULL;
    }

    *pEthType = pEthHeader->type;

    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        offset = sizeof(OVS_ETHERNET_HEADER_TAGGED);
        WORD cfi = 0;

        cfi = GetQTaggedCfi(pEthTagged->tci);

        if (cfi != 1)
        {
            DEBUGP(LOG_ERROR, "qtagged frame has 'tag present' unset\n");
            return NULL;
        }

        switch (RtlUshortByteSwap(pEthTagged->clientType))
        {
        case OVS_ETHERTYPE_ARP:
        case OVS_ETHERTYPE_IPV4:
        case OVS_ETHERTYPE_IPV6:
        case OVS_ETHERTYPE_RARP:
            break;

        case OVS_ETHERTYPE_QTAG:
            DEBUGP(LOG_ERROR, "qtagged frame cannot have client ether type = qtag\n");
            break;

        default:
            DEBUGP(LOG_ERROR, "unknown ethertype: 0x%x\n", RtlUshortByteSwap(pEthHeader->type));
            return NULL;
        }

        *pEthType = pEthTagged->clientType;
    }

    if (offset > *pLength)
    {
        DEBUGP(LOG_ERROR, "eth frame size=0x%x > buffer length=0x%x.\n", offset, *pLength);
        return NULL;
    }

    *pLength -= offset;

    return buffer + offset;
}

OVS_ETHERNET_HEADER* ReadEthernetHeader_Alloc(_In_ NET_BUFFER* net_buffer, _Out_ void** allocBuffer)
{
    OVS_CHECK(allocBuffer);
    *allocBuffer = ReadNb_Alloc(net_buffer);

    return (OVS_ETHERNET_HEADER*)*allocBuffer;
}

OVS_ETHERNET_HEADER* ReadEthernetHeaderOnly(_In_ NET_BUFFER* net_buffer)
{
    OVS_ETHERNET_HEADER* buffer = NULL;
    ULONG bufferSize = sizeof(OVS_ETHERNET_HEADER);

    buffer = (OVS_ETHERNET_HEADER*)NdisGetDataBuffer(net_buffer, bufferSize, NULL, 1, 0);
    //the buffer of a NET_BUFFER MUST have the ethernet header in contiguous space (according to msdn doc),
    //i.e. the var buffer must be != NULL here.
    OVS_CHECK(buffer);
    if (!buffer)
    {
        return NULL;
    }

    if (buffer->type == OVS_ETHERTYPE_QTAG)
    {
        bufferSize = sizeof(OVS_ETHERNET_HEADER_TAGGED);

        buffer = NdisGetDataBuffer(net_buffer, bufferSize, NULL, 1, 0);
        OVS_CHECK(buffer);
    }

    return buffer;
}

OVS_ETHERNET_HEADER* GetEthernetHeader(_In_ VOID* buffer, _Out_ ULONG* pEthSize)
{
    OVS_CHECK(pEthSize);
    OVS_CHECK(buffer);

    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)buffer;

    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        *pEthSize = sizeof(OVS_ETHERNET_HEADER_TAGGED);
    }
    else
    {
        *pEthSize = sizeof(OVS_ETHERNET_HEADER);
    }

    return pEthHeader;
}

LE16 ReadEthernetType(_In_ const OVS_ETHERNET_HEADER* pEthHeader)
{
    OVS_CHECK(pEthHeader);

    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        pEthHeader = (OVS_ETHERNET_HEADER*)((BYTE*)pEthHeader + OVS_ETHERNET_VLAN_LEN);
    }

    return RtlUshortByteSwap(pEthHeader->type);
}