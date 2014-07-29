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

#include "Encapsulator.h"
#include "OvsNetBuffer.h"
#include "Ipv4.h"
#include "Checksum.h"
#include "Frame.h"
#include "Nbls.h"
#include "Gre.h"
#include "Vxlan.h"
#include "Udp.h"
#include "OFPort.h"

volatile UINT16 g_uniqueIpv4Id = 0;

static __inline UINT16 _GenerateUniqueIpv4Id()
{
    return (UINT16)InterlockedIncrement16((volatile SHORT*)&g_uniqueIpv4Id);
}

static const OVS_DECAPSULATOR g_greDecapsulator = {
    .ReadEncapsHeader = Gre_ReadHeader,
};

static const OVS_DECAPSULATOR g_vxlanDecapsulator = {
    .ReadEncapsHeader = Vxlan_ReadHeader,
};

const OVS_DECAPSULATOR* Encap_GetDecapsulator_Gre()
{
    return &g_greDecapsulator;
}

const OVS_DECAPSULATOR* Encap_GetDecapsulator_Vxlan()
{
    return &g_vxlanDecapsulator;
}

static VOID _BuildOuterIpv4Header(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _Out_ OVS_IPV4_HEADER* pDeliveryIp4Header, ULONG payloadSize, ULONG encapHeaderSize, BYTE encapProto)
{
    /*RFC1702:
    When IP is encapsulated in IP, the TTL, TOS, and IP security options
    MAY be copied from the payload packet into the same fields in the
    delivery packet.  The payload packet's TTL MUST be decremented when
    the packet is decapsulated to insure that no packet lives forever.
    */

    //576 is the minimum TL that any host / gateway should accept (i.e. MTU cannot be less than this anywhere)
    UINT16 totalLength = 0;

    OVS_CHECK(pTunnel);
    OVS_CHECK(pDeliveryIp4Header);

    OVS_CHECK(payloadSize <= 0xFFFF);
    totalLength = (UINT16)(sizeof(OVS_IPV4_HEADER) + encapHeaderSize + payloadSize);

    pDeliveryIp4Header->FlagsAndOffset = 0;
    pDeliveryIp4Header->DontFragment = (pTunnel->tunnelFlags & OVS_TUNNEL_FLAG_DONT_FRAGMENT ? 1 : 0);

    pDeliveryIp4Header->Version = OVS_IPPROTO_VERSION_4;
    //sizeof(OVS_IPV4_HEADER) in DWORDs = 5
    pDeliveryIp4Header->HeaderLength = sizeof(OVS_IPV4_HEADER) / sizeof(DWORD);
    pDeliveryIp4Header->TypeOfServiceAndEcnField = pTunnel->ipv4TypeOfService;
    pDeliveryIp4Header->TotalLength = RtlUshortByteSwap(totalLength);
    //TODO: try setting identification incrementally (i.e. 0, 1, ...)
    //or perhaps it's ok to use the identification of the payload

    /*
    The originating protocol module of
    an internet datagram sets the identification field to a value that
    must be unique for that source-destination pair and protocol for the
    time the datagram will be active in the internet system.
    */

    /*
    To assemble the fragments of an internet datagram, an internet
    protocol module (for example at a destination host) combines
    internet datagrams that all have the same value for the four fields:
    identification, source, destination, and protocol.
    */
    //i.e. identification is considered for the same ip src & dest + proto
    //update: RFC6864 - use only for fragmentation.
    //TODO: consider using FwpsConstructIpHeaderForTransport
    pDeliveryIp4Header->Identification = _GenerateUniqueIpv4Id();
    // If TTL contains the value zero, then the datagram must be destroyed.
    pDeliveryIp4Header->TimeToLive = pTunnel->ipv4TimeToLive;
    pDeliveryIp4Header->Protocol = encapProto;
    /*
    The checksum algorithm is:

    The checksum field is the 16 bit one's complement of the one's
    complement sum of all 16 bit words in the header.
    */
    pDeliveryIp4Header->HeaderChecksum = 0;
    pDeliveryIp4Header->SourceAddress.S_un.S_addr = pTunnel->ipv4Source;
    pDeliveryIp4Header->DestinationAddress.S_un.S_addr = pTunnel->ipv4Destination;

    pDeliveryIp4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pDeliveryIp4Header, pDeliveryIp4Header->HeaderLength * sizeof(DWORD));
    pDeliveryIp4Header->HeaderChecksum = RtlUshortByteSwap(pDeliveryIp4Header->HeaderChecksum);
}

static BOOLEAN _WriteEncapsulation(_In_ const OVS_ENCAPSULATOR* pEncapsulator, _Inout_ OVS_INNER_ENCAPSULATOR_DATA* pData, ULONG payloadLength)
{
    LONG to_write = 0;
    OVS_IPV4_HEADER ipv4DeliveryHeader = { 0 };
    ULONG bufferSize = 0;
    BYTE* writeBuffer = NULL;
    UINT16 protocolType = 0;
    VOID* pEncHeader = NULL;
    OVS_IPV4_HEADER* pIpv4PayloadHeader = NULL;
    ULONG encapHeaderSize = 0;
    BOOLEAN haveChecksum = FALSE;
    const OF_PI_IPV4_TUNNEL* pTunnelInfo;

    pTunnelInfo = pData->pTunnelInfo;

    //udp is included in encapHeaderSize, for vxlan
    encapHeaderSize = pData->encBytesNeeded - sizeof(OVS_ETHERNET_HEADER) - sizeof(OVS_IPV4_HEADER);

    //buffer size = (eth_h + ipv4_h + gre_h / vxlan_h) + payload_eth_h
    bufferSize = sizeof(OVS_ETHERNET_HEADER) + pData->encBytesNeeded;

    //the protocol of the payload packet
    protocolType = RtlUshortByteSwap(pData->pPayloadEthHeader->type);

    //the buffer where to write to
    writeBuffer = NdisGetDataBuffer(pData->pNb, bufferSize, NULL, 1, 0);
    OVS_CHECK(writeBuffer);

    //1. delivery eth frame: always write a standard eth header (non-vlan)
    RtlCopyMemory(writeBuffer, pData->pDeliveryEthHeader, sizeof(OVS_ETHERNET_HEADER));
    OVS_CHECK(pData->pDeliveryEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4));
    writeBuffer += sizeof(OVS_ETHERNET_HEADER);

    //2. Add the Ipv4 - delivery protocol.
    _BuildOuterIpv4Header(/*in*/pTunnelInfo, /*out*/ &ipv4DeliveryHeader, payloadLength, encapHeaderSize, pData->encapProtocol);
    to_write = sizeof(OVS_IPV4_HEADER);

    RtlCopyMemory(writeBuffer, &ipv4DeliveryHeader, to_write);
    writeBuffer += to_write;

    //3. Add the encapsulation header. TODO: GRE size will be variable, and GRE header will need to be returned by _BuildGreHeader()
    pEncHeader = pEncapsulator->BuildEncapsulationHeader(pTunnelInfo, pData->pPortOptions, payloadLength, encapHeaderSize, &haveChecksum);
    if (!pEncHeader)
    {
        DEBUGP(LOG_ERROR, "BuildGreHeader failed!\n");
        return FALSE;
    }

    to_write = encapHeaderSize;
    RtlCopyMemory(writeBuffer, pEncHeader, to_write);
    KFree(pEncHeader);

    pEncHeader = writeBuffer;

    writeBuffer += to_write;

    //4. write payload eth header
    //TODO: no need to copy the payload eth header: it's the original!!
    RtlCopyMemory(writeBuffer, pData->pPayloadEthHeader, sizeof(OVS_ETHERNET_HEADER));
    writeBuffer += sizeof(OVS_ETHERNET_HEADER); //this must be done: ip header is retrieved below

    //E. modify ip protocol header
    if (protocolType == OVS_ETHERTYPE_IPV4)
    {
        pIpv4PayloadHeader = (OVS_IPV4_HEADER*)writeBuffer;

        pIpv4PayloadHeader->DontFragment = (pTunnelInfo->tunnelFlags & OVS_TUNNEL_FLAG_DONT_FRAGMENT ? 1 : 0);

        //NORMALLY we wouldn't worry about the payload ip header's checksum, because the checksum offloading mechanism requires the
        //NET_BUFFER_LIST to have NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO field completed CORRECTLY.
        //However, we have two problems:
        //1) the ipv4 header (which becomes payload here) comes with an invalid checksum, and the NBL info does not specify checksum offloading for Ip header
        //2) when we send packets to the userspace, we cannot ATM send the associated NBL info, so the checksum offloading info is lost.
        //TODO: given this case, it is of CRITICAL importance to either send to userspace the NBL info as well, or,
        //handle the packet requirements (checksum offloading, LSO) -- if possible, before sending to userspace.
        pIpv4PayloadHeader->HeaderChecksum = 0;

        pIpv4PayloadHeader->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pIpv4PayloadHeader, pIpv4PayloadHeader->HeaderLength * sizeof(DWORD));
        pIpv4PayloadHeader->HeaderChecksum = RtlUshortByteSwap(pIpv4PayloadHeader->HeaderChecksum);
    }

    if (haveChecksum)
    {
        pEncapsulator->ComputeChecksum(pEncHeader, encapHeaderSize, payloadLength);
    }

    //D. Here, the next byte must be the start of the payload.

    return TRUE;
}

static BOOLEAN _Encaps_EncapsulateNb(_In_ const OVS_ENCAPSULATOR* pEncapsulator, _Inout_ OVS_INNER_ENCAPSULATOR_DATA* pData)
{
    ULONG usedLength = 0, newUsedLength = 0;
    ULONG unusedLength = 0, newUnusedLength = 0;
    NDIS_STATUS status = STATUS_SUCCESS;
    ULONG deltaSize = 0;
    BOOLEAN ok = TRUE;
    NET_BUFFER* pNb = 0;

    pNb = pData->pNb;

    usedLength = NET_BUFFER_DATA_LENGTH(pNb);
    unusedLength = NET_BUFFER_DATA_OFFSET(pNb);

    deltaSize = pData->encBytesNeeded;

    //NOTE: this retreat must NOT allocate any memory / mdl-s.
    //We expect the "unused space" to be sufficient enough.
    OVS_CHECK(unusedLength >= deltaSize);

    status = NdisRetreatNetBufferDataStart(pNb, deltaSize, 0, NULL);
    if (status != STATUS_SUCCESS)
    {
        DEBUGP(LOG_ERROR, "could not retreat net buffer by %d bytes!\n", deltaSize);
        return FALSE;
    }

    newUsedLength = NET_BUFFER_DATA_LENGTH(pNb);
    newUnusedLength = NET_BUFFER_DATA_OFFSET(pNb);

    OVS_CHECK(newUsedLength > usedLength);
    OVS_CHECK(newUnusedLength <= unusedLength);

    //NOTE: we do not advance

    ok = _WriteEncapsulation(pEncapsulator, pData, /*payload len*/ usedLength);
    if (!ok)
    {
        return FALSE;
    }

    return TRUE;
}

//there must be one NET_BUFFER_LIST in pOvsNb, with one NET_BUFFER (if the packet was not fragmented)
//or one NET_BUFFER_LIST with multiple NET_BUFFER-s, for the case where the packet was fragmented by us
//its buffer must begin with the ethernet header.
_Use_decl_annotations_
BOOLEAN Encaps_EncapsulateOnb(const OVS_ENCAPSULATOR* pEncapsulator, OVS_OUTER_ENCAPSULATION_DATA* pData)
{
    ULONG len = 0;
    BOOLEAN ok = TRUE;
    OVS_NET_BUFFER* pOvsNb;
    OVS_INNER_ENCAPSULATOR_DATA innerData;
    LE16 ethType = 0;

    pOvsNb = pData->pOvsNb;
    OVS_CHECK(pOvsNb->pNbl->Next == NULL);

    innerData.pPayloadEthHeader = pData->pPayloadEthHeader;
    innerData.pDeliveryEthHeader = pData->pDeliveryEthHeader;
    innerData.pTunnelInfo = pOvsNb->pTunnelInfo;
    innerData.encapProtocol = pData->encapProtocol;
    innerData.isFromExternal = pData->isFromExternal;
    innerData.encBytesNeeded = pData->encapsHeadersSize;
    innerData.pPortOptions = pOvsNb->pDestinationPort->pOptions;

    len = ONB_GetDataLength(pOvsNb);

    //NOTE: we assume the eth header of the payload is not vlan (i.e. vlan header must have been extracted, if it existed)
    OVS_CHECK(len + innerData.encBytesNeeded <= pData->mtu + sizeof(OVS_ETHERNET_HEADER));

    ethType = ReadEthernetType(pData->pPayloadEthHeader);

    HandleChecksumOffload(pOvsNb, innerData.isFromExternal, innerData.encBytesNeeded, pData->mtu);

    for (NET_BUFFER* pNb = NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        innerData.pNb = pNb;

        ok = _Encaps_EncapsulateNb(pEncapsulator, &innerData);
        if (!ok)
        {
            return FALSE;
        }
    }

    DbgPrintOnbFrames(pOvsNb, "after encapsulation");

    return TRUE;
}

BOOLEAN Encaps_ComputeOuterEthHeader(_In_ const BYTE externalMacAddress[OVS_ETHERNET_ADDRESS_LENGTH], _In_ BYTE ipTargetOuter[4], _Inout_ OVS_ETHERNET_HEADER* pEthHeader)
{
    const BYTE* pDestHypervisorMac = Arp_FindTableEntry(ipTargetOuter);
    if (!pDestHypervisorMac)
    {
        DEBUGP(LOG_ERROR, "Could not find dest eth addr for hypervisor of ip %d.%d.%d.%d\n", ipTargetOuter[0], ipTargetOuter[1], ipTargetOuter[2], ipTargetOuter[3]);

        ONB_OriginateArpRequest(ipTargetOuter);
        return FALSE;
    }

    pEthHeader->type = RtlUshortByteSwap(OVS_ETHERTYPE_IPV4);
    RtlCopyMemory(pEthHeader->source_addr, externalMacAddress, OVS_ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(pEthHeader->destination_addr, pDestHypervisorMac, OVS_ETHERNET_ADDRESS_LENGTH);

    return TRUE;
}

static BOOLEAN _Encaps_DecapsulateOnb(_In_ const OVS_DECAPSULATOR* pDecapsulator, _Inout_ OVS_DECAPSULATION_DATA* pData)
{
    //IT IS GRE. No need to check against that.
    ULONG offset = 0;
    const OVS_IPV4_HEADER* pIpv4Header = NULL;
    const VOID* pEncapHeader = NULL;
    ULONG ethSize = 0;
    ULONG ipPayloadLen = 0;
    BOOLEAN ok = FALSE;
    OF_PI_IPV4_TUNNEL* pTunnelInfo;

    /*
      VXLAN:
      * The outer VLAN tag is optional. If present, it may be used
      * for delineating VXLAN traffic on the LAN.
      */

    /*
      NVGRE:
      * The outer VLAN tag information is optional and can be used for traffic
      * management and broadcast scalability on the physical network.
      */

    //NOTE: however, we expect the vlan to have been popped by the hyper-v switch,
    //so when we get here, we should never have an eth header qtagged

    //TODO: the payload's TTL MUST be decremented (if one exists)
    //(It might be that the need to do that was only in GRE1701 with routing... must check again the RFC)

    ethSize = sizeof(OVS_ETHERNET_HEADER);

    //A. ETHERNET
    if (pData->pOuterEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        DEBUGP(LOG_ERROR, "packet decapsulation: did not expect eth qtagged frame!\n");
        return FALSE;
    }

    offset += ethSize;

    pTunnelInfo = pData->pTunnelInfo;

    //B. IP DELIVERY
    pIpv4Header = ReadIpv4Header(pData->pOuterEthHeader);
    offset += pIpv4Header->HeaderLength * sizeof(DWORD);

    OVS_CHECK(pIpv4Header->Protocol == pData->encapProtocolType);

    //C. ENCAP HEADER
    pEncapHeader = AdvanceIpv4Header(pIpv4Header);

    ipPayloadLen = RtlUshortByteSwap(pIpv4Header->TotalLength) - pIpv4Header->HeaderLength * sizeof(DWORD);

    ok = pDecapsulator->ReadEncapsHeader(pEncapHeader, &offset, ipPayloadLen, pTunnelInfo);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, "reading encaps header failed\n");
        return FALSE;
    }

    pTunnelInfo->ipv4Destination = pIpv4Header->DestinationAddress.S_un.S_addr;
    pTunnelInfo->ipv4Source = pIpv4Header->SourceAddress.S_un.S_addr;
    pTunnelInfo->ipv4TimeToLive = pIpv4Header->TimeToLive;
    pTunnelInfo->ipv4TypeOfService = pIpv4Header->TypeOfServiceAndEcnField;

    if (pIpv4Header->DontFragment)
    {
        pTunnelInfo->tunnelFlags |= OVS_TUNNEL_FLAG_DONT_FRAGMENT;
    }

    ONB_Advance(pData->pOvsNb, offset);

    DbgPrintOnbFrames(pData->pOvsNb, "decapsulated onb\n");

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN Encaps_DecapsulateOnb(const OVS_DECAPSULATOR* pDecapsulator, OVS_NET_BUFFER* pOvsNb, OF_PI_IPV4_TUNNEL* pTunnelInfo, BYTE encapProtocolType)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL, ethHeader = { 0 };
    BOOLEAN ok = TRUE;
    OVS_DECAPSULATION_DATA decapsData = { 0 };

    OVS_CHECK(NET_BUFFER_LIST_NEXT_NBL(pOvsNb->pNbl) == NULL);
    OVS_CHECK(NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl)) == NULL);

    pEthHeader = ONB_GetDataOfSize(pOvsNb, sizeof(OVS_ETHERNET_HEADER));
    OVS_CHECK(pEthHeader);

    RtlCopyMemory(&ethHeader, pEthHeader, sizeof(OVS_ETHERNET_HEADER));

    DbgPrintOnbFrames(pOvsNb, "before decapsulation\n");

    decapsData.pOuterEthHeader = pEthHeader;
    decapsData.pOvsNb = pOvsNb;
    decapsData.pTunnelInfo = pTunnelInfo;
    decapsData.encapProtocolType = encapProtocolType;

    ok = _Encaps_DecapsulateOnb(pDecapsulator, &decapsData);

    if (ok)
    {
        DbgPrintOnbFrames(pOvsNb, "after gre decapsulation\n");
    }

    return ok;
}

_Use_decl_annotations_
const OVS_DECAPSULATOR* Encap_FindDecapsulator(NET_BUFFER* pNb, BYTE* pEncapProtoType, LE16* pUdpDestPort)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    VOID* pPacketBuffer = NULL;
    const OVS_DECAPSULATOR* pDecapsulator = NULL;

    OVS_CHECK(pEncapProtoType);

    pPacketBuffer = NdisGetDataBuffer(pNb, sizeof(OVS_ETHERNET_HEADER), NULL, 1, 0);
    //the eth header of a packet cannot be fragmented, therefore pPacketBuffer cannot be NULL here
    OVS_CHECK(pPacketBuffer);
    if (!pPacketBuffer)
    {
        return NULL;
    }

    pEthHeader = pPacketBuffer;

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        DEBUGP(LOG_ERROR, "Find Decapsulator: did not expect eth qtagged frame!\n");
        return NULL;
    }

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IPV4_HEADER* pIpv4Header = NULL;
        VOID* pAllocBuffer = NULL;

        pPacketBuffer = GetNbBufferData(pNb, &pAllocBuffer);
        pEthHeader = pPacketBuffer;

        pIpv4Header = ReadIpv4Header(pEthHeader);

        if (pIpv4Header->Protocol == OVS_IPPROTO_GRE)
        {
            *pEncapProtoType = OVS_IPPROTO_GRE;
            pDecapsulator = Encap_GetDecapsulator_Gre();
        }
        else if (pIpv4Header->Protocol == OVS_IPPROTO_UDP)
        {
            OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)AdvanceIpv4Header(pIpv4Header);
            OVS_OFPORT* pPort = NULL;

            pPort = OFPort_FindVxlan_Ref(RtlUshortByteSwap(pUdpHeader->destinationPort));

            if (pPort)
            {
                if (pUdpDestPort)
                {
                    *pUdpDestPort = RtlUshortByteSwap(pUdpHeader->destinationPort);
                }

                *pEncapProtoType = OVS_IPPROTO_UDP;
                pDecapsulator = Encap_GetDecapsulator_Vxlan();

                OVS_REFCOUNT_DEREFERENCE(pPort);
            }
        }

        KFree(pAllocBuffer);
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        //do nothing: it is not encapsulated, goes to the same ip dest
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_ARP))
    {
        //do nothing: it is not encapsulated, goes to the same ip dest
    }
    else
    {
        //do nothing: it is not encapsulated, goes to the same ip dest
    }

    return pDecapsulator;
}