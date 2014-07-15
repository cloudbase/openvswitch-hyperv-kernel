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

#include "Ipv6.h"
#include "OvsNetBuffer.h"
#include "Tcp.h"
#include "Udp.h"
#include "Checksum.h"
#include "PacketInfo.h"
#include "Frame.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Igmp.h"

OVS_IPV6_HEADER* GetIpv6Header(VOID* pPacketBuffer)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pPacketBuffer;
    OVS_IPV6_HEADER* pIpv6Header = NULL;
    UINT32 ver = 0;

    OVS_CHECK(pEthHeader);

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        pEthHeader = (OVS_ETHERNET_HEADER*)((BYTE*)pEthHeader + OVS_ETHERNET_VLAN_LEN);
    }

    if (pEthHeader->type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        return FALSE;
    }

    pIpv6Header = (OVS_IPV6_HEADER*)((BYTE*)pEthHeader + sizeof(OVS_ETHERNET_HEADER));

    ver = GetIpv6Version(pIpv6Header->vcf);
    OVS_CHECK(ver == 0x06);

    return pIpv6Header;
}

static void _Ipv6_SetAddress(OVS_NET_BUFFER* pOvsNb, UINT8 protocol, BE32 oldAddress[4], const BE32 newAddress[4], BOOLEAN recomputeChecksum)
{
    if (recomputeChecksum)
    {
        VOID* buffer = ONB_GetData(pOvsNb);
        UINT16 csumRecomp = 0;

        if (protocol == IPPROTO_TCP)
        {
            OVS_TCP_HEADER* pTcpHeader = GetTcpHeader(buffer);

            csumRecomp = (UINT16)RecomputeChecksum((BYTE*)oldAddress, (BYTE*)newAddress, 16, pTcpHeader->checksum);
            csumRecomp = RtlUshortByteSwap(csumRecomp);
            pTcpHeader->checksum = csumRecomp;
        }
        else if (protocol == IPPROTO_UDP)
        {
            OVS_UDP_HEADER* pUdpHeader = GetUdpHeader(buffer);

            //for udp, if checksum == 0, it means it was not computed
            //if the result of the checksum computation for udp is 0, the checksum must be set to 0xFFFF
            if (pUdpHeader->checksum)
            {
                csumRecomp = (UINT16)RecomputeChecksum((BYTE*)oldAddress, (BYTE*)newAddress, 16, pUdpHeader->checksum);
                csumRecomp = RtlUshortByteSwap(csumRecomp);
                pUdpHeader->checksum = csumRecomp;

                if (!pUdpHeader->checksum)
                {
                    pUdpHeader->checksum = OVS_UDP_CHECKSUM_MANGLED;
                }
            }
        }
    }

    RtlCopyMemory(oldAddress, newAddress, sizeof(BE32[4]));
}

BOOLEAN ONB_SetIpv6(OVS_NET_BUFFER* pOvsNb, const OVS_PI_IPV6* pIpv6Info)
{
    OVS_IPV6_HEADER* pIpv6Header = NULL;
    BE32* pSourceAddress = NULL;
    BE32* pDestinationAddress = NULL;

    VOID* buffer = ONB_GetData(pOvsNb);

    pIpv6Header = GetIpv6Header(buffer);
    pSourceAddress = (BE32 *)&pIpv6Header->sourceAddress;
    pDestinationAddress = (BE32 *)&pIpv6Header->destinationAddress;

    if (memcmp(pIpv6Info->source, pSourceAddress, sizeof(pIpv6Info->source)) != 0)
    {
        _Ipv6_SetAddress(pOvsNb, pIpv6Info->protocol, pSourceAddress, pIpv6Info->source, TRUE);
    }

    if (memcmp(pIpv6Info->destination, pDestinationAddress, sizeof(pIpv6Info->destination)) != 0)
    {
        BOOLEAN recomputeChecksum = TRUE;

        if (IsIpv6Extension(pIpv6Header->nextHeader))
        {
            BYTE extensionType = 0;

            recomputeChecksum = FALSE;
            buffer = GetFirstIpv6Extension(pIpv6Header, &extensionType);

            while (IsIpv6Extension(extensionType))
            {
                if (extensionType == OVS_IPV6_EXTH_ROUTING)
                {
                    OVS_IPV6_ROUTING_HEADER* pRoutingHeader = (OVS_IPV6_ROUTING_HEADER*)buffer;

                    if (pRoutingHeader->segmentsLeft > 0)
                    {
                        recomputeChecksum = TRUE;
                        break;
                    }
                }

                buffer = GetNextIpv6Extension(buffer, &extensionType);
            }
        }

        _Ipv6_SetAddress(pOvsNb, pIpv6Info->protocol, pDestinationAddress, pIpv6Info->destination, recomputeChecksum);
    }

    SetIpv6TrafficClass(pIpv6Info->trafficClass, &pIpv6Header->vcf);
    pIpv6Header->hopLimit = pIpv6Info->highLimit;
    SetIpv6FlowLabel(RtlUlongByteSwap(pIpv6Info->label), &pIpv6Header->vcf);

    return TRUE;
}

static BYTE* _VerifyHopByHopExtension(_In_ BYTE* buffer, _Inout_ ULONG* pLength)
{
    BYTE* pAdvancedBuffer = buffer;
    ULONG offset = 0;

    BYTE nextHeaderType = *buffer;
    BYTE headerLength = *(sizeof(nextHeaderType) + buffer);
    BYTE optionType = *(sizeof(nextHeaderType) + sizeof(headerLength) + buffer);

    UNREFERENCED_PARAMETER(optionType);

    offset = headerLength + 8;

    if (*pLength < offset)
    {
        DEBUGP(LOG_ERROR, "hop by hop ext: size left = 0x%x != ext size = 0x%x", *pLength, offset);
        return NULL;
    }

    pAdvancedBuffer = pAdvancedBuffer + offset;
    *pLength = *pLength - offset;

    return pAdvancedBuffer;
}

static BYTE* _VerifyRoutingExtension(_In_ BYTE* buffer, _Inout_ ULONG* pLength)
{
    BYTE* pAdvancedBuffer = buffer;
    ULONG offset;

    BYTE nextHeaderType = *buffer;
    BYTE headerLength = *(sizeof(nextHeaderType) + buffer);

    offset = headerLength + 8;

    if (*pLength < offset)
    {
        DEBUGP(LOG_ERROR, "routing ext: size left = 0x%x != ext size = 0x%x", *pLength, offset);
        return NULL;
    }

    pAdvancedBuffer = pAdvancedBuffer + offset;
    *pLength = *pLength - offset;

    return pAdvancedBuffer;
}

static BYTE* _VerifyFragmentationExtension(_In_ BYTE* buffer, _Inout_ ULONG* pLength)
{
    BYTE* pAdvancedBuffer = buffer;
    ULONG offset;

    BYTE headerLength = 8;

    offset = headerLength + 8;

    if (*pLength < offset)
    {
        DEBUGP(LOG_ERROR, "routing ext: size left = 0x%x != ext size = 0x%x", *pLength, offset);
        return NULL;
    }

    pAdvancedBuffer = pAdvancedBuffer + offset;
    *pLength = *pLength - offset;

    return pAdvancedBuffer;
}

static BYTE* _VerifyDestinationOpts(_In_ BYTE* buffer, _Inout_ ULONG* pLength)
{
    BYTE* pAdvancedBuffer = buffer;
    ULONG offset;

    BYTE nextHeaderType = *buffer;
    BYTE headerLength = *(sizeof(nextHeaderType) + buffer);
    BYTE optionType = *(sizeof(nextHeaderType) + sizeof(headerLength) + buffer);

    UNREFERENCED_PARAMETER(optionType);

    offset = headerLength + 8;

    if (*pLength < offset)
    {
        DEBUGP(LOG_ERROR, "destination opts: size left = 0x%x != ext size = 0x%x", *pLength, offset);
        return NULL;
    }

    pAdvancedBuffer = pAdvancedBuffer + offset;
    *pLength = *pLength - offset;

    return pAdvancedBuffer;
}

BYTE* VerifyIpv6Extension(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ BYTE* pProtoType)
{
    BYTE* advancedBuffer = buffer;
    BYTE nextHeaderType = *pProtoType;

    //TODO: check ip addr: multicast / broadcast

    //TOCO: check total size: advance the buffer to get to the payload.

    OVS_CHECK(buffer);

anotherHeader:
    switch (nextHeaderType)
    {
    case OVS_IPV6_EXTH_HOPBYHOP:
        nextHeaderType = *advancedBuffer;

        advancedBuffer = _VerifyHopByHopExtension(buffer, pLength);
        if (!advancedBuffer)
        {
            return NULL;
        }

        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_ROUTING:
        nextHeaderType = *advancedBuffer;

        advancedBuffer = _VerifyRoutingExtension(buffer, pLength);
        if (!advancedBuffer)
        {
            return NULL;
        }

        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_FRAGMENTATION:
        nextHeaderType = *advancedBuffer;

        advancedBuffer = _VerifyFragmentationExtension(buffer, pLength);
        if (!advancedBuffer)
        {
            return NULL;
        }

        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_DESTINATION_OPTS:
        nextHeaderType = *advancedBuffer;

        advancedBuffer = _VerifyDestinationOpts(buffer, pLength);
        if (!advancedBuffer)
        {
            return NULL;
        }

        goto anotherHeader;
        break;

    default:
        *pProtoType = nextHeaderType;
        return advancedBuffer;
    }
}

OVS_IPV6_HEADER* ReadIpv6Header(_In_ OVS_ETHERNET_HEADER* pEthHeader)
{
    UINT8* buffer = (UINT8*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER);

    OVS_IPV6_HEADER* pIpv6Header = (OVS_IPV6_HEADER*)buffer;
    OVS_CHECK(pIpv6Header);

    return pIpv6Header;
}

VOID* GetFirstIpv6Extension(_In_ const OVS_IPV6_HEADER* pIpv6Header, _Out_ BYTE* pNextExtensionType)
{
    VOID* advancedBuffer = AdvanceIpv6Header(pIpv6Header);
    *pNextExtensionType = pIpv6Header->nextHeader;

    return advancedBuffer;
}

VOID* GetNextIpv6Extension(_In_ VOID* buffer, _Inout_ BYTE* pExtensionType)
{
    BYTE extensionType = *pExtensionType;
    BYTE headerLength = 0;
    BYTE optionType = 0;

    switch (extensionType)
    {
    case OVS_IPV6_EXTH_HOPBYHOP:
        extensionType = *((BYTE*)buffer);
        headerLength = *(sizeof(extensionType) + (BYTE*)buffer);
        optionType = *(sizeof(extensionType) + sizeof(headerLength) + (BYTE*)buffer);
        buffer = ((BYTE*)buffer) + headerLength + 8;
        break;

    case OVS_IPV6_EXTH_IPIP:
        break;

    case OVS_IPV6_EXTH_EGP:
        break;

    case OVS_IPV6_EXTH_IP6:
        break;

    case OVS_IPV6_EXTH_ROUTING:
        extensionType = *((BYTE*)buffer);
        headerLength = *(sizeof(extensionType) + (BYTE*)buffer);
        buffer = ((BYTE*)buffer) + headerLength + 8;
        break;

    case OVS_IPV6_EXTH_FRAGMENTATION:
        extensionType = *((BYTE*)buffer);
        headerLength = 8;
        buffer = ((BYTE*)buffer) + headerLength + 8;
        break;

    case OVS_IPV6_EXTH_RSVP:
        break;

    case OVS_IPV6_EXTH_ESP:
        break;

    case OVS_IPV6_EXTH_AH:
        break;

    case OVS_IPV6_EXTH_ICMP6:
        ReadIcmp6Header(buffer);
        break;

    case OVS_IPV6_EXTH_NONE:
        break;

    case OVS_IPV6_EXTH_DESTINATION_OPTS:
        extensionType = *((BYTE*)buffer);
        headerLength = *(sizeof(extensionType) + (BYTE*)buffer);
        optionType = *(sizeof(extensionType) + sizeof(headerLength) + (BYTE*)buffer);
        buffer = ((BYTE*)buffer) + headerLength + 8;
        break;

    case OVS_IPV6_EXTH_ICMP4:
        DbgPrintIcmpHeader(buffer);
        break;

    case OVS_IPV6_EXTH_TCP:
        DbgPrintTcpHeader(buffer);
        break;

    case OVS_IPV6_EXTH_UDP:
        DbgPrintUdpHeader(buffer);
        break;

    case OVS_IPV6_EXTH_IGMP4:
        DbgPrintIgmpHeader(buffer);
        break;

    default:
        OVS_CHECK(0);
    }

    *pExtensionType = extensionType;

    return buffer;
}

void ReadIpv6ProtocolFrame(_In_ OVS_IPV6_HEADER* pIpv6Header)
{
    VOID* advancedBuffer = AdvanceIpv6Header(pIpv6Header);
    BYTE nextHeader = pIpv6Header->nextHeader;
    BYTE headerLength = 0;
    BYTE optionType = 0;

    //TODO: check ip addr: multicast / broadcast

    //TOCO: check total size: advance the buffer to get to the payload.

    OVS_CHECK(pIpv6Header);
anotherHeader:

    switch (nextHeader)
    {
    case OVS_IPV6_EXTH_HOPBYHOP:
        nextHeader = *((BYTE*)advancedBuffer);
        headerLength = *(sizeof(nextHeader) + (BYTE*)advancedBuffer);
        optionType = *(sizeof(nextHeader) + sizeof(headerLength) + (BYTE*)advancedBuffer);
        advancedBuffer = ((BYTE*)advancedBuffer) + headerLength + 8;
        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_IPIP:
        break;

    case OVS_IPV6_EXTH_EGP:
        break;

    case OVS_IPV6_EXTH_IP6:
        break;

    case OVS_IPV6_EXTH_ROUTING:
        nextHeader = *((BYTE*)advancedBuffer);
        headerLength = *(sizeof(nextHeader) + (BYTE*)advancedBuffer);
        advancedBuffer = ((BYTE*)advancedBuffer) + headerLength + 8;
        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_FRAGMENTATION:
        nextHeader = *((BYTE*)advancedBuffer);
        headerLength = 8;
        advancedBuffer = ((BYTE*)advancedBuffer) + headerLength + 8;
        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_RSVP:
        break;

    case OVS_IPV6_EXTH_ESP:
        break;

    case OVS_IPV6_EXTH_AH:
        break;

    case OVS_IPV6_EXTH_ICMP6:
        ReadIcmp6Header(advancedBuffer);
        break;

    case OVS_IPV6_EXTH_NONE:
        break;

    case OVS_IPV6_EXTH_DESTINATION_OPTS:
        nextHeader = *((BYTE*)advancedBuffer);
        headerLength = *(sizeof(nextHeader) + (BYTE*)advancedBuffer);
        optionType = *(sizeof(nextHeader) + sizeof(headerLength) + (BYTE*)advancedBuffer);
        advancedBuffer = ((BYTE*)advancedBuffer) + headerLength + 8;
        goto anotherHeader;
        break;

    case OVS_IPV6_EXTH_ICMP4:
        DbgPrintIcmpHeader(advancedBuffer);
        break;

    case OVS_IPV6_EXTH_TCP:
        DbgPrintTcpHeader(advancedBuffer);
        break;

    case OVS_IPV6_EXTH_UDP:
        DbgPrintUdpHeader(advancedBuffer);
        break;

    case OVS_IPV6_EXTH_IGMP4:
        DbgPrintIgmpHeader(advancedBuffer);
        break;

    default:
        OVS_CHECK(0);
    }
}

BYTE* VerifyIpv6Frame(BYTE* buffer, ULONG* pLength, BYTE* pProtoType)
{
    OVS_IPV6_HEADER* pIpv6Header = (OVS_IPV6_HEADER*)buffer;
    UINT32 version = 0;

    if (*pLength < sizeof(OVS_IPV6_HEADER))
    {
        DEBUGP(LOG_ERROR, "size left: 0x%x is less than sizeof ipv6 header = 0x%x", *pLength, sizeof(OVS_IPV6_HEADER));
        return NULL;
    }

    version = GetIpv6Version(pIpv6Header->vcf);
    if (version != 0x06)
    {
        DEBUGP(LOG_ERROR, "ipv6 version is 0x%x; expected 0x06", version);
        return NULL;
    }

    *pLength -= sizeof(OVS_IPV6_HEADER);
    *pProtoType = pIpv6Header->nextHeader;

    return buffer + sizeof(OVS_IPV6_HEADER);
}

VOID FillTransportPseudoHeader_FromIpv6(_In_ const BYTE srcIp[16], _In_ const BYTE dstIp[16], BYTE proto, ULONG tcpLen, _Out_ OVS_TRANSPORT_PSEUDO_HEADER_IPV6* pPseudoHeader)
{
    OVS_CHECK(pPseudoHeader);

    OVS_CHECK(proto == OVS_IPPROTO_TCP ||
        proto == OVS_IPPROTO_UDP ||
        proto == OVS_IPPROTO_SCTP ||
        proto == OVS_IPV6_EXTH_ICMP6);

    RtlCopyMemory(pPseudoHeader->srcIp, srcIp, 16);
    RtlCopyMemory(pPseudoHeader->destIp, dstIp, 16);
    pPseudoHeader->reserved = 0;
    pPseudoHeader->protocol = proto;

    pPseudoHeader->tcpLen = RtlUshortByteSwap(tcpLen);
}

VOID* Ipv6_FindExtensionHeader(_In_ const OVS_IPV6_HEADER* pIpv6Header, BYTE extType, ULONG* pExtensionsLength)
{
    BYTE protocolType = 0;
    VOID* extBuffer = NULL;
    ULONG extLens = 0;

    OVS_CHECK(pIpv6Header);

    extBuffer = GetFirstIpv6Extension(pIpv6Header, &protocolType);

    if (protocolType == extType)
    {
        if (pExtensionsLength)
        {
            *pExtensionsLength = extLens;
        }
        return extBuffer;
    }

    while (IsIpv6Extension(protocolType))
    {
        BYTE extLen = GetIpv6ExtensionLength(extBuffer);
        extLens += extLen;

        if (protocolType == extType)
        {
            if (pExtensionsLength)
            {
                *pExtensionsLength = extLens;
            }
            return extBuffer;
        }

        extBuffer = GetNextIpv6Extension(extBuffer, &protocolType);
    }

    return NULL;
}

ULONG Ipv6_HeaderSize(_In_ const OVS_IPV6_HEADER* pIpv6Header)
{
    BYTE protocolType = 0;
    VOID* extBuffer = NULL;
    ULONG totalHeaderSize = sizeof(OVS_IPV6_HEADER);

    OVS_CHECK(pIpv6Header);

    extBuffer = GetFirstIpv6Extension(pIpv6Header, &protocolType);

    while (IsIpv6Extension(protocolType))
    {
        BYTE extLen = GetIpv6ExtensionLength(extBuffer);

        totalHeaderSize += extLen;

        extBuffer = GetNextIpv6Extension(extBuffer, &protocolType);
    }

    return totalHeaderSize;
}