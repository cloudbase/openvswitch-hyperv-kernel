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

#include "Ipv4.h"
#include "OvsNetBuffer.h"
#include "PacketInfo.h"

#include "Tcp.h"
#include "Udp.h"
#include "Checksum.h"
#include "Gre.h"
#include "Icmp.h"
#include "Icmp6.h"
#include "Igmp.h"

OVS_IPV4_HEADER* GetIpv4Header(VOID* pPacketBuffer)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pPacketBuffer;
    OVS_IPV4_HEADER* pIpv4Header = NULL;

    OVS_CHECK(pEthHeader);

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        pEthHeader = (OVS_ETHERNET_HEADER*)((BYTE*)pEthHeader + OVS_ETHERNET_VLAN_LEN);
    }

    if (pEthHeader->type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        return FALSE;
    }

    pIpv4Header = (OVS_IPV4_HEADER*)((BYTE*)pEthHeader + sizeof(OVS_ETHERNET_HEADER));

    OVS_CHECK(pIpv4Header->Version == 0x04);
    OVS_CHECK(pIpv4Header->HeaderLength >= 5);

    return pIpv4Header;
}

static void _Ipv4_SetAddress(VOID* buffer, OVS_IPV4_HEADER* pIpv4Header, BE32* pIpAddress, BE32 newIpAddress)
{
    UINT16 csumRecomp = 0;

    if (pIpv4Header->Protocol == IPPROTO_TCP)
    {
        OVS_TCP_HEADER* pTcpHeader = GetTcpHeader(buffer);
        csumRecomp = (WORD)RecomputeChecksum((BYTE*)pIpAddress, (BYTE*)&newIpAddress, OVS_IPV4_ADDRESS_LENGTH, pTcpHeader->checksum);
        csumRecomp = RtlUshortByteSwap(csumRecomp);
        pTcpHeader->checksum = csumRecomp;
    }

    else if (pIpv4Header->Protocol == IPPROTO_UDP)
    {
        OVS_UDP_HEADER* pUdpHeader = GetUdpHeader(buffer);

        //for udp, if checksum == 0, it means it was not computed
        //if the result of the checksum computation for udp is 0, the checksum must be set to 0xFFFF
        if (pUdpHeader->checksum)
        {
            csumRecomp = (WORD)RecomputeChecksum((BYTE*)pIpAddress, (BYTE*)&newIpAddress, OVS_IPV4_ADDRESS_LENGTH, pUdpHeader->checksum);
            csumRecomp = RtlUshortByteSwap(csumRecomp);
            pUdpHeader->checksum = csumRecomp;

            if (!pUdpHeader->checksum)
            {
                pUdpHeader->checksum = OVS_UDP_CHECKSUM_MANGLED;
            }
        }
    }

    csumRecomp = (WORD)RecomputeChecksum((BYTE*)pIpAddress, (BYTE*)&newIpAddress, OVS_IPV4_ADDRESS_LENGTH, pIpv4Header->HeaderChecksum);
    csumRecomp = RtlUshortByteSwap(csumRecomp);
    pIpv4Header->HeaderChecksum = csumRecomp;

    *pIpAddress = newIpAddress;
}

static void _Ipv4_SetTos(OVS_IPV4_HEADER* pIpv4Header, UINT8 mask, UINT8 value)
{
    UINT32 checksum = 0;
    UINT8 tos = 0;

    checksum = RtlUshortByteSwap((BE16)pIpv4Header->HeaderChecksum);

    tos = pIpv4Header->TypeOfServiceAndEcnField & mask;
    tos |= value;

    checksum += pIpv4Header->TypeOfServiceAndEcnField;

    if ((checksum + 1) >> 16)
    {
        ++checksum;
        checksum &= 0xffff;
    }

    checksum -= tos;
    checksum += checksum >> 16;

    pIpv4Header->HeaderChecksum = (UINT16)RtlUshortByteSwap(checksum);
    pIpv4Header->TypeOfServiceAndEcnField = tos;
}

static void _Ipv4_SetTtl(OVS_IPV4_HEADER* pIpv4Header, UINT8 newTtl)
{
    WORD oldData = 0, newData = 0;
    WORD csumRecomp = 0;

    oldData = pIpv4Header->TimeToLive << 8;
    oldData = RtlUshortByteSwap(oldData);

    newData = newTtl << 8;
    newData = RtlUshortByteSwap(newData);

    csumRecomp = (WORD)RecomputeChecksum((BYTE*)&oldData, (BYTE*)&newData, 2, pIpv4Header->HeaderChecksum);
    csumRecomp = RtlUshortByteSwap(csumRecomp);

    pIpv4Header->HeaderChecksum = csumRecomp;

    pIpv4Header->TimeToLive = newTtl;
}

BOOLEAN ONB_SetIpv4(OVS_NET_BUFFER* pOvsNb, const OVS_PI_IPV4* pIpv4Info)
{
    OVS_IPV4_HEADER* pIpv4Header = NULL;
    VOID* buffer = ONB_GetData(pOvsNb);

    pIpv4Header = GetIpv4Header(buffer);
    OVS_CHECK(pIpv4Header);

    if (pIpv4Info->source != pIpv4Header->SourceAddress.S_un.S_addr)
    {
        _Ipv4_SetAddress(buffer, pIpv4Header, (BE32*)&pIpv4Header->SourceAddress.S_un.S_addr, pIpv4Info->source);
    }

    if (pIpv4Info->destination != pIpv4Header->DestinationAddress.S_un.S_addr)
    {
        _Ipv4_SetAddress(buffer, pIpv4Header, (BE32*)&pIpv4Header->DestinationAddress.S_un.S_addr, pIpv4Info->destination);
    }

    if (pIpv4Info->tos != pIpv4Header->TypeOfService)
    {
        _Ipv4_SetTos(pIpv4Header, 0, pIpv4Info->tos);
    }

    if (pIpv4Info->ttl != pIpv4Header->TimeToLive)
    {
        _Ipv4_SetTtl(pIpv4Header, pIpv4Info->ttl);
    }

    return TRUE;
}

_Use_decl_annotations_
const OVS_IPV4_HEADER* ReadIpv4Header(const OVS_ETHERNET_HEADER* pEthHeader)
{
    UINT8* buffer = (UINT8*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER);

    OVS_IPV4_HEADER* pIpHeader = (OVS_IPV4_HEADER*)buffer;
    OVS_CHECK(pIpHeader);
    OVS_CHECK(pIpHeader->Version == 0x04);

    return pIpHeader;
}

_Use_decl_annotations_
void ReadIpv4ProtocolFrame(const OVS_IPV4_HEADER* pIpv4Header)
{
    const VOID* advancedBuffer = AdvanceIpv4Header(pIpv4Header);

    DbgPrintIpv4(pIpv4Header);

    //TODO: check ip addr: multicast / broadcast

    if (pIpv4Header->SourceAddress.S_un.S_un_b.s_b1 >= 224 &&
        pIpv4Header->SourceAddress.S_un.S_un_b.s_b1 <= 239)
    {
        DEBUGP_FRAMES(LOG_LOUD, "multicast ipv address\n");
    }

    //TOCO: check total size: advance the buffer to get to the payload.

    OVS_CHECK(pIpv4Header);

    switch (pIpv4Header->Protocol)
    {
    case OVS_IPPROTO_GRE:
        DbgPrintGreHeader(advancedBuffer);
        break;

    case OVS_IPPROTO_ICMP:
        DbgPrintIcmpHeader(advancedBuffer);
        break;

    case OVS_IPPROTO_TCP:
        DbgPrintTcpHeader(advancedBuffer);
        break;

    case OVS_IPPROTO_UDP:
        DbgPrintUdpHeader(advancedBuffer);
        break;

    case OVS_IPPROTO_IGMP:
        DbgPrintIgmpHeader(advancedBuffer);
        break;

    default:
        OVS_CHECK(0);
    }
}

BYTE* VerifyIpv4Frame(BYTE* buffer, ULONG* pLength, BYTE* pProtoType)
{
    OVS_IPV4_HEADER* pIpv4Header = (OVS_IPV4_HEADER*)buffer;
    ULONG ipv4Size = pIpv4Header->HeaderLength * sizeof(DWORD);

    if (pIpv4Header->HeaderLength < 5)
    {
        DEBUGP(LOG_ERROR, "IHL = 0x%x. minimum = 0x14", pIpv4Header->HeaderLength);
        return NULL;
    }

    if (*pLength < ipv4Size)
    {
        DEBUGP(LOG_ERROR, "size left = 0x%x < ipv4 header size = 0x%x", *pLength, ipv4Size);
        return NULL;
    }

    //The IPv4 TL can be 0 if the packet is used on LSO
    if (RtlUshortByteSwap(pIpv4Header->TotalLength) < ipv4Size ||
        pIpv4Header->TotalLength == 0)
    {
        DEBUGP(LOG_ERROR, "TL = 0x%x < ipv4 header size = 0x%x", RtlUshortByteSwap(pIpv4Header->TotalLength), ipv4Size);
        return NULL;
    }

    if (pIpv4Header->Version != 4)
    {
        DEBUGP(LOG_ERROR, "ipv4 protocol header version = 0x%x != 4", pIpv4Header->Version);
        return NULL;
    }

    *pLength -= ipv4Size;
    *pProtoType = pIpv4Header->Protocol;

    return buffer + ipv4Size;
}

VOID FillTransportPseudoHeader_FromIpv4(_In_ const OVS_IPV4_HEADER* pIpv4Header, _Out_ OVS_TRANSPORT_PSEUDO_HEADER_IPV4* pPseudoHeader)
{
    ULONG tcpLen = 0;

    OVS_CHECK(pPseudoHeader);
    OVS_CHECK(pIpv4Header);

    OVS_CHECK(pIpv4Header->Protocol == OVS_IPPROTO_TCP ||
        pIpv4Header->Protocol == OVS_IPPROTO_UDP ||
        pIpv4Header->Protocol == OVS_IPPROTO_SCTP);

    RtlCopyMemory(pPseudoHeader->srcIp, &pIpv4Header->SourceAddress.S_un.S_addr, 4);
    RtlCopyMemory(pPseudoHeader->destIp, &pIpv4Header->DestinationAddress.S_un.S_addr, 4);
    pPseudoHeader->reserved = 0;
    pPseudoHeader->protocol = pIpv4Header->Protocol;

    tcpLen = RtlUshortByteSwap(pIpv4Header->TotalLength) - pIpv4Header->HeaderLength * sizeof(DWORD);

    pPseudoHeader->tcpLen = RtlUshortByteSwap(tcpLen);
}

BYTE* Ipv4_CopyHeaderOptions(_In_ const OVS_IPV4_HEADER* pIpv4Header, _Inout_ ULONG* pFragHeaderSize)
{
    ULONG headerSize = 0;
    ULONG inOptionsSize = 0, outOptionsSize = 0;
    BYTE* pOption = NULL;
    BYTE optionType = 0;
    BYTE* pOptionBuffer = NULL;

    OVS_CHECK(pIpv4Header);
    outOptionsSize = 0;

    if (pIpv4Header->HeaderLength == 5)
    {
        return NULL;
    }

    headerSize = pIpv4Header->HeaderLength * sizeof(DWORD);
    inOptionsSize = headerSize - sizeof(OVS_IPV4_HEADER);
    pOption = (BYTE*)pIpv4Header + sizeof(OVS_IPV4_HEADER);
    optionType = *pOption;

    pOptionBuffer = ExAllocatePoolWithTag(NonPagedPool, inOptionsSize, g_extAllocationTag);
    if (!pOptionBuffer)
    {
        return NULL;
    }

    memset(pOptionBuffer, 0, inOptionsSize);

    while ((IPV4_GET_OPTION_CLASS(optionType) != 0 || IPV4_GET_OPTION_NUMBER(optionType)) != 0
        && inOptionsSize > 0)
    {
        ULONG optSize = Ipv4_GetOptionLength(pOption);

        if (IPV4_GET_OPTION_COPIED(optionType))
        {
            //alignment on 4 bytes boundary
            if (outOptionsSize % 4 != 0)
            {
                ULONG paddingBytes = 4 - (outOptionsSize % 4);

                memset(pOptionBuffer + outOptionsSize, 1 /*no op / padding*/, paddingBytes);
                outOptionsSize += paddingBytes;
            }

            RtlCopyMemory(pOptionBuffer + outOptionsSize, pOption, optSize);
            outOptionsSize += optSize;
        }

        pOption += optSize;
        inOptionsSize -= optSize;
        optionType = *pOption;
    }

    if (outOptionsSize % 4 != 0)
    {
        ULONG paddingBytes = 4 - (outOptionsSize % 4);

        memset(pOptionBuffer + outOptionsSize, 1 /*no op / padding*/, paddingBytes);
        outOptionsSize += paddingBytes;
    }

    *pFragHeaderSize = outOptionsSize;

    return pOptionBuffer;
}