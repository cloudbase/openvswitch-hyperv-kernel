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

#include "Udp.h"
#include "Ethernet.h"
#include "Frame.h"
#include "Ipv4.h"
#include "Ipv6.h"

#include "PacketInfo.h"
#include "OvsNetBuffer.h"
#include "Tcp.h"
#include "Checksum.h"

OVS_UDP_HEADER* GetUdpHeader(VOID* pPacketBuffer)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pPacketBuffer;
    OVS_UDP_HEADER* pUdpHeader = NULL;

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        pEthHeader = (OVS_ETHERNET_HEADER*)((BYTE*)pEthHeader + OVS_ETHERNET_VLAN_LEN);
    }

    if (pEthHeader->type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV4) &&
        pEthHeader->type != RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        return NULL;
    }

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IPV4_HEADER* pIpv4Header = ReadIpv4Header(pEthHeader);
        if (pIpv4Header->Protocol != OVS_IPPROTO_UDP)
        {
            return NULL;
        }

        pUdpHeader = (OVS_UDP_HEADER*)AdvanceIpv4Header(pIpv4Header);
        return pUdpHeader;
    }

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        OVS_IPV6_HEADER* pIpv6Header = ReadIpv6Header(pEthHeader);
        BYTE nextHeader = pIpv6Header->nextHeader;
        VOID* advancedBuffer = AdvanceIpv6Header(pIpv6Header);
        BYTE headerLength = 0;

        while (IsIpv6Extension(nextHeader))
        {
            nextHeader = *((BYTE*)advancedBuffer);
            headerLength = *(sizeof(nextHeader) + (BYTE*)advancedBuffer);
            advancedBuffer = ((BYTE*)advancedBuffer) + headerLength + 8;
        }

        if (nextHeader != OVS_IPV6_EXTH_UDP)
        {
            return NULL;
        }

        pUdpHeader = (OVS_UDP_HEADER*)advancedBuffer;
        return pUdpHeader;
    }

    return NULL;
}

static void _Udp_SetPort(OVS_NET_BUFFER* pOvsNb, BE16* pPort, BE16 newPort)
{
    OVS_UDP_HEADER* pUdpHeader = GetUdpHeader(pOvsNb);
    UINT16 csumRecomp = 0;

    if (pUdpHeader->checksum)
    {
        csumRecomp = (WORD)RecomputeChecksum((BYTE*)pPort, (BYTE*)&newPort, 2, pUdpHeader->checksum);
        csumRecomp = RtlUshortByteSwap(csumRecomp);

        pUdpHeader->checksum = csumRecomp;
        *pPort = newPort;

        //UDP NOTE: If the calculated checksum is 0, it is stored as all one bits (0xFFFF), which is equivalent in ones-complement arithmetic.
        //If the transmitted checksum is 0, it indicates that the sender did not compute the checksum.
        //NOTE: only udp checksum is optional, tcp checksum is NOT optional!
        if (!pUdpHeader->checksum)
        {
            pUdpHeader->checksum = OVS_UDP_CHECKSUM_MANGLED;
        }
    }
    else
    {
        *pPort = newPort;
    }
}

BOOLEAN ONB_SetUdp(OVS_NET_BUFFER* pOvsNb, const OVS_PI_UDP* pUdpPI)
{
    OVS_UDP_HEADER* pUdpHeader = NULL;
    VOID* buffer = ONB_GetData(pOvsNb);

    pUdpHeader = GetUdpHeader(buffer);

    if (pUdpPI->source != pUdpHeader->sourcePort)
    {
        _Udp_SetPort(pOvsNb, &pUdpHeader->sourcePort, pUdpPI->source);
    }

    if (pUdpPI->destination != pUdpHeader->destinationPort)
    {
        _Udp_SetPort(pOvsNb, &pUdpHeader->destinationPort, pUdpPI->destination);
    }

    return TRUE;
}

_Use_decl_annotations_
void DbgPrintUdpHeader(const VOID* buffer)
{
    OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)buffer;
    UNREFERENCED_PARAMETER(pUdpHeader);

    DEBUGP_FRAMES(LOG_INFO, "udp: src port = %d; dest port = %d\n", RtlUshortByteSwap(pUdpHeader->sourcePort), RtlUshortByteSwap(pUdpHeader->destinationPort));
}

BOOLEAN VerifyUdpHeader(BYTE* buffer, ULONG* pLength)
{
    OVS_UDP_HEADER* pUdpHeader = (OVS_UDP_HEADER*)buffer;

    //TODO: verify. ATM nothing is done
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(pLength);
    UNREFERENCED_PARAMETER(pUdpHeader);

    return TRUE;
}