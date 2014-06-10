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

#include "Tcp.h"
#include "Ethernet.h"
#include "Ipv4.h"
#include "Ipv6.h"
#include "Frame.h"
#include "PacketInfo.h"
#include "OvsNetBuffer.h"
#include "Checksum.h"

OVS_TCP_HEADER* GetTcpHeader(VOID* pPacketBuffer)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pPacketBuffer;
    OVS_TCP_HEADER* pTcpHeader = NULL;

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
        if (pIpv4Header->Protocol != OVS_IPPROTO_TCP)
        {
            return NULL;
        }

        pTcpHeader = (OVS_TCP_HEADER*)AdvanceIpv4Header(pIpv4Header);
        return pTcpHeader;
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

        if (nextHeader != OVS_IPV6_EXTH_TCP)
        {
            return NULL;
        }

        pTcpHeader = (OVS_TCP_HEADER*)advancedBuffer;
        return pTcpHeader;
    }

    return NULL;
}

BOOLEAN ONB_SetTcp(OVS_NET_BUFFER* pOvsNb, const OVS_PI_TCP* pTcpPI)
{
    OVS_TCP_HEADER *pTcpHeader = NULL;
    OVS_IPV4_HEADER* pIpv4Header = NULL;
    VOID* buffer = NULL;
    UINT16 csumRecomp = 0;
    UINT16 offset = 0, reserved = 0, flags = 0;

    buffer = ONB_GetData(pOvsNb);
    pIpv4Header = GetIpv4Header(buffer);
    pTcpHeader = GetTcpHeader(buffer);

    if (pTcpPI->source != pTcpHeader->sourcePort)
    {
        DEBUGP_FRAMES(LOG_INFO, "src port (BE): 0x%x -> 0x%x\n", pTcpHeader->sourcePort, pTcpPI->source);
        DEBUGP_FRAMES(LOG_INFO, "dst port (BE): 0x%x\n", pTcpHeader->destinationPort);

        csumRecomp = (WORD)RecomputeChecksum((BYTE*)&pTcpHeader->sourcePort, (BYTE*)&pTcpPI->source, 2, pTcpHeader->checksum);
        csumRecomp = RtlUshortByteSwap(csumRecomp);

        pTcpHeader->checksum = csumRecomp;
        pTcpHeader->sourcePort = pTcpPI->source;
    }

    if (pTcpPI->destination != pTcpHeader->destinationPort)
    {
        DEBUGP_FRAMES(LOG_INFO, "src port (BE): 0x%x\n", pTcpHeader->sourcePort);
        DEBUGP_FRAMES(LOG_INFO, "dst port (BE): 0x%x -> 0x%x\n", pTcpHeader->destinationPort, pTcpPI->destination);

        csumRecomp = (WORD)RecomputeChecksum((BYTE*)&pTcpHeader->destinationPort, (BYTE*)&pTcpPI->destination, 2, pTcpHeader->checksum);
        csumRecomp = RtlUshortByteSwap(csumRecomp);

        pTcpHeader->checksum = csumRecomp;
        pTcpHeader->destinationPort = pTcpPI->destination;
    }

    offset = GetTcpDataOffset(pTcpHeader->flagsAndOffset);
    reserved = GetTcpReserved(pTcpHeader->flagsAndOffset);
    flags = GetTcpFlags(pTcpHeader->flagsAndOffset);

    DEBUGP_FRAMES(LOG_INFO, "seq number: 0x%x; ack number: 0x%x; offset: 0x%x; reserved: 0x%x; flags: 0x%x\n",
        pTcpHeader->sequenceNo, pTcpHeader->acknowledgeNo, offset, reserved, flags);

    return TRUE;
}

_Use_decl_annotations_
void DbgPrintTcpHeader(const VOID* buffer)
{
    OVS_TCP_HEADER* pTcpHeader = (OVS_TCP_HEADER*)buffer;
    UNREFERENCED_PARAMETER(pTcpHeader);

    DEBUGP_FRAMES(LOG_INFO, "tcp: src port = %d; dest port = %d\n", RtlUshortByteSwap(pTcpHeader->sourcePort), RtlUshortByteSwap(pTcpHeader->destinationPort));
}

BOOLEAN VerifyTcpHeader(BYTE* buffer, ULONG* pLength)
{
    OVS_TCP_HEADER* pTcpHeader = (OVS_TCP_HEADER*)buffer;

    //TODO: verify. ATM nothing is done
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(pLength);
    UNREFERENCED_PARAMETER(pTcpHeader);

    return TRUE;
}