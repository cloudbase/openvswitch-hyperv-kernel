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

#include "Sctp.h"
#include "OvsNetBuffer.h"
#include "PacketInfo.h"
#include "Ipv4.h"
#include "Ipv6.h"
#include "Frame.h"
#include "Checksum.h"

OVS_SCTP_HEADER* GetSctpHeader(VOID* pPacketBuffer)
{
    OVS_ETHERNET_HEADER* pEthHeader = (OVS_ETHERNET_HEADER*)pPacketBuffer;
    OVS_SCTP_HEADER* pSctpHeader = NULL;

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
        if (pIpv4Header->Protocol != OVS_IPPROTO_SCTP)
        {
            return NULL;
        }

        pSctpHeader = (OVS_SCTP_HEADER*)AdvanceIpv4Header(pIpv4Header);
        return pSctpHeader;
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

        if (nextHeader != OVS_IPPROTO_SCTP)
        {
            return NULL;
        }

        pSctpHeader = (OVS_SCTP_HEADER*)advancedBuffer;
        return pSctpHeader;
    }

    return NULL;
}

BOOLEAN ONB_SetSctp(OVS_NET_BUFFER* pOvsNb, const OVS_PI_SCTP* pSctpPI)
{
    OVS_SCTP_HEADER* pSctpHeader = NULL;
    VOID* buffer = ONB_GetData(pOvsNb);
    UINT offset = 0;

    pSctpHeader = GetSctpHeader(buffer);

    if (pSctpPI->source != pSctpHeader->sourcePort ||
        pSctpPI->destination != pSctpHeader->destinationPort)
    {
        UINT32 oldChecksumCorrect = 0;
        UINT32 newChecksum = 0;
        UINT32 oldChecksum = 0;

        oldChecksum = pSctpHeader->checksum;
        oldChecksumCorrect = Sctp_ComputeChecksum(pOvsNb, offset);

        pSctpHeader->sourcePort = pSctpPI->source;
        pSctpHeader->destinationPort = pSctpPI->destination;

        newChecksum = Sctp_ComputeChecksum(pOvsNb, offset);

        pSctpHeader->checksum = oldChecksum ^ oldChecksumCorrect;
        pSctpHeader->checksum ^= newChecksum;
    }

    return TRUE;
}

BOOLEAN VerifySctpHeader(BYTE* buffer, ULONG* pLength)
{
    OVS_SCTP_HEADER* pSctpHeader = (OVS_SCTP_HEADER*)buffer;

    //TODO: verify. ATM nothing is done
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(pLength);
    UNREFERENCED_PARAMETER(pSctpHeader);

    return TRUE;
}