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

#include "precomp.h"
#include "OFFlow.h"
#include "Nbls.h"
#include "Gre.h"
#include "Arp.h"
#include "Ipv6.h"
#include "Tcp.h"
#include "Udp.h"
#include "OvsNetBuffer.h"
#include "Checksum.h"
#include "Argument.h"

/*********************************************************************************/

ULONG Gre_HeaderSize(UINT16 tunnelFlags)
{
    ULONG size = sizeof(OVS_GRE_HEADER_2890);

    if (tunnelFlags & OVS_TUNNEL_FLAG_CHECKSUM)
    {
        size += sizeof(OVS_GRE2784_HEADER_OPT_CHECKSUM) + sizeof(OVS_GRE2784_HEADER_OPT_RESERVED1);
    }

    if (tunnelFlags & OVS_TUNNEL_FLAG_KEY)
    {
        size += sizeof(OVS_GRE1701_HEADER_OPT_KEY);
    }

    if (tunnelFlags & OVS_TUNNEL_FLAG_SEQ)
    {
        size += sizeof(OVS_GRE1701_HEADER_OPT_SEQNUMBER);
    }

    return size;
}

ULONG Gre_BytesNeeded(UINT16 tunnelFlags)
{
    return sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_IPV4_HEADER) + Gre_HeaderSize(tunnelFlags);
}

//i.e. the header size, computed from a packet that is encapsulated in GRE
ULONG Gre_FrameHeaderSize(_In_ const OVS_GRE_HEADER_2890* pGre)
{
    ULONG greSize = sizeof(OVS_GRE_HEADER_2890);

    OVS_CHECK(pGre);

    if (pGre->haveChecksum)
    {
        greSize += sizeof(OVS_GRE2784_HEADER_OPT_CHECKSUM) + sizeof(OVS_GRE2784_HEADER_OPT_RESERVED1);
    }

    if (pGre->haveKey)
    {
        greSize += sizeof(OVS_GRE1701_HEADER_OPT_KEY);
    }

    if (pGre->haveSeqNumber)
    {
        greSize += sizeof(OVS_GRE1701_HEADER_OPT_SEQNUMBER);
    }

    return greSize;
}

OVS_GRE_HEADER_2890* Gre_BuildHeader(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _In_ const OVS_TUNNELING_PORT_OPTIONS* pPortOptions,
    ULONG payloadLength, ULONG greHeaderSize, _Out_ BOOLEAN* pHaveChecksum)
{
    OVS_GRE_HEADER_2890* pGreHeader = NULL;
    ULONG computedSize = 0;
    UINT16* pChecksum = NULL;
    UINT32* pSequence = NULL, *pKey = NULL;
    ULONG offset = sizeof(OVS_GRE_HEADER_2890);

    UNREFERENCED_PARAMETER(payloadLength);
    UNREFERENCED_PARAMETER(pPortOptions);

    *pHaveChecksum = FALSE;

    pGreHeader = KAlloc(greHeaderSize);
    if (!pGreHeader)
    {
        return NULL;
    }

    RtlZeroMemory(pGreHeader, greHeaderSize);

    //it's a word, therefore must be turned BE
    //NOTE: normal GRE has a protocol type != TEB, such as, Ipv4, Ipv6, etc.
    //but in such a case, the payload eth header is not encapsulated
    pGreHeader->protocolType = RtlUshortByteSwap(OVS_ETHERTYPE_TEB);

    computedSize = Gre_HeaderSize(pTunnel->tunnelFlags);
    OVS_CHECK(computedSize == greHeaderSize);

    if (pTunnel->tunnelFlags & OVS_TUNNEL_FLAG_CHECKSUM)
    {
        pChecksum = (UINT16*)((BYTE*)pGreHeader + offset);

        offset += sizeof(OVS_GRE2784_HEADER_OPT_CHECKSUM) + sizeof(OVS_GRE2784_HEADER_OPT_RESERVED1);
        pGreHeader->haveChecksum = 1;
        *pHaveChecksum = TRUE;
    }

    if (pTunnel->tunnelFlags & OVS_TUNNEL_FLAG_KEY)
    {
        BE32 key = (pTunnel->tunnelId >> 32);
        pKey = (UINT32*)((BYTE*)pGreHeader + offset);
        *pKey = key;

        offset += sizeof(OVS_GRE1701_HEADER_OPT_KEY);
        pGreHeader->haveKey = 1;
    }

    if (pTunnel->tunnelFlags & OVS_TUNNEL_FLAG_SEQ)
    {
        pSequence = (UINT32*)((BYTE*)pGreHeader + offset);
        *pSequence = 0;

        offset += sizeof(OVS_GRE1701_HEADER_OPT_SEQNUMBER);
        pGreHeader->haveSeqNumber = 1;
    }

    //NOTE: if checksum => checksum must be computed afterwards (due to ip checksum offload)

    return pGreHeader;
}

VOID Gre_ComputeChecksum(VOID* pGreHeader, ULONG greHeaderSize, ULONG grePayloadSize)
{
    UINT16* pChecksum = (UINT16*)((BYTE*)pGreHeader + sizeof(OVS_GRE_HEADER_2890));
    UINT16 checksum = (UINT16)ComputeIpChecksum((BYTE*)pGreHeader, grePayloadSize + greHeaderSize);
    checksum = RtlUshortByteSwap(checksum);

    *pChecksum = checksum;
}

/*********************************************/

_Use_decl_annotations_
void DbgPrintGreHeader(const VOID* buffer)
{
    OVS_GRE_HEADER_2890* pGreHeader = (OVS_GRE_HEADER_2890*)buffer;
    BYTE* nextBuff = (BYTE*)pGreHeader;
    OVS_IPV4_HEADER* pIpv4Header = NULL;
    UINT16 tunnelFlags = 0;
    ULONG headerSize = 0;

    DEBUGP(LOG_INFO, "GRE: protocol type: 0x%x\n", RtlUshortByteSwap(pGreHeader->protocolType));

    if (pGreHeader->haveChecksum)
    {
        tunnelFlags |= OVS_TUNNEL_FLAG_CHECKSUM;
    }

    if (pGreHeader->haveKey)
    {
        tunnelFlags |= OVS_TUNNEL_FLAG_KEY;
    }

    if (pGreHeader->haveSeqNumber)
    {
        tunnelFlags |= OVS_TUNNEL_FLAG_SEQ;
    }

    headerSize = Gre_HeaderSize(tunnelFlags);

    nextBuff += headerSize;

    if (pGreHeader->protocolType == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        pIpv4Header = (OVS_IPV4_HEADER*)nextBuff;
        ReadIpv4ProtocolFrame(pIpv4Header);
    }
    //TODO: check tunnel key, sequence, checksum.
}

//pLength:    in - the length of the packet, beginning with the GRE header
//            out - the length of the packet beginning with the end of the whole GRE header (i.e. the length of payload)
//pEthType:   out - the protocol type of the GRE (i.e. the encaps protocol)
//returns:    buffer after the end of the whole GRE header, i.e. ptr to net protocol header

BYTE* VerifyGreHeader(_In_ BYTE* buffer, _Inout_ ULONG* pLength, _Inout_ UINT16* pEthType)
{
    OVS_GRE_HEADER_2890* pGreHeader = (OVS_GRE_HEADER_2890*)buffer;
    ULONG offset = sizeof(OVS_GRE_HEADER_2890);

    //TODO: assert GRE is valid for RFC 2890
    if (pGreHeader->versionNumber)
    {
        DEBUGP(LOG_ERROR, "gre header has version=0x%x != 0", pGreHeader->versionNumber);
        return NULL;
    }

    //bits 1 and 4 must be zero
    //(acc to 2784 + errata, bits 1->4 must be zero, if not implementing 1701, but 2890 uses bits 2 and 3)
    if (pGreHeader->reserved0_bit1 || pGreHeader->reserved0_bit4 || pGreHeader->reserved0_bit5)
    {
        DEBUGP(LOG_ERROR, "gre has reserved1 bits set: bit1=%d; bit4=%d; bit5=%d\n",
            pGreHeader->reserved0_bit1, pGreHeader->reserved0_bit4, pGreHeader->reserved0_bit5);
        return NULL;
    }

    switch (RtlUshortByteSwap(pGreHeader->protocolType))
    {
    case OVS_ETHERTYPE_TEB:
    case OVS_ETHERTYPE_ARP:
    case OVS_ETHERTYPE_IPV4:
    case OVS_ETHERTYPE_IPV6:
        break;
    default:
        DEBUGP(LOG_ERROR, "Invalid GRE protocol type (LE): 0x%x", RtlUshortByteSwap(pGreHeader->protocolType));
        return NULL;
    }

    if (pGreHeader->haveChecksum)
    {
        /*
        If the Checksum Present bit is set to 1, then the Checksum field
        is present and contains valid information.

        If either the Checksum Present bit or the Routing Present bit are
        set, BOTH the Checksum and Offset fields are present in the GRE
        packet.
        */

        //the checksum field is the first UINT16 after the main GRE header
        UINT16* pChecksum = (UINT16*)(buffer + sizeof(OVS_GRE_HEADER_2890));
        UINT16 oldChecksum = RtlUshortByteSwap(*pChecksum);

        *pChecksum = 0;

        UINT16 newChecksum = (UINT16)ComputeIpChecksum(buffer, *pLength);

        if (newChecksum != oldChecksum)
        {
            DEBUGP(LOG_ERROR, "GRE header has incorrect checksum: 0x%x; correct checksum = 0x%x\n", oldChecksum, newChecksum);
            return NULL;
        }

        *pChecksum = RtlUshortByteSwap(oldChecksum);

        offset += sizeof(OVS_GRE2784_HEADER_OPT_CHECKSUM) + sizeof(OVS_GRE2784_HEADER_OPT_RESERVED1);
    }

    if (pGreHeader->haveKey)
    {
        /*
        If the Key Present bit is set to 1, then it indicates that the Key
        field is present in the GRE header.  Otherwise, the Key field is
        not present in the GRE header.
        */
        offset += sizeof(OVS_GRE1701_HEADER_OPT_KEY);
    }

    if (pGreHeader->haveSeqNumber)
    {
        /*
        If the Sequence Number Present bit is set to 1, then it indicates
        that the Sequence Number field is present.  Otherwise, the
        Sequence Number field is not present in the GRE header.
        */

        offset += sizeof(OVS_GRE1701_HEADER_OPT_SEQNUMBER);
    }

    *pLength -= offset;
    *pEthType = pGreHeader->protocolType;

    return buffer + offset;
}

_Use_decl_annotations_
BOOLEAN Gre_ReadHeader(const VOID* pEncapHeader, ULONG* pOffset, ULONG outerIpPayloadLen, OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    ULONG addOffset = sizeof(OVS_GRE_HEADER_2890);
    UINT32 key = 0, sequence = 0;
    BYTE* pGreBuffer = (BYTE*)pEncapHeader;
    OVS_GRE_HEADER_2890* pGreHeader = (OVS_GRE_HEADER_2890*)pEncapHeader;

    OVS_CHECK(pOffset);

    RtlZeroMemory(pTunnelInfo, sizeof(OF_PI_IPV4_TUNNEL));

    if (outerIpPayloadLen <= sizeof(OVS_GRE_HEADER_2890))
    {
        DEBUGP(LOG_ERROR, "outer ip payload length too small, for gre\n");
        return FALSE;
    }

    if (pGreHeader->protocolType != RtlUshortByteSwap(OVS_ETHERTYPE_TEB))
    {
        DEBUGP(LOG_ERROR, "expected gre protocol type = TEB; have: %d", pGreHeader->protocolType);
        return FALSE;
    }

    //TODO: assert GRE is valid for RFC 2890
    if (pGreHeader->versionNumber)
    {
        DEBUGP(LOG_ERROR, "gre header has version=0x%x != 0", pGreHeader->versionNumber);
        return FALSE;
    }

    //bits 1 and 4 must be zero
    //(acc to 2784 + errata, bits 1->4 must be zero, if not implementing 1701, but 2890 uses bits 2 and 3)
    if (pGreHeader->reserved0_bit1 || pGreHeader->reserved0_bit4 || pGreHeader->reserved0_bit5)
    {
        DEBUGP(LOG_ERROR, "gre has reserved1 bits set: bit1=%d; bit4=%d; bit5=%d\n",
            pGreHeader->reserved0_bit1, pGreHeader->reserved0_bit4, pGreHeader->reserved0_bit5);
        return FALSE;
    }

    if (pGreHeader->haveChecksum)
    {
        /*
        If the Checksum Present bit is set to 1, then the Checksum field
        is present and contains valid information.

        If either the Checksum Present bit or the Routing Present bit are
        set, BOTH the Checksum and Offset fields are present in the GRE
        packet.
        */

        //the checksum field is the first UINT16 after the main GRE header
        ULONG checksumSize = sizeof(OVS_GRE2784_HEADER_OPT_CHECKSUM) + sizeof(OVS_GRE2784_HEADER_OPT_RESERVED1);
        UINT16* pChecksum = (UINT16*)(pGreBuffer + sizeof(OVS_GRE_HEADER_2890));
        UINT16 old_checksum = RtlUshortByteSwap(*pChecksum);

        *pChecksum = 0;

        UINT16 new_checksum = (UINT16)ComputeIpChecksum(pGreBuffer, outerIpPayloadLen);

        if (new_checksum != old_checksum)
        {
            DEBUGP(LOG_ERROR, "GRE header has incorrect checksum: 0x%x; correct checksum = 0x%x\n", old_checksum, new_checksum);
            return FALSE;
        }

        *pChecksum = RtlUshortByteSwap(old_checksum);

        addOffset += checksumSize;
        pTunnelInfo->tunnelFlags |= OVS_TUNNEL_FLAG_CHECKSUM;
    }

    if (pGreHeader->haveKey)
    {
        /*
        If the Key Present bit is set to 1, then it indicates that the Key
        field is present in the GRE header.  Otherwise, the Key field is
        not present in the GRE header.
        */

        key = *(UINT32*)(pGreBuffer + addOffset);

        addOffset += sizeof(OVS_GRE1701_HEADER_OPT_KEY);
        pTunnelInfo->tunnelFlags |= OVS_TUNNEL_FLAG_KEY;
    }

    if (pGreHeader->haveSeqNumber)
    {
        /*
        If the Sequence Number Present bit is set to 1, then it indicates
        that the Sequence Number field is present.  Otherwise, the
        Sequence Number field is not present in the GRE header.
        */

        sequence = *(UINT32*)(pGreBuffer + addOffset);

        addOffset += sizeof(OVS_GRE1701_HEADER_OPT_SEQNUMBER);
        pTunnelInfo->tunnelFlags |= OVS_TUNNEL_FLAG_SEQ;
    }

    pTunnelInfo->tunnelId = MAKEQWORD(sequence, key);
    *pOffset += addOffset;

    return TRUE;
}