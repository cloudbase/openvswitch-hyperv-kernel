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

#include "OFFlow.h"
#include "VXLAN.h"
#include "Ipv4.h"
#include "Udp.h"
#include "Frame.h"
#include "Nbls.h"
#include "OvsNetBuffer.h"
#include "Argument.h"

ULONG Vxlan_BytesNeeded(UINT16 tunnelFlags)
{
    UNREFERENCED_PARAMETER(tunnelFlags);

    return sizeof(OVS_ETHERNET_HEADER) + sizeof(OVS_IPV4_HEADER) + sizeof(OVS_UDP_HEADER) + sizeof(OVS_VXLAN_HEADER);
}

static void _BuildOuterUdpHeader(OVS_UDP_HEADER* pUdpHeader, LE16 udpPort, UINT16 oldPacketLength)
{
    UINT16 udpPayloadLength = 0;
    LE16 vxlanUdpPort = 0;

    OVS_CHECK(pUdpHeader);

    vxlanUdpPort = udpPort;
    udpPayloadLength = (UINT16)(sizeof(OVS_UDP_HEADER) + oldPacketLength);

    pUdpHeader->sourcePort = 0;//must be computed using a hash on eth or smth
    pUdpHeader->destinationPort = RtlUshortByteSwap(vxlanUdpPort);

    /*
    http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-08
    The UDP checksum field SHOULD be transmitted as zero.  When a packet
    is received with a UDP checksum of zero, it MUST be accepted for
    decapsulation.  Optionally, if the encapsulating endpoint includes a
    non-zero UDP checksum, it MUST be correctly calculated across the
    entire packet including the IP header, UDP header, VXLAN header and
    encapsulated MAC frame.  When a decapsulating endpoint receives a
    packet with a non-zero checksum it MAY choose to verify the checksum
    value.  If it chooses to perform such verification, and the
    verification fails, the packet MUST be dropped.  If the
    decapsulating destination chooses not to perform the verification,
    or performs it successfully, the packet MUST be accepted for
    decapsulation.
    */
    //TODO: we should compute the udp checksum.
    pUdpHeader->checksum = 0;
    pUdpHeader->length = RtlUshortByteSwap(udpPayloadLength);
}

VOID* Vxlan_BuildHeader(_In_ const OF_PI_IPV4_TUNNEL* pTunnel, _In_ const OVS_TUNNELING_PORT_OPTIONS* pOptions,
    ULONG payloadLength, ULONG vxlanHeaderSize, _Out_ BOOLEAN* pHaveChecksum)
{
    VOID* pVxlanFullHeader = NULL;
    BYTE* writeBuffer = NULL;
    OVS_UDP_HEADER udpHeader = { 0 };
    ULONG toWrite = 0;
    OVS_VXLAN_HEADER vxlanHeader = { 0 };
    UINT32 tunnelId = 0;

    UNREFERENCED_PARAMETER(pTunnel);
    UNREFERENCED_PARAMETER(vxlanHeaderSize);

    OVS_CHECK(vxlanHeaderSize == sizeof(OVS_UDP_HEADER) + sizeof(OVS_VXLAN_HEADER));
    *pHaveChecksum = FALSE;

    pVxlanFullHeader = KAlloc(vxlanHeaderSize);
    if (!pVxlanFullHeader)
    {
        return NULL;
    }

    writeBuffer = pVxlanFullHeader;

    //A. Add the UDP
    OVS_CHECK(pOptions);
    OVS_CHECK(pOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT);
    _BuildOuterUdpHeader(&udpHeader, pOptions->udpDestPort, (UINT16)(payloadLength + sizeof(OVS_VXLAN_HEADER)));
    toWrite = sizeof(OVS_UDP_HEADER);

    OVS_CHECK(writeBuffer);
    RtlCopyMemory(writeBuffer, &udpHeader, toWrite);
    writeBuffer += toWrite;

    //B. Add the Vxlan
    RtlZeroMemory(&vxlanHeader, sizeof(vxlanHeader));
    vxlanHeader.flags = 0x8;

    //the tunnel id must be put in a 24bit field, so its value must be max 2^24 - 1 = 0xFFFFFF
    OVS_CHECK(RtlUlonglongByteSwap(pTunnel->tunnelId) <= 0xFFFFFF);

    tunnelId = (UINT32)(pTunnel->tunnelId >> (64 - 24));

    RtlCopyMemory(vxlanHeader.vni, &tunnelId, 3);
    //copy 3 bytes, so the last byte must be 0x00
    OVS_CHECK(vxlanHeader.reserved1 == 0);

    //vxlanHeader.vni - tunnel id
    toWrite = sizeof(OVS_VXLAN_HEADER);
    RtlCopyMemory(writeBuffer, &vxlanHeader, toWrite);

    return pVxlanFullHeader;
}

_Use_decl_annotations_
BOOLEAN Vxlan_ReadHeader(const VOID* pDecapHeader, ULONG* pOffset, ULONG outerIpPayloadLen, OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    OVS_UDP_HEADER* pUdpHeader = NULL;
    ULONG offset = 0;
    OVS_VXLAN_HEADER* pVxlanHeader = NULL;
    UINT32 tunnelId = 0;

    UNREFERENCED_PARAMETER(outerIpPayloadLen);

    OVS_CHECK(pOffset);

    offset = *pOffset;

    //C. UDP
    pUdpHeader = (OVS_UDP_HEADER*)pDecapHeader;
    //if we've reached this point, then the udp dest port MUST be vxlan port
    offset += sizeof(OVS_UDP_HEADER);

    //D. VXLAN
    pVxlanHeader = (OVS_VXLAN_HEADER*)((BYTE*)pUdpHeader + sizeof(OVS_UDP_HEADER));
    offset += sizeof(OVS_VXLAN_HEADER);

    pTunnelInfo->tunnelFlags |= OVS_TUNNEL_FLAG_KEY;

    tunnelId = *((BE32*)pVxlanHeader->vni);
    tunnelId &= 0x00FFFFFF;

    pTunnelInfo->tunnelId = (UINT64)tunnelId << 32;

    if (!(pVxlanHeader->flags & 0x8))
    {
        DEBUGP(LOG_ERROR, "Expected the VNI flag to be set and it is not\n");
        return FALSE;
    }

    *pOffset = offset;

    return TRUE;
}