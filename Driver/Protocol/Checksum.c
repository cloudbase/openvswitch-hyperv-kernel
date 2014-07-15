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

#include "Checksum.h"
#include "Ipv4.h"
#include "Ipv6.h"
#include "Tcp.h"
#include "Udp.h"
#include "Nbls.h"
#include "OvsNetBuffer.h"

UINT ComputeIpChecksum(const BYTE* buffer, UINT size)
{
    UINT checksum = 0;

    for (UINT i = 0; i < size; i += 2, buffer += 2)
    {
        UINT16 value = 0;

        if (i <= size - 2)
        {
            value = *((UINT16*)buffer);
        }
        else
        {
            //if we have only one byte left, e.g. B3, we should add:
            //B3 00 (i.e. 0xB3), and not 00 B3 (i.e. 0x00B3)
            value = *((UINT8*)buffer);
            //value <<= 8;
        }

        checksum += RtlUshortByteSwap(value);

        //checksum = 0x1A0B0
        if (checksum > UINT16_MAX)
        {
            //should have 0x1xxxx, not 0x3xxxx or other digit > 1
            OVS_CHECK(checksum >> 16 == 1);

            //tmp = 0xA0B0
            UINT16 tmp = (UINT16)checksum;

            //tmp = 0xA0B1
            tmp += 1;

            checksum = tmp;
        }
    }

    OVS_CHECK(checksum >> 16 == 0);
    checksum = ~checksum;
    return checksum;
}

static WORD _ChecksumSubCsum(UINT checksum, WORD csumToSub)
{
    checksum -= csumToSub;

    //checksum = 0x1A0B0
    if (checksum > 0xFFFF)
    {
        //should have 0x1xxxx, not 0x3xxxx or other digit > 1
        OVS_CHECK(checksum >> 16 == 0xFFFF);

        //tmp = 0xA0B0
        UINT16 tmp = (UINT16)checksum;

        //tmp = 0xA0B1
        tmp -= 1;

        checksum = tmp;
    }

    return (WORD)checksum;
}

WORD ChecksumAddCsum(UINT checksum, WORD csumToAdd)
{
    checksum += csumToAdd;

    //checksum = 0x1A0B0
    if (checksum > 0xFFFF)
    {
        //should have 0x1xxxx, not 0x3xxxx or other digit > 1
        OVS_CHECK(checksum >> 16 == 1);

        //tmp = 0xA0B0
        UINT16 tmp = (UINT16)checksum;

        //tmp = 0xA0B1
        tmp += 1;

        checksum = tmp;
    }

    return (WORD)checksum;
}

UINT RecomputeChecksum(const BYTE* oldBuffer, const BYTE* newBuffer, ULONG len, WORD checksum)
{
    WORD oldBufChecksum = 0, newBufChecksum = 0;

    OVS_CHECK(len % 2 == 0);

    oldBufChecksum = (WORD)ComputeIpChecksum(oldBuffer, len);
    oldBufChecksum = RtlUshortByteSwap(oldBufChecksum);
    oldBufChecksum = ~oldBufChecksum;

    newBufChecksum = (WORD)ComputeIpChecksum(newBuffer, len);
    newBufChecksum = RtlUshortByteSwap(newBufChecksum);
    newBufChecksum = ~newBufChecksum;

    checksum = ~checksum;

    checksum = _ChecksumSubCsum(checksum, oldBufChecksum);
    checksum = ChecksumAddCsum(checksum, newBufChecksum);
    checksum = RtlUshortByteSwap(checksum);

    checksum = ~checksum;

    return checksum;
}

LE16 ComputeTransportChecksum(VOID* transportBuffer, VOID* protocolBuffer, LE16 ethType)
{
    OVS_CHECK(transportBuffer);

    if (ethType == OVS_ETHERTYPE_IPV4)
    {
        OVS_TRANSPORT_PSEUDO_HEADER_IPV4 pseudoHeader = { 0 };
        OVS_IPV4_HEADER* pIpv4Header = (OVS_IPV4_HEADER*)protocolBuffer;
        ULONG transportLen = GetTransportLength_FromIpv4(pIpv4Header);
        UINT16 checksumTcp = 0, checksumPseudo = 0, checksum = 0;

        OVS_CHECK((UINT64)((BYTE*)transportBuffer - (BYTE*)pIpv4Header) == (UINT64)(pIpv4Header->HeaderLength * sizeof(DWORD)));

        FillTransportPseudoHeader_FromIpv4(pIpv4Header, &pseudoHeader);

        checksumTcp = (UINT16)ComputeIpChecksum(transportBuffer, transportLen);
        checksumTcp = ~checksumTcp;

        checksumPseudo = (UINT16)ComputeIpChecksum((BYTE*)&pseudoHeader, sizeof(pseudoHeader));
        checksumPseudo = ~checksumPseudo;

        checksum = ChecksumAddCsum(checksumTcp, checksumPseudo);
        checksum = ~checksum;
        return checksum;
    }
    else if (ethType == OVS_ETHERTYPE_IPV6)
    {
        OVS_TRANSPORT_PSEUDO_HEADER_IPV6 pseudoHeader = { 0 };
        OVS_IPV6_HEADER* pIpv6Header = (OVS_IPV6_HEADER*)protocolBuffer;
        ULONG transportLen = RtlUshortByteSwap(pIpv6Header->payloadLength);
        ULONG extLens = 0;
        UINT16 checksumTcp = 0, checksumPseudo = 0, checksum = 0;
        VOID* extBuffer = NULL;
        BYTE protocolType = 0;

        /**************/
        extBuffer = GetFirstIpv6Extension(pIpv6Header, &protocolType);

        while (IsIpv6Extension(protocolType))
        {
            BYTE extLen = GetIpv6ExtensionLength(extBuffer);

            extBuffer = GetNextIpv6Extension(extBuffer, &protocolType);

            extLens += extLen;
        }

        transportLen -= extLens;
        /**************/

        OVS_CHECK((UINT64)((BYTE*)transportBuffer - (BYTE*)pIpv6Header) == (UINT64)(extLens + sizeof(OVS_IPV6_HEADER)));

        FillTransportPseudoHeader_FromIpv6(pIpv6Header->sourceAddress.u.Byte, pIpv6Header->destinationAddress.u.Byte, protocolType, transportLen, &pseudoHeader);

        checksumTcp = (UINT16)ComputeIpChecksum(transportBuffer, transportLen);
        checksumTcp = ~checksumTcp;

        checksumPseudo = (UINT16)ComputeIpChecksum((BYTE*)&pseudoHeader, sizeof(pseudoHeader));
        checksumPseudo = ~checksumPseudo;

        checksum = ChecksumAddCsum(checksumTcp, checksumPseudo);
        checksum = ~checksum;

        return checksum;
    }
    else
    {
        OVS_CHECK(__UNEXPECTED__);
    }

    OVS_CHECK(__UNEXPECTED__);
    return 0;
}

static VOID _HandleChecksumOffload_Ipv4(_Inout_ VOID* netHeader, _Inout_ NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pChecksumOffloadInfo)
{
    OVS_IPV4_HEADER* pIpv4Header = (OVS_IPV4_HEADER*)netHeader;

    pIpv4Header->HeaderChecksum = (UINT16)ComputeIpChecksum((BYTE*)pIpv4Header, pIpv4Header->HeaderLength * sizeof(DWORD));
    pIpv4Header->HeaderChecksum = RtlUshortByteSwap(pIpv4Header->HeaderChecksum);

    pChecksumOffloadInfo->Transmit.IpHeaderChecksum = 0;
}

static VOID _HandleChecksumOffload_Tcp(LE16 ethType, ULONG ethSize, ULONG encapsSize, ULONG mtu,
    _Inout_ BYTE* netHeader, _Inout_ NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pChecksumOffloadInfo)
{
    UINT16 checksum = 0;
    UINT16 tcpFlags = 0;
    OVS_TCP_HEADER* pTcpHeader = NULL;

    if (ethType == OVS_ETHERTYPE_IPV4)
    {
        OVS_CHECK(pChecksumOffloadInfo->Transmit.TcpHeaderOffset > 0);
        OVS_CHECK(pChecksumOffloadInfo->Transmit.IsIPv4);

        ULONG offset = pChecksumOffloadInfo->Transmit.TcpHeaderOffset - ethSize;
        pTcpHeader = (OVS_TCP_HEADER*)(netHeader + offset);

#ifdef DBG
        {
            OVS_TCP_HEADER* pTestTcpHeader = (OVS_TCP_HEADER*)AdvanceIpv4Header((OVS_IPV4_HEADER*)netHeader);
            OVS_CHECK(pTcpHeader == pTestTcpHeader);
            UNREFERENCED_PARAMETER(pTestTcpHeader);
        }
#endif
    }
    else
    {
        OVS_CHECK(pChecksumOffloadInfo->Transmit.IsIPv6);
        pTcpHeader = Ipv6_FindExtensionHeader((OVS_IPV6_HEADER*)netHeader, OVS_IPV6_EXTH_TCP, /*ext lens*/ NULL);
    }

    tcpFlags = GetTcpFlags(pTcpHeader->flagsAndOffset);
    //0x02 is  syn flag
    if (tcpFlags & 0x02)
    {
        UINT16 tcpDataOffset = GetTcpDataOffset(pTcpHeader->flagsAndOffset);
        UINT16 tcpHeaderSize = tcpDataOffset * sizeof(DWORD);
        if (tcpHeaderSize >= sizeof(OVS_TCP_HEADER))
        {
            UINT optionsLen = tcpHeaderSize - sizeof(OVS_TCP_HEADER);
            BYTE* pOption = (BYTE*)pTcpHeader + sizeof(OVS_TCP_HEADER);
            ULONG bytesAdvanced = 0, bytesToAdvance = 0;
            BYTE optionKind = 0;

            while (bytesAdvanced < optionsLen)
            {
                optionKind = *pOption;

                if (optionKind == TcpOptionKind_EndOfOptions)
                {
                    break;
                }

                if (optionKind == TcpOptionKind_NoOperation)
                {
                    //no option -- padding
                    bytesToAdvance = 1;
                }
                else if (optionKind == TcpOptionKind_MSS)
                {
                    BYTE optionLen = *(pOption + 1);
                    UINT16* pMss = NULL, mss = 0;

                    UNREFERENCED_PARAMETER(optionLen);
                    OVS_CHECK(optionLen == 4);

                    pMss = (UINT16*)(pOption + 2);//rtl ushort
                    mss = RtlUshortByteSwap(*pMss);

                    if (encapsSize > 0)
                    {
                        if (mss >= mtu - 40) //for mtu = 1500, mss is 1460 for max packet: ip + tcp headers
                        {
                            mss -= (UINT16)encapsSize;
                            *pMss = RtlUshortByteSwap(mss);
                        }
                    }

                    OVS_CHECK(mss > tcpHeaderSize);

                    break;
                }
                else
                {
                    BYTE optionLen = *(pOption + 1);
                    bytesToAdvance += optionLen;
                }

                pOption += bytesToAdvance;
                bytesAdvanced += bytesToAdvance;
            }
        }
    }

    pTcpHeader->checksum = 0;
    checksum = ComputeTransportChecksum(pTcpHeader, netHeader, ethType);
    checksum = RtlUshortByteSwap(checksum);

    pTcpHeader->checksum = checksum;

    pChecksumOffloadInfo->Transmit.TcpChecksum = 0;
    pChecksumOffloadInfo->Transmit.TcpHeaderOffset = 0;
}

static VOID _HandleChecksumOffload_Udp(LE16 ethType, BYTE* netHeader, _Inout_ NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pChecksumOffloadInfo)
{
    OVS_UDP_HEADER* pUdpHeader = NULL;

    if (ethType == OVS_ETHERTYPE_IPV4)
    {
        OVS_CHECK(pChecksumOffloadInfo->Transmit.IsIPv4);

        pUdpHeader = (OVS_UDP_HEADER*)AdvanceIpv4Header((OVS_IPV4_HEADER*)netHeader);
    }
    else
    {
        OVS_CHECK(pChecksumOffloadInfo->Transmit.IsIPv6);

        pUdpHeader = Ipv6_FindExtensionHeader((OVS_IPV6_HEADER*)netHeader, OVS_IPV6_EXTH_UDP, /*ext lens*/ NULL);
    }

    UINT16 checksum = 0;
    pUdpHeader->checksum = 0;

    checksum = ComputeTransportChecksum(pUdpHeader, netHeader, ethType);
    checksum = RtlUshortByteSwap(checksum);

    pUdpHeader->checksum = checksum;

    pChecksumOffloadInfo->Transmit.UdpChecksum = 0;
    pChecksumOffloadInfo->Transmit.TcpHeaderOffset = 0;
}

//eth type: ipv4 / ipv6? (for computing pseudo header checksum)
//eth size: the size of the eth_h in pOvsNb
//encapsSize, mtu: if encaps > 0 && mss overflows mtu if we add encaps => tcp mss must be decreased
VOID HandleChecksumOffload(_In_ OVS_NET_BUFFER* pOvsNb, BOOLEAN isFromExternal, ULONG encapsSize, ULONG mtu)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* pChecksumOffloadInfo = NULL;
    BYTE* netBuffer = NULL;
    ULONG ethSize = 0;
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    BYTE* netHeader = NULL;
    LE16 ethType = 0;

    //NOTE: pChecksumOffloadInfo has valid values for checksum offloading (i.e. pChecksumOffloadInfo->Transmit) only when the src port id != external
    //when src is external, we have pChecksumOffloadInfo->Receive, which does not concern us
    if (isFromExternal)
    {
        return;
    }

    netBuffer = ONB_GetData(pOvsNb);
    pEthHeader = GetEthernetHeader(netBuffer, &ethSize);
    ethType = RtlUshortByteSwap(pEthHeader->type);

    //TODO: WATCH FOR PSEUDO HEADER - IT IS ALREADY COMPUTED!

    //if have tcp / udp csum offloading and we need to encapsulate: disable tcp / udp csum offloading, compute checksum for tcp / udp
    pChecksumOffloadInfo = GetChecksumOffloadInfo(pOvsNb->pNbl);

    if (pChecksumOffloadInfo->Value == 0)
    {
        return;
    }

    if (!pChecksumOffloadInfo->Transmit.IsIPv4 && !pChecksumOffloadInfo->Transmit.IsIPv6)
    {
        return;
    }

    netHeader = AdvanceEthernetHeader(pEthHeader, ethSize);

    if (ethType == OVS_ETHERTYPE_IPV4 && pChecksumOffloadInfo->Transmit.IpHeaderChecksum)
    {
        _HandleChecksumOffload_Ipv4(netHeader, pChecksumOffloadInfo);
    }

    if (pChecksumOffloadInfo->Transmit.TcpChecksum)
    {
        _HandleChecksumOffload_Tcp(ethType, ethSize, encapsSize, mtu, netHeader, pChecksumOffloadInfo);
    }
    else if (pChecksumOffloadInfo->Transmit.UdpChecksum)
    {
        _HandleChecksumOffload_Udp(ethType, netHeader, pChecksumOffloadInfo);
    }

    //reset checksum value to 0: this NET_BUFFER_LIST info is disabled.
    pChecksumOffloadInfo->Value = 0;
}