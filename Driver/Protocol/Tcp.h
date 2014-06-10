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

#pragma once

#include "precomp.h"
#include "Types.h"

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_PI_TCP OVS_PI_TCP;

/*************************************/

//TODO: must test to see if the bitfields are set ok (considering LE system)
typedef struct _OVS_TCP_HEADER {
    UINT16	sourcePort;
    UINT16	destinationPort;
    SEQ_NUM	sequenceNo;//DWORD
    SEQ_NUM acknowledgeNo;

    //flag bits (after the 6 bits = reserved)
    //bit 0: URG
    //bit 1: ACK
    //bit 2: PSH
    //bit 3: RST
    //bit 4: SYN
    //bit 5: FIN
    UINT16 flagsAndOffset;

    UINT16 window;
    UINT16 checksum;
    UINT16 urgentPointer;
}OVS_TCP_HEADER, *POVS_TCP_HEADER;

C_ASSERT(sizeof(OVS_TCP_HEADER) == 20);

typedef struct _OVS_TRANSPORT_PSEUDO_HEADER_IPV4 {
    BYTE srcIp[4];
    BYTE destIp[4];
    BYTE reserved;
    BYTE protocol;
    WORD tcpLen;
}OVS_TRANSPORT_PSEUDO_HEADER_IPV4, *POVS_TRANSPORT_PSEUDO_HEADER_IPV4;

C_ASSERT(sizeof(OVS_TRANSPORT_PSEUDO_HEADER_IPV4) == 12);

typedef struct _OVS_TRANSPORT_PSEUDO_HEADER_IPV6 {
    BYTE srcIp[16];
    BYTE destIp[16];
    BYTE reserved;
    BYTE protocol;
    WORD tcpLen;
}OVS_TRANSPORT_PSEUDO_HEADER_IPV6, *POVS_TRANSPORT_PSEUDO_HEADER_IPV6;

C_ASSERT(sizeof(OVS_TRANSPORT_PSEUDO_HEADER_IPV6) == 36);

/*************************************/

enum TcpOptionKind {
    TcpOptionKind_EndOfOptions = 0x0, TcpOptionKind_NoOperation = 0x01, TcpOptionKind_MSS = 0x02, TcpOptionKind_WindowScale = 0x03, TcpOptionKind_SelAckPermitted = 0x04,
    TcpOptionKind_SelAcknowledgment = 0x05, TcpOptionKind_Timestamp = 0x08, TcpOptionKind_AltCsumRequest = 0xe, TcpOptionKind_AltCsum = 0xf
};

/********************************************************************/

OVS_TCP_HEADER* GetTcpHeader(VOID* pPacketBuffer);

BOOLEAN ONB_SetTcp(OVS_NET_BUFFER* pOvsNb, const OVS_PI_TCP* pTcpPI);

BOOLEAN VerifyTcpHeader(BYTE* buffer, ULONG* pLength);

static __inline UINT16 GetTcpDataOffset(UINT16 flagsAndOffset)
{
    UINT16 dataOffset = flagsAndOffset & 0xFF;
    dataOffset >>= 4;

    return dataOffset;
}

static __inline VOID SetTcpDataOffset(UINT16* pFlagsAndOffset, UINT16 dataOffset)
{
    OVS_CHECK(dataOffset <= 0xF);
    *pFlagsAndOffset |= dataOffset << 4;
}

static __inline UINT16 GetTcpReserved(UINT16 flagsAndOffset)
{
    UINT16 reserved = _byteswap_ushort(flagsAndOffset);
    reserved >>= 9;
    reserved &= 0x7;

    return reserved;
}

static __inline VOID SetTcpReserved(UINT16* pFlagsAndOffset, UINT16 reserved)
{
    OVS_CHECK(reserved <= 0x3F);

    UINT16 temp = reserved;
    temp <<= 9;
    temp = _byteswap_ushort(temp);

    *pFlagsAndOffset |= temp;
}

//TODO: there are 9 bits for tcp flags / control bits: 6 normal flags + 3 ECN flags
//check RFC3168 and RFC3540 for the ECN bits
//which means the maximum value for a flag is 0x1FF (binary BE: 0000 0001 1111 1111)
//FlagsAndOffset is a WORD, as BE it is: OOOO RRRC CCCC CCCC, where
//O = Data Offset
//R = Reserved
//C = Control bit
//0x1FF in BE is:				0000 0001 1111 1111
//0x1FF in LE is:				1111 1111 0000 0001
//FlagsAndOffset as LE it is:	CCCC CCCC OOOO RRRC
//=> &= is flags only:			CCCC CCCC 0000 000C
static __inline UINT16 GetTcpFlags(UINT16 flagsAndOffset)
{
    UINT16 flags = _byteswap_ushort(flagsAndOffset);
    flags &= 0x1FF;

    return flags;
}

static __inline VOID SetTcpFlags(UINT16* pFlagsAndOffset, UINT16 flags)
{
    OVS_CHECK(flags <= 0x1FF);

    UINT16 temp = flags;
    temp = _byteswap_ushort(temp);

    *pFlagsAndOffset |= temp;
}

//buffer: net buffer starting with the tcp header
//dbgprints tcp info
void DbgPrintTcpHeader(_In_ const VOID* buffer);