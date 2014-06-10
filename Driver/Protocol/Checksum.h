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

#define OVS_UDP_CHECKSUM_MANGLED ((UINT16)0xffff)

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_TCP_HEADER OVS_TCP_HEADER;
typedef struct _OVS_UDP_HEADER OVS_UDP_HEADER;
typedef struct _OVS_ETHERNET_HEADER OVS_ETHERNET_HEADER;

//TODO: IMPLEMENT -- must compute CRC32 checksum
static __inline UINT32 Sctp_ComputeChecksum(const OVS_NET_BUFFER* pOvsNb, unsigned int offset)
{
    UNREFERENCED_PARAMETER(pOvsNb);
    UNREFERENCED_PARAMETER(offset);

    OVS_CHECK(__NOT_IMPLEMENTED__);

    return 0;
}

//returns BE16 checksum value in UINT
UINT ComputeIpChecksum(const BYTE* buffer, UINT size);
UINT RecomputeChecksum(const BYTE* oldBuffer, const BYTE* newBuffer, ULONG len, WORD checksum);

LE16 ComputeTransportChecksum(VOID* transportBuffer, VOID* protocolBuffer, LE16 ethType);
WORD ChecksumAddCsum(UINT checksum, WORD csumToAdd);

VOID HandleChecksumOffload(_In_ OVS_NET_BUFFER* pOvsNb, BOOLEAN isFromExternal, ULONG encapsSize, ULONG mtu);