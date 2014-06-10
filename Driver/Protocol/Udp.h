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

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_PI_UDP OVS_PI_UDP;

typedef struct _OVS_UDP_HEADER {
    UINT16 sourcePort;
    UINT16 destinationPort;
    UINT16 length;
    UINT16 checksum;
    //payload follows
}OVS_UDP_HEADER, *POVS_UDP_HEADER;

OVS_UDP_HEADER* GetUdpHeader(VOID* pPacketBuffer);
BOOLEAN ONB_SetUdp(OVS_NET_BUFFER *pNb, const OVS_PI_UDP* pUdpPI);

//buffer: net buffer starting with the udp header
//dbg prints udp info
void DbgPrintUdpHeader(_In_ const VOID* buffer);

BOOLEAN VerifyUdpHeader(BYTE* buffer, ULONG* pLength);