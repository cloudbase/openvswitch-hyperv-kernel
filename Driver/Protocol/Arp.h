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
#include "Ethernet.h"

typedef struct _OVS_ARP_HEADER {
    UINT16      hardwareType;
    UINT16      protocolType;

    BYTE   harwareLength;
    BYTE   protocolLength;

    //1 = request; 2 = reply;
    UINT16 operation;

    BYTE       senderHardwareAddress[OVS_ETHERNET_ADDRESS_LENGTH];
    BYTE       senderProtocolAddress[4];
    BYTE       targetHardwareAddress[OVS_ETHERNET_ADDRESS_LENGTH];
    BYTE       targetProtocolAddress[4];
} OVS_ARP_HEADER, *POVS_ARP_HEADER;

void DbgPrintArp(OVS_ARP_HEADER* pArpHeader);

#define OVS_ARP_OPERATION_REQUEST        1
#define OVS_ARP_OPERATION_REPLY          2
#define OVS_ARP_HARDWARE_TYPE_ETHERNET   1

OVS_ARP_HEADER* GetArpHeader(_In_ OVS_ETHERNET_HEADER* pEthHeader);
BYTE* VerifyArpFrame(BYTE* buffer, ULONG* pLength);

VOID Arp_InsertTableEntry(_In_ const BYTE ip[4], _In_ const BYTE mac[OVS_ETHERNET_ADDRESS_LENGTH]);
const BYTE* Arp_FindTableEntry(_In_ const BYTE ip[4]);
VOID Arp_DestroyTable();