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

#include "Arp.h"
#include "Ipv4.h"

extern PNDIS_RW_LOCK_EX g_pArpRWLock;
extern LIST_ENTRY g_arpTable;

typedef struct _OVS_ARP_TABLE_ENTRY {
    LIST_ENTRY listEntry;
    BYTE ip[4];
    BYTE mac[OVS_ETHERNET_ADDRESS_LENGTH];
}OVS_ARP_TABLE_ENTRY, *POVS_ARP_TABLE_ENTRY;

OVS_ARP_HEADER* GetArpHeader(_In_ OVS_ETHERNET_HEADER* pEthHeader)
{
    UINT8* buffer = (UINT8*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER);

    OVS_ARP_HEADER* pArpHeader = (OVS_ARP_HEADER*)buffer;
    OVS_CHECK(pArpHeader);

    return pArpHeader;
}

BYTE* VerifyArpFrame(BYTE* buffer, ULONG* pLength)
{
    OVS_ARP_HEADER* pArpHeader = (OVS_ARP_HEADER*)buffer;
    OVS_CHECK(pArpHeader);
    WORD op = RtlUshortByteSwap(pArpHeader->operation);

    if (RtlUshortByteSwap(pArpHeader->hardwareType) != OVS_ARP_HARDWARE_TYPE_ETHERNET)
    {
        DEBUGP(LOG_ERROR, "arp: hardware type = 0x%x != 1", RtlUshortByteSwap(pArpHeader->hardwareType));
        return NULL;
    }

    if (pArpHeader->harwareLength != OVS_ETHERNET_ADDRESS_LENGTH)
    {
        DEBUGP(LOG_ERROR, "arp: hardware length = 0x%x != 6", pArpHeader->harwareLength);
        return NULL;
    }

    if (op != OVS_ARP_OPERATION_REQUEST &&
        op != OVS_ARP_OPERATION_REPLY)
    {
        DEBUGP(LOG_ERROR, "arp: op unknown - 0x%x", RtlUshortByteSwap(pArpHeader->operation));
        return NULL;
    }

    if (pArpHeader->protocolLength != OVS_IPV4_ADDRESS_LENGTH)
    {
        DEBUGP(LOG_ERROR, "arp: protocol length = 0x%x != 4", pArpHeader->harwareLength);
        return NULL;
    }

    if (RtlUshortByteSwap(pArpHeader->protocolType) != OVS_ETHERTYPE_IPV4)
    {
        DEBUGP(LOG_ERROR, "arp: protocol type = 0x%x != ipv4", RtlUshortByteSwap(pArpHeader->protocolType));
        return NULL;
    }

    *pLength -= sizeof(OVS_ARP_HEADER);
    return buffer + sizeof(OVS_ARP_HEADER);
}

static BYTE* _Arp_FindTableEntry_Unsafe(_In_ const BYTE ip[4])
{
    PLIST_ENTRY pCurEntry = g_arpTable.Flink;

    if (IsListEmpty(&g_arpTable))
    {
        return NULL;
    }

    do
    {
        OVS_ARP_TABLE_ENTRY* pArpEntry = CONTAINING_RECORD(pCurEntry, OVS_ARP_TABLE_ENTRY, listEntry);

        if (RtlEqualMemory(ip, pArpEntry->ip, sizeof(OVS_IPV4_ADDRESS_LENGTH)))
        {
            OVS_CHECK(pArpEntry->mac);
            return pArpEntry->mac;
        }

        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != &g_arpTable);

    return NULL;
}

VOID Arp_InsertTableEntry(_In_ const BYTE ip[4], _In_ const BYTE mac[OVS_ETHERNET_ADDRESS_LENGTH])
{
    LOCK_STATE_EX lockState = { 0 };
    BYTE* pMacAddr = NULL;

    Rwlock_LockWrite(g_pArpRWLock, &lockState);

    pMacAddr = _Arp_FindTableEntry_Unsafe(ip);
    if (!pMacAddr)
    {
        OVS_ARP_TABLE_ENTRY* pArpEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_ARP_TABLE_ENTRY), g_extAllocationTag);
        if (!pArpEntry)
        {
            DEBUGP(LOG_ERROR, "Failed to allocate arp table entry!\n");
            return;
        }

        RtlCopyMemory(pArpEntry->ip, ip, OVS_IPV4_ADDRESS_LENGTH);
        RtlCopyMemory(pArpEntry->mac, mac, OVS_ETHERNET_ADDRESS_LENGTH);

        InsertHeadList(&g_arpTable, &pArpEntry->listEntry);
    }

    else
    {
        RtlCopyMemory(pMacAddr, mac, OVS_ETHERNET_ADDRESS_LENGTH);
    }

    Rwlock_Unlock(g_pArpRWLock, &lockState);
}

const BYTE* Arp_FindTableEntry(_In_ const BYTE ip[4])
{
    LOCK_STATE_EX lockState = { 0 };
    const BYTE* pMac = NULL;

    Rwlock_LockRead(g_pArpRWLock, &lockState);

    pMac = _Arp_FindTableEntry_Unsafe(ip);

    Rwlock_Unlock(g_pArpRWLock, &lockState);

    return pMac;
}

VOID Arp_DestroyTable()
{
    OVS_ARP_TABLE_ENTRY* pArpEntry = NULL;
    PLIST_ENTRY headList = NULL;
    LOCK_STATE_EX lockState = { 0 };

    Rwlock_LockWrite(g_pArpRWLock, &lockState);

    while (!IsListEmpty(&g_arpTable))
    {
        headList = RemoveHeadList(&g_arpTable);

        pArpEntry = CONTAINING_RECORD(headList, OVS_ARP_TABLE_ENTRY, listEntry);

        ExFreePoolWithTag(pArpEntry, g_extAllocationTag);
    }

    Rwlock_Unlock(g_pArpRWLock, &lockState);
}