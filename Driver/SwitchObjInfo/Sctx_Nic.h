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

#define OVS_NIC_ENTRY_NAME_SIZE        IF_MAX_STRING_SIZE

#include "Switch.h"
#include "Ethernet.h"

/* STRUCTS AND FUNCTIONS FOR HANDLING HYPER-V SWITCH NICS */

typedef struct _OVS_NIC_INFO
{
    BYTE                    mac[OVS_ETHERNET_ADDRESS_LENGTH];
    NDIS_SWITCH_PORT_ID     portId;
    NDIS_SWITCH_NIC_INDEX   nicIndex;
    ULONG                   mtu;
    BOOLEAN                 nicConnected;

#ifdef DBG
    CHAR                    nicName[OVS_NIC_ENTRY_NAME_SIZE + 1];
    CHAR                    vmName[OVS_NIC_ENTRY_NAME_SIZE + 1];
#endif
}OVS_NIC_INFO, *POVS_NIC_INFO;

typedef struct _OVS_NIC_LIST_ENTRY
{
    OVS_REF_COUNT                       refCount;

    LIST_ENTRY                          listEntry;
    UINT8                               macAddress[OVS_ETHERNET_ADDRESS_LENGTH];
    NDIS_SWITCH_PORT_ID                 portId;
    NDIS_SWITCH_NIC_INDEX               nicIndex;
    NDIS_SWITCH_NIC_TYPE                nicType;

    BOOLEAN                             connected;
    ULONG                               mtu;

    //OVS_OFPORT_STATS                  portStats;

    //OVS_INVALID_PORT_NUMBER (0xFFFF) if we don't have one
    UINT16                              ovsPortNumber;
#ifdef DBG
    CHAR                                vmName[OVS_NIC_ENTRY_NAME_SIZE + 1];
    CHAR                                adapName[OVS_NIC_ENTRY_NAME_SIZE + 1];
#endif
} OVS_NIC_LIST_ENTRY, *POVS_NIC_LIST_ENTRY;

static __inline VOID NicListEntry_To_NicInfo(_In_ const OVS_NIC_LIST_ENTRY* pNicListEntry, _Out_ OVS_NIC_INFO* pNicInfo)
{
    RtlZeroMemory(pNicInfo, sizeof(OVS_NIC_INFO));

    pNicInfo->nicIndex = pNicListEntry->nicIndex;
    pNicInfo->portId = pNicListEntry->portId;

    RtlCopyMemory(pNicInfo->mac, pNicListEntry->macAddress, OVS_ETHERNET_ADDRESS_LENGTH);
#ifdef DBG
    RtlCopyMemory(pNicInfo->nicName, pNicListEntry->adapName, OVS_NIC_ENTRY_NAME_SIZE);
    RtlCopyMemory(pNicInfo->vmName, pNicListEntry->vmName, OVS_NIC_ENTRY_NAME_SIZE);
#endif

    pNicInfo->nicConnected = pNicListEntry->connected;
    pNicInfo->mtu = pNicListEntry->mtu;
}

/*****************************************************/

VOID Sctx_ClearNicListUnsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo);

NDIS_STATUS Sctx_AddNicUnsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pCurNic, _Inout_opt_ OVS_NIC_LIST_ENTRY** ppNicEntry);

OVS_NIC_LIST_ENTRY* Sctx_FindNicByMacAddressUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_reads_bytes_(6) const UCHAR* pMacAddress);

BOOLEAN Sctx_ForEachNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, VOID* pContext, BOOLEAN(*Action)(int, OVS_NIC_LIST_ENTRY*, VOID*));
BOOLEAN Sctx_CForEachNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, VOID* pContext, BOOLEAN(*Action)(int, _In_ const OVS_NIC_LIST_ENTRY*, VOID*));

const OVS_NIC_LIST_ENTRY* Sctx_CFindNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, BOOLEAN(*Predicate)(int, _In_ const OVS_NIC_LIST_ENTRY*));
OVS_NIC_LIST_ENTRY* Sctx_FindNicBy_Unsafe(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const VOID* pContext, BOOLEAN(*Predicate)(int, const VOID*, _In_ const OVS_NIC_LIST_ENTRY*));

OVS_NIC_LIST_ENTRY* Sctx_FindNicByPortIdAndNicIndex_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_ NDIS_SWITCH_PORT_ID portId, _In_ NDIS_SWITCH_NIC_INDEX nicIndex);
OVS_NIC_LIST_ENTRY* Sctx_FindNicByPortId_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_ NDIS_SWITCH_PORT_ID portId);

VOID NicEntry_DestroyNow_Unsafe(OVS_NIC_LIST_ENTRY* pNicEntry);
NDIS_STATUS Sctx_DeleteNicUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId, _In_ NDIS_SWITCH_NIC_INDEX nicIndex);

//returns the ovs port number of the found pers port
UINT16 Sctx_Nic_SetPersistentPort(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_SWITCH_PORT_ID portId);
