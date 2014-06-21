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

/* STRUCTS AND FUNCTIONS FOR HANDLY HYPER-V SWITCH VPORTS */

#include "precomp.h"

typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;
typedef struct _OVS_PERSISTENT_PORT OVS_PERSISTENT_PORT;

typedef struct _OVS_PORT_LIST_ENTRY
{
	//must be the first field in the struct
	OVS_RCU							rcu;

    LIST_ENTRY						listEntry;

    NDIS_SWITCH_PORT_ID				portId;
    NDIS_SWITCH_PORT_FRIENDLYNAME	portFriendlyName;
    NDIS_SWITCH_PORT_TYPE			portType;
    BOOLEAN							on;

    OVS_PERSISTENT_PORT*			pPersistentPort;
} OVS_PORT_LIST_ENTRY, *POVS_PORT_LIST_ENTRY;

OVS_PORT_LIST_ENTRY* Sctx_FindPortById_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_ NDIS_SWITCH_PORT_ID portId);
NDIS_STATUS Sctx_AddPort_Unsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pCurPort, _Inout_opt_ OVS_PORT_LIST_ENTRY** ppPortEntry);

VOID PortEntry_DestroyNow_Unsafe(OVS_PORT_LIST_ENTRY* pPortEntry);
NDIS_STATUS Sctx_DeletePort_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId);

OVS_PORT_LIST_ENTRY* Sctx_FindPortBy_Unsafe(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const VOID* pContext, BOOLEAN(*Predicate)(int, const VOID*, _In_ const OVS_PORT_LIST_ENTRY*));

//i.e. you must lock the pForwardInfo->pRwLock
VOID Sctx_Port_SetPersistentPort_Unsafe(_Inout_ OVS_PORT_LIST_ENTRY* pPortEntry);
//i.e. you must lock the pForwardInfo->pRwLock
VOID Sctx_Port_UnsetPersistentPort_Unsafe(_Inout_ OVS_PORT_LIST_ENTRY* pPortEntry);

VOID Sctx_Port_Disable_Unsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ OVS_PORT_LIST_ENTRY* pPortEntry);

VOID Sctx_Port_UpdateName_Unsafe(_Inout_ OVS_PORT_LIST_ENTRY* pPortEntry, _In_ const IF_COUNTED_STRING* pNewName);