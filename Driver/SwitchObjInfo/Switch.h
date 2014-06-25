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

/* SCTX FUNCTIONS FOR HANDLING SWITCH (OR, PER SWITCH) INFO */

#include "PersistentPort.h"

typedef struct _OVS_NIC_LIST_ENTRY OVS_NIC_LIST_ENTRY;
typedef struct _OVS_PORT_LIST_ENTRY OVS_PORT_LIST_ENTRY;

typedef struct _OVS_GLOBAL_FORWARD_INFO
{
    BOOLEAN                 switchIsActive;

    OVS_NIC_LIST_ENTRY*		pExternalNic;
    OVS_NIC_LIST_ENTRY*		pInternalNic;

    OVS_PORT_LIST_ENTRY*	pExternalPort;
    OVS_PORT_LIST_ENTRY*	pInternalPort;

    LIST_ENTRY              nicList;

    LIST_ENTRY              portList;

    PNDIS_RW_LOCK_EX        pRwLock;

    UINT32                  countNics;
    UINT32                  countPorts;
    BOOLEAN                 isInitialRestart;

    OVS_PERSISTENT_PORTS_INFO	persistentPortsInfo;
} OVS_GLOBAL_FORWARD_INFO, *POVS_GLOBAL_FORWARD_INFO;

typedef enum _OVS_SWITCH_DATAFLOW_STATE {
    OVS_SWITCH_PAUSED,
    OVS_SWITCH_RUNNING
} OVS_SWITCH_DATAFLOW_STATE, *POVS_SWITCH_DATAFLOW_STATE;

typedef enum _OVS_SWITCH_CONTROLFLOW_STATE {
    OVS_SWITCH_UNKNOWN,
    OVS_SWITCH_ATTACHED,
    OVS_SWITCH_DETACHED
} OVS_SWITCH_CONTROLFLOW_STATE, *POVS_SWITCH_CONTROLFLOW_STATE;

typedef struct _OVS_SWITCH_INFO
{
	//must be the first field in the struct
	OVS_REF_COUNT refCount;

    //entry in switchList of OVS_DRIVER
    LIST_ENTRY				listEntry;

    OVS_GLOBAL_FORWARD_INFO* pForwardInfo;

    NDIS_HANDLE filterHandle;
    NDIS_SWITCH_CONTEXT switchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS switchHandlers;

    OVS_SWITCH_DATAFLOW_STATE		dataFlowState;
    OVS_SWITCH_CONTROLFLOW_STATE	controlFlowState;

    volatile LONG pendingInjectedNblCount;
    volatile LONG pendingOidCount;

    NDIS_SWITCH_NIC_OID_REQUEST*	pOldNicRequest;

    NET_IFINDEX datapathIfIndex;
} OVS_SWITCH_INFO, *POVS_SWITCH_INFO;

#define FWDINFO_LOCK_READ(pForwardInfo, pLockState) NdisAcquireRWLockRead(pForwardInfo->pRwLock, pLockState, 0)
#define FWDINFO_LOCK_WRITE(pForwardInfo, pLockState) NdisAcquireRWLockWrite(pForwardInfo->pRwLock, pLockState, 0)
#define FWDINFO_UNLOCK(pForwardInfo, pLockState) NdisReleaseRWLock(pForwardInfo->pRwLock, pLockState)

/*****************************************************  SWITCH ****************************************************/

NDIS_STATUS Switch_CreateForwardInfo(_In_ NDIS_HANDLE filterHandle, _Outptr_result_maybenull_ OVS_GLOBAL_FORWARD_INFO** ppForwardInfo);

VOID Switch_DeleteForwardInfo(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo);

VOID Switch_Activate(_Inout_ OVS_SWITCH_INFO* pSwitchInfo);

NDIS_STATUS Switch_Restart(_Inout_ OVS_SWITCH_INFO* pSwitchInfo);

VOID Switch_Pause(_Inout_ OVS_SWITCH_INFO* pSwitchInfo);

NDIS_STATUS Switch_GetParametersUnsafe(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _Out_ NDIS_SWITCH_PARAMETERS* pSwitchParameters);