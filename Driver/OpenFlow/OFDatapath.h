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
#include "OFFlow.h"
#include "OFPort.h"

typedef struct _OVS_FLOW_TABLE OVS_FLOW_TABLE;

typedef struct _OVS_DATAPATH_STATS {
    UINT64 flowTableMatches;
    UINT64 flowTableMissed;
    //i.e. lost = not sent to usr space
    UINT64 countLost;
    //# of flows present
    UINT64 countFlows;
}OVS_DATAPATH_STATS, *POVS_DATAPATH_STATS;

typedef struct _OVS_DATAPATH
{
	//must be the first field in the struct
	OVS_RCU rcu;

    char*				name;
    //we keep one single datapath, which is created at startup.
    //we set 'deleted' = true, when it is 'deleted' from userspace
    //and we set it to false when it's created from userspace.
    //it tells us if the datapath struct is usable.
    BOOLEAN				deleted;
    PNDIS_RW_LOCK_EX	pRwLock;
    OVS_FLOW_TABLE*		pFlowTable;

	ULONG				switchIfIndex;

    OVS_DATAPATH_STATS	statistics;
}OVS_DATAPATH, *POVS_DATAPATH;

#define DATAPATH_LOCK_READ(pDatapath, pLockState) NdisAcquireRWLockRead(pDatapath->pRwLock, pLockState, 0)
#define DATAPATH_LOCK_WRITE(pDatapath, pLockState) NdisAcquireRWLockWrite(pDatapath->pRwLock, pLockState, 0)
#define DATAPATH_UNLOCK(pDatapath, pLockState) NdisReleaseRWLock(pDatapath->pRwLock, pLockState)

BOOLEAN CreateMsgFromDatapath(OVS_DATAPATH* pDatapath, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid);

OVS_DATAPATH* GetDefaultDatapath();
BOOLEAN CreateDefaultDatapath(NDIS_HANDLE ndisFilterHandle);
VOID Datapath_DestroyNow_Unsafe(OVS_DATAPATH* pDatapath);
BOOLEAN Datapath_FlushFlows(OVS_DATAPATH* pDatapath);

VOID FlowTable_LockRead(_In_ LOCK_STATE_EX* pLockState);
VOID FlowTable_LockWrite(_In_ LOCK_STATE_EX* pLockState);
VOID FlowTable_Unlock(_In_ LOCK_STATE_EX* pLockState);
