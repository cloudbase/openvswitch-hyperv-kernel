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
#include "Error.h"

typedef struct _OVS_FLOW_TABLE OVS_FLOW_TABLE;

typedef struct _OVS_DATAPATH_STATS
{
    UINT64 flowTableMatches;
    UINT64 flowTableMissed;
    //i.e. packets lost = not sent to user space (had no flow)
    UINT64 countLost;
    //# of flows present
    UINT64 masksMatched;
}OVS_DATAPATH_STATS, *POVS_DATAPATH_STATS;

typedef struct _OVS_DATAPATH_MEGAFLOW_STATS
{
    UINT64 masksMatched;
    UINT32 countMasks;
    //may be used in the future. ATM these values are unused
    BYTE padding[20];
}OVS_DATAPATH_MEGAFLOW_STATS, *POVS_DATAPATH_MEGAFLOW_STATS;

//NOTE: this enum is used as FLAGS: multiple values can be used, OR-ed together
typedef enum _OVS_DATAPATH_FEATURE
{
    OVS_DATAPATH_FEATURE_LAST_NLA_UNALIGNED = 1,
    OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT = 2
}OVS_DATAPATH_FEATURE;

typedef struct _OVS_DATAPATH
{
    //must be the first field in the struct
    OVS_REF_COUNT refCount;

    //entry in OVS_DRIVER
    LIST_ENTRY        listEntry;

    char*                name;
    //we keep one single datapath, which is created at startup.
    //we set 'deleted' = true, when it is 'deleted' from userspace
    //and we set it to false when it's created from userspace.
    //it tells us if the datapath struct is usable.
    BOOLEAN                deleted;
    /* protects stats and any other fields, and allows the replace of pFlowTable with another flow table
    **  to destroy the pFlowTable, you must;
    **        acquire this rw lock for write (so no thread would get a reference to it in the mean time)
    **        replace the pFlowTable
    **        at this moment we can destroy the pFlowTable only when / if no one else is using it.
    **        ** references to pFlowTable are retrieved (and released) using pDatapath->pRwLock
    **        call FlowTable_Destroy: if pFlowTable->refCount == 0, it will destroy the flow table
    **                                else, it will mark pFlowTable for deletion, so that the last dereferncing will destroy it.
    **        unlock the rw lock (now the datapath is safe to use by other threads, and its pFlowTable is safe to be retrieved)
    */
    PNDIS_RW_LOCK_EX    pRwLock;

    OVS_FLOW_TABLE*        pFlowTable;

    ULONG                switchIfIndex;

    OVS_DATAPATH_STATS    statistics;

    //values: constants of enum OVS_DATAPATH_FEATURE
    UINT32                userFeatures;
}OVS_DATAPATH, *POVS_DATAPATH;

#define DATAPATH_LOCK_READ(pDatapath, pLockState) NdisAcquireRWLockRead(pDatapath->pRwLock, pLockState, 0)
#define DATAPATH_LOCK_WRITE(pDatapath, pLockState) NdisAcquireRWLockWrite(pDatapath->pRwLock, pLockState, 0)
#define DATAPATH_UNLOCK(pDatapath, pLockState) NdisReleaseRWLock(pDatapath->pRwLock, pLockState)
#define DATAPATH_UNLOCK_IF(pDatapath, pLockState, locked) { if (pDatapath && locked) NdisReleaseRWLock(pDatapath->pRwLock, pLockState); }

OVS_ERROR CreateMsgFromDatapath(OVS_DATAPATH* pDatapath, _In_ const OVS_MESSAGE* pInMsg,_Out_ OVS_MESSAGE* pOutMsg, UINT8 command);

OVS_DATAPATH* GetDefaultDatapath_Ref(const char* funcName);
BOOLEAN CreateDefaultDatapath(NET_IFINDEX dpIfIndex);
VOID Datapath_DestroyNow_Unsafe(OVS_DATAPATH* pDatapath);
OVS_ERROR Datapath_FlushFlows(OVS_DATAPATH* pDatapath);

OVS_FLOW_TABLE* Datapath_ReferenceFlowTable(OVS_DATAPATH* pDatapath);

VOID Datapath_DestroyNow_Unsafe(OVS_DATAPATH* pDatapath);
