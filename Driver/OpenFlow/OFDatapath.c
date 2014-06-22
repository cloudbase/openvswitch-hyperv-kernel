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

#include "OFDatapath.h"
#include "OFPort.h"
#include "OvsCore.h"
#include "WinlDatapath.h"
#include "List.h"
#include "Argument.h"
#include "Message.h"
#include "ArgumentType.h"
#include "PersistentPort.h"
#include "OvsCore.h"
#include "OFFlowTable.h"

static OVS_DATAPATH* g_pDefaultDatapath = NULL;
static PNDIS_RW_LOCK_EX g_pFlowTableRwLock = NULL;

VOID Datapath_DestroyNow_Unsafe(OVS_DATAPATH* pDatapath)
{
	OVS_FLOW_TABLE* pFlowTable = NULL;
	LOCK_STATE_EX lockState;

	if (pDatapath->name)
		KFree(pDatapath->name);

	DATAPATH_LOCK_WRITE(pDatapath, &lockState);

	pFlowTable = pDatapath->pFlowTable;
	pDatapath->pFlowTable = NULL;
	OVS_RCU_DESTROY(pFlowTable);

	DATAPATH_UNLOCK(pDatapath, &lockState);

	NdisFreeRWLock(pDatapath->pRwLock);
}

OVS_DATAPATH* GetDefaultDatapath()
{
    return g_pDefaultDatapath;
}

VOID FlowTable_LockRead(_In_ LOCK_STATE_EX* pLockState)
{
    NdisAcquireRWLockRead(g_pFlowTableRwLock, pLockState, 0);
}

VOID FlowTable_LockWrite(_In_ LOCK_STATE_EX* pLockState)
{
    NdisAcquireRWLockWrite(g_pFlowTableRwLock, pLockState, 0);
}

BOOLEAN IsLockInitialized(const LOCK_STATE_EX* pLockState)
{
    LOCK_STATE_EX tmp = { 0 };
    return pLockState && memcmp(pLockState, &tmp, sizeof(LOCK_STATE_EX));
}

VOID FlowTable_Unlock(_In_ LOCK_STATE_EX* pLockState)
{
    if (IsLockInitialized(pLockState))
    {
        Rwlock_Unlock(g_pFlowTableRwLock, pLockState);
    }
}

static void _GetDatapathStats(OVS_DATAPATH* pDatapath, OVS_DATAPATH_STATS* pStats)
{
    OVS_FLOW_TABLE* pFlowTable = NULL;
    LOCK_STATE_EX lockStateData = { 0 }, lockStateFlowTable = { 0 };

    DATAPATH_LOCK_READ(pDatapath, &lockStateData);

    pFlowTable = pDatapath->pFlowTable;

    FLOWTABLE_LOCK_READ(pFlowTable, &lockStateFlowTable);
    pStats->countFlows = pFlowTable->countFlows;
    FLOWTABLE_UNLOCK(pFlowTable, &lockStateFlowTable);

    pStats->flowTableMatches = pDatapath->statistics.flowTableMatches;
    pStats->flowTableMissed = pDatapath->statistics.flowTableMissed;
    pStats->countLost = pDatapath->statistics.countLost;

    DATAPATH_UNLOCK(pDatapath, &lockStateData);
}

BOOLEAN CreateMsgFromDatapath(OVS_DATAPATH* pDatapath, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid)
{
    OVS_ARGUMENT_GROUP* pArgGroup = NULL;
    OVS_ARGUMENT* pNameArg = NULL, *pStatsArg = NULL;
    const char* datapathName = NULL;
    OVS_DATAPATH_STATS dpStats = { 0 };
    BOOLEAN ok = TRUE;

    OVS_CHECK(pMsg);

    pArgGroup = AllocArgumentGroup();

    if (!pArgGroup)
    {
        return FALSE;
    }

    AllocateArgumentsToGroup(2, pArgGroup);

    datapathName = pDatapath->name;

    pNameArg = CreateArgumentStringA_Alloc(OVS_ARGTYPE_DATAPATH_NAME, datapathName);
    if (!pNameArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pArgGroup->args[0] = *pNameArg;
    pArgGroup->groupSize += pNameArg->length;

    _GetDatapathStats(pDatapath, &dpStats);

    pStatsArg = CreateArgument_Alloc(OVS_ARGTYPE_DATAPATH_STATS, &dpStats);
    if (!pStatsArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pArgGroup->args[1] = *pStatsArg;
    pArgGroup->groupSize += pStatsArg->length;

    pMsg->length = sizeof(OVS_MESSAGE);
    pMsg->type = OVS_MESSAGE_TARGET_DATAPATH;
    pMsg->flags = 0;
    pMsg->sequence = sequence;
    pMsg->pid = pid;

    pMsg->command = cmd;
    pMsg->version = 1;
    pMsg->reserved = 0;

    pMsg->dpIfIndex = dpIfIndex;

    pMsg->pArgGroup = pArgGroup;

Cleanup:
    if (ok)
    {
        FreeArgument(pNameArg);
        FreeArgument(pStatsArg);
    }

    else
    {
        if (pNameArg)
        {
            DestroyArgument(pNameArg);
        }

        if (pStatsArg)
        {
            DestroyArgument(pStatsArg);
        }

        if (pArgGroup)
        {
            FreeArguments(pArgGroup);
            FreeArgGroup(pArgGroup);
        }

        return FALSE;
    }

    return ok;
}

BOOLEAN CreateDefaultDatapath(NDIS_HANDLE ndisFilterHandle)
{
    OVS_DATAPATH* pDatapath = NULL;
    BOOLEAN ok = TRUE;

    g_pFlowTableRwLock = NdisAllocateRWLock(ndisFilterHandle);
    if (!g_pFlowTableRwLock)
    {
        DEBUGP(LOG_ERROR, "could not allocate global datapath rwlock\n");
        return FALSE;
    }

    pDatapath = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_DATAPATH), g_extAllocationTag);
    if (pDatapath == NULL)
    {
        ok = FALSE;
        goto Cleanup;
    }

    RtlZeroMemory(pDatapath, sizeof(OVS_DATAPATH));

	pDatapath->rcu.Destroy = Datapath_DestroyNow_Unsafe;
    pDatapath->name = NULL;

    //i.e. at the beginning we don't have a datapath, we expect the userspace to tell us: 'create datapath'
    pDatapath->deleted = TRUE;

    //ALLOCATE TABLE
    pDatapath->pFlowTable = FlowTable_Create();
    if (!pDatapath->pFlowTable)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pDatapath->pRwLock = NdisAllocateRWLock(ndisFilterHandle);

    OVS_CHECK(!g_pDefaultDatapath);
    g_pDefaultDatapath = pDatapath;

Cleanup:

    if (!ok && pDatapath)
    {
        if (pDatapath->pFlowTable)
        {
            FlowTable_DestroyNow_Unsafe(pDatapath->pFlowTable);
        }
        ExFreePoolWithTag(pDatapath, g_extAllocationTag);
    }

    return ok;
}

BOOLEAN Datapath_FlushFlows(OVS_DATAPATH* pDatapath)
{
    OVS_FLOW_TABLE* pOldTable = NULL;
    OVS_FLOW_TABLE* pNewTable = NULL;
    LOCK_STATE_EX lockState = { 0 };

    FlowTable_LockWrite(&lockState);

    pOldTable = pDatapath->pFlowTable;
    pNewTable = FlowTable_Create();
    if (!pNewTable)
    {
        FlowTable_Unlock(&lockState);
        return FALSE;
    }

    pDatapath->pFlowTable = pNewTable;

    FlowTable_DestroyNow_Unsafe(pOldTable);

    FlowTable_Unlock(&lockState);
    return TRUE;
}