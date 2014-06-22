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

#include "Switch.h"

#include "Driver.h"

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

OVS_DATAPATH* GetDefaultDatapath_Ref(const char* funcName)
{
	OVS_DATAPATH* pDatapath = NULL;

	DRIVER_LOCK();

	OVS_CHECK(!IsListEmpty(&g_driver.datapathList));

	pDatapath = CONTAINING_RECORD(g_driver.datapathList.Flink, OVS_DATAPATH, listEntry);
	pDatapath = Rcu_Reference(pDatapath, funcName);

	DRIVER_UNLOCK();

	return pDatapath;
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
    char* datapathName = NULL;
    OVS_DATAPATH_STATS dpStats = { 0 };
    BOOLEAN ok = TRUE;
	ULONG nameLen = 0;
	LOCK_STATE_EX lockState;

    OVS_CHECK(pMsg);

	DATAPATH_LOCK_READ(pDatapath, &lockState);

	nameLen = (ULONG)strlen(pDatapath->name) + 1;
	datapathName = KAlloc(nameLen);
	RtlCopyMemory(datapathName, pDatapath->name, nameLen);

	_GetDatapathStats(pDatapath, &dpStats);

	DATAPATH_UNLOCK(pDatapath, &lockState);

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
	if (datapathName)
		KFree(datapathName);

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
	OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN ok = TRUE;

    pDatapath = KZAlloc(sizeof(OVS_DATAPATH));
    if (pDatapath == NULL)
    {
        ok = FALSE;
        goto Cleanup;
    }

	pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
	if (!pSwitchInfo) {
		ok = FALSE;
		goto Cleanup;
	}

	pDatapath->switchIfIndex = pSwitchInfo->datapathIfIndex;
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

	OVS_CHECK(!Driver_HaveDatapath());

	//TODO: use an interlocked single list instead!
	DRIVER_LOCK();
	InsertHeadList(&g_driver.datapathList, &pDatapath->listEntry);
	DRIVER_UNLOCK();

Cleanup:
    if (!ok && pDatapath)
    {
        if (pDatapath->pFlowTable)
        {
            FlowTable_DestroyNow_Unsafe(pDatapath->pFlowTable);
        }
        ExFreePoolWithTag(pDatapath, g_extAllocationTag);
    }

	if (pSwitchInfo) {
		OVS_RCU_DEREFERENCE(pSwitchInfo);
	}

    return ok;
}

BOOLEAN Datapath_FlushFlows(OVS_DATAPATH* pDatapath)
{
    OVS_FLOW_TABLE* pOldTable = NULL;
    OVS_FLOW_TABLE* pNewTable = NULL;
    LOCK_STATE_EX lockState = { 0 };
	BOOLEAN ok = TRUE;

	//pDatapath contains the pFlowTable, so we must lock its rw lock, to replace the pFlowTable
	DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    pOldTable = pDatapath->pFlowTable;
    pNewTable = FlowTable_Create();
    if (!pNewTable)
    {
		ok = FALSE;
		goto Cleanup;
    }

    pDatapath->pFlowTable = pNewTable;

	OVS_RCU_DESTROY(pOldTable);

Cleanup:
	DATAPATH_UNLOCK(pDatapath, &lockState);
    return ok;
}

OVS_FLOW_TABLE* Datapath_ReferenceFlowTable(OVS_DATAPATH* pDatapath)
{
	OVS_FLOW_TABLE* pFlowTable = NULL;
	LOCK_STATE_EX lockState;

	OVS_CHECK(pDatapath);
	DATAPATH_LOCK_READ(pDatapath, &lockState);

	pFlowTable = OVS_RCU_REFERENCE(pDatapath->pFlowTable);

	DATAPATH_UNLOCK(pDatapath, &lockState);

	return pFlowTable;
}