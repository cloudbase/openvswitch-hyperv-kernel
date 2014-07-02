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

#include "OFFlowTable.h"
#include "OFFlow.h"

//pUnmaskedPacketInfo: extracted packet info
//unsafe = does not lock pFlowTable
static OVS_FLOW* _FindFlowMatchingMaskedPI_Unsafe(OVS_FLOW_TABLE* pFlowTable, const OVS_OFPACKET_INFO* pUnmaskedPacketInfo, OVS_FLOW_MASK* pFlowMask)
{
    SIZE_T startRange = pFlowMask->piRange.startRange;
    SIZE_T endRange = pFlowMask->piRange.endRange;
    OVS_OFPACKET_INFO maskedPacketInfo = { 0 };

    LIST_ENTRY* pFlowEntry = NULL;

    ApplyMaskToPacketInfo(&maskedPacketInfo, pUnmaskedPacketInfo, pFlowMask);

    pFlowEntry = pFlowTable->pFlowList->Flink;

    while (pFlowEntry != pFlowTable->pFlowList)
    {
		LOCK_STATE_EX lockState = { 0 };
		OVS_FLOW* pFlow = NULL;

        pFlow = CONTAINING_RECORD(pFlowEntry, OVS_FLOW, listEntry);

		FLOW_LOCK_READ(pFlow, &lockState);

        if (pFlow->pMask == pFlowMask)
        {
            if (PacketInfo_EqualAtRange(&pFlow->maskedPacketInfo, &maskedPacketInfo, startRange, endRange))
            {
				FLOW_UNLOCK(pFlow, &lockState);

				return pFlow;
            }
        }

		FLOW_UNLOCK(pFlow, &lockState);

        pFlowEntry = pFlowEntry->Flink;
    }

    return NULL;
}

VOID FlowTable_DestroyNow_Unsafe(OVS_FLOW_TABLE* pFlowTable)
{
    LIST_ENTRY* pFlowEntry = NULL;

    if (!pFlowTable)
    {
        return;
    }

    while (!IsListEmpty(pFlowTable->pFlowList))
    {
        pFlowEntry = RemoveHeadList(pFlowTable->pFlowList);

        OVS_FLOW* pFlow = CONTAINING_RECORD(pFlowEntry, OVS_FLOW, listEntry);
		OVS_REFCOUNT_DESTROY(pFlow);
    }

    OVS_CHECK(IsListEmpty(pFlowTable->pMaskList));

	KFree(pFlowTable->pFlowList);
	KFree(pFlowTable->pMaskList);
    KFree(pFlowTable);
}

OVS_FLOW* FlowTable_FindFlowMatchingMaskedPI_Unsafe(OVS_FLOW_TABLE* pFlowTable, const OVS_OFPACKET_INFO* pPacketInfo)
{
    OVS_FLOW* pFlow = NULL;
    OVS_FLOW_MASK* pFlowMask = NULL;

    pFlowMask = CONTAINING_RECORD(pFlowTable->pMaskList->Flink, OVS_FLOW_MASK, listEntry);

    while (&pFlowMask->listEntry != pFlowTable->pMaskList)
    {
        pFlow = _FindFlowMatchingMaskedPI_Unsafe(pFlowTable, pPacketInfo, pFlowMask);
        if (pFlow)
        {
            break;
        }

        //advance flow mask to next in list
        pFlowMask = CONTAINING_RECORD(pFlowMask->listEntry.Flink, OVS_FLOW_MASK, listEntry);
    }

    return pFlow;
}

OVS_FLOW* FlowTable_FindFlowMatchingMaskedPI_Ref(OVS_FLOW_TABLE* pFlowTable, const OVS_OFPACKET_INFO* pPacketInfo)
{
	OVS_FLOW* pFlow = NULL;
	LOCK_STATE_EX lockState;

	FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

	pFlow = FlowTable_FindFlowMatchingMaskedPI_Unsafe(pFlowTable, pPacketInfo);
	pFlow = OVS_REFCOUNT_REFERENCE(pFlow);

	FLOWTABLE_UNLOCK(pFlowTable, &lockState);

	return pFlow;
}

OVS_FLOW_MASK* FlowTable_FindFlowMask(const OVS_FLOW_TABLE* pFlowTable, const OVS_FLOW_MASK* pFlowMask)
{
    LIST_ENTRY* pListEntry = NULL;
    LIST_ENTRY* pHeadEntry = NULL;
    OVS_FLOW_MASK* pOutFlowMask = NULL;
    LOCK_STATE_EX lockState = {0};

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);
    pHeadEntry = pFlowTable->pMaskList;
    pListEntry = pHeadEntry->Flink;

    while (pListEntry != pHeadEntry)
    {
        OVS_FLOW_MASK* pFlowMaskInList = CONTAINING_RECORD(pListEntry, OVS_FLOW_MASK, listEntry);
		if (FlowMask_Equal(pFlowMask, pFlowMaskInList))
		{
			pOutFlowMask = pFlowMaskInList;
			break;
		}

        pListEntry = pListEntry->Flink;
    }

	FLOWTABLE_UNLOCK(pFlowTable, &lockState);

	return pOutFlowMask;
}

void FlowTable_InsertFlowMask(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW_MASK* pFlowMask)
{
	LOCK_STATE_EX lockState;

	OVS_CHECK(pFlowTable);
	OVS_CHECK(pFlowMask);

	FLOWTABLE_LOCK_WRITE(pFlowTable, &lockState);
    InsertHeadList(pFlowTable->pMaskList, &pFlowMask->listEntry);
	FLOWTABLE_UNLOCK(pFlowTable, &lockState);
}

void FlowTable_InsertFlow_Unsafe(_Inout_ OVS_FLOW_TABLE* pFlowTable, _In_ OVS_FLOW* pFlow)
{
	LOCK_STATE_EX lockState;

	OVS_CHECK(pFlowTable);
	OVS_CHECK(pFlow);

	FLOWTABLE_LOCK_WRITE(pFlowTable, &lockState);
    InsertHeadList(pFlowTable->pFlowList, &pFlow->listEntry);
    pFlowTable->countFlows++;
	FLOWTABLE_UNLOCK(pFlowTable, &lockState);
}

void FlowTable_RemoveFlow_Unsafe(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW* pFlow)
{
    OVS_CHECK(pFlowTable->countFlows > 0);

	RemoveEntryList(&pFlow->listEntry);
    pFlowTable->countFlows--;
}

OVS_FLOW_TABLE* FlowTable_Create()
{
    BOOLEAN ok = TRUE;
	OVS_FLOW_TABLE* pFlowTable = NULL;

    pFlowTable = KZAlloc(sizeof(OVS_FLOW_TABLE));
    if (!pFlowTable)
    {
        return NULL;
    }

    pFlowTable->pFlowList = KAlloc(sizeof(LIST_ENTRY));
    if (!pFlowTable->pFlowList)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pFlowTable->pMaskList = KAlloc(sizeof(LIST_ENTRY));
    if (!pFlowTable->pMaskList)
    {
        ok = FALSE;
        goto Cleanup;
    }

    InitializeListHead(pFlowTable->pFlowList);
    InitializeListHead(pFlowTable->pMaskList);
	pFlowTable->refCount.Destroy = FlowTable_DestroyNow_Unsafe;
	pFlowTable->pRwLock = NdisAllocateRWLock(NULL);

Cleanup:
    if (!ok)
    {
		OVS_CHECK_RET(pFlowTable, NULL);

		if (pFlowTable->pFlowList) 
			KFree(pFlowTable->pFlowList);

		if (pFlowTable->pMaskList)
			KFree(pFlowTable->pMaskList);

		KFree(pFlowTable);

        return NULL;
    }

    return pFlowTable;
}
