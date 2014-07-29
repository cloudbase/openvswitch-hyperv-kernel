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
#include "List.h"

#include "SpookyHash.h"

#define OVS_FLOW_TABLE_AT(lists, hash)  (lists + (hash & (OVS_FLOW_TABLE_HASH_COUNT - 1)));

static __inline UINT32 _Flow_HashPacketInfo_Offset(_In_ const VOID* pPacketInfo, SIZE_T offset, SIZE_T size)
{
    const BYTE* data = pPacketInfo;
    
    data += offset;
    size -= offset;

    return Spooky_Hash32(data, size, 0);
}

//pUnmaskedPacketInfo: extracted packet info
//unsafe = does not lock pFlowTable
static OVS_FLOW* _FindFlowMatchingMaskedPI_Unsafe(OVS_FLOW_TABLE* pFlowTable, const OVS_OFPACKET_INFO* pUnmaskedPacketInfo, OVS_FLOW_MASK* pFlowMask)
{
    SIZE_T startRange = pFlowMask->piRange.startRange;
    SIZE_T endRange = pFlowMask->piRange.endRange;
    OVS_OFPACKET_INFO maskedPacketInfo = { 0 };
    UINT32 hash = 0;
    OVS_FLOW* pCurFlow = NULL;
    LIST_ENTRY* pList = NULL;

    ApplyMaskToPacketInfo(&maskedPacketInfo, pUnmaskedPacketInfo, pFlowMask);

    hash = _Flow_HashPacketInfo_Offset(&maskedPacketInfo, startRange, endRange - startRange);
    pList = OVS_FLOW_TABLE_AT(pFlowTable->pFlowLists, hash);

    OVS_LIST_FOR_EACH(OVS_FLOW, pCurFlow, pList)
    {
        LOCK_STATE_EX lockState = { 0 };

        FLOW_LOCK_READ(pCurFlow, &lockState);

        if (pCurFlow->pMask == pFlowMask)
        {
            if (PacketInfo_EqualAtRange(&pCurFlow->maskedPacketInfo, &maskedPacketInfo, startRange, endRange))
            {
                FLOW_UNLOCK(pCurFlow, &lockState);

                return pCurFlow;
            }
        }

        FLOW_UNLOCK(pCurFlow, &lockState);
    }

    return NULL;
}

static __inline VOID _FlowTable_Free(OVS_FLOW_TABLE* pFlowTable)
{
    OVS_CHECK(pFlowTable);

    KFree(pFlowTable->pFlowLists);
    KFree(pFlowTable->pMaskList);
    KFree(pFlowTable);
}

VOID FlowTable_DestroyNow_Unsafe(OVS_FLOW_TABLE* pFlowTable)
{
    LIST_ENTRY* pFlowEntry = NULL;

    if (!pFlowTable)
    {
        return;
    }

    for (ULONG i = 0; i < OVS_FLOW_TABLE_HASH_COUNT; ++i)
    {
        LIST_ENTRY* pList = OVS_FLOW_TABLE_AT(pFlowTable->pFlowLists, i);

        while (!IsListEmpty(pList))
        {
            pFlowEntry = RemoveHeadList(pList);

            OVS_FLOW* pFlow = CONTAINING_RECORD(pFlowEntry, OVS_FLOW, listEntry);
            OVS_REFCOUNT_DESTROY(pFlow);
        }
    }

    OVS_CHECK(IsListEmpty(pFlowTable->pMaskList));

    _FlowTable_Free(pFlowTable);
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

OVS_FLOW* _FlowTable_FindExactFlow_Unsafe(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW_MATCH* pFlowMatch)
{
    OVS_FLOW* pFlow = NULL;
    OVS_FLOW_MASK* pFlowMask = NULL;

    OVS_LIST_FOR_EACH(OVS_FLOW_MASK, pFlowMask, pFlowTable->pMaskList)
    {
        pFlow = _FindFlowMatchingMaskedPI_Unsafe(pFlowTable, &(pFlowMatch->packetInfo), pFlowMask);
        if (pFlow)
        {
            if (PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &(pFlowMatch->packetInfo), pFlowMatch->piRange.endRange))
            {
                break;
            }
        }
    }

    return pFlow;
}

OVS_FLOW* FlowTable_FindExactFlow_Ref(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW_MATCH* pFlowMatch)
{
    OVS_FLOW* pFlow = NULL;
    LOCK_STATE_EX lockState;

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

    pFlow = _FlowTable_FindExactFlow_Unsafe(pFlowTable, pFlowMatch);
    pFlow = OVS_REFCOUNT_REFERENCE(pFlow);

    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    return pFlow;
}

UINT32 FlowTable_CountMasks(const OVS_FLOW_TABLE* pFlowTable)
{
    LIST_ENTRY* pListEntry = NULL;
    LIST_ENTRY* pHeadEntry = NULL;
    LOCK_STATE_EX lockState = { 0 };
    UINT32 count = 0;

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

    pHeadEntry = pFlowTable->pMaskList;
    pListEntry = pHeadEntry->Flink;

    while (pListEntry != pHeadEntry)
    {
        ++count;

        pListEntry = pListEntry->Flink;
    }

    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    return count;
}

OVS_FLOW_MASK* FlowTable_FindFlowMask(const OVS_FLOW_TABLE* pFlowTable, const OVS_FLOW_MASK* pFlowMask)
{
    OVS_FLOW_MASK* pOutFlowMask = NULL;
    LOCK_STATE_EX lockState = {0};
    OVS_FLOW_MASK* pCurFlowMask = NULL;

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

    OVS_LIST_FOR_EACH(OVS_FLOW_MASK, pCurFlowMask, pFlowTable->pMaskList)
    {
        if (FlowMask_Equal(pFlowMask, pCurFlowMask))
        {
            pOutFlowMask = pCurFlowMask;
            break;
        }
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
    OVS_OFPACKET_INFO* pPacketInfo = NULL;
    SIZE_T startRange = 0;
    SIZE_T endRange = 0;
    UINT32 hash = 0;
    LIST_ENTRY* pList = NULL;

    OVS_CHECK(pFlowTable);
    OVS_CHECK(pFlow);

    pPacketInfo = &(pFlow->maskedPacketInfo);
    startRange = pFlow->pMask->piRange.startRange;
    endRange = pFlow->pMask->piRange.endRange;

    FLOWTABLE_LOCK_WRITE(pFlowTable, &lockState);

    hash = _Flow_HashPacketInfo_Offset(pPacketInfo, startRange, endRange - startRange);
    pList = OVS_FLOW_TABLE_AT(pFlowTable->pFlowLists, hash);

    InsertHeadList(pList, &pFlow->listEntry);
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

    pFlowTable->pFlowLists = KAlloc(OVS_FLOW_TABLE_HASH_COUNT * sizeof(LIST_ENTRY));
    if (!pFlowTable->pFlowLists)
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

    for (ULONG i = 0; i < OVS_FLOW_TABLE_HASH_COUNT; ++i)
    {
        LIST_ENTRY* pList = pFlowTable->pFlowLists + i;

        InitializeListHead(pList);
    }

    InitializeListHead(pFlowTable->pMaskList);
    pFlowTable->refCount.Destroy = FlowTable_DestroyNow_Unsafe;
    pFlowTable->pRwLock = NdisAllocateRWLock(NULL);

Cleanup:
    if (!ok)
    {
        OVS_CHECK_RET(pFlowTable, NULL);

        _FlowTable_Free(pFlowTable);

        return NULL;
    }

    return pFlowTable;
}
