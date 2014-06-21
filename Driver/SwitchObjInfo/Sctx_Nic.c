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

#include "precomp.h"
#include "Sctx_Nic.h"

VOID Sctx_ClearNicListUnsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo)
{
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    LIST_ENTRY* pHeadList = NULL;

    while (!IsListEmpty(pNicList))
    {
        pHeadList = RemoveHeadList(pNicList);

        pNicEntry = CONTAINING_RECORD(pHeadList, OVS_NIC_LIST_ENTRY, listEntry);

        ExFreePoolWithTag(pNicEntry, g_extAllocationTag);
    }

    return;
}

_Use_decl_annotations_
NDIS_STATUS Sctx_AddNicUnsafe(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pCurNic, OVS_NIC_LIST_ENTRY** ppNicEntry)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    LIST_ENTRY* pNicList = &pForwardInfo->nicList;

    pNicEntry = Sctx_FindNicByPortIdAndNicIndex_Unsafe(pForwardInfo, pCurNic->PortId, pCurNic->NicIndex);
    if (pNicEntry)
    {
        return status;
    }

    pNicEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_NIC_LIST_ENTRY), g_extAllocationTag);

    if (pNicEntry == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    NdisZeroMemory(pNicEntry, sizeof(OVS_NIC_LIST_ENTRY));

	pNicEntry->rcu.Destroy = NicEntry_DestroyNow_Unsafe;
    RtlCopyMemory(pNicEntry->macAddress, pCurNic->PermanentMacAddress, OVS_ETHERNET_ADDRESS_LENGTH);

    pNicEntry->portId = pCurNic->PortId;
    pNicEntry->nicIndex = pCurNic->NicIndex;
    pNicEntry->nicType = pCurNic->NicType;
    pNicEntry->connected = (pCurNic->NicState == NdisSwitchNicStateConnected);
    pNicEntry->mtu = pCurNic->MTU;
    pNicEntry->pPersistentPort = NULL;

#ifdef DBG
    WcharArrayToAscii(pNicEntry->vmName, pCurNic->VmFriendlyName.String, min(OVS_NIC_ENTRY_NAME_SIZE, pCurNic->VmFriendlyName.Length));
    WcharArrayToAscii(pNicEntry->adapName, pCurNic->NicFriendlyName.String, min(OVS_NIC_ENTRY_NAME_SIZE, pCurNic->NicFriendlyName.Length));
#endif

    DEBUGP(LOG_INFO, "NIC: port=%d; index=%d; type=%d; connected=%d; mtu=%d; name=\"%s\"; vm name=\"%s\"\n",
        pNicEntry->portId, pNicEntry->nicIndex, pNicEntry->nicType, pNicEntry->connected, pNicEntry->mtu, pNicEntry->adapName, pNicEntry->vmName);

    InsertHeadList(pNicList, &pNicEntry->listEntry);

    if (ppNicEntry)
    {
        *ppNicEntry = pNicEntry;
    }

Cleanup:
    return status;
}

OVS_NIC_LIST_ENTRY* Sctx_FindNicByMacAddressUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_reads_bytes_(6) const UCHAR* pMacAddress)
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (RtlEqualMemory(pMacAddress, pNicEntry->macAddress, sizeof(pNicEntry->macAddress)))
        {
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return (OVS_NIC_LIST_ENTRY*)pNicEntry;
}

BOOLEAN Sctx_ForEachNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, VOID* pContext, BOOLEAN(*Action)(int, OVS_NIC_LIST_ENTRY*, VOID*))
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    LIST_ENTRY* pCurEntry = pNicList->Flink;
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    int i = 0;
    BOOLEAN ok = TRUE;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (!(*Action)(i, pNicEntry, pContext))
        {
            ok = FALSE;
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;

        ++i;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return ok;
}

BOOLEAN Sctx_CForEachNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, VOID* pContext, BOOLEAN(*Action)(int, _In_ const OVS_NIC_LIST_ENTRY*, VOID*))
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    int i = 0;
    BOOLEAN ok = TRUE;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (!(*Action)(i, pNicEntry, pContext))
        {
            ok = FALSE;
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;

        ++i;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return ok;
}

const OVS_NIC_LIST_ENTRY* Sctx_CFindNic_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, BOOLEAN(*Predicate)(int, _In_ const OVS_NIC_LIST_ENTRY*))
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    int i = 0;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if ((*Predicate)(i, pNicEntry))
        {
            return pNicEntry;
        }

        pCurEntry = pCurEntry->Flink;

        ++i;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return NULL;
}

OVS_NIC_LIST_ENTRY* Sctx_FindNicBy_Unsafe(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const VOID* pContext, BOOLEAN(*Predicate)(int, const VOID*, _In_ const OVS_NIC_LIST_ENTRY*))
{
    LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    LIST_ENTRY* pCurEntry = pNicList->Flink;
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    int i = 0;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if ((*Predicate)(i, pContext, pNicEntry))
        {
            return pNicEntry;
        }

        pCurEntry = pCurEntry->Flink;

        ++i;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:

    return NULL;
}

OVS_NIC_LIST_ENTRY* Sctx_FindNicByPortIdAndNicIndex_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId, _In_ NDIS_SWITCH_NIC_INDEX nicIndex)
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (pNicEntry->portId == portId && pNicEntry->nicIndex == nicIndex)
        {
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return (OVS_NIC_LIST_ENTRY*)pNicEntry;
}

OVS_NIC_LIST_ENTRY* Sctx_FindNicByPortId_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId)
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (pNicEntry->portId == portId)
        {
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != pNicList);

    pNicEntry = NULL;

Cleanup:
    return (OVS_NIC_LIST_ENTRY*)pNicEntry;
}

VOID NicEntry_DestroyNow_Unsafe(OVS_NIC_LIST_ENTRY* pNicEntry)
{
	if (pNicEntry)
	{
		RemoveEntryList(&pNicEntry->listEntry);
		KFree(pNicEntry);
	}
}

NDIS_STATUS Sctx_DeleteNicUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId, _In_ NDIS_SWITCH_NIC_INDEX nicIndex)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    OVS_NIC_LIST_ENTRY* pNicEntry = Sctx_FindNicByPortIdAndNicIndex_Unsafe(pForwardInfo, portId, nicIndex);

    if (pNicEntry == NULL)
    {
        OVS_CHECK(FALSE);
        goto Cleanup;
    }

    OVS_CHECK(!pNicEntry->pPersistentPort);

    RemoveEntryList(&pNicEntry->listEntry);
    ExFreePoolWithTag(pNicEntry, g_extAllocationTag);

Cleanup:
    return status;
}

VOID Sctx_Nic_SetPersistentPort_Unsafe(_Inout_ OVS_NIC_LIST_ENTRY* pNicEntry)
{
    pNicEntry->pPersistentPort = PersPort_FindById_Unsafe(pNicEntry->portId, FALSE);
    if (pNicEntry->pPersistentPort)
    {
        pNicEntry->pPersistentPort->pNicListEntry = pNicEntry;
    }
}

VOID Sctx_Nic_UnsetPersistentPort_Unsafe(_Inout_ OVS_NIC_LIST_ENTRY* pNicEntry)
{
    if (pNicEntry->pPersistentPort)
    {
        pNicEntry->pPersistentPort->pNicListEntry = NULL;
        pNicEntry->pPersistentPort = NULL;
    }
}

VOID Sctx_Nic_Disable_Unsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ OVS_NIC_LIST_ENTRY* pNicEntry)
{
    pNicEntry->connected = FALSE;
    --(pForwardInfo->countNics);

    Sctx_Nic_UnsetPersistentPort_Unsafe(pNicEntry);
}