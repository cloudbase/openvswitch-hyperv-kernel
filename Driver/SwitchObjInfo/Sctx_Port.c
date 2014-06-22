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

#include "Sctx_Port.h"
#include "Switch.h"

OVS_PORT_LIST_ENTRY* Sctx_FindPortById_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardIno, _In_ NDIS_SWITCH_PORT_ID portId)
{
    const LIST_ENTRY* pPortList = &pForwardIno->portList;
    const LIST_ENTRY* pCurEntry = pPortList->Flink;
    const OVS_PORT_LIST_ENTRY* pPortEntry = NULL;

    if (IsListEmpty(pPortList))
    {
        goto Cleanup;
    }

    do {
        pPortEntry = CONTAINING_RECORD(pCurEntry, OVS_PORT_LIST_ENTRY, listEntry);

        if (pPortEntry->portId == portId)
        {
            goto Cleanup;
        }

        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != pPortList);

    pPortEntry = NULL;

Cleanup:
    return (OVS_PORT_LIST_ENTRY*)pPortEntry;
}

NDIS_STATUS Sctx_AddPort_Unsafe(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pCurPort, _Inout_opt_ OVS_PORT_LIST_ENTRY** ppPortEntry)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_PORT_LIST_ENTRY* pPortEntry = NULL;
    LIST_ENTRY* pPortList = &pForwardInfo->portList;
    char* ofPortName = NULL;

    pPortEntry = Sctx_FindPortById_Unsafe(pForwardInfo, pCurPort->PortId);
    if (pPortEntry)
    {
        return status;
    }

    pPortEntry = KZAlloc(sizeof(OVS_PORT_LIST_ENTRY));
    if (pPortEntry == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

	pPortEntry->rcu.Destroy = PortEntry_DestroyNow_Unsafe;
    pPortEntry->portId = pCurPort->PortId;
    pPortEntry->portType = pCurPort->PortType;
    pPortEntry->on = (pCurPort->PortState == NdisSwitchPortStateCreated);
    pPortEntry->portFriendlyName = pCurPort->PortFriendlyName;
	pPortEntry->ovsPortNumber = OVS_INVALID_PORT_NUMBER;

    DEBUGP(LOG_INFO, "PORT: id=%d; type=%d; on=%d; friendly name=\"%s\"\n",
        pPortEntry->portId, pPortEntry->portType, pPortEntry->on, ofPortName);

    InsertHeadList(pPortList, &pPortEntry->listEntry);

    if (ppPortEntry)
    {
        *ppPortEntry = pPortEntry;
    }

Cleanup:
    if (ofPortName)
    {
        KFree(ofPortName);
    }

    return status;
}

VOID PortEntry_DestroyNow_Unsafe(OVS_PORT_LIST_ENTRY* pPortEntry)
{
	if (pPortEntry)
	{
		RemoveEntryList(&pPortEntry->listEntry);
		KFree(pPortEntry);
	}
}

NDIS_STATUS Sctx_DeletePort_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID portId)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    OVS_PORT_LIST_ENTRY* pPortEntry = Sctx_FindPortById_Unsafe(pForwardInfo, portId);

    if (pPortEntry == NULL)
    {
        OVS_CHECK(FALSE);
        goto Cleanup;
    }

	OVS_CHECK(pPortEntry->ovsPortNumber == OVS_INVALID_PORT_NUMBER);

	OVS_RCU_DESTROY(pPortEntry);

Cleanup:
    return status;
}

OVS_PORT_LIST_ENTRY* Sctx_FindPortBy_Unsafe(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const VOID* pContext, BOOLEAN(*Predicate)(int, const VOID*, _In_ const OVS_PORT_LIST_ENTRY*))
{
    LIST_ENTRY* pPortList = &pForwardInfo->portList;
    LIST_ENTRY* pCurEntry = pPortList->Flink;
    OVS_PORT_LIST_ENTRY* pPortEntry = NULL;
    int i = 0;

    if (IsListEmpty(pPortList))
    {
        goto Cleanup;
    }

    do {
        pPortEntry = CONTAINING_RECORD(pCurEntry, OVS_PORT_LIST_ENTRY, listEntry);

        if ((*Predicate)(i, pContext, pPortEntry))
        {
            return pPortEntry;
        }

        pCurEntry = pCurEntry->Flink;

        ++i;
    } while (pCurEntry != pPortList);

    pPortEntry = NULL;

Cleanup:

    return NULL;
}

UINT16 Sctx_Port_SetPersistentPort(const char* ovsPortName, NDIS_SWITCH_PORT_ID portId)
{
	OVS_PERSISTENT_PORT* pPort = NULL;
	UINT16 ovsPortNumber = OVS_INVALID_PORT_NUMBER;

	pPort = PersPort_FindByName_Ref(ovsPortName);
	if (pPort)
	{
		LOCK_STATE_EX lockState = { 0 };

		PORT_LOCK_WRITE(pPort, &lockState);

		pPort->portId = portId;
		ovsPortNumber = pPort->ovsPortNumber;

		PORT_UNLOCK(pPort, &lockState);

		OVS_RCU_DEREFERENCE(pPort);
	}

	return ovsPortNumber;
}