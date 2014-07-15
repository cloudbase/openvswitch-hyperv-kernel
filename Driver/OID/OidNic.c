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
#include "OidNic.h"
#include "Sctx_Nic.h"
#include "SwitchContext.h"

_Use_decl_annotations_
NDIS_STATUS Nic_Create(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pNic)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    LOCK_STATE_EX lockState = { 0 };
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

    while (pForwardInfo->isInitialRestart)
    {
        NdisMSleep(100);
    }

    FWDINFO_LOCK_WRITE(pForwardInfo, &lockState);

    OVS_CHECK(pNic->NicState != NdisSwitchNicStateConnected);
    status = Sctx_AddNicUnsafe(pForwardInfo, pNic, &pNicEntry);

    if (status == NDIS_STATUS_SUCCESS)
    {
        if (pNic->NicType == NdisSwitchNicTypeExternal &&
            pNic->NicIndex != NDIS_SWITCH_DEFAULT_NIC_INDEX)
        {
            OVS_CHECK(!pForwardInfo->pExternalNic);
            OVS_CHECK(pNicEntry);

            pForwardInfo->pExternalNic = pNicEntry;
        }

        //NOTE: the internal port has nic index = 0
        else if (pNic->NicType == NdisSwitchNicTypeInternal && !pForwardInfo->pInternalNic)
        {
            OVS_CHECK(!pForwardInfo->pInternalNic);
            OVS_CHECK(pNicEntry);

            pForwardInfo->pInternalNic = pNicEntry;
        }
    }

    FWDINFO_UNLOCK(pForwardInfo, &lockState);

    return status;
}

_Use_decl_annotations_
VOID Nic_Connect(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pNic)
{
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
	NDIS_SWITCH_PORT_ID portId = NDIS_SWITCH_DEFAULT_PORT_ID;
    LOCK_STATE_EX lockState = { 0 };
	UINT16 ovsPortNumber = OVS_INVALID_PORT_NUMBER;

    while (pForwardInfo->isInitialRestart)
    {
        NdisMSleep(100);
    }

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    if (pNic->NicType == NdisSwitchNicTypeExternal &&
        pNic->NicIndex != NDIS_SWITCH_DEFAULT_NIC_INDEX)
    {
        OVS_CHECK(pForwardInfo->pExternalNic);

        pNicEntry = pForwardInfo->pExternalNic;
    }

    //NOTE: the internal port has nic index = 0
    else if (pNic->NicType == NdisSwitchNicTypeInternal)
    {
        pNicEntry = pForwardInfo->pInternalNic;
    }

    //if internal, we still check this out
    else if (pNic->NicType != NdisSwitchNicTypeExternal)
    {
        OVS_CHECK(pNic->NicType != NdisSwitchNicTypeInternal);

        pNicEntry = Sctx_FindNicByPortIdAndNicIndex_Unsafe(pForwardInfo, pNic->PortId, pNic->NicIndex);

        OVS_CHECK(pNicEntry != NULL);

		pNicEntry = OVS_REFCOUNT_REFERENCE(pNicEntry);
    }

    if (pNicEntry)
    {
		OVS_CHECK(pNicEntry->ovsPortNumber == OVS_INVALID_PORT_NUMBER);

		portId = pNicEntry->portId;
    }

	FWDINFO_UNLOCK(pForwardInfo, &lockState);

	if (portId != NDIS_SWITCH_DEFAULT_PORT_ID)
	{
		ovsPortNumber = Sctx_Nic_SetPersistentPort(pForwardInfo, portId);
	}

	FWDINFO_LOCK_WRITE(pForwardInfo, &lockState);

	if (pNicEntry)
	{
		pNicEntry->ovsPortNumber = ovsPortNumber;
		pNicEntry->connected = TRUE;

		++(pForwardInfo->countNics);
	}

	FWDINFO_UNLOCK(pForwardInfo, &lockState);

	//Cleanup
	if (pNicEntry)
	{
		OVS_REFCOUNT_DEREFERENCE(pNicEntry);
	}
}

_Use_decl_annotations_
VOID Nic_Update(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pNic)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pNic);

    //TODO:
    /*
    MTU
    A ULONG value that specifies the maximum transmission unit (MTU) size, in bytes, for the network adapter.
    Note  The value of this member can change during the lifetime of a VM NIC.
    Therefore, extensions should read this member of the NDIS_SWITCH_NIC_PARAMETERS structure that is passed down with the following OIDs:
    OID_SWITCH_NIC_CONNECT
    OID_SWITCH_NIC_UPDATED
    */

    return;
}

_Use_decl_annotations_
VOID Nic_Disconnect(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pNic)
{
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    LOCK_STATE_EX lockState = { 0 };

    while (pForwardInfo->isInitialRestart)
    {
        NdisMSleep(100);
    }

    FWDINFO_LOCK_WRITE(pForwardInfo, &lockState);

    if (pNic->NicType == NdisSwitchNicTypeExternal)
    {
        OVS_CHECK(pForwardInfo->pExternalNic);

        if (pNic->NicIndex == pForwardInfo->pExternalNic->nicIndex)
        {
            pNicEntry = pForwardInfo->pExternalNic;
        }
    }

    else if (pNic->NicType == NdisSwitchNicTypeInternal)
    {
        OVS_CHECK(pForwardInfo->pInternalNic);

        pNicEntry = pForwardInfo->pInternalNic;
    }

    else
    {
        pNicEntry = Sctx_FindNicByPortIdAndNicIndex_Unsafe(pForwardInfo, pNic->PortId, pNic->NicIndex);

        OVS_CHECK(pNicEntry != NULL);
    }

    if (pNicEntry != NULL)
    {
		pNicEntry->connected = FALSE;
		--(pForwardInfo->countNics);

		//we no longer need to 'unset' the pers port: it will try (eventually) to send to this port id, but it will not find nic, so it will fail.
    }

    FWDINFO_UNLOCK(pForwardInfo, &lockState);
}

_Use_decl_annotations_
VOID Nic_Delete(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_PARAMETERS* pNic)
{
    LOCK_STATE_EX lockState = { 0 };

    while (pForwardInfo->isInitialRestart)
    {
        NdisMSleep(100);
    }

    FWDINFO_LOCK_WRITE(pForwardInfo, &lockState);

    if (pNic->NicType == NdisSwitchNicTypeExternal)
    {
        OVS_CHECK(pForwardInfo->pExternalNic);

        if (pNic->NicIndex == pForwardInfo->pExternalNic->nicIndex)
        {
            OVS_CHECK(pForwardInfo->pExternalNic->connected == FALSE);
            pForwardInfo->pExternalNic = NULL;
        }
    }

    else if (pNic->NicType == NdisSwitchNicTypeInternal)
    {
        OVS_CHECK(pForwardInfo->pInternalNic);

        if (pNic->NicIndex == pForwardInfo->pInternalNic->nicIndex)
        {
            OVS_CHECK(pForwardInfo->pInternalNic->connected == FALSE);
            pForwardInfo->pInternalNic = FALSE;
        }
    }

    Sctx_DeleteNicUnsafe(pForwardInfo, pNic->PortId, pNic->NicIndex);

    FWDINFO_UNLOCK(pForwardInfo, &lockState);
    return;
}

_Use_decl_annotations_
NDIS_STATUS Nic_Restore(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState, ULONG* pBytesRestored)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pSaveState);

    *pBytesRestored = 0;
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Nic_RestoreComplete(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pSaveState);

    return;
}

_Use_decl_annotations_
NDIS_STATUS Nic_ProcessRequest(const NDIS_OID_REQUEST* pOidRequest)
{
    if (pOidRequest->RequestType == NdisRequestSetInformation && pOidRequest->DATA.SET_INFORMATION.Oid == OID_NIC_SWITCH_ALLOCATE_VF)
    {
        return NDIS_STATUS_FAILURE;
    }

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS Nic_ProcessRequestComplete(const OVS_GLOBAL_FORWARD_INFO* pForwardContext, NDIS_OID_REQUEST* pOidRequest,
NDIS_SWITCH_PORT_ID sourcePortId, NDIS_SWITCH_NIC_INDEX sourceNicIndex,
NDIS_SWITCH_PORT_ID destinationPortId, NDIS_SWITCH_NIC_INDEX destinationNicIndex,
NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(pForwardContext);
    UNREFERENCED_PARAMETER(pOidRequest);
    UNREFERENCED_PARAMETER(sourcePortId);
    UNREFERENCED_PARAMETER(sourceNicIndex);
    UNREFERENCED_PARAMETER(destinationPortId);
    UNREFERENCED_PARAMETER(destinationNicIndex);
    UNREFERENCED_PARAMETER(status);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS Nic_ProcessStatus(const OVS_GLOBAL_FORWARD_INFO* pForwardContext, const NDIS_STATUS_INDICATION* pStatusIndication,
NDIS_SWITCH_PORT_ID sourcePortId,
NDIS_SWITCH_NIC_INDEX sourceNicIndex)
{
    UNREFERENCED_PARAMETER(pForwardContext);
    UNREFERENCED_PARAMETER(pStatusIndication);
    UNREFERENCED_PARAMETER(sourcePortId);
    UNREFERENCED_PARAMETER(sourceNicIndex);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS Nic_Save(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_SWITCH_NIC_SAVE_STATE* pSaveState,
ULONG* pBytesWritten, ULONG* pBytesNeeded)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pSaveState);

    *pBytesWritten = 0;
    *pBytesNeeded = 0;
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Nic_SaveComplete(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pSaveState);

    return;
}