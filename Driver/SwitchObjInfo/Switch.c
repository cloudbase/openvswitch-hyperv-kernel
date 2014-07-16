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
#include "OIDRequest.h"
#include "Sctx_Nic.h"
#include "SwitchContext.h"

_Use_decl_annotations_
NDIS_STATUS Switch_CreateForwardInfo(NDIS_HANDLE filterHandle, OVS_GLOBAL_FORWARD_INFO** ppForwardInfo)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;

    pForwardInfo = KAlloc(sizeof(OVS_GLOBAL_FORWARD_INFO));
    if (pForwardInfo == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    NdisZeroMemory(pForwardInfo, sizeof(OVS_GLOBAL_FORWARD_INFO));
    InitializeListHead(&pForwardInfo->nicList);
    InitializeListHead(&pForwardInfo->portList);

    pForwardInfo->pRwLock = NdisAllocateRWLock(filterHandle);
    if (pForwardInfo->pRwLock == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    pForwardInfo->persistentPortsInfo.pRwLock = NdisAllocateRWLock(filterHandle);
    pForwardInfo->isInitialRestart = TRUE;

    *ppForwardInfo = pForwardInfo;

Cleanup:
    if (status != NDIS_STATUS_SUCCESS)
    {
        if (pForwardInfo != NULL)
        {
            ExFreePoolWithTag(pForwardInfo, g_extAllocationTag);
        }
    }

    return status;
}

_Use_decl_annotations_
VOID Switch_DeleteForwardInfo(OVS_GLOBAL_FORWARD_INFO* pForwardInfo)
{
    Sctx_ClearNicListUnsafe(pForwardInfo);

    NdisFreeRWLock(pForwardInfo->persistentPortsInfo.pRwLock);
    NdisFreeRWLock(pForwardInfo->pRwLock);
    ExFreePoolWithTag(pForwardInfo, g_extAllocationTag);
}

_Use_decl_annotations_
VOID Switch_Activate(OVS_SWITCH_INFO* pSwitchInfo)
{
    Sctx_InitSwitch(pSwitchInfo);
}

_Use_decl_annotations_
NDIS_STATUS Switch_Restart(OVS_SWITCH_INFO* pSwitchInfo)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pSwitchInfo->pForwardInfo;
    NDIS_SWITCH_PARAMETERS* pSwitchParameters = KAlloc(sizeof(NDIS_SWITCH_PARAMETERS));

    if (!pSwitchParameters)
    {
        return NDIS_STATUS_FAILURE;
    }

    OVS_CHECK(pForwardInfo);

    if (pForwardInfo->isInitialRestart)
    {
        status = Switch_GetParametersUnsafe(pSwitchInfo, pSwitchParameters);

        if (status != NDIS_STATUS_SUCCESS)
        {
            goto Cleanup;
        }

        if (pSwitchParameters->IsActive && !pForwardInfo->switchIsActive)
        {
            status = Sctx_InitSwitch(pSwitchInfo);
            if (status != NDIS_STATUS_SUCCESS)
            {
                goto Cleanup;
            }
        }

        pForwardInfo->isInitialRestart = FALSE;
    }

Cleanup:
    if (pSwitchParameters)
    {
        KFree(pSwitchParameters);
    }
    return status;
}

_Use_decl_annotations_
VOID Switch_Pause(OVS_SWITCH_INFO* pSwitchInfo)
{
    UNREFERENCED_PARAMETER(pSwitchInfo);

    return;
}

_Use_decl_annotations_
NDIS_STATUS Switch_GetParametersUnsafe(OVS_SWITCH_INFO* pSwitchInfo, NDIS_SWITCH_PARAMETERS* pSwitchParameters)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    pSwitchParameters->Header.Revision = NDIS_SWITCH_PARAMETERS_REVISION_1;
    pSwitchParameters->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    pSwitchParameters->Header.Size = sizeof(NDIS_SWITCH_PARAMETERS);

    status = OID_IssueOidRequest(pSwitchInfo, NdisRequestQueryInformation, OID_SWITCH_PARAMETERS, pSwitchParameters,
        sizeof(NDIS_SWITCH_PARAMETERS), 0, 0, 0, NULL);

    return status;
}