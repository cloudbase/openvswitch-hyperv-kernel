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
#include "OidPort.h"
#include "OidNic.h"
#include "Switch.h"
#include "OIDRequest.h"

_Use_decl_annotations_
VOID OID_CompleteInternalOidRequest(NDIS_OID_REQUEST* pNdisRequest, NDIS_STATUS status)
{
    OVS_OID_REQUEST* pOidRequest = NULL;
    ULONG bytesNeeded = 0;

    switch (pNdisRequest->RequestType)
    {
    case NdisRequestSetInformation:
        bytesNeeded = pNdisRequest->DATA.SET_INFORMATION.BytesNeeded;
        break;

    case NdisRequestQueryInformation:
        bytesNeeded = pNdisRequest->DATA.QUERY_INFORMATION.BytesNeeded;
        break;

    case NdisRequestMethod:
        bytesNeeded = pNdisRequest->DATA.METHOD_INFORMATION.BytesNeeded;
        break;
    }

    pOidRequest = CONTAINING_RECORD(pNdisRequest, OVS_OID_REQUEST, ndisOidRequest);

    pOidRequest->status = status;

    pOidRequest->bytesNeeded = bytesNeeded;

    NdisSetEvent(&pOidRequest->reqEvent);
}

/************************************ SWITCH OIDS ************************************/

_Use_decl_annotations_
NDIS_STATUS OID_GetSwitchPropertyUnsafe(OVS_SWITCH_INFO* pSwitchInfo, NDIS_SWITCH_PROPERTY_TYPE propertyType,
NDIS_SWITCH_OBJECT_ID* pPropertyId, NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS** ppSwitchPropertyEnumParameters)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS propertyParameters;
    ULONG bytesNeeded = 0;
    NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS* pOutputBuffer = NULL;
    USHORT outputBufferLength = sizeof(NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS);

    propertyParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    propertyParameters.Header.Revision = NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS_REVISION_1;
    propertyParameters.PropertyType = propertyType;
    propertyParameters.SerializationVersion = NDIS_SWITCH_OBJECT_SERIALIZATION_VERSION_1;

    if (pPropertyId != NULL)
    {
        NdisMoveMemory(&propertyParameters.PropertyId, pPropertyId, sizeof(NDIS_SWITCH_OBJECT_ID));
    }
    else
    {
        OVS_CHECK(propertyType != NdisSwitchPropertyTypeCustom);
    }

    pOutputBuffer = ExAllocatePoolWithTag(NonPagedPool, outputBufferLength, g_extAllocationTag);

    if (pOutputBuffer == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    do
    {
        //bytesNeeded: at first ener in loop, it is 0 (local var); it is an out var of OID_IssueOidRequest
        if (bytesNeeded != 0)
        {
            ExFreePoolWithTag(pOutputBuffer, g_extAllocationTag);

            outputBufferLength = (USHORT)bytesNeeded;
            pOutputBuffer = ExAllocatePoolWithTag(NonPagedPool, outputBufferLength, g_extAllocationTag);

            if (pOutputBuffer == NULL)
            {
                status = NDIS_STATUS_RESOURCES;
                goto Cleanup;
            }
        }

        if (outputBufferLength >= sizeof(propertyParameters))
        {
            //perhaps the pOutputBuffer begins with a property params header
            NdisMoveMemory(pOutputBuffer, &propertyParameters, sizeof(propertyParameters));
        }

        status = OID_IssueOidRequest(pSwitchInfo, NdisRequestMethod, OID_SWITCH_PROPERTY_ENUM, pOutputBuffer, sizeof(propertyParameters),
            outputBufferLength, 0, 0, &bytesNeeded);
    } while (status == NDIS_STATUS_INVALID_LENGTH);

Cleanup:
    if (status != NDIS_STATUS_SUCCESS &&
        pOutputBuffer != NULL)
    {
        ExFreePoolWithTag(pOutputBuffer, g_extAllocationTag);
        pOutputBuffer = NULL;
    }

    *ppSwitchPropertyEnumParameters = pOutputBuffer;

    return status;
}

/************************************ PORT OIDS ************************************/
NDIS_STATUS _OnOidPortPropertyAdd(_In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PROPERTY_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PROPERTY_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    status = Port_AddProperty((NDIS_SWITCH_PORT_PROPERTY_PARAMETERS*)pObjectHeader);

    if (status == NDIS_STATUS_NOT_SUPPORTED)
    {
        status = NDIS_STATUS_SUCCESS;
    }
    else
    {
        *pComplete = TRUE;
        goto Cleanup;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortPropertyUpdate(_In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PROPERTY_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PROPERTY_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    status = Port_UpdateProperty((NDIS_SWITCH_PORT_PROPERTY_PARAMETERS*)pObjectHeader);

    if (status == NDIS_STATUS_NOT_SUPPORTED)
    {
        status = NDIS_STATUS_SUCCESS;
    }
    else
    {
        *pComplete = TRUE;
        goto Cleanup;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortPropertyDelete(_In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Out_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    *pComplete = Port_DeleteProperty((const NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS*)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortCreate(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    status = Port_Create(pForwardInfo, (PNDIS_SWITCH_PORT_PARAMETERS)pObjectHeader);

    if (status != NDIS_STATUS_SUCCESS)
    {
        *pComplete = TRUE;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortUpdated(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Port_Update(pForwardInfo, (PNDIS_SWITCH_PORT_PARAMETERS)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortTeardown(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_  BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Port_Teardown(pForwardInfo, (PNDIS_SWITCH_PORT_PARAMETERS)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortDelete(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_  BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_PORT_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_PORT_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Port_Delete(pForwardInfo, (PNDIS_SWITCH_PORT_PARAMETERS)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidPortFeatureStatusQuery(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_OBJECT_HEADER* pObjectHeader,
    _Out_ BOOLEAN* pComplete, _Inout_ ULONG* pOutBytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_FEATURE_STATUS_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_FEATURE_STATUS_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    *pComplete = Port_QueryFeatureStatus(pForwardInfo, (NDIS_SWITCH_PORT_FEATURE_STATUS_PARAMETERS*)pObjectHeader, pOutBytesNeeded);

    if (*pOutBytesNeeded > 0)
    {
        status = NDIS_STATUS_BUFFER_TOO_SHORT;
    }

Cleanup:
    return status;
}

_Use_decl_annotations_
NDIS_STATUS OID_GetPortPropertyUnsafe(OVS_SWITCH_INFO* pSwitchInfo, NDIS_SWITCH_PORT_ID portId,
NDIS_SWITCH_PORT_PROPERTY_TYPE propertyType, NDIS_SWITCH_OBJECT_ID* pPropertyId,
NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS** ppPortPropertyEnumParameters)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS propertyParameters;
    ULONG bytesNeeded = 0;
    NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS* pOutputBuffer = NULL;
    USHORT outputBufferLength = sizeof(NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS);

    propertyParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    propertyParameters.Header.Revision = NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS_REVISION_1;
    propertyParameters.PortId = portId;
    propertyParameters.PropertyType = propertyType;
    propertyParameters.SerializationVersion = NDIS_SWITCH_OBJECT_SERIALIZATION_VERSION_1;

    if (pPropertyId != NULL)
    {
        NdisMoveMemory(&propertyParameters.PropertyId, pPropertyId, sizeof(NDIS_SWITCH_OBJECT_ID));
    }
    else
    {
        OVS_CHECK(propertyType != NdisSwitchPortPropertyTypeCustom);
    }

    pOutputBuffer = ExAllocatePoolWithTag(NonPagedPool, outputBufferLength, g_extAllocationTag);

    if (pOutputBuffer == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    do
    {
        if (bytesNeeded != 0)
        {
            ExFreePoolWithTag(pOutputBuffer, g_extAllocationTag);

            outputBufferLength = (USHORT)bytesNeeded;
            pOutputBuffer = ExAllocatePoolWithTag(NonPagedPool, outputBufferLength, g_extAllocationTag);

            if (pOutputBuffer == NULL)
            {
                status = NDIS_STATUS_RESOURCES;
                goto Cleanup;
            }
        }

        if (outputBufferLength >= sizeof(propertyParameters))
        {
            pOutputBuffer->Header.Size = outputBufferLength;
            NdisMoveMemory(pOutputBuffer, &propertyParameters, sizeof(propertyParameters));
        }

        status = OID_IssueOidRequest(pSwitchInfo, NdisRequestMethod, OID_SWITCH_PORT_PROPERTY_ENUM, pOutputBuffer, sizeof(propertyParameters),
            outputBufferLength, 0, 0, &bytesNeeded);
    } while (status == NDIS_STATUS_INVALID_LENGTH);

Cleanup:
    if (status != NDIS_STATUS_SUCCESS &&
        pOutputBuffer != NULL)
    {
        ExFreePoolWithTag(pOutputBuffer, g_extAllocationTag);
        pOutputBuffer = NULL;
    }

    *ppPortPropertyEnumParameters = pOutputBuffer;

    return status;
}

_Use_decl_annotations_
NDIS_STATUS OID_GetPortArrayUnsafe(OVS_SWITCH_INFO* pSwitchInfo, NDIS_SWITCH_PORT_ARRAY** ppOutPortArray)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG bytesNeeded = 0;
    NDIS_SWITCH_PORT_ARRAY* pPortArray = NULL;
    ULONG arrayLength = 0;

    do
    {
        if (pPortArray != NULL)
        {
            ExFreePoolWithTag(pPortArray, g_extAllocationTag);
        }

        if (bytesNeeded != 0)
        {
            arrayLength = bytesNeeded;
            pPortArray = ExAllocatePoolWithTag(NonPagedPool, arrayLength, g_extAllocationTag);

            if (pPortArray == NULL)
            {
                status = NDIS_STATUS_RESOURCES;
                goto Cleanup;
            }

            pPortArray->Header.Revision = NDIS_SWITCH_PORT_ARRAY_REVISION_1;
            pPortArray->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
            pPortArray->Header.Size = (USHORT)arrayLength;
        }

        status = OID_IssueOidRequest(pSwitchInfo, NdisRequestQueryInformation, OID_SWITCH_PORT_ARRAY, pPortArray, arrayLength,
            0, 0, 0, &bytesNeeded);
    } while (status == NDIS_STATUS_INVALID_LENGTH);

    *ppOutPortArray = pPortArray;
Cleanup:
    if (status != NDIS_STATUS_SUCCESS && pPortArray != NULL)
    {
        ExFreePoolWithTag(pPortArray, g_extAllocationTag);
    }

    return status;
}

/************************************ NIC OIDS ************************************/
NDIS_STATUS _OnOidNicCreate(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    status = Nic_Create(pForwardInfo, (PNDIS_SWITCH_NIC_PARAMETERS)pObjectHeader);
    if (status != NDIS_STATUS_SUCCESS)
    {
        *pComplete = TRUE;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicConnect(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_Connect(pForwardInfo, (const NDIS_SWITCH_NIC_PARAMETERS*)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicUpdated(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_Update(pForwardInfo, (PNDIS_SWITCH_NIC_PARAMETERS)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicDisconnect(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_Disconnect(pForwardInfo, (const NDIS_SWITCH_NIC_PARAMETERS*)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicDelete(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_PARAMETERS_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_Delete(pForwardInfo, (const NDIS_SWITCH_NIC_PARAMETERS*)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicRestore(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG bytesRestored = 0;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    status = Nic_Restore(pForwardInfo, (PNDIS_SWITCH_NIC_SAVE_STATE)pObjectHeader, &bytesRestored);

    if (status != NDIS_STATUS_SUCCESS)
    {
        *pComplete = TRUE;
    }
    else if (bytesRestored > 0)
    {
        *pComplete = TRUE;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicRestoreComplete(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_RestoreComplete(pForwardInfo, (PNDIS_SWITCH_NIC_SAVE_STATE)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicSaveComplete(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader, _Inout_ BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    Nic_SaveComplete(pForwardInfo, (PNDIS_SWITCH_NIC_SAVE_STATE)pObjectHeader);

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicRequest(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader,
    _Inout_ BOOLEAN* pComplete, _Inout_ NDIS_OID_REQUEST* pOidRequest)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_NIC_OID_REQUEST* pNicOidRequest = NULL;
    NDIS_SWITCH_PORT_ID destPort = 0, sourcePort = 0;
    NDIS_SWITCH_NIC_INDEX destNic = 0, sourceNic = 0;
    NDIS_SWITCH_NIC_OID_REQUEST* pNewNicOidRequest = NULL;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_OID_REQUEST_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_OID_REQUEST_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    pNicOidRequest = (PNDIS_SWITCH_NIC_OID_REQUEST)pObjectHeader;

    sourcePort = pNicOidRequest->SourcePortId;
    sourceNic = pNicOidRequest->SourceNicIndex;
    destPort = pNicOidRequest->DestinationPortId;
    destNic = pNicOidRequest->DestinationNicIndex;

    status = Nic_ProcessRequest(pNicOidRequest->OidRequest);

    if (status != NDIS_STATUS_SUCCESS)
    {
        *pComplete = TRUE;
        goto Cleanup;
    }

    if (sourcePort != pNicOidRequest->SourcePortId ||
        sourceNic != pNicOidRequest->SourceNicIndex ||
        destPort != pNicOidRequest->DestinationPortId ||
        destNic != pNicOidRequest->DestinationNicIndex)
    {
        OVS_CHECK(pSwitchInfo->pOldNicRequest == NULL);
        pSwitchInfo->pOldNicRequest = pNicOidRequest;

        pNewNicOidRequest = (PNDIS_SWITCH_NIC_OID_REQUEST)
            ExAllocatePoolWithTag(NonPagedPool, sizeof(NDIS_SWITCH_NIC_OID_REQUEST), g_extAllocationTag);

        if (pNewNicOidRequest == NULL)
        {
            status = NDIS_STATUS_RESOURCES;
            *pComplete = TRUE;
            goto Cleanup;
        }

        pNewNicOidRequest->Header = pNicOidRequest->Header;
        pNewNicOidRequest->SourcePortId = sourcePort;
        pNewNicOidRequest->SourceNicIndex = sourceNic;
        pNewNicOidRequest->DestinationPortId = destPort;
        pNewNicOidRequest->DestinationNicIndex = destNic;
        pNewNicOidRequest->OidRequest = pNicOidRequest->OidRequest;

        pOidRequest->DATA.METHOD_INFORMATION.InformationBuffer = pNewNicOidRequest;
    }

Cleanup:
    return status;
}

NDIS_STATUS _OnOidNicSave(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_OBJECT_HEADER* pObjectHeader,
    _Inout_ BOOLEAN* pComplete, _Inout_ ULONG* pOutBytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG bytesWritten = 0;
    ULONG bytesNeeded = 0;

    if (pObjectHeader->Type != NDIS_OBJECT_TYPE_DEFAULT ||
        pObjectHeader->Revision < NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1 ||
        pObjectHeader->Size < NDIS_SIZEOF_NDIS_SWITCH_NIC_SAVE_STATE_REVISION_1)
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    status = Nic_Save(pForwardInfo, (PNDIS_SWITCH_NIC_SAVE_STATE)pObjectHeader, &bytesWritten, &bytesNeeded);

    if (status == NDIS_STATUS_SUCCESS &&
        bytesWritten > 0)
    {
        *pComplete = TRUE;
    }
    else if (status == NDIS_STATUS_BUFFER_TOO_SHORT)
    {
        *pOutBytesNeeded = ((PNDIS_SWITCH_NIC_SAVE_STATE)pObjectHeader)->SaveDataOffset + bytesNeeded;
        *pComplete = TRUE;
    }
    else if (status != NDIS_STATUS_SUCCESS)
    {
        *pComplete = TRUE;
    }

Cleanup:
    return status;
}

_Use_decl_annotations_
NDIS_STATUS OID_GetNicArrayUnsafe(OVS_SWITCH_INFO* pSwitchInfo, NDIS_SWITCH_NIC_ARRAY** ppNicArray)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG bytesNeeded = 0;
    NDIS_SWITCH_NIC_ARRAY* pNicArray = NULL;
    ULONG arrayLength = 0;

    do
    {
        if (pNicArray != NULL)
        {
            ExFreePoolWithTag(pNicArray, g_extAllocationTag);
        }

        if (bytesNeeded != 0)
        {
            arrayLength = bytesNeeded;
            pNicArray = ExAllocatePoolWithTag(NonPagedPool, arrayLength, g_extAllocationTag);

            if (pNicArray == NULL)
            {
                status = NDIS_STATUS_RESOURCES;
                goto Cleanup;
            }

            pNicArray->Header.Revision = NDIS_SWITCH_PORT_ARRAY_REVISION_1;
            pNicArray->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
            pNicArray->Header.Size = (USHORT)arrayLength;
        }

        status = OID_IssueOidRequest(pSwitchInfo, NdisRequestQueryInformation, OID_SWITCH_NIC_ARRAY, pNicArray, arrayLength,
            0, 0, 0, &bytesNeeded);
    } while (status == NDIS_STATUS_INVALID_LENGTH);

    *ppNicArray = pNicArray;

Cleanup:
    if (status != NDIS_STATUS_SUCCESS && pNicArray != NULL)
    {
        ExFreePoolWithTag(pNicArray, g_extAllocationTag);
    }

    return status;
}

/************************************  OIDS ************************************/
_Use_decl_annotations_
NDIS_STATUS OID_ProcessSetOid(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_OID_REQUEST* pOidRequest, BOOLEAN* pComplete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_OID oid = pOidRequest->DATA.SET_INFORMATION.Oid;
    NDIS_OBJECT_HEADER* pObjectHeader;

    *pComplete = FALSE;

    pObjectHeader = pOidRequest->DATA.SET_INFORMATION.InformationBuffer;

    if (pOidRequest->DATA.SET_INFORMATION.InformationBufferLength != 0 &&
        pOidRequest->DATA.SET_INFORMATION.InformationBufferLength < sizeof(NDIS_OBJECT_HEADER))
    {
        status = NDIS_STATUS_NOT_SUPPORTED;
        *pComplete = TRUE;
        goto Cleanup;
    }

    if (pOidRequest->DATA.SET_INFORMATION.InformationBufferLength == 0)
    {
        *pComplete = FALSE;
        goto Cleanup;
    }

    switch (oid)
    {
    case OID_SWITCH_PORT_PROPERTY_ADD: status = _OnOidPortPropertyAdd(pObjectHeader, pComplete); break;
    case OID_SWITCH_PORT_PROPERTY_UPDATE: status = _OnOidPortPropertyUpdate(pObjectHeader, pComplete); break;
    case OID_SWITCH_PORT_PROPERTY_DELETE: status = _OnOidPortPropertyDelete(pObjectHeader, pComplete); break;

    case OID_SWITCH_PORT_CREATE: status = _OnOidPortCreate(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_PORT_UPDATED: status = _OnOidPortUpdated(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_PORT_TEARDOWN: status = _OnOidPortTeardown(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_PORT_DELETE: status = _OnOidPortDelete(pForwardInfo, pObjectHeader, pComplete); break;

    case OID_SWITCH_NIC_CREATE: status = _OnOidNicCreate(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_CONNECT: status = _OnOidNicConnect(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_UPDATED: status = _OnOidNicUpdated(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_DISCONNECT: status = _OnOidNicDisconnect(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_DELETE: status = _OnOidNicDelete(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_RESTORE: _OnOidNicRestore(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_SAVE_COMPLETE: _OnOidNicSaveComplete(pForwardInfo, pObjectHeader, pComplete); break;
    case OID_SWITCH_NIC_RESTORE_COMPLETE: _OnOidNicRestoreComplete(pForwardInfo, pObjectHeader, pComplete); break;

    default:
        break;
    }

Cleanup:
    return status;
}

_Use_decl_annotations_
NDIS_STATUS OID_ProcessMethodOid(OVS_SWITCH_INFO* pSwitchInfo, NDIS_OID_REQUEST* pOidRequest, BOOLEAN* pComplete, ULONG* pOutBytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_OID oid = pOidRequest->DATA.SET_INFORMATION.Oid;
    NDIS_OBJECT_HEADER* pObjectHeader = NULL;

    *pComplete = FALSE;
    *pOutBytesNeeded = 0;

    pObjectHeader = pOidRequest->DATA.METHOD_INFORMATION.InformationBuffer;

    switch (oid)
    {
    case OID_SWITCH_PORT_FEATURE_STATUS_QUERY: status = _OnOidPortFeatureStatusQuery(pSwitchInfo->pForwardInfo, pObjectHeader, pComplete, pOutBytesNeeded); break;

    case OID_SWITCH_NIC_REQUEST: status = _OnOidNicRequest(pSwitchInfo, pObjectHeader, pComplete, pOidRequest); break;
    case OID_SWITCH_NIC_SAVE: status = _OnOidNicSave(pSwitchInfo->pForwardInfo, pObjectHeader, pComplete, pOutBytesNeeded); break;

    default:
        break;
    }

    return status;
}

_Use_decl_annotations_
NDIS_STATUS OID_IssueOidRequest(OVS_SWITCH_INFO* pSwitchInfo, NDIS_REQUEST_TYPE requestType, NDIS_OID oid,
VOID* pInformationBuffer, ULONG informationBufferLength, ULONG outputBufferLength, ULONG methodId,
UINT timeout, ULONG* pOutBytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_OID_REQUEST* pOidRequest = NULL;
    NDIS_OID_REQUEST* pNdisOidRequest = NULL;
    ULONG bytesNeeded = 0;
    BOOLEAN asyncCompletion = FALSE;

    NdisInterlockedIncrement(&pSwitchInfo->pendingOidCount);

    if (pSwitchInfo->controlFlowState != OVS_SWITCH_ATTACHED)
    {
        status = NDIS_STATUS_CLOSING;
        goto Cleanup;
    }

    pOidRequest = (POVS_OID_REQUEST)ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_OID_REQUEST), g_extAllocationTag);
    if (pOidRequest == NULL)
    {
        goto Cleanup;
    }

    NdisZeroMemory(pOidRequest, sizeof(OVS_OID_REQUEST));
    pNdisOidRequest = &pOidRequest->ndisOidRequest;
    NdisInitializeEvent(&pOidRequest->reqEvent);

    pNdisOidRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    pNdisOidRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    pNdisOidRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
    pNdisOidRequest->RequestType = requestType;
    pNdisOidRequest->Timeout = timeout;

    switch (requestType)
    {
    case NdisRequestQueryInformation:
        pNdisOidRequest->DATA.QUERY_INFORMATION.Oid = oid;
        pNdisOidRequest->DATA.QUERY_INFORMATION.InformationBuffer = pInformationBuffer;
        pNdisOidRequest->DATA.QUERY_INFORMATION.InformationBufferLength = informationBufferLength;
        break;

    case NdisRequestSetInformation:
        pNdisOidRequest->DATA.SET_INFORMATION.Oid = oid;
        pNdisOidRequest->DATA.SET_INFORMATION.InformationBuffer = pInformationBuffer;
        pNdisOidRequest->DATA.SET_INFORMATION.InformationBufferLength = informationBufferLength;
        break;

    case NdisRequestMethod:
        pNdisOidRequest->DATA.METHOD_INFORMATION.Oid = oid;
        pNdisOidRequest->DATA.METHOD_INFORMATION.MethodId = methodId;
        pNdisOidRequest->DATA.METHOD_INFORMATION.InformationBuffer = pInformationBuffer;
        pNdisOidRequest->DATA.METHOD_INFORMATION.InputBufferLength = informationBufferLength;
        pNdisOidRequest->DATA.METHOD_INFORMATION.OutputBufferLength = outputBufferLength;
        break;

    default:
        NT_ASSERT(FALSE);
        break;
    }

    pNdisOidRequest->RequestId = (PVOID)g_extOidRequestId;
    status = NdisFOidRequest(pSwitchInfo->filterHandle, pNdisOidRequest);

    if (status == NDIS_STATUS_PENDING)
    {
        asyncCompletion = TRUE;
        NdisWaitEvent(&pOidRequest->reqEvent, 0);
    }
    else
    {
        OID_CompleteInternalOidRequest(pNdisOidRequest, status);
    }

    bytesNeeded = pOidRequest->bytesNeeded;
    status = pOidRequest->status;

Cleanup:

    if (pOutBytesNeeded != NULL)
    {
        *pOutBytesNeeded = bytesNeeded;
    }

    if (!asyncCompletion)
    {
        NdisInterlockedDecrement(&pSwitchInfo->pendingOidCount);
    }

    if (pOidRequest != NULL)
    {
        ExFreePoolWithTag(pOidRequest, g_extAllocationTag);
    }

    return status;
}