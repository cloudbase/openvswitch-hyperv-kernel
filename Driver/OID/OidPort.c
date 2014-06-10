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
#include "Switch.h"
#include "Sctx_Port.h"

_Use_decl_annotations_
NDIS_STATUS Port_Create(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pPort)
{
    if (!pPort->IsValidationPort)
    {
        NDIS_STATUS status = NDIS_STATUS_SUCCESS;
        LOCK_STATE_EX lockState = { 0 };
        OVS_PORT_LIST_ENTRY* pPortEntry = NULL;

        while (pForwardInfo->isInitialRestart)
        {
            NdisMSleep(100);
        }

        Rwlock_LockWrite(pForwardInfo->pRwLock, &lockState);

        OVS_CHECK(pPort->PortState == NdisSwitchPortStateCreated);
        status = Sctx_AddPort_Unsafe(pForwardInfo, pPort, &pPortEntry);
        if (status == NDIS_STATUS_SUCCESS)
        {
            ++(pForwardInfo->countPorts);

            OVS_CHECK(pPortEntry);
            Sctx_Port_SetPersistentPort_Unsafe(pPortEntry);
        }

        Rwlock_Unlock(pForwardInfo->pRwLock, &lockState);

        return status;
    }

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Port_Update(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pPort)
{
    if (!pPort->IsValidationPort)
    {
        LOCK_STATE_EX lockState = { 0 };
        OVS_PORT_LIST_ENTRY* pPortListEntry = NULL;

        while (pForwardInfo->isInitialRestart)
        {
            NdisMSleep(100);
        }

        Rwlock_LockWrite(pForwardInfo->pRwLock, &lockState);

        OVS_CHECK(pPort->PortState == NdisSwitchPortStateCreated);
        pPortListEntry = Sctx_FindPortById_Unsafe(pForwardInfo, pPort->PortId);
        OVS_CHECK(pPortListEntry);

        if (pPortListEntry->portFriendlyName.Length != pPort->PortFriendlyName.Length ||
            memcmp(pPortListEntry->portFriendlyName.String, pPort->PortFriendlyName.String, pPortListEntry->portFriendlyName.Length))
        {
            Sctx_Port_UpdateName_Unsafe(pPortListEntry, &pPort->PortFriendlyName);
        }

        pPortListEntry->portFriendlyName = pPort->PortFriendlyName;
        pPortListEntry->portType = pPort->PortType;
        pPortListEntry->on = (pPort->PortState == NdisSwitchPortStateCreated);

        Rwlock_Unlock(pForwardInfo->pRwLock, &lockState);
    }
}

_Use_decl_annotations_
VOID Port_Teardown(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pPort)
{
    if (!pPort->IsValidationPort)
    {
        LOCK_STATE_EX lockState = { 0 };
        OVS_PORT_LIST_ENTRY* pPortEntry = NULL;

        while (pForwardInfo->isInitialRestart)
        {
            NdisMSleep(100);
        }

        Rwlock_LockWrite(pForwardInfo->pRwLock, &lockState);

        if (pPort->PortType == NdisSwitchPortTypeExternal)
        {
            OVS_CHECK(pForwardInfo->pExternalPort);

            if (pPort->PortId == pForwardInfo->pExternalPort->portId)
            {
                pPortEntry = pForwardInfo->pExternalPort;
            }
        }

        else if (pPort->PortType == NdisSwitchPortTypeInternal)
        {
            OVS_CHECK(pForwardInfo->pInternalPort);
            OVS_CHECK(pPort->PortId == pForwardInfo->pInternalPort->portId);

            pPortEntry = pForwardInfo->pInternalPort;
        }

        else
        {
            pPortEntry = Sctx_FindPortById_Unsafe(pForwardInfo, pPort->PortId);

            OVS_CHECK(pPortEntry != NULL);
        }

        if (pPortEntry)
        {
            Sctx_Port_Disable_Unsafe(pForwardInfo, pPortEntry);
        }

        Rwlock_Unlock(pForwardInfo->pRwLock, &lockState);
    }

    return;
}

_Use_decl_annotations_
VOID
Port_Delete(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const NDIS_SWITCH_PORT_PARAMETERS* pPort)
{
    if (!pPort->IsValidationPort)
    {
        LOCK_STATE_EX lockState = { 0 };

        while (pForwardInfo->isInitialRestart)
        {
            NdisMSleep(100);
        }

        Rwlock_LockWrite(pForwardInfo->pRwLock, &lockState);
        if (pPort->PortType == NdisSwitchPortTypeExternal)
        {
            OVS_CHECK(pForwardInfo->pExternalPort);

            if (pPort->PortId == pForwardInfo->pExternalPort->portId)
            {
                OVS_CHECK(pForwardInfo->pExternalPort->on == FALSE);
                pForwardInfo->pExternalPort = NULL;
            }
        }

        else if (pPort->PortType == NdisSwitchPortTypeInternal)
        {
            OVS_CHECK(pForwardInfo->pInternalNic);

            if (pPort->PortId == pForwardInfo->pInternalPort->portId)
            {
                OVS_CHECK(pForwardInfo->pInternalPort->on == FALSE);
                pForwardInfo->pInternalPort = FALSE;
            }
        }

        Sctx_DeletePort_Unsafe(pForwardInfo, pPort->PortId);

        Rwlock_Unlock(pForwardInfo->pRwLock, &lockState);
    }

    return;
}

_Use_decl_annotations_
NDIS_STATUS Port_AddProperty(const NDIS_SWITCH_PORT_PROPERTY_PARAMETERS* pPortProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;

    switch (pPortProperty->PropertyType)
    {
    case NdisSwitchPortPropertyTypeCustom:
        break;

    case NdisSwitchPortPropertyTypeSecurity:
        break;

    case NdisSwitchPortPropertyTypeVlan:
        status = NDIS_STATUS_DATA_NOT_ACCEPTED;
        break;

    case NdisSwitchPortPropertyTypeProfile:
        break;
    }

    return status;
}

_Use_decl_annotations_
NDIS_STATUS Port_UpdateProperty(const NDIS_SWITCH_PORT_PROPERTY_PARAMETERS* pPortProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;

    switch (pPortProperty->PropertyType)
    {
    case NdisSwitchPortPropertyTypeCustom:
        break;

    case NdisSwitchPortPropertyTypeSecurity:
        break;

    case NdisSwitchPortPropertyTypeVlan:
        status = NDIS_STATUS_DATA_NOT_ACCEPTED;
        break;

    case NdisSwitchPortPropertyTypeProfile:
        break;
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN Port_DeleteProperty(const NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS* pPortProperty)
{
    BOOLEAN do_delete = FALSE;

    switch (pPortProperty->PropertyType)
    {
    case NdisSwitchPortPropertyTypeCustom:
        break;

    case NdisSwitchPortPropertyTypeSecurity:
        break;

    case NdisSwitchPortPropertyTypeVlan:
        do_delete = TRUE;
        break;

    case NdisSwitchPortPropertyTypeProfile:
        break;
    }

    return do_delete;
}

_Use_decl_annotations_
BOOLEAN Port_QueryFeatureStatus(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_SWITCH_PORT_FEATURE_STATUS_PARAMETERS* pPortFeatureStatus, ULONG* pBytesNeeded)
{
    UNREFERENCED_PARAMETER(pForwardInfo);
    UNREFERENCED_PARAMETER(pPortFeatureStatus);
    UNREFERENCED_PARAMETER(pBytesNeeded);

    return FALSE;
}