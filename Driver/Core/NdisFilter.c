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
#include "NdisFilter.h"
#include "OidNic.h"
#include "OIDRequest.h"
#include "NblsEgress.h"
#include "Frame.h"
#include "NblsIngress.h"
#include "Nbls.h"
#include "SendIngressBasic.h"
#include "WinlDevice.h"
#include "OvsCore.h"
#include "PersistentPort.h"
#include "OidPort.h"

#include <netioapi.h>

NDIS_HANDLE g_driverHandle = NULL;
NDIS_HANDLE g_driverObject;

LIST_ENTRY g_arpTable;

/*****************************************/
NDIS_SPIN_LOCK g_nbPoolLock;
NDIS_HANDLE g_hNblPool = NULL;
NDIS_HANDLE g_hNbPool = NULL;
UINT g_tagNblPool = 'PsvO';
UINT g_tagNbPool = 'PsvO';

PNDIS_RW_LOCK_EX g_pArpRWLock = NULL;

LONG g_requestID = 0xFFFFFFFE;

/******************************/

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_DRIVER_CHARACTERISTICS driverChars = { 0 };
    NDIS_STRING serviceName = { 0 };

    UNREFERENCED_PARAMETER(pRegistryPath);

    RtlInitUnicodeString(&serviceName, g_driverServiceName);
    RtlInitUnicodeString(&g_extensionFriendlyName, g_driverFriendlyName);
    RtlInitUnicodeString(&g_extensionGuid, g_driverUniqueName);
    g_driverObject = pDriverObject;

    NdisZeroMemory(&driverChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
    driverChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    driverChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
    driverChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    driverChars.MajorNdisVersion = g_driverMajorNdisVersion;
    driverChars.MinorNdisVersion = g_driverMinorNdisVersion;
    driverChars.MajorDriverVersion = 1;
    driverChars.MinorDriverVersion = 0;
    driverChars.Flags = 0;
    driverChars.FriendlyName = g_extensionFriendlyName;
    driverChars.UniqueName = g_extensionGuid;
    driverChars.ServiceName = serviceName;

    /******************** HANDLERS ******************/
    driverChars.SetOptionsHandler = FilterSetOptions;
    driverChars.SetFilterModuleOptionsHandler = FilterSetModuleOptions;

    driverChars.AttachHandler = FilterAttach;
    driverChars.DetachHandler = FilterDetach;
    driverChars.PauseHandler = FilterPause;
    driverChars.RestartHandler = FilterRestart;

    driverChars.SendNetBufferListsHandler = FilterSendNetBufferLists;
    driverChars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
    driverChars.CancelSendNetBufferListsHandler = FilterCancelSendNetBufferLists;
    driverChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
    driverChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;

    driverChars.OidRequestHandler = FilterOidRequest;
    driverChars.OidRequestCompleteHandler = FilterOidRequestComplete;
    driverChars.CancelOidRequestHandler = FilterCancelOidRequest;

    driverChars.NetPnPEventHandler = FilterNetPnPEvent;
    driverChars.StatusHandler = FilterStatus;

    NdisAllocateSpinLock(&g_driver.lock);
    NdisAllocateSpinLock(&g_nbPoolLock);
    g_pRefRwLock = NdisAllocateRWLock(NULL);

    InitializeListHead(&g_driver.switchList);
    InitializeListHead(&g_driver.datapathList);

    pDriverObject->DriverUnload = DriverUnload;

    status = NdisFRegisterFilterDriver(pDriverObject, (NDIS_HANDLE)g_driverObject, &driverChars, &g_driverHandle);

    if (status != NDIS_STATUS_SUCCESS)
    {
        DEBUGP(LOG_ERROR, "OVS: failed NdisFRegisterFilterDriver");
        goto Cleanup;
    }

    status = WinlCreateDevices(pDriverObject, g_driverHandle);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    g_pArpRWLock = NdisAllocateRWLock((NDIS_HANDLE)g_driverObject);
    InitializeListHead(&g_arpTable);

Cleanup:

    if (status != NDIS_STATUS_SUCCESS)
    {
        if (g_driverHandle)
        {
            NdisFDeregisterFilterDriver(g_driverHandle);
            g_driverHandle = NULL;
        }

        NdisFreeRWLock(g_pRefRwLock);
        NdisFreeSpinLock(&g_driver.lock);
    }

    return status;
}

/***************************************************************/

_Use_decl_annotations_
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject);

    WinlDeleteDevices();

    Arp_DestroyTable();
    NdisFreeRWLock(g_pArpRWLock);
    g_pArpRWLock = NULL;

    NdisFDeregisterFilterDriver(g_driverHandle);

    NdisFreeRWLock(g_pRefRwLock);
    NdisFreeSpinLock(&g_driver.lock);
    NdisFreeSpinLock(&g_nbPoolLock);
}

_Use_decl_annotations_
NDIS_STATUS FilterSetOptions(NDIS_HANDLE ndisDriverHandle, NDIS_HANDLE driverContext)
{
    UNREFERENCED_PARAMETER(ndisDriverHandle);
    UNREFERENCED_PARAMETER(driverContext);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS FilterSetModuleOptions(NDIS_HANDLE filterModuleContext)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS FilterAttach(NDIS_HANDLE ndisFilterHandle, NDIS_HANDLE hDriverContext, PNDIS_FILTER_ATTACH_PARAMETERS attachParameters)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_ATTRIBUTES filterAttributes = { 0 };
    ULONG switchObjectSize = 0;
    NDIS_SWITCH_CONTEXT switchContext = { 0 };
    NDIS_SWITCH_OPTIONAL_HANDLERS switchHandler = { 0 };
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params = { 0 };
    NET_BUFFER_POOL_PARAMETERS nb_pool_params = { 0 };

    UNREFERENCED_PARAMETER(hDriverContext);

    DEBUGP(LOG_INFO, "FilterAttach: NdisFilterHandle %p\n", ndisFilterHandle);

    status = NDIS_STATUS_SUCCESS;
    pSwitchInfo = NULL;

    NT_ASSERT(hDriverContext == (NDIS_HANDLE)g_driverObject);

    if (attachParameters->MiniportMediaType != NdisMedium802_3)
    {
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    switchHandler.Header.Type = NDIS_OBJECT_TYPE_SWITCH_OPTIONAL_HANDLERS;
    switchHandler.Header.Size = NDIS_SIZEOF_SWITCH_OPTIONAL_HANDLERS_REVISION_1;
    switchHandler.Header.Revision = NDIS_SWITCH_OPTIONAL_HANDLERS_REVISION_1;

    status = NdisFGetOptionalSwitchHandlers(ndisFilterHandle, &switchContext, &switchHandler);

    if (status != NDIS_STATUS_SUCCESS)
    {
        DEBUGP(LOG_ERROR, "Attach: Extension is running in non-switch environment.\n");
        goto Cleanup;
    }

    switchObjectSize = sizeof(OVS_SWITCH_INFO);
    pSwitchInfo = KZAlloc(switchObjectSize);
    if (pSwitchInfo == NULL)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    pSwitchInfo->refCount.Destroy = Switch_DestroyNow_Unsafe;
    pSwitchInfo->datapathIfIndex = 1;

    pSwitchInfo->filterHandle = ndisFilterHandle;
    pSwitchInfo->switchContext = switchContext;
    RtlCopyMemory(&pSwitchInfo->switchHandlers, &switchHandler, sizeof(NDIS_SWITCH_OPTIONAL_HANDLERS));

    status = Switch_CreateForwardInfo(pSwitchInfo, &pSwitchInfo->pForwardInfo);

    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    NdisZeroMemory(&filterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
    filterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    filterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
    filterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    filterAttributes.Flags = 0;

    NDIS_DECLARE_FILTER_MODULE_CONTEXT(OVS_SWITCH_INFO);
    status = NdisFSetAttributes(ndisFilterHandle, pSwitchInfo, &filterAttributes);

    if (status != NDIS_STATUS_SUCCESS)
    {
        DEBUGP(LOG_ERROR, "FilterAttach: Failed to set attributes.\n");
        goto Cleanup;
    }

    pSwitchInfo->controlFlowState = OVS_SWITCH_ATTACHED;
    pSwitchInfo->dataFlowState = OVS_SWITCH_PAUSED;

    DRIVER_LOCK();
    InsertHeadList(&g_driver.switchList, &pSwitchInfo->listEntry);
    DRIVER_UNLOCK();

    status = OvsInit(g_driverHandle);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    //the NBL pool handle
    nbl_pool_params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_params.Header.Size = sizeof(NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1);
    nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nbl_pool_params.fAllocateNetBuffer = FALSE;
    nbl_pool_params.ContextSize = MEMORY_ALLOCATION_ALIGNMENT * 2;
    nbl_pool_params.PoolTag = g_tagNblPool;
    nbl_pool_params.DataSize = 0;

    NdisAcquireSpinLock(&g_nbPoolLock);
    g_hNblPool = NdisAllocateNetBufferListPool(ndisFilterHandle, &nbl_pool_params);
    if (!g_hNblPool)
    {
        NdisReleaseSpinLock(&g_nbPoolLock);
        DEBUGP(LOG_ERROR, "FilterAtach: Could not get NBL pool handle.\n");
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    //the NB pool handle
    nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nb_pool_params.PoolTag = g_tagNbPool;
    nb_pool_params.DataSize = 0;

    g_hNbPool = NdisAllocateNetBufferPool(ndisFilterHandle, &nb_pool_params);
    if (!g_hNbPool)
    {
        NdisReleaseSpinLock(&g_nbPoolLock);
        DEBUGP(LOG_ERROR, "FilterAtach: Could not get NB pool handle.\n");
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    NdisReleaseSpinLock(&g_nbPoolLock);

Cleanup:

    if (status != NDIS_STATUS_SUCCESS)
    {
        NdisAcquireSpinLock(&g_nbPoolLock);
        if (g_hNblPool)
        {
            NdisFreeNetBufferListPool(g_hNblPool);
        }

        if (g_hNbPool)
        {
            NdisFreeNetBufferPool(g_hNbPool);
        }

        NdisReleaseSpinLock(&g_nbPoolLock);

        KFree(pSwitchInfo);
    }

    DEBUGP(LOG_TRACE, "Attach: status %x\n", status);

    return status;
}

_Use_decl_annotations_
VOID FilterDetach(NDIS_HANDLE filterModuleContext)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    DEBUGP(LOG_TRACE, "Detach: Instance %p\n", filterModuleContext);

    OvsUninit();

    NdisAcquireSpinLock(&g_nbPoolLock);
    NdisFreeNetBufferPool(g_hNbPool);
    NdisFreeNetBufferListPool(g_hNblPool);
    NdisReleaseSpinLock(&g_nbPoolLock);

    Driver_DetachExtension(pSwitchInfo);

    DEBUGP(LOG_TRACE, "Detach Successfully\n");
    return;
}

_Use_decl_annotations_
NDIS_STATUS FilterPause(NDIS_HANDLE filterModuleContext, PNDIS_FILTER_PAUSE_PARAMETERS pauseParameters)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)(filterModuleContext);

    UNREFERENCED_PARAMETER(pauseParameters);

    DEBUGP(LOG_TRACE, "NDISLWF Pause: Instance %p\n", filterModuleContext);

    Switch_Pause(pSwitchInfo);

    NT_ASSERT(pSwitchInfo->dataFlowState == OVS_SWITCH_RUNNING);
    pSwitchInfo->dataFlowState = OVS_SWITCH_PAUSED;

    KeMemoryBarrier();

    while (pSwitchInfo->pendingInjectedNblCount > 0)
    {
        NdisMSleep(1000);
    }

    DEBUGP(LOG_TRACE, "Pause: status %x\n", NDIS_STATUS_SUCCESS);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS FilterRestart(NDIS_HANDLE filterModuleContext, PNDIS_FILTER_RESTART_PARAMETERS restartParameters)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(restartParameters);

    DEBUGP(LOG_TRACE, "Restart: FilterModuleContext %p\n", filterModuleContext);

    status = Switch_Restart(pSwitchInfo);
    if (status != NDIS_STATUS_SUCCESS)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    NT_ASSERT(pSwitchInfo->dataFlowState == OVS_SWITCH_PAUSED);
    pSwitchInfo->dataFlowState = OVS_SWITCH_RUNNING;

    DEBUGP(LOG_TRACE, "Restart: FilterModuleContext %p, status %x\n", filterModuleContext, NDIS_STATUS_SUCCESS);

Cleanup:
    return status;
}

_Use_decl_annotations_
NDIS_STATUS FilterOidRequest(NDIS_HANDLE filterModuleContext, PNDIS_OID_REQUEST oidRequest)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_OID_REQUEST clonedRequest = NULL;
    PVOID *cloneRequestContext = NULL;
    BOOLEAN completeOid = FALSE;
    ULONG bytesNeeded = 0;

    DEBUGP_OID(LOG_TRACE, "FilterOidRequest: oid type: %x; oid: %x\n.", oidRequest->RequestType, oidRequest->DATA.QUERY_INFORMATION.Oid);

    NdisInterlockedIncrement(&pSwitchInfo->pendingOidCount);

    status = NdisAllocateCloneOidRequest(pSwitchInfo->filterHandle, oidRequest, g_extAllocationTag, &clonedRequest);
    if (status != NDIS_STATUS_SUCCESS)
    {
        DEBUGP_OID(LOG_WARN, "FilerOidRequest: Cannot Clone OidRequest\n");
        goto Cleanup;
    }

    cloneRequestContext = (PVOID*)(&clonedRequest->SourceReserved[0]);
    *cloneRequestContext = oidRequest;

    switch (clonedRequest->RequestType)
    {
    case NdisRequestSetInformation:
        status = OID_ProcessSetOid(pSwitchInfo->pForwardInfo, clonedRequest, &completeOid);
        break;

    case NdisRequestMethod:
        status = OID_ProcessMethodOid(pSwitchInfo, clonedRequest, &completeOid, &bytesNeeded);
        break;
    }

    if (completeOid)
    {
        NdisFreeCloneOidRequest(pSwitchInfo->filterHandle, clonedRequest);
        oidRequest->DATA.METHOD_INFORMATION.BytesNeeded = bytesNeeded;
        NdisInterlockedDecrement(&pSwitchInfo->pendingOidCount);
        goto Cleanup;
    }

    status = NdisFOidRequest(pSwitchInfo->filterHandle, clonedRequest);

    if (status != NDIS_STATUS_PENDING)
    {
        FilterOidRequestComplete(pSwitchInfo, clonedRequest, status);

        status = NDIS_STATUS_PENDING;
    }

Cleanup:

    DEBUGP_OID(LOG_TRACE, "OidRequest: status %8x.\n", status);
    return status;
}

_Use_decl_annotations_
VOID FilterCancelOidRequest(NDIS_HANDLE filterModuleContext, PVOID requestId)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(requestId);
}

_Use_decl_annotations_
VOID FilterOidRequestComplete(NDIS_HANDLE filterModuleContext, PNDIS_OID_REQUEST oidRequest, NDIS_STATUS status)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    PNDIS_OID_REQUEST originalRequest = NULL;
    PVOID *oidRequestContext = NULL;
    PNDIS_SWITCH_NIC_OID_REQUEST nicOidRequestBuf = NULL;
    PNDIS_OBJECT_HEADER header = NULL;

    DEBUGP_OID(LOG_TRACE, "FilterOidRequestComplete: oid type: %x; oid: %x\n.", oidRequest->RequestType, oidRequest->DATA.QUERY_INFORMATION.Oid);

    oidRequestContext = (PVOID*)(&oidRequest->SourceReserved[0]);
    originalRequest = (*oidRequestContext);

    if (originalRequest == NULL)
    {
        OID_CompleteInternalOidRequest(oidRequest, status);
        goto Cleanup;
    }

    switch (oidRequest->RequestType)
    {
    case NdisRequestMethod:
        originalRequest->DATA.METHOD_INFORMATION.OutputBufferLength = oidRequest->DATA.METHOD_INFORMATION.OutputBufferLength;
        originalRequest->DATA.METHOD_INFORMATION.BytesRead = oidRequest->DATA.METHOD_INFORMATION.BytesRead;
        originalRequest->DATA.METHOD_INFORMATION.BytesNeeded = oidRequest->DATA.METHOD_INFORMATION.BytesNeeded;
        originalRequest->DATA.METHOD_INFORMATION.BytesWritten = oidRequest->DATA.METHOD_INFORMATION.BytesWritten;

        if (oidRequest->DATA.METHOD_INFORMATION.Oid == OID_SWITCH_NIC_REQUEST && pSwitchInfo->pOldNicRequest != NULL)
        {
            nicOidRequestBuf = oidRequest->DATA.METHOD_INFORMATION.InformationBuffer;

            status = Nic_ProcessRequestComplete(pSwitchInfo->pForwardInfo, nicOidRequestBuf->OidRequest,
                nicOidRequestBuf->SourcePortId, nicOidRequestBuf->SourceNicIndex,
                nicOidRequestBuf->DestinationPortId, nicOidRequestBuf->DestinationNicIndex,
                status);

            originalRequest->DATA.METHOD_INFORMATION.InformationBuffer = pSwitchInfo->pOldNicRequest;
            pSwitchInfo->pOldNicRequest = NULL;
            KFree(nicOidRequestBuf);
        }

        break;

    case NdisRequestSetInformation:
        header = originalRequest->DATA.SET_INFORMATION.InformationBuffer;

        originalRequest->DATA.SET_INFORMATION.BytesRead = oidRequest->DATA.SET_INFORMATION.BytesRead;
        originalRequest->DATA.SET_INFORMATION.BytesNeeded = oidRequest->DATA.SET_INFORMATION.BytesNeeded;

        if (oidRequest->DATA.METHOD_INFORMATION.Oid == OID_SWITCH_PORT_CREATE && status != NDIS_STATUS_SUCCESS)
        {
            Port_Delete(pSwitchInfo->pForwardInfo, (PNDIS_SWITCH_PORT_PARAMETERS)header);
        }
        else if (oidRequest->DATA.METHOD_INFORMATION.Oid == OID_SWITCH_PORT_CREATE && status != NDIS_STATUS_SUCCESS)
        {
            Nic_Delete(pSwitchInfo->pForwardInfo, (PNDIS_SWITCH_NIC_PARAMETERS)header);
        }

        break;

    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    default:
        originalRequest->DATA.QUERY_INFORMATION.BytesWritten = oidRequest->DATA.QUERY_INFORMATION.BytesWritten;
        originalRequest->DATA.QUERY_INFORMATION.BytesNeeded = oidRequest->DATA.QUERY_INFORMATION.BytesNeeded;
        break;
    }

    (*oidRequestContext) = NULL;

    NdisFreeCloneOidRequest(pSwitchInfo->filterHandle, oidRequest);
    NdisFOidRequestComplete(pSwitchInfo->filterHandle, originalRequest, status);

    DEBUGP_OID(LOG_TRACE, "OidRequestComplete.\n");

Cleanup:
    NdisInterlockedDecrement(&pSwitchInfo->pendingOidCount);
}

_Use_decl_annotations_
VOID FilterSendNetBufferLists(NDIS_HANDLE filterModuleContext, PNET_BUFFER_LIST netBufferLists, NDIS_PORT_NUMBER portNumber, ULONG sendFlags)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    UNREFERENCED_PARAMETER(portNumber);

    DRIVER_LOCK();
    pSwitchInfo = OVS_REFCOUNT_REFERENCE(pSwitchInfo);
    DRIVER_UNLOCK();

    OVS_CHECK(pSwitchInfo);

    Nbls_SendIngress(pSwitchInfo, pSwitchInfo->pForwardInfo, netBufferLists, sendFlags);

    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);
}

_Use_decl_annotations_
VOID FilterSendNetBufferListsComplete(NDIS_HANDLE filterModuleContext, PNET_BUFFER_LIST netBufferLists, ULONG sendCompleteFlags)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    UNREFERENCED_PARAMETER(sendCompleteFlags);

    DEBUGP(LOG_LOUD, "Complete: ");
    DbgPrintNblList(netBufferLists);

    FreeDuplicateNbl(pSwitchInfo, netBufferLists);
    Nbls_CompletedInjected(pSwitchInfo, 1);
}

_Use_decl_annotations_
VOID FilterReceiveNetBufferLists(NDIS_HANDLE filterModuleContext, PNET_BUFFER_LIST netBufferLists, NDIS_PORT_NUMBER portNumber,
ULONG numberOfNetBufferLists, ULONG receiveFlags)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    UNREFERENCED_PARAMETER(portNumber);

    Nbls_StartEgress(pSwitchInfo, pSwitchInfo->pForwardInfo, netBufferLists, numberOfNetBufferLists, receiveFlags);
}

_Use_decl_annotations_
VOID FilterReturnNetBufferLists(NDIS_HANDLE filterModuleContext, PNET_BUFFER_LIST netBufferLists, ULONG returnFlags)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;

    Nbls_CompleteEgress(pSwitchInfo, pSwitchInfo->pForwardInfo, netBufferLists, returnFlags);
}

_Use_decl_annotations_
VOID FilterCancelSendNetBufferLists(NDIS_HANDLE filterModuleContext, PVOID cancelId)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(cancelId);
}

_Use_decl_annotations_
NDIS_STATUS FilterNetPnPEvent(NDIS_HANDLE filterModuleContext, PNET_PNP_EVENT_NOTIFICATION netPnPEvent)
{
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    if (netPnPEvent->NetPnPEvent.NetEvent == NetEventSwitchActivate)
    {
        Switch_Activate(pSwitchInfo);
    }

    return NdisFNetPnPEvent(pSwitchInfo->filterHandle, netPnPEvent);
}

_Use_decl_annotations_
VOID FilterStatus(NDIS_HANDLE filterModuleContext, PNDIS_STATUS_INDICATION statusIndication)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    OVS_SWITCH_INFO* pSwitchInfo = (OVS_SWITCH_INFO*)filterModuleContext;
    PNDIS_SWITCH_NIC_STATUS_INDICATION nicIndication = NULL;
    PNDIS_STATUS_INDICATION originalIndication = NULL;

    if (statusIndication->Header.Type != NDIS_OBJECT_TYPE_STATUS_INDICATION ||
        statusIndication->Header.Revision != NDIS_STATUS_INDICATION_REVISION_1 ||
        statusIndication->Header.Size != NDIS_SIZEOF_STATUS_INDICATION_REVISION_1)
    {
        goto Cleanup;
    }

    if (statusIndication->StatusCode != NDIS_STATUS_SWITCH_NIC_STATUS)
    {
        goto Cleanup;
    }

    nicIndication = statusIndication->StatusBuffer;

    if (nicIndication->Header.Type != NDIS_OBJECT_TYPE_DEFAULT ||
        nicIndication->Header.Revision != NDIS_SWITCH_NIC_STATUS_INDICATION_REVISION_1 ||
        nicIndication->Header.Size != NDIS_SIZEOF_SWITCH_NIC_STATUS_REVISION_1)
    {
        goto Cleanup;
    }

    originalIndication = nicIndication->StatusIndication;

    status = Nic_ProcessStatus(pSwitchInfo->pForwardInfo, originalIndication, nicIndication->SourcePortId, nicIndication->SourceNicIndex);

Cleanup:
    if (status == NDIS_STATUS_SUCCESS)
    {
        NdisFIndicateStatus(pSwitchInfo->filterHandle, statusIndication);
    }

    return;
}