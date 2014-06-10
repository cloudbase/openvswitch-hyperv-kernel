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

#pragma once

/* NIC OID HANDLERS */

typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;

NDIS_STATUS Nic_Create(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pNic);

VOID Nic_Connect(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pNic);

VOID Nic_Update(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pNic);

VOID Nic_Disconnect(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pNic);

VOID Nic_Delete(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pNic);

NDIS_STATUS Nic_Save(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ NDIS_SWITCH_NIC_SAVE_STATE* pSaveState,
    _Out_ ULONG* pBytesWritten, _Out_ ULONG* pBytesNeeded);

VOID Nic_SaveComplete(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState);

NDIS_STATUS Nic_Restore(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState, _Out_ ULONG* pBytesRestored);

VOID Nic_RestoreComplete(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_NIC_SAVE_STATE* pSaveState);

NDIS_STATUS Nic_ProcessRequest(_In_ const NDIS_OID_REQUEST* pOidRequest);

NDIS_STATUS Nic_ProcessRequestComplete(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardContext, _Inout_ NDIS_OID_REQUEST* pOidRequest,
    _In_ NDIS_SWITCH_PORT_ID sourcePortId, _In_ NDIS_SWITCH_NIC_INDEX sourceNicIndex,
    _In_ NDIS_SWITCH_PORT_ID destinationPortId, _In_ NDIS_SWITCH_NIC_INDEX destinationNicIndex,
    _In_ NDIS_STATUS status);

NDIS_STATUS Nic_ProcessStatus(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardContext, _In_ const NDIS_STATUS_INDICATION* pStatusIndication,
    _In_ NDIS_SWITCH_PORT_ID sourcePortId, _In_ NDIS_SWITCH_NIC_INDEX sourceNicIndex);