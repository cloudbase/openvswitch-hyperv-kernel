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

/* PORT OID HANDLERS */

typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;

/*****************************************************  PORT ****************************************************/

NDIS_STATUS Port_Create(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_PORT_PARAMETERS* pPort);

VOID Port_Update(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_PORT_PARAMETERS* pPort);

VOID Port_Teardown(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_PORT_PARAMETERS* pPort);

VOID Port_Delete(_Inout_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ const NDIS_SWITCH_PORT_PARAMETERS* pPort);

NDIS_STATUS Port_AddProperty(_In_ const NDIS_SWITCH_PORT_PROPERTY_PARAMETERS* pPortProperty);

NDIS_STATUS Port_UpdateProperty(_In_ const NDIS_SWITCH_PORT_PROPERTY_PARAMETERS* pPortProperty);

BOOLEAN Port_DeleteProperty(_In_ const NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS* pPortProperty);

BOOLEAN Port_QueryFeatureStatus(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ NDIS_SWITCH_PORT_FEATURE_STATUS_PARAMETERS* pPortFeatureStatus,
    _Inout_ ULONG* pBytesNeeded);