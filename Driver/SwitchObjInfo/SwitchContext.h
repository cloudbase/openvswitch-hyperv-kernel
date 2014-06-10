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

typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;
typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;

/***************************** Switch **************************************/
NDIS_STATUS Sctx_InitSwitch(_Inout_ OVS_SWITCH_INFO* pSwitchInfo);

UINT Sctx_MakeBroadcastArrayUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* pBroadcastArray,
    _In_ NDIS_SWITCH_PORT_ID sourcePortId, _In_ NDIS_SWITCH_NIC_INDEX sourceNicIndex, _Out_ ULONG* pMtu);