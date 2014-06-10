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

typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;

VOID Nbls_SendIngressBasic(_In_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, _In_ ULONG sendFlags, _In_ ULONG numInjectedNetBufferLists);

VOID Nbls_CompleteIngress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, _In_ ULONG sendCompleteFlags);

VOID Nbls_DropAllIngress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, _In_ ULONG completeFlags, OVS_NBL_FAIL_REASON failReason);

VOID Nbls_DropOneIngress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl, _In_ ULONG sourcePortId, _In_ ULONG completeFlags, OVS_NBL_FAIL_REASON failReason);

ULONG CalcSendCompleteFlags(ULONG sendFlags);