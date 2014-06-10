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

VOID StatusIndic_IssueUnsafe(_In_ NDIS_HANDLE filterHandle, _In_ NDIS_STATUS statusCode, _In_ NDIS_SWITCH_PORT_ID portId,
    _In_ NDIS_SWITCH_NIC_INDEX nicIndex, _In_ BOOLEAN isDestination, _In_opt_ VOID* pStatusBuffer, _In_ ULONG statusBufferSize);