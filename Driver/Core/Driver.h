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

extern UCHAR  g_driverMajorNdisVersion;
extern UCHAR  g_driverMinorNdisVersion;

extern PWCHAR g_driverFriendlyName;
extern PWCHAR g_driverUniqueName;
//from the INF
extern PWCHAR g_driverServiceName;

extern ULONG  g_extOidRequestId;

extern NDIS_STRING g_extensionFriendlyName;
extern NDIS_STRING g_extensionGuid;

VOID Switch_DestroyNow_Unsafe(OVS_SWITCH_INFO* pSwitchInfo);