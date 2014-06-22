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
typedef struct _OVS_DATAPATH OVS_DATAPATH;

extern UCHAR  g_driverMajorNdisVersion;
extern UCHAR  g_driverMinorNdisVersion;

extern PWCHAR g_driverFriendlyName;
extern PWCHAR g_driverUniqueName;
//from the INF
extern PWCHAR g_driverServiceName;

extern ULONG  g_extOidRequestId;

extern NDIS_STRING g_extensionFriendlyName;
extern NDIS_STRING g_extensionGuid;

typedef struct _OVS_DRIVER {
	//the pRwLock will protect against dp removal, but the dp object will need a RCU struct
	NDIS_SPIN_LOCK	lock;

	//ATM one switch
	LIST_ENTRY			switchList;
	LIST_ENTRY			datapathList;
} OVS_DRIVER, *POVS_DRIVER;

extern OVS_DRIVER g_driver;

#define DRIVER_LOCK() NdisAcquireSpinLock(&g_driver.lock)
#define DRIVER_UNLOCK() NdisReleaseSpinLock(&g_driver.lock)

VOID Driver_Uninit();
VOID Driver_DetachExtension(OVS_SWITCH_INFO* pSwitchInfo);
VOID Driver_RemoveDatapath();
VOID Switch_DestroyNow_Unsafe(OVS_SWITCH_INFO* pSwitchInfo);

BOOLEAN Driver_HaveDatapath();
OVS_SWITCH_INFO* Driver_GetDefaultSwitch_Ref(const char* funcName);