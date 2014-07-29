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

#include "OvsCore.h"
#include "List.h"
#include "OFDatapath.h"
#include "OFFlow.h"
#include "WinlDevice.h"
#include "Gre.h"
#include "Vxlan.h"
#include "OFFlowTable.h"
#include "OFPort.h"

ULONG g_extAllocationTag = 'xsvO';
NDIS_RW_LOCK_EX* g_pRefRwLock = NULL;

NDIS_STATUS OvsInit(NET_IFINDEX dpIfIndex)
{
    INT64 timeInMs = 10 /*mins*/ * 60 /*s*/ * 1000 /*ms*/;

    if (!OFPort_Initialize())
    {
        return NDIS_STATUS_FAILURE;
    }

    UNREFERENCED_PARAMETER(timeInMs);

    if (!CreateDefaultDatapath(dpIfIndex))
    {
        return NDIS_STATUS_FAILURE;
    }

    return NDIS_STATUS_SUCCESS;
}

VOID OvsUninit()
{
    Driver_RemoveDatapath();

    OFPort_Uninitialize();
}