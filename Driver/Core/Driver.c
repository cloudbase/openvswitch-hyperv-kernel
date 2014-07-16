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

#include "Driver.h"
#include "OFDatapath.h"
#include "Switch.h"

UCHAR g_driverMajorNdisVersion = NDIS_FILTER_MAJOR_VERSION;
UCHAR g_driverMinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
PWCHAR g_driverFriendlyName = L"OpenVSwitch";
PWCHAR g_driverUniqueName = L"{8DD9C187-772D-452E-AC80-D29F9247BB7D}";
PWCHAR g_driverServiceName = L"OpenVSwitch";
ULONG g_extOidRequestId = 'xsvO';

OVS_DRIVER g_driver;

VOID Driver_Uninit()
{
    OVS_DATAPATH* pDatapath = NULL;

    DRIVER_LOCK();

    if (!IsListEmpty(&g_driver.datapathList))
    {
        pDatapath = CONTAINING_RECORD(g_driver.datapathList.Flink, OVS_DATAPATH, listEntry);
        RemoveEntryList(&pDatapath->listEntry);
        OVS_CHECK(IsListEmpty(&g_driver.datapathList));

        OVS_REFCOUNT_DEREF_AND_DESTROY(pDatapath);
    }

    if (!IsListEmpty(&g_driver.switchList))
    {
        OVS_SWITCH_INFO* pSwitchInfo = CONTAINING_RECORD(g_driver.switchList.Flink, OVS_SWITCH_INFO, listEntry);

        OVS_CHECK(pSwitchInfo->dataFlowState == OVS_SWITCH_PAUSED);
        pSwitchInfo->controlFlowState = OVS_SWITCH_DETACHED;

        KeMemoryBarrier();

        while (pSwitchInfo->pendingOidCount > 0)
        {
            NdisMSleep(1000);
        }

        Switch_DeleteForwardInfo(pSwitchInfo->pForwardInfo);

        RemoveEntryList(&pSwitchInfo->listEntry);
        OVS_CHECK(IsListEmpty(&g_driver.switchList));

        KFree(pSwitchInfo);
    }

    DRIVER_UNLOCK();
}

VOID Switch_DestroyNow_Unsafe(OVS_SWITCH_INFO* pSwitchInfo)
{
    OVS_CHECK(pSwitchInfo->dataFlowState == OVS_SWITCH_PAUSED);
    pSwitchInfo->controlFlowState = OVS_SWITCH_DETACHED;

    KeMemoryBarrier();

    while (pSwitchInfo->pendingOidCount > 0)
    {
        NdisMSleep(1000);
    }

    Switch_DeleteForwardInfo(pSwitchInfo->pForwardInfo);

    RemoveEntryList(&pSwitchInfo->listEntry);
    OVS_CHECK(IsListEmpty(&g_driver.switchList));

    KFree(pSwitchInfo);
}

VOID Driver_DetachExtension(OVS_SWITCH_INFO* pSwitchInfo)
{
    DRIVER_LOCK();

    OVS_CHECK(pSwitchInfo->dataFlowState == OVS_SWITCH_PAUSED);
    pSwitchInfo->controlFlowState = OVS_SWITCH_DETACHED;

    KeMemoryBarrier();

    while (pSwitchInfo->pendingOidCount > 0)
    {
        NdisMSleep(1000);
    }

    Switch_DeleteForwardInfo(pSwitchInfo->pForwardInfo);

    RemoveEntryList(&pSwitchInfo->listEntry);
    OVS_CHECK(IsListEmpty(&g_driver.switchList));

    KFree(pSwitchInfo);

    DRIVER_UNLOCK();
}

VOID Driver_RemoveDatapath()
{
    DRIVER_LOCK();

    if (!IsListEmpty(&g_driver.datapathList))
    {
        OVS_DATAPATH* pDatapath = CONTAINING_RECORD(g_driver.datapathList.Flink, OVS_DATAPATH, listEntry);
        RemoveEntryList(&pDatapath->listEntry);
        OVS_CHECK(IsListEmpty(&g_driver.datapathList));

        OVS_REFCOUNT_DESTROY(pDatapath);
    }

    DRIVER_UNLOCK();
}

BOOLEAN Driver_HaveDatapath()
{
    BOOLEAN haveDatapath = FALSE;

    DRIVER_LOCK();

    haveDatapath = !IsListEmpty(&g_driver.datapathList);

    DRIVER_UNLOCK();

    return haveDatapath;
}

OVS_SWITCH_INFO* Driver_GetDefaultSwitch_Ref(const char* funcName)
{
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    DRIVER_LOCK();

    if (!IsListEmpty(&g_driver.switchList))
    {
        pSwitchInfo = CONTAINING_RECORD(g_driver.switchList.Flink, OVS_SWITCH_INFO, listEntry);
        pSwitchInfo = RefCount_Reference(pSwitchInfo, funcName);
    }

    DRIVER_UNLOCK();

    return pSwitchInfo;
}