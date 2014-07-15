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

#include "NormalTransfer.h"
#include "Ethernet.h"
#include "NblsIngress.h"
#include "OvsNetBuffer.h"

_Use_decl_annotations_
BOOLEAN ProcessPacket_Normal_SendUnicast(OVS_NET_BUFFER* pOvsNb, const BYTE* destMac)
{
    BOOLEAN mustTransfer = FALSE;
    OVS_NIC_INFO curDestination = { 0 };
    OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pOvsNb->pSwitchInfo->pForwardInfo;

    mustTransfer = GetDestinationInfo(pForwardInfo, destMac, pOvsNb->pSourceNic->portId, &curDestination, &failReason);
    if (!mustTransfer)
    {
        if (failReason != OVS_NBL_FAIL_DESTINATION_IS_SOURCE)
        {
            DEBUGP(LOG_ERROR, "Get destination failed: %s\n", FailReasonMessageA(failReason));
        }

        return FALSE;
    }

    DEBUGP(LOG_LOUD, "Sending unicast to: nic index: %d; port id: %d; adap name: \"%s\"; vm name: \"%s\"\n",
        curDestination.nicIndex, curDestination.portId, curDestination.nicName, curDestination.vmName);

    mustTransfer = SetOneDestination(pOvsNb->pSwitchInfo, pOvsNb->pNbl, &failReason, /*in*/ &curDestination);
    if (!mustTransfer)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN ProcessPacket_Normal_SendMulticast(OVS_NET_BUFFER* pOvsNb)
{
    NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* pMultipleDestinations = NULL;
    OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;
    ULONG mtu = 0;
    UINT portsAdded = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail = NULL;

    pForwardDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pOvsNb->pNbl);

    pMultipleDestinations = FindMultipleDestinations(pOvsNb->pSwitchInfo, pForwardDetail->NumAvailableDestinations,
        pOvsNb->pSourceNic, pOvsNb->pNbl, &failReason, &mtu, &portsAdded);

    //Make sure that the NumDestinations > 0
    if (!pMultipleDestinations || !portsAdded)
    {
        DEBUGP(LOG_ERROR, "find multiple destinations failed. returning FALSE. Fail Reason: %s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    status = pOvsNb->pSwitchInfo->switchHandlers.UpdateNetBufferListDestinations(pOvsNb->pSwitchInfo->switchContext,
        pOvsNb->pNbl, portsAdded, pMultipleDestinations);
    OVS_CHECK(status == NDIS_STATUS_SUCCESS);

    if (status != NDIS_STATUS_SUCCESS)
	{
        return FALSE;
	}

    return TRUE;
}