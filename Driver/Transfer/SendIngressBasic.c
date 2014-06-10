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
#include "Frame.h"
#include "NblsIngress.h"
#include "SendIngressBasic.h"
#include "Nbls.h"

_Use_decl_annotations_
VOID Nbls_DropOneIngress(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl, ULONG sourcePortId, ULONG completeFlags, OVS_NBL_FAIL_REASON failReason)
{
    NDIS_STRING filterReason = { 0 };
    LPCWSTR wsFailReasonMsg = FailReasonMessage(failReason);

    RtlInitUnicodeString(&filterReason, wsFailReasonMsg);

    if (failReason != NDIS_STATUS_SUCCESS)
    {
        pNbl->Status = (NDIS_STATUS)failReason;
    }

    pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
        sourcePortId, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
        1, pNbl, &filterReason);

    Nbls_CompleteIngress(pSwitchInfo, pNbl, completeFlags);
}

static VOID _DropAll_SingleSourceIngress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists,
    _In_ UINT16 sourcePortId, _In_ OVS_NBL_FAIL_REASON failReason, _In_ ULONG sendCompleteFlags)
{
    PNET_BUFFER_LIST pNbl = NULL;
    ULONG numNbls = 0;

    NDIS_STRING filterReason = { 0 };
    LPCWSTR wsFailReasonMsg = FailReasonMessage(failReason);

    RtlInitUnicodeString(&filterReason, wsFailReasonMsg);

    //TODO: if we have a fail reason, should we specify it at drop?
    for (pNbl = pNetBufferLists; pNbl != NULL; pNbl = NET_BUFFER_LIST_NEXT_NBL(pNbl))
    {
        //currently, OVS_NBL_FAIL_REASON matches exactly the NDIS_STATUS
        if (failReason != NDIS_STATUS_SUCCESS)
        {
            pNbl->Status = (NDIS_STATUS)failReason;
        }

        ++numNbls;
    }

    //all come from the same source port, fwdDetail->SourcePortId
    pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
        sourcePortId, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
        numNbls, pNetBufferLists, &filterReason);

    Nbls_CompleteIngress(pSwitchInfo, pNetBufferLists, sendCompleteFlags);
}

static VOID _DropAll_MultipleSourcesIngress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists,
    _In_ NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail, _In_ OVS_NBL_FAIL_REASON failReason, _In_ ULONG sendCompleteFlags)
{
    NDIS_SWITCH_PORT_ID groupSourcePort = 0;
    PNET_BUFFER_LIST pNbl = NULL, pNextNbl = NULL;
    //first in group
    NET_BUFFER_LIST* pFirstNbl = NULL, *pPrevNbl = NULL;
    ULONG numNbls = 0;
    NDIS_STRING filterReason = { 0 };
    LPCWSTR wsFailReasonMsg = FailReasonMessage(failReason);

    RtlInitUnicodeString(&filterReason, wsFailReasonMsg);

    groupSourcePort = pForwardDetail->SourcePortId;
    for (pNbl = pNetBufferLists; pNbl != NULL; pNbl = pNextNbl)
    {
        pNextNbl = NET_BUFFER_LIST_NEXT_NBL(pNbl);
        NET_BUFFER_LIST_NEXT_NBL(pNbl) = NULL;

        //currently, OVS_NBL_FAIL_REASON matches exactly the NDIS_STATUS
        if (failReason != NDIS_STATUS_SUCCESS)
        {
            pNbl->Status = (NDIS_STATUS)failReason;
        }

        pForwardDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);

        //the first time it's true. we've got source ports like this:
        //all nbls:
        //NBL-NBL-NBL-NBL-NBL-NBL
        //p0  p0  p0  p2  p2  p1
        //we need to send in groups of (from above example): 3 NBLs (source port 0), 2 NBLs (source port 2), 1 NBLs (source port 1)
        //we Nbls_CompleteIngress only when:
        //a) we meet a different source port
        //b) we finished looping over all NBLs
        //pFirstNbl will always be first NBL in the group of numNbls.
        if (groupSourcePort == pForwardDetail->SourcePortId)
        {
            //only the first time in the loop it will be true
            if (!pFirstNbl)
            {
                pFirstNbl = pNbl;
            }
            else
            {
                OVS_CHECK(pPrevNbl);
                NET_BUFFER_LIST_NEXT_NBL(pPrevNbl) = pNbl;
            }

            ++numNbls;
        }
        else
        {
            //finished a group, i.e. source port has changed
            //at this point, pFirstNbl is != NULL
            OVS_CHECK(pFirstNbl);
            OVS_CHECK(numNbls);

            pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
                groupSourcePort, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
                numNbls, pFirstNbl, &filterReason);

            Nbls_CompleteIngress(pSwitchInfo, pFirstNbl, sendCompleteFlags);

            //set the new group: first = pNbl, num so far = 1 (pNbl), sourcePort of the group.
            numNbls = 1;
            pFirstNbl = pNbl;
            groupSourcePort = pForwardDetail->SourcePortId;
        }

        //to link later.
        pPrevNbl = pNbl;
    }

    pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
        groupSourcePort, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
        numNbls, pFirstNbl, &filterReason);

    Nbls_CompleteIngress(pSwitchInfo, pFirstNbl, sendCompleteFlags);
}

ULONG CalcSendCompleteFlags(ULONG sendFlags)
{
    ULONG sendCompleteFlags = 0;

    if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(sendFlags))
    {
        sendCompleteFlags = NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    if (NDIS_TEST_SEND_FLAG(sendFlags, NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE))
    {
        sendCompleteFlags |= NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE;
    }

    return sendCompleteFlags;
}

_Use_decl_annotations_
VOID Nbls_DropAllIngress(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNetBufferLists, ULONG completeFlags, OVS_NBL_FAIL_REASON failReason)
{
    NDIS_STRING filterReason = { 0 };
    BOOLEAN singleSource = FALSE;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail = NULL;
    LPCWSTR wsFailReasonMsg = FailReasonMessage(failReason);

    //SendComplete relevant flags:
    //NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL
    //NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE

    RtlInitUnicodeString(&filterReason, wsFailReasonMsg);
    fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNetBufferLists);

    singleSource = NDIS_TEST_SEND_COMPLETE_FLAG(completeFlags, NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
    if (singleSource)
    {
        _DropAll_SingleSourceIngress(pSwitchInfo, pNetBufferLists, (UINT16)fwdDetail->SourcePortId, failReason, completeFlags);
    }
    else
    {
        _DropAll_MultipleSourcesIngress(pSwitchInfo, pNetBufferLists, fwdDetail, failReason, completeFlags);
    }
}

_Use_decl_annotations_
VOID Nbls_SendIngressBasic(OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNetBufferLists, ULONG sendFlags, ULONG numInjectedNetBufferLists)
{
    BOOLEAN dispatch = FALSE;
    BOOLEAN sameSource = FALSE;
    ULONG sendCompleteFlags = 0;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail = NULL;
    OVS_NBL_FAIL_REASON failReason = { 0 };

    dispatch = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(sendFlags);
    sameSource = NDIS_TEST_SEND_FLAG(sendFlags, NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE);

    InterlockedAdd(&pSwitchInfo->pendingInjectedNblCount, numInjectedNetBufferLists);
    KeMemoryBarrier();

    if (pSwitchInfo->dataFlowState != OVS_SWITCH_RUNNING)
    {
        failReason = OVS_NBL_FAIL_PAUSED;

        sendCompleteFlags = (dispatch) ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0;
        sendCompleteFlags |= (sameSource) ? NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE : 0;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNetBufferLists);

        if (sameSource)
        {
            _DropAll_SingleSourceIngress(pSwitchInfo, pNetBufferLists, (UINT16)fwdDetail->SourcePortId, failReason, sendCompleteFlags);
        }
        else
        {
            _DropAll_MultipleSourcesIngress(pSwitchInfo, pNetBufferLists, fwdDetail, failReason, sendCompleteFlags);
        }

        goto Cleanup;
    }

    NdisFSendNetBufferLists(pSwitchInfo->filterHandle, pNetBufferLists, NDIS_DEFAULT_PORT_NUMBER, sendFlags);

Cleanup:
    return;
}

_Use_decl_annotations_
VOID Nbls_CompleteIngress(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNetBufferLists, ULONG sendCompleteFlags)
{
    NdisFSendNetBufferListsComplete(pSwitchInfo->filterHandle, pNetBufferLists, sendCompleteFlags);
}