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
#include "NblsEgress.h"
#include "Gre.h"
#include "Frame.h"
#include "Nbls.h"
#include "NblsIngress.h"
#include "SendIngressBasic.h"

extern LIST_ENTRY g_egressNblList;
extern NDIS_SPIN_LOCK g_egressNblListLock;

static VOID _DropSingleSourceEgress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, ULONG numberOfNetBufferLists,
    _In_ const NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail, _In_ NDIS_STRING filterReason, ULONG returnFlags)
{
    NDIS_SWITCH_PORT_ID sourcePortId = pForwardDetail->SourcePortId;

    pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
        sourcePortId, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
        numberOfNetBufferLists, pNetBufferLists, &filterReason);

    Nbls_CompleteEgress(pSwitchInfo, pSwitchInfo->pForwardInfo, pNetBufferLists, returnFlags);
}

//NOTE: this function does almost the same work as SendIngressBasic./_DropAll_MultipleSourcesIngress(...)
//(i.e. except that it calls Nbls_CompleteEgress). TODO: We must refactor.
static VOID _DropMultipleSourcesEgress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists,
    _In_ const NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail, NDIS_STRING filterReason, ULONG returnFlags)
{
    NDIS_SWITCH_PORT_ID curSourcePort = pForwardDetail->SourcePortId;
    ULONG numNbls = 0;
    NET_BUFFER_LIST* pCurNbl = NULL, *pNextNbl = NULL;
    NET_BUFFER_LIST* pDropNbl = NULL;
    NET_BUFFER_LIST** ppCurDropNbl = &pDropNbl;

    for (pCurNbl = pNetBufferLists; pCurNbl != NULL; pCurNbl = pNextNbl)
    {
        pNextNbl = NET_BUFFER_LIST_NEXT_NBL(pCurNbl);
        NET_BUFFER_LIST_NEXT_NBL(pCurNbl) = NULL;

        pForwardDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pCurNbl);

        //the first time it will be true.
        if (curSourcePort == pForwardDetail->SourcePortId)
        {
            *ppCurDropNbl = pCurNbl;
            ppCurDropNbl = &(NET_BUFFER_LIST_NEXT_NBL(pCurNbl));
            ++numNbls;
        }

        //if source port of pNetBufferLists != source port of pCurNbl => drop?
        else
        {
            OVS_CHECK(pDropNbl);
            OVS_CHECK(numNbls > 0);

            pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
                curSourcePort, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
                numNbls, pDropNbl, &filterReason);

            /*fwd ext here*/
            Nbls_CompleteEgress(pSwitchInfo, pSwitchInfo->pForwardInfo, pDropNbl, returnFlags);

            numNbls = 1;
            pDropNbl = pCurNbl;
            ppCurDropNbl = &(NET_BUFFER_LIST_NEXT_NBL(pCurNbl));
            curSourcePort = pForwardDetail->SourcePortId;
        }
    }

    //either way drop? (if paused)
    pSwitchInfo->switchHandlers.ReportFilteredNetBufferLists(pSwitchInfo->switchContext, &g_extensionGuid, &g_extensionFriendlyName,
        curSourcePort, NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
        numNbls, pDropNbl, &filterReason);

    Nbls_CompleteEgress(pSwitchInfo, pSwitchInfo->pForwardInfo, pDropNbl, returnFlags);
}

static VOID Nbls_DropAllEgress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, _In_ ULONG numberOfNetBufferLists,
    _In_ BOOLEAN dispatch, _In_ BOOLEAN sameSource)
{
    NDIS_STRING filterReason = { 0 };
    ULONG returnFlags = 0;
    NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail = NULL;

    RtlInitUnicodeString(&filterReason, L"Extension Paused");

    returnFlags = (dispatch) ? NDIS_RETURN_FLAGS_DISPATCH_LEVEL : 0;
    returnFlags |= NDIS_RETURN_FLAGS_SWITCH_SINGLE_SOURCE;

    pForwardDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNetBufferLists);

    //if NDIS_RECEIVE_FLAGS_SWITCH_SINGLE_SOURCE (when extension paused)=> drop. why?
    if (sameSource)
    {
        _DropSingleSourceEgress(pSwitchInfo, pNetBufferLists, numberOfNetBufferLists, pForwardDetail, filterReason, returnFlags);
    }

    //not NDIS_RECEIVE_FLAGS_SWITCH_SINGLE_SOURCE
    else
    {
        _DropMultipleSourcesEgress(pSwitchInfo, pNetBufferLists, pForwardDetail, filterReason, returnFlags);
    }
}

static VOID _Nbls_StartEgress(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, ULONG numberOfNetBufferLists, ULONG receiveFlags)
{
    BOOLEAN dispatch = FALSE, sameSource = FALSE;

    dispatch = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(receiveFlags);
    sameSource = NDIS_TEST_RECEIVE_FLAG(receiveFlags, NDIS_RECEIVE_FLAGS_SWITCH_SINGLE_SOURCE);

    if (pSwitchInfo->dataFlowState != OVS_SWITCH_RUNNING)
    {
        Nbls_DropAllEgress(pSwitchInfo, pNetBufferLists, numberOfNetBufferLists, dispatch, sameSource);
        return;
    }

    NdisFIndicateReceiveNetBufferLists(pSwitchInfo->filterHandle, pNetBufferLists, NDIS_DEFAULT_PORT_NUMBER, numberOfNetBufferLists, receiveFlags);
}

static ULONG _CalcReturnFlags(ULONG receiveFlags)
{
    BOOLEAN dispatch = FALSE, sameSource = FALSE;
    ULONG returnFlags = 0;

    dispatch = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(receiveFlags);
    sameSource = NDIS_TEST_RECEIVE_FLAG(receiveFlags, NDIS_RECEIVE_FLAGS_SWITCH_SINGLE_SOURCE);

    returnFlags = (dispatch) ? NDIS_RETURN_FLAGS_DISPATCH_LEVEL : 0;
    returnFlags |= NDIS_RETURN_FLAGS_SWITCH_SINGLE_SOURCE;

    return returnFlags;
}

_Use_decl_annotations_
VOID Nbls_StartEgress(const OVS_SWITCH_INFO* pSwitchInfo, NDIS_HANDLE extensionContext, NET_BUFFER_LIST* pNetBufferLists,
ULONG numberOfNetBufferLists, ULONG receiveFlags)
{
    UNREFERENCED_PARAMETER(numberOfNetBufferLists);
    UNREFERENCED_PARAMETER(extensionContext);

    _Nbls_StartEgress(pSwitchInfo, pNetBufferLists, numberOfNetBufferLists, receiveFlags);
}

_Use_decl_annotations_
VOID Nbls_CompleteEgress(const OVS_SWITCH_INFO* pSwitchInfo, NDIS_HANDLE extensionContext, NET_BUFFER_LIST* pNetBufferLists, ULONG returnFlags)
{
    UNREFERENCED_PARAMETER(extensionContext);

    NdisFReturnNetBufferLists(pSwitchInfo->filterHandle, pNetBufferLists, returnFlags);
}