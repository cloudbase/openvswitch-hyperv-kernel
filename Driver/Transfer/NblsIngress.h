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

#include "Sctx_Nic.h"

typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;
typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;
typedef struct _OVS_ETHERNET_HEADER OVS_ETHERNET_HEADER;

/*doc: Packets arrive at the extensible switch from network adapters that are connected to the switch ports.
These packets are first issued as send requests from the protocol edge of the extensible switch down the extensible switch driver stack.
This is known as the extensible switch ingress data path.*/

/* On receipt of: NBL on ingress
** must call _Nbls_SendIngress to continue the send of the NBL on ingress.
** may also be called from egress to inject an NBL.*/
//CALLED BY NdisFilter/FilterSendNetBufferLists
VOID Nbls_SendIngress(_In_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NDIS_HANDLE extensionContext, _In_ NET_BUFFER_LIST* pNetBufferLists,
    _In_ ULONG sendFlags);

VOID Nbls_CompletedInjected(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, ULONG numInjectedNetBufferLists);

typedef enum _OVS_NBL_FAIL_REASON
{
    OVS_NBL_FAIL_SUCCESS, //corresponds to NDIS_STATUS_SUCCESS,
    //The size of the data in some NET_BUFFER structures associated with this NET_BUFFER_LIST structure was too large for the underlying NIC.
    OVS_NBL_FAIL_LENGTH, //corresponds to NDIS_STATUS_INVALID_LENGTH,
    //insufficient resources
    OVS_NBL_FAIL_RESOURCES, //corresponds to NDIS_STATUS_RESOURCES,
    //This send request for this NET_BUFFER_LIST structure failed due to some reason other than those stated in the previous three values.
    OVS_NBL_FAIL_UNKNOWN, //corresponds to NDIS_STATUS_FAILURE,
    //NDIS called the MiniportCancelSend function to cancel the send operation for this NET_BUFFER_LIST structure.
    OVS_NBL_FAIL_SEND_ABORTED, //corresponds to NDIS_STATUS_SEND_ABORTED,
    //The miniport driver aborted the send request due to a reset.
    OVS_NBL_FAIL_RESET_IN_PROGRESS, //corresponds to NDIS_STATUS_RESET_IN_PROGRESS,
    //If a driver must reject send requests because it is paused, it sets the complete status in each affected NET_BUFFER_LIST to NDIS_STATUS_PAUSED.
    //It seems it's driver paused, not vSwitch paused.
    OVS_NBL_FAIL_PAUSED, //corresponds to NDIS_STATUS_PAUSED //I hope it fully corresponds to this
    //Blocked by Source MAC Policy == !sourceNicEntry->allowSends
    OVS_NBL_FAIL_SOURCE_NIC_DENY_SENDS,
    //did not find source nic entry
    OVS_NBL_FAIL_SOURCE_NIC_NOT_FOUND,
    //Failed to grow destination list
    OVS_NBL_FAIL_CANNOT_GROW_DEST,
    //the fwd sample said "No external NIC" for "switchContext->externalPortId == 0"
    OVS_NBL_FAIL_NO_EXTERNAL_PORT,
    OVS_NBL_FAIL_DESTINATION_IS_SOURCE,
    //destination nic
    OVS_NBL_FAIL_DESTINATION_NOT_CONNECTED,
    OVS_NBL_FAIL_CLONING_FAILED
}OVS_NBL_FAIL_REASON, *POVS_NBL_FAIL_REASON;

#define __OVS_NBL_FAIL_SUCCESS_MESSAGE                        "Success"
#define __OVS_NBL_FAIL_LENGTH_MESSAGE                         "Invalid NBL length for NIC"
#define __OVS_NBL_FAIL_RESOURCES_MESSAGE                      "Insufficient resources"
#define __OVS_NBL_FAIL_UNKNOWN_MESSAGE                        "Unknown reason"
#define __OVS_NBL_FAIL_SEND_ABORTED_MESSAGE                   "Send aborted by miniport"
#define __OVS_NBL_FAIL_RESET_IN_PROGRESS_MESSAGE              "Reset in progress"
#define __OVS_NBL_FAIL_PAUSED_MESSAGE                         "Driver/Extension is paused"
#define __OVS_NBL_FAIL_SOURCE_NIC_DENY_SENDS_MESSAGE          "Source NIC does not allow sends"
#define __OVS_NBL_FAIL_SOURCE_NIC_NOT_FOUND                   "Source NIC was not found."
#define __OVS_NBL_FAIL_CANNOT_GROW_DEST_MESSAGE               "Failed to grow destination list"
#define __OVS_NBL_FAIL_NO_EXTERNAL_PORT_MESSAGE               "Have no external port / nic"
#define __OVS_NBL_FAIL_DESTINATION_IS_SOURCE_MESSAGE          "Destination port = Source port"
#define __OVS_NBL_FAIL_DESTINATION_NOT_CONNECTED_MESSAGE      "Destination NIC is not connected"
#define __OVS_NBL_FAIL_CLONING_FAILED_MESSAGE                 "could not clone NBL."
#define __OVS_NBL_FAIL_INVALID_MESSAGE                        "<invalid msg>"

#define __OVS_TO_UNICODE(x) L##x
#define OVS_TO_UNICODE(x) __OVS_TO_UNICODE(x)
#define __OVS_STR_SAME(x) x

#define __FailReasonMessageBody(reason, T) {                                                                \
    switch (reason)                                                                                         \
    {                                                                                                       \
    case OVS_NBL_FAIL_SUCCESS: return T(__OVS_NBL_FAIL_SUCCESS_MESSAGE);                                    \
    case OVS_NBL_FAIL_LENGTH: return T(__OVS_NBL_FAIL_LENGTH_MESSAGE);                                      \
    case OVS_NBL_FAIL_RESOURCES: return T(__OVS_NBL_FAIL_RESOURCES_MESSAGE);                                \
    case OVS_NBL_FAIL_UNKNOWN: return T(__OVS_NBL_FAIL_UNKNOWN_MESSAGE);                                    \
    case OVS_NBL_FAIL_SEND_ABORTED: return T(__OVS_NBL_FAIL_SEND_ABORTED_MESSAGE);                          \
    case OVS_NBL_FAIL_RESET_IN_PROGRESS: return T(__OVS_NBL_FAIL_RESET_IN_PROGRESS_MESSAGE);                \
    case OVS_NBL_FAIL_PAUSED: return T(__OVS_NBL_FAIL_PAUSED_MESSAGE);                                      \
    case OVS_NBL_FAIL_SOURCE_NIC_DENY_SENDS: return T(__OVS_NBL_FAIL_SOURCE_NIC_DENY_SENDS_MESSAGE);        \
    case OVS_NBL_FAIL_SOURCE_NIC_NOT_FOUND: return T(__OVS_NBL_FAIL_SOURCE_NIC_NOT_FOUND);                  \
    case OVS_NBL_FAIL_CANNOT_GROW_DEST: return T(__OVS_NBL_FAIL_CANNOT_GROW_DEST_MESSAGE);                  \
    case OVS_NBL_FAIL_NO_EXTERNAL_PORT: return T(__OVS_NBL_FAIL_NO_EXTERNAL_PORT_MESSAGE);                  \
    case OVS_NBL_FAIL_DESTINATION_IS_SOURCE: return T(__OVS_NBL_FAIL_DESTINATION_IS_SOURCE_MESSAGE);        \
    case OVS_NBL_FAIL_DESTINATION_NOT_CONNECTED: return T(__OVS_NBL_FAIL_DESTINATION_NOT_CONNECTED_MESSAGE);\
    case OVS_NBL_FAIL_CLONING_FAILED: return T(__OVS_NBL_FAIL_CLONING_FAILED_MESSAGE);                      \
                                                                                                            \
    default:                                                                                                \
        OVS_CHECK(0);                                                                                       \
        return T(__OVS_NBL_FAIL_INVALID_MESSAGE);                                                           \
        }                                                                                                   \
    }

__inline LPCWSTR FailReasonMessageW(OVS_NBL_FAIL_REASON failReason)
{
    __FailReasonMessageBody(failReason, OVS_TO_UNICODE);
}

__inline LPCSTR FailReasonMessageA(OVS_NBL_FAIL_REASON failReason)
{
    __FailReasonMessageBody(failReason, __OVS_STR_SAME);
}

#define FailReasonMessage(x) FailReasonMessageW(x)

__inline NDIS_STATUS NblFailReasonToNdisStatus(OVS_NBL_FAIL_REASON reason)
{
    switch (reason)
    {
    case OVS_NBL_FAIL_SUCCESS: return NDIS_STATUS_SUCCESS;
    case OVS_NBL_FAIL_LENGTH: return NDIS_STATUS_INVALID_LENGTH;
    case OVS_NBL_FAIL_RESOURCES: return NDIS_STATUS_RESOURCES;
    case OVS_NBL_FAIL_UNKNOWN: return NDIS_STATUS_FAILURE;
    case OVS_NBL_FAIL_SEND_ABORTED: return NDIS_STATUS_SEND_ABORTED;
    case OVS_NBL_FAIL_RESET_IN_PROGRESS: return NDIS_STATUS_RESET_IN_PROGRESS;
    case OVS_NBL_FAIL_PAUSED: return NDIS_STATUS_PAUSED;
    default: return NDIS_STATUS_FAILURE;
    }
}

BOOLEAN GetDestinationInfo(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_reads_bytes_(6) const BYTE* pDestMac, _In_ NDIS_SWITCH_PORT_ID sourcePort,
    _Out_ OVS_NIC_INFO* pCurDestination, _Inout_ OVS_NBL_FAIL_REASON* pFailReason);

BOOLEAN SetOneDestination(_In_ const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl, _Out_ OVS_NBL_FAIL_REASON* pFailReason, NDIS_SWITCH_PORT_ID portId,
    NDIS_SWITCH_NIC_INDEX nicIndex);

__inline BOOLEAN DestinationEqual(_In_ const OVS_NIC_INFO* pLhs, _In_ const OVS_NIC_INFO* pRhs)
{
    return pLhs->nicIndex == pRhs->nicIndex && pLhs->portId == pRhs->portId;
}

NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* FindMultipleDestinations(_In_ const OVS_SWITCH_INFO* pSwitchInfo, UINT32 availableDestinations,
    _In_ const OVS_OFPORT* pSourcePort, _Inout_ NET_BUFFER_LIST* pNbl, _Inout_ OVS_NBL_FAIL_REASON* pFailReason, _Inout_ ULONG* pMtu, _Inout_ UINT* pCountAdded);

BOOLEAN GetExternalDestinationInfo(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NDIS_SWITCH_PORT_ID sourcePort,
    _Inout_ OVS_NIC_INFO* pCurDestination, _Inout_ OVS_NBL_FAIL_REASON* pFailReason);

BOOLEAN OutputPacketToPort(_Inout_ OVS_NET_BUFFER* pOvsNb);