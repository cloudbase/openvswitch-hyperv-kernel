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

#include "precomp.h"

typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;

typedef struct _FILTER_DEVICE_EXTENSION
{
    ULONG            signature;
    NDIS_HANDLE      handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS InitializeDevice(PDRIVER_OBJECT, PUNICODE_STRING);
DRIVER_UNLOAD FilterUnload;

FILTER_SET_OPTIONS FilterSetOptions;
FILTER_SET_MODULE_OPTIONS FilterSetModuleOptions;
FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
FILTER_PAUSE FilterPause;
FILTER_RESTART FilterRestart;
FILTER_OID_REQUEST FilterOidRequest;
FILTER_CANCEL_OID_REQUEST FilterCancelOidRequest;
FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;
FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;
FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;
FILTER_RECEIVE_NET_BUFFER_LISTS FilterReceiveNetBufferLists;
FILTER_CANCEL_SEND_NET_BUFFER_LISTS FilterCancelSendNetBufferLists;
FILTER_STATUS FilterStatus;
FILTER_NET_PNP_EVENT FilterNetPnPEvent;