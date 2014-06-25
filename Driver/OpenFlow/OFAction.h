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
#include "Types.h"
#include "OFFlow.h"

typedef struct _OVS_DATAPATH OVS_DATAPATH, *POVS_DATAPATH;
typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;
typedef struct _OVS_NIC_INFO OVS_NIC_INFO;

typedef struct _OVS_ACTIONS {
	//must be the first field in the struct
	OVS_REF_COUNT refCount;

	//once set, it cannot be modified. Also, the pointer cannot be changed, unless the OVS_ACTIONS struct is destroyed
	OVS_ARGUMENT_GROUP* pActionGroup;
} OVS_ACTIONS, *POVS_ACTIONS;

typedef struct _OVS_ACTION_PUSH_VLAN {
    //usually / normally OVS_ETHERTYPE_QTAG
    BE16 protocol;
    //802.1Q TCI (user priority + cfi + vlan id).
    BE16 vlanTci;
} OVS_ACTION_PUSH_VLAN;

/**********************************************/

typedef BOOLEAN(*OutputToPortCallback)(_Inout_ OVS_NET_BUFFER* pOvsNb);

BOOLEAN ExecuteActions(_Inout_ OVS_NET_BUFFER* pOvsNb, _In_ const OutputToPortCallback outputToPort);

BOOLEAN ProcessReceivedActions(_Inout_ OVS_ARGUMENT_GROUP* pActionGroup, const OVS_OFPACKET_INFO* pPacketInfo, int recursivityDepth);

OVS_ACTIONS* Actions_Create();
VOID Actions_DestroyNow_Unsafe(_Inout_ OVS_ACTIONS* pActions);