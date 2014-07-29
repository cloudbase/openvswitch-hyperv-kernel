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
#include "Argument.h"
#include "Error.h"

typedef struct _OVS_FLOW OVS_FLOW;
typedef struct _OVS_MESSAGE OVS_MESSAGE;
typedef struct _OVS_OFPACKET_INFO OVS_OFPACKET_INFO;

OVS_ERROR CreateMsgFromFlow(_In_ const OVS_FLOW* pFlow, const OVS_MESSAGE* pInMsg, _Out_ OVS_MESSAGE* pOutMsg, UINT8 command);

//if you don't have a mask => pMask == NULL
//if you do have a mask, pPacketInfo is the masked key, while pMask is the "key" of the mask
OVS_ARGUMENT* CreateArgFromPacketInfo(const OVS_OFPACKET_INFO* pPacketInfo, const OVS_OFPACKET_INFO* pMask, UINT16 groupType);
