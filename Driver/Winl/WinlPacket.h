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

typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_UPCALL_INFO OVS_UPCALL_INFO;
typedef struct _OVS_OFPACKET_INFO OVS_OFPACKET_INFO;

VOID Packet_Execute(_In_ OVS_ARGUMENT_GROUP* pArgGroup, const FILE_OBJECT* pFileObject);

BOOLEAN QueuePacketToUserspace(NET_BUFFER* pNb, const OVS_UPCALL_INFO* pUpcallInfo);
