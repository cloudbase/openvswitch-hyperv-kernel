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

typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;

BOOLEAN ProcessPacket_Normal_SendUnicast(_Inout_ OVS_NET_BUFFER* pOvsNb, _In_reads_bytes_(6) const BYTE* destMac);
BOOLEAN ProcessPacket_Normal_SendMulticast(_Inout_ OVS_NET_BUFFER* pOvsNb);