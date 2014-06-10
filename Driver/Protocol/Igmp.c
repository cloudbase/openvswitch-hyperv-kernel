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

#include "Igmp.h"

void DbgPrintIgmpHeader(_In_ const VOID* buffer)
{
    OVS_IGMP_HEADER* pIgmpHeader = (OVS_IGMP_HEADER*)buffer;

    UNREFERENCED_PARAMETER(pIgmpHeader);

    DEBUGP_FRAMES(LOG_INFO, "IGMP: version/type = 0x%x; multicast ip = %d.%d.%d.%d\n", pIgmpHeader->versionType,
        pIgmpHeader->multicastAddress.S_un.S_un_b.s_b1,
        pIgmpHeader->multicastAddress.S_un.S_un_b.s_b2,
        pIgmpHeader->multicastAddress.S_un.S_un_b.s_b3,
        pIgmpHeader->multicastAddress.S_un.S_un_b.s_b4);
}

BOOLEAN VerifyIgmpHeader(BYTE* buffer, ULONG* pLength)
{
    OVS_IGMP_HEADER* pIgmpHeader = (OVS_IGMP_HEADER*)buffer;

    //TODO: we currently do not verify anything
    UNREFERENCED_PARAMETER(pIgmpHeader);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(pLength);

    return TRUE;
}