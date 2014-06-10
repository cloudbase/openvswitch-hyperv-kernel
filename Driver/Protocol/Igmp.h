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

//RFC 1112 (version 1), updated by 2236 (version 2), updated by 3376 (version 3), updated by 4604

// Define the structure of an IGMPv1/IGMPv2 header.
typedef struct _OVS_IGMP_HEADER {
    union {
        struct {
            //v1:
            //1 = query; 2 = report
            UINT8 type : 4;
            UINT8 version : 4;
        };
        //v2:
        //0x11 = Membership Query
        //0x16 = Version 2 Membership Report
        //0x17 = Leave Group
        //0x12 = Version 1 Membership Report
        UINT8 versionType;
    };
    union {
        // IGMPv1.
        UINT8 reserved;
        // IGMPv2; meaningful only in Membership Query messages = the maximum allowed time before sending a responding report in units of 1/10 second.
        //In all other messages, it is set to zero by the sender and ignored by receivers.
        UINT8 maxRespTime;
        UINT8 code;             // DVMRP.
    };
    UINT16 checksum;
    IN_ADDR multicastAddress;
}OVS_IGMP_HEADER, *POVS_IGMP_HEADER;

//buffer: net buffer starting with the igmp protocol
//dbgprints igmp info
void DbgPrintIgmpHeader(_In_ const VOID* buffer);

BOOLEAN VerifyIgmpHeader(BYTE* buffer, ULONG* pLength);