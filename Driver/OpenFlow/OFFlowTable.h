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

typedef struct _OVS_FLOW OVS_FLOW;
typedef struct _OVS_FLOW_MASK OVS_FLOW_MASK;

typedef struct _OVS_FLOW_TABLE {
    //here we put OVS_FLOW_LIST
    LIST_ENTRY* pFlowList;
    //the OVS_FLOW_MASK-s are enlisted here (i.e. list of shared masks)
    LIST_ENTRY* pMaskList;

    UINT countFlows;
}OVS_FLOW_TABLE, *POVS_FLOW_TABLE;

VOID FlowTable_Destroy(OVS_FLOW_TABLE* pFlowTable);
OVS_FLOW* FlowTable_FindFlowMatchingMaskedPI(OVS_FLOW_TABLE* pFlowTable, const OVS_OFPACKET_INFO* pPacketInfo);
OVS_FLOW_MASK* FlowTable_FindFlowMask(const OVS_FLOW_TABLE* pFlowTable, const OVS_FLOW_MASK* pFlowMask);
void FlowTable_InsertFlowMask(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW_MASK* pFlowMask);
void FlowTable_InsertFlow_Unsafe(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW* pFlow);
void FlowTable_RemoveFlow(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW* pFlow);
OVS_FLOW_TABLE* FlowTable_Create();