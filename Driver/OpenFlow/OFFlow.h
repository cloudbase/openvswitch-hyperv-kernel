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
#include "Ethernet.h"
#include "PacketInfo.h"

typedef struct _OVS_CACHE OVS_CACHE;
typedef struct _OVS_DATAPATH OVS_DATAPATH;
typedef struct _OVS_ARGUMENT OVS_ARGUMENT;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_MESSAGE OVS_MESSAGE;

typedef struct _OVS_PI_RANGE {
    SIZE_T startRange;
    SIZE_T endRange;
}OVS_PI_RANGE, *POVS_PI_RANGE;

typedef struct _OVS_FLOW_MASK {
    //a flow mask can be shared by multiple packet info-s (to save disk space)
    int refCount;
    //entry in OVS_FLOW_TABLE
    LIST_ENTRY			listEntry;
    OVS_PI_RANGE		piRange;
    //Value is MASK, i.e. its bytes mean 'exact match' or 'wildcard'
    OVS_OFPACKET_INFO		packetInfo;
}OVS_FLOW_MASK, *POVS_FLOW_MASK;

typedef struct _OVS_FLOW {
    //list entry in OVS_FLOW_TABLE
    LIST_ENTRY			listEntry;

    OVS_OFPACKET_INFO	maskedPacketInfo;
    OVS_OFPACKET_INFO	unmaskedPacketInfo;
    OVS_FLOW_MASK*	pMask;

    OVS_ARGUMENT_GROUP* pActions;

    //locks the values below
    NDIS_SPIN_LOCK	spinLock;

    struct  {
        UINT64 lastUsedTime;
        UINT64 packetsMached;
        UINT64 bytesMatched;
        UINT8 tcpFlags;
    } stats;
}OVS_FLOW, *POVS_FLOW;

//a match is a pair (packet info, mask), with PI range = to apply mask and compare [startRange, endRange]
typedef struct _OVS_FLOW_MATCH {
    OVS_OFPACKET_INFO*		pPacketInfo;
    OVS_FLOW_MASK*			pFlowMask;
    OVS_PI_RANGE			piRange;
}OVS_FLOW_MATCH, *POVS_FLOW_MATCH;

typedef struct _OVS_WINL_FLOW_STATS {
    UINT64 noOfMatchedPackets;
    UINT64 noOfMatchedBytes;
}OVS_WINL_FLOW_STATS, *POVS_WINL_FLOW_STATS;

/*********************************************/

static __inline SIZE_T RoundUp(SIZE_T a, SIZE_T b)
{
    return ((a + (b - 1)) / b) * b;
}

static __inline SIZE_T RoundDown(SIZE_T a, SIZE_T b)
{
    return a - (a % (b));
}

/*********************************** FLOW ***********************************/

OVS_FLOW* Flow_Create();
VOID Flow_Free(OVS_FLOW* pFlow);

static __inline void Flow_ClearStats(OVS_FLOW* pFlow)
{
    pFlow->stats.lastUsedTime = 0;
    pFlow->stats.tcpFlags = 0;
    pFlow->stats.packetsMached = 0;
    pFlow->stats.bytesMatched = 0;
}

void Flow_UpdateTimeUsed(OVS_FLOW* pFlow, OVS_NET_BUFFER* pOvsNb);

/*********************************** FLOW MATCH ***********************************/
void FlowMatch_Initialize(OVS_FLOW_MATCH* pFlowMatch, OVS_OFPACKET_INFO* pPacketInfo, OVS_FLOW_MASK* pFlowMask);

/*********************************** FLOW MASK ***********************************/
VOID FlowMask_DeleteReference(OVS_FLOW_MASK* pFlowMask);
OVS_FLOW_MASK* FlowMask_Create();
BOOLEAN FlowMask_Equal(const OVS_FLOW_MASK* pLhs, const OVS_FLOW_MASK* pRhs);

#if OVS_DBGPRINT_FLOW
void DbgPrintFlow(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end);
void DbgPrintFlowWithActions(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions);
void DbgPrintAllFlows();
void FlowWithActions_ToString(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions, CHAR str[501]);
#endif