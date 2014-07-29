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

typedef struct _OVS_DATAPATH OVS_DATAPATH;
typedef struct _OVS_ARGUMENT OVS_ARGUMENT;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_NET_BUFFER OVS_NET_BUFFER;
typedef struct _OVS_MESSAGE OVS_MESSAGE;
typedef struct _OVS_ACTIONS OVS_ACTIONS;

typedef struct _OVS_PI_RANGE
{
    //TODO: consider using UINT16 instead
    SIZE_T startRange;
    SIZE_T endRange;
}OVS_PI_RANGE, *POVS_PI_RANGE;

typedef struct _OVS_FLOW_MASK
{
    //a flow mask can be shared by multiple packet info-s (to save disk space)
    int refCount;
    //entry in OVS_FLOW_TABLE
    LIST_ENTRY          listEntry;
    OVS_PI_RANGE        piRange;
    //Value is MASK, i.e. its bytes mean 'exact match' or 'wildcard'
    OVS_OFPACKET_INFO   packetInfo;
}OVS_FLOW_MASK, *POVS_FLOW_MASK;

typedef struct _OVS_FLOW_STATS
{
    UINT64 lastUsedTime;
    UINT64 packetsMached;
    UINT64 bytesMatched;
    UINT8  tcpFlags;
}OVS_FLOW_STATS, *POVS_FLOW_STATS;

typedef struct _OVS_FLOW
{
    //must be the first field in the struct
    OVS_REF_COUNT    refCount;

    //lock that protects the flow against modifications
    PNDIS_RW_LOCK_EX pRwLock;

    //list entry in OVS_FLOW_TABLE
    LIST_ENTRY       listEntry;

    //i.e. NUMA node id
    UINT lastStatsWriter;

    //once set, cannot be modified
    OVS_OFPACKET_INFO    maskedPacketInfo;
    //once set, cannot be modified
    OVS_OFPACKET_INFO    unmaskedPacketInfo;
    //once set, cannot be modified, nor the ptr changed
    OVS_FLOW_MASK*    pMask;

    //once set in a flow, the actions can only be replaced, but the struct OVS_ARGUMENT_GROUP itself cannot be modified
    OVS_ACTIONS*      pActions;

    //we should have one stats struct for each NUMA node
    OVS_FLOW_STATS**    statsArray;
}OVS_FLOW, *POVS_FLOW;

#define FLOW_LOCK_READ(pFlow, pLockState) NdisAcquireRWLockRead(pFlow->pRwLock, pLockState, 0)
#define FLOW_LOCK_WRITE(pFlow, pLockState) NdisAcquireRWLockWrite(pFlow->pRwLock, pLockState, 0)
#define FLOW_UNLOCK(pFlow, pLockState) NdisReleaseRWLock(pFlow->pRwLock, pLockState)

//a match is a pair (packet info, mask), with PI range = to apply mask and compare [startRange, endRange]
typedef struct _OVS_FLOW_MATCH
{
    OVS_OFPACKET_INFO       packetInfo;
    OVS_FLOW_MASK           flowMask;
    OVS_PI_RANGE            piRange;
    BOOLEAN                 haveMask;
}OVS_FLOW_MATCH, *POVS_FLOW_MATCH;

typedef struct _OVS_WINL_FLOW_STATS
{
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
VOID Flow_DestroyNow_Unsafe(OVS_FLOW* pFlow);

//NOTE: must lock with pFlow's lock
void Flow_ClearStats_Unsafe(OVS_FLOW* pFlow);

void Flow_UpdateStats_Unsafe(OVS_FLOW* pFlow, OVS_NET_BUFFER* pOvsNb);
void Flow_GetStats_Unsafe(_In_ const OVS_FLOW* pFlow, _Out_ OVS_FLOW_STATS* pFlowStats);

/*********************************** FLOW MATCH ***********************************/
void FlowMatch_Initialize(OVS_FLOW_MATCH* pFlowMatch, BOOLEAN haveMask);

/*********************************** FLOW MASK ***********************************/
VOID FlowMask_DeleteReference(OVS_FLOW_MASK* pFlowMask);
OVS_FLOW_MASK* FlowMask_Create();

BOOLEAN FlowMask_Equal(const OVS_FLOW_MASK* pLhs, const OVS_FLOW_MASK* pRhs);

#if OVS_DBGPRINT_FLOW
void DbgPrintFlow(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask, ULONG start, ULONG end);

void DbgPrintFlowWithActions(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask,
    ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions);

void DbgPrintAllFlows();

void FlowWithActions_ToString(const char* msg, _In_ const OVS_OFPACKET_INFO* pPacketInfo, _In_ const OVS_OFPACKET_INFO* pMask,
    ULONG start, ULONG end, _In_ const OVS_ARGUMENT_GROUP* pActions, _Out_ CHAR str[501]);

#define DBGPRINT_FLOW(logLevel, msg, pFlow) DbgPrintFlow(msg, &(pFlow->unmaskedPacketInfo), &(pFlow->pMask->packetInfo),        \
    (ULONG)pFlow->pMask->piRange.startRange, (ULONG)pFlow->pMask->piRange.endRange)

#define DBGPRINT_FLOWMATCH(logLevel, msg, pFlowMatch) DbgPrintFlow(msg,                                                    \
    (pFlowMatch)->pPacketInfo, (pFlowMatch)->pFlowMask ? &((pFlowMatch)->pFlowMask->packetInfo) : NULL,        \
    (ULONG)(pFlowMatch)->piRange.startRange, (ULONG)(pFlowMatch)->piRange.endRange)

#else
#define DBGPRINT_FLOW(logLevel, msg, pFlow)                DEBUGP(logLevel, msg "\n")
#define DBGPRINT_FLOWMATCH(logLevel, msg, pFlowMatch)    DEBUGP(logLevel, msg "\n")
#endif
