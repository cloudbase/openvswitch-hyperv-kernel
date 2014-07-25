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

#include "Argument.h"
#include "WinlFlow.h"
#include "ArgumentType.h"
#include "OFFlow.h"
#include "PacketInfo.h"
#include "OFAction.h"
#include "OFPort.h"
#include "OFDatapath.h"
#include "OFPort.h"
#include "Message.h"
#include "Ipv4.h"
#include "OFPort.h"
#include "Icmp.h"
#include "Ipv6.h"
#include "PersistentPort.h"

#include <Ntstrsafe.h>

/******************************************* ARG SIZE FUNCTIONS **********************************************************************/

#define __SIZE_CASE_ARGTYPE(argType, size)      \
case argType:                                   \
    *pSize = size;                              \
    return TRUE;                                \

#define __SIZE_CASE_ARGTYPE_TYPE(argType, type) \
case argType:                                   \
    *pSize = sizeof(type);                      \
    return TRUE;                                \

BOOLEAN GetArgumentExpectedSize(OVS_ARGTYPE argumentType, _Inout_ UINT* pSize)
{
    if (IsArgTypeGroup(argumentType))
    {
        *pSize = MAXUINT;
        return TRUE;
    }

    switch (argumentType)
    {
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_FLOW_STATS, OVS_WINL_FLOW_STATS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_FLOW_TCP_FLAGS, UINT8);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_FLOW_TIME_USED, UINT64);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_CLEAR, 0);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_PACKET_PRIORITY, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_DP_INPUT_PORT, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_ETH_ADDRESS, OVS_PI_ETH_ADDRESS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_ETH_TYPE, UINT16);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_VLAN_TCI, BE16);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_IPV4, OVS_PI_IPV4);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_IPV6, OVS_PI_IPV6);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TCP, OVS_PI_TCP);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TCP_FLAGS, BE16);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_UDP, OVS_PI_UDP);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_SCTP, OVS_PI_SCTP);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_ICMP, OVS_PI_ICMP);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_ICMP6, OVS_PI_ICMP6);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_ARP, OVS_PI_ARP);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY, OVS_PI_NEIGHBOR_DISCOVERY);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_PACKET_MARK, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_IPV4_TUNNEL, OF_PI_IPV4_TUNNEL);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_MPLS, OVS_PI_MPLS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_DATAPATH_HASH, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID, UINT32);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TUNNEL_ID, BE64);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC, BE32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST, BE32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TUNNEL_TOS, UINT8);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_PI_TUNNEL_TTL, UINT8);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT, 0);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM, 0);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_OAM, 0);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_GENEVE_OPTIONS, MAXUINT);

        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_BUFFER, MAXUINT);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_USERDATA, MAXUINT);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_PUSH_VLAN, OVS_ACTION_PUSH_VLAN);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_POP_VLAN, 0);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_PUSH_MPLS, OVS_ACTION_PUSH_MPLS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_POP_MPLS, BE16);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_RECIRCULATION, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_HASH, OVS_ACTION_FLOW_HASH);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_UPCALL_PORT_ID, UINT32);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_UPCALL_DATA, MAXUINT);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY, UINT32);

        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_NAME, MAXUINT);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_DATAPATH_STATS, OVS_DATAPATH_STATS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_DATAPATH_MEGAFLOW_STATS, OVS_DATAPATH_MEGAFLOW_STATS);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_DATAPATH_USER_FEATURES, UINT32);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_OFPORT_NUMBER, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_OFPORT_TYPE, UINT32);
        __SIZE_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_NAME, MAXUINT);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, UINT32);
        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_OFPORT_STATS, OVS_OFPORT_STATS);

        __SIZE_CASE_ARGTYPE_TYPE(OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, UINT16);

    default:
        OVS_CHECK(__UNEXPECTED__);
        return FALSE;
    }
}

/******************************************* FIND FUNCTIONS **********************************************************************/

OVS_ARGUMENT* FindArgument(_In_ const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE argumentType)
{
    OVS_CHECK(pArgGroup);

    for (UINT32 i = 0; i < pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgGroup->args + i;

        if (!pArg->isDisabled && pArg->type == (UINT32)argumentType)
        {
            return pArg;
        }
    }

    return NULL;
}

OVS_ARGUMENT_GROUP* FindArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE groupType)
{
    OVS_CHECK(pArgGroup);

    for (UINT32 i = 0; i < pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgGroup->args + i;

        if (!pArg->isDisabled && IsArgTypeGroup(pArg->type))
        {
            OVS_ARGUMENT_GROUP* pNestedArgGroup = pArg->data;

            if (pArg->type == (UINT32)groupType)
            {
                return pNestedArgGroup;
            }
        }
    }

    return NULL;
}

OVS_ARGUMENT* FindArgumentGroupAsArg(_In_ OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE groupType)
{
    OVS_CHECK(pArgGroup);

    for (UINT32 i = 0; i < pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pArgGroup->args + i;

        if (!pArg->isDisabled && IsArgTypeGroup(pArg->type))
        {
            if (pArg->type == (UINT32)groupType)
            {
                return pArg;
            }
        }
    }

    return NULL;
}

/******************************************* ALLOC & FREE FUNCTIONS **********************************************************************/

BOOLEAN AllocateArgumentsToGroup(UINT16 count, _Out_ OVS_ARGUMENT_GROUP* pGroup)
{
    OVS_CHECK(pGroup);

    pGroup->count = count;
    pGroup->groupSize = (UINT16)(count * OVS_ARGUMENT_HEADER_SIZE);

    if (count > 0)
    {
        pGroup->args = KAlloc(count * sizeof(OVS_ARGUMENT));
        if (!pGroup->args)
        {
            return FALSE;
        }
    }
    else
    {
        pGroup->args = NULL;
    }

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        pGroup->args[i].data = NULL;
        pGroup->args[i].type = OVS_ARGTYPE_INVALID;
        pGroup->args[i].length = 0;
        pGroup->args[i].isDisabled = FALSE;
        pGroup->args[i].isNested = FALSE;
        pGroup->args[i].freeData = FALSE;
    }

    return TRUE;
}

/******************************************* CREATION & DESTRUCTION FUNCTIONS **********************************************************************/

OVS_ARGUMENT* CreateArgument(OVS_ARGTYPE argType, const VOID* buffer)
{
    OVS_ARGUMENT* pArg = NULL;
    UINT expectedSize = 0;

    pArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pArg)
    {
        return NULL;
    }

    DEBUGP_ARG(LOG_INFO, "Created argument: %p; type=%u\n", pArg, argType);
    DBGPRINT_ARGTYPE(LOG_INFO, argType, "", 0);

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = FALSE;

    if (!GetArgumentExpectedSize(argType, &expectedSize))
    {
        return NULL;
    }

    if (expectedSize == MAXUINT)
    {
        return NULL;
    }

    OVS_CHECK(expectedSize <= MAXUINT16);

    pArg->length = (UINT16)expectedSize;
    pArg->data = (VOID*)buffer;

    return pArg;
}

OVS_ARGUMENT* CreateArgumentWithSize(OVS_ARGTYPE argType, const VOID* buffer, ULONG size)
{
    OVS_ARGUMENT* pArg = NULL;
    UINT expectedSize = 0;

    OVS_CHECK(size > 0);
    OVS_CHECK(size <= MAXUINT);

    pArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pArg)
    {
        return NULL;
    }

    DEBUGP_ARG(LOG_INFO, "Created argument: %p; type=%u\n", pArg, argType);
    DBGPRINT_ARGTYPE(LOG_INFO, argType, "", 0);

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = FALSE;

    if (!GetArgumentExpectedSize(argType, &expectedSize))
    {
        return NULL;
    }

    if (expectedSize != MAXUINT)
    {
        DEBUGP_ARG(LOG_ERROR, "Create arg with size should only be used with var-sized args!");
        return NULL;
    }

    pArg->length = (UINT16)size;
    pArg->data = (VOID*)buffer;

    return pArg;
}

OVS_ARGUMENT* CreateArgument_Alloc(OVS_ARGTYPE argType, const VOID* buffer)
{
    UINT expectedSize = 0;
    VOID* newBuffer = NULL;
    OVS_ARGUMENT* pArg = NULL;

    if (!GetArgumentExpectedSize(argType, &expectedSize))
    {
        return NULL;
    }

    if (expectedSize == MAXUINT)
    {
        return NULL;
    }

    if (expectedSize)
    {
        newBuffer = KZAlloc(expectedSize);
        if (!newBuffer)
        {
            return NULL;
        }

        RtlCopyMemory(newBuffer, buffer, expectedSize);
    }

    pArg = CreateArgument(argType, newBuffer);
    if (pArg)
    {
        pArg->isNested = FALSE;
        pArg->freeData = TRUE;
    }

    return pArg;
}

OVS_ARGUMENT* CreateArgumentFromGroup(OVS_ARGTYPE argType, const OVS_ARGUMENT_GROUP* pData)
{
    OVS_ARGUMENT* pArg = NULL;

    pArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pArg)
    {
        return NULL;
    }

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = TRUE;

    pArg->length = pData->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
    pArg->data = (VOID*)pData;

    return pArg;
}

OVS_ARGUMENT* CreateArgumentStringA(OVS_ARGTYPE argType, const char* buffer)
{
    OVS_ARGUMENT* pArg;

    pArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pArg)
    {
        return NULL;
    }

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = FALSE;

    pArg->length = (UINT16)strlen(buffer) + 1;
    pArg->data = (VOID*)buffer;

    return pArg;
}

OVS_ARGUMENT* CreateArgumentStringA_Alloc(OVS_ARGTYPE argType, const char* buffer)
{
    OVS_ARGUMENT* pArg = NULL;
    VOID* newBuffer = NULL;
    UINT16 size = 0;

    pArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pArg)
    {
        return NULL;
    }

    size = (UINT16)strlen(buffer) + 1;

    newBuffer = KZAlloc(size);
    if (!newBuffer)
    {
        return NULL;
    }

    RtlCopyMemory(newBuffer, buffer, size);

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = TRUE;

    pArg->length = size;
    pArg->data = newBuffer;

    return pArg;
}

VOID DestroyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pGroup)
{
    if (pGroup)
    {
        DestroyArguments(pGroup->args, pGroup->count);
        KFree(pGroup);
    }
}

VOID DestroyArguments(_In_ OVS_ARGUMENT* argArray, UINT count)
{
    if (argArray != NULL && count > 0)
    {
        for (UINT i = 0; i < count; ++i)
        {
            OVS_ARGUMENT* pArg = argArray + i;

            DestroyArgumentData(pArg);
        }

        KFree(argArray);
    }
    else
    {
        OVS_CHECK(argArray && count > 0);
    }
}

VOID DestroyArgument(_In_ OVS_ARGUMENT* pArg)
{
    if (pArg)
    {
        DestroyArgumentData(pArg);
        KFree(pArg);
    }
}

VOID DestroyArgumentData(_In_ OVS_ARGUMENT* pArg)
{
    OVS_CHECK(pArg);

    if (IsArgTypeGroup(pArg->type))
    {
        OVS_ARGUMENT_GROUP* pGroup = pArg->data;

        DestroyArgumentGroup(pGroup);
    }
    else
    {
        //free arg data
        if (pArg->freeData)
        {
            KFree(pArg->data);
        }
    }
}

/******************************************* SET FUNCTIONS **********************************************************************/

BOOLEAN SetArgument_Alloc(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE argType, const VOID* buffer)
{
    UINT expectedSize = 0;
    VOID* newBuffer = NULL;

    OVS_CHECK(pArg);

    if (!GetArgumentExpectedSize(argType, &expectedSize))
    {
        return FALSE;
    }

    if (expectedSize == MAXUINT)
    {
        return FALSE;
    }

    OVS_CHECK(expectedSize <= MAXUINT16);

    if (expectedSize)
    {
        newBuffer = KZAlloc(expectedSize);
        if (!newBuffer)
        {
            return FALSE;
        }

        RtlCopyMemory(newBuffer, buffer, expectedSize);
    }

    DEBUGP_ARG(LOG_INFO, "Set argument: %p; type=%u\n", pArg, argType);
    DBGPRINT_ARGTYPE(LOG_INFO, argType, "", 0);

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = TRUE;

    pArg->length = (UINT16)expectedSize;
    pArg->data = (VOID*)newBuffer;

    return TRUE;
}

/******************************************* COPY FUNCTIONS **********************************************************************/

BOOLEAN CopyArgumentGroup(_Out_ OVS_ARGUMENT_GROUP* pDest, _In_ const OVS_ARGUMENT_GROUP* pSource, UINT16 argsMore)
{
    OVS_CHECK(pDest);
    OVS_CHECK(pSource);

    AllocateArgumentsToGroup(pSource->count + argsMore, pDest);

    pDest->count = pSource->count + argsMore;
    pDest->groupSize = pSource->groupSize;

    for (UINT i = 0; i < pSource->count; ++i)
    {
        if (!CopyArgument(pDest->args + i, pSource->args + i))
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN CopyArgument(_Out_ OVS_ARGUMENT* pDest, _In_ const OVS_ARGUMENT* pSource)
{
    OVS_CHECK(pDest);
    OVS_CHECK(pSource);

    pDest->type = pSource->type;
    pDest->length = pSource->length;
    pDest->isDisabled = pSource->isDisabled;
    pDest->isNested = pSource->isNested;
    pDest->freeData = pSource->freeData;

    if (pDest->length)
    {
        pDest->data = KZAlloc(pDest->length);
        if (!pDest->data)
        {
            return FALSE;
        }
    }

    if (IsArgTypeGroup(pDest->type))
    {
        if (!CopyArgumentGroup(pDest->data, pSource->data, /*args more*/0))
        {
            DestroyArgumentGroup(pDest->data);
        }
    }
    else
    {
        RtlCopyMemory(pDest->data, pSource->data, pDest->length);
    }

    return TRUE;
}

/*********************************** DbgPrint FUNCTIONS ***********************************/

#if OVS_DBGPRINT_ARG

VOID DbgPrintArg(ULONG logLevel, _In_ OVS_ARGUMENT* pArg, int depth, int index)
{
    char* padding = NULL;

    OVS_CHECK(pArg);
    OVS_CHECK(depth >= 0);

    padding = KAlloc(depth + 1);
    if (!padding)
    {
        return;
    }

    memset(padding, '\t', depth);
    padding[depth] = 0;

    DbgPrintArgType(logLevel, pArg->type, padding, index);
    DEBUGP_ARG(logLevel, "%ssize: 0x%x\n", padding, pArg->length);

    if (IsArgTypeGroup(pArg->type))
    {
        ++depth;
        DbgPrintArgGroup(logLevel, pArg->data, depth);
    }

    KFree(padding);
}

VOID DbgPrintArgGroup(ULONG logLevel, _In_ OVS_ARGUMENT_GROUP* pGroup, int depth)
{
    char* padding = NULL;

    OVS_CHECK(pGroup);
    OVS_CHECK(depth >= 0);

    padding = KAlloc(depth + 1);
    if (!padding)
    {
        return;
    }

    memset(padding, '\t', depth);
    padding[depth] = 0;

    DEBUGP_ARG(logLevel, "%sgroup: count=0x%x; size=0x%x\n", padding, pGroup->count, pGroup->groupSize);

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        DbgPrintArg(logLevel, pGroup->args + i, depth + 1, i);
    }

    DEBUGP_ARG(logLevel, "\n");

    KFree(padding);
}

#define __STR_CASE_ARGTYPE(argType, text)                  \
case argType:                                               \
    if (IsArgTypeGroup(argType))                            \
    {                                                       \
        RtlStringCchCatA(msg, 256, "GROUP: " text "\n");    \
    }                                                       \
    else                                                    \
    {                                                       \
        RtlStringCchCatA(msg, 256, text "\n");              \
    }                                                       \
    break;

VOID DbgPrintArgType(ULONG logLevel, OVS_ARGTYPE argType, const char* padding, int index)
{
    char msg[256];

    RtlStringCchPrintfA(msg, 256, "%s%d. ", padding, index);

    switch (argType)
    {
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PSEUDOGROUP_FLOW,   "FLOW");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_PI_GROUP,      "FLOW/PI");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_MASK_GROUP,    "FLOW/PI_MASKS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ENCAP_GROUP,     "FLOW/PACKET_ENCAP");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_GROUP,    "FLOW/PI/TUNNEL");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_ACTIONS_GROUP, "FLOW/ACTIONS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_STATS,         "FLOW: STATS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_TCP_FLAGS,     "FLOW: TCP_FLAGS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_TIME_USED,     "FLOW: TIME_USED");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_FLOW_CLEAR,         "FLOW: CLEAR");

        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_PACKET_PRIORITY,     "..PI: PACKET_PRIORITY\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_DP_INPUT_PORT,       "..PI: IN_PORT\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ETH_ADDRESS,         "..PI: ETH_ADDR\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ETH_TYPE,            "..PI: ETH_TYPE\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_VLAN_TCI,            "..PI: VLAN_TCI\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_IPV4,                "..PI: IPV4\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_IPV6,                "..PI: IPV6\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TCP,                 "..PI: TCP\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TCP_FLAGS,           "..PI: TCP_FLAGS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_UDP,                 "..PI: UDP\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_SCTP,                "..PI: SCTP\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ICMP,                "..PI: ICMP\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ICMP6,               "..PI: ICMP6\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_ARP,                 "..PI: ARP\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY,  "..PI: ND\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_PACKET_MARK,         "..PI: PACKET MARK\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_IPV4_TUNNEL,         "..PI: IPV4 TUNNEL\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_MPLS,                "..PI: MPLS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_DATAPATH_HASH,       "..PI: DP_HASH\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_DATAPATH_RECIRCULATION_ID,    "..PI: DP_RECIRC_ID\n");

        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_ID,           "..PI/TUNNEL: ID\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC,     "..PI/TUNNEL: IPV4 SRC\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST,     "..PI/TUNNEL: IPV4 DST\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_TOS,          "..PI/TUNNEL: TOS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_TTL,          "..PI/TUNNEL: TTL\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT,"..PI/TUNNEL: DONT_FRAGMENT\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM,     "..PI/TUNNEL: CHECKSUM\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_OAM,          "..PI/TUNNEL: OAM\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PI_TUNNEL_GENEVE_OPTIONS, "..PI/TUNNEL: GENEVE_OPTS\n");

        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PSEUDOGROUP_PACKET,     "PACKET");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_PI_GROUP,        "PACKET/PI");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_ACTIONS_GROUP,   "PACKET/ACTIONS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_BUFFER,          "PACKET: BUFFER\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PACKET_USERDATA,        "PACKET: USER_DATA\n");
        
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP,    "..ACTIONS/SAMPLE/ACTIONS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_UPCALL_GROUP,            "..ACTIONS/UPCALL");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_UPCALL_PORT_ID,          "..ACTIONS/UPCALL: PORT ID\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_UPCALL_DATA,             "..ACTIONS/UPCALL: DATA\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_SAMPLE_GROUP,            "..ACTIONS/SAMPLE");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY,      "..ACTIONS/SAMPLE: PROBABILITY\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_SETINFO_GROUP,           "..ACTIONS/SET INFO");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT,          "..ACTIONS: OUT TO PORT\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_PUSH_VLAN,               "..ACTIONS: PUSH VLAN\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_POP_VLAN,                "..ACTIONS: POP VLAN\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_PUSH_MPLS,               "..ACTIONS: PUSH MPLS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_POP_MPLS,                "..ACTIONS: POP MPLS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_RECIRCULATION,           "..ACTIONS: DP_RECIRC\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_ACTION_HASH,                    "..ACTIONS: DP_HASH\n");
        
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PSEUDOGROUP_DATAPATH,       "DATAPATH");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_NAME,              "DATAPATH: NAME\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID,    "DATAPATH: UPCALL_PORT_ID\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_STATS,             "DATAPATH: STATS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_MEGAFLOW_STATS,    "DATAPATH: MEGAFLOW_STATS\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_DATAPATH_USER_FEATURES,     "DATAPATH: USER_FEATURES\n");

        __STR_CASE_ARGTYPE(OVS_ARGTYPE_PSEUDOGROUP_OFPORT,             "OFPORT");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_OPTIONS_GROUP,           "OFPORT/OPTIONS");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, "OFPORT/OPTIONS: DESTINATION\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_NUMBER,                  "OFPORT: NUMBER\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_TYPE,                    "OFPORT: TYPE\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_NAME,                    "OFPORT: NAME\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID,          "OFPORT: UPCALL_PORT_ID\n");
        __STR_CASE_ARGTYPE(OVS_ARGTYPE_OFPORT_STATS,                   "OFPORT: STATS\n");

    default:
        OVS_CHECK(__UNEXPECTED__);
    }

    DEBUGP_ARG(logLevel, msg, padding, index);
}

#endif