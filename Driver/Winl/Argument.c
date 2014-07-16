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

/******************************************* ARG SIZE FUNCTIONS **********************************************************************/

static BOOLEAN _GetFlowArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_FLOW_STATS:
        *pSize = sizeof(OVS_WINL_FLOW_STATS);
        break;

    case OVS_ARGTYPE_FLOW_TCP_FLAGS:
        *pSize = sizeof(UINT8);
        break;

    case OVS_ARGTYPE_FLOW_TIME_USED:
        *pSize = sizeof(UINT64);
        break;

    case OVS_ARGTYPE_FLOW_CLEAR:
        *pSize = 0;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _GetPIArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_PI_PACKET_PRIORITY:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_PI_DP_INPUT_PORT:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_PI_ETH_ADDRESS:
        *pSize = sizeof(OVS_PI_ETH_ADDRESS);
        return TRUE;

    case OVS_ARGTYPE_PI_ETH_TYPE:
        *pSize = sizeof(UINT16);
        return TRUE;

    case OVS_ARGTYPE_PI_VLAN_TCI:
        *pSize = sizeof(BE16);
        return TRUE;

    case OVS_ARGTYPE_PI_IPV4:
        *pSize = sizeof(OVS_PI_IPV4);
        return TRUE;

    case OVS_ARGTYPE_PI_IPV6:
        *pSize = sizeof(OVS_PI_IPV6);
        return TRUE;

    case OVS_ARGTYPE_PI_TCP:
        *pSize = sizeof(OVS_PI_TCP);
        return TRUE;

    case OVS_ARGTYPE_PI_UDP:
        *pSize = sizeof(OVS_PI_UDP);
        return TRUE;

    case OVS_ARGTYPE_PI_SCTP:
        *pSize = sizeof(OVS_ARGTYPE_PI_SCTP);
        return TRUE;

    case OVS_ARGTYPE_PI_ICMP:
        *pSize = sizeof(OVS_PI_ICMP);
        return TRUE;

    case OVS_ARGTYPE_PI_ICMP6:
        *pSize = sizeof(OVS_PI_ICMP6);
        return TRUE;

    case OVS_ARGTYPE_PI_ARP:
        *pSize = sizeof(OVS_PI_ARP);
        return TRUE;

    case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
        *pSize = sizeof(OVS_PI_NEIGHBOR_DISCOVERY);
        return TRUE;

    case OVS_ARGTYPE_PI_PACKET_MARK:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
        *pSize = sizeof(OF_PI_IPV4_TUNNEL);
        return TRUE;

    case OVS_ARGTYPE_PI_MPLS:
        *pSize = sizeof(OVS_PI_MPLS);
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetFlowKeyTunnelArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_PI_TUNNEL_ID:
        *pSize = sizeof(BE64);
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
        *pSize = sizeof(BE32);
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
        *pSize = sizeof(BE32);
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_TOS:
        *pSize = sizeof(UINT8);
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_TTL:
        *pSize = sizeof(UINT8);
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
        *pSize = 0;
        return TRUE;

    case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
        *pSize = 0;
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetPacketArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_NETBUFFER:
        //any size can be expected!
        *pSize = MAXUINT;
        return TRUE;

    case OVS_ARGTYPE_NETBUFFER_USERDATA:
        //any size can be expected (userdata should normally be an OVS_ARGUMENT / attribute)
        *pSize = MAXUINT;
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetPacketActionsArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_ACTION_PUSH_VLAN:
        *pSize = sizeof(OVS_ACTION_PUSH_VLAN);
        return TRUE;

    case OVS_ARGTYPE_ACTION_POP_VLAN:
        *pSize = 0;
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetPacketActionUpcallArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_ACTION_UPCALL_DATA:
        *pSize = MAXUINT;
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetPacketActionSampleArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
        *pSize = sizeof(UINT32);
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetDatapathArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_DATAPATH_NAME:
        *pSize = MAXUINT;
        return TRUE;

    case OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_DATAPATH_STATS:
        *pSize = sizeof(OVS_DATAPATH_STATS);
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetOFPortArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    switch (argumentType)
    {
    case OVS_ARGTYPE_OFPORT_NUMBER:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_OFPORT_TYPE:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_OFPORT_NAME:
        *pSize = MAXUINT;
        return TRUE;

    case OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID:
        *pSize = sizeof(UINT32);
        return TRUE;

    case OVS_ARGTYPE_OFPORT_STATS:
        *pSize = sizeof(OVS_OFPORT_STATS);
        return TRUE;

    default:
        return FALSE;
    }
}

static BOOLEAN _GetOFPortOptionsArgExpectedSize(OVS_ARGTYPE argumentType, UINT* pSize)
{
    UNREFERENCED_PARAMETER(argumentType);
    UNREFERENCED_PARAMETER(pSize);

    switch (argumentType)
    {
    case OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT:
        *pSize = sizeof(UINT16);
        return TRUE;

    default:
        return FALSE;
    }
}

OVS_ARGTYPE GetParentGroupType(OVS_ARGTYPE childArgType)
{
    //if child is group
    if (childArgType >= OVS_ARGTYPE_FIRST_GROUP && childArgType <= OVS_ARGTYPE_LAST_GROUP)
    {
        switch (childArgType)
        {
        case OVS_ARGTYPE_GROUP_PI:
        case OVS_ARGTYPE_GROUP_MASK:
            return OVS_ARGTYPE_PSEUDOGROUP_FLOW;

        case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
        case OVS_ARGTYPE_GROUP_PI_TUNNEL:
            return OVS_ARGTYPE_GROUP_PI;

        case OVS_ARGTYPE_GROUP_ACTIONS:
            return OVS_ARGTYPE_PSEUDOGROUP_PACKET;

        case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
        case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
        case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
            return OVS_ARGTYPE_GROUP_ACTIONS;

        case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
            return OVS_ARGTYPE_PSEUDOGROUP_OFPORT;

        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            return OVS_ARGTYPE_GROUP_MAIN;

        default:
            OVS_CHECK(__UNEXPECTED__);
        }
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTION && childArgType <= OVS_ARGTYPE_LAST_ACTION)
    {
        return OVS_ARGTYPE_GROUP_ACTIONS;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTIONS_SAMPLE && childArgType <= OVS_ARGTYPE_LAST_ACTIONS_SAMPLE)
    {
        return OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTIONS_UPCALL && childArgType <= OVS_ARGTYPE_LAST_ACTIONS_UPCALL)
    {
        return OVS_ARGTYPE_GROUP_ACTIONS_UPCALL;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_DATAPATH && childArgType <= OVS_ARGTYPE_LAST_DATAPATH)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_DATAPATH;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_FLOW && childArgType <= OVS_ARGTYPE_LAST_FLOW)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_FLOW;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_KEY && childArgType <= OVS_ARGTYPE_LAST_KEY)
    {
        return OVS_ARGTYPE_GROUP_PI;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_KEY_TUNNEL && childArgType <= OVS_ARGTYPE_LAST_KEY_TUNNEL)
    {
        return OVS_ARGTYPE_GROUP_PI_TUNNEL;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_NETBUFFER && childArgType <= OVS_ARGTYPE_LAST_NETBUFFER)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_PACKET;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_OFPORT && childArgType <= OVS_ARGTYPE_LAST_OFPORT)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_OFPORT;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_OFPORT_OPTION && childArgType <= OVS_ARGTYPE_LAST_OFPORT_OPTION)
    {
        return OVS_ARGTYPE_GROUP_OFPORT_OPTIONS;
    }

    OVS_CHECK(__UNEXPECTED__);

    return OVS_ARGTYPE_INVALID;
}

BOOLEAN GetArgumentExpectedSize(OVS_ARGTYPE argumentType, _Inout_ UINT* pSize)
{
    OVS_ARGTYPE groupType = OVS_ARGTYPE_INVALID;

    if (IsArgTypeGroup(argumentType))
    {
        *pSize = MAXUINT;
        return TRUE;
    }

    groupType = GetParentGroupType(argumentType);

    switch (groupType)
    {
    case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
        return _GetFlowArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_PI:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_MASK:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_PI_TUNNEL:
        return _GetFlowKeyTunnelArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
        return _GetPacketArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_ACTIONS:
        return _GetPacketActionsArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
        return _GetPacketActionUpcallArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
        return _GetPacketActionSampleArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
        return _GetDatapathArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
        return _GetOFPortArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
        return _GetOFPortOptionsArgExpectedSize(argumentType, pSize);
    default:
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
    DbgPrintArgType(argType, "", 0);

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
    DbgPrintArgType(argType, "", 0);

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
    DbgPrintArgType(argType, "", 0);

    pArg->type = argType;
    pArg->isDisabled = FALSE;
    pArg->isNested = FALSE;
    pArg->freeData = TRUE;

    pArg->length = (UINT16)expectedSize;
    pArg->data = (VOID*)newBuffer;

    return TRUE;
}

/******************************************* ARGUMENT LIST FUNCTIONS **********************************************************************/

OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry(OVS_ARGTYPE argType, const VOID* buffer)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem;

    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArg = CreateArgument_Alloc(argType, buffer);
    if (!pArg)
    {
        return NULL;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;
    return pArgListItem;
}

OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem;

    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArg = CreateArgumentWithSize(argType, buffer, size);
    if (!pArg)
    {
        return NULL;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;
    return pArgListItem;
}

OVS_ARGUMENT* ArgumentListToArray(_In_ OVS_ARGUMENT_SLIST_ENTRY* pHeadArg, _Inout_ UINT16* pCountArgs, _Inout_ UINT* pSize)
{
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    OVS_ARGUMENT* args = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListEntry = NULL;

    OVS_CHECK(pHeadArg);
    //pFirstArg must be the HEAD of the list: the HEAD has pArg = NULL
    OVS_CHECK(pHeadArg->pArg == NULL);

    pArgListEntry = pHeadArg->pNext;

    while (pArgListEntry)
    {
        ++countArgs;
        totalSize += pArgListEntry->pArg->length;
        totalSize += OVS_ARGUMENT_HEADER_SIZE;

        pArgListEntry = pArgListEntry->pNext;
    }

    args = KZAlloc(countArgs);
    if (!args)
    {
        return NULL;
    }

    pArgListEntry = pHeadArg->pNext;

    for (UINT i = 0; i < countArgs; ++i, pArgListEntry = pArgListEntry->pNext)
    {
        args[i] = *pArgListEntry->pArg;
    }

    *pCountArgs = countArgs;
    *pSize = totalSize;

    return args;
}

BOOLEAN AppendArgumentToList(OVS_ARGUMENT* pArg, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastEntry)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem = NULL;
    
    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;

    (*ppLastEntry)->pNext = pArgListItem;
    *ppLastEntry = pArgListItem;

    return TRUE;
}

BOOLEAN CreateArgInList(OVS_ARGTYPE argType, const VOID* buffer, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg)
{
    (*ppLastArg)->pNext = CreateArgumentListEntry(argType, buffer);
    if (!(*ppLastArg)->pNext)
    {
        return FALSE;
    }

    *ppLastArg = (*ppLastArg)->pNext;

    return TRUE;
}

BOOLEAN CreateArgInList_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg)
{
    (*ppLastArg)->pNext = CreateArgumentListEntry_WithSize(argType, buffer, size);
    if (!(*ppLastArg)->pNext)
    {
        return FALSE;
    }

    *ppLastArg = (*ppLastArg)->pNext;

    return TRUE;
}

VOID DestroyArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = *ppHeadEntry;
    OVS_ARGUMENT_SLIST_ENTRY* pNext = NULL;

    if (!pArgListCur)
        return;

    //the pArgListFirst points to a head, which has pArg = NULL
    OVS_CHECK(!pArgListCur->pArg);

    pArgListCur = pArgListCur->pNext;

    //free head
    KFree(*ppHeadEntry);

    while (pArgListCur)
    {
        pNext = pArgListCur->pNext;

        //1. destroy the arg
        DestroyArgument(pArgListCur->pArg);

        //2. free the list entry
        KFree(pArgListCur);

        pArgListCur = pNext;
    }

    *ppHeadEntry = NULL;
}

//also frees the OVS_ARGUMENT-s within (the OVS_ARGUMENT::data is not freed)
VOID FreeArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = *ppHeadEntry;
    OVS_ARGUMENT_SLIST_ENTRY* pNext = NULL;

    if (!pArgListCur)
        return;

    //the pArgListFirst points to a head, which has pArg = NULL
    OVS_CHECK(!pArgListCur->pArg);

    pArgListCur = pArgListCur->pNext;
    //free head
    KFree(*ppHeadEntry);

    while (pArgListCur)
    {
        pNext = pArgListCur->pNext;

        KFree(pArgListCur);
        KFree(pArgListCur->pArg);

        pArgListCur = pNext;
    }

    *ppHeadEntry = NULL;
}

//NOTE: it also destroys the list
OVS_ARGUMENT* CreateGroupArgFromList(OVS_ARGTYPE groupType, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadArg)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    OVS_ARGUMENT* argArray = NULL, *pGroupArg = NULL;
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    BOOLEAN ok = TRUE;

    pGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pGroup)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pGroupArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pGroupArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //1. create args[] from arg single linked list
    argArray = ArgumentListToArray(*ppHeadArg, &countArgs, &totalSize);

    //2. create OVS_ARGUMENT_GROUP (i.e. group) with these args[]
    pGroup->args = argArray;
    pGroup->count = countArgs;

    //3. create an OVS_ARGUMENT which embeds the group (type of arg = group)
    pGroupArg->data = pGroup;
    pGroupArg->length = (UINT16)totalSize;
    pGroupArg->type = groupType;
    pGroupArg->isNested = FALSE;
    pGroupArg->freeData = TRUE;

    //4. Destroy the linked list
Cleanup:
    if (ok)
    {
        FreeArgList(ppHeadArg);
    }
    else
    {
        //also destroys pArgs and its children
        DestroyArgument(pGroupArg);
    }

    return pGroupArg;
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

VOID DbgPrintArg(_In_ OVS_ARGUMENT* pArg, int depth, int index)
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

    DbgPrintArgType(pArg->type, padding, index);
    DEBUGP_ARG(LOG_INFO, "%ssize: 0x%x\n", padding, pArg->length);

    if (IsArgTypeGroup(pArg->type))
    {
        ++depth;
        DbgPrintArgGroup(pArg->data, depth);
    }

    KFree(padding);
}

VOID DbgPrintArgGroup(_In_ OVS_ARGUMENT_GROUP* pGroup, int depth)
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

    DEBUGP_ARG(LOG_INFO, "%sgroup: count=0x%x; size=0x%x\n", padding, pGroup->count, pGroup->groupSize);

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        DbgPrintArg(pGroup->args + i, depth + 1, i);
    }

    DEBUGP_ARG(LOG_INFO, "\n");

    KFree(padding);
}

static __inline VOID _DbgPrintArgType_Flow(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_FLOW_STATS:
        DEBUGP_ARG(LOG_INFO, "FLOW: STATS\n");
        break;

    case OVS_ARGTYPE_FLOW_TCP_FLAGS:
        DEBUGP_ARG(LOG_INFO, "FLOW: TCP FLAGS\n");
        break;

    case OVS_ARGTYPE_FLOW_TIME_USED:
        DEBUGP_ARG(LOG_INFO, "FLOW: TIME USED\n");
        break;

    case OVS_ARGTYPE_FLOW_CLEAR:
        DEBUGP_ARG(LOG_INFO, "FLOW: CLEAR\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_PacketInfo(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_PI_PACKET_PRIORITY:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: PACKET PRIORITY\n");
        break;

    case OVS_ARGTYPE_PI_DP_INPUT_PORT:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: IN PORT\n");
        break;

    case OVS_ARGTYPE_PI_ETH_ADDRESS:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ETH ADDR\n");
        break;

    case OVS_ARGTYPE_PI_ETH_TYPE:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ETH TYPE\n");
        break;

    case OVS_ARGTYPE_PI_VLAN_TCI:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: VLAN TCI\n");
        break;

    case OVS_ARGTYPE_PI_IPV4:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: IPV4\n");
        break;

    case OVS_ARGTYPE_PI_IPV6:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: IPV6\n");
        break;

    case OVS_ARGTYPE_PI_TCP:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: TCP\n");
        break;

    case OVS_ARGTYPE_PI_UDP:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: UDP\n");
        break;

    case OVS_ARGTYPE_PI_SCTP:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: SCTP\n");
        break;

    case OVS_ARGTYPE_PI_ICMP:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ICMP\n");
        break;

    case OVS_ARGTYPE_PI_ICMP6:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ICMP6\n");
        break;

    case OVS_ARGTYPE_PI_ARP:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ARP\n");
        break;

    case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: ND\n");
        break;

    case OVS_ARGTYPE_PI_PACKET_MARK:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: PACKET MARK\n");
        break;

    case OVS_ARGTYPE_PI_IPV4_TUNNEL:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: IPV4 TUNNEL\n");
        break;

    case OVS_ARGTYPE_PI_MPLS:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY: MPLS\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_PITunnel(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_PI_TUNNEL_ID:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL: ID\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:IPV4 SRC\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:IPV4 DST\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_TOS:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:TOS\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_TTL:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:TTL\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:DON'T FRAGMENT\n");
        break;

    case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
        DEBUGP_ARG(LOG_INFO, "FLOW/KEY/TUNNEL:CHECKSUM\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_Packet(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_NETBUFFER:
        DEBUGP_ARG(LOG_INFO, "PACKET: BUFFER\n");
        break;

    case OVS_ARGTYPE_NETBUFFER_USERDATA:
        DEBUGP_ARG(LOG_INFO, "PACKET: USER DATA\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_PacketActions(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS: OUT TO PORT\n");
        break;

    case OVS_ARGTYPE_ACTION_PUSH_VLAN:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS: PUSH VLAN\n");
        break;

    case OVS_ARGTYPE_ACTION_POP_VLAN:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS: POP VLAN\n");
        break;

    case OVS_ARGTYPE_ACTION_PUSH_MPLS:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS: PUSH MPLS\n");
        break;

    case OVS_ARGTYPE_ACTION_POP_MPLS:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS: POP MPLS\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_PacketActionsUpcall(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS/UPCALL: PORT ID\n");
        break;

    case OVS_ARGTYPE_ACTION_UPCALL_DATA:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS/UPCALL: DATA\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_PacketActionsSample(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
        DEBUGP_ARG(LOG_INFO, "PACKET/ACTIONS/SAMPLE: PROBABILITY\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_Datapath(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_DATAPATH_NAME:
        DEBUGP_ARG(LOG_INFO, "DATAPATH: NAME\n");
        break;

    case OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID:
        DEBUGP_ARG(LOG_INFO, "DATAPATH: UPCALL PORT ID\n");
        break;

    case OVS_ARGTYPE_DATAPATH_STATS:
        DEBUGP_ARG(LOG_INFO, "DATAPATH: STATS\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_OFPort(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_OFPORT_NUMBER:
        DEBUGP_ARG(LOG_INFO, "OFPORT: NUMBER\n");
        break;

    case OVS_ARGTYPE_OFPORT_TYPE:
        DEBUGP_ARG(LOG_INFO, "OFPORT: TYPE\n");
        break;

    case OVS_ARGTYPE_OFPORT_NAME:
        DEBUGP_ARG(LOG_INFO, "OFPORT: NAME\n");
        break;

    case OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID:
        DEBUGP_ARG(LOG_INFO, "OFPORT: UPCALL PORT ID\n");
        break;

    case OVS_ARGTYPE_OFPORT_STATS:
        DEBUGP_ARG(LOG_INFO, "OFPORT: STATS\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

static __inline VOID _DbgPrintArgType_OFPortOptions(OVS_ARGTYPE argType)
{
    switch (argType)
    {
    case OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT:
        DEBUGP_ARG(LOG_INFO, "PORT OPT: DESTINATION\n");
        break;

    default:
        OVS_CHECK(0);
    }
}

VOID DbgPrintArgType(OVS_ARGTYPE argType, const char* padding, int index)
{
    UNREFERENCED_PARAMETER(index);
    UNREFERENCED_PARAMETER(padding);

    DEBUGP_ARG(LOG_INFO, "%s%d. ", padding, index);

    if (IsArgTypeGroup(argType))
    {
        switch (argType)
        {
        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW\n");
            break;

        case OVS_ARGTYPE_GROUP_PI:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY\n");
            break;

        case OVS_ARGTYPE_GROUP_MASK:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY MASKS\n");

            break;
        case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/PACKET ENCAPSULATION\n");
            break;

        case OVS_ARGTYPE_GROUP_PI_TUNNEL:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY/TUNNEL\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET\n");
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/ACTIONS\n");
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/ACTIONS/UPCALL\n");
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/ACTIONS/SAMPLE\n");
            break;

            //contains packet info args to set
        case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/ACTIONS/SET INFO\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
            DEBUGP_ARG(LOG_INFO, "GROUP: DATAPATH\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
            DEBUGP_ARG(LOG_INFO, "GROUP: OF PORT\n");
            break;

        case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
            DEBUGP_ARG(LOG_INFO, "GROUP: OF PORT / OPTIONS\n");
            break;

        default: OVS_CHECK(0);
        }
    }
    else
    {
        OVS_ARGTYPE groupType = GetParentGroupType(argType);

        switch (groupType)
        {
        case OVS_ARGTYPE_GROUP_MAIN:
            switch (argType)
            {
            case OVS_ARGTYPE_NETBUFFER:
                DEBUGP_ARG(LOG_INFO, "PACKET: BUFFER\n");
                break;

            default:
                OVS_CHECK(0);
            }

            break;

        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
            _DbgPrintArgType_Flow(argType);
            break;

        case OVS_ARGTYPE_GROUP_PI:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_GROUP_MASK:
            _DbgPrintArgType_PacketInfo(argType);

            break;
        case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_GROUP_PI_TUNNEL:
            _DbgPrintArgType_PITunnel(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            _DbgPrintArgType_Packet(argType);
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS:
            _DbgPrintArgType_PacketActions(argType);
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
            _DbgPrintArgType_PacketActionsUpcall(argType);
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
            _DbgPrintArgType_PacketActionsSample(argType);
            break;

            //contains packet info args to set
        case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
            _DbgPrintArgType_Datapath(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
            _DbgPrintArgType_OFPort(argType);
            break;

        case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
            _DbgPrintArgType_OFPortOptions(argType);
            break;

        default: OVS_CHECK(0);
        }
    }
}

/*********************************** VALIDATION FUNCTIONS ***********************************/

UINT VerifyArgGroupSize(OVS_ARGUMENT_GROUP* pGroup)
{
    UINT expectedSize = 0;

    OVS_CHECK(pGroup);
    //group count can be zero, but in this case, group size must also be zero

    expectedSize = pGroup->count * OVS_ARGUMENT_HEADER_SIZE;

    for (UINT i = 0; i != pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;
        OVS_CHECK(pArg->data && pArg->length || !pArg->data && !pArg->length);

        if (IsArgTypeGroup(argType))
        {
            UINT groupSize;

            DEBUGP_ARG(LOG_INFO, "checking subgroup: ");
            DbgPrintArgType(pArg->type, "", i);

            groupSize = VerifyArgGroupSize(pArg->data);
            OVS_CHECK(pArg->length == groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE);
        }

        expectedSize += pArg->length;
    }

    OVS_CHECK(expectedSize == pGroup->groupSize);

    return pGroup->groupSize;
}

/********************************* FLOW / KEY / TUNNEL *********************************/

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelChecksum(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    //data type: no data
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelDontFragment(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    //data type: no data
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelFlags(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT16 flags = GET_ARG_DATA(pArg, UINT16);

    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (flags == OVS_PI_MASK_MATCH_WILDCARD(UINT16))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel flag is default\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelId(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE64 tunnelId = GET_ARG_DATA(pArg, BE64);

    //data type: BE64
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (tunnelId == OVS_PI_MASK_MATCH_WILDCARD(UINT64))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel id is default. no need to be set\n");
        }
    }

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelIpv4Dst(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 destAddr = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
        if (destAddr == 0)
        {
            return FALSE;
        }
    }
    //is mask
    else if (isRequest)
    {
        if (destAddr == OVS_PI_MASK_MATCH_WILDCARD(UINT32))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ipv4 dest is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelIpv4Src(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE32 ipv4Src = GET_ARG_DATA(pArg, BE32);

    //data type: BE64
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (ipv4Src == OVS_PI_MASK_MATCH_WILDCARD(UINT32))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ipv4 src is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelTos(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT8 tos = GET_ARG_DATA(pArg, UINT8);

    //data type: UINT8
    if (!isMask)
    {
    }
    //is mask
    else if (isRequest)
    {
        if (tos == OVS_PI_MASK_MATCH_WILDCARD(UINT8))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel tos is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfoTunnelTtl(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT8 ttl = GET_ARG_DATA(pArg, UINT8);

    if (!isMask)
    {
        if (ttl == 0)
        {
            return FALSE;
        }
    }
    else if (isRequest)
    {
        if (ttl == OVS_PI_MASK_MATCH_WILDCARD(UINT8))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tunnel ttl is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_FlowKeyTunnel(OVS_ARGUMENT* pParentArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = pParentArg->data;
    BOOLEAN haveDest = FALSE, haveTtl = FALSE;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_TUNNEL_CHECKSUM:
            if (!_VerifyArg_PacketInfoTunnelChecksum(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT:
            if (!_VerifyArg_PacketInfoTunnelDontFragment(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_ID:
            if (!_VerifyArg_PacketInfoTunnelId(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_DST:
            if (!_VerifyArg_PacketInfoTunnelIpv4Dst(pArg, isMask, isRequest))
            {
                return FALSE;
            }

            haveDest = TRUE;
            break;

        case OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC:
            if (!_VerifyArg_PacketInfoTunnelIpv4Src(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TOS:
            if (!_VerifyArg_PacketInfoTunnelTos(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TUNNEL_TTL:
            if (!_VerifyArg_PacketInfoTunnelTtl(pArg, isMask, isRequest))
            {
                return FALSE;
            }

            haveTtl = TRUE;
            break;

        default:
            return FALSE;
        }
    }

    if (!isMask)
    {
        if (!haveDest || !haveTtl)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* FLOW / KEY  *********************************/

static __inline BOOLEAN _VerifyArg_PacketInfo_DpInputPort(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 inPort = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
        if (inPort > OVS_MAX_PORTS)
        {
            DEBUGP_ARG(LOG_ERROR, "the in port id is too big. max is: 0x%x; given is: 0x%x\n", OVS_MAX_PORTS, inPort);
        }
    }
    else if (isRequest)
    {
        DEBUGP_ARG(LOG_INFO, "the mask shouldn't be set for dp in port: it is always set as exact match (~0)\n");
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_EthAddress(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OVS_PI_ETH_ADDRESS* pEthAddrInfo = pArg->data;

    if (!isMask)
    {
    }
    //mask
    else if (isRequest)
    {
        OVS_PI_ETH_ADDRESS wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pEthAddrInfo, &wildcard, sizeof(OVS_PI_ETH_ADDRESS)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for eth addr is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_EthType(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    UINT16 ethType = RtlUshortByteSwap(GET_ARG_DATA(pArg, UINT16));

    UNREFERENCED_PARAMETER(isRequest);

    if (!isMask)
    {
        if (ethType < OVS_ETHERTYPE_802_3_MIN)
        {
            return FALSE;
        }

        switch (ethType)
        {
        case OVS_ETHERTYPE_ARP:
        case OVS_ETHERTYPE_RARP:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ARP))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as (r)arp, but no arp key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_IPV4:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as ipv4, but no ipv4 key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_IPV6:
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
            {
                DEBUGP_ARG(LOG_ERROR, "eth key specified as ipv6, but no ipv6 key found!\n");
                return FALSE;
            }
            break;

        case OVS_ETHERTYPE_QTAG:
            //must have vlan tci & encapsulation
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_VLAN_TCI))
            {
                return FALSE;
            }

            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_GROUP_PI_ENCAPSULATION))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "we don't handle ether type: 0x%x\n", ethType);
            return FALSE;
        }
    }

    //is mask & !request
    else
    {
        if (ethType != OVS_PI_MASK_MATCH_EXACT(UINT16))
        {
            DEBUGP_ARG(LOG_ERROR, "the mask for eth type should be exact match.\n");
            return FALSE;
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Icmp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ICMP* pIcmpInfo = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4))
        {
            return FALSE;
        }
    }

    //mask
    else if (isRequest)
    {
        OVS_PI_ICMP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIcmpInfo, &wildcard, sizeof(OVS_PI_ICMP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for icmp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Icmp6(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ICMP6* pIcmp6Info = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
        {
            return FALSE;
        }

        if (pIcmp6Info->type == OVS_NDISC_NEIGHBOUR_SOLICITATION ||
            pIcmp6Info->code == OVS_NDISC_NEIGHBOUR_ADVERTISEMENT)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY))
            {
                return FALSE;
            }
        }
    }

    //mask
    else if (isRequest)
    {
        OVS_PI_ICMP6 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIcmp6Info, &wildcard, sizeof(OVS_PI_ICMP6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for icmp6 is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv4(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer)
{
    OVS_PI_IPV4* pIpv4Info = pArg->data;

    if (!isMask)
    {
        if (checkTransportLayer)
        {
            if (pIpv4Info->fragmentType != OVS_FRAGMENT_TYPE_FRAG_N)
            {
                switch (pIpv4Info->protocol)
                {
                case OVS_IPPROTO_TCP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_TCP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_UDP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_UDP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_SCTP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_SCTP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_ICMP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ICMP))
                    {
                        return FALSE;
                    }
                    break;
                }
            }
        }

        switch (pIpv4Info->fragmentType)
        {
        case OVS_FRAGMENT_TYPE_NOT_FRAG:
        case OVS_FRAGMENT_TYPE_FIRST_FRAG:
        case OVS_FRAGMENT_TYPE_FRAG_N:
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "fragment type is not an enum constant!\n");
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_IPV4 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };
        int res = memcmp(pIpv4Info, &wildcard, sizeof(OVS_PI_IPV4));

        if (0 == res)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv4Tunnel(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    OF_PI_IPV4_TUNNEL* pTunnelInfo = pArg->data;

    if (!isMask)
    {
    }

    //mask
    else if (isRequest)
    {
        OF_PI_IPV4_TUNNEL wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pTunnelInfo, &wildcard, sizeof(OF_PI_IPV4_TUNNEL)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ipv4 tunnel is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Ipv6(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer)
{
    OVS_PI_IPV6* pIpv6Info = pArg->data;

    if (!isMask)
    {
        if (checkTransportLayer)
        {
            if (pIpv6Info->fragmentType != OVS_FRAGMENT_TYPE_FRAG_N)
            {
                switch (pIpv6Info->protocol)
                {
                case OVS_IPPROTO_TCP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_TCP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_UDP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_UDP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPPROTO_SCTP:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_SCTP))
                    {
                        return FALSE;
                    }
                    break;

                case OVS_IPV6_EXTH_ICMP6:
                    if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_ICMP6))
                    {
                        return FALSE;
                    }
                    break;
                }
            }
        }

        switch (pIpv6Info->fragmentType)
        {
        case OVS_FRAGMENT_TYPE_NOT_FRAG:
        case OVS_FRAGMENT_TYPE_FIRST_FRAG:
        case OVS_FRAGMENT_TYPE_FRAG_N:
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "fragment type is not an enum constant!\n");
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_IPV6 wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pIpv6Info, &wildcard, sizeof(OVS_PI_IPV6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ipv6 is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Mpls(OVS_ARGUMENT* pArg, BOOLEAN isMask)
{
    UNREFERENCED_PARAMETER(pArg);
    UNREFERENCED_PARAMETER(isMask);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented -- mpls not (yet) supported\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_NeighborDiscovery(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_NEIGHBOR_DISCOVERY* pNd = pArg->data;

    if (!isMask)
    {
        if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))
        {
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_NEIGHBOR_DISCOVERY wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pNd, &wildcard, sizeof(OVS_PI_IPV6)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for ip6 net discovery is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_PacketMark(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 packetMark = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
    }
    else
    {
        if (isRequest && packetMark == OVS_PI_MASK_MATCH_WILDCARD(UINT))
        {
            DEBUGP_ARG(LOG_LOUD, "default value is 0 / wildcard match; setting default value manually is useless overhead\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_PacketPriority(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    UINT32 packetPriority = GET_ARG_DATA(pArg, UINT32);

    if (!isMask)
    {
    }
    else
    {
        if (isRequest && packetPriority == OVS_PI_MASK_MATCH_WILDCARD(UINT))
        {
            DEBUGP_ARG(LOG_LOUD, "default value is 0 / wildcard match; setting default value manually would be useless overhead\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Sctp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_SCTP* pSctpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_SCTP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pSctpInfo, &wildcard, sizeof(OVS_PI_SCTP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for sctp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Tcp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_TCP* pTcpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_TCP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pTcpInfo, &wildcard, sizeof(OVS_PI_TCP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for tcp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Udp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg, BOOLEAN seekIp)
{
    OVS_PI_UDP* pUdpInfo = pArg->data;

    if (!isMask)
    {
        if (seekIp)
        {
            if (!FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV4) &&

                !FindArgument(pParentArg->data, OVS_ARGTYPE_PI_IPV6))

                return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_UDP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pUdpInfo, &wildcard, sizeof(OVS_PI_UDP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for udp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Arp(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest, OVS_ARGUMENT* pParentArg)
{
    OVS_PI_ARP* pArpInfo = pArg->data;

    UNREFERENCED_PARAMETER(pParentArg);

    if (!isMask)
    {
        UINT16 op = RtlUshortByteSwap(pArpInfo->operation);

        if (op != 1 && op != 2)
        {
            DEBUGP_ARG(LOG_ERROR, "packet info / arp: unknown op code %d\n", op);
            return FALSE;
        }
    }
    else if (isRequest)
    {
        OVS_PI_ARP wildcard = { OVS_PI_MASK_MATCH_WILDCARD(UINT) };

        if (0 == memcmp(pArpInfo, &wildcard, sizeof(OVS_PI_ARP)))
        {
            DEBUGP_ARG(LOG_LOUD, "mask wildcard for arp is default. no need to be set\n");
        }
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_VlanTci(OVS_ARGUMENT* pArg, BOOLEAN isMask, BOOLEAN isRequest)
{
    BE16 tci = GET_ARG_DATA(pArg, BE16);

    //it is possible we shouldn't allow to specify tci = 0 as key

    if (!isMask)
    {
    }
    else if (isRequest)
    {
        if (tci == OVS_PI_MASK_MATCH_WILDCARD(UINT16))
        {
            DEBUGP_ARG(LOG_LOUD, "tci mask should not be set as wildcard. it's the default\n");
        }
    }

    if (!(tci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        DEBUGP_ARG(LOG_ERROR, "if you set vlan tci, you must set 'tag present' = 1!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketInfo_Encap(OVS_ARGUMENT* pEncArg, BOOLEAN isMask, BOOLEAN isRequest, BOOLEAN checkTransportLayer, BOOLEAN seekIp)
{
    OVS_ARGUMENT_GROUP* pGroup = pEncArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PI_ETH_TYPE:
            if (!_VerifyArg_PacketInfo_EthType(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP:
            if (!_VerifyArg_PacketInfo_Icmp(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP6:
            if (!_VerifyArg_PacketInfo_Icmp6(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4:
            if (!_VerifyArg_PacketInfo_Ipv4(pArg, isMask, isRequest, pEncArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV6:
            if (!_VerifyArg_PacketInfo_Ipv6(pArg, isMask, isRequest, pEncArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            if (!_VerifyArg_PacketInfo_NeighborDiscovery(pArg, isMask, isRequest, pEncArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_SCTP:
            if (!_VerifyArg_PacketInfo_Sctp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TCP:
            if (!_VerifyArg_PacketInfo_Tcp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_UDP:
            if (!_VerifyArg_PacketInfo_Udp(pArg, isMask, isRequest, pEncArg, seekIp))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

//pArg = FLOW/KEY
BOOLEAN VerifyGroup_PacketInfo(BOOLEAN isMask, BOOLEAN isRequest, _In_ OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer, BOOLEAN seekIp)
{
    OVS_ARGUMENT_GROUP* pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_PI_ENCAPSULATION:
            if (!_VerifyArg_PacketInfo_Encap(pArg, isMask, isRequest, checkTransportLayer, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_PI_TUNNEL:
            if (!_VerifyGroup_FlowKeyTunnel(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_DP_INPUT_PORT:
            if (!_VerifyArg_PacketInfo_DpInputPort(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ETH_ADDRESS:
            if (!_VerifyArg_PacketInfo_EthAddress(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ETH_TYPE:
            if (!_VerifyArg_PacketInfo_EthType(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP:
            if (!_VerifyArg_PacketInfo_Icmp(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ICMP6:
            if (!_VerifyArg_PacketInfo_Icmp6(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4:
            if (!_VerifyArg_PacketInfo_Ipv4(pArg, isMask, isRequest, pParentArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV4_TUNNEL:
            if (!_VerifyArg_PacketInfo_Ipv4Tunnel(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_IPV6:
            if (!_VerifyArg_PacketInfo_Ipv6(pArg, isMask, isRequest, pParentArg, checkTransportLayer))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_MPLS:
            if (!_VerifyArg_PacketInfo_Mpls(pArg, isMask))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY:
            if (!_VerifyArg_PacketInfo_NeighborDiscovery(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_PACKET_MARK:
            if (!_VerifyArg_PacketInfo_PacketMark(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_PACKET_PRIORITY:
            if (!_VerifyArg_PacketInfo_PacketPriority(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_SCTP:
            if (!_VerifyArg_PacketInfo_Sctp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_TCP:
            if (!_VerifyArg_PacketInfo_Tcp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_UDP:
            if (!_VerifyArg_PacketInfo_Udp(pArg, isMask, isRequest, pParentArg, seekIp))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_ARP:
            if (!_VerifyArg_PacketInfo_Arp(pArg, isMask, isRequest, pParentArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PI_VLAN_TCI:
            if (!_VerifyArg_PacketInfo_VlanTci(pArg, isMask, isRequest))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* FLOW  *********************************/
BOOLEAN VerifyArg_Flow_Clear(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    //data type: no data

    return TRUE;
}

BOOLEAN VerifyArg_Flow_Stats(OVS_ARGUMENT* pArg)
{
    OVS_WINL_FLOW_STATS* pStats = pArg->data;

    UNREFERENCED_PARAMETER(pStats);

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

BOOLEAN VerifyArg_Flow_TcpFlags(OVS_ARGUMENT* pArg)
{
    UINT8 flags = GET_ARG_DATA(pArg, UINT8);

    //data type: UINT8

    UNREFERENCED_PARAMETER(flags);

    //tcp flags / ctrl bits, without the ECN bits (because we have data type of 1 byte = 8 bits)
    //0x3f = (binary) 0011 1111, i.e. 6 bits that can be set for flags
    if (flags > 0x3F)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " tcp flags: only bits [0, 5] can be set\n");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN VerifyArg_Flow_TimeUsed(OVS_ARGUMENT* pArg)
{
    UINT64 timeUsed = GET_ARG_DATA(pArg, UINT64);

    UNREFERENCED_PARAMETER(timeUsed);

    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_Flow(OVS_ARGUMENT* pArg, BOOLEAN isRequest)
{
    OVS_ARGTYPE argType = pArg->type;

    switch (argType)
    {
    case OVS_ARGTYPE_GROUP_PI:
        return VerifyGroup_PacketInfo(FALSE, isRequest, pArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE);

    case OVS_ARGTYPE_GROUP_MASK:
        return VerifyGroup_PacketInfo(TRUE, isRequest, pArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE);

    case OVS_ARGTYPE_FLOW_CLEAR:
        return VerifyArg_Flow_Clear(pArg->data);

    case OVS_ARGTYPE_FLOW_STATS:
        return VerifyArg_Flow_Stats(pArg->data);

    case OVS_ARGTYPE_FLOW_TCP_FLAGS:
        return VerifyArg_Flow_TcpFlags(pArg->data);

    case OVS_ARGTYPE_FLOW_TIME_USED:
        return VerifyArg_Flow_TimeUsed(pArg->data);

    default:
        return FALSE;
    }
}

/********************************* PACKET / ACTIONS / UPCALL  *********************************/

static __inline BOOLEAN _VerifyArg_PacketActionUpcall_PortId(OVS_ARGUMENT* pArg)
{
    UINT32 pid = GET_ARG_DATA(pArg, UINT32);
    if (pid == 0)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " port id 0 is invalid!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActionUpcall_Data(OVS_ARGUMENT* pArg)
{
    typedef VOID* PCOOKIE;

    PCOOKIE pCookie = pArg->data;
    UNREFERENCED_PARAMETER(pCookie);

    //NOTE: THERE IS NO WAY TO CHECK THE COOKIE!
    return TRUE;
}

static __inline BOOLEAN _VerifyGroup_PacketActionsUpcall(OVS_ARGUMENT* pParentArg)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_ACTION_UPCALL_PORT_ID:
            if (!_VerifyArg_PacketActionUpcall_PortId(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_DATA:
            if (!_VerifyArg_PacketActionUpcall_Data(pArg))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "PACKET/ACTIONS/SAMPLE should not have argtype = 0x%x\n", pArg->type);
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* PACKET / ACTIONS / SAMPLE  *********************************/

static __inline BOOLEAN _VerifyArg_PacketAction_Sample_Probability(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyGroup_PacketActionsSample(OVS_ARGUMENT* pParentArg, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_ACTIONS:
            if (!VerifyGroup_PacketActions(pArg->data, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
            if (!_VerifyArg_PacketAction_Sample_Probability(pArg->data))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "PACKET/ACTIONS/SAMPLE should not have argtype = 0x%x\n", pArg->type);
            return FALSE;
        }
    }

    return TRUE;
}

/********************************* PACKET / ACTIONS  *********************************/

static __inline BOOLEAN _VerifyArg_PacketActions_OutToPort(OVS_ARGUMENT* pArg)
{
    UINT32 portNumber = GET_ARG_DATA(pArg, UINT32);

    if (portNumber >= OVS_MAX_PORTS)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " invalid port number!\n");
        return FALSE;
    }

    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PopMpls(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PushMpls(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " verification not yet implemented\n");
    return FALSE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PushVlan(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    const OVS_ACTION_PUSH_VLAN* pPushVlanAction = pArg->data;
    if (pPushVlanAction->protocol != RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        return FALSE;
    }

    if (!(pPushVlanAction->vlanTci & RtlUshortByteSwap(OVS_VLAN_TAG_PRESENT)))
    {
        return FALSE;
    }

    DEBUGP_ARG(LOG_LOUD, __FUNCTION__ " verification not yet implemented\n");
    return TRUE;
}

static __inline BOOLEAN _VerifyArg_PacketActions_PopVlan(OVS_ARGUMENT* pArg)
{
    UNREFERENCED_PARAMETER(pArg);

    if (pArg->length > 0)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg len > 0\n");
        return FALSE;
    }

    if (pArg->data)
    {
        DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " arg data != null\n");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN VerifyGroup_PacketActions(OVS_ARGUMENT* pParentArg, BOOLEAN isRequest)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    pGroup = pParentArg->data;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_ACTIONS_UPCALL:
            if (!_VerifyGroup_PacketActionsUpcall(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_SAMPLE:
            if (!_VerifyGroup_PacketActionsSample(pArg, isRequest))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_ACTIONS_SETINFO:
        {
            OVS_ARGUMENT_GROUP* pSetGroup = pArg->data;
            if (pSetGroup->count > 1)
            {
                DEBUGP_ARG(LOG_ERROR, "only one key can be set using a set action. count keys to set: %d\n", pSetGroup->count);
                return FALSE;
            }

            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, isRequest, /*parent*/ pArg, /*check transport layer*/ FALSE, /*seek ip*/ FALSE))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT:
            if (!_VerifyArg_PacketActions_OutToPort(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_POP_MPLS:
            if (!_VerifyArg_PacketActions_PopMpls(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_POP_VLAN:
            if (!_VerifyArg_PacketActions_PopVlan(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_PUSH_MPLS:
            if (!_VerifyArg_PacketActions_PushMpls(pArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_ACTION_PUSH_VLAN:
            if (!_VerifyArg_PacketActions_PushVlan(pArg))
            {
                return FALSE;
            }
            break;

        default:
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN VerifyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    OVS_CHECK(pGroup);

    VerifyArgGroupSize(pGroup);
    if (!VerifyArgNoDuplicates(pGroup, groupType))
    {
        return FALSE;
    }

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;

        if (IsArgTypeGroup(pArg->type))
        {
            if (!VerifyArgumentGroup(pArg->data, pArg->type))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOLEAN VerifyArgNoDuplicates(OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    UNREFERENCED_PARAMETER(groupType);

    if (0 == pGroup->count)
    {
        return TRUE;
    }

    for (UINT16 i = 0; i < pGroup->count - 1; ++i)
    {
        OVS_ARGUMENT* pArgL = pGroup->args + i;

        for (UINT16 j = i + 1; j < pGroup->count; ++j)
        {
            OVS_ARGUMENT* pArgR = pGroup->args + j;

            if (pArgL->type == pArgR->type)
            {
                //we allow multiple 'out to port' and 'set info' actions.
                //we do not allow other duplicate arguments.
                if (pArgL->type != OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT ||
                    pArgL->type == OVS_ARGTYPE_GROUP_ACTIONS_SETINFO)
                {
                    DEBUGP_ARG(LOG_ERROR, "found duplicate: arg type: 0x%x; group: 0x%x\n", pArgL->type, groupType);
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}