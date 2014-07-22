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
    case OVS_ARGTYPE_PACKET_BUFFER:
        //any size can be expected!
        *pSize = MAXUINT;
        return TRUE;

    case OVS_ARGTYPE_PACKET_USERDATA:
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
    if (IsArgTypeGroup(childArgType))
    {
        switch (childArgType)
        {
        case OVS_ARGTYPE_FLOW_PI_GROUP:
        case OVS_ARGTYPE_FLOW_MASK_GROUP:
            return OVS_ARGTYPE_PSEUDOGROUP_FLOW;

        case OVS_ARGTYPE_PI_ENCAP_GROUP:
        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            return OVS_ARGTYPE_FLOW_PI_GROUP;

        case OVS_ARGTYPE_PACKET_ACTIONS_GROUP:
        case OVS_ARGTYPE_PACKET_PI_GROUP:
            return OVS_ARGTYPE_PSEUDOGROUP_PACKET;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            return OVS_ARGTYPE_FLOW_ACTIONS_GROUP;

        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
        case OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY:
            return OVS_ARGTYPE_ACTION_SAMPLE_GROUP;

        case OVS_ARGTYPE_OFPORT_OPTIONS_GROUP:
            return OVS_ARGTYPE_PSEUDOGROUP_OFPORT;

        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            return OVS_ARGTYPE_INVALID;

        default:
            OVS_CHECK(__UNEXPECTED__);
        }
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTION && childArgType <= OVS_ARGTYPE_LAST_ACTION)
    {
        return OVS_ARGTYPE_FLOW_ACTIONS_GROUP;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTION_SAMPLE && childArgType <= OVS_ARGTYPE_LAST_ACTION_SAMPLE)
    {
        return OVS_ARGTYPE_ACTION_SAMPLE_GROUP;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_ACTION_UPCALL && childArgType <= OVS_ARGTYPE_LAST_ACTION_UPCALL)
    {
        return OVS_ARGTYPE_ACTION_UPCALL_GROUP;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_DATAPATH && childArgType <= OVS_ARGTYPE_LAST_DATAPATH)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_DATAPATH;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_FLOW && childArgType <= OVS_ARGTYPE_LAST_FLOW)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_FLOW;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_PI && childArgType <= OVS_ARGTYPE_LAST_PI)
    {
        return OVS_ARGTYPE_FLOW_PI_GROUP;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_PI_TUNNEL && childArgType <= OVS_ARGTYPE_LAST_PI_TUNNEL)
    {
        return OVS_ARGTYPE_PI_TUNNEL_GROUP;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_PACKET&& childArgType <= OVS_ARGTYPE_LAST_PACKET)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_PACKET;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_OFPORT && childArgType <= OVS_ARGTYPE_LAST_OFPORT)
    {
        return OVS_ARGTYPE_PSEUDOGROUP_OFPORT;
    }
    else if (childArgType >= OVS_ARGTYPE_FIRST_OFPORT_OPTION && childArgType <= OVS_ARGTYPE_LAST_OFPORT_OPTION)
    {
        return OVS_ARGTYPE_OFPORT_OPTIONS_GROUP;
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

    case OVS_ARGTYPE_FLOW_PI_GROUP:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_FLOW_MASK_GROUP:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PI_ENCAP_GROUP:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PI_TUNNEL_GROUP:
        return _GetFlowKeyTunnelArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
        return _GetPacketArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
    case OVS_ARGTYPE_PACKET_ACTIONS_GROUP:
    case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
        return _GetPacketActionsArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
        return _GetPacketActionUpcallArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
        return _GetPacketActionSampleArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
        return _GetPIArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
        return _GetDatapathArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
        return _GetOFPortArgExpectedSize(argumentType, pSize);

    case OVS_ARGTYPE_OFPORT_OPTIONS_GROUP:
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

VOID DestroyOrFreeArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry, BOOLEAN destroy)
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
        if (destroy)
        {
            DestroyArgument(pArgListCur->pArg);
        }
        else
        {
            KFree(pArgListCur->pArg);
        }

        //2. free the list entry
        KFree(pArgListCur);

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
        DestroyOrFreeArgList(ppHeadArg, /*destroy*/ FALSE);
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
    case OVS_ARGTYPE_PACKET_BUFFER:
        DEBUGP_ARG(LOG_INFO, "PACKET: BUFFER\n");
        break;

    case OVS_ARGTYPE_PACKET_USERDATA:
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

        case OVS_ARGTYPE_FLOW_PI_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY\n");
            break;

        case OVS_ARGTYPE_PACKET_PI_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/PI\n");
            break;

        case OVS_ARGTYPE_FLOW_MASK_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY MASKS\n");

            break;
        case OVS_ARGTYPE_PI_ENCAP_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/PACKET ENCAPSULATION\n");
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/KEY/TUNNEL\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET\n");
            break;

        case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: FLOW/ACTIONS\n");
            break;

        case OVS_ARGTYPE_PACKET_ACTIONS_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: PACKET/ACTIONS\n");
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: ACTIONS/SAMPLE/ACTIONS\n");
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: <FLOW/PACKET>/ACTIONS/UPCALL\n");
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: <FLOW/PACKET>/ACTIONS/SAMPLE\n");
            break;

            //contains packet info args to set
        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            DEBUGP_ARG(LOG_INFO, "GROUP: <FLOW/PACKET>/ACTIONS/SET INFO\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
            DEBUGP_ARG(LOG_INFO, "GROUP: DATAPATH\n");
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
            DEBUGP_ARG(LOG_INFO, "GROUP: OF PORT\n");
            break;

        case OVS_ARGTYPE_OFPORT_OPTIONS_GROUP:
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
        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
            _DbgPrintArgType_Flow(argType);
            break;

        case OVS_ARGTYPE_FLOW_PI_GROUP:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_PACKET_PI_GROUP:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_FLOW_MASK_GROUP:
            _DbgPrintArgType_PacketInfo(argType);

            break;
        case OVS_ARGTYPE_PI_ENCAP_GROUP:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_PI_TUNNEL_GROUP:
            _DbgPrintArgType_PITunnel(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            _DbgPrintArgType_Packet(argType);
            break;

        case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
        case OVS_ARGTYPE_PACKET_ACTIONS_GROUP:
        case OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP:
            _DbgPrintArgType_PacketActions(argType);
            break;

        case OVS_ARGTYPE_ACTION_UPCALL_GROUP:
            _DbgPrintArgType_PacketActionsUpcall(argType);
            break;

        case OVS_ARGTYPE_ACTION_SAMPLE_GROUP:
            _DbgPrintArgType_PacketActionsSample(argType);
            break;

            //contains packet info args to set
        case OVS_ARGTYPE_ACTION_SETINFO_GROUP:
            _DbgPrintArgType_PacketInfo(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
            _DbgPrintArgType_Datapath(argType);
            break;

        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
            _DbgPrintArgType_OFPort(argType);
            break;

        case OVS_ARGTYPE_OFPORT_OPTIONS_GROUP:
            _DbgPrintArgType_OFPortOptions(argType);
            break;

        default: OVS_CHECK(0);
        }
    }
}