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
#include "Argument.h"

#define FLAGS enum

typedef struct _OVS_BUFFER OVS_BUFFER;

//OVS_USERSPACE_PACKET_CMD_MISS is the userspace correspondent of the kernel ovs message type = OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS
#define OVS_USERSPACE_PACKET_CMD_MISS                 1
//OVS_USERSPACE_PACKET_CMD_ACTION is the correspondent of the kernel ovs message type = OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION
#define    OVS_USERSPACE_PACKET_CMD_ACTION            2
//OVS_USERSPACE_PACKET_CMD_EXECUTE is the correspondent of the kernel ovs message type = OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE
#define OVS_USERSPACE_PACKET_CMD_EXECUTE              3

#define OVS_VPORT_MCGROUP 33

typedef enum _OVS_MESSAGE_TARGET_TYPE
{
    OVS_MESSAGE_TARGET_RTM_GETROUTE = 0,
    OVS_MESSAGE_TARGET_NO_OPERATION = 1,
    OVS_MESSAGE_TARGET_ERROR = 2,
    OVS_MESSAGE_TARGET_DUMP_DONE = 3,
    OVS_MESSAGE_TARGET_OVERRUN = 4,

    OVS_MESSAGE_TARGET_CONTROL = 16,

    OVS_MESSAGE_TARGET_MULTICAST = 33,

    OVS_MESSAGE_TARGET_SET_FILE_PID = 80,

    OVS_MESSAGE_TARGET_FLOW = 90,
    OVS_MESSAGE_TARGET_DATAPATH,
    OVS_MESSAGE_TARGET_PORT,
    OVS_MESSAGE_TARGET_PACKET,

    OVS_MESSAGE_TARGET_INVALID = 0xFFFF
}OVS_MESSAGE_TARGET_TYPE;

typedef enum _OVS_MESSAGE_COMMAND_TYPE
{
    OVS_MESSAGE_COMMAND_INVALID,
    OVS_MESSAGE_COMMAND_NEW,
    OVS_MESSAGE_COMMAND_DELETE,
    OVS_MESSAGE_COMMAND_GET,
    OVS_MESSAGE_COMMAND_SET,
    OVS_MESSAGE_COMMAND_DUMP,
    //kernel-user notification: flow table miss
    OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS,
    //kernel-user notification: represents the action OVS_USPACE_ACTION_ATTRIBUTE_USERSPACE / OVS_ARGTYPE_PACKET_ACTIONS_UPCALL_GROUP
    OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION,
    //user space command: apply action to a packet
    OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE
}OVS_MESSAGE_COMMAND_TYPE;

typedef struct _OVS_NLMSGHDR
{
    //length of the message, including header
    UINT32 length;

    UINT16 type;

    UINT16 flags;

    //used to match replies with requests
    UINT32 sequence;

    UINT32 pid;
}OVS_NLMSGHDR;

C_ASSERT(16 == sizeof(OVS_NLMSGHDR));

typedef struct _OVS_NL_ATTRIBUTE
{
    UINT16 length;
    UINT16 type;
}OVS_NL_ATTRIBUTE;

//message from / to the user space
typedef struct _OVS_MESSAGE
{
    OVS_NLMSGHDR;

    //new / delete / get / set /dump / error
    UINT8 command;
    UINT8 version;
    UINT16 reserved;

    //OVS_HEADER
    UINT32 dpIfIndex;

    OVS_ARGUMENT_GROUP* pArgGroup;
}OVS_MESSAGE, *POVS_MESSAGE;

#define OVS_MESSAGE_HEADER_SIZE (sizeof(OVS_MESSAGE) - sizeof(OVS_ARGUMENT_GROUP*))

C_ASSERT(OVS_MESSAGE_HEADER_SIZE == 24);

//message to the userspace
typedef struct _OVS_MESSAGE_ERROR
{
    OVS_NLMSGHDR;

    int error;
    OVS_NLMSGHDR originalMsg;
}OVS_MESSAGE_ERROR, *POVS_MESSAGE_ERROR;

C_ASSERT(sizeof(OVS_MESSAGE_ERROR) == 36);

//message to the userspace
typedef struct _OVS_MESSAGE_DONE
{
    OVS_NLMSGHDR;
}OVS_MESSAGE_DONE, *POVS_MESSAGE_DONE;

C_ASSERT(sizeof(OVS_MESSAGE_DONE) == 16);

typedef struct _OVS_MESSAGE_ROUTE_TABLE
{
    OVS_NLMSGHDR;

    //e.g. AF_INET
    BYTE socketFamily;
}OVS_MESSAGE_ROUTE_TABLE;

typedef struct _OVS_MESSAGE_MULTICAST
{
    OVS_NLMSGHDR;

    //if true, join; if else, leave
    BOOLEAN join;
    UINT32 groupId;
}OVS_MESSAGE_MULTICAST;

//message from the user space
typedef struct _OVS_MESSAGE_SET_FILE_PID
{
    OVS_NLMSGHDR;
}OVS_MESSAGE_SET_FILE_PID, *POVS_MESSAGE_SET_FILE_PID;

C_ASSERT(sizeof(OVS_MESSAGE_DONE) == 16);

/**************************************/

static __inline BOOLEAN NlMsgIsGeneric(OVS_NLMSGHDR* pNlMsgHdr)
{
    OVS_CHECK(pNlMsgHdr);

    switch (pNlMsgHdr->type)
    {
    case OVS_MESSAGE_TARGET_FLOW:
    case OVS_MESSAGE_TARGET_DATAPATH:
    case OVS_MESSAGE_TARGET_PORT:
    case OVS_MESSAGE_TARGET_PACKET:
    case OVS_MESSAGE_TARGET_CONTROL:
        return TRUE;

    default:
        return FALSE;
    }
}

BOOLEAN ParseReceivedMessage(VOID* buffer, UINT16 length, _Out_ OVS_NLMSGHDR** ppNlMessage);

//pBuffer: must be non-null. pBuffer->buffer must be NULL
BOOLEAN WriteMsgsToBuffer(_In_ OVS_NLMSGHDR* pMsgs, int countMsgs, OVS_BUFFER* pBuffer);

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest);

static __inline OVS_NLMSGHDR* AdvanceMessage(_In_ const OVS_NLMSGHDR* pMsg)
{
    OVS_NLMSGHDR* pNextMsg = NULL;

    OVS_CHECK(pMsg->length >= sizeof(OVS_NLMSGHDR));

    pNextMsg = (OVS_NLMSGHDR*)((BYTE*)pMsg + pMsg->length);

    return pNextMsg;
}

static __inline ULONG KernelPacketCmdToUserspaceCmd(OVS_MESSAGE_COMMAND_TYPE cmd)
{
    ULONG resultCmd = 0;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS:
        resultCmd = OVS_USERSPACE_PACKET_CMD_MISS;
        break;

    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION:
        resultCmd = OVS_USERSPACE_PACKET_CMD_ACTION;
        break;

    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE:
        resultCmd = OVS_USERSPACE_PACKET_CMD_EXECUTE;
        break;

    default:
        OVS_CHECK(__UNEXPECTED__);
    }

    return resultCmd;
}

static __inline OVS_MESSAGE_COMMAND_TYPE UserspacePacketCmdToKernelCmd(ULONG cmd)
{
    OVS_MESSAGE_COMMAND_TYPE resultCmd = 0;

    switch (cmd)
    {
    case OVS_USERSPACE_PACKET_CMD_MISS:
        resultCmd = OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS;
        break;

    case OVS_USERSPACE_PACKET_CMD_ACTION:
        resultCmd = OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION;
        break;

    case OVS_USERSPACE_PACKET_CMD_EXECUTE:
        resultCmd = OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE;
        break;

    default:
        OVS_CHECK(__UNEXPECTED__);
    }

    return resultCmd;
}

VOID DestroyMessages(_Inout_ OVS_MESSAGE* msgs, UINT countMsgs);

