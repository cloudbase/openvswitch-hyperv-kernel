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

#include "WinlDatapath.h"
#include "OFDatapath.h"
#include "OFPort.h"
#include "List.h"
#include "Message.h"
#include "ArgumentType.h"
#include "WinlDevice.h"
#include "Winetlink.h"
#include "Error.h"
#include "PersistentPort.h"
#include "Sctx_Nic.h"
#include "OFFlowTable.h"

#include <Netioapi.h>

_Use_decl_annotations_
OVS_ERROR Datapath_New(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH* pDatapath = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ARGUMENT* pArgName = NULL, *pArgUpcallPid = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    ULONG dpNameLen = 0;
    UINT32 upcallPid = 0;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    pArgName = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_NAME);
    if (!pArgName)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    pArgUpcallPid = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID);
    if (!pArgUpcallPid)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    upcallPid = GET_ARG_DATA(pArgUpcallPid, UINT32);

    DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    if (!pDatapath->deleted || pDatapath->name)
    {
        KFree(pDatapath->name);
    }

    pDatapath->deleted = FALSE;

    dpNameLen = (ULONG)strlen(pArgName->data) + 1;

    pDatapath->name = KAlloc(dpNameLen);
    if (!pDatapath->name)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    RtlCopyMemory(pDatapath->name, pArgName->data, dpNameLen);

    DATAPATH_UNLOCK(pDatapath, &lockState);

    if (0 == pDatapath->switchIfIndex)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    if (!CreateMsgFromDatapath(pDatapath, pMsg->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pDatapath->switchIfIndex, pMsg->pid))
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
        replyMsg.pArgGroup = NULL;

        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Datapath_Delete(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_DATAPATH *pDatapath = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    DEBUGP(LOG_ERROR, "cannot delete datapath: we must always have one!\n");

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);

    if (pDatapath->deleted || !pDatapath->name)
    {
        DATAPATH_UNLOCK(pDatapath, &lockState);

        DEBUGP(LOG_ERROR, "expected the datapath not to exist");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    RtlZeroMemory(&replyMsg, sizeof(replyMsg));
    if (!CreateMsgFromDatapath(pDatapath, pMsg->sequence, OVS_MESSAGE_COMMAND_DELETE, &replyMsg, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
    }

    DATAPATH_UNLOCK(pDatapath, &lockState);

    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

    if (pMsg->flags & OVS_MESSAGE_FLAG_DUMP)
    {
        replyMsg.type = OVS_MESSAGE_TARGET_DUMP_DONE;
    }

    replyMsg.command = OVS_MESSAGE_COMMAND_NEW;
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE_ONLY(pDatapath);
    OVS_REFCOUNT_DESTROY(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Datapath_Get(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_DATAPATH *pDatapath = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    RtlZeroMemory(&replyMsg, sizeof(replyMsg));
    if (!CreateMsgFromDatapath(pDatapath, pMsg->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    if (pMsg->flags & OVS_MESSAGE_FLAG_DUMP)
    {
        replyMsg.type = OVS_MESSAGE_TARGET_DUMP_DONE;
    }

    replyMsg.command = OVS_MESSAGE_COMMAND_NEW;
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Datapath_Set(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH *pDatapath = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    DEBUGP(LOG_ERROR, "setting dp has no meaning!\n");
    OVS_CHECK(0);

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    if (!CreateMsgFromDatapath(pDatapath, pMsg->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Datapath_Dump(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH* pDatapath = NULL;
    OVS_MESSAGE replyMsg = { 0 }, *msgs = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    if (!pDatapath->deleted)
    {
        if (!CreateMsgFromDatapath(pDatapath, pMsg->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pDatapath->switchIfIndex, pMsg->pid))
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        replyMsg.flags |= OVS_MESSAGE_FLAG_MULTIPART;

        msgs = KAlloc(2 * sizeof(OVS_MESSAGE));
        if (!msgs)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        msgs[0] = replyMsg;
        msgs[1] = replyMsg;

        msgs[1].type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgs[1].pArgGroup = NULL;
        msgs[1].length = sizeof(OVS_MESSAGE_DONE);

        OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);
        error = WriteMsgsToDevice((OVS_NLMSGHDR*)msgs, 2, pFileObject, OVS_MULTICAST_GROUP_NONE);

        DestroyArgumentGroup(replyMsg.pArgGroup);

        KFree(msgs);
    }
    else
    {
        replyMsg.type = OVS_MESSAGE_TARGET_DUMP_DONE;
        replyMsg.command = OVS_MESSAGE_COMMAND_NEW;
        replyMsg.sequence = pMsg->sequence;
        replyMsg.dpIfIndex = pDatapath->switchIfIndex;
        replyMsg.flags = 0;
        replyMsg.pArgGroup = NULL;
        replyMsg.length = sizeof(OVS_MESSAGE_DONE);
        replyMsg.pid = pMsg->pid;
        replyMsg.reserved = 0;
        replyMsg.version = 1;

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return error;
}