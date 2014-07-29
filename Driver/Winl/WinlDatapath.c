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
#include "List.h"
#include "Message.h"
#include "ArgumentType.h"
#include "WinlDevice.h"
#include "Winetlink.h"
#include "Error.h"
#include "OFPort.h"
#include "Sctx_Nic.h"
#include "OFFlowTable.h"

#include <Netioapi.h>

//NOTE: Assuming the verification part has done its job (arg & msg verification), we can use the input data as valid

static OVS_ERROR _Datapath_SetName(OVS_DATAPATH* pDatapath, const char* newName)
{
    ULONG dpNameLen = 0;

    if (!pDatapath->deleted)
    {
        KFree(pDatapath->name);
    }

    pDatapath->deleted = FALSE;

    dpNameLen = (ULONG)strlen(newName) + 1;

    pDatapath->name = KAlloc(dpNameLen);
    if (!pDatapath->name)
    {
        return OVS_ERROR_NOMEM;
    }

    RtlCopyMemory(pDatapath->name, newName, dpNameLen);

    return OVS_ERROR_NOERROR;
}

_Use_decl_annotations_
OVS_ERROR WinlDatapath_New(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ARGUMENT* pArgName = NULL, *pArgUpcallPid = NULL, *pUserFeaturesArg = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    UINT32 upcallPid = 0;
    BOOLEAN locked = FALSE;

    pArgName = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_NAME);
    OVS_CHECK(pArgName);

    pArgUpcallPid = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID);
    OVS_CHECK(pArgUpcallPid);

    upcallPid = GET_ARG_DATA(pArgUpcallPid, UINT32);

    DATAPATH_LOCK_WRITE(pDatapath, &lockState);
    locked = TRUE;
    
    CHECK_E(_Datapath_SetName(pDatapath, pArgName->data));
    CHECK_B_E(pDatapath->switchIfIndex, OVS_ERROR_NODEV);

    pUserFeaturesArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_USER_FEATURES);
    if (pUserFeaturesArg)
    {
        pDatapath->userFeatures = GET_ARG_DATA(pUserFeaturesArg, UINT32);
    }
    
    DATAPATH_UNLOCK(pDatapath, &lockState);
    locked = FALSE;

    //TODO: should we set pMsg->dpIfIndex to pDatapath->switchIfIndex?
    CHECK_E(CreateMsgFromDatapath(pDatapath, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);

    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DATAPATH_UNLOCK_IF(pDatapath, &lockState, locked);
    DestroyArgumentGroup(replyMsg.pArgGroup);
    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlDatapath_Delete(OVS_DATAPATH** ppDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_DATAPATH* pDatapath = *ppDatapath;

    DATAPATH_LOCK_READ(pDatapath, &lockState);

    if (pDatapath->deleted || !pDatapath->name)
    {
        DATAPATH_UNLOCK(pDatapath, &lockState);

        DEBUGP(LOG_ERROR, "expected the datapath to exist");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    RtlZeroMemory(&replyMsg, sizeof(replyMsg));
    CHECK_E(CreateMsgFromDatapath(pDatapath, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_DELETE));

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

    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    OVS_REFCOUNT_DEREF_AND_DESTROY(pDatapath);
    *ppDatapath = NULL;

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlDatapath_Get(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    RtlZeroMemory(&replyMsg, sizeof(replyMsg));
    CHECK_E(CreateMsgFromDatapath(pDatapath, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));

    if (pMsg->flags & OVS_MESSAGE_FLAG_DUMP)
    {
        replyMsg.type = OVS_MESSAGE_TARGET_DUMP_DONE;
    }

    replyMsg.command = OVS_MESSAGE_COMMAND_NEW;

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);
    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlDatapath_Set(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_ARGUMENT* pUserFeaturesArg = NULL;
    LOCK_STATE_EX lockState = { 0 };

    DEBUGP(LOG_WARN, "setting dp has no meaning!\n");

    DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    if (pUserFeaturesArg)
    {
        pDatapath->userFeatures = GET_ARG_DATA(pUserFeaturesArg, UINT32);
    }

    DATAPATH_UNLOCK(pDatapath, &lockState);

    CHECK_E(CreateMsgFromDatapath(pDatapath, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_DATAPATH);
    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlDatapath_Dump(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 }, *msgs = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (!pDatapath->deleted)
    {
        CHECK_E(CreateMsgFromDatapath(pDatapath, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));

        replyMsg.flags |= OVS_MESSAGE_FLAG_MULTIPART;

        msgs = KAlloc(2 * sizeof(OVS_MESSAGE));
        CHECK_B_E(msgs, OVS_ERROR_NOMEM);

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
        CHECK_E(CreateReplyMsgDone(pMsg, &replyMsg, sizeof(OVS_MESSAGE_DONE), OVS_MESSAGE_COMMAND_NEW));

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    }

Cleanup:
    return error;
}