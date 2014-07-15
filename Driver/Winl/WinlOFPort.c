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

#include "WinlOFPort.h"
#include "OvsCore.h"
#include "OFPort.h"
#include "OFDatapath.h"
#include "List.h"
#include "Argument.h"
#include "Message.h"
#include "ArgumentType.h"
#include "WinlDevice.h"
#include "Winetlink.h"
#include "Vxlan.h"
#include "Gre.h"
#include "NdisFilter.h"
#include "Sctx_Nic.h"
#include "PersistentPort.h"
#include "Error.h"

typedef struct _PORT_FETCH_CTXT{
    OVS_MESSAGE* pReplyMsg;
    UINT sequence;
    UINT dpIfIndex;
    UINT pid;
}PORT_FETCH_CTXT;

/************************/
static BOOLEAN _OFPort_GroupToOptions(_In_ const OVS_ARGUMENT_GROUP* pOptionsArgs, _Inout_ OVS_TUNNELING_PORT_OPTIONS* pOptions)
{
    OVS_ARGUMENT* pArg = NULL;

    OVS_CHECK(pOptions);

    if (!pOptionsArgs)
    {
        return FALSE;
    }

    pArg = FindArgument(pOptionsArgs, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT);
    if (pArg)
    {
        pOptions->optionsFlags |= OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT;
        //TODO: BE or LE?
        pOptions->udpDestPort = GET_ARG_DATA(pArg, UINT16);
    }

    return TRUE;
}

static DWORD _CountBits(DWORD value)
{
    DWORD count = 0;
    for (DWORD i = 0; i < sizeof(DWORD) * 8; i++)
    {
        DWORD bit = (value >> i);
        bit &= 1;

        count += bit;
    }

    return count;
}

static OVS_ARGUMENT_GROUP* _OFPort_OptionsToGroup(_In_ const OVS_TUNNELING_PORT_OPTIONS* pOptions)
{
    UINT16 countArgs = 0;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    OVS_ARGUMENT* pArg = NULL;
    UINT16 i = 0;

    if (!pOptions)
    {
        return NULL;
    }

    countArgs = (UINT16)_CountBits(pOptions->optionsFlags);
    pOptionsGroup = AllocArgumentGroup();

    if (!pOptionsGroup)
    {
        return NULL;
    }

    AllocateArgumentsToGroup(countArgs, pOptionsGroup);

    if (pOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT)
    {
        pArg = pOptionsGroup->args + i;

        ok = SetArgument_Alloc(pArg, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, &pOptions->udpDestPort);

        if (!ok)
        {
            goto Cleanup;
        }

        pOptionsGroup->groupSize += pArg->length;
        ++i;
    }

Cleanup:
    if (!ok)
    {
        DestroyArgumentsFromGroup(pOptionsGroup);
    }

    return pOptionsGroup;
}
/************************/

static BOOLEAN _CreateMsgFromPersistentPort(int i, _In_ const OVS_PERSISTENT_PORT* pPort, PORT_FETCH_CTXT* pContext)
{
    OVS_WINL_PORT port;
    BOOLEAN ok = TRUE;
    OVS_MESSAGE replyMsg = { 0 };

    UNREFERENCED_PARAMETER(i);

    RtlZeroMemory(&port, sizeof(OVS_WINL_PORT));
    port.number = pPort->ovsPortNumber;
    port.pOptions = _OFPort_OptionsToGroup(pPort->pOptions);
    port.type = pPort->ofPortType;
    port.name = pPort->ovsPortName;
    port.stats = pPort->stats;
    port.upcallId = pPort->upcallPortId;

    ok = CreateMsgFromOFPort(&port, pContext->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pContext->dpIfIndex, pContext->pid);
    if (!ok)
    {
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    replyMsg.flags |= OVS_MESSAGE_FLAG_MULTIPART;

    *(pContext->pReplyMsg + i) = replyMsg;
Cleanup:
    //NOTE: we must NOT destroy port.pOptions: it is destroy at replyMsg.pArgGroup destruction

    return ok;
}

_Use_decl_annotations_
OVS_ERROR OFPort_New(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH* pDatapath = NULL;
    UINT32 portNumber = OVS_INVALID_PORT_NUMBER;
    const char* ofPortName = NULL;
    UINT32 portType = 0, upcallPortId = 0;
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    OVS_PERSISTENT_PORT* pPersPort = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN locked = FALSE;

    //NAME: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    ofPortName = pArg->data;

    //TYPE: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    portType = GET_ARG_DATA(pArg, UINT32);

    //UPCALL PID: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    upcallPortId = GET_ARG_DATA(pArg, UINT32);

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    //NOTE: name is required; number is optional
    //NUMBER: optional
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
    if (pArg)
    {
        UINT16 validPortNumber = 0;
        portNumber = GET_ARG_DATA(pArg, UINT32);

        if (portNumber >= OVS_MAX_PORTS)
        {
            error = OVS_ERROR_FBIG;
            goto Cleanup;
        }

        validPortNumber = (UINT16)portNumber;

        pPersPort = PersPort_Create_Ref(ofPortName, &validPortNumber, portType);
        if (!pPersPort)
        {
            //TODO: perhaps we should give more specific error value
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }
    else
    {
        OVS_CHECK(ofPortName);

        pPersPort = PersPort_Create_Ref(ofPortName, /*number*/ NULL, portType);
        if (!pPersPort)
        {
            //TODO: perhaps we should give more specific error value
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;

    PORT_LOCK_READ(pPersPort, &lockState);
    locked = TRUE;

    pPersPort->ofPortType = portType;
    pPersPort->upcallPortId = upcallPortId;

    //OPTIONS: optional
    pOptionsGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_OFPORT_OPTIONS);
    if (pOptionsGroup)
    {
        if (!pPersPort->pOptions)
        {
            pPersPort->pOptions = KZAlloc(sizeof(OVS_TUNNELING_PORT_OPTIONS));
            if (!pPersPort->pOptions)
            {
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }
        }

        _OFPort_GroupToOptions(pOptionsGroup, pPersPort->pOptions);
    }

    //create OVS_MESSAGE from pPersPort
    if (!_CreateMsgFromPersistentPort(0, pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write reply message to buffer.
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        if (error != OVS_ERROR_NOERROR)
        {
            //NOTE: must be referenced when called for delete
            PersPort_Delete(pPersPort);
        }
        else
        {
            OVS_REFCOUNT_DEREFERENCE(pPersPort);
        }
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Set(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_PERSISTENT_PORT* pPersPort = NULL;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    UINT32 portType = OVS_OFPORT_TYPE_INVALID;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_ARGUMENT* pArg = NULL;
    LOCK_STATE_EX lockState = { 0 };
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT)-1;
    PORT_FETCH_CTXT context = { 0 };
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    BOOLEAN locked = FALSE;

    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u!\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    //TYPE: if set, must be the same as original
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    if (pArg)
    {
        portType = GET_ARG_DATA(pArg, UINT32);

        if (portType != (UINT32)pPersPort->ofPortType)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    PORT_LOCK_WRITE(pPersPort, &lockState);
    locked = TRUE;

    //OPTIONS: optional
    pOptionsGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_OFPORT_OPTIONS);
    if (pOptionsGroup)
    {
        if (!pPersPort->pOptions)
        {
            pPersPort->pOptions = KZAlloc(sizeof(OVS_TUNNELING_PORT_OPTIONS));
            if (!pPersPort->pOptions)
            {
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }
        }

        if (!_OFPort_GroupToOptions(pOptionsGroup, pPersPort->pOptions))
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    //UPCALL PORT ID: optional
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    if (pArg)
    {
        pPersPort->upcallPortId = GET_ARG_DATA(pArg, UINT32);
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;

    if (!_CreateMsgFromPersistentPort(0, pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        OVS_REFCOUNT_DEREFERENCE(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Get(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_PERSISTENT_PORT* pPersPort = NULL;
    OVS_ARGUMENT* pArg = NULL;
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT32)-1;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    BOOLEAN locked = FALSE;

    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u!\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;

    PORT_LOCK_READ(pPersPort, &lockState);
    locked = TRUE;

    //create message
    if (!_CreateMsgFromPersistentPort(0, pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        OVS_REFCOUNT_DEREFERENCE(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Delete(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ARGUMENT* pArg = NULL;
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT32)-1;
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    OVS_PERSISTENT_PORT* pPersPort = NULL;
    PORT_FETCH_CTXT context = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN locked = FALSE;

    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    if (pPersPort->ovsPortNumber == OVS_LOCAL_PORT_NUMBER)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;

    PORT_LOCK_WRITE(pPersPort, &lockState);
    locked = TRUE;

    //create mesasge
    if (!_CreateMsgFromPersistentPort(0, pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        PersPort_Delete(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Dump(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE *msgs = NULL;
    int i = 0, countMsgs = 1;
    LOCK_STATE_EX lockState = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        return OVS_ERROR_NODEV;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pid = pMsg->pid;

    pForwardInfo = pSwitchInfo->pForwardInfo;

    PERSPORTS_LOCK_READ(&pForwardInfo->persistentPortsInfo, &lockState);

    if (pForwardInfo->persistentPortsInfo.count > 0)
    {
        countMsgs += pForwardInfo->persistentPortsInfo.count;
        msgs = ExAllocatePoolWithTag(NonPagedPool, countMsgs * sizeof(OVS_MESSAGE), g_extAllocationTag);

        if (!msgs)
        {
            PERSPORTS_UNLOCK(&pForwardInfo->persistentPortsInfo, &lockState);

            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));
        context.pReplyMsg = msgs + i;

        if (!PersPort_CForEach_Unsafe(&pForwardInfo->persistentPortsInfo, &context, _CreateMsgFromPersistentPort))
        {
            error = OVS_ERROR_INVAL;
        }
    }

    PERSPORTS_UNLOCK(&pForwardInfo->persistentPortsInfo, &lockState);

    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

    //the last is dump done, so no ports means count == 1
    if (countMsgs > 1)
    {
        msgs[countMsgs - 1].type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgs[countMsgs - 1].pArgGroup = NULL;
        msgs[countMsgs - 1].length = sizeof(OVS_MESSAGE_DONE);

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)msgs, countMsgs, pFileObject, OVS_VPORT_MCGROUP);
    }
    else
    {
        OVS_MESSAGE msgDone = { 0 };

        OVS_CHECK(countMsgs == 1);

        msgDone.type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgDone.command = OVS_MESSAGE_COMMAND_NEW;
        msgDone.sequence = pMsg->sequence;
        msgDone.dpIfIndex = pDatapath->switchIfIndex;
        msgDone.flags = 0;
        msgDone.pArgGroup = NULL;
        msgDone.length = sizeof(OVS_MESSAGE_DONE);
        msgDone.pid = pMsg->pid;
        msgDone.reserved = 0;
        msgDone.version = 1;

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&msgDone, 1, pFileObject, OVS_VPORT_MCGROUP);
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    if (msgs)
    {
        for (i = 0; i < countMsgs; ++i)
        {
            OVS_MESSAGE* pMsg = msgs + i;

            if (pMsg->pArgGroup)
            {
                DestroyArgumentGroup(pMsg->pArgGroup);
                pMsg->pArgGroup = NULL;
            }
        }

        ExFreePoolWithTag(msgs, g_extAllocationTag);
    }

    return error;
}