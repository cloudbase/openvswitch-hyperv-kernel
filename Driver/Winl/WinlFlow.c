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

#include "WinlFlow.h"
#include "OvsCore.h"
#include "OFFlow.h"
#include "OFDatapath.h"
#include "PacketInfo.h"
#include "OFAction.h"
#include "Argument.h"
#include "WinlDevice.h"
#include "MessageToFlowMatch.h"
#include "Message.h"
#include "FlowToMessage.h"
#include "Argument.h"
#include "ArgumentType.h"
#include "Winetlink.h"
#include "Attribute.h"
#include "Error.h"
#include "OFFlowTable.h"
#include "Winetlink.h"

_Use_decl_annotations_
OVS_ERROR Flow_New(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_ARGUMENT* pFlowActionGroupArg = NULL;
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL, *pPacketInfoMaskArgs = NULL;
    OVS_OFPACKET_INFO packetInfo = { 0 }, maskedPacketInfo = { 0 };
    OVS_FLOW* pFlow = NULL;
    OVS_FLOW_MASK flowMask = { 0 };
    OVS_MESSAGE replyMsg = { 0 };
    OVS_DATAPATH* pDatapath = NULL;
    OVS_FLOW_TABLE* pFlowTable = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    BOOLEAN flowWasCreated = TRUE;
    OVS_ACTIONS* pActions = NULL;

    /*** get flow info from message ***/
    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
    if (!pPacketInfoArgs)
    {
        DEBUGP(LOG_ERROR, "flow create fail: no Packet Info arg!\n");
        return OVS_ERROR_INVAL;
    }

    //OVS_ARGTYPE_GROUP_MASK is optional
    pPacketInfoMaskArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MASK);

    FlowMatch_Initialize(&flowMatch, &packetInfo, &flowMask);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, pPacketInfoMaskArgs))
    {
        DEBUGP(LOG_ERROR, "flow create fail: flow match!\n");
        return OVS_ERROR_INVAL;
    }

    pFlowActionGroupArg = FindArgumentGroupAsArg(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (pFlowActionGroupArg)
    {
        OVS_ARGUMENT_GROUP* pOriginalGroup = pFlowActionGroupArg->data;

        pActions = Actions_Create();
        if (NULL == pActions)
        {
            DEBUGP(LOG_ERROR, "flow create fail: create actions!\n");
            return OVS_ERROR_INVAL;
        }

        ApplyMaskToPacketInfo(&maskedPacketInfo, &packetInfo, &flowMask);

        if (!CopyArgumentGroup(pActions->pActionGroup, pOriginalGroup, /*actionsToAdd*/0))
        {
            DEBUGP(LOG_ERROR, "flow create fail: copy actions!\n");

            Actions_DestroyNow_Unsafe(pActions);
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (!ProcessReceivedActions(pActions->pActionGroup, &maskedPacketInfo, /*recursivity depth*/0))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " failed processing the received actions!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }
    else
    {
        DEBUGP(LOG_ERROR, "flow create fail: have no actions arg!\n");
        return OVS_ERROR_INVAL;
    }

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        DEBUGP(LOG_ERROR, "flow create fail: no datapath!\n");
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    OVS_CHECK(pFlowTable);

    /*** process data ***/
    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pFlowTable, &packetInfo);
    if (!pFlow)
    {
        /*** create new flow ***/
        OVS_FLOW_MASK* pFlowMask = NULL;

        pFlow = Flow_Create();
        if (!pFlow)
        {
            DEBUGP(LOG_ERROR, "flow create fail: Flow_Create!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        pFlow = OVS_REFCOUNT_REFERENCE(pFlow);
        OVS_CHECK(pFlow);

        Flow_ClearStats_Unsafe(pFlow);

        pFlow->unmaskedPacketInfo = packetInfo;
        pFlow->maskedPacketInfo = maskedPacketInfo;

        pFlowMask = FlowTable_FindFlowMask(pFlowTable, &flowMask);
        if (!pFlowMask)
        {
            pFlowMask = FlowMask_Create();
            if (!pFlowMask)
            {
                DEBUGP(LOG_ERROR, "flow mask creation failed!\n");
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }

            pFlowMask->packetInfo = flowMask.packetInfo;
            pFlowMask->piRange = flowMask.piRange;

            FlowTable_InsertFlowMask(pFlowTable, pFlowMask);
        }

        ++pFlowMask->refCount;
        pFlow->pMask = pFlowMask;
        pFlow->pActions = pActions;

        DBGPRINT_FLOW(LOG_LOUD, "flow created: ", pFlow);
        FlowTable_InsertFlow_Unsafe(pFlowTable, pFlow);
    }
    else
    {
        OVS_ACTIONS* pOldActions = NULL;
        LOCK_STATE_EX lockState = { 0 };
        flowWasCreated = FALSE;

        //if we have cmd = new with the flag 'exclusive', it means we're not allowed to override existing flows.
        //the flag 'create' is accepted as well: 'create' may be set instead of 'exclusive'
        if (pMsg->flags & OVS_MESSAGE_FLAG_CREATE &&
            pMsg->flags & OVS_MESSAGE_FLAG_EXCLUSIVE)
        {
            FLOW_LOCK_READ(pFlow, &lockState);
            DBGPRINT_FLOW(LOG_LOUD, "flow create/set failed (EXISTS but Create & Exclusive): ", pFlow);
            FLOW_UNLOCK(pFlow, &lockState);

            error = OVS_ERROR_EXIST;
            goto Cleanup;
        }

        /*** set existing flow ***/

        FLOW_LOCK_READ(pFlow, &lockState);

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &packetInfo, flowMatch.piRange.endRange))
        {
            DBGPRINT_FLOW(LOG_LOUD, "flow create/set failed (flow does not match the unmasked key): ", pFlow);

            FLOW_UNLOCK(pFlow, &lockState);

            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        //the old actions may be in use at the moment (e.g. execute actions on packet)
        //so we remove it from flow now, but will possibly destroy it (the actions struct) later
        pOldActions = pFlow->pActions;
        pFlow->pActions = pActions;

        DBGPRINT_FLOW(LOG_LOUD, "flow create/set: ", pFlow);

        FLOW_UNLOCK(pFlow, &lockState);
        //the pFlow does not become invalidated between locks, because it's referenced
        FLOW_LOCK_WRITE(pFlow, &lockState);

        OVS_REFCOUNT_DESTROY(pOldActions);

        if (FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_CLEAR))
        {
            Flow_ClearStats_Unsafe(pFlow);
        }
    }

    /*** reply ***/
    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        DEBUGP(LOG_ERROR, "flow new fail: create msg!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);

    if (error == OVS_ERROR_NOERROR)
    {
        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
        if (error != OVS_ERROR_NOERROR)
        {
            DEBUGP(LOG_ERROR, "flow new fail: buffer write!\n");

            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    /*** cleanup ***/
Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    if (error != OVS_ERROR_NOERROR)
    {
        if (flowWasCreated)
        {
            if (pFlow)
            {
                Flow_DestroyNow_Unsafe(pFlow);
                pFlow = NULL;
            }
        }

        if (pActions)
        {
            Actions_DestroyNow_Unsafe(pActions);
            pActions = NULL;
        }
    }

    OVS_REFCOUNT_DEREFERENCE(pFlow);
    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Flow_Set(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_ARGUMENT* pFlowActionGroupArg = NULL;
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL, *pPacketInfoMaskArgs = NULL;
    OVS_OFPACKET_INFO packetInfo = { 0 }, maskedPacketInfo = { 0 };
    OVS_FLOW* pFlow = NULL;
    OVS_FLOW_MASK flowMask = { 0 };
    OVS_MESSAGE replyMsg = { 0 };
    OVS_DATAPATH* pDatapath = NULL;
    OVS_FLOW_TABLE* pFlowTable = NULL;
    OVS_ACTIONS* pActions = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    /*** get flow info from message ***/
    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
    if (!pPacketInfoArgs)
    {
        DEBUGP(LOG_ERROR, "flow set fail: no Packet Info arg!\n");
        return OVS_ERROR_INVAL;
    }

    //OVS_ARGTYPE_GROUP_MASK is optional
    pPacketInfoMaskArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MASK);

    FlowMatch_Initialize(&flowMatch, &packetInfo, &flowMask);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, pPacketInfoMaskArgs))
    {
        DEBUGP(LOG_ERROR, "flow set fail: flow match!\n");
        return OVS_ERROR_INVAL;
    }

    pFlowActionGroupArg = FindArgumentGroupAsArg(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (pFlowActionGroupArg)
    {
        OVS_ARGUMENT_GROUP* pOriginalGroup = pFlowActionGroupArg->data;

        ApplyMaskToPacketInfo(&maskedPacketInfo, &packetInfo, &flowMask);

        pActions = Actions_Create();
        if (NULL == pActions)
        {
            DEBUGP(LOG_ERROR, "flow set fail: actions create!\n");
            return OVS_ERROR_INVAL;
        }

        if (!CopyArgumentGroup(pActions->pActionGroup, pOriginalGroup, /*actionsToAdd*/0))
        {
            DEBUGP(LOG_ERROR, "flow set fail: copy  actions!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (!ProcessReceivedActions(pActions->pActionGroup, &maskedPacketInfo, /*recursivity depth*/0))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " failed processing the received actions.\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        DEBUGP(LOG_ERROR, "flow set fail: no datapath!\n");
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    OVS_CHECK(pFlowTable);

    /*** process data ***/
    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pFlowTable, &packetInfo);
    if (!pFlow)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " we were asked to set a flow that does not exist!\n");
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }
    else
    {
        OVS_ACTIONS* pOldActions = NULL;
        LOCK_STATE_EX lockState = { 0 };

        /*** set existing flow ***/

        FLOW_LOCK_READ(pFlow, &lockState);

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &packetInfo, flowMatch.piRange.endRange))
        {
            FLOW_UNLOCK(pFlow, &lockState);

            DBGPRINT_FLOW(LOG_ERROR, "flow set FAIL: unmasked): ", pFlow);

            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        pOldActions = pFlow->pActions;
        pFlow->pActions = pActions;

        DBGPRINT_FLOW(LOG_LOUD, "flow set: ", pFlow);

        FLOW_UNLOCK(pFlow, &lockState);
        //the pFlow does not become invalidated between locks, because it's referenced
        FLOW_LOCK_WRITE(pFlow, &lockState);

        OVS_REFCOUNT_DESTROY(pOldActions);

        if (FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_CLEAR))
        {
            Flow_ClearStats_Unsafe(pFlow);
        }

        FLOW_UNLOCK(pFlow, &lockState);
    }

    /*** reply ***/
    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        DEBUGP(LOG_ERROR, "flow set fail: create msg!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);
    OVS_CHECK(error == OVS_ERROR_NOERROR);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        DEBUGP(LOG_ERROR, "flow set fail: buffer write!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    /*** cleanup ***/
Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    OVS_REFCOUNT_DEREFERENCE(pFlow);
    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (error != OVS_ERROR_NOERROR)
    {
        if (pActions)
        {
            Actions_DestroyNow_Unsafe(pActions);
        }
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR Flow_Get(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_OFPACKET_INFO packetInfo = { 0 };
    OVS_FLOW *pFlow = NULL;
    OVS_DATAPATH *pDatapath = NULL;
    OVS_FLOW_TABLE *pFlowTable = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
    if (!pPacketInfoArgs)
    {
        DEBUGP(LOG_ERROR, "flow get fail: no Packet Info arg!\n");
        return OVS_ERROR_INVAL;
    }

    FlowMatch_Initialize(&flowMatch, &packetInfo, NULL);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, NULL))
    {
        DEBUGP(LOG_ERROR, "flow get fail: flow match!\n");
        return OVS_ERROR_INVAL;
    }

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        DEBUGP(LOG_ERROR, "flow get fail: no datapath!\n");
        return OVS_ERROR_NODEV;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    OVS_CHECK(pFlowTable);

    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pFlowTable, flowMatch.pPacketInfo);
    if (pFlow)
    {
        FLOW_LOCK_READ(pFlow, &lockState);

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, flowMatch.pPacketInfo, flowMatch.piRange.endRange))
        {
            FLOW_UNLOCK(pFlow, &lockState);

            pFlow = NULL;
        }
        else
        {
            FLOW_UNLOCK(pFlow, &lockState);
        }
    }

    if (!pFlow)
    {
        DEBUGP(LOG_ERROR, "flow get fail: flow not found!\n");
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        DEBUGP(LOG_ERROR, "flow get fail: create msg!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        DEBUGP(LOG_ERROR, "flow get fail: buffer write!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    OVS_REFCOUNT_DEREFERENCE(pFlow);
    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Flow_Delete(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_OFPACKET_INFO packetInfo = { 0 };
    OVS_FLOW* pFlow = NULL;
    OVS_DATAPATH* pDatapath = NULL;
    OVS_FLOW_TABLE* pFlowTable = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        DEBUGP(LOG_ERROR, "flow delete fail: no datapath!\n");
        return OVS_ERROR_NODEV;
    }

    if (pMsg->pArgGroup)
    {
        pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
        if (!pPacketInfoArgs)
        {
            DEBUGP(LOG_ERROR, "flow delete fail: no Packet Info arg!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }
    else
    {
        if (!Datapath_FlushFlows(pDatapath))
        {
            DEBUGP(LOG_ERROR, "flow 'delete all' failed!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        //must send reply = ok
        WriteErrorToDevice((OVS_NLMSGHDR*)pMsg, OVS_ERROR_NOERROR, pFileObject, OVS_MULTICAST_GROUP_NONE);

        goto Cleanup;
    }

    FlowMatch_Initialize(&flowMatch, &packetInfo, NULL);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, NULL))
    {
        DEBUGP(LOG_ERROR, "flow delete fail: flow match!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    OVS_CHECK(pFlowTable);

    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pFlowTable, flowMatch.pPacketInfo);
    if (pFlow)
    {
        FLOW_LOCK_READ(pFlow, &lockState);

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, flowMatch.pPacketInfo, flowMatch.piRange.endRange))
        {
            FLOW_UNLOCK(pFlow, &lockState);

            pFlow = NULL;
        }
        else
        {
            FLOW_UNLOCK(pFlow, &lockState);
        }
    }

    if (!pFlow)
    {
        DBGPRINT_FLOWMATCH(LOG_ERROR, "flow delete -- no flow: ", &flowMatch);
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_DELETE, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        DEBUGP(LOG_ERROR, "flow delete: create msg fail!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //NOTE: we can only delete the flow AFTER we reply: we need it to... write the reply
    FLOWTABLE_LOCK_WRITE(pFlowTable, &lockState);

    DBGPRINT_FLOW(LOG_LOUD, "flow delete: ", pFlow);

    //remove the flow from the list of flows
    FlowTable_RemoveFlow_Unsafe(pFlowTable, pFlow);

    OVS_REFCOUNT_DEREF_AND_DESTROY(pFlow);

    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        DEBUGP(LOG_ERROR, "flow delete fail: buffer write!\n");
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    OVS_REFCOUNT_DEREFERENCE(pFlow);
    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Flow_Dump(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH *pDatapath = NULL;
    OVS_FLOW_TABLE *pFlowTable = NULL;
    OVS_MESSAGE* msgs = NULL;
    UINT countMsgs = 0;
    OVS_MESSAGE msgDone = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        DEBUGP(LOG_ERROR, "flow dump fail: no datapath!\n");
        return OVS_ERROR_NODEV;
    }

    pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    OVS_CHECK(pFlowTable);

    if (pFlowTable->countFlows > 0)
    {
        LIST_ENTRY* pCurItem = pFlowTable->pFlowList->Flink;
        UINT i = 0;
        LOCK_STATE_EX lockState = { 0 };

        countMsgs = pFlowTable->countFlows + 1;
        msgs = KZAlloc(countMsgs * sizeof(OVS_MESSAGE));
        if (!msgs)
        {
            DEBUGP(LOG_ERROR, "flow dump fail: could not alloc messages!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));

        FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

        while (pCurItem != pFlowTable->pFlowList)
        {
            OVS_FLOW* pFlow = CONTAINING_RECORD(pCurItem, OVS_FLOW, listEntry);
            OVS_MESSAGE* pReplyMsg = msgs + i;

            if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, pReplyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
            {
                FLOWTABLE_UNLOCK(pFlowTable, &lockState);

                DEBUGP(LOG_ERROR, "flow dump fail: create msg!\n");
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }

            OVS_CHECK(pReplyMsg->type == OVS_MESSAGE_TARGET_FLOW);
            pReplyMsg->flags |= OVS_MESSAGE_FLAG_MULTIPART;

            ++i;
            pCurItem = pCurItem->Flink;
        }

        FLOWTABLE_UNLOCK(pFlowTable, &lockState);

        //there must be room for one more message: the dump done message
        OVS_CHECK(i == countMsgs - 1);
        msgDone = *(msgs + 0);

        msgDone.type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgDone.pArgGroup = NULL;
        msgDone.length = sizeof(OVS_MESSAGE_DONE);

        *(msgs + i) = msgDone;

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)msgs, countMsgs, pFileObject, OVS_MULTICAST_GROUP_NONE);
    }

    //if we have no flow, write only "done"
    else
    {
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

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&msgDone, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    }

    if (error != OVS_ERROR_NOERROR)
    {
        DEBUGP(LOG_ERROR, "flow dump fail: buffer write!\n");
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pFlowTable);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyMessages(msgs, countMsgs);

    return error;
}