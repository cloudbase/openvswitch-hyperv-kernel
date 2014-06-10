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
    OVS_ARGUMENT_GROUP* pActions = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    BOOLEAN flowTableLocked = FALSE;
    BOOLEAN flowWasCreated = TRUE;

    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
    if (!pPacketInfoArgs)
    {
        return OVS_ERROR_INVAL;
    }

    //OVS_ARGTYPE_GROUP_MASK is optional
    pPacketInfoMaskArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MASK);

    FlowMatch_Initialize(&flowMatch, &packetInfo, &flowMask);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, pPacketInfoMaskArgs))
        return OVS_ERROR_INVAL;

    pFlowActionGroupArg = FindArgumentGroupAsArg(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (pFlowActionGroupArg)
    {
        OVS_ARGUMENT_GROUP* pOriginalGroup = pFlowActionGroupArg->data;

        ApplyMaskToPacketInfo(&maskedPacketInfo, &packetInfo, &flowMask);

        pActions = AllocArgumentGroup();
        if (!pActions)
        {
            return OVS_ERROR_INVAL;
        }

        if (!CopyArgumentGroup(pActions, pOriginalGroup, /*actionsToAdd*/0))
        {
            DestroyArgumentGroup(pActions);
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (!ProcessReceivedActions(pActions, &maskedPacketInfo, /*recursivity depth*/0))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " _ProcessActions failed!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    else
    {
        return OVS_ERROR_INVAL;
    }

    pDatapath = GetDefaultDatapath();
    if (!pDatapath)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    FlowTable_LockWrite(&lockState);
    flowTableLocked = TRUE;

    pFlowTable = pDatapath->pFlowTable;

    pFlow = FlowTable_FindFlowMatchingMaskedPI(pFlowTable, &packetInfo);

    if (!pFlow)
    {
        OVS_FLOW_MASK* pFlowMask = NULL;

        pFlow = Flow_Create();
        if (!pFlow)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        Flow_ClearStats(pFlow);

        pFlow->unmaskedPacketInfo = packetInfo;
        pFlow->maskedPacketInfo = maskedPacketInfo;

        pFlowMask = FlowTable_FindFlowMask(pFlowTable, &flowMask);
        if (!pFlowMask)
        {
            pFlowMask = FlowMask_Create();
            if (!pFlowMask)
            {
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

        FlowTable_InsertFlow_Unsafe(pFlowTable, pFlow);
    }
    else
    {
        OVS_ARGUMENT_GROUP* pOldActions = NULL;

        flowWasCreated = FALSE;

        //if we have cmd = new with the flag 'exclusive', it means we're not allowed to override existing flows.
        //the flag 'create' is accepted as well: 'create' may be set instead of 'exclusive'
        if (pMsg->flags & OVS_MESSAGE_FLAG_CREATE ||
            pMsg->flags & OVS_MESSAGE_FLAG_EXCLUSIVE)
        {
            DEBUGP(LOG_LOUD, __FUNCTION__ " we are not allowed to override the flow, because of the nl flag = create / exclusive!\n");
            error = OVS_ERROR_EXIST;
            goto Cleanup;
        }

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &packetInfo, flowMatch.piRange.endRange))
        {
            DEBUGP(LOG_ERROR, "Cannot override flow, because it does not match the unmasked key!\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_CLEAR))
        {
            NdisAcquireSpinLock(&pFlow->spinLock);
            Flow_ClearStats(pFlow);
            NdisReleaseSpinLock(&pFlow->spinLock);
        }

        pOldActions = pFlow->pActions;
        pFlow->pActions = pActions;
        DestroyArgumentGroup(pOldActions);
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    FlowTable_Unlock(&lockState);
    flowTableLocked = FALSE;

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);

    if (error == OVS_ERROR_NOERROR)
    {
        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
        if (error != OVS_ERROR_NOERROR)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

Cleanup:
    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
        replyMsg.pArgGroup = NULL;
    }

    if (error != OVS_ERROR_NOERROR)
    {
        if (flowWasCreated)
        {
            if (pFlow)
                Flow_Free(pFlow);
        }

        if (flowTableLocked)
            FlowTable_Unlock(&lockState);

        if (pActions)
            DestroyArgumentGroup(pActions);
    }

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
    OVS_ARGUMENT_GROUP* pActions = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    BOOLEAN flowTableLocked = FALSE;

    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
    if (!pPacketInfoArgs)
    {
        return OVS_ERROR_INVAL;
    }

    //OVS_ARGTYPE_GROUP_MASK is optional
    pPacketInfoMaskArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MASK);

    FlowMatch_Initialize(&flowMatch, &packetInfo, &flowMask);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, pPacketInfoMaskArgs))
    {
        return OVS_ERROR_INVAL;
    }

    pFlowActionGroupArg = FindArgumentGroupAsArg(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (pFlowActionGroupArg)
    {
        OVS_ARGUMENT_GROUP* pOriginalGroup = pFlowActionGroupArg->data;

        ApplyMaskToPacketInfo(&maskedPacketInfo, &packetInfo, &flowMask);

        pActions = AllocArgumentGroup();
        if (!pActions)
        {
            return OVS_ERROR_INVAL;
        }

        if (!CopyArgumentGroup(pActions, pOriginalGroup, /*actionsToAdd*/0))
        {
            DestroyArgumentGroup(pActions);
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (!ProcessReceivedActions(pActions, &maskedPacketInfo, /*recursivity depth*/0))
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ " ProcessReceivedActions failed.\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    pDatapath = GetDefaultDatapath();

    if (!pDatapath)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    FlowTable_LockWrite(&lockState);
    flowTableLocked = TRUE;
    pFlowTable = pDatapath->pFlowTable;

    pFlow = FlowTable_FindFlowMatchingMaskedPI(pFlowTable, &packetInfo);

    if (!pFlow)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " we were asked to set a flow that does not exist!\n");
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }

    else
    {
        OVS_ARGUMENT_GROUP* pOldActions = NULL;

        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &packetInfo, flowMatch.piRange.endRange))
        {
            DEBUGP(LOG_ERROR, "Flow Set error: the flow's unmasked key does not match the given key\n.\n");
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        if (FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_CLEAR))
        {
            NdisAcquireSpinLock(&pFlow->spinLock);
            Flow_ClearStats(pFlow);
            NdisReleaseSpinLock(&pFlow->spinLock);
        }

        pOldActions = pFlow->pActions;
        pFlow->pActions = pActions;
        DestroyArgumentGroup(pOldActions);
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    FlowTable_Unlock(&lockState);
    flowTableLocked = FALSE;

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);
    OVS_CHECK(error == OVS_ERROR_NOERROR);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

Cleanup:
    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
        replyMsg.pArgGroup = NULL;
    }

    if (error != OVS_ERROR_NOERROR)
    {
        if (flowTableLocked)
            FlowTable_Unlock(&lockState);

        if (pActions)
            DestroyArgumentGroup(pActions);
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
    BOOLEAN flowTableLocked = FALSE;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
    if (!pPacketInfoArgs)
    {
        return OVS_ERROR_INVAL;
    }

    FlowMatch_Initialize(&flowMatch, &packetInfo, NULL);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, NULL))
    {
        return OVS_ERROR_INVAL;
    }

    pDatapath = GetDefaultDatapath();
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    FlowTable_LockRead(&lockState);
    flowTableLocked = TRUE;

    pFlowTable = pDatapath->pFlowTable;

    pFlow = FlowTable_FindFlowMatchingMaskedPI(pFlowTable, flowMatch.pPacketInfo);

    if (pFlow)
    {
        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, flowMatch.pPacketInfo, flowMatch.piRange.endRange))
        {
            pFlow = NULL;
        }
    }

    if (!pFlow)
    {
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    FlowTable_Unlock(&lockState);
    flowTableLocked = FALSE;

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

Cleanup:
    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
        replyMsg.pArgGroup = NULL;
    }

    if (flowTableLocked)
    {
        FlowTable_Unlock(&lockState);
    }

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
    BOOLEAN flowTableLocked = FALSE;

    pDatapath = GetDefaultDatapath();
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    if (pMsg->pArgGroup)
    {
        pPacketInfoArgs = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
        if (!pPacketInfoArgs)
        {
            return OVS_ERROR_INVAL;
        }
    }

    else
    {
        if (!Datapath_FlushFlows(pDatapath))
            return OVS_ERROR_INVAL;

        //must send reply = ok
        WriteErrorToDevice((OVS_NLMSGHDR*)pMsg, OVS_ERROR_NOERROR, pFileObject, OVS_MULTICAST_GROUP_NONE);

        return error;
    }

    FlowMatch_Initialize(&flowMatch, &packetInfo, NULL);

    if (!GetFlowMatchFromArguments(&flowMatch, pPacketInfoArgs, NULL))
    {
        return OVS_ERROR_INVAL;
    }

    FlowTable_LockWrite(&lockState);
    flowTableLocked = TRUE;

    pFlowTable = pDatapath->pFlowTable;

    pFlow = FlowTable_FindFlowMatchingMaskedPI(pFlowTable, flowMatch.pPacketInfo);

    if (pFlow)
    {
        if (!PacketInfo_Equal(&pFlow->unmaskedPacketInfo, flowMatch.pPacketInfo, flowMatch.piRange.endRange))
        {
            pFlow = NULL;
        }
    }

    if (!pFlow)
    {
        error = OVS_ERROR_NOENT;
        goto Cleanup;
    }

    if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_DELETE, &replyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    FlowTable_RemoveFlow(pFlowTable, pFlow);

    Flow_Free(pFlow);
    FlowTable_Unlock(&lockState);
    flowTableLocked = FALSE;

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_FLOW);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE);
    if (error != OVS_ERROR_NOERROR)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

Cleanup:
    if (replyMsg.pArgGroup)
    {
        DestroyArgumentGroup(replyMsg.pArgGroup);
        replyMsg.pArgGroup = NULL;
    }

    if (flowTableLocked)
        FlowTable_Unlock(&lockState);

    return error;
}

_Use_decl_annotations_
OVS_ERROR Flow_Dump(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH *pDatapath = NULL;
    OVS_FLOW_TABLE *pFlowTable = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_MESSAGE* msgs = NULL;
    UINT countMsgs = 0;
    OVS_MESSAGE msgDone = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pDatapath = GetDefaultDatapath();
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    FlowTable_LockRead(&lockState);

    pFlowTable = pDatapath->pFlowTable;

    if (pFlowTable->countFlows > 0)
    {
        LIST_ENTRY* pCurItem = pFlowTable->pFlowList->Flink;
        UINT i = 0;

        countMsgs = pFlowTable->countFlows + 1;
        msgs = ExAllocatePoolWithTag(NonPagedPool, countMsgs * sizeof(OVS_MESSAGE), g_extAllocationTag);

        if (!msgs)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));

        while (pCurItem != pFlowTable->pFlowList)
        {
            OVS_FLOW* pFlow = CONTAINING_RECORD(pCurItem, OVS_FLOW, entryInTable);
            OVS_MESSAGE* pReplyMsg = msgs + i;

            if (!CreateMsgFromFlow(pFlow, OVS_MESSAGE_COMMAND_NEW, pReplyMsg, pMsg->sequence, pDatapath->switchIfIndex, pMsg->pid))
            {
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }

            OVS_CHECK(pReplyMsg->type == OVS_MESSAGE_TARGET_FLOW);
            pReplyMsg->flags |= OVS_MESSAGE_FLAG_MULTIPART;

            ++i;
            pCurItem = pCurItem->Flink;
        }

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

Cleanup:
    if (msgs)
    {
        for (UINT i = 0; i < countMsgs; ++i)
        {
            OVS_MESSAGE* pReplyMsg = msgs + i;

            if (pMsg->pArgGroup)
            {
                DestroyArgumentGroup(pReplyMsg->pArgGroup);
                pReplyMsg->pArgGroup = NULL;
            }
        }

        ExFreePoolWithTag(msgs, g_extAllocationTag);
    }

    FlowTable_Unlock(&lockState);

    return error;
}