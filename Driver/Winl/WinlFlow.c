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
#include "List.h"

static OVS_ERROR _CreateActionsFromArgGroup(OVS_ARGUMENT_GROUP* pOriginalActionsGroup, OVS_FLOW_MATCH* pFlowMatch, _Out_ OVS_OFPACKET_INFO* pMaskedPI, OVS_ACTIONS** ppActions)
{
    OVS_ACTIONS* pActions = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pActions = Actions_Create();
    CHECK_B_E(pActions, OVS_ERROR_NOMEM);

    ApplyMaskToPacketInfo(pMaskedPI, &(pFlowMatch->packetInfo), &(pFlowMatch->flowMask));

    CHECK_B_E(CopyArgumentGroup(pActions->pActionGroup, pOriginalActionsGroup, /*actionsToAdd*/0), OVS_ERROR_NOMEM);
    CHECK_B_E(ProcessReceivedActions(pActions->pActionGroup, pMaskedPI, /*recursivity depth*/0), OVS_ERROR_INVAL);

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        *ppActions = pActions;
    }
    else
    {
        OVS_REFCOUNT_DESTROY(pActions);
    }

    return error;
}

static OVS_ERROR _Flow_SetMask(OVS_FLOW_TABLE* pFlowTable, OVS_FLOW_MATCH* pFlowMatch, _Inout_ OVS_FLOW* pFlow)
{
    OVS_FLOW_MASK* pOutMask = NULL, *pInMask = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pInMask = &(pFlowMatch->flowMask);
    
    pOutMask = FlowTable_FindFlowMask(pFlowTable, pInMask);
    if (!pOutMask)
    {
        pOutMask = FlowMask_Create();
        CHECK_B_E(pOutMask, OVS_ERROR_INVAL);

        pOutMask->packetInfo = pInMask->packetInfo;
        pOutMask->piRange = pInMask->piRange;

        FlowTable_InsertFlowMask(pFlowTable, pOutMask);
    }

    ++pOutMask->refCount;
    pFlow->pMask = pOutMask;

Cleanup:
    if (error != OVS_ERROR_NOERROR)
    {
        FlowMask_DeleteReference(pOutMask);
    }

    return error;
}

static OVS_ERROR _InsertNewFlow(OVS_FLOW_TABLE* pFlowTable, OVS_ACTIONS* pActions, OVS_FLOW_MATCH* pFlowMatch, OVS_OFPACKET_INFO* pMaskedPI)
{
    OVS_FLOW* pFlow = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pFlow = Flow_Create();
    CHECK_B_E(pFlow, OVS_ERROR_INVAL);

    pFlow = OVS_REFCOUNT_REFERENCE(pFlow);
    OVS_CHECK(pFlow);

    Flow_ClearStats_Unsafe(pFlow);

    pFlow->unmaskedPacketInfo = pFlowMatch->packetInfo;
    pFlow->maskedPacketInfo = *pMaskedPI;

    CHECK_E(_Flow_SetMask(pFlowTable, pFlowMatch, pFlow));
    OVS_CHECK(pFlow->pMask);
    pFlow->pActions = pActions;

    DBGPRINT_FLOW(LOG_LOUD, "flow created: ", pFlow);
    FlowTable_InsertFlow_Unsafe(pFlowTable, pFlow);

Cleanup:
    if (error != OVS_ERROR_NOERROR)
    {
        if (pFlow)
        {
            OVS_REFCOUNT_DEREF_AND_DESTROY(pFlow);
        }
    }

    return error;
}

static VOID _SetExistingFlow(OVS_FLOW* pFlow, const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ACTIONS* pActions)
{
    OVS_ACTIONS* pOldActions = NULL;
    LOCK_STATE_EX lockState = { 0 };

    FLOW_LOCK_READ(pFlow, &lockState);

    //the old actions may be in use at the moment (e.g. execute actions on packet)
    //so we remove it from flow now, but will possibly destroy it (the actions struct) later
    pOldActions = pFlow->pActions;
    pFlow->pActions = pActions;

    DBGPRINT_FLOW(LOG_LOUD, "flow create/set: ", pFlow);

    FLOW_UNLOCK(pFlow, &lockState);
    //the pFlow does not become invalidated between locks, because it's referenced
    FLOW_LOCK_WRITE(pFlow, &lockState);

    OVS_REFCOUNT_DESTROY(pOldActions);

    if (FindArgument(pArgGroup, OVS_ARGTYPE_FLOW_CLEAR))
    {
        Flow_ClearStats_Unsafe(pFlow);
    }

    FLOW_UNLOCK(pFlow, &lockState);
}

static OVS_ERROR _ExtractFowInfoFromArgs(_In_ const OVS_MESSAGE* pMsg, BOOLEAN actionsOptional, _Out_ OVS_FLOW_MATCH* pFlowMatch, 
    _Out_ OVS_OFPACKET_INFO* pMaskedPI, _Out_ OVS_ACTIONS** ppActions)
{
    OVS_ARGUMENT_GROUP* pPIGroup = NULL, *pMaskGroup = NULL, *pActionsGroup = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    pPIGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
    CHECK_B_E(pPIGroup, OVS_ERROR_INVAL);
    pMaskGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_MASK_GROUP);

    FlowMatch_Initialize(pFlowMatch, /*have mask*/ TRUE);
    CHECK_B_E(GetFlowMatchFromArguments(pFlowMatch, pPIGroup, pMaskGroup), OVS_ERROR_INVAL);

    pActionsGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_ACTIONS_GROUP);
    if (!pActionsGroup && !actionsOptional)
    {
        OVS_CHECK(__UNEXPECTED__);
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    CHECK_E(_CreateActionsFromArgGroup(pActionsGroup, pFlowMatch, pMaskedPI, ppActions));

Cleanup:
    return error;
}

static OVS_ERROR _ExtractPIFromArgsAndFindFlow_Ref(_In_ OVS_ARGUMENT_GROUP* pArgGroup, OVS_FLOW_TABLE* pFlowTable, _Out_ OVS_FLOW** ppFlow)
{
    OVS_ARGUMENT_GROUP* pPIGroup = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_FLOW_MATCH flowMatch = { 0 };
    OVS_FLOW* pFlow = NULL;

    pPIGroup = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
    CHECK_B_E(pPIGroup, OVS_ERROR_INVAL);

    FlowMatch_Initialize(&flowMatch, /*have mask*/ FALSE);
    CHECK_B_E(GetFlowMatchFromArguments(&flowMatch, pPIGroup, /*mask group*/ NULL), OVS_ERROR_INVAL);

    pFlow = FlowTable_FindExactFlow_Ref(pFlowTable, &flowMatch);
    CHECK_B_E(pFlow, OVS_ERROR_NOENT);

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        *ppFlow = pFlow;
    }

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlFlow_New(OVS_FLOW_TABLE* pFlowTable, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_OFPACKET_INFO packetInfo = { 0 }, maskedPacketInfo = { 0 };
    OVS_FLOW* pFoundFlow = NULL, *pFlow = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_FLOW_MATCH flowMatch = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_ACTIONS* pActions = NULL;

    CHECK_E(_ExtractFowInfoFromArgs(pMsg, /*actions opt*/ FALSE, &flowMatch, &maskedPacketInfo, &pActions));

    /*** PROCESS DATA: ADD / SET FLOW ***/
    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pFlowTable, &packetInfo);
    if (!pFlow)
    {
        CHECK_E(_InsertNewFlow(pFlowTable, pActions, &flowMatch, &maskedPacketInfo));
    }
    else
    {
        LOCK_STATE_EX lockState = { 0 };
        BOOLEAN packetInfoEqual = FALSE;

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

        FLOW_LOCK_READ(pFlow, &lockState);
        packetInfoEqual = PacketInfo_Equal(&pFlow->unmaskedPacketInfo, &(flowMatch.packetInfo), flowMatch.piRange.endRange);
        FLOW_UNLOCK(pFlow, &lockState);

        if (!packetInfoEqual)
        {
            OVS_REFCOUNT_DEREFERENCE(pFlow);

            pFlow = FlowTable_FindExactFlow_Ref(pFlowTable, &flowMatch);
            if (!pFlow)
            {
                DEBUGP(LOG_LOUD, "flow create/set failed (flow does not match the unmasked key): ");

                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }
        }

        pFoundFlow = pFlow;

        _SetExistingFlow(pFoundFlow, pMsg->pArgGroup, pActions);
    }

    /*** REPLY ***/
    CHECK_E(CreateMsgFromFlow(pFlow, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));
    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

    /*** cleanup ***/
Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);

    OVS_REFCOUNT_DEREFERENCE(pFlow);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlFlow_Set(OVS_FLOW_TABLE* pFlowTable, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_OFPACKET_INFO maskedPacketInfo = { 0 };
    OVS_FLOW* pFlow = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ACTIONS* pActions = NULL;
    OVS_FLOW_MATCH flowMatch = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    CHECK_E(_ExtractFowInfoFromArgs(pMsg, /*actions opt*/ TRUE, &flowMatch, &maskedPacketInfo, &pActions));

    pFlow = FlowTable_FindExactFlow_Ref(pFlowTable, &flowMatch);
    CHECK_B_E(pFlow, OVS_ERROR_NOENT);
    _SetExistingFlow(pFlow, pMsg->pArgGroup, pActions);

    /*** reply ***/
    CHECK_E(CreateMsgFromFlow(pFlow, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));
    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);
    OVS_REFCOUNT_DEREFERENCE(pFlow);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlFlow_Get(OVS_FLOW_TABLE* pFlowTable, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_FLOW *pFlow = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    CHECK_E(_ExtractPIFromArgsAndFindFlow_Ref(pMsg->pArgGroup, pFlowTable, &pFlow));

    CHECK_E(CreateMsgFromFlow(pFlow, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW));
    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);
    OVS_REFCOUNT_DEREFERENCE(pFlow);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlFlow_Delete(OVS_DATAPATH* pDatapath, OVS_FLOW_TABLE* pFlowTable, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_FLOW* pFlow = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (!pMsg->pArgGroup)
    {
        CHECK_E(Datapath_FlushFlows(pDatapath));

        //i.e. must send reply = ok
        WriteErrorToDevice((OVS_NLMSGHDR*)pMsg, OVS_ERROR_NOERROR, pFileObject, OVS_MULTICAST_GROUP_NONE);
        goto Cleanup;
    }

    CHECK_E(_ExtractPIFromArgsAndFindFlow_Ref(pMsg->pArgGroup, pFlowTable, &pFlow));

    FLOWTABLE_LOCK_WRITE(pFlowTable, &lockState);
    DBGPRINT_FLOW(LOG_LOUD, "deleting flow: ", pFlow);
    //remove the flow from the list of flows
    FlowTable_RemoveFlow_Unsafe(pFlowTable, pFlow);
    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    CHECK_E(CreateMsgFromFlow(pFlow, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_DELETE));
    OVS_REFCOUNT_DEREF_AND_DESTROY(pFlow);

    CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));

Cleanup:
    DestroyArgumentGroup(replyMsg.pArgGroup);
    OVS_REFCOUNT_DEREFERENCE(pFlow);

    return error;
}

static OVS_ERROR _CreateMsgsFromFlows(OVS_MESSAGE* msgs, ULONG countMsgs, const OVS_MESSAGE* pInMsg, OVS_FLOW_TABLE* pFlowTable)
{
    LOCK_STATE_EX lockState = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    ULONG j = 0;

    FLOWTABLE_LOCK_READ(pFlowTable, &lockState);

    for (ULONG i = 0; i < OVS_FLOW_TABLE_HASH_COUNT; ++i)
    {
        OVS_FLOW* pFlow = NULL;
        LIST_ENTRY* pList = NULL;

        pList = pFlowTable->pFlowLists + i;

        OVS_LIST_FOR_EACH(OVS_FLOW, pFlow, pList)
        {
            OVS_MESSAGE* pReplyMsg = msgs + j;

            CHECK_E(CreateMsgFromFlow(pFlow, pInMsg, pReplyMsg, OVS_MESSAGE_COMMAND_NEW));
            pReplyMsg->flags |= OVS_MESSAGE_FLAG_MULTIPART;

            ++j;
        }
    }

    //there must be room for one more message: the dump done message
    OVS_CHECK(j == countMsgs - 1);

    CHECK_E(CreateReplyMsgDone(pInMsg, msgs + j, sizeof(OVS_MESSAGE_DONE), OVS_MESSAGE_COMMAND_NEW));

Cleanup:
    FLOWTABLE_UNLOCK(pFlowTable, &lockState);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlFlow_Dump(OVS_FLOW_TABLE* pFlowTable, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE* msgs = NULL;
    UINT countMsgs = 0;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (pFlowTable->countFlows > 0)
    {
        countMsgs = pFlowTable->countFlows + 1;
        msgs = KZAlloc(countMsgs * sizeof(OVS_MESSAGE));
        CHECK_B_E(msgs, OVS_ERROR_NOMEM);

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));

        CHECK_E(_CreateMsgsFromFlows(msgs, countMsgs, pMsg, pFlowTable));
        CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)msgs, countMsgs, pFileObject, OVS_MULTICAST_GROUP_NONE));
    }

    //if we have no flow, write only "done"
    else
    {
        OVS_MESSAGE msgDone = { 0 };

        CHECK_E(CreateReplyMsgDone(pMsg, &msgDone, sizeof(OVS_MESSAGE_DONE), OVS_MESSAGE_COMMAND_NEW));
        CHECK_E(WriteMsgsToDevice((OVS_NLMSGHDR*)&msgDone, 1, pFileObject, OVS_MULTICAST_GROUP_NONE));
    }

Cleanup:
    DestroyMessages(msgs, countMsgs);

    return error;
}