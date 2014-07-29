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
#include "OFPort.h"
#include "Error.h"

typedef struct _OVS_WINL_PORT
{
    UINT32            number;
    OVS_OFPORT_TYPE   type;
    const char*       name;
    //Used for userpace to kernel communication
    OVS_UPCALL_PORT_IDS    upcallPortIds;

    OVS_OFPORT_STATS  stats;

    //group type: OVS_ARGTYPE_OFPORT_GROUP
    //only available option is  OVS_ARGTYPE_PORT_OPTION_DST_PORT
    OVS_ARGUMENT_GROUP* pOptions;
}OVS_WINL_PORT, *POVS_WINL_PORT;

/************************/

static __inline VOID _OFPort_AddStats(_Inout_ OVS_OFPORT_STATS* pDest, _In_ const  OVS_OFPORT_STATS* pSrc)
{
    pDest->bytesReceived += pSrc->bytesReceived;
    pDest->bytesSent += pSrc->bytesSent;
    pDest->droppedOnReceive += pSrc->droppedOnReceive;
    pDest->droppedOnSend += pSrc->droppedOnSend;
    pDest->errorsOnReceive += pSrc->errorsOnReceive;
    pDest->errorsOnSend += pSrc->errorsOnSend;
    pDest->packetsReceived += pSrc->packetsReceived;
    pDest->packetsSent += pSrc->packetsSent;
}

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

    OVS_CHECK_RET(pOptions, NULL);

    countArgs = (UINT16)_CountBits(pOptions->optionsFlags);

    pOptionsGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    OVS_CHECK_RET(pOptionsGroup, NULL);

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
        DestroyArguments(pOptionsGroup->args, pOptionsGroup->count);
    }

    return pOptionsGroup;
}

static OVS_ERROR _CreateMsgFromOFPort(OVS_OFPORT* pOFPort, const OVS_MESSAGE* pInMsg, _Out_ OVS_MESSAGE* pOutMsg, UINT8 command, BOOLEAN multipleUpcallPids)
{
    OVS_ARGUMENT* pArgPortName = NULL, *pArgPortType = NULL, *pArgPortNumber = NULL;
    OVS_ARGUMENT* pArgUpcallPid = NULL, *pArgPortSats = NULL, *pArgPortOpts = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    UINT16 argsCount = 5;
    ULONG i = 0;
    OVS_WINL_PORT winlPort = { 0 };

    OVS_CHECK(pOutMsg);
    OVS_CHECK(pInMsg);

    RtlZeroMemory(&winlPort, sizeof(OVS_WINL_PORT));
    winlPort.number = pOFPort->ofPortNumber;
    winlPort.pOptions = _OFPort_OptionsToGroup(pOFPort->pOptions);
    winlPort.type = pOFPort->ofPortType;
    winlPort.name = pOFPort->ofPortName;
    winlPort.stats = pOFPort->stats;
    winlPort.upcallPortIds = pOFPort->upcallPortIds;

    if (winlPort.pOptions)
    {
        ++argsCount;
    }

    RtlZeroMemory(pOutMsg, sizeof(OVS_MESSAGE));

    CHECK_E(CreateReplyMsg(pInMsg, pOutMsg, sizeof(OVS_MESSAGE), command, argsCount));
    OVS_CHECK(pOutMsg->type == OVS_MESSAGE_TARGET_PORT);

    //arg 1: port number
    pArgPortNumber = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_NUMBER, &winlPort.number);
    CHECK_B_E(pArgPortNumber, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pOutMsg->pArgGroup, pArgPortNumber, &i);

    //arg 2: port type
    pArgPortType = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_TYPE, &winlPort.type);
    CHECK_B_E(pArgPortType, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pOutMsg->pArgGroup, pArgPortType, &i);

    //arg 3: port name
    pArgPortName = CreateArgumentStringA_Alloc(OVS_ARGTYPE_OFPORT_NAME, winlPort.name);
    CHECK_B_E(pArgPortName, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pOutMsg->pArgGroup, pArgPortName, &i);

    //arg 4: port upcall pid
    if (multipleUpcallPids)
    {
        pArgUpcallPid = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, &(winlPort.upcallPortIds));
    }
    else
    {
        pArgUpcallPid = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, &(winlPort.upcallPortIds.ids[0]));
    }

    CHECK_B_E(pArgUpcallPid, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pOutMsg->pArgGroup, pArgUpcallPid, &i);

    //arg 5: port stats
    pArgPortSats = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_STATS, &winlPort.stats);
    CHECK_B_E(pArgPortSats, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pOutMsg->pArgGroup, pArgPortSats, &i);

    if (winlPort.pOptions)
    {
        //arg 6
        pArgPortOpts = CreateArgumentFromGroup(OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, winlPort.pOptions);
        CHECK_B_E(pArgPortOpts, OVS_ERROR_NOMEM);
        AddArgToArgGroup(pOutMsg->pArgGroup, pArgPortOpts, &i);

        if (pArgPortOpts)
        {
            ++argsCount;
        }
    }

    pOutMsg->pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    CHECK_B_E(pOutMsg->pArgGroup, OVS_ERROR_NOMEM);

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        KFree(pArgPortNumber); KFree(pArgPortName);
        KFree(pArgPortType); KFree(pArgPortSats);
        KFree(pArgUpcallPid); KFree(pArgPortOpts);
    }
    else
    {
        DestroyArgument(pArgPortNumber); DestroyArgument(pArgPortName);
        DestroyArgument(pArgPortType); DestroyArgument(pArgUpcallPid);
        DestroyArgument(pArgPortSats); DestroyArgument(pArgPortOpts);

        FreeGroupWithArgs(pOutMsg->pArgGroup);
    }

    return error;
}

OVS_ERROR _CreateOFPortFromArgGroup_Ref(OVS_ARGUMENT_GROUP* pArgGroup, OVS_OFPORT** ppOFPort)
{
    OVS_OFPORT* pOFPort = NULL;
    OVS_ARGUMENT* pNameArg = NULL, *pNumberArg = NULL, *pTypeArg = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    const char* ofPortName = NULL;
    UINT32 portType = 0;

    //NAME: required
    pNameArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    CHECK_B_E(pNameArg, OVS_ERROR_INVAL);

    //TYPE: required
    pTypeArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    CHECK_B_E(pTypeArg, OVS_ERROR_INVAL);

    ofPortName = pNameArg->data;
    portType = GET_ARG_DATA(pTypeArg, UINT32);

    //NOTE: name is required; number is optional
        //NUMBER: optional
    pNumberArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
    if (pNumberArg)
    {
        UINT16 portNumber = 0;
        portNumber = (UINT16)GET_ARG_DATA(pNumberArg, UINT32);

        pOFPort = OFPort_Create_Ref(ofPortName, &portNumber, portType);
        CHECK_B_E(pOFPort, OVS_ERROR_INVAL);
    }
    else
    {
        OVS_CHECK(ofPortName);

        pOFPort = OFPort_Create_Ref(ofPortName, /*number*/ NULL, portType);
        CHECK_B_E(pOFPort, OVS_ERROR_INVAL);
    }

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        *ppOFPort = pOFPort;
    }

    return error;
}

OVS_ERROR _FindOFPortFromArgGroup_Ref(OVS_ARGUMENT_GROUP* pArgGroup, OVS_OFPORT** ppOFPort)
{
    OVS_OFPORT* pOFPort = NULL;
    OVS_ARGUMENT* pNameArg = NULL, *pNumberArg = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    const char* ofPortName = NULL;

    //NAME: required
    pNameArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pNameArg)
    {
        ofPortName = pNameArg->data;
        pOFPort = OFPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pNumberArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        CHECK_B_E(pNameArg, OVS_ERROR_INVAL);

        UINT16 portNumber = 0;
        portNumber = (UINT16)GET_ARG_DATA(pNumberArg, UINT32);

        pOFPort = OFPort_FindByNumber_Ref((UINT16)portNumber);
    }

    CHECK_B_E(pOFPort, OVS_ERROR_NODEV);

Cleanup:
    if (error == OVS_ERROR_NOERROR)
    {
        *ppOFPort = pOFPort;
    }

    return error;
}

OVS_ERROR _OFPort_SetOptions(OVS_OFPORT* pOFPort, OVS_ARGUMENT_GROUP* pArgGroup)
{
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    //OPTIONS: optional
    pOptionsGroup = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_OFPORT_OPTIONS_GROUP);
    if (pOptionsGroup)
    {
        if (!pOFPort->pOptions)
        {
            pOFPort->pOptions = KZAlloc(sizeof(OVS_TUNNELING_PORT_OPTIONS));
            CHECK_B_E(pOFPort->pOptions, OVS_ERROR_NOMEM);
        }

        CHECK_B_E(_OFPort_GroupToOptions(pOptionsGroup, pOFPort->pOptions), OVS_ERROR_INVAL);
    }

Cleanup:
    return error;
}

static OVS_ERROR _OFPort_GetUpcallPids(OVS_ARGUMENT_GROUP* pArgGroup, BOOLEAN multiplePidsPerOFPort, _Out_ OVS_UPCALL_PORT_IDS* pUpcallPids)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    //UPCALL PID(S): required
    pArg = FindArgument(pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    CHECK_B_E(pArg, OVS_ERROR_INVAL);

    if (multiplePidsPerOFPort)
    {
        UINT32 countPids = pArg->length / sizeof(UINT32);

        pUpcallPids->count = countPids;
        pUpcallPids->ids = KZAlloc(pArg->length);
        CHECK_B_E(pUpcallPids->ids, OVS_ERROR_NOMEM);

        RtlCopyMemory(pUpcallPids->ids, pArg->data, pArg->length);
    }
    else
    {
        pUpcallPids->count = 1;
        pUpcallPids->ids = KZAlloc(sizeof(UINT));
        CHECK_B_E(pUpcallPids->ids, OVS_ERROR_NOMEM);

        pUpcallPids->ids[0] = GET_ARG_DATA(pArg, UINT32);
    }

Cleanup:
    return error;
}

/*******************************************************************************************/

//NOTE: We're Assuming the verification part has done its job (arg & msg verification), we can use the input data as valid

_Use_decl_annotations_
OVS_ERROR WinlOFPort_New(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{   
    UINT32 portType = 0, upcallPortId = 0;
    OVS_ARGUMENT* pArg = NULL;
    OVS_OFPORT* pOFPort = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX portLockState = { 0 }, dpLockState = { 0 };
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;
    OVS_UPCALL_PORT_IDS upcallPids = { 0 };

    //UPCALL PID: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    CHECK_B_E(pArg, OVS_ERROR_INVAL);

    upcallPortId = GET_ARG_DATA(pArg, UINT32);

    CHECK_E(_CreateOFPortFromArgGroup_Ref(pMsg->pArgGroup, &pOFPort));

    DATAPATH_LOCK_READ(pDatapath, &dpLockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &dpLockState);

    PORT_LOCK_READ(pOFPort, &portLockState);
    locked = TRUE;

    pOFPort->ofPortType = portType;

    CHECK_E(_OFPort_SetOptions(pOFPort, pMsg->pArgGroup));
    CHECK_E(_OFPort_GetUpcallPids(pMsg->pArgGroup, multiplePidsPerOFPort, &upcallPids));

    CHECK_E(_CreateMsgFromOFPort(pOFPort, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW, multiplePidsPerOFPort));

    //write reply message to buffer.
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pOFPort)
    {
        PORT_UNLOCK_IF(pOFPort, &portLockState, locked);

        if (error != OVS_ERROR_NOERROR)
        {
            //NOTE: must be referenced when called for delete
            OFPort_Delete(pOFPort);
            pOFPort = NULL;
        }
        
        OVS_REFCOUNT_DEREFERENCE(pOFPort);
    }

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlOFPort_Set(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_OFPORT* pOFPort = NULL;
    UINT32 portType = OVS_OFPORT_TYPE_INVALID;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_ARGUMENT* pArg = NULL;
    LOCK_STATE_EX portLockState = { 0 }, dpLockState = { 0 };
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;
    OVS_UPCALL_PORT_IDS upcallPids = { 0 };

    CHECK_E(_FindOFPortFromArgGroup_Ref(pMsg->pArgGroup, &pOFPort));

    //TYPE: if set, must be the same as original
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    if (pArg)
    {
        portType = GET_ARG_DATA(pArg, UINT32);
        CHECK_B_E(portType == (UINT32)pOFPort->ofPortType, OVS_ERROR_INVAL);
    }

    DATAPATH_LOCK_READ(pDatapath, &dpLockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &dpLockState);

    PORT_LOCK_WRITE(pOFPort, &portLockState);
    locked = TRUE;

    CHECK_E(_OFPort_SetOptions(pOFPort, pMsg->pArgGroup));
    CHECK_E(_OFPort_GetUpcallPids(pMsg->pArgGroup, multiplePidsPerOFPort, &upcallPids));

    CHECK_E(_CreateMsgFromOFPort(pOFPort, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW, multiplePidsPerOFPort));

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    PORT_UNLOCK_IF(pOFPort, &portLockState, locked);
    OVS_REFCOUNT_DEREFERENCE(pOFPort);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlOFPort_Get(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_OFPORT* pOFPort = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX portLockState = { 0 }, dpLockState = { 0 };
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    CHECK_E(_FindOFPortFromArgGroup_Ref(pMsg->pArgGroup, &pOFPort));

    DATAPATH_LOCK_READ(pDatapath, &dpLockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &dpLockState);

    PORT_LOCK_READ(pOFPort, &portLockState);
    locked = TRUE;

    CHECK_E(_CreateMsgFromOFPort(pOFPort, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_NEW, multiplePidsPerOFPort));

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    PORT_UNLOCK_IF(pOFPort, &portLockState, locked);
    OVS_REFCOUNT_DEREFERENCE(pOFPort);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlOFPort_Delete(OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_OFPORT* pOFPort = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX portLockState = { 0 }, dpLockState = { 0 };
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    CHECK_E(_FindOFPortFromArgGroup_Ref(pMsg->pArgGroup, &pOFPort));
    CHECK_B_E(pOFPort->ofPortNumber != OVS_LOCAL_PORT_NUMBER, OVS_ERROR_INVAL);

    DATAPATH_LOCK_READ(pDatapath, &dpLockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &dpLockState);

    PORT_LOCK_WRITE(pOFPort, &portLockState);
    locked = TRUE;

    CHECK_E(_CreateMsgFromOFPort(pOFPort, pMsg, &replyMsg, OVS_MESSAGE_COMMAND_DELETE, multiplePidsPerOFPort));

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pOFPort)
    {
        PORT_UNLOCK_IF(pOFPort, &portLockState, locked);
        OFPort_Delete(pOFPort);
    }

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR WinlOFPort_Dump(OVS_SWITCH_INFO* pSwitchInfo, OVS_DATAPATH* pDatapath, const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE *msgs = NULL;
    int i = 0, countMsgs = 1;
    LOCK_STATE_EX fwdLockState = { 0 }, dpLockState = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    pForwardInfo = pSwitchInfo->pForwardInfo;

    DATAPATH_LOCK_READ(pDatapath, &dpLockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &dpLockState);

    locked = TRUE;
    FXARRAY_LOCK_READ(&pForwardInfo->ofPorts, &fwdLockState);

    if (pForwardInfo->ofPorts.count > 0)
    {
        OVS_MESSAGE* pReplyMsg = NULL;

        countMsgs += pForwardInfo->ofPorts.count;

        msgs = KAlloc(countMsgs * sizeof(OVS_MESSAGE));
        CHECK_B_E(msgs, OVS_ERROR_NOMEM);

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));
        pReplyMsg = msgs + i;

        OVS_FXARRAY_FOR_EACH(&pForwardInfo->ofPorts, pCurItem, 
            /*if*/ error != OVS_ERROR_NOERROR,
        {
            error = _CreateMsgFromOFPort((OVS_OFPORT*)pCurItem, pMsg, pReplyMsg, OVS_MESSAGE_COMMAND_NEW, multiplePidsPerOFPort);
        });
    }

    FXARRAY_UNLOCK(&pForwardInfo->ofPorts, &fwdLockState);
    locked = FALSE;

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
        CHECK_E(CreateReplyMsgDone(pMsg, &msgDone, sizeof(OVS_MESSAGE_DONE), OVS_MESSAGE_COMMAND_NEW));

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&msgDone, 1, pFileObject, OVS_VPORT_MCGROUP);
    }

Cleanup:
    FXARRAY_UNLOCK_IF(&pForwardInfo->ofPorts, &fwdLockState, locked);
    DestroyMessages(msgs, countMsgs);

    return error;
}