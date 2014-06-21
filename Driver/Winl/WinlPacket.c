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

#include "WinlPacket.h"
#include "OvsCore.h"
#include "OFFlow.h"
#include "OFDatapath.h"
#include "OvsNetBuffer.h"
#include "OFAction.h"
#include "PacketInfo.h"
#include "Buffer.h"
#include "Argument.h"
#include "Message.h"
#include "MessageToFlowMatch.h"
#include "FlowToMessage.h"
#include "Upcall.h"
#include "ArgumentType.h"
#include "WinlDevice.h"
#include "Frame.h"
#include "NblsIngress.h"
#include "Winetlink.h"
#include "Gre.h"
#include "Vxlan.h"

extern OVS_SWITCH_INFO* g_pSwitchInfo;

static volatile LONG g_upcallSequence = 0;

static LONG _NextUpcallSequence()
{
    LONG result = g_upcallSequence;

    KeMemoryBarrier();

    InterlockedIncrement(&g_upcallSequence);

    return result;
}

VOID Packet_Execute(_In_ OVS_ARGUMENT_GROUP* pArgGroup, const FILE_OBJECT* pFileObject)
{
    OVS_NET_BUFFER* pOvsNb = NULL;
    OVS_FLOW* pFlow = NULL;
    OVS_DATAPATH* pDatapath = NULL;
    OVS_ETHERNET_HEADER* ethHeader = NULL;
    BOOLEAN ok = FALSE;
    LOCK_STATE_EX lockState = { 0 };
    OVS_BUFFER buffer = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pFwdContext = NULL;
    OVS_NIC_INFO sourcePort = { 0 };
    ULONG additionalSize = max(Gre_BytesNeeded(0xFFFF), Vxlan_BytesNeeded(0xFFFF));
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL, *pActionsArgs = NULL, *pTargetActions = NULL;

    UNREFERENCED_PARAMETER(pFileObject);

    pArg = FindArgument(pArgGroup, OVS_ARGTYPE_NETBUFFER);
    if (!pArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no arg net buffer!\n");
        return;
    }

    buffer.size = pArg->length;
    buffer.offset = 0;
    buffer.p = pArg->data;

    //i.e. packet info
    pPacketInfoArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_GROUP_PI);
    if (!pPacketInfoArgs)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no arg key!\n");
        return;
    }

    pActionsArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (!pActionsArgs)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no arg group actions!\n");
        return;
    }

    pOvsNb = ONB_CreateFromBuffer(&buffer, additionalSize);

    if (!pOvsNb)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not create ONB!\n");
        return;
    }

    ethHeader = (OVS_ETHERNET_HEADER*)ONB_GetData(pOvsNb);

    OVS_CHECK(RtlUshortByteSwap(ethHeader->type) >= OVS_ETHERTYPE_802_3_MIN);

    pFlow = Flow_Create();
    if (!pFlow)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not alloc flow!\n");
        ok = FALSE;
        goto Cleanup;
    }

    ok = PacketInfo_Extract(ONB_GetData(pOvsNb), ONB_GetDataLength(pOvsNb), OVS_INVALID_PORT_NUMBER, &pFlow->maskedPacketInfo);
    if (!ok) {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not extract keys from packet!\n");
        goto Cleanup;
    }

    ok = GetPacketContextFromPIArgs(pPacketInfoArgs, &pFlow->maskedPacketInfo);
    if (!ok) {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not extract context keys from packet!\n");
        goto Cleanup;
    }

    pTargetActions = AllocArgumentGroup();
    if (NULL == pTargetActions)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not alloc group for target actions!\n");
        return;
    }

    if (!CopyArgumentGroup(pTargetActions, pActionsArgs, /*actionsToAdd*/0))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not copy actions group\n");
        DestroyArgumentGroup(pTargetActions);
        return;
    }

    ok = ProcessReceivedActions(pTargetActions, &pFlow->maskedPacketInfo, /*recursivity depth*/0);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ "ProcessReceivedActions failed!\n");
        goto Cleanup;
    }

    pFlow->pActions = pTargetActions;

    pOvsNb->pFlow = pFlow;
    pOvsNb->pOriginalPacketInfo = &pFlow->maskedPacketInfo;
    pOvsNb->packetPriority = pFlow->maskedPacketInfo.physical.packetPriority;
    pOvsNb->packetMark = pFlow->maskedPacketInfo.physical.packetMark;

    pOvsNb->pDestinationPort = NULL;
    pOvsNb->sendToPortNormal = FALSE;
    pOvsNb->pSourceNic = &sourcePort;
    pOvsNb->pSwitchInfo = g_pSwitchInfo;
    pOvsNb->sendFlags = 0;

    if (pOvsNb->pOriginalPacketInfo->physical.ovsInPort != OVS_INVALID_PORT_NUMBER)
    {
		FWDINFO_LOCK_READ(g_pSwitchInfo->pForwardInfo, &lockState);

        OVS_PERSISTENT_PORT* pPersPort = PersPort_FindByNumber_Unsafe(pOvsNb->pOriginalPacketInfo->physical.ovsInPort);
        if (pPersPort && pPersPort->pNicListEntry)
        {
            NicListEntry_To_NicInfo(pPersPort->pNicListEntry, &sourcePort);
        }

        pOvsNb->pSourcePort = pPersPort;

		FWDINFO_UNLOCK(g_pSwitchInfo->pForwardInfo, &lockState);
    }

    pDatapath = GetDefaultDatapath();

    if (!pDatapath)
    {
        ok = FALSE;
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no datapath!\n");
        goto Cleanup;
    }

    OVS_CHECK(g_pSwitchInfo);
    pFwdContext = g_pSwitchInfo->pForwardInfo;
    OVS_CHECK(pFwdContext);

    FlowTable_LockRead(&lockState);

    pOvsNb->pTunnelInfo = NULL;
    ok = ExecuteActions(pOvsNb, OutputPacketToPort);

    FlowTable_Unlock(&lockState);

Cleanup:
    Flow_DestroyNow_Unsafe(pFlow);

    if (ok)
    {
        //NOTE: the NET_BUFFER_LIST and NET_BUFFER and MDL are destroyed on NDIS callback
        KFree(pOvsNb);
    }

    else
    {
        ONB_Destroy(g_pSwitchInfo, &pOvsNb);
    }
}

static OVS_ERROR _QueueUserspacePacket(_In_ NET_BUFFER* pNb, _In_ const OVS_UPCALL_INFO* pUpcallInfo)
{
    BOOLEAN dbgPrintPacket = FALSE;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_MESSAGE msg = { 0 };
    UINT16 countArgs = 0;
    OVS_ARGUMENT* pPacketInfoArg = NULL, *pNbArg = NULL, *pUserDataArg = NULL;
    UINT i = 0;
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    VOID* nbBuffer = NULL;
    ULONG bufLen = NET_BUFFER_DATA_LENGTH(pNb);

    nbBuffer = NdisGetDataBuffer(pNb, bufLen, NULL, 1, 0);
    OVS_CHECK(nbBuffer);

    if (!nbBuffer)
    {
        error = OVS_ERROR_INVAL;
        goto Out;
    }

    if (dbgPrintPacket)
    {
        DbgPrintNbFrames(pNb, "buffer sent to userspace");
    }

    pEthHeader = nbBuffer;

    UNREFERENCED_PARAMETER(pEthHeader);

    if (bufLen > USHORT_MAX)
    {
        error = OVS_ERROR_INVAL;
        goto Out;
    }

    msg.length = sizeof(OVS_MESSAGE);
    msg.type = OVS_MESSAGE_TARGET_PACKET;
    msg.flags = 0;
    msg.sequence = _NextUpcallSequence();
    msg.pid = pUpcallInfo->portId;

    msg.command = pUpcallInfo->command;
    msg.version = 1;
    msg.reserved = 0;

    msg.dpIfIndex = g_pSwitchInfo->datapathIfIndex;

    msg.pArgGroup = AllocArgumentGroup();

    if (!msg.pArgGroup)
    {
        error = OVS_ERROR_INVAL;
        goto Out;
    }

    countArgs = (pUpcallInfo->pUserData ? 3 : 2);

    AllocateArgumentsToGroup(countArgs, msg.pArgGroup);

    pPacketInfoArg = CreateArgFromPacketInfo(pUpcallInfo->pPacketInfo, NULL, OVS_ARGTYPE_GROUP_PI);
    OVS_CHECK(pPacketInfoArg);

    i = 0;
    msg.pArgGroup->args[i] = *pPacketInfoArg;
    msg.pArgGroup->groupSize += pPacketInfoArg->length;
    ++i;

    if (pUpcallInfo->pUserData)
    {
        pUserDataArg = CreateArgumentWithSize(OVS_ARGTYPE_NETBUFFER_USERDATA, pUpcallInfo->pUserData->data, pUpcallInfo->pUserData->length);

        if (pUserDataArg)
        {
            msg.pArgGroup->args[i] = *pUserDataArg;
            msg.pArgGroup->groupSize += pUserDataArg->length;
            ++i;
        }
        else
        {
            OVS_CHECK(pUserDataArg);
            DEBUGP(LOG_ERROR, __FUNCTION__ "failed to create user data arg!\n");
        }
    }

    //we send the net buffer data and only it: starting from eth -> payload.
    pNbArg = CreateArgumentWithSize(OVS_ARGTYPE_NETBUFFER, nbBuffer, bufLen);
    msg.pArgGroup->args[i] = *pNbArg;
    msg.pArgGroup->groupSize += pNbArg->length;

    OVS_CHECK(msg.type == OVS_MESSAGE_TARGET_PACKET);
    OVS_CHECK(msg.command == OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION ||
        msg.command == OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS);

    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&msg, 1, /*pFileObject*/ NULL, OVS_MULTICAST_GROUP_NONE);
    if (error)
    {
        //NOSPC = NO SPACE
        if (error != OVS_ERROR_NOSPC)
        {
            DEBUGP(LOG_ERROR, "failed to queue packet to userspace!\n");
        }
    }

Out:
    if (msg.pArgGroup)
    {
        DestroyArgumentGroup(msg.pArgGroup);
        msg.pArgGroup = NULL;

        if (pNbArg)
        {
            FreeArgument(pNbArg);
        }

        if (pUserDataArg)
        {
            FreeArgument(pUserDataArg);
        }

        if (pPacketInfoArg)
        {
            FreeArgument(pPacketInfoArg);
        }
    }

    else
    {
        if (pNbArg)
        {
            //we free, not destroy: the nb inside was not duplicated
            FreeArgument(pNbArg);
        }

        if (pUserDataArg)
        {
            DestroyArgument(pUserDataArg);
        }

        if (pPacketInfoArg)
        {
            DestroyArgument(pPacketInfoArg);
        }
    }

    return error;
}

BOOLEAN QueuePacketToUserspace(_In_ NET_BUFFER* pNb, _In_ const OVS_UPCALL_INFO* pUpcallInfo)
{
    int dpifindex = 0;
    BOOLEAN ok = TRUE;
    OVS_DATAPATH* pDatapath = GetDefaultDatapath();

    //__DONT_QUEUE_BY_DEFAULT is used for debugging purposes only
#define __DONT_QUEUE_BY_DEFAULT 0

#if __DONT_QUEUE_BY_DEFAULT
    BOOLEAN queuePacket = FALSE;
#endif

    if (pUpcallInfo->portId == 0) {
        ok = FALSE;
        goto Cleanup;
    }

    dpifindex = pDatapath->switchIfIndex;

#if __DONT_QUEUE_BY_DEFAULT
    if (queuePacket)
#endif
    {
        OVS_ERROR error = _QueueUserspacePacket(pNb, pUpcallInfo);
        if (error != OVS_ERROR_NOERROR)
        {
            //no other kind of error except 'no space' (for queued buffers) normally happen.
            //or NOENT = file not found (where to write the info to)
            OVS_CHECK(error == OVS_ERROR_NOSPC || error == OVS_ERROR_NOENT);

            goto Cleanup;
        }
    }

Cleanup:
    if (!ok)
    {
        LOCK_STATE_EX lockState = { 0 };

        DATAPATH_LOCK_WRITE(pDatapath, &lockState);

        ++pDatapath->statistics.countLost;

        DATAPATH_UNLOCK(pDatapath, &lockState);
    }

    return ok;
}