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
    OVS_NIC_INFO sourcePort = { 0 };
    ULONG additionalSize = max(Gre_BytesNeeded(0xFFFF), Vxlan_BytesNeeded(0xFFFF));
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL, *pActionsArgs = NULL;
    OVS_ACTIONS* pTargetActions = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    UNREFERENCED_PARAMETER(pFileObject);

    pArg = FindArgument(pArgGroup, OVS_ARGTYPE_PACKET_BUFFER);
    if (!pArg)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no arg net buffer!\n");
        return;
    }

    buffer.size = pArg->length;
    buffer.offset = 0;
    buffer.p = pArg->data;

    //i.e. packet info
    pPacketInfoArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_PACKET_PI_GROUP);
    if (!pPacketInfoArgs)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no arg key!\n");
        return;
    }

    pActionsArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_PACKET_ACTIONS_GROUP);
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
    if (!ok)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not extract keys from packet!\n");
        goto Cleanup;
    }

    ok = GetPacketContextFromPIArgs(pPacketInfoArgs, &pFlow->maskedPacketInfo);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not extract context keys from packet!\n");
        goto Cleanup;
    }

    pTargetActions = Actions_Create();
    if (NULL == pTargetActions)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not alloc group for target actions!\n");
        goto Cleanup;
    }

    if (!CopyArgumentGroup(pTargetActions->pActionGroup, pActionsArgs, /*actionsToAdd*/0))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: could not copy actions group\n");
        goto Cleanup;
    }

    ok = ProcessReceivedActions(pTargetActions->pActionGroup, &pFlow->maskedPacketInfo, /*recursivity depth*/0);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ "ProcessReceivedActions failed!\n");
        goto Cleanup;
    }

    pFlow->pActions = pTargetActions;

    //while we will process the packet, we do not allow its actions to be destroyed
    pOvsNb->pActions = OVS_REFCOUNT_REFERENCE(pTargetActions);
    pOvsNb->pOriginalPacketInfo = &pFlow->maskedPacketInfo;
    pOvsNb->packetPriority = pFlow->maskedPacketInfo.physical.packetPriority;
    pOvsNb->packetMark = pFlow->maskedPacketInfo.physical.packetMark;

    pOvsNb->pDestinationPort = NULL;
    pOvsNb->sendToPortNormal = FALSE;
    pOvsNb->pSourceNic = &sourcePort;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        goto Cleanup;
    }

    pOvsNb->pSwitchInfo = pSwitchInfo;
    pOvsNb->sendFlags = 0;

    if (pOvsNb->pOriginalPacketInfo->physical.ovsInPort != OVS_INVALID_PORT_NUMBER)
    {
        OVS_PERSISTENT_PORT* pSourcePersPort = PersPort_FindByNumber_Ref(pOvsNb->pOriginalPacketInfo->physical.ovsInPort);
        NDIS_SWITCH_PORT_ID portId = NDIS_SWITCH_DEFAULT_PORT_ID;

        //NOTE: actually, the portId of pers port CAN change (when mapping it to a hyper-v switch port)
        //pershaps make it volatile and use it with interlocked ops?
        if (pSourcePersPort && pSourcePersPort->portId != NDIS_SWITCH_DEFAULT_PORT_ID)
        {
            OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

            portId = pSourcePersPort->portId;

            FWDINFO_LOCK_READ(pSwitchInfo->pForwardInfo, &lockState);

            //actually, pNicEntry might have been deleted, even before Packet_Execute
            pNicEntry = Sctx_FindNicByPortId_Unsafe(pSwitchInfo->pForwardInfo, portId);
            if (pNicEntry)
            {
                NicListEntry_To_NicInfo(pNicEntry, &sourcePort);
            }

            FWDINFO_UNLOCK(pSwitchInfo->pForwardInfo, &lockState);
        }

        pOvsNb->pSourcePort = pSourcePersPort;
    }

    else
    {
        pOvsNb->pSourcePort = PersPort_FindInternal_Ref();
    }

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        ok = FALSE;
        DEBUGP(LOG_ERROR, __FUNCTION__ " fail: have no datapath!\n");
        goto Cleanup;
    }

    pOvsNb->pTunnelInfo = NULL;

    if (pOvsNb->pSwitchInfo)
    {
        ok = ExecuteActions(pOvsNb, OutputPacketToPort);
    }
    else
    {
        ok = FALSE;
    }

Cleanup:
    if (pFlow)
    {
        Flow_DestroyNow_Unsafe(pFlow);
    }

    OVS_REFCOUNT_DEREFERENCE(pTargetActions);
    OVS_REFCOUNT_DEREFERENCE(pDatapath);
    OVS_REFCOUNT_DEREFERENCE(pOvsNb->pSourcePort);

    if (ok)
    {
        //NOTE: the NET_BUFFER_LIST and NET_BUFFER and MDL are destroyed on NDIS callback
        KFree(pOvsNb);
    }
    else
    {
        if (pSwitchInfo)
        {
            ONB_Destroy(pSwitchInfo, &pOvsNb);
        }

        OVS_REFCOUNT_DEREF_AND_DESTROY(pTargetActions);
    }

    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);
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
    OVS_DATAPATH* pDatapath = NULL;
    ULONG bufLen = NET_BUFFER_DATA_LENGTH(pNb);

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_INVAL;
    }

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

    //NOTE: make sure pDatapath->switchIfIndex == pSwitchInfo->datapathIfIndex
    msg.dpIfIndex = pDatapath->switchIfIndex;
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    msg.pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!msg.pArgGroup)
    {
        error = OVS_ERROR_INVAL;
        goto Out;
    }

    countArgs = (pUpcallInfo->pUserData ? 3 : 2);

    AllocateArgumentsToGroup(countArgs, msg.pArgGroup);

    pPacketInfoArg = CreateArgFromPacketInfo(pUpcallInfo->pPacketInfo, NULL, OVS_ARGTYPE_PACKET_PI_GROUP);
    OVS_CHECK(pPacketInfoArg);

    i = 0;
    msg.pArgGroup->args[i] = *pPacketInfoArg;
    msg.pArgGroup->groupSize += pPacketInfoArg->length;
    ++i;

    if (pUpcallInfo->pUserData)
    {
        pUserDataArg = CreateArgumentWithSize(OVS_ARGTYPE_PACKET_USERDATA, pUpcallInfo->pUserData->data, pUpcallInfo->pUserData->length);

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
    pNbArg = CreateArgumentWithSize(OVS_ARGTYPE_PACKET_BUFFER, nbBuffer, bufLen);
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
    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    if (msg.pArgGroup)
    {
        DestroyArgumentGroup(msg.pArgGroup);

        KFree(pNbArg);
        KFree(pUserDataArg);
        KFree(pPacketInfoArg);
    }
    else
    {
        //we free, not destroy: the nb inside was not duplicated
        KFree(pNbArg);

        DestroyArgument(pUserDataArg);
        DestroyArgument(pPacketInfoArg);
    }

    return error;
}

BOOLEAN QueuePacketToUserspace(_In_ NET_BUFFER* pNb, _In_ const OVS_UPCALL_INFO* pUpcallInfo)
{
    int dpifindex = 0;
    BOOLEAN ok = TRUE;
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);

    //__DONT_QUEUE_BY_DEFAULT is used for debugging purposes only
#define __DONT_QUEUE_BY_DEFAULT 0

#if __DONT_QUEUE_BY_DEFAULT
    BOOLEAN queuePacket = FALSE;
#endif

    if (pUpcallInfo->portId == 0)
    {
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

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return ok;
}