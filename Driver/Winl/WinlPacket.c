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

static OVS_NET_BUFFER* _CreateONBFromArg(OVS_ARGUMENT* pOnbArg)
{
    OVS_NET_BUFFER* pOvsNb = NULL;
    OVS_BUFFER buffer = { 0 };
    ULONG additionalSize = max(Gre_BytesNeeded(0xFFFF), Vxlan_BytesNeeded(0xFFFF));
    OVS_ETHERNET_HEADER* pEthHeader = NULL;

    buffer.size = pOnbArg->length;
    buffer.offset = 0;
    buffer.p = pOnbArg->data;

    pOvsNb = ONB_CreateFromBuffer(&buffer, additionalSize);
    OVS_CHECK_RET(pOvsNb, NULL);

    pEthHeader = (OVS_ETHERNET_HEADER*)ONB_GetData(pOvsNb);
    OVS_CHECK(RtlUshortByteSwap(pEthHeader->type) >= OVS_ETHERTYPE_802_3_MIN);

    return pOvsNb;
}

static OVS_FLOW* _CreateFlowFromArgs(OVS_NET_BUFFER* pOvsNb, OVS_ARGUMENT_GROUP* pPIArgs, OVS_ARGUMENT_GROUP* pActionsArgs)
{
    OVS_FLOW* pFlow = NULL;
    BOOLEAN ok = TRUE;
    OVS_ACTIONS* pTargetActions = NULL;

    pFlow = Flow_Create();
    OVS_CHECK_GC(pFlow);

    ok = PacketInfo_Extract(ONB_GetData(pOvsNb), ONB_GetDataLength(pOvsNb), OVS_INVALID_PORT_NUMBER, &pFlow->maskedPacketInfo);
    OVS_CHECK_GC(ok);

    ok = GetPacketContextFromPIArgs(pPIArgs, &pFlow->maskedPacketInfo);
    OVS_CHECK_GC(ok);

    pTargetActions = Actions_Create();
    OVS_CHECK_GC(pTargetActions);

    OVS_CHECK_GC(CopyArgumentGroup(pTargetActions->pActionGroup, pActionsArgs, /*actionsToAdd*/0));

    ok = ProcessReceivedActions(pTargetActions->pActionGroup, &pFlow->maskedPacketInfo, /*recursivity depth*/0);
    OVS_CHECK_GC(ok);

    pFlow->pActions = pTargetActions;

Cleanup:
    return pFlow;
}

static VOID _SetOnbMetadata(OVS_NET_BUFFER* pOvsNb, OVS_FLOW* pFlow, OVS_SWITCH_INFO* pSwitchInfo, OVS_DATAPATH* pDatapath)
{
    pOvsNb->pActions = pFlow->pActions;
    pOvsNb->pOriginalPacketInfo = &pFlow->maskedPacketInfo;
    pOvsNb->packetPriority = pFlow->maskedPacketInfo.physical.packetPriority;
    pOvsNb->packetMark = pFlow->maskedPacketInfo.physical.packetMark;

    pOvsNb->pDestinationPort = NULL;
    pOvsNb->sendToPortNormal = FALSE;

    pOvsNb->pSwitchInfo = pSwitchInfo;
    pOvsNb->pDatapath = pDatapath;
    pOvsNb->sendFlags = 0;

    if (pOvsNb->pOriginalPacketInfo->physical.ofInPort != OVS_INVALID_PORT_NUMBER)
    {
        OVS_OFPORT* pSourceOFPort = OFPort_FindByNumber_Ref(pOvsNb->pOriginalPacketInfo->physical.ofInPort);

        pOvsNb->pSourcePort = pSourceOFPort;
    }

    else
    {
        pOvsNb->pSourcePort = OFPort_FindInternal_Ref();
    }

    pOvsNb->pTunnelInfo = NULL;
}

//NOTE: Assuming the verification part has done its job (arg & msg verification), we can use the input data as valid

VOID WinlPacket_Execute(OVS_SWITCH_INFO* pSwitchInfo, OVS_DATAPATH* pDatapath, _In_ OVS_ARGUMENT_GROUP* pArgGroup, const FILE_OBJECT* pFileObject)
{
    OVS_NET_BUFFER* pOvsNb = NULL;
    OVS_FLOW* pFlow = NULL;
    BOOLEAN ok = FALSE;
    //OVS_NIC_INFO sourcePort = { 0 };
    
    OVS_ARGUMENT* pOnbArg = NULL;
    OVS_ARGUMENT_GROUP* pPacketInfoArgs = NULL, *pActionsArgs = NULL;

    UNREFERENCED_PARAMETER(pFileObject);

    pOnbArg = FindArgument(pArgGroup, OVS_ARGTYPE_PACKET_BUFFER);
    OVS_CHECK(pOnbArg);

    //i.e. packet info
    pPacketInfoArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_PACKET_PI_GROUP);
    OVS_CHECK(!pPacketInfoArgs);

    pActionsArgs = FindArgumentGroup(pArgGroup, OVS_ARGTYPE_PACKET_ACTIONS_GROUP);
    OVS_CHECK(pActionsArgs);

    pOvsNb = _CreateONBFromArg(pOnbArg);
    OVS_CHECK_GC(pOvsNb);

    pFlow = _CreateFlowFromArgs(pOvsNb, pPacketInfoArgs, pActionsArgs);
    OVS_CHECK_GC(pFlow);

    OVS_REFCOUNT_REFERENCE(pFlow->pActions)

    //while we will process the packet, we do not allow its actions to be destroyed
    _SetOnbMetadata(pOvsNb, pFlow, pSwitchInfo, pDatapath);

    ok = ExecuteActions(pOvsNb, OutputPacketToPort);

Cleanup:
    if (pFlow)
    {
        OVS_REFCOUNT_DEREF_AND_DESTROY(pFlow->pActions);

        Flow_DestroyNow_Unsafe(pFlow);
    }

    OVS_REFCOUNT_DEREFERENCE(pOvsNb->pSourcePort);

    if (ok)
    {
        //NOTE: the NET_BUFFER_LIST and NET_BUFFER and MDL are destroyed on NDIS callback
        KFree(pOvsNb);
    }
    else
    {
        ONB_Destroy(pSwitchInfo, &pOvsNb);   
    }
}

static OVS_ERROR _QueueUserspacePacket(OVS_DATAPATH* pDatapath, _In_ NET_BUFFER* pNb, _In_ const OVS_UPCALL_INFO* pUpcallInfo)
{
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_MESSAGE msg = { 0 };
    UINT16 countArgs = 0;
    OVS_ARGUMENT* pPacketInfoArg = NULL, *pNbArg = NULL, *pUserDataArg = NULL;
    ULONG i = 0;
    VOID* nbBuffer = NULL;
    ULONG bufLen = NET_BUFFER_DATA_LENGTH(pNb);
    countArgs = (pUpcallInfo->pUserData ? 3 : 2);
    UINT32 sequence = _NextUpcallSequence();

    nbBuffer = NdisGetDataBuffer(pNb, bufLen, NULL, 1, 0);

    CHECK_B_E(nbBuffer, OVS_ERROR_INVAL);
    CHECK_B_E(bufLen > USHORT_MAX, OVS_ERROR_INVAL);

    CHECK_E(CreateMsg(&msg, pUpcallInfo->portId, sequence, sizeof(OVS_MESSAGE), OVS_MESSAGE_TARGET_PACKET, pUpcallInfo->command,
        pDatapath->switchIfIndex, countArgs));

    pPacketInfoArg = CreateArgFromPacketInfo(pUpcallInfo->pPacketInfo, NULL, OVS_ARGTYPE_PACKET_PI_GROUP);
    CHECK_B_E(pPacketInfoArg, OVS_ERROR_INVAL);

    AddArgToArgGroup(msg.pArgGroup, pPacketInfoArg, &i);

    if (pUpcallInfo->pUserData)
    {
        pUserDataArg = CreateArgumentWithSize(OVS_ARGTYPE_PACKET_USERDATA, pUpcallInfo->pUserData->data, pUpcallInfo->pUserData->length);
        CHECK_B_E(pUserDataArg, OVS_ERROR_NOMEM);

        AddArgToArgGroup(msg.pArgGroup, pUserDataArg, &i);
    }

    //we send the net buffer data and only it: starting from eth -> payload.
    pNbArg = CreateArgumentWithSize(OVS_ARGTYPE_PACKET_BUFFER, nbBuffer, bufLen);
    CHECK_B_E(pNbArg, OVS_ERROR_NOMEM);

    AddArgToArgGroup(msg.pArgGroup, pNbArg, &i);

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

Cleanup:
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

BOOLEAN QueuePacketToUserspace(OVS_DATAPATH* pDatapath, _In_ NET_BUFFER* pNb, _In_ const OVS_UPCALL_INFO* pUpcallInfo)
{
    int dpifindex = 0;
    BOOLEAN ok = TRUE;

    if (pUpcallInfo->portId == 0)
    {
        ok = FALSE;
        goto Cleanup;
    }

    dpifindex = pDatapath->switchIfIndex;

    OVS_ERROR error = _QueueUserspacePacket(pDatapath, pNb, pUpcallInfo);
    if (error != OVS_ERROR_NOERROR)
    {
        //no other kind of error except 'no space' (for queued buffers) normally happen.
        //or NOENT = file not found (where to write the info to)
        OVS_CHECK(error == OVS_ERROR_NOSPC || error == OVS_ERROR_NOENT);

        goto Cleanup;
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