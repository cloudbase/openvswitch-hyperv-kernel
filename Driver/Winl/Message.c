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

#include "Message.h"
#include "Buffer.h"
#include "ArgumentType.h"
#include "Nbls.h"
#include "Winetlink.h"
#include "OFPort.h"
#include "AttrToArgument.h"
#include "ArgToAttribute.h"

static BOOLEAN _ParseAttribute(_In_ BYTE** pBuffer, UINT16* pBytesLeft, _Inout_ OVS_ARGUMENT* pOutArg, OVS_ARGTYPE parentArgType, UINT16 targetType, UINT8 cmd)
{
    OVS_ARGUMENT* pAttribute = (OVS_ARGUMENT*)*pBuffer;
    OVS_ARGTYPE typeAsArg = OVS_ARGTYPE_GROUP_MAIN;

    if (*pBytesLeft < OVS_ARGUMENT_HEADER_SIZE)
    {
        return FALSE;
    }

    pOutArg->length = pAttribute->length - OVS_ARGUMENT_HEADER_SIZE;
    pOutArg->data = NULL;
    pOutArg->freeData = TRUE;

    *pBuffer += OVS_ARGUMENT_HEADER_SIZE;
    *pBytesLeft -= OVS_ARGUMENT_HEADER_SIZE;

    if (!AttrType_To_ArgType(targetType, pAttribute->type, parentArgType, &typeAsArg))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed: attr to argument failed for attr: %u\n", pAttribute->type);
        return FALSE;
    }

    pOutArg->type = typeAsArg;

    if (IsArgTypeGroup(typeAsArg))
    {
        OVS_ARGUMENT_GROUP* pGroup = AllocArgumentGroup();

        if (!pGroup)
        {
            return FALSE;
        }

        if (!_ParseArgGroup_FromAttributes(pBuffer, pBytesLeft, pOutArg->length, pGroup, typeAsArg, targetType, cmd))
        {
            return FALSE;
        }

        pOutArg->data = pGroup;

        pOutArg->length = pGroup->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
    }
    else
    {
        if (*pBytesLeft < pOutArg->length)
        {
            return FALSE;
        }

        if (pOutArg->length)
        {
            pOutArg->data = ExAllocatePoolWithTag(NonPagedPool, pOutArg->length, g_extAllocationTag);

            if (!pOutArg->data)
            {
                return FALSE;
            }

            RtlCopyMemory(pOutArg->data, *pBuffer, pOutArg->length);
        }

        *pBuffer += pOutArg->length;
        *pBytesLeft -= pOutArg->length;
    }

    return TRUE;
}

static BOOLEAN _CountAttributes(BYTE* buffer, ULONG totalLength, UINT16* pCount)
{
    OVS_ARGUMENT* pArg = NULL;
    UINT16 count = 0;
    ULONG len = 0;

    pArg = (OVS_ARGUMENT*)buffer;
    ++count;
    len += pArg->length;

    while (len < totalLength)
    {
        pArg = (OVS_ARGUMENT*)((BYTE*)pArg + pArg->length);

        ++count;
        len += pArg->length;

        if (pArg->length <= 0)
        {
            DEBUGP(LOG_ERROR, "Asserting in _CountAttributes pArg->length <= 0\n");
            OVS_CHECK(0);
            break;
        }
    }

    if (len > totalLength)
    {
        return FALSE;
    }

    *pCount = count;
    return TRUE;
}

//i.e. the buffer starts with the first nlattr in the list
static BOOLEAN _ParseArgGroup_FromAttributes(_In_ BYTE** ppBuffer, UINT16* pBytesLeft, UINT16 groupSize, _Inout_ OVS_ARGUMENT_GROUP* pGroup, OVS_ARGTYPE parentArgType, UINT16 targetType, UINT8 cmd)
{
    OVS_CHECK(pGroup);

    if (groupSize == 0)
    {
        //the main group must have count args > 0
        if (parentArgType == OVS_ARGTYPE_GROUP_MAIN)
        {
            return FALSE;
        }

        RtlZeroMemory(pGroup, sizeof(OVS_ARGUMENT_GROUP));
        return TRUE;
    }

    if (*pBytesLeft < OVS_ARGUMENT_HEADER_SIZE)
    {
        return FALSE;
    }

    if (!_CountAttributes(*ppBuffer, groupSize, &pGroup->count))
    {
        return FALSE;
    }

    OVS_CHECK(pGroup->count > 0);
    AllocateArgumentsToGroup(pGroup->count, pGroup);

    pGroup->groupSize = pGroup->count * OVS_ARGUMENT_HEADER_SIZE;

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        if (!_ParseAttribute(ppBuffer, pBytesLeft, pGroup->args + i, parentArgType, targetType, cmd))
        {
            return FALSE;
        }

        pGroup->groupSize += (pGroup->args + i)->length;
    }

    return TRUE;
}

BOOLEAN ParseReceivedMessage(VOID* buffer, UINT16 length, _Out_ OVS_NLMSGHDR** ppNlMessage)
{
    UINT16 bytesLeft = length;
    OVS_MESSAGE* pBufferedMsg = buffer, *pMessage = NULL;
    OVS_NLMSGHDR* pNlMessage = NULL;
    BOOLEAN ok = TRUE;

    OVS_CHECK(ppNlMessage);
    *ppNlMessage = NULL;

    if (length >= sizeof(OVS_NLMSGHDR))
    {
        OVS_NLMSGHDR* pOriginalHeader = (OVS_NLMSGHDR*)buffer;

        switch (pOriginalHeader->type)
        {
        case OVS_MESSAGE_TARGET_DATAPATH:
        case OVS_MESSAGE_TARGET_FLOW:
        case OVS_MESSAGE_TARGET_PORT:
        case OVS_MESSAGE_TARGET_PACKET:
            length = sizeof(OVS_MESSAGE);
            break;

        default:
            break;
        }

        pNlMessage = KAlloc(length);
        if (!pNlMessage)
        {
            return FALSE;
        }

        RtlZeroMemory(pNlMessage, length);
        *((OVS_NLMSGHDR*)pNlMessage) = *((OVS_NLMSGHDR*)pBufferedMsg);
    }
    else
    {
        DEBUGP(LOG_ERROR, "message to small - it's not even a NLMSGHDR!\n");
        return FALSE;
    }

    switch (pNlMessage->type)
    {
    case OVS_MESSAGE_TARGET_CONTROL:
        goto Cleanup;

    case OVS_MESSAGE_TARGET_RTM_GETROUTE:
        goto Cleanup;

    case OVS_MESSAGE_TARGET_SET_FILE_PID:
        goto Cleanup;

    case OVS_MESSAGE_TARGET_MULTICAST:
        ((OVS_MESSAGE_MULTICAST*)pNlMessage)->join = ((OVS_MESSAGE_MULTICAST*)pBufferedMsg)->join;
        goto Cleanup;

    case OVS_MESSAGE_TARGET_DATAPATH:
    case OVS_MESSAGE_TARGET_FLOW:
    case OVS_MESSAGE_TARGET_PORT:
    case OVS_MESSAGE_TARGET_PACKET:
        OVS_CHECK(pNlMessage->length >= OVS_MESSAGE_HEADER_SIZE);
        pMessage = (OVS_MESSAGE*)pNlMessage;
        pMessage->pArgGroup = NULL;
        break;

    case OVS_MESSAGE_TARGET_DUMP_DONE:
        goto Cleanup;

    case OVS_MESSAGE_TARGET_ERROR:
    {
        OVS_MESSAGE_ERROR* pErrorMsg = (OVS_MESSAGE_ERROR*)pNlMessage;
        OVS_CHECK(pErrorMsg->length == sizeof(OVS_MESSAGE_ERROR));

        RtlCopyMemory(pErrorMsg, pBufferedMsg, pErrorMsg->length);
        goto Cleanup;
    }

    default:
        ok = FALSE;
        goto Cleanup;
    }

    pMessage->command = pBufferedMsg->command;

    if (pMessage->type == OVS_MESSAGE_TARGET_PACKET)
    {
        pMessage->command = UserspacePacketCmdToKernelCmd(pMessage->command);
    }

    pMessage->version = pBufferedMsg->version;

    if (pMessage->version != 1)
    {
        DEBUGP(LOG_WARN, "cmd %d has unsupported version %d\n", pMessage->command, pMessage->version);
    }

    pMessage->reserved = pBufferedMsg->reserved;

    pMessage->dpIfIndex = pBufferedMsg->dpIfIndex;

    DEBUGP_ARG(LOG_INFO, "MSG: type=%x; cmd=%x;\n", pMessage->type, pMessage->command);

    buffer = (BYTE*)buffer + OVS_MESSAGE_HEADER_SIZE;
    bytesLeft -= OVS_MESSAGE_HEADER_SIZE;

    if (bytesLeft == 0)
    {
        goto Cleanup;
    }

    pMessage->pArgGroup = AllocArgumentGroup();

    if (!pMessage->pArgGroup)
    {
        goto Cleanup;
    }

    RtlZeroMemory(pMessage->pArgGroup, sizeof(OVS_ARGUMENT_GROUP));

    DEBUGP_ARG(LOG_INFO, "arg hdr size: 0x%x; group hdr size: 0x%x\n", OVS_ARGUMENT_HEADER_SIZE, OVS_ARGUMENT_GROUP_HEADER_SIZE);

    if (!_ParseArgGroup_FromAttributes((BYTE**)&buffer, &bytesLeft, bytesLeft, /*out*/pMessage->pArgGroup, OVS_ARGTYPE_GROUP_MAIN, pMessage->type, pMessage->command))
    {
        OVS_CHECK(__UNEXPECTED__);

        ok = FALSE;
        goto Cleanup;
    }

    OVS_CHECK(bytesLeft == 0);

Cleanup:
    if (ok)
    {
        *ppNlMessage = pNlMessage;
    }
    else
    {
        KFree(pNlMessage);
    }

    return ok;
}

static VOID _DestroyAttribute(OVS_ATTRIBUTE* pAttribute)
{
    if (pAttribute->isNested)
    {
        ULONG dataLen = pAttribute->length - OVS_ARGUMENT_HEADER_SIZE;
        UINT16 i = 0;
        OVS_ARGUMENT* pAttrArray = pAttribute->data;

        while (dataLen >= OVS_ARGUMENT_HEADER_SIZE)
        {
            OVS_ARGUMENT* pChildAttr = pAttrArray + i;

            _DestroyAttribute(pChildAttr);

            ++i;
            OVS_CHECK(dataLen >= pChildAttr->length);
            dataLen -= pChildAttr->length;
        }

        if (pAttrArray)
        {
            FreeArgument(pAttrArray);
        }
        else
        {
            OVS_CHECK(dataLen == 0);
        }
    }
}

static VOID _DestroyAttributes(OVS_ATTRIBUTE* pAttributes, UINT count)
{
    for (UINT i = 0; i < count; ++i)
    {
        OVS_ATTRIBUTE* pAttr = pAttributes + i;

        _DestroyAttribute(pAttr);
    }

    FreeArgument(pAttributes);
}

static OVS_ARGUMENT* _ArgumentsToAttributes(ULONG target, ULONG cmd, OVS_ARGTYPE parentArgType, _In_ const OVS_ARGUMENT* pArgs, UINT16 count, UINT16* pGroupSize)
{
    OVS_ARGUMENT* pAttributes = NULL;
    BOOLEAN ok = TRUE;
    UINT16 groupSize = 0;

    OVS_CHECK(count != 0);

    pAttributes = KZAlloc(count);

    for (UINT16 i = 0; i < count; ++i)
    {
        const OVS_ARGUMENT* pArg = pArgs + i;
        OVS_ARGUMENT* pAttr = pAttributes + i;

        if (IsArgTypeGroup(pArg->type))
        {
            OVS_ARGUMENT_GROUP* pArgGroup = pArg->data;
            UINT16 subGroupSize = 0;
            OVS_ARGUMENT* pSubAttrs = NULL;

            if (pArgGroup->count > 0)
            {
                pSubAttrs = _ArgumentsToAttributes(target, cmd, pArg->type, pArgGroup->args, pArgGroup->count, &subGroupSize);
                if (!pSubAttrs)
                {
                    ok = FALSE;
                    break;
                }
            }

            pAttr->isNested = TRUE;
            pAttr->type = pArg->type;
            pAttr->length = subGroupSize + OVS_ARGUMENT_HEADER_SIZE;
            pAttr->data = pSubAttrs;
            pAttr->freeData = TRUE;

            groupSize += pAttr->length;

            if (!Reply_SetAttrType(target, cmd, parentArgType, pAttr))
            {
                if (pSubAttrs)
                {
                    FreeArgument(pSubAttrs);
                }

                ok = FALSE;
                break;
            }
        }
        else
        {
            //NOTE: arg data is not copied, the pointer is copied!
            RtlCopyMemory(pAttr, pArg, sizeof(OVS_ARGUMENT));
            pAttr->length = pArg->length + OVS_ARGUMENT_HEADER_SIZE;
            pAttr->isNested = FALSE;
            pAttr->freeData = TRUE;

            groupSize += pAttr->length;

            if (!Reply_SetAttrType(target, cmd, parentArgType, pAttr))
            {
                ok = FALSE;
                break;
            }
        }
    }

    if (!ok)
    {
        FreeArgument(pAttributes);
        return NULL;
    }

    if (pGroupSize)
    {
        *pGroupSize = groupSize;
    }

    return pAttributes;
}

static __inline VOID _WriteArgToBuffer_AsAttribute(UINT16 targetType, BYTE** pBuffer, OVS_ARGTYPE parentArgType, OVS_ARGUMENT* pAttr, UINT* pOffset)
{
    OVS_ARGTYPE typeAsArg = { 0 };

    RtlCopyMemory(*pBuffer, &pAttr->length, sizeof(pAttr->length));
    *pBuffer += sizeof(pAttr->length);
    *pOffset += sizeof(pAttr->length);

    RtlCopyMemory(*pBuffer, &pAttr->type, sizeof(pAttr->type));
    *pBuffer += sizeof(pAttr->type);
    *pOffset += sizeof(pAttr->type);

    if (!AttrType_To_ArgType(targetType, pAttr->type, parentArgType, &typeAsArg))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed: attr to argument failed for attr: %u\n", pAttr->type);
        OVS_CHECK(0);

        return;
    }

    if (IsArgTypeGroup(typeAsArg))
    {
        ULONG dataLen = pAttr->length - OVS_ARGUMENT_HEADER_SIZE;
        UINT16 i = 0;
        OVS_ARGUMENT* pAttrArray = pAttr->data;

        while (dataLen >= OVS_ARGUMENT_HEADER_SIZE)
        {
            OVS_ARGUMENT* pChildAttr = pAttrArray + i;

            _WriteArgToBuffer_AsAttribute(targetType, pBuffer, typeAsArg, pChildAttr, pOffset);

            ++i;
            OVS_CHECK(dataLen >= pChildAttr->length);
            dataLen -= pChildAttr->length;
        }
    }
    else
    {
        UINT16 dataLen = pAttr->length - OVS_ARGUMENT_HEADER_SIZE;

        RtlCopyMemory(*pBuffer, pAttr->data, dataLen);
        *pBuffer += dataLen;
        *pOffset += dataLen;
    }
}

BOOLEAN WriteMsgsToBuffer(_In_ OVS_NLMSGHDR* pMsgs, int countMsgs, OVS_BUFFER* pBuffer)
{
    UINT bufSize = 0, groupSize = 0, totalBufSize = 0;
    BYTE* pos = NULL;
    UINT offset = 0;
    OVS_ARGUMENT* pAttributes = NULL;
    OVS_NLMSGHDR* pNlMsg = NULL;

    OVS_CHECK(countMsgs);
    OVS_CHECK(pBuffer);
    OVS_CHECK(pBuffer->p == NULL && pBuffer->size == 0 && pBuffer->offset == 0);

    OVS_CHECK(pMsgs);

#if DBG
    pNlMsg = pMsgs;

    for (int i = 0; i < countMsgs; ++i)
    {
        if (pNlMsg->type == OVS_MESSAGE_TARGET_DUMP_DONE)
        {
            OVS_CHECK(pNlMsg->length == sizeof(OVS_MESSAGE_DONE));
        }
        else if (pNlMsg->type == OVS_MESSAGE_TARGET_ERROR)
        {
            OVS_CHECK(pNlMsg->length == sizeof(OVS_MESSAGE_ERROR));
        }
        else
        {
            OVS_MESSAGE* pMsg = (OVS_MESSAGE*)pNlMsg;

            OVS_CHECK(pMsg->pArgGroup);
            OVS_CHECK(pMsg->pArgGroup->count > 0);
            UNREFERENCED_PARAMETER(pMsg);
        }

        pNlMsg = AdvanceMessage(pNlMsg);
    }

#endif

    totalBufSize = 0;

    pNlMsg = pMsgs;

    for (int i = 0; i < countMsgs; ++i)
    {
        if (pNlMsg->type == OVS_MESSAGE_TARGET_DUMP_DONE)
        {
            groupSize = 0;
            bufSize = sizeof(OVS_MESSAGE_DONE);
        }
        else if (pNlMsg->type == OVS_MESSAGE_TARGET_ERROR)
        {
            groupSize = 0;
            bufSize = sizeof(OVS_MESSAGE_ERROR);
        }
        else
        {
            OVS_MESSAGE* pMsg = (OVS_MESSAGE*)pNlMsg;
            groupSize = pMsg->pArgGroup->groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE;
            bufSize = OVS_MESSAGE_HEADER_SIZE + groupSize;

            if (pMsg->type == OVS_MESSAGE_TARGET_PACKET)
            {
                pMsg->command = (UINT8)KernelPacketCmdToUserspaceCmd(pMsg->command);
            }
        }

        totalBufSize += bufSize;
        pNlMsg = AdvanceMessage(pNlMsg);
    }

    if (!AllocateBuffer(pBuffer, totalBufSize))
    {
        return FALSE;
    }

    offset = 0;

    pNlMsg = pMsgs;
    for (int i = 0; i < countMsgs; ++i)
    {
        ULONG msgOffset = offset;
        UINT msgHeaderSize;
        OVS_ARGUMENT_GROUP* pGroup;

        if (pNlMsg->type == OVS_MESSAGE_TARGET_DUMP_DONE || pNlMsg->type == OVS_MESSAGE_TARGET_ERROR)
        {
            msgHeaderSize = pNlMsg->length;
            pGroup = NULL;
        }
        else
        {
            msgHeaderSize = OVS_MESSAGE_HEADER_SIZE;
            pGroup = ((OVS_MESSAGE*)pNlMsg)->pArgGroup;
        }

        pos = (BYTE*)pBuffer->p + offset;
        RtlCopyMemory(pos, pNlMsg, msgHeaderSize);

        pos += msgHeaderSize;
        offset += msgHeaderSize;

        if (pGroup)
        {
            OVS_MESSAGE* pMsg = (OVS_MESSAGE*)pNlMsg;
            UINT16 groupSize = 0;

            pAttributes = _ArgumentsToAttributes(pMsg->type, pMsg->command, OVS_ARGTYPE_GROUP_MAIN, pGroup->args, pGroup->count, &groupSize);

            if (!pAttributes)
            {
                FreeBufferData(pBuffer);
                return FALSE;
            }

            for (UINT i = 0; i < pGroup->count; ++i)
            {
                _WriteArgToBuffer_AsAttribute(pMsg->type, &pos, OVS_ARGTYPE_GROUP_MAIN, pAttributes + i, &offset);
            }

            _DestroyAttributes(pAttributes, pMsg->pArgGroup->count);

            pMsg = (OVS_MESSAGE*)((BYTE*)pBuffer->p + msgOffset);
            pMsg->length = offset - msgOffset;
        }

        pBuffer->size = offset;
        pNlMsg = AdvanceMessage(pNlMsg);
    }

    return TRUE;
}

static BOOLEAN _VerifyFlowMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGUMENT* pArg = NULL;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
    case OVS_MESSAGE_COMMAND_SET:
        //request / flow / NEW must have: key & packet actions. keymask is optional.
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_PI);
            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pArg->data, OVS_ARGTYPE_PI_ETH_TYPE))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have key argtype: 0x%x", OVS_ARGTYPE_PI_ETH_TYPE);

            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pArg->data, OVS_ARGTYPE_PI_ETH_ADDRESS))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have key argtype: 0x%x", OVS_ARGTYPE_PI_ETH_ADDRESS);

            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_ACTIONS);
            OVS_CHECK(0);
            return FALSE;
        }

        break;

    case OVS_MESSAGE_COMMAND_DELETE:
        //request / flow / DELETE - must have: key
        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_PI);
            OVS_CHECK(0);
            return FALSE;
        }

        break;

    case OVS_MESSAGE_COMMAND_GET:
        //request / flow / GET - must have: key
        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_PI);
            OVS_CHECK(0);
            return FALSE;
        }
        break;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (cmd)
        {
        case OVS_MESSAGE_COMMAND_NEW:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_GROUP_PI:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_GROUP_MASK:
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

                //NOTE: set info cannot check here if the given packet info specify eth type / proto acc to set info
                //nor can check the masks.
            case OVS_ARGTYPE_GROUP_ACTIONS:
                if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_CLEAR:
                if (!VerifyArg_Flow_Clear(pMainGroupArg))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_SET:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_GROUP_PI:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_GROUP_MASK:
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_GROUP_ACTIONS:
                if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_CLEAR:
                if (!VerifyArg_Flow_Clear(pMainGroupArg))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd SET should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_DELETE:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_GROUP_PI:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd DELETE should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_GET:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_GROUP_PI:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd GET should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_DUMP:
            if (argType == OVS_ARGTYPE_GROUP_MASK)
            {
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;
            }
            else
            {
                DEBUGP_ARG(LOG_ERROR, "Flow cmd DUMP should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            //request / flow / DUMP mustn't have any arg... perhaps it must have no arg...
            break;

        case OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE:
            DEBUGP_ARG(LOG_ERROR, "Flow should not have command EXECUTE!");
            OVS_CHECK(0);
            return FALSE;

        default:
            DEBUGP_ARG(LOG_ERROR, "Invalid flow request command: 0x%x", cmd);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyFlowMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    UNREFERENCED_PARAMETER(cmd);

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        //replies may have:
        /* Packet Actions
            Stats
            Tcp Flags
            Time Used
            */

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_ACTIONS:
            if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ FALSE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_STATS:
            if (!VerifyArg_Flow_Stats(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_TCP_FLAGS:
            if (!VerifyArg_Flow_TcpFlags(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_TIME_USED:
            if (!VerifyArg_Flow_TimeUsed(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_PI:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_MASK:
            if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "flow reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyArg_PacketBuffer(OVS_ARGUMENT* pPacketBufferArg)
{
    if (!VerifyNetBuffer(pPacketBufferArg->data, pPacketBufferArg->length))
    {
        DEBUGP_ARG(LOG_ERROR, "invalid packet buffer!");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPacketMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGUMENT* pArg = NULL;

    if (cmd != OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE)
    {
        DEBUGP_ARG(LOG_ERROR, "Packet request should have cmd = execute. Found cmd: 0x%x", cmd);
        OVS_CHECK(0);
        return FALSE;
    }

    //request / packet / exec must have: buffer, packet info, actions - all required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_NETBUFFER);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_NETBUFFER);
        OVS_CHECK(0);
        return FALSE;
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_PI);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_PI);
        OVS_CHECK(0);
        return FALSE;
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_ACTIONS);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_GROUP_ACTIONS);
        OVS_CHECK(0);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_NETBUFFER:
            if (!_VerifyArg_PacketBuffer(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_GROUP_PI:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

            //NOTE: set info cannot check here if the given packet info-s specify eth type / proto acc to set info
            //nor can check the masks.
        case OVS_ARGTYPE_GROUP_ACTIONS:
            if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyArg_UserData(OVS_ARGUMENT* pUserDataArg)
{
    UNREFERENCED_PARAMETER(pUserDataArg);

    DEBUGP_ARG(LOG_LOUD, "don't know how to check packet / user data arg\n");

    return TRUE;
}

static BOOLEAN _VerifyPacketMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    //req: OVS_ARGTYPE_GROUP_PI
    //opt: OVS_ARGTYPE_PACKET_USERDATA
    //req: OVS_ARGTYPE_PACKET_BUFFER

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION:
    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS:
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for packet reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        if (!(argType == OVS_ARGTYPE_GROUP_PI ||
            argType == OVS_ARGTYPE_NETBUFFER_USERDATA ||
            argType == OVS_ARGTYPE_NETBUFFER))
        {
            DEBUGP_ARG(LOG_ERROR, "reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }

        switch (argType)
        {
        case OVS_ARGTYPE_GROUP_PI:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_NETBUFFER_USERDATA:
            if (!_VerifyArg_UserData(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_NETBUFFER:
            if (!_VerifyArg_PacketBuffer(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        default:
            OVS_CHECK(0);
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyDatapathMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
        //not allowed
        //DEBUGP_ARG(LOG_WARN, "Datapath command New: ignore!\n");
        break;

    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_GET:
        if (pMsg->pArgGroup->count > 1)
        {
            DEBUGP_ARG(LOG_ERROR, "Datapath request GET should have max 1 args. Found count: 0x%x", pMsg->pArgGroup->count);
            return FALSE;
        }
        else if (pMsg->pArgGroup->count == 1)
        {
            OVS_ARGUMENT* pArg = pMsg->pArgGroup->args;

            if (pArg->type != OVS_ARGTYPE_DATAPATH_NAME)
            {
                DEBUGP_ARG(LOG_ERROR, "Datapath request GET has 1 arg, and it's not datapath name. It is: 0x%x", pArg->type);
            }

            return TRUE;
        }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath request: 0x%x", cmd);
        return FALSE;
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _IsStringPrintableA(const char* str, UINT16 len)
{
    for (UINT16 i = 0; i < len; ++i)
    {
        if (str[i] == 0)
        {
            break;
        }

        //verify that all chars are printable chars
        if (!(str[i] >= 0x20 && str[i] <= 0x7e))
        {
            DEBUGP_ARG(LOG_ERROR, "name not printable: %s", str);
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN _VerifyDatapathMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    {
        OVS_ARGUMENT* pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_NAME);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "datapath reply does not have arg: name\n");
            OVS_CHECK(0);
            return FALSE;
        }

        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_STATS);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "datapath reply does not have arg: stats\n");
            OVS_CHECK(0);
            return FALSE;
        }
    }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        UINT argType = pMainGroupArg->type;

        if (!(argType == OVS_ARGTYPE_DATAPATH_NAME ||
            argType == OVS_ARGTYPE_DATAPATH_STATS))
        {
            DEBUGP_ARG(LOG_ERROR, "reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }

        switch (argType)
        {
        case OVS_ARGTYPE_DATAPATH_NAME:
        {
            const char* name = pMainGroupArg->data;
            if (!_IsStringPrintableA(name, pMainGroupArg->length))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_DATAPATH_STATS:
            break;

        default:
            OVS_CHECK(0);
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPortMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
        //DEBUGP(LOG_WARN, "we don't verify args for request port new!\n");
        break;

    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    case OVS_MESSAGE_COMMAND_DELETE:
    {
        OVS_ARGUMENT* pNameArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);

        if (!pNameArg &&
            !FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER))
        {
            DEBUGP_ARG(LOG_ERROR, "Port request GET: could not find arg port name / number\n");
            return FALSE;
        }

        if (pNameArg)
        {
            if (!_IsStringPrintableA(pNameArg->data, pNameArg->length))
            {
                return FALSE;
            }
        }
    }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath request: 0x%x", cmd);
        return FALSE;
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPortMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    case OVS_MESSAGE_COMMAND_DUMP:
        DEBUGP_ARG(LOG_ERROR, "for reply we expect command = new; have: 0x%x", cmd);
        return FALSE;

    case OVS_MESSAGE_COMMAND_NEW:
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for port reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_OFPORT_NAME:
        {
            const char* name = pMainGroupArg->data;
            for (UINT16 i = 0; i < pMainGroupArg->length; ++i)
            {
                if (name[i] == 0)
                {
                    break;
                }

                //verify that all chars are printable chars
                if (!(name[i] >= 0x20 && name[i] <= 0x7e))
                {
                    DEBUGP_ARG(LOG_ERROR, "reply should have name arg all printable chars: %s", name);
                    //OVS_CHECK(0);
                    return FALSE;
                }
            }
        }
            break;

        case OVS_ARGTYPE_OFPORT_NUMBER:
            break;

        case OVS_ARGTYPE_OFPORT_TYPE:
        {
            UINT16 portType = GET_ARG_DATA(pMainGroupArg, UINT16);
            switch (portType)
            {
            case OVS_OFPORT_TYPE_PHYSICAL:
            case OVS_OFPORT_TYPE_MANAG_OS:
            case OVS_OFPORT_TYPE_GRE:
            case OVS_OFPORT_TYPE_VXLAN:
                break;

            default:
                DEBUGP(LOG_ERROR, "invalid port type: %d\n", portType);
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID:
            break;

        case OVS_ARGTYPE_OFPORT_STATS:
            break;

        case OVS_ARGTYPE_GROUP_OFPORT_OPTIONS:
        {
            OVS_ARGUMENT_GROUP* pGroup = pMainGroupArg->data;

            OVS_ARGUMENT* pArg = pGroup->args;

            if (pGroup->count != 1)
            {
                DEBUGP(LOG_ERROR, "expected port options count: 1; have: %d", pGroup->count);
                return FALSE;
            }

            if (pArg->type != OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT)
            {
                DEBUGP(LOG_ERROR, "invalid port option: %d; expected dest port = %d", pArg->type, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT);
                return FALSE;
            }
        }
            break;

        default:
            OVS_CHECK(0);
        }
    }

    if (!VerifyArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_GROUP_MAIN))
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest)
{
    switch (pMsg->type)
    {
    case OVS_MESSAGE_TARGET_INVALID:
        DEBUGP_ARG(LOG_ERROR, "target type == invalid!");
        OVS_CHECK(0);
        return FALSE;

    case OVS_MESSAGE_TARGET_FLOW:
    {
        OVS_MESSAGE* pFlowMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyFlowMessageRequest(pFlowMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyFlowMessageReply(pFlowMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_DATAPATH:
    {
        OVS_MESSAGE* pDatapathMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyDatapathMessageRequest(pDatapathMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyDatapathMessageReply(pDatapathMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_PORT:
    {
        OVS_MESSAGE* pPortMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyPortMessageRequest(pPortMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyPortMessageReply(pPortMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_PACKET:
    {
        OVS_MESSAGE* pPacketMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyPacketMessageRequest(pPacketMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyPacketMessageReply(pPacketMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_CONTROL:
        //TODO add functionality for checking
        return TRUE;

    case OVS_MESSAGE_TARGET_DUMP_DONE:
        OVS_CHECK(!isRequest);
        OVS_CHECK(pMsg->length == sizeof(OVS_MESSAGE_DONE));
        return TRUE;

    case OVS_MESSAGE_TARGET_ERROR:
        OVS_CHECK(!isRequest);
        OVS_CHECK(pMsg->length == sizeof(OVS_MESSAGE_ERROR));
        return TRUE;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid target type: 0x%x", pMsg->type);
        OVS_CHECK(0);
        return FALSE;
    }

    //verify: duplicates; required
}