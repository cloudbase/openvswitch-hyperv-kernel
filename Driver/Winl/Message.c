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
#include "AttrToArgument.h"
#include "ArgToAttribute.h"
#include "ArgVerification.h"

static BOOLEAN _ParseArgGroup_FromAttributes(_In_ BYTE** ppBuffer, UINT16* pBytesLeft, UINT16 groupSize, _Inout_ OVS_ARGUMENT_GROUP* pGroup, OVS_ARGTYPE parentArgType, UINT16 targetType, UINT8 cmd);;

static BOOLEAN _ParseAttribute(_In_ BYTE** pBuffer, UINT16* pBytesLeft, _Inout_ OVS_ARGUMENT* pOutArg, OVS_ARGTYPE parentArgType, UINT16 targetType, UINT8 cmd)
{
    OVS_NL_ATTRIBUTE* pAttribute = (OVS_NL_ATTRIBUTE*)*pBuffer;
    OVS_ARGTYPE typeAsArg = OVS_ARGTYPE_INVALID;

    if (*pBytesLeft < OVS_ARGUMENT_HEADER_SIZE)
    {
        return FALSE;
    }

    pOutArg->length = pAttribute->length - OVS_ARGUMENT_HEADER_SIZE;
    pOutArg->data = NULL;
    pOutArg->freeData = TRUE;

    *pBuffer += OVS_ARGUMENT_HEADER_SIZE;
    *pBytesLeft -= OVS_ARGUMENT_HEADER_SIZE;

    if (!AttrType_To_ArgType(pAttribute->type, parentArgType, &typeAsArg))
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " failed: attr to argument failed for attr: %u\n", pAttribute->type);
        return FALSE;
    }

    pOutArg->type = typeAsArg;

    if (IsArgTypeGroup(typeAsArg))
    {
        OVS_ARGUMENT_GROUP* pGroup = NULL;
        
        pGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
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
        UINT16 alignedLeft = OVS_SIZE_ALIGNED_4(pOutArg->length);

        if (*pBytesLeft < alignedLeft)
        {
            return FALSE;
        }

        if (pOutArg->length)
        {
            pOutArg->data = KAlloc(pOutArg->length);
            if (!pOutArg->data)
            {
                return FALSE;
            }

            RtlCopyMemory(pOutArg->data, *pBuffer, pOutArg->length);
        }

        *pBuffer += alignedLeft;
        *pBytesLeft -= alignedLeft;
    }

    return TRUE;
}

static BOOLEAN _CountAttributes(BYTE* buffer, ULONG totalLength, UINT16* pCount)
{
    OVS_NL_ATTRIBUTE* pAttr = NULL;
    UINT16 count = 0;
    ULONG len = 0;

    pAttr = (OVS_NL_ATTRIBUTE*)buffer;
    ++count;
    len += OVS_SIZE_ALIGNED_4(pAttr->length);

    while (len < totalLength)
    {
        pAttr = (OVS_NL_ATTRIBUTE*)((BYTE*)pAttr + OVS_SIZE_ALIGNED_4(pAttr->length));

        ++count;
        len += OVS_SIZE_ALIGNED_4(pAttr->length);

        if (pAttr->length <= 0)
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
BOOLEAN _ParseArgGroup_FromAttributes(_In_ BYTE** ppBuffer, UINT16* pBytesLeft, UINT16 groupSize, _Inout_ OVS_ARGUMENT_GROUP* pGroup, OVS_ARGTYPE parentArgType, UINT16 targetType, UINT8 cmd)
{
    OVS_CHECK(pGroup);

    if (groupSize == 0)
    {
        //the main group must have count args > 0
        switch (parentArgType)
        {
        case OVS_ARGTYPE_PSEUDOGROUP_DATAPATH:
        case OVS_ARGTYPE_PSEUDOGROUP_FLOW:
        case OVS_ARGTYPE_PSEUDOGROUP_OFPORT:
        case OVS_ARGTYPE_PSEUDOGROUP_PACKET:
            return FALSE;
        default:
            //nothing special for default
            break;
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
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

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
        *((OVS_MESSAGE_MULTICAST*)pNlMessage) = *((OVS_MESSAGE_MULTICAST*)pBufferedMsg);
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

    pMessage->pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pMessage->pArgGroup)
    {
        goto Cleanup;
    }

    RtlZeroMemory(pMessage->pArgGroup, sizeof(OVS_ARGUMENT_GROUP));

    DEBUGP_ARG(LOG_INFO, "arg hdr size: 0x%x; group hdr size: 0x%x\n", OVS_ARGUMENT_HEADER_SIZE, OVS_ARGUMENT_GROUP_HEADER_SIZE);

    mainArgType = MessageTargetTypeToArgType(pMessage->type);

    if (!_ParseArgGroup_FromAttributes((BYTE**)&buffer, &bytesLeft, bytesLeft, /*out*/pMessage->pArgGroup, mainArgType, pMessage->type, pMessage->command))
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

        while (dataLen > 0)
        {
            OVS_ARGUMENT* pChildAttr = pAttrArray + i;
            ULONG alignedSize = OVS_SIZE_ALIGNED_4(pChildAttr->length);

            _DestroyAttribute(pChildAttr);

            ++i;
            OVS_CHECK(dataLen >= alignedSize);
            dataLen -= alignedSize;
        }

        OVS_CHECK((pAttrArray && pAttribute->length > sizeof(OVS_NL_ATTRIBUTE)) || 
            (!pAttrArray && pAttribute->length == sizeof(OVS_NL_ATTRIBUTE)));

        KFree(pAttrArray);
    }
}

static VOID _DestroyAttributes(OVS_ATTRIBUTE* pAttributes, UINT count)
{
    for (UINT i = 0; i < count; ++i)
    {
        OVS_ATTRIBUTE* pAttr = pAttributes + i;

        _DestroyAttribute(pAttr);
    }

    KFree(pAttributes);
}

static OVS_ARGUMENT* _ArgumentsToAttributes(ULONG target, ULONG cmd, OVS_ARGTYPE parentArgType, _In_ const OVS_ARGUMENT* pArgs, UINT16 count, UINT16* pGroupSize)
{
    OVS_ARGUMENT* pAttributes = NULL;
    BOOLEAN ok = TRUE;
    UINT16 groupSize = 0;

    OVS_CHECK(count != 0);

    pAttributes = KZAlloc(count * sizeof(OVS_ARGUMENT));

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

            groupSize += OVS_SIZE_ALIGNED_4(pAttr->length);

            if (!Reply_SetAttrType(parentArgType, pAttr))
            {
                KFree(pSubAttrs);

                ok = FALSE;
                break;
            }
        }
        else
        {
            //NOTE: arg data is not copied, the data pointer is copied!
            RtlCopyMemory(pAttr, pArg, sizeof(OVS_ARGUMENT));
            pAttr->length = pArg->length + OVS_ARGUMENT_HEADER_SIZE;
            pAttr->isNested = FALSE;
            pAttr->freeData = TRUE;

            groupSize += OVS_SIZE_ALIGNED_4(pAttr->length);

            if (!Reply_SetAttrType(parentArgType, pAttr))
            {
                ok = FALSE;
                break;
            }
        }
    }

    if (!ok)
    {
        KFree(pAttributes);
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

    if (!AttrType_To_ArgType(pAttr->type, parentArgType, &typeAsArg))
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
        UINT16 alignedLen = 0;

        while (dataLen > 0)
        {
            OVS_ARGUMENT* pChildAttr = pAttrArray + i;

            alignedLen = OVS_SIZE_ALIGNED_4(pChildAttr->length);

            _WriteArgToBuffer_AsAttribute(targetType, pBuffer, typeAsArg, pChildAttr, pOffset);

            ++i;
            OVS_CHECK(dataLen >= alignedLen);
            dataLen -= alignedLen;
        }
    }
    else
    {
        UINT16 dataLen = pAttr->length - OVS_ARGUMENT_HEADER_SIZE;
        UINT16 alignedLen = OVS_SIZE_ALIGNED_4(dataLen);
        
        RtlZeroMemory(*pBuffer, alignedLen);
        RtlCopyMemory(*pBuffer, pAttr->data, dataLen);

        *pBuffer += alignedLen;
        *pOffset += alignedLen;
    }
}

static ULONG _ComputeGroupAlignedSize_Recursive(OVS_ARGUMENT_GROUP* pGroup)
{
    ULONG alignedSize = 0;

    OVS_FOR_EACH_ARG(pGroup, pArg, argType,
    {
        alignedSize += sizeof(OVS_NL_ATTRIBUTE);

        if (IsArgTypeGroup(argType))
        {
            alignedSize += _ComputeGroupAlignedSize_Recursive(pArg->data);
        }
        else
        {
            alignedSize += OVS_SIZE_ALIGNED_4(pArg->length);
        }
    });

    return alignedSize;
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
            groupSize = _ComputeGroupAlignedSize_Recursive(pMsg->pArgGroup);
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
            OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

            mainArgType = MessageTargetTypeToArgType(pMsg->type);
            pAttributes = _ArgumentsToAttributes(pMsg->type, pMsg->command, mainArgType, pGroup->args, pGroup->count, &groupSize);

            if (!pAttributes)
            {
                FreeBufferData(pBuffer);
                return FALSE;
            }

            for (UINT i = 0; i < pGroup->count; ++i)
            {
                _WriteArgToBuffer_AsAttribute(pMsg->type, &pos, mainArgType, pAttributes + i, &offset);
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

VOID DestroyMessages(_Inout_ OVS_MESSAGE* msgs, UINT countMsgs)
{
    if (msgs)
    {
        for (UINT i = 0; i < countMsgs; ++i)
        {
            OVS_MESSAGE* pReplyMsg = msgs + i;

            DestroyArgumentGroup(pReplyMsg->pArgGroup);
        }

        KFree(msgs);
    }
}

OVS_ERROR CreateMsg(OVS_MESSAGE* pMsg, UINT32 portId, UINT32 sequence, UINT32 length, OVS_MESSAGE_TARGET_TYPE target, UINT8 command,
    UINT32 dpIfIndex, UINT16 countArgs)
{
    pMsg->length = length;
    pMsg->type = target;
    pMsg->flags = 0;
    pMsg->pid = portId;
    pMsg->pArgGroup = NULL;
    pMsg->sequence = sequence;

    pMsg->command = command;
    pMsg->version = 1;
    pMsg->reserved = 0;

    //NOTE: make sure pDatapath->switchIfIndex == pSwitchInfo->datapathIfIndex
    pMsg->dpIfIndex = dpIfIndex;

    if (countArgs)
    {
        pMsg->pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
        if (!pMsg->pArgGroup)
        {
            return OVS_ERROR_NOMEM;
        }

        if (!AllocateArgumentsToGroup(countArgs, pMsg->pArgGroup))
        {
            KFree(pMsg->pArgGroup);
            return OVS_ERROR_NOMEM;
        }
    }

    return OVS_ERROR_NOERROR;
}

OVS_ERROR CreateReplyMsg(const OVS_MESSAGE* pInMsg, OVS_MESSAGE* pOutMsg, UINT32 length,
    UINT8 command, UINT16 countArgs)
{
    return CreateMsg(pOutMsg, pInMsg->pid, pInMsg->sequence, length, pInMsg->type, command, pInMsg->dpIfIndex, countArgs);
}

OVS_ERROR CreateReplyMsgDone(const OVS_MESSAGE* pInMsg, OVS_MESSAGE* pOutMsg, UINT32 length,
    UINT8 command)
{
    OVS_ERROR error = OVS_ERROR_NOERROR;
    
    error = CreateReplyMsg(pInMsg, pOutMsg, length, command, 0);
    if (error == OVS_ERROR_NOERROR)
    {
        pOutMsg->type = OVS_MESSAGE_TARGET_DUMP_DONE;
    }

    return error;
}