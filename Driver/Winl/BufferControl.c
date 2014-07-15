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

#include "BufferControl.h"
#include "Buffer.h"
#include "List.h"
#include "Message.h"
#include "OvsCore.h"
#include "Winetlink.h"

#define OVS_MAX_QUEUED_BUFFERS        50

/*****************************************/

typedef struct _OVS_BUFFER_ENTRY
{
    LIST_ENTRY listEntry;
    OVS_BUFFER buffer;
}OVS_BUFFER_ENTRY;

typedef struct _OVS_UNICAST_BUFFER_ENTRY
{
    LIST_ENTRY listEntry;
    UINT portId;
    OVS_BUFFER buffer;
    const FILE_OBJECT* pFileObject;
}OVS_UNICAST_BUFFER_ENTRY, *POVS_UNICAST_BUFFER_ENTRY;

typedef struct _OVS_MULTICAST_BUFFER_ENTRY
{
    LIST_ENTRY listEntry;
    UINT32 groupId;
    //TODO: we need a queue of buffers for multicast / notifications
    OVS_BUFFER buffer;
    //multiple file objects may reference the same multicast buffer entry
    UINT refCount;
    const FILE_OBJECT* pFileObject;
    //NOTE: each multicast group has port Ids -- should we consider them when working with groupId-s?
} OVS_MULTICAST_BUFFER_ENTRY;

typedef struct _OVS_QUEUED_BUFFER_ENTRY
{
    LIST_ENTRY    listEntry;
    UINT          portId;

    LIST_ENTRY    bufferQueue;
    UINT          count;
}OVS_QUEUED_BUFFER_ENTRY;

typedef struct _OVS_DEVICE_FILE_INFO
{
    const FILE_OBJECT* pFileObject;
    //TRUE = a request (write) was set, so a unicast reply (read) is expected; else, a read will search a multicast (notify) buffer
    //for 'send packet to userspace', it should be FALSE.
    BOOLEAN            expectReply;
    UINT               portId;
    //if none, it should be set to OVS_MULTICAST_GROUP_NONE
    UINT               groupId;
}OVS_DEVICE_FILE_INFO;

typedef struct _OVS_DEVICE_FILE_INFO_ENTRY
{
    LIST_ENTRY listEntry;
    OVS_DEVICE_FILE_INFO info;
}OVS_DEVICE_FILE_INFO_ENTRY;

/****************************************/

NDIS_RW_LOCK_EX* g_pOvsDeviceRWLock = NULL;

static LIST_ENTRY g_deviceFileInfoList;

static LIST_ENTRY g_unicastBufferList;
static LIST_ENTRY g_multicastFileObjects;
static LIST_ENTRY g_queuedBufferList;

/****************************************/

#if DBG

VOID DbgPrintFile(const char* msg, OVS_DEVICE_FILE_INFO_ENTRY* pEntry)
{
    DEBUGP_FILE(LOG_INFO, "%s:\n", msg);
    DEBUGP_FILE(LOG_INFO, "file object: %p\n", pEntry->info.pFileObject);
    DEBUGP_FILE(LOG_INFO, "expected reply: %d\n", pEntry->info.expectReply);
    DEBUGP_FILE(LOG_INFO, "port id: %u\n", pEntry->info.portId);
    DEBUGP_FILE(LOG_INFO, "group id: %u\n", pEntry->info.groupId);
    DEBUGP_FILE(LOG_INFO, "\n");
}

VOID DbgPrintDeviceFiles()
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = NULL;
    int i = 0;

    LIST_FOR_EACH(OVS_DEVICE_FILE_INFO_ENTRY, pEntry, &g_deviceFileInfoList)
    {
        DEBUGP_FILE(LOG_INFO, "file %d:\n", i);
        DEBUGP_FILE(LOG_INFO, "file object: %p\n", pEntry->info.pFileObject);
        DEBUGP_FILE(LOG_INFO, "expected reply: %d\n", pEntry->info.expectReply);
        DEBUGP_FILE(LOG_INFO, "port id: %u\n", pEntry->info.portId);
        DEBUGP_FILE(LOG_INFO, "group id: %u\n", pEntry->info.groupId);
        DEBUGP_FILE(LOG_INFO, "\n");
        i++;
    }
}

VOID DbgPrintUCastBuffers()
{
    OVS_UNICAST_BUFFER_ENTRY* pEntry = NULL;
    int i = 0;

    LIST_FOR_EACH(OVS_UNICAST_BUFFER_ENTRY, pEntry, &g_unicastBufferList)
    {
        DEBUGP_FILE(LOG_INFO, "ucast buffer %d:\n", i);
        DEBUGP_FILE(LOG_INFO, "file object: %p\n", pEntry->pFileObject);
        DEBUGP_FILE(LOG_INFO, "port: %u\n", pEntry->portId);
        DEBUGP_FILE(LOG_INFO, "buffer ptr: %p\n", pEntry->buffer.p);
        DEBUGP_FILE(LOG_INFO, "buffer size: %u\n", pEntry->buffer.size);
        DEBUGP_FILE(LOG_INFO, "buffer offset: %u\n", pEntry->buffer.offset);
        DEBUGP_FILE(LOG_INFO, "\n");
        i++;
    }
}

VOID DbgPrintMCastBuffers()
{
    OVS_MULTICAST_BUFFER_ENTRY* pEntry = NULL;
    int i = 0;

    LIST_FOR_EACH(OVS_MULTICAST_BUFFER_ENTRY, pEntry, &g_multicastFileObjects)
    {
        DEBUGP_FILE(LOG_INFO, "mcast buffer %d:\n", i);
        DEBUGP_FILE(LOG_INFO, "file object: %p\n", pEntry->pFileObject);
        DEBUGP_FILE(LOG_INFO, "group id: %u\n", pEntry->groupId);
        DEBUGP_FILE(LOG_INFO, "ref count: %u\n", pEntry->refCount);
        DEBUGP_FILE(LOG_INFO, "buffer ptr: %p\n", pEntry->buffer.p);
        DEBUGP_FILE(LOG_INFO, "buffer size: %u\n", pEntry->buffer.size);
        DEBUGP_FILE(LOG_INFO, "buffer offset: %u\n", pEntry->buffer.offset);
        DEBUGP_FILE(LOG_INFO, "\n");
        i++;
    }
}

VOID DbgPrintQueuedBuffers()
{
    OVS_QUEUED_BUFFER_ENTRY* pEntry = NULL;
    int i = 0;

    LIST_FOR_EACH(OVS_QUEUED_BUFFER_ENTRY, pEntry, &g_queuedBufferList)
    {
        OVS_BUFFER_ENTRY* pBufferEntry = NULL;
        UINT j = 0;

        DEBUGP_FILE(LOG_INFO, "queued buffer %d:\n", i);
        DEBUGP_FILE(LOG_INFO, "port id: %u\n", pEntry->portId);
        DEBUGP_FILE(LOG_INFO, "count: %u\n", pEntry->count);

        LIST_FOR_EACH(OVS_BUFFER_ENTRY, pBufferEntry, &pEntry->bufferQueue)
        {
            DEBUGP_FILE(LOG_INFO, "buffer %u ptr: %p\n", j, pBufferEntry->buffer.p);
            DEBUGP_FILE(LOG_INFO, "buffer %u size: %u\n", j, pBufferEntry->buffer.size);
            DEBUGP_FILE(LOG_INFO, "buffer %u offset: %u\n", j, pBufferEntry->buffer.offset);
            DEBUGP_FILE(LOG_INFO, "\n");

            ++j;
        }

        i++;
    }
}

#else

#define DbgPrintFile(msg, entry)
#define DbgPrintDeviceFiles()
#define DbgPrintUCastBuffers()
#define DbgPrintMCastBuffers()
#define DbgPrintQueuedBuffers()

#endif

/****************************************/

_Ret_maybenull_
static OVS_DEVICE_FILE_INFO_ENTRY* _FindDeviceFileInfo_Unsafe(_In_ const FILE_OBJECT* pFileObject)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = NULL;

    LIST_FOR_EACH(OVS_DEVICE_FILE_INFO_ENTRY, pEntry, &g_deviceFileInfoList)
    {
        if (pEntry->info.pFileObject == pFileObject)
        {
            return pEntry;
        }
    }

    return NULL;
}

_Ret_maybenull_
static OVS_DEVICE_FILE_INFO_ENTRY* _FindDeviceFileInfoByPortId_Unsafe(UINT portId)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = NULL;

    OVS_CHECK(portId);

    LIST_FOR_EACH(OVS_DEVICE_FILE_INFO_ENTRY, pEntry, &g_deviceFileInfoList)
    {
        if (pEntry->info.portId == portId)
        {
            return pEntry;
        }
    }

    return NULL;
}

_Ret_maybenull_
OVS_UNICAST_BUFFER_ENTRY* _FindBufferUnicast_Unsafe(_In_ const OVS_DEVICE_FILE_INFO* pFileInfo)
{
    OVS_UNICAST_BUFFER_ENTRY* pEntry = NULL;

    LIST_FOR_EACH(OVS_UNICAST_BUFFER_ENTRY, pEntry, &g_unicastBufferList)
    {
        if (pEntry->pFileObject == pFileInfo->pFileObject)
        {
            OVS_CHECK(pEntry->portId == pFileInfo->portId);
            return pEntry;
        }
    }

    return NULL;
}

_Ret_maybenull_
OVS_MULTICAST_BUFFER_ENTRY* _FindBufferMulticast_Unsafe(_In_ const OVS_DEVICE_FILE_INFO* pFileInfo)
{
    OVS_MULTICAST_BUFFER_ENTRY* pEntry = NULL;

    LIST_FOR_EACH(OVS_MULTICAST_BUFFER_ENTRY, pEntry, &g_multicastFileObjects)
    {
        if (pEntry->pFileObject == pFileInfo->pFileObject)
        {
            OVS_CHECK(pEntry->groupId == pFileInfo->groupId);
            return pEntry;
        }
    }

    return NULL;
}

_Ret_maybenull_
OVS_QUEUED_BUFFER_ENTRY* _FindQueuedBuffer_Unsafe(_In_ const OVS_DEVICE_FILE_INFO* pFileInfo)
{
    OVS_QUEUED_BUFFER_ENTRY* pEntry = NULL;

    LIST_FOR_EACH(OVS_QUEUED_BUFFER_ENTRY, pEntry, &g_queuedBufferList)
    {
        if (pEntry->portId == pFileInfo->portId)
        {
            return pEntry;
        }
    }

    return NULL;
}

BOOLEAN _RemoveMulticastBuffer_Unsafe(OVS_DEVICE_FILE_INFO* pFileInfo)
{
    OVS_MULTICAST_BUFFER_ENTRY* pBufferEntry = _FindBufferMulticast_Unsafe(pFileInfo);

    if (!pBufferEntry)
    {
        //it's not an error if we don't have buffer for device file
        return TRUE;
    }

    if (pBufferEntry->refCount > 1)
    {
        --pBufferEntry->refCount;
    }
    else
    {
        if (IsBufferEmpty(&pBufferEntry->buffer))
        {
            FreeBufferData(&pBufferEntry->buffer);
        }

        RemoveEntryList(&pBufferEntry->listEntry);

        KFree(pBufferEntry);
    }

    return TRUE;
}

BOOLEAN _RemoveUnicastBuffer_Unsafe(OVS_DEVICE_FILE_INFO* pFileInfo)
{
    OVS_UNICAST_BUFFER_ENTRY* pBufferEntry = _FindBufferUnicast_Unsafe(pFileInfo);

    if (!pBufferEntry)
    {
        //it's not an error if we don't have buffer for device file
        return TRUE;
    }

    if (IsBufferEmpty(&pBufferEntry->buffer))
    {
        FreeBufferData(&pBufferEntry->buffer);
    }

    RemoveEntryList(&pBufferEntry->listEntry);

    KFree(pBufferEntry);

    return TRUE;
}

BOOLEAN _McGroup_Join_Unsafe(_In_ const FILE_OBJECT* pFileObject, UINT32 groupId)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pFileEntry = _FindDeviceFileInfo_Unsafe(pFileObject);

    if (!pFileEntry)
    {
        return FALSE;
    }

    //we currently do not allow one fd / HANDLE to belong to multiple multicast groups
    OVS_CHECK(pFileEntry->info.groupId == 0);

    pFileEntry->info.groupId = groupId;

    return TRUE;
}

BOOLEAN _McGroup_Leave_Unsafe(_In_ const FILE_OBJECT* pFileObject, UINT32 groupId)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pFileEntry = _FindDeviceFileInfo_Unsafe(pFileObject);

    if (!pFileEntry)
    {
        return FALSE;
    }

    if (pFileEntry->info.groupId != 0)
    {
        DEBUGP(LOG_WARN, __FUNCTION__  " we are asked to leave a group, but we never joined any!\n");
        return FALSE;
    }

    if (pFileEntry->info.groupId != groupId)
    {
        DEBUGP(LOG_WARN, __FUNCTION__  " we are asked to leave a group that we never joined!\n");
        return FALSE;
    }

    pFileEntry->info.groupId = 0;

    return TRUE;
}

OVS_ERROR _BufferCtl_ReadUnicast_Unsafe(_Inout_ OVS_BUFFER* pBuffer, _Inout_ VOID* pOutBuf, ULONG toRead, _Out_opt_ ULONG* pBytesRead)
{
    OVS_CHECK(pBuffer);
    OVS_CHECK(pOutBuf);

    OVS_CHECK(!pBuffer->size || pBuffer->size != pBuffer->offset);

    if (IsBufferEmpty(pBuffer))
    {
        if (pBuffer->size)
        {
            FreeBufferData(pBuffer);
        }

        if (pBytesRead)
        {
            *pBytesRead = 0;
        }

        return OVS_ERROR_AGAIN;
    }
    else
    {
        VOID* srcBuffer = (BYTE*)pBuffer->p + pBuffer->offset;
        ULONG bytesLeft = 0;
        ULONG bytesRead = 0;

        bytesLeft = pBuffer->size - pBuffer->offset;
        bytesRead = min(toRead, bytesLeft);

        //copy from our data to device io buffer
        __try
        {
            RtlCopyMemory(pOutBuf, srcBuffer, bytesRead);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
#ifdef DBG
            ULONG status = GetExceptionCode();
            DEBUGP(LOG_ERROR, "ucast read mem copy exception: 0x%x\n", status);
            OVS_CHECK(__UNEXPECTED__);
#endif

            return OVS_ERROR_IO;
        }

        if (bytesRead == bytesLeft)
        {
            FreeBufferData(pBuffer);
        }
        else
        {
            pBuffer->offset += bytesRead;
        }

        if (pBytesRead)
        {
            *pBytesRead = bytesRead;
        }
    }

    return OVS_ERROR_NOERROR;
}

OVS_ERROR _BufferCtl_ReadMulticast_Unsafe(_Inout_ OVS_BUFFER* pBuffer, _Inout_ VOID* pOutBuf, ULONG toRead, _Out_opt_ ULONG* pBytesRead)
{
    OVS_CHECK(pBuffer);
    OVS_CHECK(pOutBuf);

    OVS_CHECK(!pBuffer->size || pBuffer->size != pBuffer->offset);

    if (IsBufferEmpty(pBuffer))
    {
        if (pBuffer->size)
        {
            FreeBufferData(pBuffer);
        }

        if (pBytesRead)
        {
            *pBytesRead = 0;
        }

        return OVS_ERROR_AGAIN;
    }
    else
    {
        VOID* srcBuffer = (BYTE*)pBuffer->p;
        ULONG bytesLeft = 0;
        ULONG bytesRead = 0;

        bytesLeft = pBuffer->size;
        bytesRead = min(toRead, bytesLeft);

        //copy from our data to device io buffer
        __try
        {
            RtlCopyMemory(pOutBuf, srcBuffer, bytesRead);
        }

        __except (EXCEPTION_EXECUTE_HANDLER)
        {
#ifdef DBG
            ULONG status = GetExceptionCode();
            DEBUGP(LOG_ERROR, "mcast read mem copy exception: 0x%x\n", status);
            OVS_CHECK(__UNEXPECTED__);
#endif

            return OVS_ERROR_IO;
        }

        if (bytesRead == bytesLeft)
        {
            FreeBufferData(pBuffer);
        }
        else
        {
            //pBuffer->offset += bytesRead;
        }

        if (pBytesRead)
        {
            *pBytesRead = bytesRead;
        }
    }

    return OVS_ERROR_NOERROR;
}

static OVS_ERROR _PushBufferToQueue_Unsafe(_Inout_ OVS_QUEUED_BUFFER_ENTRY* pQBufferEntry, _In_ const OVS_BUFFER* pBuffer)
{
    OVS_CHECK(pQBufferEntry);

    if (pQBufferEntry->count < OVS_MAX_QUEUED_BUFFERS)
    {
        OVS_BUFFER_ENTRY* pBufferEntry = KAlloc(sizeof(OVS_BUFFER_ENTRY));
        if (!pBufferEntry)
        {
            return OVS_ERROR_NOMEM;
        }

        pBufferEntry->buffer = *pBuffer;

        InsertTailList(&pQBufferEntry->bufferQueue, &pBufferEntry->listEntry);
        pQBufferEntry->count++;
    }
    else
    {
        return OVS_ERROR_NOSPC;
    }

    return OVS_ERROR_NOERROR;
}

static OVS_ERROR _PopBufferFromQueue_Unsafe(_Inout_ OVS_QUEUED_BUFFER_ENTRY* pQBufferEntry, _Inout_ OVS_BUFFER* pBuffer)
{
    OVS_CHECK(pQBufferEntry);
    OVS_CHECK(pBuffer);

    if (pQBufferEntry->count > 0)
    {
        OVS_BUFFER_ENTRY* pBufferEntry = NULL;
        LIST_ENTRY* pListEntry = NULL;

        OVS_CHECK(!IsListEmpty(&pQBufferEntry->bufferQueue));

        pListEntry = RemoveHeadList(&pQBufferEntry->bufferQueue);
        OVS_CHECK(pListEntry);

        pBufferEntry = CONTAINING_RECORD(pListEntry, OVS_BUFFER_ENTRY, listEntry);
        *pBuffer = pBufferEntry->buffer;

        KFree(pBufferEntry);
        pQBufferEntry->count--;
    }
    else
    {
        return OVS_ERROR_AGAIN;
    }

    return OVS_ERROR_NOERROR;
}

/****************************************/

VOID BufferCtl_Init(NDIS_HANDLE ndishandle)
{
    g_pOvsDeviceRWLock = NdisAllocateRWLock(ndishandle);

    InitializeListHead(&g_deviceFileInfoList);
    InitializeListHead(&g_unicastBufferList);
    InitializeListHead(&g_multicastFileObjects);
    InitializeListHead(&g_queuedBufferList);
}

VOID BufferCtl_Uninit()
{
    LOCK_STATE_EX lockState = { 0 };
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = NULL;
    BOOLEAN okMcast = TRUE, okUcast = TRUE;

    Rwlock_LockWrite(g_pOvsDeviceRWLock, &lockState);

    LIST_FOR_EACH(OVS_DEVICE_FILE_INFO_ENTRY, pEntry, &g_deviceFileInfoList)
    {
        if (pEntry->info.groupId)
        {
            okMcast = _RemoveMulticastBuffer_Unsafe(&pEntry->info);
        }

        if (pEntry->info.portId)
        {
            okUcast = _RemoveUnicastBuffer_Unsafe(&pEntry->info);
        }
    }

    while (!IsListEmpty(&g_deviceFileInfoList))
    {
        LIST_ENTRY* pListEntry = RemoveHeadList(&g_deviceFileInfoList);
        pEntry = CONTAINING_RECORD(pListEntry, OVS_DEVICE_FILE_INFO_ENTRY, listEntry);
        KFree(pEntry);
    }

    OVS_CHECK(IsListEmpty(&g_unicastBufferList));
    OVS_CHECK(IsListEmpty(&g_multicastFileObjects));

    Rwlock_Unlock(g_pOvsDeviceRWLock, &lockState);

    NdisFreeRWLock(g_pOvsDeviceRWLock);
}

_Use_decl_annotations_
VOID BufferCtl_LockRead(LOCK_STATE_EX* pLockState)
{
    NdisAcquireRWLockRead(g_pOvsDeviceRWLock, pLockState, 0);
}

_Use_decl_annotations_
VOID BufferCtl_LockWrite(LOCK_STATE_EX* pLockState)
{
    NdisAcquireRWLockWrite(g_pOvsDeviceRWLock, pLockState, 0);
}

_Use_decl_annotations_
VOID BufferCtl_Unlock(LOCK_STATE_EX* pLockState)
{
    NdisReleaseRWLock(g_pOvsDeviceRWLock, pLockState);
}

/*******************************************************/

OVS_BUFFER* BufferCtl_FindBuffer_Unsafe(_In_ const FILE_OBJECT* pFileObject)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = _FindDeviceFileInfo_Unsafe(pFileObject);

    if (!pEntry)
    {
        return NULL;
    }

    if (pEntry->info.expectReply)
    {
        OVS_UNICAST_BUFFER_ENTRY* pBufferEntry = _FindBufferUnicast_Unsafe(&pEntry->info);

        if (!pBufferEntry)
        {
            return NULL;
        }

        return &pBufferEntry->buffer;
    }
    else
    {
        OVS_MULTICAST_BUFFER_ENTRY* pBufferEntry = _FindBufferMulticast_Unsafe(&pEntry->info);

        if (!pBufferEntry)
        {
            return NULL;
        }

        return &pBufferEntry->buffer;
    }
}

BOOLEAN BufferCtl_AddDeviceFile_Unsafe(_In_ const FILE_OBJECT* pFileObject)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = _FindDeviceFileInfo_Unsafe(pFileObject);

    if (pEntry)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " we were asked to add a device file, but we already have it in list!\n");
        OVS_CHECK(0);

        return FALSE;
    }

    pEntry = KAlloc(sizeof(OVS_DEVICE_FILE_INFO_ENTRY));

    if (!pEntry)
    {
        return FALSE;
    }

    RtlZeroMemory(pEntry, sizeof(OVS_DEVICE_FILE_INFO_ENTRY));
    pEntry->info.pFileObject = pFileObject;

    InsertTailList(&g_deviceFileInfoList, &pEntry->listEntry);

    DbgPrintFile("device added", pEntry);

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN BufferCtl_RemoveDeviceFile_Unsafe(const FILE_OBJECT* pFileObject)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pEntry = _FindDeviceFileInfo_Unsafe(pFileObject);
    BOOLEAN okMcast = TRUE, okUcast = TRUE;

    if (!pEntry)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " we were asked to remove a device file, but we don't have it in list!\n");
        OVS_CHECK(0);

        return FALSE;
    }

    if (pEntry->info.groupId)
    {
        okMcast = _RemoveMulticastBuffer_Unsafe(&pEntry->info);
    }

    if (pEntry->info.portId)
    {
        okUcast = _RemoveUnicastBuffer_Unsafe(&pEntry->info);
    }

    DbgPrintFile("device will be removed\n", pEntry);

    RemoveEntryList(&pEntry->listEntry);
    KFree(pEntry);

    return okUcast && okMcast;
}

_Use_decl_annotations_
OVS_ERROR BufferCtl_Read_Unsafe(const FILE_OBJECT* pFileObject, VOID* pOutBuf, ULONG toRead, ULONG* pBytesRead)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pFileEntry = _FindDeviceFileInfo_Unsafe(pFileObject);
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (!pFileEntry)
    {
        return OVS_ERROR_NOENT;
    }

    if (pFileEntry->info.expectReply)
    {
        OVS_UNICAST_BUFFER_ENTRY* pBufferEntry = NULL;
        pBufferEntry = _FindBufferUnicast_Unsafe(&pFileEntry->info);
        if (!pBufferEntry)
        {
            return OVS_ERROR_AGAIN;
        }

        error = _BufferCtl_ReadUnicast_Unsafe(&pBufferEntry->buffer, pOutBuf, toRead, pBytesRead);

        if (error == OVS_ERROR_NOERROR)
        {
            pFileEntry->info.expectReply = FALSE;
        }

        return error;
    }
    else
    {
        //attempt multicast read, only if we belong to a multicast group
        if (pFileEntry->info.groupId)
        {
            OVS_MULTICAST_BUFFER_ENTRY* pBufferEntry = NULL;
            pBufferEntry = _FindBufferMulticast_Unsafe(&pFileEntry->info);
            if (!pBufferEntry)
            {
                return OVS_ERROR_AGAIN;
            }

            return _BufferCtl_ReadMulticast_Unsafe(&pBufferEntry->buffer, pOutBuf, toRead, pBytesRead);
        }
        else
        {
            OVS_QUEUED_BUFFER_ENTRY* pQBufferEntry = NULL;
            OVS_BUFFER buffer = { 0 };

            pQBufferEntry = _FindQueuedBuffer_Unsafe(&pFileEntry->info);
            if (!pQBufferEntry)
            {
                return OVS_ERROR_AGAIN;
            }

            do
            {
                error = _PopBufferFromQueue_Unsafe(pQBufferEntry, &buffer);
                if (error != OVS_ERROR_NOERROR)
                {
                    return error;
                }
            } while (IsBufferEmpty(&buffer));

            //mcast read reads without concern for offset in buffer.
            return _BufferCtl_ReadMulticast_Unsafe(&buffer, pOutBuf, toRead, pBytesRead);
        }
    }
}

_Use_decl_annotations_
OVS_ERROR BufferCtl_Write_Unsafe(const FILE_OBJECT* pFileObject, const OVS_BUFFER* pBuffer, UINT portId, UINT groupId)
{
    OVS_DEVICE_FILE_INFO_ENTRY* pFileEntry = NULL;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (portId == 0 && groupId == 0)
    {
        return OVS_ERROR_CONNREFUSED;
    }

    //if we don't have a pFileObject, then it means the write is not the result of a request from userspace,
    //so we should use the port id to find the buffer. Also, we use queued buffers in this case.
    //this case == send packet to userspace.
    if (!pFileObject)
    {
        OVS_QUEUED_BUFFER_ENTRY* pQBufferEntry = NULL;

        pFileEntry = _FindDeviceFileInfoByPortId_Unsafe(portId);
        if (!pFileEntry)
        {
            return OVS_ERROR_NOENT;
        }

        pQBufferEntry = _FindQueuedBuffer_Unsafe(&pFileEntry->info);
        if (!pQBufferEntry)
        {
            pQBufferEntry = KAlloc(sizeof(OVS_QUEUED_BUFFER_ENTRY));
            RtlZeroMemory(pQBufferEntry, sizeof(OVS_QUEUED_BUFFER_ENTRY));

            InitializeListHead(&pQBufferEntry->bufferQueue);

            pQBufferEntry->portId = portId;
            error = _PushBufferToQueue_Unsafe(pQBufferEntry, pBuffer);
            if (error != OVS_ERROR_NOERROR)
            {
                KFree(pQBufferEntry);
                return error;
            }

            InsertTailList(&g_queuedBufferList, &pQBufferEntry->listEntry);
        }
        else
        {
            error = _PushBufferToQueue_Unsafe(pQBufferEntry, pBuffer);
            if (error != OVS_ERROR_NOERROR)
            {
                return error;
            }
        }

        return OVS_ERROR_NOERROR;
    }

    pFileEntry = _FindDeviceFileInfo_Unsafe(pFileObject);
    OVS_CHECK(pFileEntry);

    if (!pFileEntry)
    {
        return OVS_ERROR_INVAL;
    }

    //write unicast
    if (groupId == OVS_MULTICAST_GROUP_NONE || pFileEntry->info.groupId == OVS_MULTICAST_GROUP_NONE)
    {
        OVS_UNICAST_BUFFER_ENTRY* pBufferEntry = NULL;

        pFileEntry->info.expectReply = TRUE;
        pBufferEntry = _FindBufferUnicast_Unsafe(&pFileEntry->info);
        if (!pBufferEntry)
        {
            pBufferEntry = KAlloc(sizeof(OVS_UNICAST_BUFFER_ENTRY));

            if (!pBufferEntry)
            {
                return OVS_ERROR_INVAL;
            }

            RtlZeroMemory(pBufferEntry, sizeof(OVS_UNICAST_BUFFER_ENTRY));

            pBufferEntry->buffer = *pBuffer;
            pBufferEntry->pFileObject = pFileObject;
            pBufferEntry->portId = portId;

            InsertTailList(&g_unicastBufferList, &pBufferEntry->listEntry);
        }
        else
        {
            if (!IsBufferEmpty(&pBufferEntry->buffer))
            {
                FreeBufferData(&pBufferEntry->buffer);
            }

            pBufferEntry->buffer = *pBuffer;
        }

        return OVS_ERROR_NOERROR;
    }
    //write multicast
    else if (pFileEntry->info.groupId != OVS_MULTICAST_GROUP_NONE)
    {
        //NOTE: at the moment we use only one buffer for all multicast groups
        //NOTE: for write, all file handles should read this same new data
        OVS_MULTICAST_BUFFER_ENTRY* pBufferEntry = NULL;
        pBufferEntry = _FindBufferMulticast_Unsafe(&pFileEntry->info);
        if (!pBufferEntry)
        {
            pBufferEntry = KAlloc(sizeof(OVS_UNICAST_BUFFER_ENTRY));

            if (!pBufferEntry)
            {
                return OVS_ERROR_INVAL;
            }

            RtlZeroMemory(pBufferEntry, sizeof(OVS_UNICAST_BUFFER_ENTRY));

            pBufferEntry->buffer = *pBuffer;
            pBufferEntry->pFileObject = pFileObject;
            pBufferEntry->groupId = groupId;

            InsertTailList(&g_multicastFileObjects, &pBufferEntry->listEntry);
        }
        else
        {
            if (!IsBufferEmpty(&pBufferEntry->buffer))
            {
                FreeBufferData(&pBufferEntry->buffer);
            }

            pBufferEntry->buffer = *pBuffer;
        }

        return OVS_ERROR_NOERROR;
    }

    return OVS_ERROR_INVAL;
}

_Use_decl_annotations_
VOID McGroup_Change(OVS_MESSAGE_MULTICAST* pMulticastMsg, const FILE_OBJECT* pFileObject)
{
    LOCK_STATE_EX lockState = { 0 };

    BufferCtl_LockWrite(&lockState);

    if (pMulticastMsg->join)
    {
        _McGroup_Join_Unsafe(pFileObject, pMulticastMsg->groupId);
    }
    else
    {
        _McGroup_Leave_Unsafe(pFileObject, pMulticastMsg->groupId);
    }

    BufferCtl_Unlock(&lockState);
}

BOOLEAN BufferCtl_SetPidForFile(UINT32 pid, _In_ const FILE_OBJECT* pFileObject)
{
    LOCK_STATE_EX lockState = { 0 };
    OVS_DEVICE_FILE_INFO_ENTRY* pFileEntry = NULL;
    BOOLEAN ok = TRUE;

    BufferCtl_LockWrite(&lockState);

    pFileEntry = _FindDeviceFileInfo_Unsafe(pFileObject);
    if (!pFileEntry)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ " could not find file entry!\n");
        ok = FALSE;
        goto Cleanup;
    }

    OVS_CHECK(pFileEntry->info.portId == 0);
    pFileEntry->info.portId = pid;

Cleanup:
    BufferCtl_Unlock(&lockState);
    return ok;
}