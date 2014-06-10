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

#pragma once

#include "precomp.h"
#include "Error.h"

typedef struct _OVS_BUFFER OVS_BUFFER;
typedef struct _OVS_MESSAGE_MULTICAST OVS_MESSAGE_MULTICAST;

extern NDIS_RW_LOCK_EX* g_pOvsDeviceRWLock;

BOOLEAN BufferCtl_WriteUnicast(_In_ const FILE_OBJECT* pFileObject, UINT portId);
BOOLEAN BufferCtl_WriteMulticast(_In_ const FILE_OBJECT* pFileObject, UINT portId);

OVS_ERROR BufferCtl_Read_Unsafe(_In_ const FILE_OBJECT* pFileObject, _Inout_ VOID* pOutBuf, ULONG toRead, _Inout_opt_ ULONG* pBytesRead);
OVS_ERROR BufferCtl_Write_Unsafe(_In_ const FILE_OBJECT* pFileObject, _In_ const OVS_BUFFER* pBuffer, UINT portId, UINT groupId);

OVS_BUFFER* BufferCtl_FindBuffer_Unsafe(_In_ const FILE_OBJECT* pFileObject);

BOOLEAN BufferCtl_AddDeviceFile_Unsafe(_In_ const FILE_OBJECT* pFileObject);
BOOLEAN BufferCtl_RemoveDeviceFile_Unsafe(_In_ const FILE_OBJECT* pFileObject);

VOID BufferCtl_Init(NDIS_HANDLE ndishandle);
VOID BufferCtl_Uninit();

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_shared_lock_(g_pOvsDeviceRWLock)
VOID BufferCtl_LockRead(_IRQL_saves_ LOCK_STATE_EX* pLockState);

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_exclusive_lock_(g_pOvsDeviceRWLock)
VOID BufferCtl_LockWrite(_IRQL_saves_ LOCK_STATE_EX* pLockState);

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(g_pOvsDeviceRWLock)
VOID BufferCtl_Unlock(_IRQL_restores_ LOCK_STATE_EX* pLockState);

VOID McGroup_Change(_In_ OVS_MESSAGE_MULTICAST* pMulticastMsg, _In_ const FILE_OBJECT* pFileObject);
BOOLEAN BufferCtl_SetPidForFile(UINT32 pid, _In_ const FILE_OBJECT* pFileObject);

#if DBG
VOID DbgPrintFile(const char* msg, VOID* pEntry);
VOID DbgPrintDeviceFiles();
VOID DbgPrintUCastBuffers();
VOID DbgPrintMCastBuffers();
VOID DbgPrintQueuedBuffers();
#endif