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

//used in ASSERT-s
#define __NEVER_TRIED_THIS__      0
#define __NOT_IMPLEMENTED__       0
#define __UNEXPECTED__            0

#define KAlloc(size) ExAllocatePoolWithTag(NonPagedPool, size, g_extAllocationTag)
#define KFree(p) ExFreePoolWithTag(p, g_extAllocationTag)

#define OVS_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

typedef struct _OVS_FLOW                     OVS_FLOW;
typedef struct _OVS_OFPACKET_INFO            OVS_OFPACKET_INFO;
typedef struct _OF_PI_IPV4_TUNNEL            OF_PI_IPV4_TUNNEL;
typedef struct _OVS_OFPORT                   OVS_OFPORT;
typedef struct _OVS_DATAPATH                 OVS_DATAPATH;

/*************************************/

//memory pool tag
extern ULONG  g_extAllocationTag;

/*************************************/

NDIS_STATUS OvsInit(NDIS_HANDLE ndisHandle);
VOID OvsUninit();

VOID Rwlock_LockRead(_In_ PNDIS_RW_LOCK_EX pRwLock, _In_ LOCK_STATE_EX* pLockState);
VOID Rwlock_LockWrite(_In_ PNDIS_RW_LOCK_EX pRwLock, _In_ LOCK_STATE_EX* pLockState);
VOID Rwlock_Unlock(_In_ PNDIS_RW_LOCK_EX pRwLock, _In_ LOCK_STATE_EX* pLockState);

__inline void WcharArrayToAscii(CHAR* dest, const WCHAR* src, UINT count)
{
    UINT i = 0;
    for (i = 0; i < count; ++i)
    {
        dest[i] = (CHAR)src[i];
    }
}

static __inline char* IfCountedStringToCharArray(_In_ const IF_COUNTED_STRING* pCountedStr)
{
    char* result = NULL;
    ULONG len = pCountedStr->Length / 2;

    OVS_CHECK(pCountedStr);
    OVS_CHECK(len <= IF_MAX_STRING_SIZE + 1);

    result = KAlloc(len + 1);

    if (!result)
    {
        return NULL;
    }

    WcharArrayToAscii(result, pCountedStr->String, len);
    result[len] = 0;

    return result;
}

static __inline WCHAR* IfCountedStringToWCharArray(_In_ const IF_COUNTED_STRING* pCountedStr)
{
    WCHAR* result = NULL;
    ULONG len = pCountedStr->Length / 2;

    OVS_CHECK(pCountedStr);
    OVS_CHECK(len <= IF_MAX_STRING_SIZE + 1);

    result = KAlloc(len + 1);

    if (!result)
    {
        return NULL;
    }

    wcscpy_s(result, len, pCountedStr->String);
    result[len] = 0;

    return result;
}

static __inline VOID* KZAlloc(SIZE_T size)
{
    VOID* p = ExAllocatePoolWithTag(NonPagedPool, size, g_extAllocationTag);
    if (!p)
    {
        return NULL;
    }

    RtlZeroMemory(p, size);
    return p;
}