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

typedef struct _OVS_BUFFER
{
    VOID*    p;
    UINT     size;
    UINT     offset;
} OVS_BUFFER;

static __inline VOID InitializeBuffer(_Inout_  OVS_BUFFER* pBuf)
{
    OVS_CHECK(pBuf);

    RtlZeroMemory(pBuf, sizeof(OVS_BUFFER));
}

static __inline BOOLEAN AllocateBuffer(_Inout_ OVS_BUFFER* pBuf, UINT size)
{
    OVS_CHECK(pBuf);
    OVS_CHECK(!pBuf->p);
    OVS_CHECK(!pBuf->offset);

    pBuf->p = KAlloc(size);
    if (!pBuf->p)
    {
        return FALSE;
    }

    pBuf->size = size;

    return TRUE;
}

static __inline BOOLEAN IsBufferEmpty(_In_ const OVS_BUFFER* pBuffer)
{
    OVS_CHECK(pBuffer);

    return !pBuffer->p || !pBuffer->size || pBuffer->size == pBuffer->offset;
}

static __inline VOID FreeBufferData(_Inout_ OVS_BUFFER* pBuf)
{
    if (!IsBufferEmpty(pBuf))
    {
        KFree(pBuf->p);

        RtlZeroMemory(pBuf, sizeof(OVS_BUFFER));
    }
}