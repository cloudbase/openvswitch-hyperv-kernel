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

#define OVS_MAX_ARRAY_SIZE      MAXUINT16

typedef struct _OVS_FXARRAY_ITEM OVS_FXARRAY_ITEM;

typedef BOOLEAN (*FXArrayCondition)(OVS_FXARRAY_ITEM* pItem, UINT_PTR data);

//specific item entries inherit OVS_FXARRAY_ITEM
typedef struct _OVS_FXARRAY_ITEM
{
    //must be the first field in the struct
    OVS_REF_COUNT refCount;

    NDIS_RW_LOCK_EX* pRwLock;
}OVS_FXARRAY_ITEM, *POVS_FXARRAY_ITEM;

#define FXITEM_LOCK_READ(pItem, pLockState) NdisAcquireRWLockRead((pItem)->pRwLock, pLockState, 0)
#define FXITEM_LOCK_WRITE(pItem, pLockState) NdisAcquireRWLockWrite((pItem)->pRwLock, pLockState, 0)
#define FXITEM_UNLOCK(pItem, pLockState) NdisReleaseRWLock((pItem)->pRwLock, pLockState)

typedef struct _OVS_FIXED_SIZED_ARRAY
{
    NDIS_RW_LOCK_EX* pRwLock;

    OVS_FXARRAY_ITEM* array[OVS_MAX_ARRAY_SIZE];
    UINT16 count;
    UINT16 firstFree;
}OVS_FIXED_SIZED_ARRAY;

#define FXARRAY_LOCK_READ(pArray, pLockState) NdisAcquireRWLockRead((pArray)->pRwLock, pLockState, 0)
#define FXARRAY_LOCK_WRITE(pArray, pLockState) NdisAcquireRWLockWrite((pArray)->pRwLock, pLockState, 0)
#define FXARRAY_UNLOCK(pArray, pLockState) NdisReleaseRWLock((pArray)->pRwLock, pLockState)
#define FXARRAY_UNLOCK_IF(pArray, pLockState, locked) { if ((locked) && (pArray)) FXARRAY_UNLOCK((pArray), pLockState); }

#define OVS_FXARRAY_FOR_EACH(pArray, pCurItem, condition, code) \
{                                                               \
    ULONG countProcessed = 0;                                   \
                                                                \
    for (ULONG i = 0; i < OVS_MAX_ARRAY_SIZE; ++i)              \
    {                                                           \
        OVS_FXARRAY_ITEM* pCurItem = (pArray)->array[i];        \
                                                                \
        if (pCurItem)                                           \
        {                                                       \
            LOCK_STATE_EX lockState = { 0 };                    \
                                                                \
            FXITEM_LOCK_READ(pCurItem, &lockState);             \
                                                                \
            if ((condition))                                    \
            {                                                   \
                code;                                           \
                                                                \
                FXITEM_UNLOCK(pCurItem, &lockState);            \
                break;                                          \
            }                                                   \
                                                                \
            FXITEM_UNLOCK(pCurItem, &lockState);                \
                                                                \
            ++countProcessed;                                   \
        }                                                       \
                                                                \
        if (countProcessed >= (pArray)->count)                  \
        {                                                       \
            break;                                              \
        }                                                       \
    }                                                           \
                                                                \
    OVS_CHECK(countProcessed == (pArray)->count);               \
}

/**********************************************************************************/

//unsafe = you must lock with FXARRAY lock
BOOLEAN FXArray_FindNextFree_Unsafe(_In_ const OVS_FIXED_SIZED_ARRAY* pPorts, _Inout_ UINT16* pFirst);

//unsafe = you must lock with FXARRAY lock
OVS_ERROR FXArray_AddByNumber_Unsafe(_Inout_ OVS_FIXED_SIZED_ARRAY* pArray, _In_ const OVS_FXARRAY_ITEM* pItem, UINT16 number);

//unsafe = you must lock with FXARRAY lock
BOOLEAN FXArray_Add_Unsafe(_Inout_ OVS_FIXED_SIZED_ARRAY* pArray, const OVS_FXARRAY_ITEM* pItem, _Out_ UINT16* pNumber);

_Ret_maybenull_
OVS_FXARRAY_ITEM* FXArray_Find_Unsafe(_In_ const OVS_FIXED_SIZED_ARRAY* pArray, FXArrayCondition condition, _In_ const VOID* pCondData);

_Ret_maybenull_
OVS_FXARRAY_ITEM* FXArray_Find_Ref(_In_ const OVS_FIXED_SIZED_ARRAY* pArray, FXArrayCondition condition, _In_ const VOID* pCondData);

_Ret_maybenull_
BOOLEAN FXArray_Remove_Unsafe(_Inout_ OVS_FIXED_SIZED_ARRAY* pArray, _In_ OVS_FXARRAY_ITEM* pItem, UINT16 number);