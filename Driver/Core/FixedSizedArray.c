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

#include "FixedSizedArray.h"

_Use_decl_annotations_
BOOLEAN FXArray_FindNextFree_Unsafe(_In_ const OVS_FIXED_SIZED_ARRAY* pArray, _Inout_ UINT16* pFirst)
{
    UINT16 first = 0;

    OVS_CHECK(pFirst);

    first = *pFirst;

    //we have set the 'firstFree' to a port => we must find the next free port to set firstFree = null_port
    //we start searching a free slot in [first, end]
    while (first < OVS_MAX_ARRAY_SIZE && pArray->array[first])
    {
        first++;
    }

    //if we found a free slot => this is the free port we return
    if (first < OVS_MAX_ARRAY_SIZE)
    {
        if (!pArray->array[first])
        {
            *pFirst = first;
            return TRUE;
        }
    }

    //else, search [0, first)
    for (first = 0; first < pArray->firstFree; ++first)
    {
        if (!pArray->array[first])
        {
            *pFirst = first;
            return TRUE;
        }
    }

    return FALSE;
}

_Use_decl_annotations_
OVS_ERROR FXArray_AddByNumber_Unsafe(_Inout_ OVS_FIXED_SIZED_ARRAY* pArray, const OVS_FXARRAY_ITEM* pItem, UINT16 number)
{
    UINT16 first = pArray->firstFree;
    OVS_ERROR error = OVS_ERROR_NOERROR;

    if (NULL != pArray->array[number])
    {
        return OVS_ERROR_EXIST;
    }

    pArray->array[number] = OVS_CONST_CAST(pItem);
    pArray->count++;

    if (first == 0)
    {
        OVS_CHECK(number <= MAXUINT16);

        first = (UINT16)number;
    }

    if (first != number)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    if (first == number)
    {
        //we have set the 'firstFree' to a port => we must find the next free port to set firstFree = null_port
        if (!FXArray_FindNextFree_Unsafe(pArray, &first))
        {
            OVS_CHECK(pArray->count == MAXUINT16);

            DEBUGP(LOG_ERROR, "all available ports are used!\n");
            error = OVS_ERROR_NOSPC;
            goto Cleanup;
        }

        pArray->firstFree = first;
    }

Cleanup:
    if (error)
    {
        //found no room for new port
        pArray->array[number] = NULL;
        pArray->count--;
    }

    return error;
}

_Use_decl_annotations_
BOOLEAN FXArray_Add_Unsafe(_Inout_ OVS_FIXED_SIZED_ARRAY* pArray, const OVS_FXARRAY_ITEM* pItem, UINT16* pNumber)
{
    UINT16 first = pArray->firstFree;
    UINT16 number = 0;
    BOOLEAN ok = TRUE;

    OVS_CHECK(NULL == pArray->array[first]);
    number = first;

    pArray->array[number] = OVS_CONST_CAST(pItem);
    pArray->count++;

    if (!FXArray_FindNextFree_Unsafe(pArray, &first))
    {
        OVS_CHECK(pArray->count == MAXUINT16);

        DEBUGP(LOG_ERROR, "all available ports are used!\n");
        ok = FALSE;
        goto Cleanup;
    }

    pArray->firstFree = first;

Cleanup:
    if (ok)
    {
        *pNumber = number;
    }
    else
    {
        //found no room for new port
        pArray->array[number] = NULL;
        pArray->count--;
    }

    return ok;
}

_Use_decl_annotations_
OVS_FXARRAY_ITEM* FXArray_Find_Unsafe(const OVS_FIXED_SIZED_ARRAY* pArray, FXArrayCondition condition, const VOID* pCondData)
{
    OVS_FXARRAY_ITEM* pOutItem = NULL;

    OVS_FXARRAY_FOR_EACH(pArray, pCurItem, /*if*/ condition(pCurItem, (UINT_PTR)pCondData),
        pOutItem = OVS_REFCOUNT_REFERENCE(pCurItem)
        );

    return pOutItem;
}

_Use_decl_annotations_
OVS_FXARRAY_ITEM* FXArray_Find_Ref(const OVS_FIXED_SIZED_ARRAY* pArray, FXArrayCondition condition, const VOID* pCondData)
{
    OVS_FXARRAY_ITEM* pOutItem = NULL;
    LOCK_STATE_EX lockState;

    FXARRAY_LOCK_READ(pArray, &lockState);

    pOutItem = FXArray_Find_Unsafe(pArray, condition, pCondData);

    FXARRAY_UNLOCK(pArray, &lockState);

    return pOutItem;
}

BOOLEAN FXArray_Remove_Unsafe(OVS_FIXED_SIZED_ARRAY* pArray, OVS_FXARRAY_ITEM* pItem, UINT16 number)
{
    if (pArray->array[number] != pItem)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ "item not found: %u\n", number);
        return FALSE;
    }

    OVS_CHECK(number <= 0xFFFF);
    pArray->array[number] = NULL;

    pArray->firstFree = number;

    OVS_CHECK(pArray->count > 0);
    --(pArray->count);

    return TRUE;
}