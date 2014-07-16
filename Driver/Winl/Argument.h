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
#include "ArgumentType.h"

#define STRUCT_FIELD_SIZE(structType, fieldName) sizeof(((structType*)0)->fieldName)

typedef struct _OVS_ARGUMENT
{
    UINT16 length;
    UINT16 type;

    //isDisabled: internal use only (it is not sent, not received) -- used by msg to flow
    BOOLEAN isDisabled;
    //internal use only -- used when converting args to attrs
    BOOLEAN isNested;
    //if freeData => we should free the 'data' field of OVS_ARGUMENT.
    //otherwise, we must not
    BOOLEAN freeData;
    //informational purpose only: sizeof(OVS_ARGUMENT) == 16 => there is one byte of padding
    BYTE padding;
    VOID* data;
}OVS_ARGUMENT, *POVS_ARGUMENT;

#define OVS_ARGUMENT_HEADER_SIZE (FIELD_SIZE(OVS_ARGUMENT, type) + FIELD_SIZE(OVS_ARGUMENT, length))

C_ASSERT(OVS_ARGUMENT_HEADER_SIZE == 4);
C_ASSERT(sizeof(OVS_ARGUMENT) == 16);

typedef struct _OVS_ARGUMENT OVS_ATTRIBUTE;

typedef struct _OVS_ARGUMENT_GROUP
{
    //the number of args in the group
    UINT16 count;
    //the total size of the group: sizeof each OVS_ARGUMENT + length of allocated "data" of each arg
    UINT16 groupSize;
    //informational purpose only: (OVS_ARGUMENT_GROUP) == 16 => there are 4 bytes of padding
    UINT32 padding;
    OVS_ARGUMENT* args;
}OVS_ARGUMENT_GROUP, *POVS_ARGUMENTS;

#define OVS_ARGUMENT_GROUP_HEADER_SIZE (FIELD_SIZE(OVS_ARGUMENT_GROUP, count) + FIELD_SIZE(OVS_ARGUMENT_GROUP, groupSize))

C_ASSERT(OVS_ARGUMENT_GROUP_HEADER_SIZE == 4);
C_ASSERT(sizeof(OVS_ARGUMENT_GROUP) == 16);

typedef struct _OVS_ARGUMENT_SLIST_ENTRY
{
    OVS_ARGUMENT* pArg;
    struct _OVS_ARGUMENT_SLIST_ENTRY* pNext;
} OVS_ARGUMENT_SLIST_ENTRY;

#define COMPARE_ARGUMENT_SIMPLE(arg, value, typeOfValue) \
    (*(typeOfValue*)arg->data == value ? TRUE : FALSE)

#define GET_ARG_DATA(arg, typeOfDest) \
(*(typeOfDest*)arg->data)

#define GET_ARG_DATA_PTR(arg, ptrType) \
    ((ptrType*)arg->data)

/******************************************* ALLOC & FREE FUNCTIONS **********************************************************************/

#define AllocArgumentData(size) ExAllocatePoolWithTag(NonPagedPool, size, g_extAllocationTag)

//frees the pArg->data of an OVS_ARGUMENT
static __inline VOID FreeArgumentData(VOID* pData)
{
    if (pData)
    {
        ExFreePoolWithTag(pData, g_extAllocationTag);
    }
}

//allocates an OVS_ARGUMENT and initializes it
static __inline OVS_ARGUMENT* AllocArgument()
{
    OVS_ARGUMENT* pArg = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_ARGUMENT), g_extAllocationTag);
    if (!pArg)
    {
        return NULL;
    }

    pArg->data = NULL;
    pArg->length = 0;
    pArg->type = OVS_ARGTYPE_INVALID;

    return pArg;
}

static __inline VOID FreeArgument(OVS_ARGUMENT* pArg)
{
    if (pArg)
    {
        ExFreePoolWithTag(pArg, g_extAllocationTag);
    }
}

//allocates an array of count OVS_ARGUMENT-s, and assigns it to pGroup->args
BOOLEAN AllocateArgumentsToGroup(UINT16 count, _Out_ OVS_ARGUMENT_GROUP* pGroup);

//frees the array of OVS_ARGUMENT-s of an OVS_ARGUMENT_GROUP struct
static __inline VOID FreeArguments(_Inout_ OVS_ARGUMENT_GROUP* pGroup)
{
    OVS_CHECK(pGroup);

    if (pGroup->args)
    {
        ExFreePoolWithTag(pGroup->args, g_extAllocationTag);
    }

    pGroup->args = NULL;
    pGroup->count = 0;
}

#define AllocArgumentGroup() ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_ARGUMENT_GROUP), g_extAllocationTag)

//frees an OVS_ARGUMENT_GROUP: it does not free pGroup->args
static __inline VOID FreeArgGroup(_Inout_ OVS_ARGUMENT_GROUP* pGroup)
{
    if (pGroup)
    {
        ExFreePoolWithTag(pGroup, g_extAllocationTag);
    }
}

/******************************************* CREATION & DESTRUCTION FUNCTIONS **********************************************************************/

//allocates an OVS_ARGUMENT and sets buffer (NOTE: not a copy of it) as pArg->data;
//computes the size and that size is stored as pArg->length
//if computed size = ~0 (i.e. unknown size) => function fails
OVS_ARGUMENT* CreateArgument(OVS_ARGTYPE argType, const VOID* buffer);

//allocates an OVS_ARGUMENT and sets buffer (NOTE: not a copy of it) as pArg->data;
//sets the arg size as "size".
//NOTE: the argType must represent a variable-sized arg.
OVS_ARGUMENT* CreateArgumentWithSize(OVS_ARGTYPE argType, const VOID* buffer, ULONG size);

//allocates an OVS_ARGUMENT and sets a copy of buffer as pArg->data
//computes the size and that size is stored as pArg->length
//if computed size = ~0 (i.e. unknown size) => function fails
OVS_ARGUMENT* CreateArgument_Alloc(OVS_ARGTYPE argType, const VOID* buffer);

//allocates an OVS_ARGUMENT and encapsulates the OVS_ARGUMENT_GROUP as its pArg->data (NOTE: not a copy of it)
OVS_ARGUMENT* CreateArgumentFromGroup(OVS_ARGTYPE argType, const OVS_ARGUMENT_GROUP* pData);

//allocates an OVS_ARGUMENT and stores the ASCII string "buffer" as its data (NOTE: it does not use a copy of buffer)
OVS_ARGUMENT* CreateArgumentStringA(OVS_ARGTYPE argType, const char* buffer);

//allocates an OVS_ARGUMENT and stores a copy of the ASCII string "buffer" as its data
OVS_ARGUMENT* CreateArgumentStringA_Alloc(OVS_ARGTYPE argType, const char* buffer);

//destroys the OVS_ARGUMENT-s of pGroup (i.e. pGroup->args) and frees pGroup
VOID DestroyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pGroup);

//destroys pArg->data of each argument in group, then it frees pGroup->args array
VOID DestroyArgumentsFromGroup(_In_ OVS_ARGUMENT_GROUP* pGroup);

//count: the number of OVS_ARGUMENT-s in the array
//destroys pArg->data of count args, then frees the argArray.
VOID DestroyArguments(_In_ OVS_ARGUMENT* argArray, UINT count);

//destroys the pArg->data and frees pArg
VOID DestroyArgument(_In_ OVS_ARGUMENT* pArg);
//if pArg = group => destroys group; else frees pArg->data
VOID DestroyArgumentData(_In_ OVS_ARGUMENT* pArg);

/******************************************* SET FUNCTIONS **********************************************************************/

//uses an empty OVS_ARGUMENT: sets type and sets a copy of buffer as pArg->data
//computes the size and that size is stored as pArg->length
//if computed size = ~0 (i.e. unknown size) => function fails
BOOLEAN SetArgument_Alloc(_Inout_ OVS_ARGUMENT* pArg, OVS_ARGTYPE argType, const VOID* buffer);

/******************************************* FIND FUNCTIONS **********************************************************************/
//finds the first OVS_ARGUMENT who was type == argumentType
OVS_ARGUMENT* FindArgument(_In_ const OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE argumentType);
//finds the first OVS_ARGUMENT who was type == groupType, and returns the OVS_ARGUMENT_GROUP it contains
OVS_ARGUMENT_GROUP* FindArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE groupType);
//finds the first OVS_ARGUMENT who was type == groupType, and returns the OVS_ARGUMENT that contains the group
//NOTE: it is equivalent to FindArgument
OVS_ARGUMENT* FindArgumentGroupAsArg(_In_ OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGTYPE groupType);

/******************************************* VALIDATION FUNCTIONS **********************************************************************/

static __inline BOOLEAN IsArgumentValid(_In_ OVS_ARGUMENT* pArg)
{
    OVS_CHECK(pArg);

    return (pArg->data && pArg->length || !pArg->data && !pArg->length);
}

BOOLEAN VerifyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pArgs, OVS_ARGTYPE groupType);

//calculates the size the group should have, based on the sizes of its args and the data and the data sizes of its args - it goes recursively
//OVS_CHECK-s that pGroup->size == expected size
//returns pGroup->size
UINT VerifyArgGroupSize(OVS_ARGUMENT_GROUP* pGroup);

BOOLEAN VerifyArgNoDuplicates(OVS_ARGUMENT_GROUP* pGroup, OVS_ARGTYPE groupType);

BOOLEAN VerifyArg_Flow_Stats(OVS_ARGUMENT* pArg);
BOOLEAN VerifyArg_Flow_TcpFlags(OVS_ARGUMENT* pArg);
BOOLEAN VerifyArg_Flow_TimeUsed(OVS_ARGUMENT* pArg);
BOOLEAN VerifyArg_Flow_Clear(OVS_ARGUMENT* pArg);
BOOLEAN VerifyGroup_PacketInfo(BOOLEAN isMask, BOOLEAN isRequest, _In_ OVS_ARGUMENT* pParentArg, BOOLEAN checkTransportLayer, BOOLEAN seekIp);
BOOLEAN VerifyGroup_PacketActions(OVS_ARGUMENT* pArg, BOOLEAN isRequest);

/******************************************* ARGUMENT LIST FUNCTIONS **********************************************************************/

#define AllocateArgListItem() ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_ARGUMENT_SLIST_ENTRY), g_extAllocationTag)

static __inline VOID FreeArgListItem(OVS_ARGUMENT_SLIST_ENTRY* pArgHead)
{
    if (pArgHead)
    {
        ExFreePoolWithTag(pArgHead, sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    }
}

//creates an OVS_ARGUMENT with a copy of buffer; allocates a list item; sets the arg as the listItem->pArg, and listItem->next = NULL
OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry(OVS_ARGTYPE argType, const VOID* buffer);
OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size);

//allocates an array of OVS_ARGUMENT-s, of count = the total number of OVS_ARGUMENT-s in list
//shallow copies the OVS_ARGUMENT-s from list to array items (i.e. pArrayArgItem->data == pListArgItem->data -- the buffer is not copied, only the pointer to it)
//NOTE: after this, you may need to free all args and arg list items from the list (this function does not do this)
//returns the arg array; countArgs = number of args; pSize = total size (including OVS_ARGUMENT_HEADER_SIZE-s)
OVS_ARGUMENT* ArgumentListToArray(_In_ OVS_ARGUMENT_SLIST_ENTRY* pHeadArg, _Inout_ UINT16* pCountArgs, _Inout_ UINT* pSize);

//crates an OVS_ARGUMENT with a copy of the buffer, creates a list item for it, and appends it to *pLastArg;
//*ppLastArg will point to the last (now-created) list item
BOOLEAN CreateArgInList(OVS_ARGTYPE argType, const VOID* buffer, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg);

BOOLEAN CreateArgInList_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg);

//allocates an arg list item, sets pArg as its listItem->pArg, and appends it to *ppLastEntry;
//*ppLastEntry then points to the appended listItem
BOOLEAN AppendArgumentToList(OVS_ARGUMENT* pArg, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastEntry);

//destroys each OVS_ARGUMENT in the list, and frees all list items
VOID DestroyArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppFirstEntry);

//also frees the OVS_ARGUMENT-s within (the OVS_ARGUMENT::data is not freed)
VOID FreeArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry);

//creates an OVS_ARGUMENT array, argArray, with the args of the list, whose head is *pHeadArg
//creates an OVS_ARGUMENT_GROUP to have pGroup->args = argArray, and encapsulates it in an OVS_ARGUMENT, pArg
//on success, it frees the arg list with FreeArgList and returns the pArg.
OVS_ARGUMENT* CreateGroupArgFromList(OVS_ARGTYPE groupType, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadArg);

/******************************************* COPY FUNCTIONS **********************************************************************/

//argsMore: pDest will be allocated for "pSource->count + argsMore" arguments.
//allocates an OVS_ARGUMENT argArray of pSource->count + argsMore arguments, and calls CopyArgument to copy each argument in pDest
BOOLEAN CopyArgumentGroup(_Out_ OVS_ARGUMENT_GROUP* pDest, _In_ const OVS_ARGUMENT_GROUP* pSource, UINT16 argsMore);

//copy arg info (type, length); allocates pDest->data;
//if arg = group => calls CopyArgumentGroup to copy data; else RtlCopyMemory to copy data
BOOLEAN CopyArgument(_Out_ OVS_ARGUMENT* pDest, _In_ const OVS_ARGUMENT* pSource);

/******************************************* DbgPrint for args **********************************************************************/

VOID DbgPrintArgType(OVS_ARGTYPE argType, const char* padding, int index);
VOID DbgPrintArg(_In_ OVS_ARGUMENT* pArg, int depth, int index);
VOID DbgPrintArgGroup(_In_ OVS_ARGUMENT_GROUP* pGroup, int depth);

/******************************************* ARG SIZE FUNCTIONS **********************************************************************/

//given group type & arg type, retrieve expected size: 0 = no data; ~0 = any size.
//returns TRUE on success, FALSE on failure.
BOOLEAN GetArgumentExpectedSize(OVS_ARGTYPE argumentType, _Inout_ UINT* pSize);
OVS_ARGTYPE GetParentGroupType(OVS_ARGTYPE childArgType);