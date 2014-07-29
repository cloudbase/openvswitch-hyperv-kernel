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

#define OVS_SIZE_ALIGNED_N(dataSize, N)        (((dataSize) / (N)) * (N) + ((dataSize) % (N) ? (N) : 0))
#define OVS_SIZE_ALIGNED_4(dataSize)            OVS_SIZE_ALIGNED_N(dataSize, 4)
#define OVS_NLA_DATA(nlAttr)                ((BYTE*)nlAttr + sizeof(OVS_NL_ATTRIBUTE))

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

#define COMPARE_ARGUMENT_SIMPLE(arg, value, typeOfValue) \
    (*(typeOfValue*)arg->data == value ? TRUE : FALSE)

#define GET_ARG_DATA(arg, typeOfDest) \
(*(typeOfDest*)arg->data)

#define GET_ARG_DATA_PTR(arg, ptrType) \
    ((ptrType*)arg->data)

#define OVS_FOR_EACH_ARG(pGroup, pArg, argType, code)            \
    for (UINT i = 0; i < (pGroup)->count; ++i)    \
{                                            \
    OVS_ARGUMENT* pArg = (pGroup)->args + i;        \
    OVS_ARGTYPE argType = pArg->type;            \
    code;                                        \
}

#define OVS_PARSE_ARGS_QUICK(group, pGroup, args)                       \
    OVS_ARGUMENT* args[OVS_ARGTYPE_COUNT(group)] = {0};                 \
                                                                        \
    OVS_FOR_EACH_ARG((pGroup), pArg, argType,                           \
                                                                        \
    OVS_ARGUMENT** ppCurArg = args + OVS_ARG_TOINDEX(argType, group);   \
    OVS_CHECK(!*ppCurArg);                                              \
    *ppCurArg = pArg                                                    \
    );

/******************************************* ALLOC & FREE FUNCTIONS **********************************************************************/

//allocates an array of count OVS_ARGUMENT-s, and assigns it to pGroup->args
BOOLEAN AllocateArgumentsToGroup(UINT16 count, _Out_ OVS_ARGUMENT_GROUP* pGroup);

static __inline VOID FreeGroupWithArgs(_Inout_ OVS_ARGUMENT_GROUP* pGroup)
{
    if (pGroup)
    {
        KFree(pGroup->args);
        KFree(pGroup);
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

OVS_ARGUMENT_GROUP* CreateGroupFromArgArray(OVS_ARGUMENT* argArray, UINT16 countArgs, UINT16 totalSize);

//allocates an OVS_ARGUMENT and stores the ASCII string "buffer" as its data (NOTE: it does not use a copy of buffer)
OVS_ARGUMENT* CreateArgumentStringA(OVS_ARGTYPE argType, const char* buffer);

//allocates an OVS_ARGUMENT and stores a copy of the ASCII string "buffer" as its data
OVS_ARGUMENT* CreateArgumentStringA_Alloc(OVS_ARGTYPE argType, const char* buffer);

//destroys the OVS_ARGUMENT-s of pGroup (i.e. pGroup->args) and frees pGroup
VOID DestroyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pGroup);

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

/******************************************* COPY FUNCTIONS **********************************************************************/

//argsMore: pDest will be allocated for "pSource->count + argsMore" arguments.
//allocates an OVS_ARGUMENT argArray of pSource->count + argsMore arguments, and calls CopyArgument to copy each argument in pDest
BOOLEAN CopyArgumentGroup(_Out_ OVS_ARGUMENT_GROUP* pDest, _In_ const OVS_ARGUMENT_GROUP* pSource, UINT16 argsMore);

//copy arg info (type, length); allocates pDest->data;
//if arg = group => calls CopyArgumentGroup to copy data; else RtlCopyMemory to copy data
BOOLEAN CopyArgument(_Out_ OVS_ARGUMENT* pDest, _In_ const OVS_ARGUMENT* pSource);

/******************************************* DbgPrint for args **********************************************************************/

#if OVS_DBGPRINT_ARG
VOID DbgPrintArgType(ULONG logLevel, OVS_ARGTYPE argType, const char* padding, int index);
VOID DbgPrintArg(ULONG logLevel, _In_ OVS_ARGUMENT* pArg, int depth, int index);
VOID DbgPrintArgGroup(ULONG logLevel, _In_ OVS_ARGUMENT_GROUP* pGroup, int depth);

#define DBGPRINT_ARG(logLevel, pArg, depth, index)          DbgPrintArg(logLevel, pArg, depth, index)
#define DBGPRINT_ARGTYPE(logLevel, argType, padding, index) DbgPrintArgType(logLevel, argType, padding, index)
#define DBGPRINT_ARGGROUP(logLevel, pGroup, depth)          DbgPrintArgGroup(logLevel, pGroup, depth)
#else
#define DBGPRINT_ARG(logLevel, pArg, depth, index)
#define DBGPRINT_ARGTYPE(logLevel, argType, padding, index)
#define DBGPRINT_ARGGROUP(logLevel, pGroup, depth)

#endif

/******************************************* ARG SIZE FUNCTIONS **********************************************************************/

//given group type & arg type, retrieve expected size: 0 = no data; ~0 = any size.
//returns TRUE on success, FALSE on failure.
BOOLEAN GetArgumentExpectedSize(OVS_ARGTYPE argumentType, _Inout_ UINT* pSize);
OVS_ARGTYPE GetParentGroupType(OVS_ARGTYPE childArgType);

static __inline AddArgToArgGroup(OVS_ARGUMENT_GROUP* pArgGroup, OVS_ARGUMENT* pArg, _Inout_ ULONG* pIndex)
{
    pArgGroup->args[*pIndex] = *pArg;
    pArgGroup->groupSize += pArg->length;

    ++pIndex;
}