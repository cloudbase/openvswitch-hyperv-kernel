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

typedef struct _OVS_ARGUMENT OVS_ARGUMENT;

typedef struct _OVS_ARGUMENT_SLIST_ENTRY
{
    OVS_ARGUMENT* pArg;
    struct _OVS_ARGUMENT_SLIST_ENTRY* pNext;
} OVS_ARGUMENT_SLIST_ENTRY;

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

//destroys each OVS_ARGUMENT in the list, and frees all list items; or frees the OVS_ARGUMENT-s within
VOID DestroyOrFreeArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry, BOOLEAN destroy);

//creates an OVS_ARGUMENT array, argArray, with the args of the list, whose head is *pHeadArg
//creates an OVS_ARGUMENT_GROUP to have pGroup->args = argArray, and encapsulates it in an OVS_ARGUMENT, pArg
//on success, it frees the arg list with FreeArgList and returns the pArg.
OVS_ARGUMENT* CreateGroupArgFromList(OVS_ARGTYPE groupType, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadArg);