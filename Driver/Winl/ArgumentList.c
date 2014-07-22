#include "ArgumentList.h"

#include "Argument.h"

OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry(OVS_ARGTYPE argType, const VOID* buffer)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem;

    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArg = CreateArgument_Alloc(argType, buffer);
    if (!pArg)
    {
        return NULL;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;
    return pArgListItem;
}

OVS_ARGUMENT_SLIST_ENTRY* CreateArgumentListEntry_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem;

    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArg = CreateArgumentWithSize(argType, buffer, size);
    if (!pArg)
    {
        return NULL;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;
    return pArgListItem;
}

OVS_ARGUMENT* ArgumentListToArray(_In_ OVS_ARGUMENT_SLIST_ENTRY* pHeadArg, _Inout_ UINT16* pCountArgs, _Inout_ UINT* pSize)
{
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    OVS_ARGUMENT* args = NULL;
    OVS_ARGUMENT_SLIST_ENTRY* pArgListEntry = NULL;

    OVS_CHECK(pHeadArg);
    //pFirstArg must be the HEAD of the list: the HEAD has pArg = NULL
    OVS_CHECK(pHeadArg->pArg == NULL);

    pArgListEntry = pHeadArg->pNext;

    while (pArgListEntry)
    {
        ++countArgs;
        totalSize += pArgListEntry->pArg->length;
        totalSize += OVS_ARGUMENT_HEADER_SIZE;

        pArgListEntry = pArgListEntry->pNext;
    }

    args = KZAlloc(countArgs);
    if (!args)
    {
        return NULL;
    }

    pArgListEntry = pHeadArg->pNext;

    for (UINT i = 0; i < countArgs; ++i, pArgListEntry = pArgListEntry->pNext)
    {
        args[i] = *pArgListEntry->pArg;
    }

    *pCountArgs = countArgs;
    *pSize = totalSize;

    return args;
}

BOOLEAN AppendArgumentToList(OVS_ARGUMENT* pArg, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastEntry)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListItem = NULL;

    pArgListItem = KZAlloc(sizeof(OVS_ARGUMENT_SLIST_ENTRY));
    if (!pArgListItem)
    {
        return FALSE;
    }

    pArgListItem->pArg = pArg;
    pArgListItem->pNext = NULL;

    (*ppLastEntry)->pNext = pArgListItem;
    *ppLastEntry = pArgListItem;

    return TRUE;
}

BOOLEAN CreateArgInList(OVS_ARGTYPE argType, const VOID* buffer, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg)
{
    (*ppLastArg)->pNext = CreateArgumentListEntry(argType, buffer);
    if (!(*ppLastArg)->pNext)
    {
        return FALSE;
    }

    *ppLastArg = (*ppLastArg)->pNext;

    return TRUE;
}

BOOLEAN CreateArgInList_WithSize(OVS_ARGTYPE argType, const VOID* buffer, UINT16 size, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppLastArg)
{
    (*ppLastArg)->pNext = CreateArgumentListEntry_WithSize(argType, buffer, size);
    if (!(*ppLastArg)->pNext)
    {
        return FALSE;
    }

    *ppLastArg = (*ppLastArg)->pNext;

    return TRUE;
}

VOID DestroyOrFreeArgList(_Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadEntry, BOOLEAN destroy)
{
    OVS_ARGUMENT_SLIST_ENTRY* pArgListCur = *ppHeadEntry;
    OVS_ARGUMENT_SLIST_ENTRY* pNext = NULL;

    if (!pArgListCur)
        return;

    //the pArgListFirst points to a head, which has pArg = NULL
    OVS_CHECK(!pArgListCur->pArg);

    pArgListCur = pArgListCur->pNext;

    //free head
    KFree(*ppHeadEntry);

    while (pArgListCur)
    {
        pNext = pArgListCur->pNext;

        //1. destroy the arg
        if (destroy)
        {
            DestroyArgument(pArgListCur->pArg);
        }
        else
        {
            KFree(pArgListCur->pArg);
        }

        //2. free the list entry
        KFree(pArgListCur);

        pArgListCur = pNext;
    }

    *ppHeadEntry = NULL;
}

//NOTE: it also destroys the list
OVS_ARGUMENT* CreateGroupArgFromList(OVS_ARGTYPE groupType, _Inout_ OVS_ARGUMENT_SLIST_ENTRY** ppHeadArg)
{
    OVS_ARGUMENT_GROUP* pGroup = NULL;
    OVS_ARGUMENT* argArray = NULL, *pGroupArg = NULL;
    UINT16 countArgs = 0;
    UINT totalSize = 0;
    BOOLEAN ok = TRUE;

    pGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pGroup)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pGroupArg = KZAlloc(sizeof(OVS_ARGUMENT));
    if (!pGroupArg)
    {
        ok = FALSE;
        goto Cleanup;
    }

    //1. create args[] from arg single linked list
    argArray = ArgumentListToArray(*ppHeadArg, &countArgs, &totalSize);

    //2. create OVS_ARGUMENT_GROUP (i.e. group) with these args[]
    pGroup->args = argArray;
    pGroup->count = countArgs;

    //3. create an OVS_ARGUMENT which embeds the group (type of arg = group)
    pGroupArg->data = pGroup;
    pGroupArg->length = (UINT16)totalSize;
    pGroupArg->type = groupType;
    pGroupArg->isNested = FALSE;
    pGroupArg->freeData = TRUE;

    //4. Destroy the linked list
Cleanup:
    if (ok)
    {
        DestroyOrFreeArgList(ppHeadArg, /*destroy*/ FALSE);
    }
    else
    {
        //also destroys pArgs and its children
        DestroyArgument(pGroupArg);
    }

    return pGroupArg;
}