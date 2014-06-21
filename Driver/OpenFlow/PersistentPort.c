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

#include "PersistentPort.h"
#include "Sctx_Nic.h"
#include "Sctx_Port.h"
#include "List.h"
#include <ntstrsafe.h>

extern OVS_SWITCH_INFO* g_pSwitchInfo;

static LIST_ENTRY g_grePorts;
static LIST_ENTRY g_vxlanPorts;

static BOOLEAN g_haveInternal = FALSE;

/***************************************************/

static BOOLEAN _AddPersPort_Logical(LIST_ENTRY* pList, _In_ const OVS_PERSISTENT_PORT* pPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;

    pPortEntry = KAlloc(sizeof(OVS_LOGICAL_PORT_ENTRY));
    if (!pPortEntry)
    {
        return FALSE;
    }

    pPortEntry->pPort = (OVS_PERSISTENT_PORT*)pPort;

    InsertTailList(pList, &pPortEntry->listEntry);

    return TRUE;
}

static BOOLEAN _RemovePersPort_Logical(LIST_ENTRY* pList, _In_ const OVS_PERSISTENT_PORT* pPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;

    LIST_FOR_EACH_ENTRY(pPortEntry, pList, listEntry, OVS_LOGICAL_PORT_ENTRY)
    {
        if (pPortEntry->pPort == pPort)
        {
            RemoveEntryList(&pPortEntry->listEntry);

            KFree(pPortEntry);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN _AddPersPort_Gre(_In_ const OVS_PERSISTENT_PORT* pPort)
{
    return _AddPersPort_Logical(&g_grePorts, pPort);
}

static BOOLEAN _AddPersPort_Vxlan(_In_ const OVS_PERSISTENT_PORT* pPort)
{
    return _AddPersPort_Logical(&g_vxlanPorts, pPort);
}

static BOOLEAN _RemovePersPort_Gre(_In_ const OVS_PERSISTENT_PORT* pPort)
{
    return _RemovePersPort_Logical(&g_grePorts, pPort);
}

static BOOLEAN _RemovePersPort_Vxlan(_In_ const OVS_PERSISTENT_PORT* pPort)
{
    return _RemovePersPort_Logical(&g_vxlanPorts, pPort);
}

static OVS_PERSISTENT_PORT* _PersPort_FindTunnel(_In_ const LIST_ENTRY* pList, _In_ const OVS_TUNNELING_PORT_OPTIONS* pTunnelOptions)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;

    if (pList == &g_vxlanPorts)
    {
        OVS_CHECK(pTunnelOptions);
    }

    LIST_FOR_EACH_ENTRY(pPortEntry, pList, listEntry, OVS_LOGICAL_PORT_ENTRY)
    {
        if (pList == &g_grePorts)
        {
            pPortEntry = CONTAINING_RECORD(pList->Flink, OVS_LOGICAL_PORT_ENTRY, listEntry);
            return pPortEntry->pPort;
        }

        else
        {
            //VXLAN
            OVS_TUNNELING_PORT_OPTIONS* pOptions = NULL;

            OVS_CHECK(pList == &g_vxlanPorts);

            pOptions = pPortEntry->pPort->pOptions;
            OVS_CHECK(pOptions);
            OVS_CHECK(pTunnelOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT);

            if (pOptions->udpDestPort == pTunnelOptions->udpDestPort)
            {
                return pPortEntry->pPort;
            }
        }
    }

    return NULL;
}

static BOOLEAN _PortFriendlyNameIs(int i, const char* portName, _In_ const OVS_PORT_LIST_ENTRY* pPortEntry)
{
    char asciiPortName[IF_MAX_STRING_SIZE + 1];

    UNREFERENCED_PARAMETER(i);

    if (strlen(portName) != pPortEntry->portFriendlyName.Length / 2)
    {
        return FALSE;
    }

    OVS_CHECK(pPortEntry->portFriendlyName.Length / 2 <= IF_MAX_STRING_SIZE);

    NdisZeroMemory(asciiPortName, IF_MAX_STRING_SIZE + 1);
    WcharArrayToAscii(asciiPortName, pPortEntry->portFriendlyName.String, pPortEntry->portFriendlyName.Length / 2);

    return (0 == strcmp(portName, asciiPortName));
}

//Unsafe = does not lock PersPort
static VOID _PersPort_SetNicAndPort_Unsafe(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, OVS_PERSISTENT_PORT* pPersPort)
{
    const char* externalPortName = "external";

    OVS_CHECK(pPersPort);

    if (pPersPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        pPersPort->pPortListEntry = pForwardInfo->pInternalPort;
        pPersPort->pNicListEntry = pForwardInfo->pInternalNic;
    }

    else if (pPersPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        pPersPort->pPortListEntry = NULL;
        pPersPort->pNicListEntry = NULL;
    }

    else if (pPersPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        pPersPort->pPortListEntry = NULL;
        pPersPort->pNicListEntry = NULL;
    }

    else if (0 == _stricmp(pPersPort->ovsPortName, externalPortName))
    {
        pPersPort->pPortListEntry = pForwardInfo->pExternalPort;
        pPersPort->pNicListEntry = pForwardInfo->pExternalNic;
    }

    else
    {
        pPersPort->pPortListEntry = Sctx_FindPortBy_Unsafe(g_pSwitchInfo->pForwardInfo, pPersPort->ovsPortName, _PortFriendlyNameIs);

        if (pPersPort->pPortListEntry)
        {
            pPersPort->pNicListEntry = Sctx_FindNicByPortId_Unsafe(g_pSwitchInfo->pForwardInfo, pPersPort->pPortListEntry->portId);
        }
    }

    if (pPersPort->pPortListEntry)
    {
        pPersPort->pPortListEntry->pPersistentPort = pPersPort;
    }

    if (pPersPort->pNicListEntry)
    {
        pPersPort->pNicListEntry->pPersistentPort = pPersPort;
    }
}

static VOID _PersPort_UnsetNicAndPort_Unsafe(OVS_PERSISTENT_PORT* pPersPort)
{
    OVS_CHECK(pPersPort);

    if (pPersPort->pPortListEntry)
    {
        pPersPort->pPortListEntry->pPersistentPort = NULL;
        pPersPort->pPortListEntry = NULL;
    }

    if (pPersPort->pNicListEntry)
    {
        pPersPort->pNicListEntry->pPersistentPort = NULL;
        pPersPort->pNicListEntry = NULL;
    }
}

static BOOLEAN _FindNextFreePort(_In_ const OVS_PERSISTENT_PORTS_INFO* pPorts, _Inout_ UINT16* pFirst)
{
    UINT16 first = 0;

    OVS_CHECK(pFirst);

    first = *pFirst;

    //we have set the 'firstFree' to a port => we must find the next free port to set firstFree = null_port
    //we start searching a free slot in [first, end]
    while (first < OVS_MAX_PORTS && pPorts->portsArray[first])
    {
        first++;
    }

    //if we found a free slot => this is the free port we return
    if (first < OVS_MAX_PORTS)
    {
        if (!pPorts->portsArray[first])
        {
            *pFirst = first;
            return TRUE;
        }
    }

    //else, search [0, first)
    for (first = 0; first < pPorts->firstPortFree; ++first)
    {
        if (!pPorts->portsArray[first])
        {
            *pFirst = first;
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN _PersPort_AddByNumber_Unsafe(_Inout_ OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo, _In_ OVS_PERSISTENT_PORT* pPort)
{
    UINT16 first = pPersistentPortsInfo->firstPortFree;
    BOOLEAN ok = TRUE;

    if (NULL != pPersistentPortsInfo->portsArray[pPort->ovsPortNumber])
    {
        const OVS_PERSISTENT_PORT* pOtherPort = pPersistentPortsInfo->portsArray[pPort->ovsPortNumber];

        UNREFERENCED_PARAMETER(pOtherPort);

        OVS_CHECK(pOtherPort->ofPortType == pPort->ofPortType);
        OVS_CHECK(pOtherPort->ovsPortNumber == pPort->ovsPortNumber);

        //TODO: OVS_ERROR_EXIST
        return FALSE;
    }

    pPersistentPortsInfo->portsArray[pPort->ovsPortNumber] = pPort;
    pPersistentPortsInfo->count++;

    if (first == OVS_LOCAL_PORT_NUMBER && !g_haveInternal)
    {
        OVS_CHECK(pPort->ovsPortNumber <= MAXUINT16);

        first = (UINT16)pPort->ovsPortNumber;
    }

    if (first != pPort->ovsPortNumber)
    {
        ok = FALSE;
        goto Cleanup;
    }

    if (first == pPort->ovsPortNumber)
    {
        //we have set the 'firstFree' to a port => we must find the next free port to set firstFree = null_port

        if (!_FindNextFreePort(pPersistentPortsInfo, &first))
        {
            OVS_CHECK(pPersistentPortsInfo->count == MAXUINT16);

            DEBUGP(LOG_ERROR, "all available ports are used!\n");
            ok = FALSE;
            goto Cleanup;
        }

        pPersistentPortsInfo->firstPortFree = first;
    }

Cleanup:
    if (!ok)
    {
        //found no room for new port
        pPersistentPortsInfo->portsArray[pPort->ovsPortNumber] = NULL;
        pPersistentPortsInfo->count--;
    }

    return ok;
}

BOOLEAN _PersPort_AddByName_Unsafe(_Inout_ OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo, _In_ OVS_PERSISTENT_PORT* pPort)
{
    UINT16 first = pPersistentPortsInfo->firstPortFree;
    BOOLEAN ok = TRUE;

    OVS_CHECK(NULL == pPersistentPortsInfo->portsArray[first]);
    pPort->ovsPortNumber = first;

    pPersistentPortsInfo->portsArray[pPort->ovsPortNumber] = pPort;
    pPersistentPortsInfo->count++;

    if (!_FindNextFreePort(pPersistentPortsInfo, &first))
    {
        OVS_CHECK(pPersistentPortsInfo->count == MAXUINT16);

        DEBUGP(LOG_ERROR, "all available ports are used!\n");
        ok = FALSE;
        goto Cleanup;
    }

    pPersistentPortsInfo->firstPortFree = first;

Cleanup:
    if (!ok)
    {
        //found no room for new port
        pPersistentPortsInfo->portsArray[pPort->ovsPortNumber] = NULL;
        pPersistentPortsInfo->count--;
    }

    return ok;
}

OVS_PERSISTENT_PORT* PersPort_Create_Unsafe(_In_opt_ const char* portName, _In_opt_ const UINT16* pPortNumber, OVS_OFPORT_TYPE portType)
{
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPersPort = NULL;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;

    OVS_CHECK(g_pSwitchInfo);

    pForwardInfo = g_pSwitchInfo->pForwardInfo;

    OVS_CHECK(pForwardInfo);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    if (portType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        //i.e. the first internal port is port LOCAL, must be created or must have been created
        //on slot = 0 (LOCAL port's number). ovs 1.11 allows multiple internal (i.e. datapath) ports.
        OVS_CHECK(pPersistentPortsInfo->firstPortFree == OVS_LOCAL_PORT_NUMBER ||
            pPersistentPortsInfo->portsArray[OVS_LOCAL_PORT_NUMBER]);
        OVS_CHECK(portName);
    }

    pPersPort = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_PERSISTENT_PORT), g_extAllocationTag);

    if (!pPersPort)
    {
        ok = FALSE;
        goto Cleanup;
    }

    NdisZeroMemory(pPersPort, sizeof(OVS_PERSISTENT_PORT));

    //if name for port was not provided, we must have been given a number
    if (!portName)
    {
        if (!pPortNumber)
        {
            ok = FALSE;
            goto Cleanup;
        }

        pPersPort->ovsPortName = ExAllocatePoolWithTag(NonPagedPool, 257, g_extAllocationTag);

        if (!pPersPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchPrintfA((char*)pPersPort->ovsPortName, 257, "kport_%u", *pPortNumber);
    }

    //if a name has been given, we use it
    else
    {
        ULONG portNameLen = (ULONG)strlen(portName) + 1;
        pPersPort->ovsPortName = ExAllocatePoolWithTag(NonPagedPool, portNameLen, g_extAllocationTag);

        if (!pPersPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchCopyA((char*)pPersPort->ovsPortName, portNameLen, portName);
    }

    //if port number was not given, we set it now to 0 an call below _PersPort_AddByName_Unsafe
    pPersPort->ovsPortNumber = (pPortNumber ? *pPortNumber : 0);
    pPersPort->ofPortType = portType;
    pPersPort->pSwitchInfo = g_pSwitchInfo;

    //NOTE: we may have more persistent ports than NICS: logical ports don't have nics associated
    //the same goes with hyper-v switch ports

    _PersPort_SetNicAndPort_Unsafe(pForwardInfo, pPersPort);

    //TODO: we must allow hyper-v switch ports to be created after the OVS ports!
    if (!pPersPort->pNicListEntry && portType == OVS_OFPORT_TYPE_PHYSICAL)
    {
        DEBUGP(LOG_LOUD, "we created a physical persistent port without having a hyper-v switch port as match.\n");
    }

    if (pPortNumber)
    {
        ok = _PersPort_AddByNumber_Unsafe(pPersistentPortsInfo, pPersPort);
    }
    else
    {
        ok = _PersPort_AddByName_Unsafe(pPersistentPortsInfo, pPersPort);
    }

    if (!ok)
    {
        goto Cleanup;
    }

    if (portType == OVS_OFPORT_TYPE_GRE)
    {
        if (IsListEmpty(&g_grePorts))
        {
            _AddPersPort_Gre(pPersPort);
        }
        else
        {
            DEBUGP(LOG_ERROR, "we already have gre vport!\n");
            ok = FALSE;//TODO: return EEXISTS!
            goto Cleanup;
        }
    }

    else if (portType == OVS_OFPORT_TYPE_VXLAN)
    {
        _AddPersPort_Vxlan(pPersPort);
    }

Cleanup:
    if (!ok)
    {
        if (pPersPort)
        {
            if (pPersPort->ovsPortName)
            {
                ExFreePoolWithTag((char*)pPersPort->ovsPortName, g_extAllocationTag);
            }

            ExFreePoolWithTag(pPersPort, g_extAllocationTag);
        }
    }

    return (ok ? pPersPort : NULL);
}

/***************************************************/

BOOLEAN PersPort_HaveInternal_Unsafe()
{
    BOOLEAN have = FALSE;

    have = g_haveInternal;

    return have;
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindExternal_Unsafe()
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        OVS_PERSISTENT_PORT* pCurPort = pPersistentPortsInfo->portsArray[i];

        if (pCurPort)
        {
            if (pCurPort->pNicListEntry && pCurPort->pNicListEntry->nicType == NdisSwitchNicTypeExternal)
            {
                pPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPersistentPortsInfo->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPersistentPortsInfo->count);

Cleanup:
    return pPort;
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindInternal_Unsafe()
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        OVS_PERSISTENT_PORT* pCurPort = pPersistentPortsInfo->portsArray[i];

        if (pCurPort)
        {
            if (pCurPort->pNicListEntry && pCurPort->pNicListEntry->nicType == NdisSwitchNicTypeInternal)
            {
                pPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPersistentPortsInfo->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPersistentPortsInfo->count);

Cleanup:
    return pPort;
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindGre(const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo)
{
    return _PersPort_FindTunnel(&g_grePorts, pTunnelInfo);
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindVxlan(const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo)
{
    return _PersPort_FindTunnel(&g_vxlanPorts, pTunnelInfo);
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindVxlanByDestPort(LE16 udpDestPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;

    LIST_FOR_EACH_ENTRY(pPortEntry, &g_vxlanPorts, listEntry, OVS_LOGICAL_PORT_ENTRY)
    {
        OVS_TUNNELING_PORT_OPTIONS* pOptions = NULL;

        pOptions = pPortEntry->pPort->pOptions;
        OVS_CHECK(pOptions);

        if (pOptions->udpDestPort == udpDestPort)
        {
            return pPortEntry->pPort;
        }
    }

    return NULL;
}

BOOLEAN PersPort_Initialize()
{
    InitializeListHead(&g_grePorts);
    InitializeListHead(&g_vxlanPorts);

    return TRUE;
}

VOID PersPort_Uninitialize()
{
    //TODO: Implement unitialize
}

BOOLEAN PersPort_CForEach_Unsafe(_In_ const OVS_PERSISTENT_PORTS_INFO* pPorts, VOID* pContext, BOOLEAN(*Action)(int, OVS_PERSISTENT_PORT*, VOID*))
{
    ULONG countProcessed = 0;
    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        if (pPorts->portsArray[i])
        {
            if (!(*Action)(countProcessed, pPorts->portsArray[i], pContext))
            {
                return FALSE;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPorts->count);

    return TRUE;
}

OVS_PERSISTENT_PORT* PersPort_FindByName_Unsafe(const char* ofPortName)
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        if (pPersistentPortsInfo->portsArray[i])
        {
            if (0 == strcmp(pPersistentPortsInfo->portsArray[i]->ovsPortName, ofPortName))
            {
                pPort = pPersistentPortsInfo->portsArray[i];
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPersistentPortsInfo->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPersistentPortsInfo->count);

Cleanup:
    return pPort;
}

OVS_PERSISTENT_PORT* PersPort_FindById_Unsafe(NDIS_SWITCH_PORT_ID portId, BOOLEAN lookInNic)
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;

    OVS_CHECK(portId != NDIS_SWITCH_DEFAULT_PORT_ID);
    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        if (pPersistentPortsInfo->portsArray[i])
        {
            if (lookInNic)
            {
                if (pPersistentPortsInfo->portsArray[i]->pNicListEntry)
                {
                    if (pPersistentPortsInfo->portsArray[i]->pNicListEntry->portId == portId)
                    {
                        pPort = pPersistentPortsInfo->portsArray[i];
                        goto Cleanup;
                    }
                }
            }

            else
            {
                if (pPersistentPortsInfo->portsArray[i]->pPortListEntry)
                {
                    if (pPersistentPortsInfo->portsArray[i]->pPortListEntry->portId == portId)
                    {
                        pPort = pPersistentPortsInfo->portsArray[i];
                        goto Cleanup;
                    }
                }
            }

            ++countProcessed;
        }

        if (countProcessed >= pPersistentPortsInfo->count)
            break;
    }

    OVS_CHECK(countProcessed == pPersistentPortsInfo->count);

Cleanup:
    return pPort;
}

OVS_PERSISTENT_PORT* PersPort_FindByNumber_Unsafe(UINT16 portNumber)
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        if (pPersistentPortsInfo->portsArray[i])
        {
            if (pPersistentPortsInfo->portsArray[i]->ovsPortNumber == portNumber)
            {
                pPort = pPersistentPortsInfo->portsArray[i];
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPersistentPortsInfo->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPersistentPortsInfo->count);

Cleanup:
    return pPort;
}

BOOLEAN PersPort_Delete_Unsafe(OVS_PERSISTENT_PORT* pPersPort)
{
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo);

    if (pPersPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        _RemovePersPort_Gre(pPersPort);
    }

    else if (pPersPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        _RemovePersPort_Vxlan(pPersPort);
    }

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;

    if (pPorts->portsArray[pPersPort->ovsPortNumber] != pPersPort)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ "port not found: %u\n", pPersPort->ovsPortNumber);
        ok = FALSE;
        goto Cleanup;
    }

    pPorts->portsArray[pPersPort->ovsPortNumber] = NULL;
    OVS_CHECK(pPersPort->ovsPortNumber <= 0xFFFF);

    pPorts->firstPortFree = (UINT16)pPersPort->ovsPortNumber;
    OVS_CHECK(pPorts->count > 0);
    --(pPorts->count);

    ExFreePoolWithTag((VOID*)pPersPort->ovsPortName, g_extAllocationTag);

    _PersPort_UnsetNicAndPort_Unsafe(pPersPort);

    if (pPersPort->pOptions)
    {
        ExFreePoolWithTag(pPersPort->pOptions, g_extAllocationTag);
    }

    ExFreePoolWithTag(pPersPort, g_extAllocationTag);

Cleanup:
    return ok;
}

OVS_PERSISTENT_PORT* PersPort_GetInternal_Unsafe()
{
    OVS_PERSISTENT_PORTS_INFO* pPersistentPortsInfo = NULL;
    OVS_PERSISTENT_PORT* pInternalPort = NULL;

    OVS_CHECK(g_pSwitchInfo);

    pPersistentPortsInfo = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPersistentPortsInfo->count >= OVS_MAX_PORTS)
    {
        return NULL;
    }

    if (pPersistentPortsInfo->count == 0)
    {
        return NULL;
    }

    pInternalPort = pPersistentPortsInfo->portsArray[0];
    if (pInternalPort)
    {
        OVS_CHECK(pInternalPort->ovsPortNumber == OVS_LOCAL_PORT_NUMBER);
    }

    return pInternalPort;
}