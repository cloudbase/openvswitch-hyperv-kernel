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

	LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, pList)
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

	LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, pList)
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
static VOID _PersPort_SetNicAndPort_Unsafe(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, OVS_PERSISTENT_PORT* pPort)
{
    const char* externalPortName = "external";

    OVS_CHECK(pPort);

    if (pPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        pPort->pPortListEntry = pForwardInfo->pInternalPort;
        pPort->pNicListEntry = pForwardInfo->pInternalNic;
    }

    else if (pPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        pPort->pPortListEntry = NULL;
        pPort->pNicListEntry = NULL;
    }

    else if (pPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        pPort->pPortListEntry = NULL;
        pPort->pNicListEntry = NULL;
    }

    else if (0 == _stricmp(pPort->ovsPortName, externalPortName))
    {
        pPort->pPortListEntry = pForwardInfo->pExternalPort;
        pPort->pNicListEntry = pForwardInfo->pExternalNic;
    }

    else
    {
        pPort->pPortListEntry = Sctx_FindPortBy_Unsafe(g_pSwitchInfo->pForwardInfo, pPort->ovsPortName, _PortFriendlyNameIs);

        if (pPort->pPortListEntry)
        {
            pPort->pNicListEntry = Sctx_FindNicByPortId_Unsafe(g_pSwitchInfo->pForwardInfo, pPort->pPortListEntry->portId);
        }
    }

    if (pPort->pPortListEntry)
    {
        pPort->pPortListEntry->pPersistentPort = pPort;
    }

    if (pPort->pNicListEntry)
    {
        pPort->pNicListEntry->pPersistentPort = pPort;
    }
}

static VOID _PersPort_UnsetNicAndPort_Unsafe(OVS_PERSISTENT_PORT* pPort)
{
    OVS_CHECK(pPort);

    if (pPort->pPortListEntry)
    {
        pPort->pPortListEntry->pPersistentPort = NULL;
        pPort->pPortListEntry = NULL;
    }

    if (pPort->pNicListEntry)
    {
        pPort->pNicListEntry->pPersistentPort = NULL;
        pPort->pNicListEntry = NULL;
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

BOOLEAN _PersPort_AddByNumber_Unsafe(_Inout_ OVS_PERSISTENT_PORTS_INFO* pPorts, _In_ OVS_PERSISTENT_PORT* pPort)
{
    UINT16 first = pPorts->firstPortFree;
    BOOLEAN ok = TRUE;

    if (NULL != pPorts->portsArray[pPort->ovsPortNumber])
    {
        const OVS_PERSISTENT_PORT* pOtherPort = pPorts->portsArray[pPort->ovsPortNumber];

        UNREFERENCED_PARAMETER(pOtherPort);

        OVS_CHECK(pOtherPort->ofPortType == pPort->ofPortType);
        OVS_CHECK(pOtherPort->ovsPortNumber == pPort->ovsPortNumber);

        //TODO: OVS_ERROR_EXIST
        return FALSE;
    }

    pPorts->portsArray[pPort->ovsPortNumber] = pPort;
    pPorts->count++;

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

        if (!_FindNextFreePort(pPorts, &first))
        {
            OVS_CHECK(pPorts->count == MAXUINT16);

            DEBUGP(LOG_ERROR, "all available ports are used!\n");
            ok = FALSE;
            goto Cleanup;
        }

        pPorts->firstPortFree = first;
    }

Cleanup:
    if (!ok)
    {
        //found no room for new port
        pPorts->portsArray[pPort->ovsPortNumber] = NULL;
        pPorts->count--;
    }

    return ok;
}

BOOLEAN _PersPort_AddByName_Unsafe(_Inout_ OVS_PERSISTENT_PORTS_INFO* pPorts, _In_ OVS_PERSISTENT_PORT* pPort)
{
    UINT16 first = pPorts->firstPortFree;
    BOOLEAN ok = TRUE;

    OVS_CHECK(NULL == pPorts->portsArray[first]);
    pPort->ovsPortNumber = first;

    pPorts->portsArray[pPort->ovsPortNumber] = pPort;
    pPorts->count++;

    if (!_FindNextFreePort(pPorts, &first))
    {
        OVS_CHECK(pPorts->count == MAXUINT16);

        DEBUGP(LOG_ERROR, "all available ports are used!\n");
        ok = FALSE;
        goto Cleanup;
    }

    pPorts->firstPortFree = first;

Cleanup:
    if (!ok)
    {
        //found no room for new port
        pPorts->portsArray[pPort->ovsPortNumber] = NULL;
        pPorts->count--;
    }

    return ok;
}

OVS_PERSISTENT_PORT* PersPort_Create_Unsafe(_In_opt_ const char* portName, _In_opt_ const UINT16* pPortNumber, OVS_OFPORT_TYPE portType)
{
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pPort = NULL;
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;

    OVS_CHECK(g_pSwitchInfo);

    pForwardInfo = g_pSwitchInfo->pForwardInfo;

    OVS_CHECK(pForwardInfo);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    if (portType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        //i.e. the first internal port is port LOCAL, must be created or must have been created
        //on slot = 0 (LOCAL port's number). ovs 1.11 allows multiple internal (i.e. datapath) ports.
        OVS_CHECK(pPorts->firstPortFree == OVS_LOCAL_PORT_NUMBER ||
            pPorts->portsArray[OVS_LOCAL_PORT_NUMBER]);
        OVS_CHECK(portName);
    }

    pPort = ExAllocatePoolWithTag(NonPagedPool, sizeof(OVS_PERSISTENT_PORT), g_extAllocationTag);

    if (!pPort)
    {
        ok = FALSE;
        goto Cleanup;
    }

    NdisZeroMemory(pPort, sizeof(OVS_PERSISTENT_PORT));

	pPort->rcu.Destroy = PersPort_DestroyNow_Unsafe;
	pPort->pRwLock = NdisAllocateRWLock(NULL);

    //if name for port was not provided, we must have been given a number
    if (!portName)
    {
        if (!pPortNumber)
        {
            ok = FALSE;
            goto Cleanup;
        }

        pPort->ovsPortName = ExAllocatePoolWithTag(NonPagedPool, 257, g_extAllocationTag);

        if (!pPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchPrintfA((char*)pPort->ovsPortName, 257, "kport_%u", *pPortNumber);
    }

    //if a name has been given, we use it
    else
    {
        ULONG portNameLen = (ULONG)strlen(portName) + 1;
        pPort->ovsPortName = ExAllocatePoolWithTag(NonPagedPool, portNameLen, g_extAllocationTag);

        if (!pPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchCopyA((char*)pPort->ovsPortName, portNameLen, portName);
    }

    //if port number was not given, we set it now to 0 an call below _PersPort_AddByName_Unsafe
    pPort->ovsPortNumber = (pPortNumber ? *pPortNumber : 0);
    pPort->ofPortType = portType;
    pPort->pSwitchInfo = g_pSwitchInfo;

    //NOTE: we may have more persistent ports than NICS: logical ports don't have nics associated
    //the same goes with hyper-v switch ports

    _PersPort_SetNicAndPort_Unsafe(pForwardInfo, pPort);

    //TODO: we must allow hyper-v switch ports to be created after the OVS ports!
    if (!pPort->pNicListEntry && portType == OVS_OFPORT_TYPE_PHYSICAL)
    {
        DEBUGP(LOG_LOUD, "we created a physical persistent port without having a hyper-v switch port as match.\n");
    }

    if (pPortNumber)
    {
        ok = _PersPort_AddByNumber_Unsafe(pPorts, pPort);
    }
    else
    {
        ok = _PersPort_AddByName_Unsafe(pPorts, pPort);
    }

    if (!ok)
    {
        goto Cleanup;
    }

    if (portType == OVS_OFPORT_TYPE_GRE)
    {
        if (IsListEmpty(&g_grePorts))
        {
            _AddPersPort_Gre(pPort);
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
        _AddPersPort_Vxlan(pPort);
    }

Cleanup:
    if (!ok)
    {
        if (pPort)
        {
            if (pPort->ovsPortName)
            {
                ExFreePoolWithTag((char*)pPort->ovsPortName, g_extAllocationTag);
            }

            ExFreePoolWithTag(pPort, g_extAllocationTag);
        }
    }

    return (ok ? pPort : NULL);
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
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;
    OVS_PERSISTENT_PORT* pOutPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        OVS_PERSISTENT_PORT* pCurPort = pPorts->portsArray[i];

        if (pCurPort)
        {
            if (pCurPort->pNicListEntry && pCurPort->pNicListEntry->nicType == NdisSwitchNicTypeExternal)
            {
				pOutPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPorts->count);

Cleanup:
	return pOutPort;
}

_Use_decl_annotations_
OVS_PERSISTENT_PORT* PersPort_FindInternal_Unsafe()
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;
	OVS_PERSISTENT_PORT* pOutPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
        OVS_PERSISTENT_PORT* pCurPort = pPorts->portsArray[i];

        if (pCurPort)
        {
            if (pCurPort->pNicListEntry && pCurPort->pNicListEntry->nicType == NdisSwitchNicTypeInternal)
            {
				pOutPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPorts->count);

Cleanup:
	return pOutPort;
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

	LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, &g_vxlanPorts)
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
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;
	OVS_PERSISTENT_PORT* pOutPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
		OVS_PERSISTENT_PORT* pCurPort = pPorts->portsArray[i];

		if (pCurPort)
        {
			if (0 == strcmp(pCurPort->ovsPortName, ofPortName))
            {
				pOutPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPorts->count);

Cleanup:
	return pOutPort;
}

OVS_PERSISTENT_PORT* PersPort_FindById_Unsafe(NDIS_SWITCH_PORT_ID portId, BOOLEAN lookInNic)
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;
	OVS_PERSISTENT_PORT* pOutPort = NULL;

    OVS_CHECK(portId != NDIS_SWITCH_DEFAULT_PORT_ID);
    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
		OVS_PERSISTENT_PORT* pCurPort = pPorts->portsArray[i];

        if (pCurPort)
        {
            if (lookInNic)
            {
				if (pCurPort->pNicListEntry)
                {
					if (pCurPort->pNicListEntry->portId == portId)
                    {
						pOutPort = pCurPort;
                        goto Cleanup;
                    }
                }
            }

            else
            {
				if (pCurPort->pPortListEntry)
                {
					if (pCurPort->pPortListEntry->portId == portId)
                    {
						pOutPort = pCurPort;
                        goto Cleanup;
                    }
                }
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
            break;
    }

    OVS_CHECK(countProcessed == pPorts->count);

Cleanup:
	return pOutPort;
}

OVS_PERSISTENT_PORT* PersPort_FindByNumber_Unsafe(UINT16 portNumber)
{
    ULONG countProcessed = 0;
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;
	OVS_PERSISTENT_PORT* pOutPort = NULL;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo->pRwLock);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    for (ULONG i = 0; i < OVS_MAX_PORTS; ++i)
    {
		OVS_PERSISTENT_PORT* pCurPort = pPorts->portsArray[i];

		if (pCurPort)
        {
			if (pCurPort->ovsPortNumber == portNumber)
            {
				pOutPort = pCurPort;
                goto Cleanup;
            }

            ++countProcessed;
        }

        if (countProcessed >= pPorts->count)
        {
            break;
        }
    }

    OVS_CHECK(countProcessed == pPorts->count);

Cleanup:
	return pOutPort;
}

BOOLEAN PersPort_Delete(OVS_PERSISTENT_PORT* pPort)
{
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    BOOLEAN ok = TRUE;

    OVS_CHECK(g_pSwitchInfo);
    OVS_CHECK(g_pSwitchInfo->pForwardInfo);

    if (pPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        _RemovePersPort_Gre(pPort);
    }

    else if (pPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        _RemovePersPort_Vxlan(pPort);
    }

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;

    if (pPorts->portsArray[pPort->ovsPortNumber] != pPort)
    {
        DEBUGP(LOG_ERROR, __FUNCTION__ "port not found: %u\n", pPort->ovsPortNumber);
        ok = FALSE;
        goto Cleanup;
    }

    pPorts->portsArray[pPort->ovsPortNumber] = NULL;
    OVS_CHECK(pPort->ovsPortNumber <= 0xFFFF);

    pPorts->firstPortFree = (UINT16)pPort->ovsPortNumber;
    OVS_CHECK(pPorts->count > 0);
    --(pPorts->count);

    ExFreePoolWithTag((VOID*)pPort->ovsPortName, g_extAllocationTag);

    _PersPort_UnsetNicAndPort_Unsafe(pPort);

    if (pPort->pOptions)
    {
        ExFreePoolWithTag(pPort->pOptions, g_extAllocationTag);
    }

    ExFreePoolWithTag(pPort, g_extAllocationTag);

Cleanup:
    return ok;
}

OVS_PERSISTENT_PORT* PersPort_GetInternal_Unsafe()
{
    OVS_PERSISTENT_PORTS_INFO* pPorts = NULL;
    OVS_PERSISTENT_PORT* pInternalPort = NULL;

    OVS_CHECK(g_pSwitchInfo);

    pPorts = &g_pSwitchInfo->pForwardInfo->persistentPortsInfo;
    if (pPorts->count >= OVS_MAX_PORTS)
    {
        return NULL;
    }

    if (pPorts->count == 0)
    {
        return NULL;
    }

    pInternalPort = pPorts->portsArray[0];
    if (pInternalPort)
    {
        OVS_CHECK(pInternalPort->ovsPortNumber == OVS_LOCAL_PORT_NUMBER);
    }

    return pInternalPort;
}

VOID PersPort_DestroyNow_Unsafe(OVS_PERSISTENT_PORT* pPort)
{
	KFree(pPort->ovsPortName);

	/* previously, we 'unset' the nic and port: the hyper-v switch ports & nics were set to have pPort = NULL
	** Now we use numbers instead. Anyway, there's no need to do unset now, because:
	** o) the only reason we keep the mapping between ovs port numbers and hyper-v switch port ids is because we need to find a port id, given an ovs port number (or ovs port name)
	** o) we need to be able to find a persistent port, when knowing a port id, only when setting a hyper-v switch port name.
	** o) any packet is sent out using an ovs port number (persistent port)
	** o) it never happens for a port (hyper-v switch port or ovs port) to be created with the same number as one that had been deleted.
	*/

	if (pPort->pOptions)
	{
		KFree(pPort->pOptions);
	}

	if (pPort->pRwLock) {
		NdisFreeRWLock(pPort->pRwLock);
	}

	KFree(pPort);
}