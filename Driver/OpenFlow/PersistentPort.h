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
#include "OFPort.h"

#define OVS_LOCAL_PORT_NUMBER            ((UINT32)0)
#define OVS_MAX_PORTS                    MAXUINT16
#define OVS_INVALID_PORT_NUMBER          OVS_MAX_PORTS

typedef struct _OVS_NIC_LIST_ENTRY OVS_NIC_LIST_ENTRY;
typedef struct _OVS_PORT_LIST_ENTRY OVS_PORT_LIST_ENTRY;

typedef struct _OVS_TUNNELING_PORT_OPTIONS OVS_TUNNELING_PORT_OPTIONS;
typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;

typedef struct _OVS_PERSISTENT_PORT
{
    //must be the first field in the struct
    OVS_REF_COUNT refCount;

    NDIS_RW_LOCK_EX* pRwLock;

    //port number assigned by OVS (userspace, or computed in driver)
    UINT16           ovsPortNumber;

    //port name assigned by OVS (userspace, or computed in driver)
    char*            ovsPortName;

    //OpenFlow / ovs port type
    OVS_OFPORT_TYPE  ofPortType;
    OVS_OFPORT_STATS stats;
    UINT32           upcallPortId;

    OVS_TUNNELING_PORT_OPTIONS*    pOptions;

    //NDIS_SWITCH_DEFAULT_PORT_ID (i.e. 0), if not connected
    NDIS_SWITCH_PORT_ID            portId;

    //if it's the external port of the switch or not
    BOOLEAN                        isExternal;
}OVS_PERSISTENT_PORT;

#define PORT_LOCK_READ(pPort, pLockState) NdisAcquireRWLockRead(pPort->pRwLock, pLockState, 0)
#define PORT_LOCK_WRITE(pPort, pLockState) NdisAcquireRWLockWrite(pPort->pRwLock, pLockState, 0)
#define PORT_UNLOCK(pPort, pLockState) NdisReleaseRWLock(pPort->pRwLock, pLockState)

typedef struct _OVS_LOGICAL_PORT_ENTRY {
    LIST_ENTRY listEntry;
    OVS_PERSISTENT_PORT* pPort;
}OVS_LOGICAL_PORT_ENTRY;

typedef struct _OVS_PERSISTENT_PORTS_INFO {
    NDIS_RW_LOCK_EX* pRwLock;

    OVS_PERSISTENT_PORT* portsArray[OVS_MAX_PORTS];
    UINT16 count;
    UINT16 firstPortFree;
}OVS_PERSISTENT_PORTS_INFO;

#define PERSPORTS_LOCK_READ(pPersPorts, pLockState) NdisAcquireRWLockRead((pPersPorts)->pRwLock, pLockState, 0)
#define PERSPORTS_LOCK_WRITE(pPersPorts, pLockState) NdisAcquireRWLockWrite((pPersPorts)->pRwLock, pLockState, 0)
#define PERSPORTS_UNLOCK(pPersPorts, pLockState) NdisReleaseRWLock((pPersPorts)->pRwLock, pLockState)

typedef struct _OF_PI_IPV4_TUNNEL OF_PI_IPV4_TUNNEL;

OVS_PERSISTENT_PORT* PersPort_Create_Ref(_In_opt_ const char* portName, _In_opt_ const UINT16* pPortNumber, OVS_OFPORT_TYPE portType);

BOOLEAN PersPort_CForEach_Unsafe(_In_ const OVS_PERSISTENT_PORTS_INFO* pPorts, VOID* pContext, BOOLEAN(*Action)(int, OVS_PERSISTENT_PORT*, VOID*));

OVS_PERSISTENT_PORT* PersPort_FindByName_Ref(const char* ofPortName);
OVS_PERSISTENT_PORT* PersPort_FindByNumber_Ref(UINT16 portNumber);

OVS_PERSISTENT_PORT* PersPort_FindById_Unsafe(NDIS_SWITCH_PORT_ID portId);
OVS_PERSISTENT_PORT* PersPort_FindById_Ref(NDIS_SWITCH_PORT_ID portId);

OVS_PERSISTENT_PORT* PersPort_GetInternal_Ref();
BOOLEAN PersPort_Delete(OVS_PERSISTENT_PORT* pPersPort);

_Ret_maybenull_
OVS_PERSISTENT_PORT* PersPort_FindExternal_Ref();

_Ret_maybenull_
OVS_PERSISTENT_PORT* PersPort_FindInternal_Ref();

_Ret_maybenull_
OVS_PERSISTENT_PORT* PersPort_FindGre_Ref(const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo);
_Ret_maybenull_
OVS_PERSISTENT_PORT* PersPort_FindVxlan_Ref(_In_ const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo);
_Ret_maybenull_
OVS_PERSISTENT_PORT* PersPort_FindVxlanByDestPort_Ref(LE16 udpDestPort);

BOOLEAN PersPort_Initialize();
VOID PersPort_Uninitialize();

BOOLEAN PersPort_HaveInternal_Unsafe();

VOID PersPort_DestroyNow_Unsafe(OVS_PERSISTENT_PORT* pPersPort);
