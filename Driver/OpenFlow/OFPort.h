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

#include "FixedSizedArray.h"

#define OVS_LOCAL_PORT_NUMBER            ((UINT32)0)
#define OVS_MAX_PORTS                    MAXUINT16
#define OVS_INVALID_PORT_NUMBER          OVS_MAX_PORTS

#define OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT    0x80

typedef struct _OVS_NIC_LIST_ENTRY OVS_NIC_LIST_ENTRY;
typedef struct _OVS_PORT_LIST_ENTRY OVS_PORT_LIST_ENTRY;

typedef struct _OVS_TUNNELING_PORT_OPTIONS OVS_TUNNELING_PORT_OPTIONS;
typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;

typedef enum
{
    OVS_OFPORT_TYPE_INVALID = 0,

    //a specific physical port, i.e. one that has a port id (vm port, external)
    OVS_OFPORT_TYPE_PHYSICAL = 1,
    //, internal / management OS
    OVS_OFPORT_TYPE_MANAG_OS = 2,
    //PORT type GRE
    OVS_OFPORT_TYPE_GRE = 3,
    //PORT type VXLAN
    OVS_OFPORT_TYPE_VXLAN = 4,

    //NOTE: not supported yet
    OVS_OFPORT_TYPE_GENEVE = 6,
    //same as GRE, except keys are 64-bit
    //NOTE: not supported yet
    OVS_OFPORT_TYPE_GRE64 = 104,
    //NOTE: not supported yet
    OVS_OFPORT_TYPE_LISP = 105,

    /********* NOTE: **********
    **        The of port types below are defined by the kernel only.
    **        Care must be taken for future versions, these port type codes not to collide with the userspace port type codes.
    **        Only the port type NORMAL is implemtented (and can be used, at choice), in kernel
    **************************/

    //reserved port: all physical except in port
    OVS_OFPORT_TYPE_ALL = 0x200,

    //send the packet back whence it came
    OVS_OFPORT_TYPE_IN = 0x201,

    //the traditional non-openflow pipeline of the switch
    OVS_OFPORT_TYPE_NORMAL = 0x202,

    //All physical ports in VLAN, except source /input port and those blocked or link down.
    OVS_OFPORT_TYPE_FLOOD = 0x203,
}OVS_OFPORT_TYPE;
C_ASSERT(sizeof(OVS_OFPORT_TYPE) == sizeof(UINT));

//NOTE: here it's OVS virtual port (OpenFlow port), not Hyper-V virtual port!
typedef struct _OVS_OFPORT_STATS
{
    UINT64   packetsReceived;
    UINT64   packetsSent;
    UINT64   bytesReceived;
    UINT64   bytesSent;
    UINT64   errorsOnReceive;
    UINT64   errorsOnSend;
    UINT64   droppedOnReceive;
    UINT64   droppedOnSend;
}OVS_OFPORT_STATS, *POVS_OFPORT_STATS;

typedef struct _OVS_UPCALL_PORT_IDS
{
    //TODO: we might need to use ref counting for this
    UINT count;
    UINT* ids;
}OVS_UPCALL_PORT_IDS, *POVS_UPCALL_PORT_IDS;

typedef struct _OVS_OFPORT
{
    OVS_FXARRAY_ITEM;

    //port number assigned by OVS (userspace, or computed in driver)
    UINT16           ofPortNumber;

    //port name assigned by OVS (userspace, or computed in driver)
    char*            ofPortName;

    //OpenFlow / datapath port type
    OVS_OFPORT_TYPE  ofPortType;
    OVS_OFPORT_STATS stats;

    OVS_UPCALL_PORT_IDS    upcallPortIds;

    OVS_TUNNELING_PORT_OPTIONS*    pOptions;

    //NDIS_SWITCH_DEFAULT_PORT_ID (i.e. 0), if not connected
    NDIS_SWITCH_PORT_ID            portId;
    NDIS_SWITCH_NIC_INDEX          nicIndex;

    //if it's the external port of the switch or not
    BOOLEAN                        isExternal;
}OVS_OFPORT;

#define PORT_LOCK_READ(pPort, pLockState) NdisAcquireRWLockRead(((OVS_FXARRAY_ITEM*)pPort)->pRwLock, pLockState, 0)
#define PORT_LOCK_WRITE(pPort, pLockState) NdisAcquireRWLockWrite(((OVS_FXARRAY_ITEM*)pPort)->pRwLock, pLockState, 0)
#define PORT_UNLOCK(pPort, pLockState) NdisReleaseRWLock(((OVS_FXARRAY_ITEM*)pPort)->pRwLock, pLockState)
#define PORT_UNLOCK_IF(pPort, pLockState, locked) { if ((locked) && (pPort)) PORT_UNLOCK((pPort), pLockState); }

typedef struct _OVS_TUNNELING_PORT_OPTIONS
{
    //OVS_TUNNEL_OPTIONS_HAVE_*
    DWORD   optionsFlags;

    //OVS_TUNNEL_PORT_FLAG_*
    BE32    tunnelFlags;
    BE32    destIpv4;
    BE32    sourceIpv4;
    BE64    outKey;
    BE64    inKey;
    UINT8   tos;
    UINT8   ttl;

    UINT16  udpDestPort;
}OVS_TUNNELING_PORT_OPTIONS;

typedef struct _OVS_LOGICAL_PORT_ENTRY
{
    LIST_ENTRY listEntry;
    OVS_OFPORT* pPort;
}OVS_LOGICAL_PORT_ENTRY;

typedef struct _OF_PI_IPV4_TUNNEL OF_PI_IPV4_TUNNEL;

/********************************************************************/

OVS_OFPORT* OFPort_Create_Ref(_In_opt_ const char* portName, _In_opt_ const UINT16* pPortNumber, OVS_OFPORT_TYPE portType);

OVS_OFPORT* OFPort_FindByName_Ref(const char* ofPortName);
OVS_OFPORT* OFPort_FindByNumber_Ref(UINT16 portNumber);

OVS_OFPORT* OFPort_FindById_Unsafe(NDIS_SWITCH_PORT_ID portId);
OVS_OFPORT* OFPort_FindById_Ref(NDIS_SWITCH_PORT_ID portId);

BOOLEAN OFPort_Delete(OVS_OFPORT* pOFPort);

_Ret_maybenull_
OVS_OFPORT* OFPort_FindExternal_Ref();

_Ret_maybenull_
OVS_OFPORT* OFPort_FindInternal_Ref();

_Ret_maybenull_
OVS_OFPORT* OFPort_FindGre_Ref();

_Ret_maybenull_
OVS_OFPORT* OFPort_FindVxlan_Ref(LE16 udpDestPort);

BOOLEAN OFPort_Initialize();
VOID OFPort_Uninitialize();

VOID OFPort_DestroyNow_Unsafe(OVS_OFPORT* pOFPort);
