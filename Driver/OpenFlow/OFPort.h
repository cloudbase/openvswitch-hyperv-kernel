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
#include "OvsCore.h"

#define OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT    0x80

typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;
typedef struct _OVS_MESSAGE OVS_MESSAGE;

typedef enum {
    OVS_OFPORT_TYPE_INVALID = 0,

    //a specific physical port, i.e. one that has a port id (vm port, external)
    OVS_OFPORT_TYPE_PHYSICAL = 1,
    //, internal / management OS
    OVS_OFPORT_TYPE_MANAG_OS = 2,
    //PORT type GRE
    OVS_OFPORT_TYPE_GRE = 3,
    //PORT type VXLAN
    OVS_OFPORT_TYPE_VXLAN = 4,

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
typedef struct _OVS_OFPORT_STATS{
    UINT64   packetsReceived;
    UINT64   packetsSent;
    UINT64   bytesReceived;
    UINT64   bytesSent;
    UINT64   errorsOnReceive;
    UINT64   errorsOnSend;
    UINT64   droppedOnReceive;
    UINT64   droppedOnSend;
}OVS_OFPORT_STATS, *POVS_OFPORT_STATS;

typedef struct _OVS_WINL_PORT {
    UINT32            number;
    OVS_OFPORT_TYPE   type;
    const char*       name;
    //Used for userpace to kernel communication
    UINT32            upcallId;

    OVS_OFPORT_STATS  stats;

    //group type: OVS_ARGTYPE_OFPORT_GROUP
    //only available option is  OVS_ARGTYPE_PORT_OPTION_DST_PORT
    OVS_ARGUMENT_GROUP* pOptions;
}OVS_WINL_PORT, *POVS_WINL_PORT;

typedef struct _OVS_TUNNELING_PORT_OPTIONS {
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

/**********************************************************/
BOOLEAN CreateMsgFromOFPort(OVS_WINL_PORT* pOFPort, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid);