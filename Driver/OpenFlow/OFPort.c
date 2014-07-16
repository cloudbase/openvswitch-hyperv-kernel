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

#include "OFPort.h"
#include "List.h"
#include "OFDatapath.h"

#include "WinlOFPort.h"
#include "OvsNetBuffer.h"
#include "Argument.h"
#include "Message.h"
#include "WinlFlow.h"
#include "ArgumentType.h"
#include "Gre.h"
#include "Vxlan.h"

BOOLEAN CreateMsgFromOFPort(OVS_WINL_PORT* pPort, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid)
{
    OVS_ARGUMENT* pArgPortName = NULL, *pArgPortType = NULL, *pArgPortNumber = NULL;
    OVS_ARGUMENT* pArgUpcallPid = NULL, *pArgPortSats = NULL, *pArgPortOpts = NULL;
    BOOLEAN ok = TRUE;
    UINT16 argsCount = 5;
    UINT16 argsSize = 0;

    OVS_CHECK(pMsg);

    RtlZeroMemory(pMsg, sizeof(OVS_MESSAGE));

    pMsg->length = sizeof(OVS_MESSAGE);
    pMsg->type = OVS_MESSAGE_TARGET_PORT;
    pMsg->flags = 0;
    pMsg->sequence = sequence;
    pMsg->pid = pid;

    pMsg->command = cmd;
    pMsg->version = 1;
    pMsg->reserved = 0;

    pMsg->dpIfIndex = dpIfIndex;

    //arg 1: port number
    pArgPortNumber = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_NUMBER, &pPort->number);
    if (!pArgPortNumber)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortNumber->length;

    //arg 2: port type
    pArgPortType = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_TYPE, &pPort->type);
    if (!pArgPortType)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortType->length;

    //arg 3: port name
    pArgPortName = CreateArgumentStringA_Alloc(OVS_ARGTYPE_OFPORT_NAME, pPort->name);
    if (!pArgPortName)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortName->length;

    //arg 4: port upcall pid
    pArgUpcallPid = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, &pPort->upcallId);
    if (!pArgUpcallPid)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgUpcallPid->length;
    //arg 5: port stats
    pArgPortSats = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_STATS, &pPort->stats);
    if (!pArgPortSats)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortSats->length;

    if (pPort->pOptions)
    {
        pArgPortOpts = CreateArgumentFromGroup(OVS_ARGTYPE_GROUP_OFPORT_OPTIONS, pPort->pOptions);
        if (!pArgPortOpts)
        {
            pArgPortOpts = NULL;
            return FALSE;
        }

        argsSize += pArgPortOpts->length;

        if (pArgPortOpts)
        {
            ++argsCount;
        }
    }

    pMsg->pArgGroup = AllocArgumentGroup();

    if (!pMsg->pArgGroup)
    {
        goto Cleanup;
    }

    AllocateArgumentsToGroup(argsCount, pMsg->pArgGroup);
    pMsg->pArgGroup->groupSize += argsSize;

    pMsg->pArgGroup->args[0] = *pArgPortNumber;
    pMsg->pArgGroup->args[1] = *pArgPortType;
    pMsg->pArgGroup->args[2] = *pArgPortName;
    pMsg->pArgGroup->args[3] = *pArgUpcallPid;
    pMsg->pArgGroup->args[4] = *pArgPortSats;

    if (argsCount == 6)
    {
        OVS_CHECK(pArgPortOpts);
        pMsg->pArgGroup->args[5] = *pArgPortOpts;
    }

Cleanup:
    if (ok)
    {
        KFree(pArgPortNumber);
        KFree(pArgPortType);
        KFree(pArgPortName);
        KFree(pArgUpcallPid);
        KFree(pArgPortSats);
        KFree(pArgPortOpts);

        return TRUE;
    }
    else
    {
        if (pArgPortNumber)
        {
            DestroyArgument(pArgPortNumber);
        }

        if (pArgPortType)
        {
            DestroyArgument(pArgPortType);
        }

        if (pArgPortName)
        {
            DestroyArgument(pArgPortName);
        }

        if (pArgUpcallPid)
        {
            DestroyArgument(pArgUpcallPid);
        }

        if (pArgPortSats)
        {
            DestroyArgument(pArgPortSats);
        }

        if (pArgPortOpts)
        {
            DestroyArgument(pArgPortOpts);
        }

        if (pMsg->pArgGroup)
        {
            FreeArguments(pMsg->pArgGroup);
            FreeArgGroup(pMsg->pArgGroup);
        }

        return FALSE;
    }
}