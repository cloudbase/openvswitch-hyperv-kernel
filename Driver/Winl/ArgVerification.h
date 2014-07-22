#pragma once

#include "precomp.h"
#include "Argument.h"

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