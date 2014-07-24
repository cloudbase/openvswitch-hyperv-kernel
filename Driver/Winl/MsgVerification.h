#pragma once

#include "precomp.h"
#include "ArgumentType.h"

typedef struct _OVS_NLMSGHDR OVS_NLMSGHDR;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;

//calculates the size the group should have, based on the sizes of its args and the data and the data sizes of its args - it goes recursively
//OVS_CHECK-s that pGroup->size == expected size
//returns pGroup->size
UINT VerifyArgGroupSize(OVS_ARGUMENT_GROUP* pGroup);

BOOLEAN VerifyArgumentGroup(_In_ OVS_ARGUMENT_GROUP* pArgs, OVS_ARGTYPE groupType);

BOOLEAN VerifyArgNoDuplicates(OVS_ARGUMENT_GROUP* pGroup, OVS_ARGTYPE groupType);

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest);