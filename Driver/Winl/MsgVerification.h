#pragma once

#include "precomp.h"
#include "ArgumentType.h"

typedef struct _OVS_NLMSGHDR OVS_NLMSGHDR;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;

//calculates the size the group should have, based on the sizes of its args and the data and the data sizes of its args - it goes recursively
//OVS_CHECK-s that pGroup->size == expected size
//returns pGroup->size
UINT VerifyGroup_Size_Recursive(OVS_ARGUMENT_GROUP* pGroup);

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest);