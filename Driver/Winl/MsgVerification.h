#pragma once

#include "precomp.h"

typedef struct _OVS_NLMSGHDR OVS_NLMSGHDR;
typedef struct _OVS_ARGUMENT_GROUP OVS_ARGUMENT_GROUP;

UINT VerifyGroup_Size_Recursive(OVS_ARGUMENT_GROUP* pGroup);

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest);