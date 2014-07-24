#pragma once

#include "precomp.h"

typedef struct _OVS_NLMSGHDR OVS_NLMSGHDR;

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest);