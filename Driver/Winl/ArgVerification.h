#pragma once

#include "precomp.h"
#include "Argument.h"

typedef struct _OVS_NLMSGHDR OVS_NLMSGHDR;

#define OVS_ARG_HAVE_IN_ARRAY(argArray, argType)    \
    (argArray[ArgTypeToIndex(argType)] != NULL)

static __inline BOOLEAN IsArgumentValid(_In_ OVS_ARGUMENT* pArg)
{
    OVS_CHECK(pArg);

    return (pArg->data && pArg->length || !pArg->data && !pArg->length);
}

typedef enum
{
    OVS_VERIFY_OPTION_ISMASK = 1,
    OVS_VERIFY_OPTION_ISREQUEST,
    OVS_VERIFY_OPTION_CHECK_TP_LAYER,
    OVS_VERIFY_OPTION_SEEK_IP,
    OVS_VERIFY_OPTION_NEW_OR_SET
};

typedef UINT OVS_VERIFY_OPTIONS;

typedef BOOLEAN(*Func)(OVS_ARGUMENT*, OVS_ARGUMENT*, OVS_VERIFY_OPTIONS);

typedef struct _OVS_ARG_VERIFY_INFO
{
    OVS_ARGTYPE parentArgType;
    OVS_ARGTYPE firstChildArgType;
    const Func* f;
}OVS_ARG_VERIFY_INFO, *POVS_ARG_VERIFY_INFO;

const OVS_ARG_VERIFY_INFO* FindArgVerificationGroup(OVS_ARGTYPE parentArgType);