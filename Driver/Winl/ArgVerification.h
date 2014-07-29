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
    OVS_VERIFY_OPTION_ISREQUEST = 2,
    OVS_VERIFY_OPTION_CHECK_TP_LAYER = 4,
    OVS_VERIFY_OPTION_SEEK_IP = 8,
    OVS_VERIFY_OPTION_NEW_OR_SET = 16
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