#include "MsgVerification.h"

#include "Message.h"
#include "ArgVerification.h"

typedef enum
{
    OVS_MSG_REQUEST = 0,
    OVS_MSG_REPLY = 1
} OVS_MSG_KIND;

#define OVS_PARSE_ARGS(pGroup, args)                                    \
    OVS_ARGUMENT* args[OVS_ARGTYPE_MAX_COUNT];                    \
    \
    OVS_FOR_EACH_ARG((pGroup),                                        \
    \
    OVS_ARGUMENT** ppCurArg = args + ArgTypeToIndex(argType);    \
    OVS_CHECK(!*ppCurArg);                                            \
    *ppCurArg = pArg                                                \
    );

/*********************************** args allowed **********************************/

#define OVS_ARG_ALLOWED_MAX_ARGS 6

typedef struct _OVS_ARG_ALLOWED
{
    OVS_MESSAGE_COMMAND_TYPE cmd;
    int countArgs;
    OVS_ARGTYPE args[OVS_ARG_ALLOWED_MAX_ARGS];

}OVS_ARG_ALLOWED, *POVS_ARG_ALLOWED;

#define OVS_ARG_ALLOWED_ENTRIES 10

//REQUEST
#define OVS_ARGS_ALLOWED_FLOW_REQ_NEW_SET 4, { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FLOW_MASK_GROUP, OVS_ARGTYPE_FLOW_ACTIONS_GROUP, OVS_ARGTYPE_FLOW_CLEAR }
#define OVS_ARGS_ALLOWED_PORT_REQ_NEW_SET 5, { OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_TYPE, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, OVS_ARGTYPE_OFPORT_NUMBER,  \
OVS_ARGTYPE_OFPORT_OPTIONS_GROUP }

#define OVS_ARGS_ALLOWED_PORT_REQ_GET 2, {OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_NUMBER }
#define OVS_ARGS_ALLOWED_PORT_REQ_DELETE 2, {OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_NUMBER }
#define OVS_ARGS_ALLOWED_PACKET_REQ_EXEC 3, {OVS_ARGTYPE_PACKET_BUFFER, OVS_ARGTYPE_PACKET_PI_GROUP, OVS_ARGTYPE_PACKET_ACTIONS_GROUP }

//REPLY
#define OVS_ARGS_ALLOWED_FLOW_REPLY 6, { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FLOW_MASK_GROUP, OVS_ARGTYPE_FLOW_ACTIONS_GROUP, OVS_ARGTYPE_FLOW_STATS, \
OVS_ARGTYPE_FLOW_TIME_USED, OVS_ARGTYPE_FLOW_TCP_FLAGS }

#define OVS_ARGS_ALLOWED_PORT_REPLY 6, { OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_TYPE, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, OVS_ARGTYPE_OFPORT_NUMBER,  \
    OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, OVS_ARGTYPE_OFPORT_STATS }

#define OVS_ARGS_ALLOWED_PACKET_REPLY 3, { OVS_ARGTYPE_PACKET_PI_GROUP, OVS_ARGTYPE_PACKET_USERDATA, OVS_ARGTYPE_PACKET_BUFFER }
#define OVS_ARGS_ALLOWED_DATAPATH_REPLY 2, { OVS_ARGTYPE_DATAPATH_NAME, OVS_ARGTYPE_DATAPATH_STATS }

static const OVS_ARG_ALLOWED s_argsAllowed[2][OVS_GENL_TARGET_COUNT][OVS_ARG_ALLOWED_ENTRIES] =
{
    [OVS_MSG_REQUEST] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_ALLOWED_FLOW_REQ_NEW_SET },
            { OVS_MESSAGE_COMMAND_SET, OVS_ARGS_ALLOWED_FLOW_REQ_NEW_SET },
            { OVS_MESSAGE_COMMAND_GET, 1, { OVS_ARGTYPE_FLOW_PI_GROUP } },
            { OVS_MESSAGE_COMMAND_DELETE, 1, { OVS_ARGTYPE_FLOW_PI_GROUP } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 }/*or PI?*/, },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, 2, { OVS_ARGTYPE_DATAPATH_NAME, OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID } },
            { OVS_MESSAGE_COMMAND_SET, 3, { OVS_ARGTYPE_DATAPATH_NAME } },
            { OVS_MESSAGE_COMMAND_GET, 3, { OVS_ARGTYPE_DATAPATH_NAME } },
            { OVS_MESSAGE_COMMAND_DELETE, 3, { OVS_ARGTYPE_DATAPATH_NAME } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_ALLOWED_PORT_REQ_NEW_SET },
            { OVS_MESSAGE_COMMAND_SET, OVS_ARGS_ALLOWED_PORT_REQ_NEW_SET },
            { OVS_MESSAGE_COMMAND_GET, OVS_ARGS_ALLOWED_PORT_REQ_GET },
            { OVS_MESSAGE_COMMAND_DELETE, OVS_ARGS_ALLOWED_PORT_REQ_DELETE },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] =
        {
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE, OVS_ARGS_ALLOWED_PACKET_REQ_EXEC }
        },
    },

    [OVS_MSG_REPLY] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_ALLOWED_FLOW_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, OVS_ARGS_ALLOWED_FLOW_REPLY },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_ALLOWED_DATAPATH_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, OVS_ARGS_ALLOWED_DATAPATH_REPLY },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_ALLOWED_PORT_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] =
        {
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS, OVS_ARGS_ALLOWED_PACKET_REPLY },
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION, OVS_ARGS_ALLOWED_PACKET_REPLY }
        },
    },
};

static __inline BOOLEAN _ArgAllowed(OVS_MSG_KIND request, OVS_MESSAGE_TARGET_TYPE target, OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGTYPE argType)
{
    for (int i = 0; i < OVS_ARG_ALLOWED_ENTRIES; ++i)
    {
        const OVS_ARG_ALLOWED* pArgAllowed = &(s_argsAllowed[request][target][i]);

        if (pArgAllowed->cmd == cmd)
        {
            for (int j = 0; j < pArgAllowed->countArgs; ++j)
            {
                if (pArgAllowed->args[j] == argType)
                {
                    return TRUE;
                }
            }
        }
    }

    OVS_CHECK_RET(__UNEXPECTED__, FALSE);
}


/********************************* args required *******************************/

#define OVS_ARG_REQUIRED_MAX_ARGS 5

typedef struct _OVS_ARG_REQUIRED
{
    OVS_MESSAGE_COMMAND_TYPE cmd;
    int countArgs;
    OVS_ARGTYPE args[OVS_ARG_REQUIRED_MAX_ARGS];

}OVS_ARG_REQUIRED, *POVS_ARG_REQUIRED;

#define OVS_ARG_REQUIRED_ENTRIES 8

#define OVS_ARGS_REQUIRED_FLOW_REQ_NEW  2, { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FLOW_ACTIONS_GROUP }
#define OVS_ARGS_REQUIRED_FLOW_REQ_SET  2, { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FLOW_ACTIONS_GROUP }
#define OVS_ARGS_REQUIRED_PORT_REQ_NEW  3, { OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_TYPE, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID }
#define OVS_ARGS_REQUIRED_PACKET_REQ_EXEC  3, { OVS_ARGTYPE_PACKET_BUFFER, OVS_ARGTYPE_PACKET_PI_GROUP, OVS_ARGTYPE_PACKET_ACTIONS_GROUP }

#define OVS_ARGS_REQUIRED_FLOW_REPLY    3, { OVS_ARGTYPE_FLOW_PI_GROUP, OVS_ARGTYPE_FLOW_MASK_GROUP, OVS_ARGTYPE_FLOW_ACTIONS_GROUP }
#define OVS_ARGS_REQUIRED_PACKET_REPLY  2, { OVS_ARGTYPE_PACKET_PI_GROUP, OVS_ARGTYPE_PACKET_BUFFER }
#define OVS_ARGS_REQUIRED_DATAPATH_REPLY    2, { OVS_ARGTYPE_DATAPATH_NAME, OVS_ARGTYPE_DATAPATH_STATS }
#define OVS_ARGS_REQUIRED_PORT_REPLY    5, { OVS_ARGTYPE_OFPORT_NAME, OVS_ARGTYPE_OFPORT_NUMBER, OVS_ARGTYPE_OFPORT_TYPE, OVS_ARGTYPE_OFPORT_STATS, \
OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID }

static const OVS_ARG_REQUIRED s_argsRequired[2][OVS_GENL_TARGET_COUNT][OVS_ARG_REQUIRED_ENTRIES] =
{
    [OVS_MSG_REQUEST] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_REQUIRED_FLOW_REQ_NEW },
            { OVS_MESSAGE_COMMAND_SET, OVS_ARGS_REQUIRED_FLOW_REQ_SET },
            { OVS_MESSAGE_COMMAND_GET, 1, { OVS_ARGTYPE_FLOW_PI_GROUP } },
            { OVS_MESSAGE_COMMAND_DELETE, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 }, },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, 2, { OVS_ARGTYPE_DATAPATH_NAME, OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID } },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DELETE, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_REQUIRED_PORT_REQ_NEW },
            { OVS_MESSAGE_COMMAND_SET, 1, { OVS_ARGTYPE_OFPORT_NAME } },
            { OVS_MESSAGE_COMMAND_SET, 1, { OVS_ARGTYPE_OFPORT_NUMBER } },
            { OVS_MESSAGE_COMMAND_GET, 1, { OVS_ARGTYPE_OFPORT_NAME } },
            { OVS_MESSAGE_COMMAND_GET, 1, { OVS_ARGTYPE_OFPORT_NUMBER } },
            { OVS_MESSAGE_COMMAND_DELETE, 1, { OVS_ARGTYPE_OFPORT_NAME } },
            { OVS_MESSAGE_COMMAND_DELETE, 1, { OVS_ARGTYPE_OFPORT_NUMBER } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] =
        {
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE, OVS_ARGS_REQUIRED_PACKET_REQ_EXEC },
        }
    },

    [OVS_MSG_REPLY] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_REQUIRED_FLOW_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, OVS_ARGS_REQUIRED_FLOW_REPLY },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_REQUIRED_DATAPATH_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, OVS_ARGS_REQUIRED_DATAPATH_REPLY },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] =
        {
            { OVS_MESSAGE_COMMAND_NEW, OVS_ARGS_REQUIRED_PORT_REPLY },
            { OVS_MESSAGE_COMMAND_DELETE, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_SET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_GET, 0, { 0 } },
            { OVS_MESSAGE_COMMAND_DUMP, 0, { 0 } },
        },

        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] =
        {
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS, OVS_ARGS_REQUIRED_PACKET_REPLY },
            { OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION, OVS_ARGS_REQUIRED_PACKET_REPLY },
        },
    },
};

static __inline BOOLEAN _HaveAllRequiredArgs(OVS_MSG_KIND request, OVS_MESSAGE_TARGET_TYPE target, OVS_MESSAGE_COMMAND_TYPE cmd, OVS_ARGUMENT_GROUP* pArgGroup)
{
    BOOLEAN haveAll = FALSE;

    OVS_PARSE_ARGS(pArgGroup, args);

    for (int i = 0; i < OVS_ARG_ALLOWED_ENTRIES; ++i)
    {
        const OVS_ARG_REQUIRED* pArgRequired = &(s_argsRequired[request][target][i]);

        if (pArgRequired->cmd == cmd)
        {
            for (int j = 0; j < pArgRequired->countArgs; ++j)
            {
                haveAll = OVS_ARG_HAVE_IN_ARRAY(args, pArgRequired->args[j]);
                if (haveAll)
                {
                    return TRUE;
                }
                //we continue if not found for the case: "must have one arg of ..."
            }
        }
    }

    OVS_CHECK_RET(__UNEXPECTED__, FALSE);
}

/*************************** commands allowed **********************************/

#define OVS_GENL_REQUEST_DEFAULT_CMDS 5, {OVS_MESSAGE_COMMAND_NEW, OVS_MESSAGE_COMMAND_SET, OVS_MESSAGE_COMMAND_GET, OVS_MESSAGE_COMMAND_DELETE, OVS_MESSAGE_COMMAND_DUMP}
#define OVS_GENL_REPLY_DEFAULT_CMDS 4, {OVS_MESSAGE_COMMAND_NEW, OVS_MESSAGE_COMMAND_SET, OVS_MESSAGE_COMMAND_GET, OVS_MESSAGE_COMMAND_DELETE}

#define OVS_CMD_ALLOWED_MAX_CMDS    5

typedef struct _OVS_CMD_ALLOWED
{
    int count;
    OVS_ARGTYPE cmds[OVS_CMD_ALLOWED_MAX_CMDS];

}OVS_CMD_ALLOWED, *POVS_CMD_ALLOWED;

static const OVS_CMD_ALLOWED s_commandsAllowed[2][4] =
{
    [OVS_MSG_REQUEST] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] = { OVS_GENL_REQUEST_DEFAULT_CMDS },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] = { OVS_GENL_REQUEST_DEFAULT_CMDS },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] = { 1, { OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE } },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] = { OVS_GENL_REQUEST_DEFAULT_CMDS }
    },

    [OVS_MSG_REPLY] =
    {
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_FLOW)] = { OVS_GENL_REPLY_DEFAULT_CMDS },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_DATAPATH)] = { OVS_GENL_REPLY_DEFAULT_CMDS },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PACKET)] = { 2, { OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION, OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS } },
        [OVS_GENL_TARGET_TO_INDEX(OVS_MESSAGE_TARGET_PORT)] = { OVS_GENL_REPLY_DEFAULT_CMDS }
    },
};

static __inline BOOLEAN _CommandAllowed(OVS_MSG_KIND reqOrReply, OVS_MESSAGE_TARGET_TYPE target, OVS_MESSAGE_COMMAND_TYPE cmd)
{
    const OVS_CMD_ALLOWED* pCmdAllowed = &(s_commandsAllowed[reqOrReply][OVS_GENL_TARGET_TO_INDEX(target)]);

    for (int i = 0; i < pCmdAllowed->count; ++i)
    {
        if (cmd == pCmdAllowed->cmds[i])
        {
            return TRUE;
        }
    }

    OVS_CHECK_RET(__UNEXPECTED__, FALSE);
}

/*************************************************************/

static __inline OVS_VERIFY_OPTIONS _GetOptionsForArgGroup(OVS_ARGTYPE argType, OVS_MSG_KIND reqOrReply)
{
    OVS_VERIFY_OPTIONS options = 0;

    if (IsArgTypeGroup(argType))
    {
        switch (argType)
        {
        case OVS_ARGTYPE_FLOW_PI_GROUP:
            options = (OVS_VERIFY_OPTION_CHECK_TP_LAYER | OVS_VERIFY_OPTION_SEEK_IP);
            break;

        case OVS_ARGTYPE_FLOW_MASK_GROUP:
            options = (OVS_VERIFY_OPTION_ISMASK | OVS_VERIFY_OPTION_CHECK_TP_LAYER | OVS_VERIFY_OPTION_SEEK_IP);
            break;

        default:
            break;
        }
    }

    if (reqOrReply == OVS_MSG_REQUEST)
    {
        options |= OVS_VERIFY_OPTION_ISREQUEST;
    }

    return options;
}

UINT VerifyGroup_Size_Recursive(OVS_ARGUMENT_GROUP* pGroup)
{
    UINT expectedSize = 0;

    OVS_CHECK(pGroup);
    //group count can be zero, but in this case, group size must also be zero

    expectedSize = pGroup->count * OVS_ARGUMENT_HEADER_SIZE;

    for (UINT i = 0; i != pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;
        OVS_ARGTYPE argType = pArg->type;
        OVS_CHECK(pArg->data && pArg->length || !pArg->data && !pArg->length);

        if (IsArgTypeGroup(argType))
        {
            UINT groupSize;

            DEBUGP_ARG(LOG_INFO, "checking subgroup: ");
            DBGPRINT_ARGTYPE(LOG_INFO, pArg->type, "", i);

            groupSize = VerifyGroup_Size_Recursive(pArg->data);
            OVS_CHECK(pArg->length == groupSize + OVS_ARGUMENT_GROUP_HEADER_SIZE);
        }

        expectedSize += pArg->length;
    }

    OVS_CHECK(expectedSize == pGroup->groupSize);

    return pGroup->groupSize;
}

BOOLEAN _VerifyGroup_Duplicates(OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    UNREFERENCED_PARAMETER(groupType);

    if (0 == pGroup->count)
    {
        return TRUE;
    }

    for (UINT16 i = 0; i < pGroup->count - 1; ++i)
    {
        OVS_ARGUMENT* pArgL = pGroup->args + i;

        for (UINT16 j = i + 1; j < pGroup->count; ++j)
        {
            OVS_ARGUMENT* pArgR = pGroup->args + j;

            if (pArgL->type == pArgR->type)
            {
                //we allow multiple 'out to port' and 'set info' actions.
                //we do not allow other duplicate arguments.
                if (pArgL->type != OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT ||
                    pArgL->type == OVS_ARGTYPE_ACTION_SETINFO_GROUP)
                {
                    DEBUGP_ARG(LOG_ERROR, "found duplicate: arg type: 0x%x; group: 0x%x\n", pArgL->type, groupType);
                    OVS_CHECK_RET(__UNEXPECTED__, FALSE);
                }
            }
        }
    }

    return TRUE;
}

BOOLEAN _VerifyGroup_SizeAndDuplicates_Recursive(_In_ OVS_ARGUMENT_GROUP* pGroup, UINT groupType)
{
    OVS_CHECK(pGroup);

    VerifyGroup_Size_Recursive(pGroup);

    if (!_VerifyGroup_Duplicates(pGroup, groupType))
    {
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    for (UINT i = 0; i < pGroup->count; ++i)
    {
        OVS_ARGUMENT* pArg = pGroup->args + i;

        if (IsArgTypeGroup(pArg->type))
        {
            if (!_VerifyGroup_SizeAndDuplicates_Recursive(pArg->data, pArg->type))
            {
                OVS_CHECK_RET(__UNEXPECTED__, FALSE);
            }
        }
    }

    return TRUE;
}

static BOOLEAN _GenlVerifier(OVS_MESSAGE* pMsg, OVS_MSG_KIND reqOrReply)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    EXPECT(_CommandAllowed(reqOrReply, pMsg->type, pMsg->command));
    EXPECT(_HaveAllRequiredArgs(reqOrReply, pMsg->type, pMsg->command, pMsg->pArgGroup));

    OVS_FOR_EACH_ARG(pMsg->pArgGroup,
    {
        const OVS_ARG_VERIFY_INFO* pVerify = FindArgVerificationGroup(MessageTargetTypeToArgType(pMsg->type));
        OVS_VERIFY_OPTIONS options = _GetOptionsForArgGroup(argType, reqOrReply);

        if (!_ArgAllowed(reqOrReply, pMsg->type, pMsg->command, argType))
        {
            DEBUGP_ARG(LOG_ERROR, __FUNCTION__ " cmd 0x%x should not have main argtype: 0x%x", pMsg->command, argType);
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }

        if (!pVerify->f[ArgTypeToIndex(argType)](pArg, NULL, options))
        {
            OVS_CHECK_RET(__UNEXPECTED__, FALSE);
        }
    });

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!_VerifyGroup_SizeAndDuplicates_Recursive(pMsg->pArgGroup, mainArgType))
    {
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }

    return TRUE;
}

BOOLEAN VerifyMessage(_In_ const OVS_NLMSGHDR* pMsg, UINT isRequest)
{
    switch (pMsg->type)
    {
    case OVS_MESSAGE_TARGET_INVALID:
        DEBUGP_ARG(LOG_ERROR, "target type == invalid!");
        OVS_CHECK(0);
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);

    case OVS_MESSAGE_TARGET_DATAPATH:
    case OVS_MESSAGE_TARGET_FLOW:
    case OVS_MESSAGE_TARGET_PORT:
    case OVS_MESSAGE_TARGET_PACKET:
    {
        OVS_MESSAGE* pGenlMsg = (OVS_MESSAGE*)pMsg;

        _GenlVerifier(pGenlMsg, isRequest ? OVS_MSG_REQUEST : OVS_MSG_REPLY);
    }

    case OVS_MESSAGE_TARGET_CONTROL:
        //TODO add functionality for checking
        return TRUE;

    case OVS_MESSAGE_TARGET_DUMP_DONE:
        OVS_CHECK(!isRequest);
        OVS_CHECK(pMsg->length == sizeof(OVS_MESSAGE_DONE));
        return TRUE;

    case OVS_MESSAGE_TARGET_ERROR:
        OVS_CHECK(!isRequest);
        OVS_CHECK(pMsg->length == sizeof(OVS_MESSAGE_ERROR));
        return TRUE;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid target type: 0x%x", pMsg->type);
        OVS_CHECK(0);
        OVS_CHECK_RET(__UNEXPECTED__, FALSE);
    }
}