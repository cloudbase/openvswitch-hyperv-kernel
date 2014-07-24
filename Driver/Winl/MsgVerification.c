#include "MsgVerification.h"

#include "Message.h"
#include "OFPort.h"
#include "ArgVerification.h"
#include "Nbls.h"

static BOOLEAN _VerifyFlowMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
    case OVS_MESSAGE_COMMAND_SET:
        //request / flow / NEW must have: key & packet actions. keymask is optional.
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_FLOW_PI_GROUP);
            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pArg->data, OVS_ARGTYPE_PI_ETH_TYPE))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have key argtype: 0x%x", OVS_ARGTYPE_PI_ETH_TYPE);

            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pArg->data, OVS_ARGTYPE_PI_ETH_ADDRESS))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have key argtype: 0x%x", OVS_ARGTYPE_PI_ETH_ADDRESS);

            OVS_CHECK(0);
            return FALSE;
        }

        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_ACTIONS_GROUP))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_FLOW_ACTIONS_GROUP);
            OVS_CHECK(0);
            return FALSE;
        }

        break;

    case OVS_MESSAGE_COMMAND_DELETE:
        //request / flow / DELETE - must have: key
        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_FLOW_PI_GROUP);
            OVS_CHECK(0);
            return FALSE;
        }

        break;

    case OVS_MESSAGE_COMMAND_GET:
        //request / flow / GET - must have: key
        if (!FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_FLOW_PI_GROUP))
        {
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_FLOW_PI_GROUP);
            OVS_CHECK(0);
            return FALSE;
        }
        break;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (cmd)
        {
        case OVS_MESSAGE_COMMAND_NEW:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_FLOW_PI_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_MASK_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

                //NOTE: set info cannot check here if the given packet info specify eth type / proto acc to set info
                //nor can check the masks.
            case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
                if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_CLEAR:
                if (!VerifyArg_Flow_Clear(pMainGroupArg))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_SET:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_FLOW_PI_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_MASK_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
                if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
                {
                    return FALSE;
                }
                break;

            case OVS_ARGTYPE_FLOW_CLEAR:
                if (!VerifyArg_Flow_Clear(pMainGroupArg))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd SET should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_DELETE:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_FLOW_PI_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd DELETE should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_GET:
            switch (argType)
            {
                //TODO: "Flow"??
            case OVS_ARGTYPE_FLOW_PI_GROUP:
                if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;

            default:
                DEBUGP_ARG(LOG_ERROR, "Flow cmd GET should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            break;

        case OVS_MESSAGE_COMMAND_DUMP:
            if (argType == OVS_ARGTYPE_FLOW_MASK_GROUP)
            {
                if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
                {
                    return FALSE;
                }
                break;
            }
            else
            {
                DEBUGP_ARG(LOG_ERROR, "Flow cmd DUMP should not have main argtype: 0x%x", argType);
                OVS_CHECK(0);
                return FALSE;
            }

            //request / flow / DUMP mustn't have any arg... perhaps it must have no arg...
            break;

        case OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE:
            DEBUGP_ARG(LOG_ERROR, "Flow should not have command EXECUTE!");
            OVS_CHECK(0);
            return FALSE;

        default:
            DEBUGP_ARG(LOG_ERROR, "Invalid flow request command: 0x%x", cmd);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyFlowMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    UNREFERENCED_PARAMETER(cmd);
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        //replies may have:
        /* Packet Actions
        Stats
        Tcp Flags
        Time Used
        */

        switch (argType)
        {
        case OVS_ARGTYPE_FLOW_ACTIONS_GROUP:
            if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ FALSE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_STATS:
            if (!VerifyArg_Flow_Stats(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_TCP_FLAGS:
            if (!VerifyArg_Flow_TcpFlags(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_TIME_USED:
            if (!VerifyArg_Flow_TimeUsed(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_PI_GROUP:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_FLOW_MASK_GROUP:
            if (!VerifyGroup_PacketInfo(/*mask*/ TRUE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "flow reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyArg_PacketBuffer(OVS_ARGUMENT* pPacketBufferArg)
{
    if (!VerifyNetBuffer(pPacketBufferArg->data, pPacketBufferArg->length))
    {
        DEBUGP_ARG(LOG_ERROR, "invalid packet buffer!");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPacketMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    if (cmd != OVS_MESSAGE_COMMAND_PACKET_UPCALL_EXECUTE)
    {
        DEBUGP_ARG(LOG_ERROR, "Packet request should have cmd = execute. Found cmd: 0x%x", cmd);
        OVS_CHECK(0);
        return FALSE;
    }

    //request / packet / exec must have: buffer, packet info, actions - all required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_PACKET_BUFFER);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_PACKET_BUFFER);
        OVS_CHECK(0);
        return FALSE;
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_PACKET_PI_GROUP);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_PACKET_PI_GROUP);
        OVS_CHECK(0);
        return FALSE;
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_PACKET_ACTIONS_GROUP);
    if (!pArg)
    {
        DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW does not have main argtype: 0x%x", OVS_ARGTYPE_PACKET_ACTIONS_GROUP);
        OVS_CHECK(0);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_PACKET_BUFFER:
            if (!_VerifyArg_PacketBuffer(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PACKET_PI_GROUP:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/TRUE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

            //NOTE: set info cannot check here if the given packet info-s specify eth type / proto acc to set info
            //nor can check the masks.
        case OVS_ARGTYPE_PACKET_ACTIONS_GROUP:
            if (!VerifyGroup_PacketActions(pMainGroupArg, /*request*/ TRUE))
            {
                return FALSE;
            }
            break;

        default:
            DEBUGP_ARG(LOG_ERROR, "Flow cmd NEW should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyArg_UserData(OVS_ARGUMENT* pUserDataArg)
{
    UNREFERENCED_PARAMETER(pUserDataArg);

    DEBUGP_ARG(LOG_LOUD, "don't know how to check packet / user data arg\n");

    return TRUE;
}

static BOOLEAN _VerifyPacketMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    //req: OVS_ARGTYPE_GROUP_PI
    //opt: OVS_ARGTYPE_PACKET_USERDATA
    //req: OVS_ARGTYPE_PACKET_BUFFER

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_ACTION:
    case OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS:
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for packet reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        if (!(argType == OVS_ARGTYPE_PACKET_PI_GROUP ||
            argType == OVS_ARGTYPE_PACKET_USERDATA ||
            argType == OVS_ARGTYPE_PACKET_BUFFER))
        {
            DEBUGP_ARG(LOG_ERROR, "reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }

        switch (argType)
        {
        case OVS_ARGTYPE_PACKET_PI_GROUP:
            if (!VerifyGroup_PacketInfo(/*mask*/ FALSE, /*request*/ FALSE, pMainGroupArg, /*check transport layer*/ TRUE, /*seek ip*/ TRUE))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PACKET_USERDATA:
            if (!_VerifyArg_UserData(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        case OVS_ARGTYPE_PACKET_BUFFER:
            if (!_VerifyArg_PacketBuffer(pMainGroupArg))
            {
                return FALSE;
            }
            break;

        default:
            OVS_CHECK(0);
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyDatapathMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
        //not allowed
        //DEBUGP_ARG(LOG_WARN, "Datapath command New: ignore!\n");
        break;

    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_GET:
        if (pMsg->pArgGroup->count > 1)
        {
            DEBUGP_ARG(LOG_ERROR, "Datapath request GET should have max 1 args. Found count: 0x%x", pMsg->pArgGroup->count);
            return FALSE;
        }
        else if (pMsg->pArgGroup->count == 1)
        {
            OVS_ARGUMENT* pArg = pMsg->pArgGroup->args;

            if (pArg->type != OVS_ARGTYPE_DATAPATH_NAME)
            {
                DEBUGP_ARG(LOG_ERROR, "Datapath request GET has 1 arg, and it's not datapath name. It is: 0x%x", pArg->type);
            }

            return TRUE;
        }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath request: 0x%x", cmd);
        return FALSE;
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _IsStringPrintableA(const char* str, UINT16 len)
{
    for (UINT16 i = 0; i < len; ++i)
    {
        if (str[i] == 0)
        {
            break;
        }

        //verify that all chars are printable chars
        if (!(str[i] >= 0x20 && str[i] <= 0x7e))
        {
            DEBUGP_ARG(LOG_ERROR, "name not printable: %s", str);
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN _VerifyDatapathMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    {
        OVS_ARGUMENT* pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_NAME);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "datapath reply does not have arg: name\n");
            OVS_CHECK(0);
            return FALSE;
        }

        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_DATAPATH_STATS);
        if (!pArg)
        {
            DEBUGP_ARG(LOG_ERROR, "datapath reply does not have arg: stats\n");
            OVS_CHECK(0);
            return FALSE;
        }
    }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        UINT argType = pMainGroupArg->type;

        if (!(argType == OVS_ARGTYPE_DATAPATH_NAME ||
            argType == OVS_ARGTYPE_DATAPATH_STATS))
        {
            DEBUGP_ARG(LOG_ERROR, "reply should not have main argtype: 0x%x", argType);
            OVS_CHECK(0);
            return FALSE;
        }

        switch (argType)
        {
        case OVS_ARGTYPE_DATAPATH_NAME:
        {
            const char* name = pMainGroupArg->data;
            if (!_IsStringPrintableA(name, pMainGroupArg->length))
            {
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_DATAPATH_STATS:
            break;

        default:
            OVS_CHECK(0);
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPortMessageRequest(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_NEW:
        //DEBUGP(LOG_WARN, "we don't verify args for request port new!\n");
        break;

    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    case OVS_MESSAGE_COMMAND_DELETE:
    {
        OVS_ARGUMENT* pNameArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);

        if (!pNameArg &&
            !FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER))
        {
            DEBUGP_ARG(LOG_ERROR, "Port request GET: could not find arg port name / number\n");
            return FALSE;
        }

        if (pNameArg)
        {
            if (!_IsStringPrintableA(pNameArg->data, pNameArg->length))
            {
                return FALSE;
            }
        }
    }
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for datapath request: 0x%x", cmd);
        return FALSE;
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _VerifyPortMessageReply(OVS_MESSAGE_COMMAND_TYPE cmd, _In_ OVS_MESSAGE* pMsg)
{
    OVS_ARGTYPE mainArgType = OVS_ARGTYPE_INVALID;

    switch (cmd)
    {
    case OVS_MESSAGE_COMMAND_DELETE:
    case OVS_MESSAGE_COMMAND_SET:
    case OVS_MESSAGE_COMMAND_GET:
    case OVS_MESSAGE_COMMAND_DUMP:
        DEBUGP_ARG(LOG_ERROR, "for reply we expect command = new; have: 0x%x", cmd);
        return FALSE;

    case OVS_MESSAGE_COMMAND_NEW:
        break;

    default:
        DEBUGP_ARG(LOG_ERROR, "invalid cmd for port reply: 0x%x", cmd);
        return FALSE;
    }

    for (UINT i = 0; i < pMsg->pArgGroup->count; ++i)
    {
        OVS_ARGUMENT* pMainGroupArg = pMsg->pArgGroup->args + i;
        OVS_ARGTYPE argType = pMainGroupArg->type;

        switch (argType)
        {
        case OVS_ARGTYPE_OFPORT_NAME:
        {
            const char* name = pMainGroupArg->data;
            for (UINT16 i = 0; i < pMainGroupArg->length; ++i)
            {
                if (name[i] == 0)
                {
                    break;
                }

                //verify that all chars are printable chars
                if (!(name[i] >= 0x20 && name[i] <= 0x7e))
                {
                    DEBUGP_ARG(LOG_ERROR, "reply should have name arg all printable chars: %s", name);
                    //OVS_CHECK(0);
                    return FALSE;
                }
            }
        }
            break;

        case OVS_ARGTYPE_OFPORT_NUMBER:
            break;

        case OVS_ARGTYPE_OFPORT_TYPE:
        {
            UINT16 portType = GET_ARG_DATA(pMainGroupArg, UINT16);
            switch (portType)
            {
            case OVS_OFPORT_TYPE_PHYSICAL:
            case OVS_OFPORT_TYPE_MANAG_OS:
            case OVS_OFPORT_TYPE_GRE:
            case OVS_OFPORT_TYPE_VXLAN:
                break;

            default:
                DEBUGP(LOG_ERROR, "invalid port type: %d\n", portType);
                return FALSE;
            }
        }
            break;

        case OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID:
            break;

        case OVS_ARGTYPE_OFPORT_STATS:
            break;

        case OVS_ARGTYPE_OFPORT_OPTIONS_GROUP:
        {
            OVS_ARGUMENT_GROUP* pGroup = pMainGroupArg->data;

            OVS_ARGUMENT* pArg = pGroup->args;

            if (pGroup->count != 1)
            {
                DEBUGP(LOG_ERROR, "expected port options count: 1; have: %d", pGroup->count);
                return FALSE;
            }

            if (pArg->type != OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT)
            {
                DEBUGP(LOG_ERROR, "invalid port option: %d; expected dest port = %d", pArg->type, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT);
                return FALSE;
            }
        }
            break;

        default:
            OVS_CHECK(0);
        }
    }

    mainArgType = MessageTargetTypeToArgType(pMsg->type);
    if (!VerifyArgumentGroup(pMsg->pArgGroup, mainArgType))
    {
        return FALSE;
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
        return FALSE;

    case OVS_MESSAGE_TARGET_FLOW:
    {
        OVS_MESSAGE* pFlowMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyFlowMessageRequest(pFlowMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyFlowMessageReply(pFlowMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_DATAPATH:
    {
        OVS_MESSAGE* pDatapathMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyDatapathMessageRequest(pDatapathMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyDatapathMessageReply(pDatapathMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_PORT:
    {
        OVS_MESSAGE* pPortMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyPortMessageRequest(pPortMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyPortMessageReply(pPortMsg->command, (OVS_MESSAGE*)pMsg);
        }
    }

    case OVS_MESSAGE_TARGET_PACKET:
    {
        OVS_MESSAGE* pPacketMsg = (OVS_MESSAGE*)pMsg;

        if (isRequest)
        {
            return _VerifyPacketMessageRequest(pPacketMsg->command, (OVS_MESSAGE*)pMsg);
        }
        else
        {
            return _VerifyPacketMessageReply(pPacketMsg->command, (OVS_MESSAGE*)pMsg);
        }
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
        return FALSE;
    }

    //verify: duplicates; required
}