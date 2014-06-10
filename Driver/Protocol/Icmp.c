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

#include "Icmp.h"
#include "Frame.h"

static void _HandleDestUnreachable(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_DEST_UNREACH* pMessage = (OVS_ICMP_MESSAGE_DEST_UNREACH*)pIcmpHeader;
    BYTE* buffer = (BYTE*)pMessage;
    UINT16 sourcePort = 0, destPort = 0;

    //0, 1, 4, 5: received from gateway
    //2, 3: received from host
    OVS_CHECK(pIcmpHeader->code >= 0 || pIcmpHeader->code <= 5);

    buffer += pMessage->ipv4Header.HeaderLength * sizeof(DWORD);
    sourcePort = RtlUshortByteSwap(*((UINT16*)buffer));
    buffer += sizeof(UINT16);

    destPort = RtlUshortByteSwap(*((UINT16*)buffer));

    DEBUGP(LOG_ERROR, "Destination ureachable for ip:\n");
    ReadIpv4ProtocolFrame(&pMessage->ipv4Header);
}

static void _HandleTimeExceeded(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_TIME_EXCEEDED* pMessage = (OVS_ICMP_MESSAGE_TIME_EXCEEDED*)pIcmpHeader;
    BYTE* buffer = (BYTE*)pMessage;
    UINT16 sourcePort = 0, destPort = 0;

    //0: gateway
    //1: host
    OVS_CHECK(pIcmpHeader->code == 0 || pIcmpHeader->code == 1);

    buffer += pMessage->ipv4Header.HeaderLength * sizeof(DWORD);
    sourcePort = RtlUshortByteSwap(*((UINT16*)buffer));
    buffer += sizeof(UINT16);

    destPort = RtlUshortByteSwap(*((UINT16*)buffer));
}

static void _HandleParameterProblem(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_PARAM_PROBLEM* pMessage = (OVS_ICMP_MESSAGE_PARAM_PROBLEM*)pIcmpHeader;
    BYTE* buffer = (BYTE*)pMessage;
    UINT16 sourcePort = 0, destPort = 0;

    //code 0 may be received from host or gateway
    OVS_CHECK(pIcmpHeader->code == 0 || pIcmpHeader->code == 1);

    buffer += pMessage->ipv4Header.HeaderLength * sizeof(DWORD);
    sourcePort = RtlUshortByteSwap(*((UINT16*)buffer));
    buffer += sizeof(UINT16);

    destPort = RtlUshortByteSwap(*((UINT16*)buffer));
}

static void _HandleRedirect(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_REDIRECT* pMessage = (OVS_ICMP_MESSAGE_REDIRECT*)pIcmpHeader;
    BYTE* buffer = (BYTE*)pMessage;
    UINT16 sourcePort = 0, destPort = 0;

    //0, 1, 2, 3: from gateway
    OVS_CHECK(pIcmpHeader->code >= 0 && pIcmpHeader->code <= 3);

    buffer += pMessage->ipv4Header.HeaderLength * sizeof(DWORD);
    sourcePort = RtlUshortByteSwap(*((UINT16*)buffer));
    buffer += sizeof(UINT16);

    destPort = RtlUshortByteSwap(*((UINT16*)buffer));
}

static void _HandleEcho(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_ECHO* pMessage = (OVS_ICMP_MESSAGE_ECHO*)pIcmpHeader;
    UNREFERENCED_PARAMETER(pMessage);

    DEBUGP_FRAMES(LOG_INFO, "echo: id=%d; seq=%d\n", RtlUshortByteSwap(pMessage->identifier), RtlUshortByteSwap(pMessage->sequenceNumber));

    //code 0: from gateway or host
    OVS_CHECK(pIcmpHeader->code == 0);
}

static void _HandleTimestamp(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    OVS_ICMP_MESSAGE_TIMESTAMP* pMessage = (OVS_ICMP_MESSAGE_TIMESTAMP*)pIcmpHeader;
    UNREFERENCED_PARAMETER(pMessage);

    //code 0 may be received from a gateway or a host.
    OVS_CHECK(pIcmpHeader->code == 0);
}

const char* ReadIcmp(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    UINT8 type = pIcmpHeader->type;
    UINT8 code = pIcmpHeader->code;

    OVS_CHECK(pIcmpHeader);

    if (type == 0)
    {
        OVS_CHECK(code == 0);
        _HandleEcho(pIcmpHeader);

        return "QUERY: echo / ping reply";
    }

    if (type == 3)
    {
        switch (code)
        {
        case 0: _HandleDestUnreachable(pIcmpHeader); return "ERROR: network unreachable (see sec 9.3)";
        case 1: _HandleDestUnreachable(pIcmpHeader); return "ERROR: host unreachable (see sec 9.3)";
        case 2: _HandleDestUnreachable(pIcmpHeader); return "ERROR: protocol unreachable";
        case 3: _HandleDestUnreachable(pIcmpHeader); return "ERROR: port unreachable (see sec 6.5)";
        case 4: _HandleDestUnreachable(pIcmpHeader); return "ERROR: fragmentation needed but DF is set (see sec 11.6)";
        case 5: _HandleDestUnreachable(pIcmpHeader); return "ERROR: source route failed (see sec 8.5)";

        case 6: return "ERROR: destination network unknown";
        case 7: return "ERROR: destination host unknown";
        case 8: return "ERROR: source host isolated (OBSOLETE)";
        case 9: return "ERROR: destination network administratively prohibited";
        case 10: return "ERROR: destination host administratively prohibited";
        case 11: return "ERROR: network unreachable for TOS (see sec 9.3)";
        case 12: return "ERROR: host unreachable for TOS (see sec 9.3)";
        case 13: return "ERROR: communication administratively prohibited by filtering";
        case 14: return "ERROR: host precedence violation";
        case 15: return "ERROR: precedence cutoff in effect ";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 4)
    {
        OVS_CHECK(code == 0);

        return "ERROR: source quench (elementary flow control. see sec 11.11) (obsolete)";
    }

    if (type == 5)
    {
        _HandleRedirect(pIcmpHeader);

        switch (code)
        {
        case 0: return "ERROR: redirect for network (see sec 9.5)";
        case 1: return "ERROR: redirect for host (see sec 9.5)";
        case 2: return "ERROR: redirect for TOS and network (see sec 9.5)";
        case 3: return "ERROR: redirect for TOS and host (see sec 9.5)";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 8)
    {
        OVS_CHECK(code == 0);

        _HandleEcho(pIcmpHeader);
        return "QUERY: echo / ping request (see ch 7)";
    }

    if (type == 9)
    {
        OVS_CHECK(code == 0);
        return "QUERY: router advertisement (see sec 9.6)";
    }

    if (type == 10)
    {
        OVS_CHECK(code == 0);
        return "QUERY: router solicitation (see sec 9.6)";
    }

    if (type == 11)
    {
        switch (code)
        {
        case 0: _HandleTimeExceeded(pIcmpHeader); return "ERROR: TTL == 0 during transit (see ch 8)";
        case 1: _HandleTimeExceeded(pIcmpHeader); return "ERROR: TTL == 0 during reassembly (see sec 11.5)";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 12)
    {
        switch (code)
        {
        case 0: _HandleParameterProblem(pIcmpHeader); return "ERROR: IP header bad (catchall error)";
        case 1: _HandleParameterProblem(pIcmpHeader); return "ERROR: required option missing";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 13)
    {
        OVS_CHECK(code == 0);

        _HandleTimestamp(pIcmpHeader);

        return "QUERY: timestamp request (see sec 6.4)";
    }

    if (type == 14)
    {
        OVS_CHECK(code == 0);

        _HandleTimestamp(pIcmpHeader);

        return "QUERY: timestamp reply (see sec 6.4)";
    }

    if (type == 15)
    {
        OVS_CHECK(code == 0);

        return "QUERY: information request (obsolete)";
    }

    if (type == 16)
    {
        OVS_CHECK(code == 0);

        return "QUERY: information reply (obsolete)";
    }

    if (type == 17)
    {
        OVS_CHECK(code == 0);

        return "QUERY: address mask request (see sec 6.3) (obsolete)";
    }

    if (type == 18)
    {
        OVS_CHECK(code == 0);

        return "QUERY: address mask reply (see sec 6.3)";
    }

    OVS_CHECK(0);

    return 0;
}

void DbgPrintIcmpHeader(_In_ const VOID* buffer)
{
    OVS_ICMP_HEADER* pIcmpHeader = (OVS_ICMP_HEADER*)buffer;

    BOOLEAN isQuery = FALSE;
    BOOLEAN isError = FALSE;

    if (pIcmpHeader->type == 0 ||
        pIcmpHeader->type >= 8 && pIcmpHeader->type <= 10 ||
        pIcmpHeader->type >= 13 && pIcmpHeader->type <= 18)
    {
        isQuery = TRUE;
    }

    if (pIcmpHeader->type >= 3 && pIcmpHeader->type <= 5 ||
        pIcmpHeader->type == 11 || pIcmpHeader->type == 12)
    {
        isError = TRUE;
    }

    OVS_CHECK(isQuery ^ isError);

    DEBUGP_FRAMES(LOG_INFO, "ICMP message: %s\n", ReadIcmp(pIcmpHeader));
}

BOOLEAN VerifyIcmpHeader(_In_ const BYTE* buffer, _Inout_ ULONG* pLength)
{
    UNREFERENCED_PARAMETER(pLength);

    //NOTE: there is too much to test about ICMP, also to include the length. so we don't do that test here.
    DbgPrintIcmpHeader(buffer);

    return TRUE;
}