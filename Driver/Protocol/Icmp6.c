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

#include "Icmp6.h"

/* ICMPv6 messages are grouped into two classes: error messages and
   informational messages.  Error messages are identified as such by a
   zero in the high-order bit of their message Type field values.  Thus,
   error messages have message types from 0 to 127; informational
   messages have message types from 128 to 255.*/

const char* ReadIcmp6(_In_ OVS_ICMP_HEADER* pIcmpHeader)
{
    UINT8 type = pIcmpHeader->type;
    UINT8 code = pIcmpHeader->code;

    OVS_CHECK(pIcmpHeader);

    if (type == 1)
    {
        switch (code)
        {
        case 0: return "ERROR: No route to destination";
        case 1: return "ERROR: Communication with destination administratively prohibited";
        case 2: return "ERROR: Beyond scope of source address";
        case 3: return "ERROR: Address unreachable";
        case 4: return "ERROR: Port unreachable";
        case 5: return "ERROR: Source address failed ingress/egress policy";
        case 6: return "ERROR: Reject route to destination";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 2)
    {
        OVS_CHECK(code == 0);

        return "ERROR: Packet Too Big";
    }

    if (type == 3)
    {
        switch (code)
        {
        case 0: return "ERROR: Hop limit exceeded in transit";
        case 1: return "ERROR: Fragment reassembly time exceeded";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 4)
    {
        switch (code)
        {
        case 0: return "ERROR: Erroneous header field encountered";
        case 1: return "ERROR: Unrecognized Next Header type encountered";
        case 2: return "ERROR: Unrecognized IPv6 option encountered";
        default:
            OVS_CHECK(0);
        }
    }

    if (type == 128)
    {
        OVS_CHECK(code == 0);
        return "INFO: Echo Request";
    }

    if (type == 129)
    {
        OVS_CHECK(code == 0);
        return "INFO: Echo Reply";
    }

    /********************/

    if (type == 130)
    {
        OVS_CHECK(code == 0);
        return "Multicast Listener Query";
    }

    if (type == 131)
    {
        OVS_CHECK(code == 0);
        return "Multicast Listener Report";
    }
    if (type == 132)
    {
        OVS_CHECK(code == 0);
        return "Multicast Listener Done";
    }
    if (type == 133)
    {
        OVS_CHECK(code == 0);
        return "Router Solicitation";
    }
    if (type == 134)
    {
        OVS_CHECK(code == 0);
        return "Router Advertisement";
    }
    if (type == 135)
    {
        OVS_CHECK(code == 0);
        return "Neighbor Solicitation";
    }

    if (type == 136)
    {
        OVS_CHECK(code == 0);
        return "Neighbor Advertisement";
    }

    if (type == 137)
    {
        OVS_CHECK(code == 0);
        return "Redirect Message";
    }

    if (type == 138)
    {
        //Router Renumbering

        switch (code)
        {
        case 0: return "Router Renumbering Command";
        case 1: return "Router Renumbering Result";
        case 255: return "Sequence Number Reset";
        default: OVS_CHECK(0);
        }

        return "";
    }

    if (type == 139)
    {
        // ICMP Node Information Query
        switch (code)
        {
        case 0: return "The Data field contains an IPv6 address which is the Subject of this Query";
        case 1: return "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP";
        case 2: return "The Data field contains an IPv4 address which is the Subject of this Query";
        default: OVS_CHECK(0);
        }

        return "";
    }

    if (type == 140)
    {
        // ICMP Node Information Response
        switch (code)
        {
        case 0: return "A successful reply. The Reply Data field may or may not be empty";
        case 1: return "The Responder refuses to supply the answer. The Reply Data field will be empty";
        case 2: return "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty";
        default: OVS_CHECK(0);
        }

        return "";
    }

    if (type == 141)
    {
        OVS_CHECK(code == 0);
        return "Inverse Neighbor Discovery";
    }

    if (type == 142)
    {
        OVS_CHECK(code == 0);
        return "Inverse Neighbor Discovery2";
    }

    if (type == 143)
    {
        return "Version 2 Multicast Listener Report";
    }

    if (type == 144)
    {
        OVS_CHECK(code == 0);
        return "Home Agent Address Discovery";
    }

    if (type == 145)
    {
        OVS_CHECK(code == 0);
        return "Home Agent Address Discovery2";
    }

    if (type == 146)
    {
        OVS_CHECK(code == 0);
        return "Mobile Prefix Solicitation";
    }

    if (type == 147)
    {
        return "Mobile Prefix Advertisement";
    }

    OVS_CHECK(0);

    return 0;
}

void ReadIcmp6Header(VOID* buffer)
{
    OVS_ICMP_HEADER* pIcmpHeader = (OVS_ICMP_HEADER*)buffer;

    UNREFERENCED_PARAMETER(pIcmpHeader);
    DEBUGP_FRAMES(LOG_INFO, "ICMP6 message: %s\n", ReadIcmp6(pIcmpHeader));
}

BOOLEAN VerifyIcmp6Header(BYTE* buffer, ULONG* pLength)
{
    ReadIcmp6Header(buffer);

    UNREFERENCED_PARAMETER(pLength);

    return TRUE;
}