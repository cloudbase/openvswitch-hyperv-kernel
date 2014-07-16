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

#include "precomp.h"
#include "Frame.h"
#include "Nbls.h"
#include "Gre.h"
#include "NdisFilter.h"
#include "Icmp.h"
#include "Arp.h"
#include "Gre.h"
#include "Tcp.h"
#include "Udp.h"
#include "Igmp.h"
#include "Ipv6.h"
#include "Icmp6.h"
#include "OvsNetBuffer.h"

VOID DbgPrintNbFrames(NET_BUFFER* pNb, const char* msg)
{
#if OVS_DBGPRINT_FRAMES
    VOID* buffer;
    OVS_ETHERNET_HEADER* pEthHeader;

    buffer = NdisGetDataBuffer(pNb, NET_BUFFER_DATA_LENGTH(pNb), NULL, 1, 0);
    pEthHeader = (OVS_ETHERNET_HEADER*)buffer;

    OVS_CHECK(buffer);

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        pEthHeader += OVS_ETHERNET_VLAN_LEN;
    }

    DEBUGP_FRAMES(LOG_INFO, "%s: nb frames: size=%d; eth type = 0x%x\n", msg, NET_BUFFER_DATA_LENGTH(pNb), RtlUshortByteSwap(pEthHeader->type));
    DbgPrintNb(pNb, msg);
    DbgPrintMac(pEthHeader);

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        const OVS_IPV4_HEADER* pIpv4Header = ReadIpv4Header(pEthHeader);

        ReadIpv4ProtocolFrame(pIpv4Header);
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        DEBUGP_FRAMES(LOG_INFO, "ipv6\n");
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_ARP))
    {
        OVS_ARP_HEADER* pArpHeader = NULL;

        pArpHeader = (OVS_ARP_HEADER*)((BYTE*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER));

        DEBUGP_FRAMES(LOG_INFO, "sending arp: op = %s, sender ip: %d.%d.%d.%d; sender mac: %02x-%02x-%02x-%02x-%02x-%02x; "
            "target ip:%d.%d.%d.%d; target mac: %02x-%02x-%02x-%02x-%02x-%02x\n ", RtlUshortByteSwap(pArpHeader->operation) == 1 ? "request" : "reply",

            pArpHeader->senderProtocolAddress[0], pArpHeader->senderProtocolAddress[1], pArpHeader->senderProtocolAddress[2], pArpHeader->senderProtocolAddress[3],
            pArpHeader->senderHardwareAddress[0], pArpHeader->senderHardwareAddress[1], pArpHeader->senderHardwareAddress[2],
            pArpHeader->senderHardwareAddress[3], pArpHeader->senderHardwareAddress[4], pArpHeader->senderHardwareAddress[5],

            pArpHeader->targetProtocolAddress[0], pArpHeader->targetProtocolAddress[1], pArpHeader->targetProtocolAddress[2], pArpHeader->targetProtocolAddress[3],
            pArpHeader->targetHardwareAddress[0], pArpHeader->targetHardwareAddress[1], pArpHeader->targetHardwareAddress[2],
            pArpHeader->targetHardwareAddress[3], pArpHeader->targetHardwareAddress[4], pArpHeader->targetHardwareAddress[5]);
    }
#else
    UNREFERENCED_PARAMETER(pNb);
    UNREFERENCED_PARAMETER(msg);
#endif
}

VOID DbgPrintOnbFrames(OVS_NET_BUFFER* pOvsNb, const char* msg)
{
#if OVS_DBGPRINT_FRAMES
    for (NET_BUFFER* pNb = NET_BUFFER_LIST_FIRST_NB(pOvsNb->pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        DbgPrintNbFrames(pNb, msg);
    }
#else
    UNREFERENCED_PARAMETER(pOvsNb);
    UNREFERENCED_PARAMETER(msg);
#endif
}

BOOLEAN ReadProtocolFrame(_In_ NET_BUFFER* pNb)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL;
    const OVS_IPV4_HEADER* pIpv4Header = NULL;
    void* pAllocBuffer = NULL;
    OVS_ARP_HEADER* pArpHeader = NULL;
    OVS_IPV6_HEADER* pIpv6Header = NULL;

    pEthHeader = ReadEthernetHeader_Alloc(pNb, &pAllocBuffer);
    if (!pEthHeader)
    {
        //TODO: what do we do if we could not alloc mem for eth header?
        //ATM simply send forward
        DEBUGP(LOG_ERROR, "Could not alloc mem for eth header. nb: %p\n", pNb);
        return FALSE;
    }

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_QTAG))
    {
        //advance ethernet header by QTag Prefix. pEthHeader->type will be pEthHeader->clientType from ethernet tagged struct.
        pEthHeader += OVS_ETHERNET_VLAN_LEN;
    }

    if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV4))
    {
        pIpv4Header = ReadIpv4Header(pEthHeader); //proto type: 1 = ICMP; 2 = IGMP; 6 = tcp; 0x11 = udp

        if (pIpv4Header->Protocol != OVS_IPPROTO_UDP)
        {
            DbgPrintMacMsg(pEthHeader, "NB");
            ReadIpv4ProtocolFrame(pIpv4Header);
        }
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_IPV6))
    {
        pIpv6Header = (OVS_IPV6_HEADER*)((UINT8*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER));

        //do nothing: it is not encapsulated, goes to the same ip dest
    }
    else if (pEthHeader->type == RtlUshortByteSwap(OVS_ETHERTYPE_ARP))
    {
        pArpHeader = (OVS_ARP_HEADER*)((BYTE*)(pEthHeader)+sizeof(OVS_ETHERNET_HEADER));

        DbgPrintArp(pArpHeader);
    }
    else
    {
        //must check all  protocol types.
        OVS_CHECK(0);
    }

    return TRUE;
}