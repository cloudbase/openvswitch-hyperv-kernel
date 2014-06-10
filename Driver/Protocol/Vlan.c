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

#include "Vlan.h"
#include "OvsNetBuffer.h"

#include "OFAction.h"

//TODO: we must test VLANs from userspace, and see if the vlan is already popped by the switch (case in which we can pop it from here) or not
//NOTE: it is possible this function will not work. We might need to store the vlan tci & protocol as 'cached' in OVS_NET_BUFFER
//it is possible that the cached values (tci and protocol) are used in other parts in ovs, even if the vlan header itself was removed.
BOOLEAN Vlan_Pop(OVS_NET_BUFFER* pOvsNb)
{
    OVS_ETHERNET_HEADER* pEthHeader = NULL;

    OVS_CHECK(NULL == pOvsNb->pNbl->FirstNetBuffer->Next);

    pEthHeader = ONB_GetData(pOvsNb);

    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        BYTE* pUsedArea = (BYTE*)pEthHeader;

        RtlMoveMemory(pUsedArea + OVS_ETHERNET_VLAN_LEN, pUsedArea, 2 * OVS_ETHERNET_ADDRESS_LENGTH);

        ONB_Advance(pOvsNb, OVS_ETHERNET_VLAN_LEN);
    }

    else
    {
        return TRUE;
    }

    pEthHeader = ONB_GetData(pOvsNb);

    if (RtlUshortByteSwap(pEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        OVS_CHECK(__UNEXPECTED__);
        return FALSE;
    }

    return TRUE;
}

//TODO: we must test VLANs from userspace
//NOTE: it is possible this function will not work. We might need to store the vlan tci & protocol as 'cached' in OVS_NET_BUFFER
//it is possible that the cached values (tci and protocol) are used in other parts in ovs, even if the vlan header itself was removed.
BOOLEAN Vlan_Push(OVS_NET_BUFFER* pOvsNb, const OVS_ACTION_PUSH_VLAN* pVlan)
{
    OVS_CHECK(NULL == pOvsNb->pNbl->FirstNetBuffer->Next);
    OVS_ETHERNET_HEADER* pEthHeader = ONB_GetData(pOvsNb);

    //we add vlan header only if one was not added already.
    if (RtlUshortByteSwap(pEthHeader->type) != OVS_ETHERTYPE_QTAG)
    {
        BYTE* buffer = NULL;
        OVS_ETHERNET_HEADER_TAGGED* pEthHeaderTagged = NULL;
        ULONG unusedSpace = ONB_GetDataOffset(pOvsNb);
        NDIS_STATUS status = NDIS_STATUS_SUCCESS;

        buffer = (BYTE*)pEthHeader;

        if (unusedSpace < OVS_ETHERNET_VLAN_LEN)
        {
            return FALSE;
        }

        status = ONB_Retreat(pOvsNb, OVS_ETHERNET_VLAN_LEN);
        if (status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(LOG_ERROR, __FUNCTION__ "retreat failed!\n");
            return FALSE;
        }

        buffer = ONB_GetData(pOvsNb);
        pEthHeaderTagged = (OVS_ETHERNET_HEADER_TAGGED*)buffer;

        RtlMoveMemory(buffer, buffer + OVS_ETHERNET_VLAN_LEN, 2 * OVS_ETHERNET_ADDRESS_LENGTH);

        pEthHeaderTagged->type = pVlan->protocol;
        pEthHeaderTagged->tci = pVlan->vlanTci | RtlUshortByteSwap(OVS_VLAN_CFI_MASK);
    }

    else
    {
        DEBUGP(LOG_ERROR, "cannot push vlan: we already have a vlan header!\n");
    }

    return TRUE;
}