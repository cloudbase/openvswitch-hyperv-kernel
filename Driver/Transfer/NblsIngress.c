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
#include "NblsIngress.h"
#include "SendIngressBasic.h"
#include "Sctx_Nic.h"
#include "SwitchContext.h"
#include "Gre.h"
#include "Vxlan.h"
#include "Nbls.h"
#include "OFFlow.h"
#include "OvsNetBuffer.h"
#include "OFPort.h"
#include "OFDatapath.h"
#include "WinlPacket.h"
#include "OFAction.h"
#include "PacketInfo.h"
#include "Upcall.h"
#include "Message.h"
#include "OFPort.h"
#include "Encapsulator.h"
#include "NormalTransfer.h"
#include "PersistentPort.h"
#include "OFFlowTable.h"
#include "Checksum.h"

static BOOLEAN _GetSourceInfo(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _In_ NET_BUFFER_LIST* pNetBufferLists, _Out_ OVS_NIC_INFO* pSourceInfo,
    _Inout_ OVS_NBL_FAIL_REASON* failReason)
{
    NDIS_SWITCH_PORT_ID sourcePort = 0;
    NDIS_SWITCH_NIC_INDEX sourceIndex = 0;
    OVS_NIC_LIST_ENTRY* pSourceNicEntry = NULL;
    NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO* pForwardDetail = NULL;
    BOOLEAN ok = TRUE;
    LOCK_STATE_EX lockState = { 0 };

    OVS_CHECK(pSourceInfo);
    RtlZeroMemory(pSourceInfo, sizeof(OVS_NIC_INFO));

    pForwardDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNetBufferLists);
    sourcePort = pForwardDetail->SourcePortId;
    sourceIndex = (NDIS_SWITCH_NIC_INDEX)pForwardDetail->SourceNicIndex;

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    pSourceNicEntry = Sctx_FindNicByPortIdAndNicIndex_Unsafe(pForwardInfo, sourcePort, sourceIndex);

    //FAIL CASE 2: low resources (guessed)
    if (pSourceNicEntry == NULL)
    {
        *failReason = OVS_NBL_FAIL_SOURCE_NIC_NOT_FOUND;
        DEBUGP(LOG_ERROR, "GetSourceInfo failed: %s\n", FailReasonMessageA(*failReason));

        ok = FALSE;
        goto Cleanup;
    }

    if (pSourceNicEntry)
    {
        NicListEntry_To_NicInfo(pSourceNicEntry, pSourceInfo);
    }

    pSourceInfo->nicIndex = sourceIndex;
    pSourceInfo->portId = sourcePort;

Cleanup:
	FWDINFO_UNLOCK(pForwardInfo, &lockState);
    return ok;
}

static BOOLEAN _GetExternalDestinationInfo_Unsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_SWITCH_PORT_ID sourcePort, _Inout_ OVS_NIC_INFO* pCurDestination,
    _Inout_ OVS_NBL_FAIL_REASON* pFailReason)
{
    //FAIL CASE: No external
    if (!pForwardInfo->pExternalNic)
    {
        *pFailReason = OVS_NBL_FAIL_NO_EXTERNAL_PORT;
        return FALSE;
    }

    OVS_CHECK(pForwardInfo->pExternalNic);
    OVS_CHECK(pForwardInfo->pExternalNic->portId != NDIS_SWITCH_DEFAULT_PORT_ID);

    //FAIL CASE: if source is external. (and was not found in FindNicByMacAddress)
    if (sourcePort == pForwardInfo->pExternalNic->portId)
    {
        *pFailReason = OVS_NBL_FAIL_DESTINATION_IS_SOURCE;
        return FALSE;
    }

    NicListEntry_To_NicInfo(pForwardInfo->pExternalNic, pCurDestination);

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN GetExternalDestinationInfo(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NDIS_SWITCH_PORT_ID sourcePort, OVS_NIC_INFO* pCurDestination,
OVS_NBL_FAIL_REASON* pFailReason)
{
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN ok = TRUE;

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    ok = _GetExternalDestinationInfo_Unsafe(pForwardInfo, sourcePort, pCurDestination, pFailReason);

	FWDINFO_UNLOCK(pForwardInfo, &lockState);

    return ok;
}

_Use_decl_annotations_
BOOLEAN GetDestinationInfo(const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, const BYTE* pDestMac, NDIS_SWITCH_PORT_ID sourcePort,
OVS_NIC_INFO* pCurDestination, OVS_NBL_FAIL_REASON* pFailReason)
{
    OVS_NIC_LIST_ENTRY* pDestinationNicEntry = NULL;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN ok = TRUE;

    RtlZeroMemory(pCurDestination, sizeof(OVS_NIC_INFO));

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    pDestinationNicEntry = Sctx_FindNicByMacAddressUnsafe(pForwardInfo, pDestMac);

    // Not a VM or host, send to external.
    if (pDestinationNicEntry == NULL)
    {
        ok = _GetExternalDestinationInfo_Unsafe(pForwardInfo, sourcePort, pCurDestination, pFailReason);
        if (!ok)
        {
            goto Cleanup;
        }
    }

    //vm or host, send to stored port & nic index.
    else if (pDestinationNicEntry->connected)
    {
        NicListEntry_To_NicInfo(pDestinationNicEntry, pCurDestination);
    }

    //FAIL CASE: destination nic not conected
    else
    {
        *pFailReason = OVS_NBL_FAIL_DESTINATION_NOT_CONNECTED;
        ok = FALSE;
        goto Cleanup;
    }

Cleanup:
	FWDINFO_UNLOCK(pForwardInfo, &lockState);
    return ok;
}

void DbgPrintMultipleDestinations(NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* broadcastArray)
{
    UINT idx = 0;
    NDIS_SWITCH_PORT_DESTINATION* pDestination = NULL;
    OVS_CHECK(broadcastArray);

    DEBUGP(LOG_INFO, "multiple destinations: %d\n", broadcastArray->NumElements);

    for (idx = 0; idx < broadcastArray->NumElements; ++idx)
    {
        pDestination = NDIS_SWITCH_PORT_DESTINATION_AT_ARRAY_INDEX(broadcastArray, idx);
        DEBUGP(LOG_INFO, "dest: port=%d; index=%d\n", pDestination->PortId, pDestination->NicIndex);
    }
}

_Use_decl_annotations_
NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* FindMultipleDestinations(const OVS_SWITCH_INFO* pSwitchInfo, UINT32 availableDestinations,
const OVS_NIC_INFO* pSourceInfo, NET_BUFFER_LIST* pNbl, OVS_NBL_FAIL_REASON* pFailReason, ULONG* pMtu, UINT* pCountAdded)
{
    UINT32 growNumber = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_SWITCH_FORWARDING_DESTINATION_ARRAY pBroadcastArray = NULL;
    const OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pSwitchInfo->pForwardInfo;
    //i.e. all ports minus the source port.
    UINT32 neededDestinations = 0;
    LOCK_STATE_EX lockState = { 0 };

    if (pForwardInfo->countNics == 0)
    {
        DEBUGP(LOG_INFO, "have no nics connected!\n");
        return NULL;
    }

    neededDestinations = pForwardInfo->countNics - 1;

    if (neededDestinations == 0)
    {
        DEBUGP(LOG_INFO, "no destinations to send packets to!\n");
        return NULL;
    }

    OVS_CHECK(pFailReason);
    OVS_CHECK(pMtu);

    if (availableDestinations < neededDestinations)
    {
        growNumber = (neededDestinations - availableDestinations);
        status = pSwitchInfo->switchHandlers.GrowNetBufferListDestinations(pSwitchInfo->switchContext, pNbl, growNumber, &pBroadcastArray);

        if (status != NDIS_STATUS_SUCCESS)
        {
            //FAIL CASE: cannot put sufficient destination ports into the NBL
            *pFailReason = OVS_NBL_FAIL_CANNOT_GROW_DEST;
            return NULL;
        }
    }

    else
    {
        pSwitchInfo->switchHandlers.GetNetBufferListDestinations(pSwitchInfo->switchContext, pNbl, &pBroadcastArray);
    }

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    //set destination ports for broadcasts in broadcastArray destination port lists.
    *pCountAdded = Sctx_MakeBroadcastArrayUnsafe(pForwardInfo, pBroadcastArray, pSourceInfo->portId, pSourceInfo->nicIndex, /*out*/ pMtu);

    OVS_CHECK(*pCountAdded <= neededDestinations);

	FWDINFO_UNLOCK(pForwardInfo, &lockState);

    return pBroadcastArray;
}

_Use_decl_annotations_
BOOLEAN SetOneDestination(const OVS_SWITCH_INFO* pSwitchInfo, NET_BUFFER_LIST* pNbl, OVS_NBL_FAIL_REASON* pFailReason, const OVS_NIC_INFO* pCurDestination)
{
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail = NULL;
    NDIS_STATUS status = STATUS_SUCCESS;
    NDIS_SWITCH_PORT_DESTINATION ndisPortDestination = { 0 };

    OVS_CHECK(pFailReason);
    OVS_CHECK(pCurDestination);
    *pFailReason = OVS_NBL_FAIL_SUCCESS;
    UNREFERENCED_PARAMETER(pFailReason);

    //what about NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP?
    //"sendFlags |= NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;"

    OVS_CHECK(pNbl);
    OVS_CHECK(NULL == NET_BUFFER_LIST_NEXT_NBL(pNbl));

    fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);

    OVS_CHECK(fwdDetail->NumAvailableDestinations > 0);

    ndisPortDestination.PortId = pCurDestination->portId;
    ndisPortDestination.NicIndex = pCurDestination->nicIndex;
    ndisPortDestination.PreserveVLAN = TRUE;
    ndisPortDestination.PreservePriority = TRUE;

    status = pSwitchInfo->switchHandlers.AddNetBufferListDestination(pSwitchInfo->switchContext, pNbl, &ndisPortDestination);
    OVS_CHECK(status == NDIS_STATUS_SUCCESS);

    return TRUE;
}

static void _LoopNbFrames(NET_BUFFER_LIST* pNbl)
{
    NET_BUFFER* pNb = NULL;

    for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        ReadProtocolFrame(pNb);
    }
}

VOID _ComputePacketsAndBytesSent(NET_BUFFER_LIST* pNbl, _Out_ ULONG* pBytesSent, _Out_ ULONG* pPacketsSent)
{
    ULONG bytesSent = 0, packetsSent = 0;

    for (NET_BUFFER* pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
    {
        ++packetsSent;
        bytesSent += NET_BUFFER_DATA_LENGTH(pNb);
    }

    *pBytesSent = bytesSent;
    *pPacketsSent = packetsSent;
}

static BOOLEAN _FragmentAndEncapsulateIpv4Packet(_In_ OVS_NET_BUFFER* pOvsNb, OVS_ENCAPSULATOR* pEncapsulator, OVS_OUTER_ENCAPSULATION_DATA* pEncapsData)
{
    NET_BUFFER_LIST* pFragmentedNbl = NULL;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO pFwdDetail = NULL;
    BOOLEAN ok = TRUE;
	//max ipv4 packet size (i.e. not including eth header), and not including the encapsulation bytes
	ULONG maxIpPacketSize = 0;
	//the amount of bytes to reserve, for encapsulation. For gre, it is: eth delivery + ipv4 delivery + gre + eth payload.
	ULONG dataOffset = 0;

	maxIpPacketSize = pEncapsData->mtu - pEncapsData->encapsHeadersSize;
	dataOffset = pEncapsData->encapsHeadersSize + sizeof(OVS_ETHERNET_HEADER);

	HandleChecksumOffload(pOvsNb, pEncapsData->isFromExternal, pEncapsData->encapsHeadersSize, pEncapsData->mtu);
	//TODO: we do not currently support fragmentation of LSO packets
	//NOTE that TCP packets should normally not be concerned with LSO because Tcp's MSS is being negociated
	OVS_CHECK(!NblIsLso(pOvsNb->pNbl));

	//This function will fragment the ipv4 packet, having dataOffset bytes as unused bytes in the beginning of the packet.
	pFragmentedNbl = ONB_FragmentBuffer_Ipv4(pOvsNb, maxIpPacketSize, pEncapsData->pPayloadEthHeader, dataOffset);
	if (!pFragmentedNbl)
	{
		return FALSE;
	}

    status = pOvsNb->pSwitchInfo->switchHandlers.CopyNetBufferListInfo(pOvsNb->pSwitchInfo->switchContext, pFragmentedNbl, pOvsNb->pNbl, 0);
    if (status != NDIS_STATUS_SUCCESS)
    {
        OVS_CHECK(0);
        return FALSE;
    }

    pFwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pFragmentedNbl);
    pFwdDetail->IsPacketDataSafe = TRUE;

    DbgPrintNblInfo(pFragmentedNbl);

    ONB_DestroyNbl(pOvsNb);
    pOvsNb->pNbl = pFragmentedNbl;

    //encapsulate the buffer
    ok = Encaps_EncapsulateOnb(pEncapsulator, pEncapsData);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, "encapsulation failed (mtu = new mtu). returning FALSE\n");
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN _OutputPacketToPort_Encaps(OVS_NET_BUFFER* pOvsNb)
{
    BOOLEAN ok = FALSE;
    OVS_NBL_FAIL_REASON failReason = { 0 };
    OVS_NIC_INFO externalNicInfo = { 0 };
    OVS_ETHERNET_HEADER* pOriginalEthHeader = NULL, payloadEthHeader = { 0 }, outerEthHeader = { 0 };
    ULONG nbLen = 0;
    OVS_ENCAPSULATOR encapsulator = { 0 };
    OVS_OUTER_ENCAPSULATION_DATA encapData = { 0 };
    OF_PI_IPV4_TUNNEL tunnelInfo = { 0 };
    LOCK_STATE_EX lockState = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pOvsNb->pSwitchInfo->pForwardInfo;
	BOOLEAN haveExternal = FALSE;

	FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    if (pForwardInfo->pExternalNic)
    {
        NicListEntry_To_NicInfo(pForwardInfo->pExternalNic, &externalNicInfo);
		haveExternal = TRUE;
    }

	FWDINFO_UNLOCK(pForwardInfo, &lockState);

	if (!haveExternal)
	{
        DEBUGP(LOG_ERROR, __FUNCTION__ " cannot out to prot encap because we have no port external!\n");
        return FALSE;
    }

    DEBUGP(LOG_LOUD, "Sending unicast to: nic index: %d; port id: %d; adap name: \"%s\"; vm name: \"%s\"\n",
        externalNicInfo.nicIndex, externalNicInfo.portId, externalNicInfo.nicName, externalNicInfo.vmName);

	PORT_LOCK_READ(pOvsNb->pDestinationPort, &lockState);

    if (pOvsNb->pDestinationPort->pOptions)
    {
        OVS_TUNNELING_PORT_OPTIONS* pPortOptions = pOvsNb->pDestinationPort->pOptions;

        OVS_CHECK(pPortOptions->optionsFlags != 0);

        UNREFERENCED_PARAMETER(pPortOptions);

        if (pOvsNb->pTunnelInfo)
        {
            tunnelInfo = *pOvsNb->pTunnelInfo;
        }

        pOvsNb->pTunnelInfo = &tunnelInfo;
    }

	PORT_UNLOCK(pOvsNb->pDestinationPort, &lockState);

    OVS_CHECK(pOvsNb->pTunnelInfo);

    ok = Encaps_ComputeOuterEthHeader(externalNicInfo.mac, (BYTE*)&pOvsNb->pTunnelInfo->ipv4Destination, &outerEthHeader);
    if (!ok)
    {
        return FALSE;
    }

    /*******************************/
    DbgPrintOnbFrames(pOvsNb, "before encaps");
    pOriginalEthHeader = ReadEthernetHeaderOnly(ONB_GetNetBuffer(pOvsNb));

    /* NVGRE:
    Inner 802.1Q tag: The inner Ethernet header of NVGRE MUST NOT
    contain 802.1Q Tag. The encapsulating NVE MUST remove any existing
    802.1Q Tag before encapsulation of the frame in NVGRE. A
    decapsulating NVE MUST drop the frame if the inner Ethernet frame
    contains an 802.1Q tag.
    */

    /* VXLAN:
    Decapsulated VXLAN frames with the inner VLAN tag SHOULD be
    discarded unless configured otherwise.  On the encapsulation side, a
    VTEP SHOULD NOT include an inner VLAN tag on tunnel packets unless
    configured otherwise.  When a VLAN-tagged packet is a candidate for
    VXLAN tunneling, the encapsulating VTEP SHOULD strip the VLAN tag
    unless configured otherwise.
    */

    if (RtlUshortByteSwap(pOriginalEthHeader->type) == OVS_ETHERTYPE_QTAG)
    {
        DEBUGP(LOG_ERROR, "payload eth header: expected vlan info to be removed!\n");
        return FALSE;
    }

    RtlCopyMemory(&payloadEthHeader, pOriginalEthHeader, sizeof(OVS_ETHERNET_HEADER));

    nbLen = ONB_GetDataLength(pOvsNb);
    OVS_CHECK(!pOvsNb->sendToPortNormal);

    if (pOvsNb->pDestinationPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        encapsulator.BuildEncapsulationHeader = Gre_BuildHeader;
        encapsulator.BytesNeeded = Gre_BytesNeeded;
        encapsulator.ComputeChecksum = Gre_ComputeChecksum;

        encapData.encapProtocol = OVS_IPPROTO_GRE;
    }

    else if (pOvsNb->pDestinationPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        OVS_TUNNELING_PORT_OPTIONS* pPortOptions = pOvsNb->pDestinationPort->pOptions;

        encapsulator.BuildEncapsulationHeader = Vxlan_BuildHeader;
        encapsulator.BytesNeeded = Vxlan_BytesNeeded;
        encapsulator.ComputeChecksum = NULL;

        encapData.encapProtocol = OVS_IPPROTO_UDP;

        OVS_CHECK(pPortOptions);

        if (!pPortOptions)
        {
            return FALSE;
        }

        if (!(pPortOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT))
        {
            pPortOptions->udpDestPort = OVS_VXLAN_UDP_PORT_DEFAULT;
            pPortOptions->optionsFlags |= OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT;
        }
    }

    else
    {
        DEBUGP(LOG_ERROR, "unknown encap port type: %d", pOvsNb->pDestinationPort->ofPortType);
        return FALSE;
    }

    encapData.mtu = externalNicInfo.mtu;
    encapData.pDeliveryEthHeader = &outerEthHeader;
    encapData.pPayloadEthHeader = &payloadEthHeader;
    encapData.pOvsNb = pOvsNb;
    encapData.isFromExternal = (pOvsNb->pSourceNic->portId == externalNicInfo.portId);
    encapData.encapsHeadersSize = encapsulator.BytesNeeded(pOvsNb->pTunnelInfo->tunnelFlags);

	//TODO: should we use the DF of the packet to see if we should fragment or not,
	//or use the tunnel info's flag DON'T FRAGMENT?

    //try to encapsulate. if it fails, and the cause is encaps_size + payload size > mtu:
    //		if ipv4:
    //			if DF is set: originate icmp4 "packet too big and DF is set"
    //			if DF is not set: fragment the buffer, and encapsulate each buffer
    //		if ipv6: originate icmp6 "Packet Too Big"
    if (nbLen + encapData.encapsHeadersSize <= encapData.mtu)
    {
        ok = Encaps_EncapsulateOnb(&encapsulator, &encapData);
    }

    else
    {
        if (nbLen + encapData.encapsHeadersSize > encapData.mtu)
        {
            //nblen = 1500; mtu = 1500; bytes required = (encap + payload) 1550
            //new mtu = 1500 - (1550 - 1500) = 1500 - 50 - 1450
            //if needed = 1536, mtu = 1500 => new mtu = 1500 - 36 = 1464
            // nbLen - (bytesRequired - mtu);//len - (len + encaps_size - mtu) = len - len - encaps_size + mtu = mtu - encaps_size
            ULONG newMtu = encapData.mtu - encapData.encapsHeadersSize;

            if (RtlUshortByteSwap(pOriginalEthHeader->type) == OVS_ETHERTYPE_IPV6)
            {
				ONB_OriginateIcmp6Packet_Type2Code0(pOvsNb, newMtu, pOvsNb->pSourceNic);

                DEBUGP(LOG_ERROR, "encapsulation failed. originated icmp error. now returning FALSE\n");
                return FALSE;
            }

            else if (RtlUshortByteSwap(pOriginalEthHeader->type) == OVS_ETHERTYPE_IPV4)
            {
                OVS_IPV4_HEADER* pIpv4Header = AdvanceEthernetHeader(pOriginalEthHeader, sizeof(OVS_ETHERNET_HEADER));

                if (pIpv4Header->DontFragment)
                {
					ONB_OriginateIcmpPacket_Ipv4_Type3Code4(pOvsNb, newMtu, pOvsNb->pSourceNic);

                    DEBUGP(LOG_ERROR, "encapsulation failed. originated icmp error. now returning FALSE\n");
                    return FALSE;
                }

                ok = _FragmentAndEncapsulateIpv4Packet(pOvsNb, &encapsulator, &encapData);
            }

            else
            {
                DEBUGP(LOG_ERROR, "encapsulation failed. returning FALSE\n");
                return FALSE;
            }
        }

        else
        {
            DEBUGP(LOG_ERROR, "encapsulation failed. returning FALSE\n");
            return FALSE;
        }
    }

    ok = SetOneDestination(pOvsNb->pSwitchInfo, pOvsNb->pNbl, &failReason, /*in*/ &externalNicInfo);
    if (!ok)
    {
        DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        return FALSE;
    }

    return ok;
}

static BOOLEAN _OutputPacketToPort_Normal(OVS_NET_BUFFER* pOvsNb)
{
    BOOLEAN isSrcExternal = FALSE;
    BOOLEAN isBroadcast = FALSE, isMulticast = FALSE;
    OVS_ETHERNET_HEADER* pEthHeader = ONB_GetDataOfSize(pOvsNb, sizeof(OVS_ETHERNET_HEADER));
    BOOLEAN ok = FALSE;
    LOCK_STATE_EX lockState = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pOvsNb->pSwitchInfo->pForwardInfo;

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    if (pForwardInfo->pExternalNic && pForwardInfo->pExternalNic->portId == pOvsNb->pSourceNic->portId)
    {
        /*If the source port is connected to the external network adapter, the non-extensible switch OOB data will be in a receive format.
        For other ports, this OOB data will be in a send format.*/
        isSrcExternal = FALSE;
    }

    else
    {
        isSrcExternal = TRUE;
    }

    FWDINFO_UNLOCK(pForwardInfo, &lockState);

    isBroadcast = ETH_IS_BROADCAST(pEthHeader->destination_addr);
    isMulticast = ETH_IS_MULTICAST(pEthHeader->destination_addr);

    if (isBroadcast || isMulticast)
    {
        DEBUGP(LOG_LOUD, "Sending %s", isMulticast ? "multicast\n" : "broadcast\n");

        ok = ProcessPacket_Normal_SendMulticast(pOvsNb);
    }

    else
    {
        ok = ProcessPacket_Normal_SendUnicast(pOvsNb, pEthHeader->destination_addr);
    }

    return ok;
}

//physical = specific
static BOOLEAN _OutputPacketToPort_Physical(OVS_NET_BUFFER* pOvsNb)
{
    OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    LOCK_STATE_EX lockState = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pOvsNb->pSwitchInfo->pForwardInfo;
    ULONG bytesSent = 0;
    BOOLEAN ok = TRUE;

    bytesSent = ONB_GetDataLength(pOvsNb);

    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

	//we don't need to lock pDestinationPort, because its field, portId, never changed
	pNicEntry = Sctx_FindNicByPortId_Unsafe(pForwardInfo, pOvsNb->pDestinationPort->portId);

    if (pNicEntry)
    {
        OVS_NIC_INFO nicInfo = { 0 };
        OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;

		//TODO: stats lock
        pOvsNb->pDestinationPort->stats.packetsSent++;
        pOvsNb->pDestinationPort->stats.bytesSent += bytesSent;

        NicListEntry_To_NicInfo(pNicEntry, &nicInfo);
        ok = SetOneDestination(pOvsNb->pSwitchInfo, pOvsNb->pNbl, &failReason, /*in*/ &nicInfo);
        if (!ok)
        {
            DEBUGP(LOG_ERROR, "set one destination failed. returning FALSE. Fail Reason:%s\n", FailReasonMessageA(failReason));
        }
    }

    else
    {
        DEBUGP(LOG_LOUD, "ovs port %s does not have a nic associated!\n", pOvsNb->pDestinationPort->ovsPortName);
        ok = FALSE;
    }

    FWDINFO_UNLOCK(pForwardInfo, &lockState);

    return ok;
}

_Use_decl_annotations_
BOOLEAN OutputPacketToPort(OVS_NET_BUFFER* pOvsNb)
{
    BOOLEAN ok = FALSE;
    OVS_DATAPATH* pDatapath = NULL;
    ULONG packetsSent = 0, bytesSent = 0;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);

    //NOTE: it is no longer used.
    //It used to be used when a dest port was not provided by the userspace
    //And the kernel was supposed to find a dest port -- the kernel taking the role of port type NORMAL
    if (pOvsNb->sendToPortNormal)
    {
        ok = _OutputPacketToPort_Normal(pOvsNb);
        goto Cleanup;
    }

    OVS_CHECK(pOvsNb->pDestinationPort);

    switch (pOvsNb->pDestinationPort->ofPortType)
    {
    case OVS_OFPORT_TYPE_GRE:
    {
        OVS_OFPORT_STATS* pPortStats = &pOvsNb->pDestinationPort->stats;
        ok = _OutputPacketToPort_Encaps(pOvsNb);

        if (ok)
        {
            _ComputePacketsAndBytesSent(pOvsNb->pNbl, &bytesSent, &packetsSent);

			//TODO: lock for stats
            pPortStats->packetsSent += packetsSent;
            pPortStats->bytesSent += bytesSent;
        }

        else
        {
            ++pPortStats->errorsOnSend;
        }
    }
        break;

    case OVS_OFPORT_TYPE_VXLAN:
    {
        OVS_OFPORT_STATS* pPortStats = &pOvsNb->pDestinationPort->stats;

        ok = _OutputPacketToPort_Encaps(pOvsNb);

        if (ok)
        {
            _ComputePacketsAndBytesSent(pOvsNb->pNbl, &bytesSent, &packetsSent);

			//TODO: lock for stats
            pPortStats->packetsSent += packetsSent;
            pPortStats->bytesSent += bytesSent;
        }

        else
        {
            ++pPortStats->errorsOnSend;
        }
    }
        break;

    case OVS_OFPORT_TYPE_MANAG_OS:
    case OVS_OFPORT_TYPE_PHYSICAL:
        ok = _OutputPacketToPort_Physical(pOvsNb);
        break;

    default:
        //or default is drop
        DEBUGP(LOG_ERROR, "unknown port type. returning FALSE!");
        OVS_CHECK(0);
    }

Cleanup:
	if (pDatapath)
	{
		OVS_REFCOUNT_DEREFERENCE(pDatapath);
	}

    if (ok)
    {
        Nbls_SendIngressBasic(pOvsNb->pSwitchInfo, pOvsNb->pNbl, pOvsNb->sendFlags, 1);
    }

    return ok;
}

/*	extract packet info / packet info from ONB
    find if the packet info matches any registered flow
    if no match is found:
    call QueuePacketToUserspace() - the userspace will decide what to do with it
    update datapath statistics
    return (testing / debugging purposes: output to port normal)
    if match is found:
    update flow time used
    execute flow actions on packet, and provide it with a function to the OutputToPort, to be able to send the packet
    update datapath statistics

    */
static BOOLEAN _ProcessPacket(OVS_NET_BUFFER* pOvsNb, _In_ const OVS_PERSISTENT_PORT* pSourcePort, const OF_PI_IPV4_TUNNEL* pTunnelInfo)
{
    OVS_OFPACKET_INFO packetInfo = { 0 };
    OVS_DATAPATH* pDatapath = NULL;
    OVS_FLOW* pFlow = NULL;
    BOOLEAN sent = FALSE;
    BOOLEAN dbgPrintPacket = FALSE;
    ULONG nbLen = 0;
    LOCK_STATE_EX lockState = { 0 };
    VOID* pNbBuffer = NULL;
    UINT16 ovsInPortNumber = OVS_INVALID_PORT_NUMBER;
	OVS_FLOW_TABLE* pFlowTable = NULL;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
	if (!pDatapath)
	{
		return FALSE;
	}

    //note: no need to set pOvsNb->pTunnelInfo because:
    //a) it's being reset to 0 at exec actions;
    //b) it's for 'set tunnel', not for 'received tunnel'
    //pOvsNb->pTunnelInfo = pTunnelInfo;

    pNbBuffer = ONB_GetData(pOvsNb);
    OVS_CHECK(pNbBuffer);
    nbLen = ONB_GetDataLength(pOvsNb);

    if (pSourcePort)
    {
        ovsInPortNumber = pSourcePort->ovsPortNumber;
    }

    if (!PacketInfo_Extract(pNbBuffer, nbLen, ovsInPortNumber, &packetInfo))
    {
        sent = FALSE;
		goto Cleanup;
    }

    //we do this after PacketInfo_Extract, because PacketInfo_Extract updates the ARP table
    if (!pSourcePort)
    {
        sent = FALSE;
		goto Cleanup;
    }

    nbLen = ONB_GetDataLength(pOvsNb);

    if (pTunnelInfo)
    {
        packetInfo.tunnelInfo = *pTunnelInfo;
    }

	//the pFlowTable will not be deleted by a different thread until we call deref.
	pFlowTable = Datapath_ReferenceFlowTable(pDatapath);
    pFlow = FlowTable_FindFlowMatchingMaskedPI_Ref(pDatapath->pFlowTable, &packetInfo);

    pOvsNb->pOriginalPacketInfo = &packetInfo;

    if (!pFlow)
    {
        OVS_UPCALL_INFO upcallInfo;
        upcallInfo.command = OVS_MESSAGE_COMMAND_PACKET_UPCALL_MISS;
        upcallInfo.pPacketInfo = &packetInfo;
        upcallInfo.pUserData = NULL;
        upcallInfo.portId = pSourcePort ? pSourcePort->upcallPortId : 0;

        //sendpacket to userspace only if the datapath has been 'created' (i.e. activated) from userspace
        //and we have a persistent port associated with the source NDIS_SWITCH_PORT_ID
        if (pDatapath->name && !pDatapath->deleted && pSourcePort)
        {
            QueuePacketToUserspace(pOvsNb->pNbl->FirstNetBuffer, &upcallInfo);
        }

        sent = FALSE;
        goto Cleanup;
    }

	//else -- if pFlow

	FLOW_LOCK_READ(pFlow, &lockState);

	pOvsNb->pActions = OVS_REFCOUNT_REFERENCE(pFlow->pActions);

	Flow_UpdateTimeUsed_Unsafe(pFlow, pOvsNb);

	FLOW_UNLOCK(pFlow, &lockState);

    if (dbgPrintPacket)
    {
        DbgPrintOnbFrames(pOvsNb, "found match (before processing): pNb");
    }

    pOvsNb->pTunnelInfo = NULL;

    sent = ExecuteActions(pOvsNb, OutputPacketToPort);

Cleanup:
    DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    if (pFlow)
    {
        ++pDatapath->statistics.flowTableMatches;

		//we don't use the pActions anymore
		//the actions are not modified, once set in a flow, so there's no need to lock the pFlow to dereference pActions
		OVS_REFCOUNT_DEREFERENCE(pOvsNb->pActions);
		pOvsNb->pActions = NULL;

		OVS_REFCOUNT_DEREFERENCE(pFlow);
    }

    else
    {
        ++pDatapath->statistics.flowTableMissed;
    }

	//we don't use the pFlowTable anymore.
	OVS_REFCOUNT_DEREFERENCE(pFlowTable);

    DATAPATH_UNLOCK(pDatapath, &lockState);

	OVS_REFCOUNT_DEREFERENCE(pDatapath);

    return sent;
}

static BOOLEAN _DecapsulateIfNeeded_Ref(_In_ const BYTE managOsMac[OVS_ETHERNET_ADDRESS_LENGTH],
	OVS_NET_BUFFER* pOvsNb, _Out_ OF_PI_IPV4_TUNNEL* pTunnelInfo, BOOLEAN* pWasEncapsulated, _Out_ OVS_PERSISTENT_PORT** ppPersPort)
{
    BOOLEAN ok = TRUE;
    const OVS_DECAPSULATOR* pDecapsulator = NULL;
    BYTE encapProtocolType = 0;
    LE16 udpDestPort = 0;

    OVS_CHECK(ppPersPort);
    OVS_CHECK(pWasEncapsulated);
    OVS_CHECK(pTunnelInfo);

    *pWasEncapsulated = FALSE;
    *ppPersPort = NULL;

    RtlZeroMemory(pTunnelInfo, sizeof(OF_PI_IPV4_TUNNEL));

    pDecapsulator = Encap_FindDecapsulator(ONB_GetNetBuffer(pOvsNb), &encapProtocolType, &udpDestPort);

    if (Encap_GetDecapsulator_Gre() == pDecapsulator)
    {
        OVS_PERSISTENT_PORT* pGrePort = NULL;

        *pWasEncapsulated = TRUE;
        ok = Encaps_DecapsulateOnb(pDecapsulator, pOvsNb, pTunnelInfo, encapProtocolType);

        pGrePort = PersPort_FindGre_Ref(NULL);
        if (pGrePort)
        {
            pGrePort->stats.packetsReceived++;
            pGrePort->stats.bytesReceived += ONB_GetDataLength(pOvsNb);
        }

        *ppPersPort = pGrePort;
    }

    else if (Encap_GetDecapsulator_Vxlan() == pDecapsulator)
    {
        OVS_PERSISTENT_PORT* pVxlanPort = NULL;

        *pWasEncapsulated = TRUE;
        ok = Encaps_DecapsulateOnb(pDecapsulator, pOvsNb, pTunnelInfo, encapProtocolType);

        pVxlanPort = PersPort_FindVxlanByDestPort_Ref(udpDestPort);

        if (pVxlanPort)
        {
            pVxlanPort->stats.packetsReceived++;
            pVxlanPort->stats.bytesReceived += ONB_GetDataLength(pOvsNb);
        }

        *ppPersPort = pVxlanPort;
    }

    else
    {
        OVS_PERSISTENT_PORT* pInternalPort = NULL;
        OVS_PERSISTENT_PORT* pExternalPort = NULL;
        OVS_ETHERNET_HEADER* pEthHeader = NULL;

        OVS_CHECK(!pDecapsulator);

        pInternalPort = PersPort_FindInternal_Ref();
        pExternalPort = PersPort_FindExternal_Ref();

        pEthHeader = (OVS_ETHERNET_HEADER*)ONB_GetDataOfSize(pOvsNb, sizeof(OVS_ETHERNET_HEADER));

		if (pInternalPort && pInternalPort->portId != NDIS_SWITCH_DEFAULT_PORT_ID)
        {
            //if the src eth addr = external nic (the internal nic has the same eth addr) => we say the src port is internal, so the destination may be external port
            //otherwise, we say the src is external, and the destination may be the internal port
			if (!memcmp(pEthHeader->source_addr, managOsMac, OVS_ETHERNET_ADDRESS_LENGTH))
            {
                ++pInternalPort->stats.packetsReceived;
                pInternalPort->stats.bytesReceived += ONB_GetDataLength(pOvsNb);

                *ppPersPort = pInternalPort;
				OVS_REFCOUNT_DEREFERENCE(pExternalPort);
            }

            else
            {
                *ppPersPort = pExternalPort;
				OVS_REFCOUNT_DEREFERENCE(pInternalPort);
            }
        }

        else
        {
            *ppPersPort = pExternalPort;
			OVS_REFCOUNT_DEREFERENCE(pInternalPort);
        }
    }

    return ok;
}

/* for each nbl in list:
        try to extract src info, if we don't have it; drop the nbl if fail
        find: isFromExternal?
        for each nb in nbl:
        create an OVS_NET_BUFFER from it
        if isFromExternal: decapsulate if needed
        call _ProcessPacket to process the OVS_NET_BUFFER

        drop all original packets

        NOTE: this function is in a READ lock on pForwardInfo->pRwLock
        NOTE: NDIS_RW_LOCK_EX-s can be locked recursively
        NOTE: do not hold a write lock for a long time!
        NOTE: you cannot promote the rw lock from read to write. i.e. while locked for read, DON'T lock for write!
        */
static VOID _ProcessAllNblsIngress(_In_ OVS_SWITCH_INFO* pSwitchInfo, _In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, NET_BUFFER_LIST* nbls, OVS_NIC_INFO* pSourceInfo,
    ULONG sendFlags, ULONG completeFlags)
{
    PNET_BUFFER_LIST pNbl = NULL;
    BOOLEAN mustTransfer = FALSE;
    OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;
    NET_BUFFER* pNb = NULL;
    BOOLEAN isFromExternal = FALSE;
    BOOLEAN isFromInternal = FALSE;
	BYTE managOsMac[OVS_ETHERNET_ADDRESS_LENGTH] = { 0 };

    UNREFERENCED_PARAMETER(sendFlags);

    OVS_CHECK(pForwardInfo);
    //NOTE: this function is called by NDIS callback, and therefore, nbls cannot be null.
    OVS_CHECK(nbls);

    //loop over each NBL in the list. put the the send buffers in the send list.
    //the drop buffers are dropped each when needed.
    //the mustSend ones are being linked (pPrev->Next = pNbl);
    DbgPrintNblCount(nbls);
    DEBUGP(LOG_LOUD, "original list:\n");
    DbgPrintNblList(nbls);

    //TODO:we could check the nblFlags of each nbl.
    for (pNbl = nbls; pNbl != NULL; pNbl = NET_BUFFER_LIST_NEXT_NBL(pNbl))
    {
		LOCK_STATE_EX lockState = { 0 };
        mustTransfer = TRUE;

        DEBUGP(LOG_LOUD, "current nbl: %p\n", pNbl);

        // A. Must have source info: check for allowed source if not single source for all NBLs
        // A.1. Fail case.
        if (!pSourceInfo && !_GetSourceInfo(pForwardInfo, pNbl, /*out*/ pSourceInfo, /*out*/ &failReason))
        {
            mustTransfer = FALSE;

            DEBUGP(LOG_ERROR, "ERROR: can't retrieve source info. Reason: %s. Dropping!\n", FailReasonMessageA(failReason));

            Nbls_DropOneIngress(pSwitchInfo, pNbl, pSourceInfo->portId, completeFlags, failReason);
            continue;
        }

        // A.2. Success case
        DEBUGP(LOG_LOUD, "source info: nic index=%d; port id=%d; nic name: \"%s\"; vm name: \"%s\"\n",
            pSourceInfo->nicIndex, pSourceInfo->portId,
            pSourceInfo->nicName, pSourceInfo->vmName);

		FWDINFO_LOCK_READ(pForwardInfo, &lockState);
        if (pForwardInfo->pExternalNic && pSourceInfo->portId == pForwardInfo->pExternalNic->portId)
        {
            /*If the source port is connected to the external network adapter, the non-extensible switch OOB data will be in a receive format.
            For other ports, this OOB data will be in a send format.*/
            isFromExternal = TRUE;
        }

        else
        {
            isFromExternal = FALSE;

			if (pForwardInfo->pInternalNic)
			{
				RtlCopyMemory(managOsMac, pForwardInfo->pInternalNic->macAddress, OVS_ETHERNET_ADDRESS_LENGTH);

				if (pSourceInfo->portId == pForwardInfo->pInternalNic->portId)
				{
					isFromInternal = TRUE;
				}
			}
        }

		FWDINFO_UNLOCK(pForwardInfo, &lockState);

        OVS_CHECK(mustTransfer);

        for (pNb = NET_BUFFER_LIST_FIRST_NB(pNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
        {
            ULONG additionalSize = max(Gre_BytesNeeded(0xFFFF), Vxlan_BytesNeeded(0xFFFF));
            OF_PI_IPV4_TUNNEL tunnelInfo = { 0 }, *pTunnelInfo = NULL;
            BOOLEAN wasEncapsulated = FALSE;
            OVS_PERSISTENT_PORT* pPersPort = NULL;

            OVS_NET_BUFFER* pOvsNb = ONB_CreateFromNbAndNbl(pSwitchInfo, pNbl, pNb, additionalSize);
            if (!pOvsNb)
            {
                break;
            }

            if (isFromExternal)
            {
                //if has gre / vxlan => decapsulates
				BOOLEAN ok = _DecapsulateIfNeeded_Ref(managOsMac, pOvsNb, &tunnelInfo, &wasEncapsulated, &pPersPort);
                if (!ok)
                {
					OVS_REFCOUNT_DEREFERENCE(pPersPort);

                    ONB_Destroy(pSwitchInfo, &pOvsNb);
                    continue;
                }

                if (wasEncapsulated)
                {
                    pTunnelInfo = &tunnelInfo;
                }
            }

            else
            {
				pPersPort = PersPort_FindById_Ref(pSourceInfo->portId);
            }

            pOvsNb->pSwitchInfo = pSwitchInfo;
            pOvsNb->pDestinationPort = NULL;
            pOvsNb->sendToPortNormal = FALSE;
            pOvsNb->pSourceNic = pSourceInfo;
            pOvsNb->sendFlags = sendFlags;
            pOvsNb->pSourcePort = pPersPort;

            if (!_ProcessPacket(pOvsNb, pPersPort, pTunnelInfo))
            {
                OVS_CHECK(pOvsNb->pNbl != pNbl);

                ONB_Destroy(pSwitchInfo, &pOvsNb);
            }

            else
            {
                OVS_CHECK(pOvsNb->pNbl != pNbl);

                ExFreePoolWithTag(pOvsNb, g_extAllocationTag);
            }

			OVS_REFCOUNT_DEREFERENCE(pPersPort);
        }
    }

	Nbls_DropAllIngress(pSwitchInfo, nbls, completeFlags, OVS_NBL_FAIL_SUCCESS);
}

//drops the packets if the switch is not running (or, switch extension?)
//retrieves the source info, if all packets are from the same source; if failure, it drops the packets
//calls _ProcessAllNblsIngress to actually process the packets
_Use_decl_annotations_
VOID Nbls_SendIngress(OVS_SWITCH_INFO* pSwitchInfo, NDIS_HANDLE extensionContext, NET_BUFFER_LIST* pNetBufferLists, ULONG sendFlags)
{
    ULONG completeFlags = CalcSendCompleteFlags(sendFlags);
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = (OVS_GLOBAL_FORWARD_INFO*)extensionContext;
    OVS_NIC_INFO sourceInfo = { 0 };
    OVS_NBL_FAIL_REASON failReason = OVS_NBL_FAIL_SUCCESS;
    OVS_NIC_INFO* pSourceInfo = NULL;

	OVS_CHECK(pSwitchInfo);

    //FIRST THINGS FIRST: if pSwitchInfo is not running, drop all
    if (pSwitchInfo->dataFlowState != OVS_SWITCH_RUNNING)
    {
        Nbls_DropAllIngress(pSwitchInfo, pNetBufferLists, completeFlags, OVS_NBL_FAIL_PAUSED);
        return;
    }

    //if single source & cannot get source info, drop all
    if (NDIS_TEST_SEND_FLAG(sendFlags, NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE))
    {
        if (!_GetSourceInfo(pForwardInfo, pNetBufferLists, &sourceInfo, &failReason))
        {
            Nbls_DropAllIngress(pSwitchInfo, pNetBufferLists, completeFlags, failReason);
            goto Cleanup;
        }

        pSourceInfo = &sourceInfo;
    }

    //some will be sent, others will be dropped. cloned NBLs will be sent and the original 'completed'.
    _ProcessAllNblsIngress(pSwitchInfo, pForwardInfo, pNetBufferLists, pSourceInfo, sendFlags, completeFlags);

Cleanup:
    return;
}

_Use_decl_annotations_
VOID Nbls_CompletedInjected(OVS_SWITCH_INFO* pSwitchInfo, ULONG numInjectedNetBufferLists)
{
    LONG subtract = -(LONG)numInjectedNetBufferLists;
    InterlockedAdd(&pSwitchInfo->pendingInjectedNblCount, subtract);
}