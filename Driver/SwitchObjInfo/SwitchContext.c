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
#include "SwitchContext.h"
#include "OIDRequest.h"
#include "StatusIndication.h"
#include "Sctx_Nic.h"
#include "Sctx_Port.h"
#include "PersistentPort.h"
#include <Netioapi.h>

NDIS_STATUS _PortSupported(_In_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NDIS_SWITCH_PORT_ID portId)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS* pPortPropertyParameters = NULL;
    NDIS_SWITCH_PORT_PROPERTY_ENUM_INFO* pPortPropertyInfo = NULL;
    NDIS_SWITCH_PORT_PROPERTY_VLAN* pVlanProperty = NULL;

    //MAKE SURE VLAN IS ACCESS AND VLANID != 0

    status = pSwitchInfo->switchHandlers.ReferenceSwitchPort(pSwitchInfo->switchContext, portId);

    OVS_CHECK(status == NDIS_STATUS_SUCCESS);

    // Get VLAN Port property to ensure no VLAN set.
    status = OID_GetPortPropertyUnsafe(pSwitchInfo, portId, NdisSwitchPortPropertyTypeVlan, NULL, &pPortPropertyParameters);

    if (status != NDIS_STATUS_SUCCESS)
    {
        status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    pPortPropertyInfo = NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS_GET_FIRST_INFO(pPortPropertyParameters);

    // Should always get back v1 or later. It is safe to access the v1
    // version of the structure if newer property is retrieved.
    OVS_CHECK(pPortPropertyInfo->PropertyVersion >= NDIS_SWITCH_PORT_PROPERTY_VLAN_REVISION_1);

    pVlanProperty = NDIS_SWITCH_PORT_PROPERTY_ENUM_INFO_GET_PROPERTY(pPortPropertyInfo);

    // Real production code should support VLAN,
    // and not fail Switch_Restart.
    if (pVlanProperty->OperationMode != NdisSwitchPortVlanModeAccess || pVlanProperty->VlanProperties.AccessVlanId != 0)
    {
        OVS_CHECK(__NEVER_TRIED_THIS__);
    }

    status = pSwitchInfo->switchHandlers.DereferenceSwitchPort(pSwitchInfo->switchContext, portId);

    OVS_CHECK(status == NDIS_STATUS_SUCCESS);

Cleanup:
    if (pPortPropertyParameters)
    {
        ExFreePoolWithTag(pPortPropertyParameters, g_extAllocationTag);
    }

    return status;
}

NDIS_STATUS _NicSupported(_In_ OVS_SWITCH_INFO* pSwitchInfo, _In_ const NDIS_SWITCH_NIC_PARAMETERS* pCurNic)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    status = _PortSupported(pSwitchInfo, pCurNic->PortId);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    //HANDLE CASE: traffic flows through VF (must disable VF - packets will pass through the switch port instead). Read more here:
    //http://msdn.microsoft.com/en-us/library/windows/hardware/hh598215(v=vs.85).aspx
    //"VFAssigned: A BOOLEAN value that, if set to TRUE, specifies that the network adapter is attached to a PCI Express (PCIe) virtual function (VF).
    //A VF is exposed by an underlying physical network adapter that supports the single root I/O virtualization (SR-IOV) interface."

    // If a VF is assigned to a NIC, then the traffic flows through the VF and not the switch. This means we have to revoke the VF to enforce our policy.
    if (pCurNic->VFAssigned)
    {
        status = pSwitchInfo->switchHandlers.ReferenceSwitchNic(pSwitchInfo->switchContext, pCurNic->PortId, pCurNic->NicIndex);
        OVS_CHECK(status == NDIS_STATUS_SUCCESS);

        StatusIndic_IssueUnsafe(pSwitchInfo->filterHandle, NDIS_STATUS_SWITCH_PORT_REMOVE_VF, pCurNic->PortId, NDIS_SWITCH_DEFAULT_NIC_INDEX,
            /*is dest*/ TRUE, /*status buffer*/ NULL, /*status buffer len*/0);

        status = pSwitchInfo->switchHandlers.DereferenceSwitchNic(pSwitchInfo->switchContext, pCurNic->PortId, pCurNic->NicIndex);
        OVS_CHECK(status == NDIS_STATUS_SUCCESS);
    }

Cleanup:
    return status;
}

static NDIS_STATUS _InitializeNicList(_Inout_ OVS_SWITCH_INFO* pSwitchInfo)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    PNDIS_SWITCH_NIC_ARRAY nicArray = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pSwitchInfo->pForwardInfo;

    // Then it queries the NIC list
    // Now, get NIC list.
    status = OID_GetNicArrayUnsafe(pSwitchInfo, &nicArray);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    // and verifies it can support all of the NICs currently connected to the switch
    for (ULONG i = 0; i < nicArray->NumElements; ++i)
    {
        NDIS_SWITCH_NIC_PARAMETERS* pCurNic = NDIS_SWITCH_NIC_AT_ARRAY_INDEX(nicArray, i);

        status = _NicSupported(pSwitchInfo, pCurNic);

        if (status == NDIS_STATUS_SUCCESS)
        {
            OVS_NIC_LIST_ENTRY* pNicEntry = NULL;

            if (pCurNic->NicType == NdisSwitchNicTypeExternal &&
                pCurNic->NicIndex != NDIS_SWITCH_DEFAULT_NIC_INDEX && !pForwardInfo->pExternalNic)
            {
                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddNicUnsafe(pForwardInfo, pCurNic, &pNicEntry);

                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pNicEntry);
                    pForwardInfo->pExternalNic = pNicEntry;
                }
            }
            //NOTE: the internal port has nic index = 0
            else if (pCurNic->NicType == NdisSwitchNicTypeInternal && !pForwardInfo->pInternalNic)
            {
                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddNicUnsafe(pForwardInfo, pCurNic, &pNicEntry);

                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pNicEntry);
                    pForwardInfo->pInternalNic = pNicEntry;
                }
            }
            else if (pCurNic->NicType != NdisSwitchNicTypeExternal)
            {
                OVS_CHECK(pCurNic->NicType != NdisSwitchNicTypeInternal);

                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddNicUnsafe(pForwardInfo, pCurNic, &pNicEntry);
                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pNicEntry);
                }
            }

            if (pNicEntry)
            {
                OVS_CHECK(pNicEntry->pPersistentPort == NULL);

                ++(pForwardInfo->countNics);
            }
        }
        else
        {
            goto Cleanup;
        }
    }

Cleanup:
    if (nicArray != NULL)
    {
        ExFreePoolWithTag(nicArray, g_extAllocationTag);
    }

    return status;
}

static NDIS_STATUS _InitializePortList(_Inout_ OVS_SWITCH_INFO* pSwitchInfo)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    PNDIS_SWITCH_PORT_ARRAY portArray = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pSwitchInfo->pForwardInfo;

    // Then it queries the NIC list
    // Now, get NIC list.
    status = OID_GetPortArrayUnsafe(pSwitchInfo, &portArray);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    // and verifies it can support all of the NICs currently connected to the switch
    for (ULONG i = 0; i < portArray->NumElements; ++i)
    {
        NDIS_SWITCH_PORT_PARAMETERS* pCurPort = NDIS_SWITCH_PORT_AT_ARRAY_INDEX(portArray, i);

        status = _PortSupported(pSwitchInfo, pCurPort->PortId);

        if (status == NDIS_STATUS_SUCCESS)
        {
            OVS_PORT_LIST_ENTRY* pPortEntry = NULL;

            if (pCurPort->IsValidationPort)
            {
                continue;
            }

            if (pCurPort->PortType == NdisSwitchPortTypeExternal && !pForwardInfo->pExternalPort)
            {
                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddPort_Unsafe(pForwardInfo, pCurPort, &pPortEntry);

                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pPortEntry);
                    pForwardInfo->pExternalPort = pPortEntry;
                }
            }
            //NOTE: the internal port has nic index = 0
            else if (pCurPort->PortType == NdisSwitchPortTypeInternal && !pForwardInfo->pInternalPort)
            {
                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddPort_Unsafe(pForwardInfo, pCurPort, &pPortEntry);

                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pPortEntry);
                    pForwardInfo->pInternalPort = pPortEntry;
                }
            }
            else if (pCurPort->PortType != NdisSwitchPortTypeInternal &&
                pCurPort->PortType != NdisSwitchPortTypeExternal)
            {
                // and adds the NICs to the NIC list.
                // Now we've verified we can support the NIC, so check if there's a property for it, and add it to the NIC list.
                status = Sctx_AddPort_Unsafe(pForwardInfo, pCurPort, &pPortEntry);
                if (status == NDIS_STATUS_SUCCESS)
                {
                    OVS_CHECK(pPortEntry);
                }
            }

            if (pPortEntry)
            {
                OVS_CHECK(pPortEntry->pPersistentPort == NULL);

                pPortEntry->on = (pCurPort->PortState == NdisSwitchPortStateCreated);

                ++(pForwardInfo->countPorts);
            }
        }
        else
        {
            goto Cleanup;
        }
    }

Cleanup:
    if (portArray != NULL)
    {
        ExFreePoolWithTag(portArray, g_extAllocationTag);
    }

    return status;
}

NDIS_STATUS Sctx_InitSwitch(_Inout_ OVS_SWITCH_INFO* pSwitchInfo)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS* pSwitchPropertyParameters = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = pSwitchInfo->pForwardInfo;

    OVS_CHECK(!pForwardInfo->switchIsActive);

    status = _InitializeNicList(pSwitchInfo);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    status = _InitializePortList(pSwitchInfo);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    pForwardInfo->switchIsActive = TRUE;

Cleanup:
    if (pSwitchPropertyParameters != NULL)
    {
        ExFreePoolWithTag(pSwitchPropertyParameters, g_extAllocationTag);
    }

    return status;
}

static __inline VOID _AssertIsNew(_In_ const NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* broadcastArray, NDIS_SWITCH_PORT_ID portId, NDIS_SWITCH_NIC_INDEX nicIndex)
{
    UINT idx = 0;
    const NDIS_SWITCH_PORT_DESTINATION* pDestination = NULL;
    OVS_CHECK(broadcastArray);

    UNREFERENCED_PARAMETER(portId);

    for (idx = 0; idx < broadcastArray->NumElements; ++idx)
    {
        pDestination = NDIS_SWITCH_PORT_DESTINATION_AT_ARRAY_INDEX(broadcastArray, idx);

        OVS_CHECK(pDestination->PortId != portId);
        if (pDestination->NicIndex == nicIndex)
        {
            DEBUGP(LOG_WARN, "WARN: nic index prev = nic index current\n");
        }
    }
}

UINT Sctx_MakeBroadcastArrayUnsafe(_In_ const OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY* pBroadcastArray,
    _In_ NDIS_SWITCH_PORT_ID sourcePortId, _In_ NDIS_SWITCH_NIC_INDEX sourceNicIndex, _Out_ ULONG* pMtu)
{
    const LIST_ENTRY* pNicList = &pForwardInfo->nicList;
    const LIST_ENTRY* pCurEntry = pNicList->Flink;
    const OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
    UINT32 index = pBroadcastArray->NumDestinations;
    PNDIS_SWITCH_PORT_DESTINATION destination = NULL;
    ULONG minMtu = (ULONG)-1;
    UINT newDestinations = 0;

    OVS_CHECK(pMtu); *pMtu = 0;

    if (IsListEmpty(pNicList))
    {
        goto Cleanup;
    }

    do {
        pNicEntry = CONTAINING_RECORD(pCurEntry, OVS_NIC_LIST_ENTRY, listEntry);

        if (!pNicEntry->connected ||
            (sourcePortId == pNicEntry->portId && sourceNicIndex == pNicEntry->nicIndex))
        {
            if (pCurEntry->Flink == pNicList)
            {
                break;
            }
            else
            {
                pCurEntry = pCurEntry->Flink;
                continue;
            }
        }

        if (minMtu > pNicEntry->mtu)
        {
            minMtu = pNicEntry->mtu;
        }

        destination = NDIS_SWITCH_PORT_DESTINATION_AT_ARRAY_INDEX(pBroadcastArray, index);
        NdisZeroMemory(destination, sizeof(NDIS_SWITCH_PORT_DESTINATION));

        destination->PortId = pNicEntry->portId;
        destination->NicIndex = pNicEntry->nicIndex;

        DEBUGP(LOG_LOUD, "(multi_dest %d) set destination: port=%d; nic index=%d; nic name=\"%s\"; vm name=\"%s\"; type=%d (0=ext; 3=int)\n",
            index, pNicEntry->portId, pNicEntry->nicIndex, pNicEntry->adapName, pNicEntry->vmName, pNicEntry->nicType);

        ++index;
        ++newDestinations;
        pCurEntry = pCurEntry->Flink;
    } while (pCurEntry != pNicList);

    *pMtu = minMtu;

Cleanup:
    return newDestinations;
}