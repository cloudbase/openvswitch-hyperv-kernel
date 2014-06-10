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
#include "StatusIndication.h"

_Use_decl_annotations_
VOID StatusIndic_IssueUnsafe(NDIS_HANDLE filterHandle, NDIS_STATUS statusCode, NDIS_SWITCH_PORT_ID portId,
NDIS_SWITCH_NIC_INDEX nicIndex, BOOLEAN isDestination, VOID* pStatusBuffer, ULONG statusBufferSize)
{
    NDIS_STATUS_INDICATION statusIndication;
    NDIS_STATUS_INDICATION wrappedIndication;
    NDIS_SWITCH_NIC_STATUS_INDICATION nicIndication;

    NdisZeroMemory(&wrappedIndication, sizeof(wrappedIndication));

    wrappedIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    wrappedIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    wrappedIndication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;

    wrappedIndication.SourceHandle = filterHandle;
    wrappedIndication.PortNumber = NDIS_DEFAULT_PORT_NUMBER;

    wrappedIndication.StatusCode = statusCode;
    wrappedIndication.StatusBuffer = pStatusBuffer;
    wrappedIndication.StatusBufferSize = statusBufferSize;

    NdisZeroMemory(&nicIndication, sizeof(nicIndication));

    nicIndication.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nicIndication.Header.Revision = NDIS_SWITCH_NIC_STATUS_INDICATION_REVISION_1;
    nicIndication.Header.Size = NDIS_SIZEOF_SWITCH_NIC_STATUS_REVISION_1;
    nicIndication.StatusIndication = &wrappedIndication;

    if (isDestination)
    {
        nicIndication.DestinationPortId = portId;
        nicIndication.DestinationNicIndex = nicIndex;
    }
    else
    {
        nicIndication.SourcePortId = portId;
        nicIndication.SourceNicIndex = nicIndex;
    }

    NdisZeroMemory(&statusIndication, sizeof(statusIndication));

    statusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    statusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    statusIndication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;

    statusIndication.SourceHandle = filterHandle;
    statusIndication.PortNumber = NDIS_DEFAULT_PORT_NUMBER;

    statusIndication.StatusCode = NDIS_STATUS_SWITCH_NIC_STATUS;
    statusIndication.StatusBuffer = &nicIndication;
    statusIndication.StatusBufferSize = sizeof(nicIndication);

    NdisFIndicateStatus(filterHandle, &statusIndication);
}