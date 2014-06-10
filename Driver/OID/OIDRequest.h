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

typedef struct _OVS_SWITCH_INFO OVS_SWITCH_INFO;
typedef struct _OVS_GLOBAL_FORWARD_INFO OVS_GLOBAL_FORWARD_INFO;

typedef struct _OVS_OID_REQUEST
{
    NDIS_OID_REQUEST ndisOidRequest;
    NDIS_EVENT reqEvent;
    NDIS_STATUS status;
    ULONG bytesNeeded;
} OVS_OID_REQUEST, *POVS_OID_REQUEST;

VOID OID_CompleteInternalOidRequest(_In_ NDIS_OID_REQUEST* pNdisRequest, _In_ NDIS_STATUS status);

NDIS_STATUS OID_ProcessSetOid(_In_ OVS_GLOBAL_FORWARD_INFO* pForwardInfo, _Inout_ NDIS_OID_REQUEST* pOidRequest, _Out_ BOOLEAN* pComplete);

NDIS_STATUS OID_ProcessMethodOid(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _Inout_ NDIS_OID_REQUEST* pOidRequest, _Out_ BOOLEAN* pComplete, _Out_ ULONG* pOutBytesNeeded);

NDIS_STATUS OID_IssueOidRequest(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NDIS_REQUEST_TYPE requestType, _In_ NDIS_OID oid,
    _In_opt_ VOID* pInformationBuffer, _In_ ULONG informationBufferLength, _In_ ULONG outputBufferLength, _In_ ULONG methodId,
    _In_ UINT timeout, ULONG* pOutBytesNeeded);

NDIS_STATUS OID_GetNicArrayUnsafe(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _Out_ NDIS_SWITCH_NIC_ARRAY** ppNicArray);

NDIS_STATUS OID_GetSwitchPropertyUnsafe(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NDIS_SWITCH_PROPERTY_TYPE propertyType,
    _In_opt_ NDIS_SWITCH_OBJECT_ID* pPropertyId, NDIS_SWITCH_PROPERTY_ENUM_PARAMETERS** ppSwitchPropertyEnumParameters);

NDIS_STATUS OID_GetPortPropertyUnsafe(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _In_ NDIS_SWITCH_PORT_ID portId,
    _In_ NDIS_SWITCH_PORT_PROPERTY_TYPE propertyType, _In_opt_ NDIS_SWITCH_OBJECT_ID* pPropertyId,
    NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS** ppPortPropertyEnumParameters);

NDIS_STATUS OID_GetPortArrayUnsafe(_Inout_ OVS_SWITCH_INFO* pSwitchInfo, _Out_ NDIS_SWITCH_PORT_ARRAY** ppOutPortArray);