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

NET_BUFFER_LIST* CloneNblFragment(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl, _In_ ULONG maxNbLength);
NET_BUFFER_LIST* CloneNblNormal(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl);
NET_BUFFER_LIST* DuplicateNbl(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl);
VOID FreeDuplicateNbl(_In_ const OVS_SWITCH_INFO* pSwitchInfo, _In_ NET_BUFFER_LIST* pNbl);

VOID* ReadNb_Alloc(_In_ NET_BUFFER* net_buffer);
VOID* GetNbBufferData(_In_ NET_BUFFER* pNb, _Out_ void** pAllocBuffer);
VOID* GetNbBufferData_OfSize(_In_ NET_BUFFER* pNb, ULONG size, _Out_ void** pAllocBuffer);
VOID FreeNbBufferData(VOID* allocBuffer);

VOID FreeClonedNblFragment(_In_ NET_BUFFER_LIST* pNbl, _In_ ULONG dataOffsetDelta);
VOID FreeClonedNblNormal(_In_ NET_BUFFER_LIST* pNbl);

ULONG CountNbs(_In_ NET_BUFFER_LIST* pNbl);
ULONG CountNbls(_In_ NET_BUFFER_LIST* pNbl);

BOOLEAN VerifyNetBuffer(VOID* buffer, ULONG length);
BOOLEAN VerifyProtocolHeader(BYTE* buffer, ULONG* pLength, UINT16* pEthType);

NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO* GetChecksumOffloadInfo(_In_ NET_BUFFER_LIST* pNbl);

VOID DbgPrintNblInfo(NET_BUFFER_LIST* pNbl);

#ifdef DBG
VOID DbgPrintMdl(MDL* pMdl);
VOID DbgPrintNb(NET_BUFFER* pNb, LPCSTR msg);
VOID DbgPrintNbl(NET_BUFFER_LIST* pNbl, LPCSTR msg);
VOID DbgPrintNblList(NET_BUFFER_LIST* pNbl);
VOID DbgPrintNblCount(NET_BUFFER_LIST* pNbl);
VOID DbgPrintNbCount(NET_BUFFER_LIST* pNbl);

#else
#define DbgPrintMdl(pMdl)
#define DbgPrintNb(pNb, msg)
#define DbgPrintNbl(pNbl, msg)
#define DbgPrintNblList(pNbl)
#define DbgPrintNblCount(pNbl)
#define DbgPrintNbCount(pNbl)
#endif