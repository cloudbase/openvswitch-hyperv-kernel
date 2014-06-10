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

#define LIST_FOR_EACH_ENTRY(pos, head, member, typeOfPos)          \
	for (pos = CONTAINING_RECORD((head)->Flink, typeOfPos, member);\
	&pos->member != (head);                                        \
	pos = CONTAINING_RECORD(pos->member.Flink, typeOfPos, member))

#define LIST_FOR_EACH(structType, pEntry, pHead)                                \
	for (pEntry = CONTAINING_RECORD((pHead)->Flink, structType, listEntry);     \
	&pEntry->listEntry != (pHead);                                              \
	pEntry = CONTAINING_RECORD(pEntry->listEntry.Flink, structType, listEntry))