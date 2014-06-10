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

#define OVS_MULTICAST_GROUP_NONE		0
#define OVS_NETLINK_PORT_ID_NONE		0

//Flags
#define OVS_MESSAGE_FLAG_REQUEST			1
//multipart messages are terminated by an OVS_MESSAGE_TARGET_DUMP_DONE
#define OVS_MESSAGE_FLAG_MULTIPART			2
#define OVS_MESSAGE_FLAG_ACK				4
#define OVS_MESSAGE_FLAG_ECHO				8
//inconsistent dump (i.e. due to a change of sequence)
#define OVS_MESSAGE_FLAG_DUMP_INTR			16

//GET
#define OVS_MESSAGE_FLAG_ROOT		0x100
#define OVS_MESSAGE_FLAG_MATCH		0x200
#define OVS_MESSAGE_FLAG_ATOMIC		0x400
#define OVS_MESSAGE_FLAG_DUMP		(OVS_MESSAGE_FLAG_ROOT | OVS_MESSAGE_FLAG_MATCH)

//NEW
#define OVS_MESSAGE_FLAG_REPLACE	0x100
#define OVS_MESSAGE_FLAG_EXCLUSIVE	0x200
#define OVS_MESSAGE_FLAG_CREATE		0x400
#define OVS_MESSAGE_FLAG_APPEND		0x800
