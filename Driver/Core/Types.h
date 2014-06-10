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

#include "precomp.h"

#ifdef LODWORD
#undef LODWORD
#endif

#ifdef HIDWORD
#undef HIDWORD
#endif

typedef UINT16	LE16;
typedef UINT32	LE32;
typedef UINT64	LE64;

typedef UINT16	BE16;
typedef UINT32	BE32;
typedef UINT64	BE64;
typedef UINT64	QWORD;

//byte
#define LONIBBLE(b)         ((BYTE)(((DWORD_PTR)(b)) & 0xf))
#define HINIBBLE(b)         ((BYTE)((((DWORD_PTR)(b)) >> 4) & 0xf))

#define MAKEBYTE(l, h)      ((BYTE)(LONIBBLE(l) | ((BYTE)LONIBBLE(h)) << 4))

//word
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))

#define MAKEWORD(l, h)      ((WORD)(LOBYTE(l) | ((WORD)LOBYTE(h)) << 8))

//dword
#define LOWORD(dw)          ((WORD)(((DWORD_PTR)(dw)) & 0xffff))
#define HIWORD(dw)          ((WORD)((((DWORD_PTR)(dw)) >> 16) & 0xffff))

#define MAKEDWORD(l, h)     ((DWORD)(LOWORD(l) | ((DWORD)LOWORD(h)) << 16))

//qword
#define LODWORD(qw)         ((DWORD)(((DWORD_PTR)(qw)) & 0xffffffff))
#define HIDWORD(qw)         ((DWORD)((((DWORD_PTR)(qw)) >> 32) & 0xffffffff))

#define MAKEQWORD(l, h)     ((QWORD)(LODWORD(l) | ((QWORD)LODWORD(h)) << 32))