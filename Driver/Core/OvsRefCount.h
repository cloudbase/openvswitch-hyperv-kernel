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

#if OVS_USE_REFCOUNT_CALL_STACK
#define OVS_REFCOUNT_MAX_THREAD_COUNT	16
#define OVS_REFCOUNT_MAX_FUNC_COUNT		10

C_ASSERT(OVS_REFCOUNT_MAX_THREAD_COUNT <= 64);
#endif

//NOTE: must be the first field of any struct using the OVS_REF_COUNT
typedef struct _OVS_REF_COUNT
{
#if OVS_USE_REFCOUNT_CALL_STACK
	//for debugging purposes: when a refCount is increased, it is first added to countsPerThread[currentThreadNumber]
	//then the func name (__FUNCTION__)  will be placed at funcs[curThreadNumber][refCountPerCurrentThread]
	//if there is not enough room to store the func name in the stack (i.e. refCount >= OVS_REFCOUNT_MAX_FUNC_COUNT) => we consider it a bug
	const char* funcs[OVS_REFCOUNT_MAX_THREAD_COUNT][OVS_REFCOUNT_MAX_FUNC_COUNT];
	ULONG refCountsPerThread[OVS_REFCOUNT_MAX_THREAD_COUNT];
	PKTHREAD threads[OVS_REFCOUNT_MAX_THREAD_COUNT];
	ULONG noOfThreads;
#endif

	//if refCount > 0, the object deletion will be postponed
	//it is used so that we can keep a pointer to the object, while allowing it to be modified (but not deleted) by other threads.
	volatile ULONG refCount;
	//if the object should be destroyed, but some thread currently holds a reference to it, it will be marked for deletion instead.
	//when the refCount reaches 0, if deletetionPending is set, the dereference function will destroy the object.
	volatile BOOLEAN deletionPending;

	VOID (*Destroy)(VOID*);
}OVS_REF_COUNT;

extern NDIS_RW_LOCK_EX* g_pRefRwLock;

/**************************************/

static __inline RefCount_DereferenceOnly(VOID* pObj)
{
	if (pObj)
	{
		LOCK_STATE_EX lockState;
		OVS_REF_COUNT* pRefCount = pObj;

		NdisAcquireRWLockWrite(g_pRefRwLock, &lockState, 0);

		OVS_CHECK(pRefCount->refCount > 0);
#if OVS_USE_REFCOUNT_CALL_STACK
		{
			ULONG threadNumber = MAXULONG;
			ULONG curThreadRefCount = 0;
			PKTHREAD pThread = NULL;

			OVS_CHECK(pRefCount->refCount < OVS_REFCOUNT_MAX_FUNC_COUNT);
			pThread = KeGetCurrentThread();

			for (ULONG i = 0; i < OVS_REFCOUNT_MAX_THREAD_COUNT; ++i)
			{
				if (pRefCount->threads[i] == pThread)
				{
					threadNumber = i;
					break;
				}
			}

			OVS_CHECK(threadNumber != MAXULONG);

			OVS_CHECK(pRefCount->refCountsPerThread[threadNumber] > 0);
			pRefCount->refCountsPerThread[threadNumber]--;
			curThreadRefCount = pRefCount->refCountsPerThread[threadNumber];
			pRefCount->funcs[threadNumber][curThreadRefCount] = NULL;

			if (curThreadRefCount == 0)
			{
				pRefCount->threads[threadNumber] = NULL;
				pRefCount->noOfThreads--;
			}
		}
#endif
		--pRefCount->refCount;

		NdisReleaseRWLock(g_pRefRwLock, &lockState);
	}
}

#define OVS_REFCOUNT_DEREFERENCE_ONLY(pObj)	RefCount_DereferenceOnly(pObj)

static VOID __inline RefCount_Dereference(VOID* pObj)
{
	LOCK_STATE_EX lockState;
	OVS_REF_COUNT* pRefCount = pObj;

	if (!pObj)
	{
		return;
	}

	OVS_CHECK(pRefCount->Destroy);

	NdisAcquireRWLockWrite(g_pRefRwLock, &lockState, 0);

	OVS_CHECK(pRefCount->refCount > 0);
#if OVS_USE_REFCOUNT_CALL_STACK
	{
		ULONG threadNumber = MAXULONG;
		ULONG curThreadRefCount = 0;
		PKTHREAD pThread = NULL;

		OVS_CHECK(pRefCount->refCount < OVS_REFCOUNT_MAX_FUNC_COUNT);
		pThread = KeGetCurrentThread();

		for (ULONG i = 0; i < OVS_REFCOUNT_MAX_THREAD_COUNT; ++i)
		{
			if (pRefCount->threads[i] == pThread)
			{
				threadNumber = i;
				break;
			}
		}

		OVS_CHECK(threadNumber != MAXULONG);

		OVS_CHECK(pRefCount->refCountsPerThread[threadNumber] > 0);
		pRefCount->refCountsPerThread[threadNumber]--;
		curThreadRefCount = pRefCount->refCountsPerThread[threadNumber];
		pRefCount->funcs[threadNumber][curThreadRefCount] = NULL;

		if (curThreadRefCount == 0)
		{
			pRefCount->threads[threadNumber] = NULL;
			pRefCount->noOfThreads--;
		}
	}
#endif
	--pRefCount->refCount;

	if (pRefCount->refCount == 0 && pRefCount->deletionPending)
	{
		pRefCount->Destroy(pObj);
	}

	NdisReleaseRWLock(g_pRefRwLock, &lockState);
}

#define OVS_REFCOUNT_DEREFERENCE(pObj) {RefCount_Dereference(pObj); pObj = NULL; }

static __inline VOID* RefCount_Reference(VOID* pObj, const char* funcName)
{
	if (pObj)
	{
		LOCK_STATE_EX lockState;
		OVS_REF_COUNT* pRefCount = pObj;

		NdisAcquireRWLockWrite(g_pRefRwLock, &lockState, 0);

		if (pRefCount->deletionPending)
		{
			pObj = NULL;
		}

		else
		{
#if OVS_USE_REFCOUNT_CALL_STACK
			ULONG threadNumber = MAXULONG;
			ULONG curThreadRefCount = 0;
			PKTHREAD pThread = NULL;

			OVS_CHECK(pRefCount->noOfThreads < OVS_REFCOUNT_MAX_THREAD_COUNT);

			pThread = KeGetCurrentThread();

			for (ULONG i = 0; i < OVS_REFCOUNT_MAX_THREAD_COUNT; ++i)
			{
				if (pRefCount->threads[i] == pThread)
				{
					threadNumber = i;
					break;
				}
			}

			if (threadNumber == MAXULONG)
			{
				OVS_CHECK(pRefCount->noOfThreads  + 1 < OVS_REFCOUNT_MAX_THREAD_COUNT);

				for (ULONG i = 0; i < OVS_REFCOUNT_MAX_THREAD_COUNT; ++i)
				{
					if (pRefCount->threads[i] == NULL)
					{
						pRefCount->threads[i] = pThread;
						pRefCount->noOfThreads++;

						threadNumber = i;
						break;
					}
				}
			}

			OVS_CHECK(threadNumber != MAXULONG);

			curThreadRefCount = pRefCount->refCountsPerThread[threadNumber];
			OVS_CHECK(curThreadRefCount + 1 < OVS_REFCOUNT_MAX_FUNC_COUNT);

			pRefCount->funcs[threadNumber][curThreadRefCount] = funcName;
			pRefCount->refCountsPerThread[threadNumber]++;
#else
			UNREFERENCED_PARAMETER(funcName);
#endif

			++pRefCount->refCount;
		}

		NdisReleaseRWLock(g_pRefRwLock, &lockState);
	}

	return pObj;
}

#define OVS_REFCOUNT_REFERENCE(pObj) RefCount_Reference(pObj, __FUNCTION__);

static __inline VOID RefCount_Destroy(VOID* pObj)
{
	if (pObj)
	{
		LOCK_STATE_EX lockState;
		OVS_REF_COUNT* pRefCount = pObj;

		OVS_CHECK(pRefCount->Destroy);

		NdisAcquireRWLockWrite(g_pRefRwLock, &lockState, 0);

		if (pRefCount->refCount > 0)
		{
			pRefCount->deletionPending = TRUE;
		}

		else
		{
			pRefCount->Destroy(pObj);
		}

		NdisReleaseRWLock(g_pRefRwLock, &lockState);
	}
}

#define OVS_REFCOUNT_DESTROY(pObj) { RefCount_Destroy(pObj); pObj = NULL; }