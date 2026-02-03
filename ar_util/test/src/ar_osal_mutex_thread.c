/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_types.h"
#include "ar_osal_mutex.h"
#include "ar_osal_thread.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
#include "ar_osal_test.h"

#define THREADCOUNT  (2)

void *ghMutex = NULL;

int32_t WriteToDatabase(void*);

void ar_test_mutex_thread_main()
{
	int32_t status = 0;
	void *aThread[THREADCOUNT] = { NULL };
	int32_t ThreadID = 0;
	int32_t i = 0;
	ar_osal_thread_attr_t osal_thread_attr = { NULL, 1024, 0 };
	int32_t test = 0;

	// Create a mutex
	status = ar_osal_mutex_create(&ghMutex);             // unnamed mutex
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_mutex_create error: %d", status);
		goto end;
	}

	// Create worker threads
	for (i = 0; i < THREADCOUNT; i++)
	{
		status = ar_osal_thread_attr_init(&osal_thread_attr);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG,"ar_osal_thread_attr_init error: %d", status);
			goto end;
		}

		status = ar_osal_thread_create(
			&aThread[i],
			&osal_thread_attr,
			(ar_osal_thread_start_routine)WriteToDatabase,
			NULL);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG,"ar_osal_thread_create error: %d", status);
			goto end;
		}
	}

	// Wait for all threads to terminate
	for (i = 0; i < THREADCOUNT; i++)
	{
		status = ar_osal_thread_join_destroy(aThread[i]);
		if (AR_EOK != status)
		{
			AR_LOG_ERR(LOG_TAG,"ar_osal_thread_join_destroy for thread(%d) destroy failed (%d(", i, status);
			goto end;
		}
	}

	// Close mutex handles
	status = ar_osal_mutex_destroy(ghMutex);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_mutex_destroy destroy failed(%d)", status);
	}

	/* fuzz test*/
	ar_osal_mutex_lock(NULL);
	ar_osal_mutex_unlock(NULL);
	ar_osal_mutex_lock(&test);
	ar_osal_mutex_unlock(&test);
end:
	return;
}

int32_t WriteToDatabase(void* lpParam)
{
	// lpParam not used in this example,suppress warning
    __UNREFERENCED_PARAM(lpParam);

	int32_t dwCount = 0;
	int32_t status = AR_EOK;

	// Request ownership of mutex.
	while (dwCount < 20)
	{
		status = ar_osal_mutex_lock(
			ghMutex);  // no time-out interval
		if (AR_EOK == status)
		{
			dwCount++;
			AR_LOG_INFO(LOG_TAG,"Thread 0x%Ix writing to database %d ",
				ar_osal_thread_get_id(), dwCount);
			// Release ownership of the mutex object
			if (AR_EOK != ar_osal_mutex_unlock(ghMutex))
			{
				AR_LOG_ERR(LOG_TAG,"Thread 0x%Ix osal_mutex_unlock failed",
					ar_osal_thread_get_id());
			}
		}
		else
		{
			AR_LOG_ERR(LOG_TAG,"Thread 0x%Ix osal_mutex_lock failed",
				ar_osal_thread_get_id());
		}
	}
	return AR_EOK;
}
