/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_types.h"
#include "ar_osal_signal.h"
#include "ar_osal_thread.h"
#include "ar_osal_error.h"
#include "ar_osal_test.h"
#include "ar_osal_log.h"

#define THREADCOUNT  (4)

void* ghWriteEvent = NULL;
void* ghThreads[THREADCOUNT] = { NULL };

int32_t ThreadProc(void*);

void CreateEventsAndThreads(void)
{
	int32_t i;
	ar_osal_thread_attr_t osal_thread_attr = { NULL, 1024, 0 };

	int32_t status = AR_EOK;
	// Create a manual-reset event object. The write thread sets this
	// object to the signaled state when it finishes writing to a
	// shared buffer.

	status = ar_osal_signal_create(&ghWriteEvent);
	if (NULL == ghWriteEvent || AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_signal_create failed (%d)", status);
		return;
	}

	status = ar_osal_signal_clear(ghWriteEvent);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_signal_clear failed (%d)", status);
		return;
	}

	// Create multiple threads to read from the buffer.
	for (i = 0; i < THREADCOUNT; i++)
	{
		status = ar_osal_thread_attr_init(&osal_thread_attr);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG,"ar_osal_thread_attr_init error: %d", status);
			return;
		}

		status = ar_osal_thread_create(
			&ghThreads[i],
			&osal_thread_attr,
			(ar_osal_thread_start_routine)ThreadProc,
			NULL);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG,"ar_osal_thread_create error: %d", status);
			return;
		}
	}
}

void WriteToBuffer(void)
{
	int32_t status = AR_EOK;

	AR_LOG_INFO(LOG_TAG,"Main thread writing to the shared buffer...");

	// Set ghWriteEvent to signaled
	status = ar_osal_signal_set(ghWriteEvent);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_signal_set failed (%d)", status);
		return;
	}
}

void CloseEvents()
{
	// Close all event handles (currently, only one global handle).
	int32_t status = ar_osal_signal_destroy(ghWriteEvent);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"ar_osal_signal_destroy failed (%d)", status);
		return;
	}

	/*fuzz test*/
	ar_osal_signal_set(ghWriteEvent);
	ar_osal_signal_destroy(ghWriteEvent);
	ar_osal_signal_clear(ghWriteEvent);
	ar_osal_signal_wait(ghWriteEvent);
}

void ar_test_signal_thread_main()
{
	int32_t status = AR_EOK;
	int32_t test = 0;
	ar_osal_signal_t test_signal = NULL;

	// Create events and THREADCOUNT threads to read from the buffer
	CreateEventsAndThreads();

	WriteToBuffer();

	AR_LOG_INFO(LOG_TAG,"Main thread waiting for threads to exit...");

	for (int32_t i = 0; i < THREADCOUNT; i++)
	{
		status = ar_osal_thread_join_destroy(ghThreads[i]);
		if (AR_EOK != status)
		{
			AR_LOG_ERR(LOG_TAG," Thread[%d] ar_osal_thread_join_destroy() failed, err: %d ", i, status);
		}
	}

	if (AR_EOK == ar_osal_signal_clear(ghWriteEvent))
	{
		AR_LOG_INFO(LOG_TAG, "Thread 0x%Ix  thread cleared ",
			ar_osal_thread_get_id());
	}

	/* fuzz test */
	ar_osal_signal_timedwait(ghWriteEvent,100000);

	CloseEvents();

	/*fuzz test*/
	ar_osal_signal_wait(NULL);

	return;
}

int32_t ThreadProc(void *lpParam)
{
	// lpParam not used in this example, suppress warning.
	lpParam;

	AR_LOG_INFO(LOG_TAG,"Thread 0x%Ix waiting for write event...", ar_osal_thread_get_id());

	if (AR_EOK == ar_osal_signal_wait(ghWriteEvent))    // indefinite wait
	{
		AR_LOG_INFO(LOG_TAG,"Thread 0x%Ix  reading from buffer ",
			ar_osal_thread_get_id());
	}
	AR_LOG_INFO(LOG_TAG,"Thread 0x%Ix  exiting ", ar_osal_thread_get_id());
	return 1;
}
