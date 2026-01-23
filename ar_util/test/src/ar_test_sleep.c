/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_osal_sleep.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

void ar_test_sleep_main()
{
	int32_t status = AR_EOK;
	uint64_t usec_sleep = 0;

	// 0 usec sleep, on win32 A value of zero causes the thread to relinquish
	// the remainder of its time slice to any other thread that is ready to run.
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) start", usec_sleep);
	status = ar_osal_micro_sleep(usec_sleep);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to sleep(%llu usec): status(0x%x) ", usec_sleep, status);
	}
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) end", usec_sleep);

	// 1 usec sleep, on win32 A value of zero causes the thread to relinquish
	// the remainder of its time slice to any other thread that is ready to run
	usec_sleep = 1;
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) start", usec_sleep);
	status = ar_osal_micro_sleep(usec_sleep);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed to sleep(%llu usec): status(0x%x) ", usec_sleep, status);
	}
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) end", usec_sleep);

	usec_sleep = 1000; // 1 msec
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) start", usec_sleep);
	status = ar_osal_micro_sleep(usec_sleep);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed to sleep(%llu usec): status(0x%x) ", usec_sleep, status);
	}
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) end", usec_sleep);


	usec_sleep = 10000;//10 msec
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) start", usec_sleep);
	status = ar_osal_micro_sleep(usec_sleep);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed to sleep(%llu usec): status(0x%x) ", usec_sleep, status);
	}
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) end", usec_sleep);

	usec_sleep = 100000; //100msec
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) start", usec_sleep);
	status = ar_osal_micro_sleep(usec_sleep);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed to sleep(%llu usec): status(0x%x) ", usec_sleep, status);
	}
	AR_LOG_INFO(LOG_TAG, "sleep for usec(%llu) end", usec_sleep);

	return;
}
