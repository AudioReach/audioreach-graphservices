/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_test.h"
#include "ar_osal_log.h"

void main()
{
	ar_log_init();

	AR_LOG_DEBUG(NULL,"*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG," mutex thread test case starting ");
	/* mutex thread test case*/
	ar_test_mutex_thread_main();
	AR_LOG_DEBUG(LOG_TAG," mutex thread test case ended ");
	AR_LOG_DEBUG(LOG_TAG,"*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG," signal thread test case starting ");
	/* signal thread test case*/
	ar_test_signal_thread_main();
	AR_LOG_DEBUG(LOG_TAG," signal thread test case ended ");
	AR_LOG_DEBUG(LOG_TAG,"*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG," list test case starting ");
	/* list test case*/
	ar_test_util_list_main();
	AR_LOG_DEBUG(LOG_TAG," list test case ended ");
	AR_LOG_DEBUG(LOG_TAG,"*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG," shmem test case starting ");
	/* shmem test case*/
	ar_test_shmem_main();
	AR_LOG_DEBUG(LOG_TAG," shmem test case ended ");
	AR_LOG_DEBUG(LOG_TAG,"*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG," file IO test case starting ");
	/* file io test case*/
	ar_test_file_main();
	AR_LOG_DEBUG(LOG_TAG," file IO test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG, " sleep test case starting ");
	/* sleep test case*/
	ar_test_sleep_main();
	AR_LOG_DEBUG(LOG_TAG, " sleep test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG, " Servreg test case starting ");
	/* Servreg test case*/
	ar_test_servreg_main();
	AR_LOG_DEBUG(LOG_TAG, " Servreg test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG, " heap test case starting ");
	/* Heap test case*/
	ar_test_heap_main();
	AR_LOG_DEBUG(LOG_TAG, " heap test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG, " mem op test case starting ");
	/* Mem op test case*/
	ar_test_mem_op_main();
	AR_LOG_DEBUG(LOG_TAG, " mem op test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
	AR_LOG_DEBUG(LOG_TAG, " string test case starting ");
	/* string test case*/
	ar_test_string_main();
	AR_LOG_DEBUG(LOG_TAG, " string test case ended ");
	AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");
    AR_LOG_DEBUG(LOG_TAG, " data logging test case starting ");
    /* data log test case*/
    ar_test_data_log_main();
    AR_LOG_DEBUG(LOG_TAG, " data logging test case ended ");
    AR_LOG_DEBUG(LOG_TAG, "*******************************************************************");


	ar_log_deinit();
	return;
}
