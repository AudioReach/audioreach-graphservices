/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

void ar_test_mem_op_main()
{
	int32_t status = AR_EOK;
	int8_t BufA[10] = { 1 };
	int8_t BufB[10] = { 2 };
	int32_t cmpSize = 0;

	AR_LOG_DEBUG(LOG_TAG, "ar_mem_cmp(%d), expected < 0", ar_mem_cmp(BufA, BufB, sizeof(BufA)));
	AR_LOG_DEBUG(LOG_TAG, "ar_mem_cmp(%d), expected > 0", ar_mem_cmp(BufB, BufA, sizeof(BufB)));
	AR_LOG_DEBUG(LOG_TAG, "ar_mem_cpy(%d) ", ar_mem_cpy(BufA, sizeof(BufA), BufB, sizeof(BufB)));
	AR_LOG_DEBUG(LOG_TAG, "ar_mem_cmp(%d), expected == 0 ", ar_mem_cmp(BufA, BufB, sizeof(BufA)));

	for (int8_t i = 0; i < sizeof(BufA) / sizeof(BufA[0]); i++)
	{
		BufA[i] = i + 1;
	}

	for (int8_t i = 0; i < sizeof(BufA)/sizeof(BufA[0]); i++)
	{
		AR_LOG_DEBUG(LOG_TAG, "BufA[%d]: %d ",i, BufA[i]);
	}

	AR_LOG_DEBUG(LOG_TAG, "ar_mem_move(%d) ", ar_mem_move(&BufA[2], (sizeof(BufA) - sizeof(int8_t)*2), &BufA[4], sizeof(int8_t)*5));

	for (int8_t i = 0; i < sizeof(BufA) / sizeof(BufA[0]); i++)
	{
		AR_LOG_DEBUG(LOG_TAG, "BufA[%d]: %d ", i, BufA[i]);
	}

	AR_LOG_DEBUG(LOG_TAG, "ar_mem_set(%d) ", ar_mem_set(BufA, 3, sizeof(BufA)));

	for (int8_t i = 0; i < sizeof(BufA) / sizeof(BufA[0]); i++)
	{
		AR_LOG_DEBUG(LOG_TAG, "BufA[%d]: %d ", i, BufA[i]);
	}

	return;
}
