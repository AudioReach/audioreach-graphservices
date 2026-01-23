/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_osal_heap.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

void ar_test_heap_main()
{
	int32_t status = AR_EOK;
	void* pBuff = NULL;
	size_t BuffSize = 4096;
	ar_heap_info heap_info = { AR_HEAP_ALIGN_DEFAULT, AR_HEAP_ID_DEFAULT,AR_HEAP_POOL_DEFAULT, AR_HEAP_TAG_DEFAULT };
	int32_t* IntPtr;
	status = ar_heap_init();
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed ar_heap_init %d ", status);
		goto end;
	}

	pBuff = ar_heap_malloc(BuffSize, &heap_info);
	if (NULL == pBuff)
	{
		AR_LOG_ERR(LOG_TAG, "failed ar_heap_malloc: size%d ", BuffSize);
		goto end;
	}
	IntPtr = (int32_t*)pBuff;
	AR_LOG_DEBUG(LOG_TAG, "allocated address: 0x%p, size: 0x%x alignment:8 0x%p", pBuff, BuffSize, ((uintptr_t)pBuff % 8));
	AR_LOG_DEBUG(LOG_TAG, " value [0]:%d,[1]:%d,[2]:%d,[3]:%d, ", IntPtr[0], IntPtr[1], IntPtr[2], IntPtr[3]);
	ar_heap_free(pBuff, &heap_info);

	pBuff = NULL;
	BuffSize = 32;
	pBuff = ar_heap_calloc(BuffSize, &heap_info);
	if (NULL == pBuff)
	{
		AR_LOG_ERR(LOG_TAG, "failed ar_heap_calloc: size%d ", BuffSize);
		goto end;
	}

	IntPtr = (int32_t*)pBuff;
	AR_LOG_DEBUG(LOG_TAG, "allocated address: 0x%p, size: 0x%x alignment:8 0x%p", pBuff, BuffSize, ((uintptr_t)pBuff % 8));
	AR_LOG_DEBUG(LOG_TAG, " value [0]:%d,[1]:%d,[2]:%d,[3]:%d, ", IntPtr[0], IntPtr[1], IntPtr[2], IntPtr[3]);

	ar_heap_free(pBuff, &heap_info);

	status = ar_heap_deinit();
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG, "failed ar_heap_deinit %d ", status);
		goto end;
	}
end:
	return;
}
