/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_osal_shmem.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

void ar_test_shmem_main()
{
	int32_t status = AR_EOK;
    uint8_t sys_id = AR_AUDIO_DSP;
	ar_shmem_info shmem_info = { AR_SHMEM_VIRTUAL_MEMORY/*virtual & cached*/, 4096, AR_SHMEM_CACHED, AR_SHMEM_BUFFER_ADDRESS, 0,0,0,0, NULL,0, 1, &sys_id};
	status = ar_shmem_init();
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to shmem init %d ", status);
		goto end;
	}

	status = ar_shmem_alloc(&shmem_info);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to shmem alloc(%d): size%d ", status, shmem_info.buf_size);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG,"shmem allocated address: 0x%p, size: 0x%x ", shmem_info.vaddr, shmem_info.buf_size);
	AR_LOG_INFO(LOG_TAG,"shmem allocated address ipa_msw:ipa_lsw: (0x%08X:%08X) ", shmem_info.ipa_msw, shmem_info.ipa_lsw);
	AR_LOG_INFO(LOG_TAG,"shmem allocated address pa_msw:pa_lsw: (0x%08X:%08X) ", shmem_info.pa_msw, shmem_info.pa_lsw);
	AR_LOG_INFO(LOG_TAG, "shmem allocated mem_type(0x%x), cache_type(0x%x), index_type(0x%x) ", shmem_info.mem_type, shmem_info.cache_type, shmem_info.index_type);

	status = ar_shmem_free(&shmem_info);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to shmem free %d ", status);
		goto end;
	}
end:
	return;
}
