/**
 *
 * \file ar_osal_shmem.c
 *
 * \brief
 *      This file has implementation for selection of functions with ARM/DSP-specific processing.
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdbool.h>
#include "ar_osal_shmem.h" // Public API
#include "ar_osal_error.h" // Error codes
#include "ar_osal_log.h"
#include "ar_osal_shmem_dsp.h"
#include "ar_osal_shmem_ap.h"
#define AR_OSAL_SHMEM_LOG_TAG "COSH"

static bool are_on_apps = false;

int32_t ar_shmem_init()
{
   return AR_EOK;
}

int32_t ar_shmem_init_v2(uint32_t num_master_procs, uint32_t *master_procs)
{
    /* Assumption: There is no case with multiple master processors with one of them being APSS. */
    for (int i = 0; i < num_master_procs; i++) {
        if(master_procs[i]== AR_APSS){
            are_on_apps = true;
            break;
        }
    }

    return are_on_apps ? ar_shmem_ap_init() : ar_shmem_dsp_init();
}

int32_t ar_shmem_alloc(ar_shmem_info *info)
{
    return are_on_apps ? ar_shmem_ap_alloc(info) : ar_shmem_dsp_alloc(info);
}

int32_t ar_shmem_free(ar_shmem_info *info)
{
    return are_on_apps ? ar_shmem_ap_free(info) : ar_shmem_dsp_free(info);
}

int32_t ar_shmem_map(ar_shmem_info *info)
{
    return are_on_apps ? ar_shmem_ap_map(info) : ar_shmem_dsp_map(info);
}

int32_t ar_shmem_unmap(ar_shmem_info *info)
{
    return are_on_apps ? ar_shmem_ap_unmap(info) : ar_shmem_dsp_unmap(info);
}

int32_t ar_shmem_hyp_assign_phys(ar_shmem_hyp_assign_phys_info *info)
{
    return are_on_apps ? ar_shmem_ap_hyp_assign_phys(info)
                   : ar_shmem_dsp_hyp_assign_phys(info);
}

int32_t ar_shmem_get_uid(uint64_t alloc_handle, uint64_t *uid)
{
    if (are_on_apps) {
        return ar_shmem_ap_get_uid(alloc_handle, uid);
    }
    return AR_EUNSUPPORTED;
}

int32_t ar_shmem_sync_for_device(ar_shmem_info *info)
{
	return are_on_apps ? AR_EOK : ar_shmem_dsp_sync_for_device(info);
}

int32_t ar_shmem_sync_for_cpu(ar_shmem_info *info)
{
	return are_on_apps ? AR_EOK : ar_shmem_dsp_sync_for_cpu(info);
}

int32_t ar_shmem_deinit(void)
{
    int32_t rc = are_on_apps ? ar_shmem_ap_deinit() : ar_shmem_dsp_deinit();
    return rc;
}
