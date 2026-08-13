/**
 *
 * \file ar_osal_shmem.c
 *
 * \brief
 *      Defines public APIs for shared memory allocation for DSP.
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdbool.h>
#include <stdatomic.h>
#include "ar_osal_shmem.h" // Public API
#include "ar_osal_error.h" // Error codes
#include "ar_osal_log.h"
#define AR_OSAL_SHMEM_LOG_TAG "COSH"

// DSP backend (ar_osal_shmem_dsp.c)
int32_t ar_shmem_dsp_init(void);
int32_t ar_shmem_dsp_alloc(ar_shmem_info *info);
int32_t ar_shmem_dsp_free(ar_shmem_info *info);
int32_t ar_shmem_dsp_map(ar_shmem_info *info);
int32_t ar_shmem_dsp_unmap(ar_shmem_info *info);
int32_t ar_shmem_dsp_hyp_assign_phys(ar_shmem_hyp_assign_phys_info *info);
int32_t ar_shmem_dsp_sync_for_device(ar_shmem_info *info);
int32_t ar_shmem_dsp_sync_for_cpu(ar_shmem_info *info);
int32_t ar_shmem_dsp_deinit(void);
