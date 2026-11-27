/**
 * \file ar_osal_boot.h
 * \brief
 *      Defines the boot-state API.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef AR_OSAL_BOOT_H
#define AR_OSAL_BOOT_H

#include "ar_osal_types.h"

#if defined(AR_OSAL_HAS_BOOT_STATE_PROVIDER)

bool_t ar_osal_is_non_cold_boot(void);

#else

static inline bool_t ar_osal_is_non_cold_boot(void)
{
    return FALSE;
}

#endif

#endif
