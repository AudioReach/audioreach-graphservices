/**
 * \file ar_osal_boot.c
 * \brief
 *      Provides the LY platform boot-state implementation.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ar_osal_boot.h"

#include <stdlib.h>
#include <string.h>

bool_t ar_osal_is_non_cold_boot(void)
{
    const char *value = getenv("AR_NON_COLD_BOOT");
    return value != NULL && strcmp(value, "1") == 0 ? TRUE : FALSE;
}
