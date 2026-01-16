/**
 * \file gpr_log.c
 * \brief
 *    This file contains logger implementation
 *
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/******************************************************************************
 * Includes                                                                    *
 *****************************************************************************/

#include "ar_osal_error.h"

#include "gpr_api_i.h"
#include "gpr_log.h"

/*****************************************************************************
 * Defines                                                                   *
 ****************************************************************************/

/*****************************************************************************
 * Structure definitions                                                     *
 ****************************************************************************/

/*****************************************************************************
 * Variables                                                                 *
 ****************************************************************************/

/*****************************************************************************
 * Function Definitions                                                      *
 ****************************************************************************/

GPR_INTERNAL uint32_t gpr_log_init(void)
{
   return AR_EOK;
}

GPR_INTERNAL uint32_t gpr_log_deinit(void)
{
   return AR_EOK;
}

GPR_INTERNAL int32_t gpr_log_packet(gpr_packet_t *packet)
{
   return AR_EOK;
}
