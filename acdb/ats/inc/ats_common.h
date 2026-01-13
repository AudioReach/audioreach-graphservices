#ifndef _ATS_COMMON_H_
#define _ATS_COMMON_H_
/**
*=============================================================================
* \file ats_common.h
*
* \brief
*      Common header file used by ATS modules.
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ar_osal_types.h"
#include "ar_osal_log.h"
#include "ar_osal_mem_op.h"

#define ATS_LOG_TAG  "ATS"
#define ATS_ERR(...)  AR_LOG_ERR(ATS_LOG_TAG, __VA_ARGS__)
#define ATS_DBG(...)  AR_LOG_DEBUG(ATS_LOG_TAG, __VA_ARGS__)
#define ATS_INFO(...) AR_LOG_INFO(ATS_LOG_TAG, __VA_ARGS__)

/* Error/Debug Message Format 1
* \param msg Brief message describing the error
* \param err_code Error code to be logged
*/
#define ATS_ERR_MSG_1(msg, err_code, ...) ATS_ERR("Error[%d]:%s", err_code, msg, __VA_ARGS__)
#define ATS_DBG_MSG_1(msg, err_code, ...) ATS_DBG("Error[%d]:%s", err_code, msg, __VA_ARGS__)

#define ATS_ERR_MSG_2(msg, err_code, ...) ATS_ERR("Error[%d]:%s"##msg, err_code)

#define ATS_MEM_CPY_SAFE(dest, dest_size, src, src_size) ar_mem_cpy((int8_t*) dest, dest_size, (int8_t*)src, src_size)

#endif /*_ATS_COMMON_H_*/
