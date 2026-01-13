#ifndef GSL_RTC_MAIN_H
#define GSL_RTC_MAIN_H
/**
 * \file gsl_rtc_main.h
 *
 * \brief
 *      GSL RTC internal header
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "ar_osal_types.h"

enum gsl_rtc_request_type {
	GSL_RTC_GET_UC_INFO,
	GSL_RTC_GET_PERSIST_DATA,
	GSL_RTC_GET_NON_PERSIST_DATA,
	GSL_RTC_SET_PERSIST_DATA,
	GSL_RTC_SET_NON_PERSIST_DATA,
	GSL_RTC_PREPARE_CHANGE_GRAPH,
	GSL_RTC_CHANGE_GRAPH,
	GSL_RTC_CONN_INFO_CHANGE,
};

typedef int32_t(*gsl_rtc_cb_t)(enum gsl_rtc_request_type req, void *cb_data);

/*
 *  Initialize GSL RTC layer
 * \param[in] cb callback into gsl_main to get graph information (gkv, ckv)
 */

int32_t gsl_rtc_init(gsl_rtc_cb_t cb);

/*
 *  De-initialize GSL RTC layer
 * \param[in] cb callback into gsl_main to get graph information (gkv, ckv)
 */

int32_t gsl_rtc_deinit(void);

#endif /* GSL_RTC_MAIN_H */
