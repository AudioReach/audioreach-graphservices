/**
 * \file gsl_rtc_main.c
 *
 * \brief
 *      Real Time Calibration API implementation layer
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_error.h"
#include "gsl_rtc_intf.h"
#include "gsl_rtc_main.h"
#include "gsl_common.h"
#include "gsl_rtc.h"
#include "ar_osal_log_pkt_op.h"

struct gsl_rtc_ctxt {
	/*
	 * callback invoked whenever there is an SSR up or down event
	 */
	gsl_rtc_cb_t rtc_cb;
} rtc_ctxt;

static bool_t is_gsl_rtc_inited(void)
{
	if (!rtc_ctxt.rtc_cb) {
		GSL_ERR("GSL rtc not initialized");
		return FALSE;
	}
	return TRUE;
}

int32_t gsl_rtc_get_active_usecase_info(struct gsl_rtc_active_uc_info *info)
{
	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_GET_UC_INFO, info);
}

int32_t gsl_rtc_get_persist_data(struct gsl_rtc_persist_param *rtc_param)
{
	if (!rtc_param)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_GET_PERSIST_DATA, rtc_param);
}

int32_t gsl_rtc_get_non_persist_data(struct gsl_rtc_param *rtc_param)
{
	if (!rtc_param)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_GET_NON_PERSIST_DATA, rtc_param);
}

int32_t gsl_rtc_set_persist_data(struct gsl_rtc_persist_param *rtc_param)
{
	if (!rtc_param)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_SET_PERSIST_DATA, rtc_param);
}

int32_t gsl_rtc_set_non_persist_data(struct gsl_rtc_param *rtc_param)
{
	if (!rtc_param)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_SET_NON_PERSIST_DATA, rtc_param);
}

int32_t gsl_rtc_prepare_change_graph(
	struct gsl_rtc_prepare_change_graph_info *rtc_param)
{
	if (!rtc_param)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_PREPARE_CHANGE_GRAPH, rtc_param);
}

int32_t gsl_rtc_change_graph(struct gsl_rtc_change_graph_info *rtc_param)
{
	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_CHANGE_GRAPH, rtc_param);
}

int32_t gsl_rtc_notify_conn_state(struct gsl_rtc_conn_info *rtgm_session_info)
{
	if (!rtgm_session_info)
		return AR_EBADPARAM;

	if (!is_gsl_rtc_inited())
		return AR_EFAILED;

	return rtc_ctxt.rtc_cb(GSL_RTC_CONN_INFO_CHANGE, rtgm_session_info);
}

int32_t gsl_rtc_init(gsl_rtc_cb_t cb)
{
	int32_t rc = AR_EOK;

	rc = gsl_rtc_internal_init();
	if (rc)
		return rc;

	rtc_ctxt.rtc_cb = cb;
	return rc;
}

int32_t gsl_rtc_deinit(void)
{
	gsl_rtc_internal_deinit();
	rtc_ctxt.rtc_cb = NULL;
	return AR_EOK;
}
