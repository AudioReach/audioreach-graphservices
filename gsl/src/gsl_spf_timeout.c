/**
 * \file gsl_spf_timeout.c
 *
 * \brief
 *      Represents GSL SPF timeouts
 *
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_common.h"
#include "ar_osal_error.h"
#include "acdb.h"

#define SET_TIMEOUT_IF_VALID(val, max, target) \
    do { if ((val) > 0 && (val) <= (max)) (target) = (val); } while (0)

uint32_t GSL_SPF_TIMEOUT_MS = GSL_SPF_TIMEOUT_MS_DEFAULT;
uint32_t GSL_GRAPH_OPEN_TIMEOUT_MS = GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT;
uint32_t GSL_GRAPH_PREPARE_TIMEOUT_MS = GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT;
uint32_t GSL_GRAPH_START_STOP_TIMEOUT_MS = GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT;
uint32_t GSL_SPF_READ_WRITE_TIMEOUT_MS = GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT;
uint32_t GSL_AMDB_LOAD_MODULES_TIMEOUT_MS = GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT;

int32_t gsl_spf_timeouts_get_timeouts_from_acdb(void)
{
	AcdbDriverData acdb_req = { 0, };
	AcdbBlob acdb_rsp = { 0, };
	struct spf_timeouts_value *sv = NULL;
	int32_t rc = AR_EOK;
	uint32_t i = 0, *tmp_p = NULL, *tmp_pos = NULL;

	GSL_INFO("Enter");

	/* first query for size */
	acdb_req.key_vector.num_keys = 0;
	acdb_req.module_id = GSL_SPF_TIMEOUTS;
	acdb_rsp.buf = NULL;
	acdb_rsp.buf_size = 0;
	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &acdb_req, sizeof(acdb_req),
		&acdb_rsp, sizeof(acdb_rsp));
	if (rc != AR_EOK && rc != AR_ENOTEXIST) {
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_DATA failed %d", rc);
		return rc;
	}

	acdb_rsp.buf = gsl_mem_zalloc(acdb_rsp.buf_size);
	if (!acdb_rsp.buf) {
		rc = AR_ENOMEMORY;
		return rc;
	}

	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &acdb_req, sizeof(acdb_req),
		&acdb_rsp, sizeof(acdb_rsp));
	if (rc != AR_EOK) {
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_DATA failed %d", rc);
		goto exit;
	}

	tmp_p = (uint32_t *)acdb_rsp.buf;
	/* MID */
	if (*tmp_p++ != GSL_SPF_TIMEOUTS) {
		GSL_ERR("got incorrect SPF_TIMEOUTS from ACDB %d", *((uint32_t *)acdb_rsp.buf));
		rc = AR_EFAILED;
		goto exit;
	}

	acdb_rsp.buf_size -= 4; /* PARAM ID GSL_SPF_TIMEOUTS size */
	while (acdb_rsp.buf_size > 0) {
		if (*tmp_p == PARAM_ID_SPF_TIMEOUTS) {
			GSL_INFO("Get the spf timeout value success");
			tmp_pos = tmp_p;
			++tmp_p; /* Skip Param ID */
			++tmp_p; /* Skip Size */
			sv = (struct spf_timeouts_value *)tmp_p;
			SET_TIMEOUT_IF_VALID(sv->spf_timeout,
								GSL_SPF_TIMEOUT_MS_DEFAULT, GSL_SPF_TIMEOUT_MS);
			SET_TIMEOUT_IF_VALID(sv->graph_open_timeout,
								GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT, GSL_GRAPH_OPEN_TIMEOUT_MS);
			SET_TIMEOUT_IF_VALID(sv->graph_prepare_timeout,
								GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT, GSL_GRAPH_PREPARE_TIMEOUT_MS);
			SET_TIMEOUT_IF_VALID(sv->graph_start_stop_timeout,
								GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT, GSL_GRAPH_START_STOP_TIMEOUT_MS);
			SET_TIMEOUT_IF_VALID(sv->spf_read_write_timeout,
								GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT, GSL_SPF_READ_WRITE_TIMEOUT_MS);
			SET_TIMEOUT_IF_VALID(sv->amdb_load_modules_timeout,
								GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT, GSL_AMDB_LOAD_MODULES_TIMEOUT_MS);
			++sv;
			acdb_rsp.buf_size -= ((void *)sv - (void *)tmp_pos);
			tmp_p = (uint32_t *)sv;
		} else {
			GSL_ERR("got incorrect PID from ACDB %d", *((uint32_t *)acdb_rsp.buf));
			goto exit;
		}
	}

exit:
	if(acdb_rsp.buf)
		gsl_mem_free(acdb_rsp.buf);
	return rc;
}

int32_t gsl_spf_timeouts_init(void)
{
	int32_t rc = AR_EOK;
	rc = gsl_spf_timeouts_get_timeouts_from_acdb();
	if (rc) {
		GSL_ERR("get spf timeouts data failed rc %d, use the default value", rc);
		GSL_SPF_TIMEOUT_MS = GSL_SPF_TIMEOUT_MS_DEFAULT;
		GSL_GRAPH_OPEN_TIMEOUT_MS = GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT;
		GSL_GRAPH_PREPARE_TIMEOUT_MS = GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT;
		GSL_GRAPH_START_STOP_TIMEOUT_MS = GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT;
		GSL_SPF_READ_WRITE_TIMEOUT_MS = GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT;
		GSL_AMDB_LOAD_MODULES_TIMEOUT_MS = GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT;
	}
	GSL_INFO("GSL_SPF_TIMEOUT_MS[%d] GSL_GRAPH_OPEN_TIMEOUT_MS[%d]", GSL_SPF_TIMEOUT_MS,
			 GSL_GRAPH_OPEN_TIMEOUT_MS);
	GSL_INFO("GSL_GRAPH_PREPARE_TIMEOUT_MS[%d] GSL_GRAPH_START_STOP_TIMEOUT_MS[%d]",
			 GSL_GRAPH_PREPARE_TIMEOUT_MS, GSL_GRAPH_OPEN_TIMEOUT_MS);
	GSL_INFO("GSL_SPF_READ_WRITE_TIMEOUT_MS[%d]", GSL_SPF_READ_WRITE_TIMEOUT_MS);
	GSL_INFO("GSL_AMDB_LOAD_MODULES_TIMEOUT_MS[%d]", GSL_AMDB_LOAD_MODULES_TIMEOUT_MS);
	return AR_EOK;
}
