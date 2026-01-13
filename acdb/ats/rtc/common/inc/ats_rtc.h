#ifndef __ATS_RTC_H__
#define __ATS_RTC_H__
/**
*==============================================================================
* \file ats_rtc.h
* \brief
*				A T S  R T C  H E A D E R  F I L E
*
*	The Realtime Calibration Service(RTC) header file contains all the
*	definitions necessary for ATS to handle requests that operate the DSP
*
* \copyright
*	  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*	  SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include "gsl_rtc_intf.h"

#define ATS_RTC_MAJOR_VERSION 0x1
#define ATS_RTC_MINOR_VERSION 0x3

/**
	\brief
	The Online Service IOCTL

	\param [in] svc_cmd_id: The command to be issued
	\param [in] cmd_buf: Pointer to the command structure.
	\param [in] cmd_buf_size:
	\param [out] rsp_buf: The response structre
	\param [in] rsp_buf_size: The size of the response
	\param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer

	\return 0 on success, non-zero on failure
*/
int32_t ats_rtc_ioctl(
	uint32_t svc_cmd_id,
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled
);

/**
	\brief
	Initializes the Realtime Calibration to allow interaction between ACDB SW and and QST clients.

	\return 0 on success, non-zero on failure
*/
int32_t ats_rtc_init(void);

/**
	\brief
	Deinitializes the Realtime Calibration service to allow interaction between ACDB SW and and QST clients.

	\return 0 on success, non-zero on failure
*/
int32_t ats_rtc_deinit(void);

#endif /*__ATS_RTC_H__*/
