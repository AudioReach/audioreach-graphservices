#ifndef _ATS_ONLINE_H_
#define _ATS_ONLINE_H_
/**
*==============================================================================
* \file ats_online.h
* \brief
*                  A T S  O N L I N E  H E A D E R  F I L E
*
*      The Online Calibration Service(ONC) header file contains all the
*      definitions necessary for ATS to handle requests that operate ACDB SW
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*-----------------------------------------------------------------------------
* Includes
*----------------------------------------------------------------------------*/
#include "acdb.h"

/*-----------------------------------------------------------------------------
* Defines and Constants
*----------------------------------------------------------------------------*/
#define ATS_ONC_MAJOR_VERSION 0x1
#define ATS_ONC_MINOR_VERSION 0x4

/* ---------------------------------------------------------------------------
* Public Functions
*-------------------------------------------------------------------------- */

/**
* \brief ats_online_ioctl
*		The Online Service IOCTL
* \param [in] cmd_id: The command to be issued
* \param [in] cmd_buf: Pointer to the command structure.
* \param [in] cmd_buf_size:
* \param [out] rsp_buf: The response structre
* \param [in] rsp_buf_size: The size of the response
* \param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer
* \return 0 on success, non-zero on failure
*/
int32_t ats_online_ioctl(
	uint32_t svc_cmd_id,
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled
);

/**
* \brief ats_online_init
*		Initializes the online service to allow interaction between
*		ACDB SW and and QST clients.
* \return 0 on success, non-zero on failure
*/
int32_t ats_online_init(void);

/**
* \brief ats_online_deinit
*		Initializes the online service to allow interaction between
*		ACDB SW and and QST clients.
* \return 0 on success, non-zero on failure
*/
int32_t ats_online_deinit(void);

#endif /*_ATS_ONLINE_H_*/
