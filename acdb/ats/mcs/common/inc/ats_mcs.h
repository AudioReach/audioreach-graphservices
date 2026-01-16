#ifndef _ATS_MCS_H_
#define _ATS_MCS_H_
/**
*==============================================================================
* \file ats_mcs.h
* \brief
*                  A T S  F T S  H E A D E R  F I L E
*
*     The Media Control Service(MCS) header file contains all the
*     definitions necessary for ATS to handle requests that operate
*     the platform media controller.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include "ar_osal_types.h"

/*-----------------------------------------------------------------------------
* Defines and Constants
*----------------------------------------------------------------------------*/
#define ATS_MCS_MAJOR_VERSION 0x1
#define ATS_MCS_MINOR_VERSION 0x1

/* ---------------------------------------------------------------------------
* Public Functions
*-------------------------------------------------------------------------- */

/**
* \brief
*		The Media Control Service IOCTL
* \param [in] svc_cmd_id: The command to be issued
* \param [in] cmd_buf: Pointer to the command structure.
* \param [in] cmd_buf_size: Size of the command structure
* \param [out] rsp_buf: The response structre
* \param [in] rsp_buf_size: The size of the response
* \param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_mcs_ioctl(
    uint32_t svc_cmd_id,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled
);

/**
* \brief
*		Initializes the file transfer service to allow interaction between
*		ACDB SW and and QST clients.
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_mcs_init(void);

/**
* \brief
*		Deinitializes the file transfer service to allow interaction between
*		ACDB SW and and QST clients.
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_mcs_deinit(void);

/**
* \brief
*		Gets the MCS service version used by the platform layer.
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_mcs_get_version(uint32_t *major, uint32_t *minor);
#endif /*_ATS_MCS_H_*/
