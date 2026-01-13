#ifndef __ATS_DLS_H__
#define __ATS_DLS_H__
/**
*==============================================================================
* \file ats_dls.h
* \brief
*                                 A T S  D L S
                               H E A D E R  F I L E
*
*	The Data Logging Service header file defines an interface for initializing,
*	handling dls commands from the ATS realtime tuning client, and
*	pushing binary log packet push events to the ATS realtime tuning client.
*
* \copyright
*	  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*	  SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

#include "gsl_dls_client_intf.h"

#define ATS_DLS_MAJOR_VERSION 0x1
#define ATS_DLS_MINOR_VERSION 0x0

typedef int32_t (*ATS_DSL_TCPIP_SEND_CALLBACK)(const uint8_t* buffer, uint32_t buffer_size);
// int32_t ats_transport_dls_send_callback(const uint8_t* buffer, uint32_t buffer_size);

/**
	\brief
	The Data Logging Service IOCTL

	\param [in] svc_cmd_id: The command to be issued
	\param [in] cmd_buf: Pointer to the command structure.
	\param [in] cmd_buf_size:
	\param [out] rsp_buf: The response structre
	\param [in] rsp_buf_size: The size of the response
	\param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer

	\return 0 on success, non-zero on failure
*/
    int32_t ats_dls_ioctl(
	uint32_t svc_cmd_id,
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled
);

/**
* \brief Initializes the gsl dls client
*
* \param [in] callback: The callback function that is invoked when spf notifies
*                       gsl about ready dls log buffers
* \return 0 on success, non-zero on failure
*/
int32_t ats_dls_init(ATS_DSL_TCPIP_SEND_CALLBACK callback);


/**
* \brief Releases resources aquired during ats_dls_init(...). These resources
* include:
*	1. the dls shared memory pool
*	2. the ats dls packet buffer for sending binary packets through the dls tcpip server
*
* \param [in] callback: The callback function that is invoked when spf notifies
*                       gsl about ready dls log buffers
* \return 0 on success, non-zero on failure
*/
int32_t ats_dls_deinit(void);

#endif /*__ATS_DLS_H__*/
