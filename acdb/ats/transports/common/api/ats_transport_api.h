#ifndef _ATS_TRANSPORT_API_H_
#define _ATS_TRANSPORT_API_H_
/**
*=============================================================================
* \file ats_transport_api.h
* \brief
*                    A T S  T R A N S P O R T  A P I
*
*   This file defines APIs for initializing/deinitializing ATS transports.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "ar_osal_types.h"

/**
* \brief
*      The command + response callback used to pass request to the
*      application layer and return responses to the transport layer
*
* \param [in] req_buffer: The request buffer containing the command to execute
* \param [in] req_buffer_length: The length of the request buffer
* \param [in/out] resp_buffer: The response buffer returned after executing the command
* \param [out] resp_buffer_length: The length of the response buffer
* \return 0 on success, non-zero on failure
*/
typedef void(*ats_cmd_rsp_callback_t)(
    uint8_t *req_buffer, uint32_t req_buffer_length,
    uint8_t **resp_buffer, uint32_t *resp_buffer_length);

/**
* \brief ats_transport_init
*      Initializes the transport layer. One or more transports can be initialized depending
*      on the build configuration see implementation of ats_transport_init
*
* \param [in] cmd_rsp_callback: A callback to ats_exectue_command
*
* \return 0 on success, non-zero on failure
*/
int32_t ats_transport_init(ats_cmd_rsp_callback_t cmd_rsp_callback);

/**
 * \brief ats_transport_deinit
 *		De-initializes the transport layer by realeasing resources aquired during ats_transport_init
 * \return 0 on success, non-zero on failure
 */
int32_t ats_transport_deinit(void);

/**
 * \brief ats_transport_dls_send_callback
 *		Sends binary log data through the transport layer
 * \param [in] buffer: the buffer containing the data to send
 * \param [in] buffer_size: the size of the buffer
 * \return 0 on success, non-zero on failure
 */
int32_t ats_transport_dls_send_callback(const uint8_t* buffer, uint32_t buffer_size);

#endif /*_ATS_TRANSPORT_API_H_*/

