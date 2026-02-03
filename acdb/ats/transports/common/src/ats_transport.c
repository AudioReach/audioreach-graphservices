/**
*=============================================================================
* \file ats_transport.c
* \brief
*                    A T S  T R A N S P O R T  A P I
*
*   This file implements APIs for initializing/deinitializing ATS transports.
*
* \detdesc
*	When adding a new transport, define a preprocessor macro for
*   enabling/disabling the transport. Not every platform may support your
*   transport. It is up to the platform to decide if a transport is supported
*   by enabling the preprocessor macro associated with the transport.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/
#include "ats_transport_api.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"

/* Transport includes */
#include "tcpip_server_api.h"
#include "actp.h"

#define LOG_TAG  "ATS Transport"
#define ATS_TRANSPORT_ERR(...) AR_LOG_ERR(LOG_TAG, __VA_ARGS__)
#define ATS_TRANSPORT_DBG(...) AR_LOG_DEBUG(LOG_TAG, __VA_ARGS__)
#define ATS_TRANSPORT_INFO(...) AR_LOG_INFO(LOG_TAG, __VA_ARGS__)

#if !defined(ATS_TRANSPORT_DIAG) && !defined(ATS_TRANSPORT_TCPIP)
/* The DIAG transport is the default transport. If no transports are
 * specified in the build configuration then ATS_TRANSPORT_DIAG
 * will be defined */
#define ATS_TRANSPORT_DIAG
#endif

int32_t ats_transport_init(ats_cmd_rsp_callback_t cmd_rsp_callback)
{
    int32_t status = AR_EOK;

    #if defined(ATS_TRANSPORT_TCPIP)
	status = tcpip_cmd_server_init(cmd_rsp_callback);
	if (AR_FAILED(status))
	{
		ATS_TRANSPORT_ERR(
            "Error[%d]: Failed to initialize "
			"ATS TCP/IP Server", status);
	}
    #endif

    #if defined(ATS_TRANSPORT_DIAG)
    status = actp_diag_init(cmd_rsp_callback);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to initialize Diag", status);
	}
    #endif

    //Init Other Transport

    return status;
}

int32_t ats_transport_deinit(void)
{
    int32_t status = AR_EOK;

    //Init TCPIP Server
    #if defined(ATS_TRANSPORT_TCPIP)
	status = tcpip_cmd_server_deinit();
	if (AR_FAILED(status))
	{
		ATS_TRANSPORT_ERR(
            "Error[%d]: Failed to deinitialize "
			"ATS TCP/IP Server", status);
	}
    #endif

    //Init Diag Transport
    #if defined(ATS_TRANSPORT_DIAG)
    status = actp_diag_deinit();
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to deinitialize Diag", status);
	}
    #endif

    return status;
}

int32_t ats_transport_dls_send_callback(const uint8_t* buffer, uint32_t buffer_size)
{
	#if defined(ATS_TRANSPORT_TCPIP)

	ATS_TRANSPORT_DBG("Sending %d bytes", buffer_size);
	return tcpip_cmd_server_send_dls_log_data(buffer, buffer_size);

	#else
	__UNREFERENCED_PARAM(buffer);
	__UNREFERENCED_PARAM(buffer_size);
	/* We dont need to support diag since it already has support for pushing
	 * binary log packets to the ats realtime tuning client */

	return AR_EUNSUPPORTED;
	#endif
}
