#ifndef _ATS_ADIE_RTC_H_
#define _ATS_ADIE_RTC_H_
/**
*==============================================================================
*  \file ats_adie-rtc.h
*  \brief
*                   A T S  A D I E  R T C  H E A D E R  F I L E
*
*      The ADIE(Codec) RTC Service(ARTC) header file contains all the
*      definitions necessary for ATS to handle requests that operate on
*      codec registers.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/
#include "ats.h"
#include "acdb.h"

/*-----------------------------------------------------------------------------
* Defines and Constants
*----------------------------------------------------------------------------*/
#define ATS_ADIE_RTC_MAJOR_VERSION 0x1
#define ATS_ADIE_RTC_MINOR_VERSION 0x2

//const char* LOG_TAG = "ATS-ADIE-RTC";
/* ---------------------------------------------------------------------------
* Public Functions
*-------------------------------------------------------------------------- */

/**
* \brief
*		The Codec Realtime Calibration Service IOCTL
* \param [in] svc_cmd_id: The command to be issued
* \param [in] cmd_buf: Pointer to the command structure.
* \param [in] cmd_buf_size: Size of the command structure
* \param [out] rsp_buf: The response structre
* \param [in] rsp_buf_size: The size of the response
* \param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_adie_rtc_ioctl(
    uint32_t svc_cmd_id,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled
);

/**
* \brief
*		Initializes the codec realtime calibration service to
*       allow interaction between ATS Clients device codec registers
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_adie_rtc_init(void);

/**
* \brief
*		Deinitializes the codec realtime calibration service
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_adie_rtc_deinit(void);

/**
* \brief
*		Gets the ADIE RTC service version used by the platform layer
* \return AR_EOK on success, non-zero otherwise
*/
int32_t ats_adie_rtc_get_version(uint32_t* major, uint32_t* minor);
#endif /*_ATS_ADIE_RTC_H_*/