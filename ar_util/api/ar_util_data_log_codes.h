#ifndef AR_UTIL_DATA_LOG_CODES_H
#define AR_UTIL_DATA_LOG_CODES_H

/**
* \file ar_util_data_log.h
* \brief
*      Defines log codes used by the AR Util Data Logging Utility
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/

/** Log codes for audio/voice data path logging. */

#define AR_DATA_LOG_CODE_UNUSED 0x0            /**< Unused. */
#define AR_DATA_LOG_CODE_AUD_DEC_IN 0x152E     /**<  audio decoder input. */
#define AR_DATA_LOG_CODE_AUD_POPP_IN 0x152F    /**<  audio POPP input. */
#define AR_DATA_LOG_CODE_AUD_COPP_IN 0x1531    /**<  audio COPP input. */
#define AR_DATA_LOG_CODE_AUD_POPREP_IN 0x1534  /**<  audio POPREP input. */
#define AR_DATA_LOG_CODE_AUD_COPREP_IN 0x1532  /**<  audio COPREP input. */
#define AR_DATA_LOG_CODE_AUD_MTMX_RX_IN 0x1530 /**<  audio matrix Rx input. */
#define AR_DATA_LOG_CODE_AUD_MTMX_TX_IN 0x1533 /**<  audio matrix Tx input. */
#define AR_DATA_LOG_CODE_AUD_ENC_IN 0x1535     /**<  audio encoder input. */
#define AR_DATA_LOG_CODE_AUD_ENC_OUT 0x1536    /**<  audio encoder output. */
#define AR_DATA_LOG_CODE_AFE_RX_TX_OUT 0x1586  /**<  AFE Rx output and AFE Tx input. */
#define AR_DATA_LOG_CODE_VPTX 0x158A           /**<  vptx near and far input and output. */
#define AR_DATA_LOG_CODE_VPRX 0x158A           /**< Logs PCM data at vprx output. */
#define AR_DATA_LOG_CODE_VOC_ENC_IN 0x158B     /**<  voice encoder input  */
#define AR_DATA_LOG_CODE_VOC_PKT_OUT 0x14EE    /**<  voice encoder output . */
#define AR_DATA_LOG_CODE_VOC_PKT_IN 0x14EE     /**<  voice decoder input. */
#define AR_DATA_LOG_CODE_VOC_DEC_OUT 0x158B    /**<  voice decoder output. */
#define AR_DATA_LOG_CODE_AFE_ALGO_CALIB 0x17D8 /**< Logs run-time parameters of algorithms in AFE. */
#define AR_DATA_LOG_CODE_PP_RTM 0x184B         /**< Logs RTM parameters of algorithms in PP. */
#define AR_DATA_LOG_CODE_LSM_OUTPUT 0x1882     /**<  LSM output. */
#define AR_DATA_LOG_CODE_AUD_DEC_OUT 0x19AF    /**<  audio Decoder output. */
#define AR_DATA_LOG_CODE_AUD_COPP_OUT 0x19B0   /**<  audio COPP output. */
#define AR_DATA_LOG_CODE_AUD_POPP_OUT 0x19B1   /**<  audio POPP output. */
#define AR_DATA_LOG_CODE_ATS 0x14A7            /**<  Audio Tuning Service Log Code */

#endif /* AR_UTIL_DATA_LOGGER_H */