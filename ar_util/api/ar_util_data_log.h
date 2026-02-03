#ifndef AR_UTIL_DATA_LOG_H
#define AR_UTIL_DATA_LOG_H

/**
* \file ar_util_data_log.h
* \brief
*      Defines platform agnostic APIs for logging data through a data
*      transport(diag, tcpip, etc...)
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/

#include "ar_osal_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** An enumeration of the log packet types supported by the utility. */
typedef enum ar_log_pkt_type_t
{
    AR_DATA_LOG_PKT_TYPE_UNKNOWN         = 0x00,  /**< Unknown log packet*/
    AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM = 0x01, /**< Bitstream log packet format. */
    AR_DATA_LOG_PKT_TYPE_AUDIO_PCM       = 0x02, /**< PCM Log packet. */
    AR_DATA_LOG_PKT_TYPE_GENERIC         = 0x03, /**< A general purpose log packets that adds headers
                                                      for handling fragmentation and re-assembly */
    AR_DATA_LOG_PKT_TYPE_RAW             = 0x04 /**< A raw data packet where data is sent as is */
} ar_log_pkt_type_t;

typedef enum ar_data_log_generic_fmt_t
{
    AR_LOG_PKT_GENERIC_FMT_CAL_BLOB = 0x5043414C, /**< 'P''C''A''L'. Calibration Blob data format */
    AR_LOG_PKT_GENERIC_FMT_RAW      = 0x52415720  /**< 'R''A''W'''. Raw data format */
}ar_data_log_generic_fmt_t;

/** PCM data format information for the logging utility user. */
typedef struct ar_data_log_pcm_info_t
{
    uint32_t sampling_rate;      /**< PCM sampling rate.
                                 @values 8000 Hz, 48000 Hz, etc. */
    uint16_t num_channels;       /**< Number of channels in the PCM stream. */
    uint8_t bits_per_sample;     /**< Bits per sample for the PCM data. */
    uint8_t interleaved;         /**< Specifies whether the data is interleaved. */
    uint16_t *channel_mapping;   /**< Array of channel mappings. */
} ar_data_log_pcm_info_t;

/** Format of the data being logged: PCM or bitstream. */
typedef struct ar_data_log_audio_fmt_info_t
{
    ar_data_log_pcm_info_t
        pcm_data_fmt;           /**< Format of the PCM data. */
    uint32_t media_fmt_id;      /**< Format of the bitstream data. */
} ar_data_log_audio_fmt_info_t;

/**< Log Packet allocation information */
typedef struct ar_data_log_alloc_info_t
{
    uint32_t log_code;          /**< The log code used for logging */
    uint32_t buffer_size;       /**< The length of the buffer to log */
    ar_log_pkt_type_t pkt_type; /**< The type of packet to use for logging data */
} ar_data_log_alloc_info_t;

/**< Contains information needed to log a packet through
the ar_data_log_commit(...) API */
typedef struct ar_data_log_commit_info_t
{
    uint32_t session_id;            /**< The session id for the log packet */
    uint32_t log_tap_id;            /**< The log tap point id */
    uint32_t buffer_size;           /**< The length of the buffer to log */
    ar_log_pkt_type_t pkt_type;     /**< The type of packet to use for logging data */
    void *pkt_info;                 /**< Pointer to the packet info structure that is
                                         determined by pkt_type. See "Packet Info Structures".
                                         For Raw packets, set this to NULL */
    void *log_pkt_data;             /**< Pointer to the data section of the log packet */
} ar_data_log_commit_info_t;

/**< Contains information needed to log a buffer through
the ar_data_log_submit(...) API.*/
typedef struct ar_data_log_submit_info_t
{
    uint16_t log_code;              /**< The log code used for logging */
    uint32_t session_id;            /**< The session id for the log packet */
    uint32_t log_tap_id;            /**< The log tap point id */
    ar_log_pkt_type_t pkt_type;     /**< The type of packet to use for logging data */
    void *pkt_info;                 /**< Pointer to the packet info structure that is
                                         determined by pkt_type. See "Packet Info Structures".
                                         For Raw packets, set this to NULL */
    uint32_t buffer_size;           /**< The length of the buffer to log */
    int8_t *buffer;                 /**< Pointer to the buffer to be logged. */
} ar_data_log_submit_info_t;

/*
-------------------------------------------------------------------------------
    Packet Info Structures
-------------------------------------------------------------------------------
*/

/**< Additional packet information for PCM/Bitstream packets used in
conjunction with the pkt_info field in ar_data_log_submit_info_t
and ar_data_log_commit_info_t */
typedef struct ar_data_log_pcm_pkt_info_t
{
    uint64_t log_time_stamp;        /**< Timestamp in microseconds. */
    ar_data_log_audio_fmt_info_t
             data_info;             /**< Pointer to the data packet information. */
    uint32_t *seq_number_ptr;       /**< Reference to sequence number
                                         variable shared by client. */
}ar_data_log_pcm_pkt_info_t;

/**< Additional packet information for General purpose packets used in
conjunction with the pkt_info field in ar_data_log_submit_info_t
and ar_data_log_commit_info_t */
typedef struct ar_data_log_generic_pkt_info_t
{
    uint64_t log_time_stamp;            /**< Timestamp in microseconds. */
    uint32_t token_id;                  /**< Used to distinguish the logging source of
                                             a packet or set of packets */
    ar_data_log_generic_fmt_t format;   /**< Specifies the command format to use in
                                             the generic log packet */
}ar_data_log_generic_pkt_info_t;

/*
-------------------------------------------------------------------------------
    Data Logging Formats for AR_DATA_LOG_PKT_TYPE_GENERIC
-------------------------------------------------------------------------------
*/

typedef struct ar_data_log_blob_fmt_t
{
    uint32_t data_size;             /**< The length in bytes of the data that
                                         follows this header */
    uint8_t data[0];                /**< The data */
}ar_data_log_blob_fmt_t;

/*=============================================================================
Function Declarations
=============================================================================*/
/**
* \brief
*   Initializes the data logging utility
*
* \return
*   AR_EOK             : on success
*   AR_E<other error>  : on failure
*
* \dependencies
*   None
*/
int32_t ar_data_log_init(void);

/**
* \brief
*   Deitializes the data logging utility
*
* \return
*   AR_EOK             : on success
*   AR_E<other error>  : on failure
*
* \dependencies
*   None
*/
int32_t ar_data_log_deinit(void);

/**
 * \brief
 *   Checks whether the log code is enabled
 *
 * \return
 *   TRUE   : is enabled
 *   FALSE  : is disabled
 *
 * \dependencies
 *   None
 */
bool_t ar_data_log_code_status(uint16_t log_code);

/**
* \brief
*   Returns the max log packet size
*
* \dependencies
*   None
*/
uint32_t ar_data_log_get_max_packet_size(void);

/**
* \brief
*   Allocates a data log packet
*
* \param[in] info: Contains the info needed to allocate a log packet
*
* \dependencies
*   None.
*
* \return
*   Pointer to the payload of the allocated log packet.
*   Returns NULL if buffer allocation fails or log code is disabled.
*
*   +---------------++----------------+
*   | Packet Header || Packet Payload |
*   +---------------++----------------+
*                     /\
*/
void *ar_data_log_alloc(ar_data_log_alloc_info_t *info);

/**
* Commits a packet for logging. The log header is populated by this call.
* The client fills in the data portion of the packet.
*
* \param[in] info:  A pointer to the commit info structure that contains
*                   info needed to commit a packet.
*
* \dependencies
* A log packet needs to be allocated with ar_data_log_alloc(...)
* before calling ar_data_log_commit
*
* \return
* 0 -- Success
* \par
* Nonzero -- Failure
*
*/
int32_t ar_data_log_commit(ar_data_log_commit_info_t *info);

/**
* \brief
*   Segments a buffer into log packets and commits each packet for data logging.
*   Log packet allocation and disposal are automatically taken care of.
*
* \param[in] info:  A pointer to the submit info structure that contains
*                   the buffer to log as well as info for creating the
*                   log packet
*
* \return
* 0       -- Success
* Nonzero -- Failure
*
* \dependencies
* None
*/
int32_t ar_data_log_submit(ar_data_log_submit_info_t *info);

/**
* \brief
*   Releases the memory allocated for a log packet
*
* \param[in] log_ptr  : pointer to the payload of the data log packet
* \param[in] pkt_type : the type of packet that needs to be freed
*
* \return
* None.
*
* \dependencies
*   Must call ar_data_log_alloc(..) before freeing
*   Only pointers returned after calling ar_data_log_alloc(..) can be freed
*/
void ar_data_log_free(void *log_pkt_payload_ptr, ar_log_pkt_type_t pkt_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* AR_UTIL_DATA_LOG_H */