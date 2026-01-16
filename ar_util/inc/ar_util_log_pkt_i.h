#ifndef AR_UTIL_LOG_PKT_I_H
#define AR_UTIL_LOG_PKT_I_H

/**
* \file ar_util_log_pkt_i.h
* \brief
*  Defines internal structures used by the data logging utility
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/

#include "ar_osal_types.h"

/* Log container tags */
#define AR_AUDIOLOG_CNTR_LOG_HEADER 0x0001      /** Container tag for the log header. */
#define AR_AUDIOLOG_CNTR_USER_SESSION 0x0002    /** Container tag for the user session. */
#define AR_AUDIOLOG_CNTR_PCM_DATA_FORMAT 0x0004 /** Container tag for the PCM data format. */
#define AR_AUDIOLOG_CNTR_BS_DATA_FORMAT 0x0005  /** Container tag for the bitstream data format. */

#define AR_LOGGING_MAX_NUM_CH 32 /** Maximum number of channels supported for multichannel PCM logging. */

#define AR_SEG_PKT (0xDEADBEEF) /** Magic number for indicating the fragmented packet. */

enum ar_util_interleaving_t
{
   AR_UTIL_INTERLEAVED,
   /**< Data for all channels is present in one buffer. The samples are
        interleaved per channel. */

   AR_UTIL_DEINTERLEAVED_PACKED,
   /**< Data for all channels is present in one buffer. All of the samples of
        one channel are present, followed by all of the samples of
        the next channel, etc. */

   AR_UTIL_DEINTERLEAVED_UNPACKED,
   /**< Data for each channel is present in a different buffer. In this case,
        the capi_stream_data_t::buf_ptr field points to an array of buffer
        structures with the number of elements equal to the number of channels.
        The bufs_num field must be set to the number of channels. */

   AR_UTIL_INVALID_INTERLEAVING = 0xFFFFFFFF
   /**< Interleaving is not valid. */
};

/*==========================================================================
  Structure definitions
  ========================================================================== */
/* Overall log packet structure
*   For PCM data, the containers are in following order:
*       AUDIOLOG_HEADER
*       AUDIOLOG_USER_SESSION
*       AUDIOLOG_PCM_DATA_FORMAT
*
*   For Bitsream data:
*       AUDIOLOG_HEADER
*       AUDIOLOG_USER_SESSION
*       AUDIOLOG_BITSTREAM_DATA_FORMAT
*
*   For RAW data
*       n/a (there are no containers)
*
*   For Generic Packet Data
*       DATA_LOG_HEADER
*       COMMAND_HEADER
*       DATA
*/

/** User session container.  */
typedef struct ar_log_pkt_user_session_t
{
   uint16_t size;               /**< Size information for this container. */
   uint16_t tag;                /**< Tag information for this container. */
   uint32_t user_session_id;    /**< User session ID. Currently not used; set this parameter to zero. */
   uint64_t time_stamp;         /**< Timestamp (in microseconds) for the log packet. */
}
ar_log_pkt_user_session_t;

/** Audio log PCM data format container. */
typedef struct ar_log_pkt_pcm_data_format_t
{
   uint16_t size;                                   /**< Size information for this container. */
   uint16_t tag;                                    /**< Tag information for this container. */
   uint32_t log_tap_id;                             /**< GUID for the tap point. */
   uint32_t sampling_rate;                          /**< PCM sampling rate (8000 Hz, 48000 Hz, etc.). */
   uint16_t num_channels;                           /**< Number of channels in the PCM stream. */
   uint8_t pcm_width;                               /**< Bits per sample for the PCM data. */
   uint8_t interleaved;                             /**< Specifies whether the data is interleaved. */
   uint8_t channel_mapping[AR_LOGGING_MAX_NUM_CH];  /**< Array of channel mappings. @newpagetable */
}
ar_log_pkt_pcm_data_format_t;

/** Audio log bitstream data format container. */
typedef struct ar_log_pkt_bitstream_data_format_t
{
   uint16_t size;           /**< Size information for this container. */
   uint16_t tag;            /**< Tag information for this container. */
   uint32_t log_tap_id;     /**< GUID for the tap point. */
   uint32_t media_fmt_id;   /**< Media format ID for the audio/voice encoder/decoder. */
}
ar_log_pkt_bitstream_data_format_t;

/** Common header structure for PCM/bitstream data. */
typedef struct ar_log_pkt_cmn_audio_header_t
{
   uint16_t size;                   /**< Size information for this container. */
   uint16_t tag;                    /**< Tag information for this container. */
   uint32_t log_session_id;         /**< Log session ID. */
   uint32_t log_fragment_number;    /**< Log fragment number. */
   uint32_t fragment_size;          /**< Size in bytes of the payload, excluding the header. */
   uint32_t fragment_offset;        /**< Fragment offset. Currently not used. */
   ar_log_pkt_user_session_t
       user_session_info;           /**< Audio log user session. */
}
ar_log_pkt_cmn_audio_header_t;

typedef struct ar_log_pkt_fragment_info_t
{
    uint16_t header_length;    /**< The size of this header not including header_length */
    uint16_t fragment_count;   /**< The total number of buffer fragments */
    uint32_t buffer_length;    /**< The total Length of the client buffer being logged */
    uint32_t session_id;       /**< Log session ID. */
    uint32_t tap_point_id;     /**< Tap point ID. */
    uint32_t token_id;         /**< A unique identifier for the client */
    uint32_t reserved;         /**< Used for maintaining 8 byte alignment */
    uint16_t fragment_num;     /**< The packet fragment number */
    uint16_t fragment_length;  /**< The length of the buffer fragment which is at most
                               AR_UTIL_DATA_LOGGER_MAX_LOG_PKT_SIZE */
    uint32_t fragment_offset;  /**< Offset of the fragment in the client buffer */
    uint64_t time_stamp;       /**< The time stamp in microseconds of when the packet is
                               committed */
}ar_log_pkt_fragment_info_t;

/**< Data log header for General Purpose. */
typedef struct ar_log_pkt_data_format_header_t
{
    uint16_t header_length;  /**< The this structure not including header_length */
    uint16_t version;        /**< The header version. */
    uint32_t format_id;      /**< The Format ID used to identify the format of the
                                  data after this header */
}
ar_log_pkt_data_format_header_t;

/**< Audio log packet header for PCM data. */
typedef struct ar_log_pkt_pcm_header_t
{
   ar_log_pkt_cmn_audio_header_t cmn_struct;  /**< Common header structure for
                                                   PCM/bitstream data. */
   ar_log_pkt_pcm_data_format_t pcm_data_fmt; /**< Audio log PCM data format. */
}
ar_log_pkt_pcm_header_t;

/** Audio log packet header for bitstream data. */
typedef struct ar_log_pkt_bitstream_header_t
{
   ar_log_pkt_cmn_audio_header_t cmn_struct;       /**< Common header structure for
                                                        PCM/bitstream data. */
   ar_log_pkt_bitstream_data_format_t bs_data_fmt; /**< Audio log bitstream data format. */
}
ar_log_pkt_bitstream_header_t;

/** Log packet header for command based packets. */
typedef struct ar_log_pkt_generic_header_t
{
    ar_log_pkt_fragment_info_t info;     /**< Information about the log packet that will be used
                                              by packet recievers to re-assemble buffers sent
                                              by clients*/
    ar_log_pkt_data_format_header_t cmd; /**< The command header describing the packet contents */
}
ar_log_pkt_generic_header_t;

/*==========================================================================
  Log Packet Structures
  ========================================================================== */

/**< Log Packet for PCM Data */
typedef struct ar_data_log_pkt_pcm_t
{
   ar_log_pkt_pcm_header_t
       header;             /**< Audio log header for PCM data. */
   uint8_t payload[0];     /**< Contains the logged pcm data. */
}
ar_data_log_pkt_pcm_t;

/**< Log Packet for bitstream data. */
typedef struct ar_data_log_pkt_bit_stream_t
{
   ar_log_pkt_bitstream_header_t
       header;              /**< Audio log header for bitstream data. */
   uint8_t payload[0];      /**< Contains the logged bitsream data. */
}
ar_data_log_pkt_bit_stream_t;

/**< Generic Log packet for general purpose use */
typedef struct ar_data_log_pkt_generic_t
{
    ar_log_pkt_generic_header_t
        header;           /**< General purpose log header. */
    uint8_t payload[0];   /**< Contains the logged data. */
}
ar_data_log_pkt_generic_t;

/**< Raw Log packet
typedef struct ar_data_log_pkt_raw_t
{
    uint8_t payload[0];   // Contains the raw data.
}
ar_data_log_pkt_raw_t;
*/

#endif /* AR_UTIL_LOG_PKT_I_H */
