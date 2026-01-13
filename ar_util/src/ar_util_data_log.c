/**
* \file ar_util_data_log.c
*
* \brief
*      Defines platform agnostic APIs for logging data through a data
*      transport(diag, tcpip, etc...)
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/

#include "ar_util_log_pkt_i.h"
#include "ar_util_data_log.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_log_pkt_op.h"
#include "ar_osal_types.h"

#define AR_DATA_LOG_LOG_TAG "AR Data Logger"
#define AR_DATA_LOG_ERR(...) AR_LOG_ERR(AR_DATA_LOG_LOG_TAG, __VA_ARGS__)
#define AR_DATA_LOG_DBG(...) AR_LOG_DEBUG(AR_DATA_LOG_LOG_TAG, __VA_ARGS__)
#define AR_DATA_LOG_INFO(...) AR_LOG_INFO(AR_DATA_LOG_LOG_TAG, __VA_ARGS__)

/*
-------------------------------------------------------------------------------
|    Log packet info structure
-------------------------------------------------------------------------------
*/
typedef struct fragment_info_t
{
    uint32_t total_count;
    uint32_t number;
    uint32_t length;
    uint32_t offset;
}fragment_info_t;

/*
-------------------------------------------------------------------------------
|    Internal Helper Function Prototypes
-------------------------------------------------------------------------------
*/
int32_t _get_max_log_pkt_data_size(
    ar_log_pkt_type_t pkt_type, uint32_t *max_log_pkt_data_size);

void *_log_alloc_pkt(
    uint32_t buffer_size,    uint32_t log_code,
    bool_t handle_fragments, ar_log_pkt_type_t pkt_type);

static int32_t _log_bitsream_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info);

static int32_t _log_pcm_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info);

static int32_t _log_generic_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info);

static int32_t _log_raw_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size);

/*
-------------------------------------------------------------------------------
|    Public Functions
-------------------------------------------------------------------------------
*/
int32_t ar_data_log_init()
{
    int32_t status = AR_EOK;

    status = ar_log_pkt_op_init(NULL);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: "
            "Failed to initialize the data logging utility.", status);
    }
    return status;
}

int32_t ar_data_log_deinit()
{
    int32_t status = AR_EOK;

    status = ar_log_pkt_op_deinit();
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: "
            "Failed to de-initialize the data logging utility.", status);
    }
    return status;
}

bool_t ar_data_log_code_status(uint16_t log_code)
{
    return ar_log_code_status(log_code);
}

uint32_t ar_data_log_get_max_packet_size()
{
    return ar_log_pkt_get_max_size();
}

void *ar_data_log_alloc(ar_data_log_alloc_info_t *info)
{
    int32_t status = AR_EOK;
    uint32_t max_log_pkt_size = 0;

    if (!info)
        return NULL;

    status = _get_max_log_pkt_data_size(info->pkt_type, &max_log_pkt_size);
    if (AR_FAILED(status))
    {
        return NULL;
    }

    if (info->buffer_size > max_log_pkt_size)
    {
        AR_DATA_LOG_ERR("Status[%d]: "
            "buffer size of %d bytes is larger than max log packet size of %d bytes.",
            AR_EBADPARAM, info->buffer_size, max_log_pkt_size);
        return NULL;
    }

    return _log_alloc_pkt(
        info->buffer_size, info->log_code, FALSE, info->pkt_type);
}

int32_t ar_data_log_commit(ar_data_log_commit_info_t *info)
{
    int32_t status = AR_EOK;
    void *log_pkt = NULL;

    if (!info || !info->log_pkt_data)
    {
        AR_DATA_LOG_ERR("Status[%d]: Bad input parameter(s)",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    switch (info->pkt_type)
    {
    case AR_DATA_LOG_PKT_TYPE_AUDIO_PCM:
    {
        uint16_t i = 0;
        ar_data_log_pkt_pcm_t *log_pkt_pcm =
            (ar_data_log_pkt_pcm_t *)(
            (uint8_t *)info->log_pkt_data - sizeof(ar_data_log_pkt_pcm_t));

        ar_data_log_pcm_pkt_info_t *pcm_log_pkt_info =
            (ar_data_log_pcm_pkt_info_t*)info->pkt_info;

        ar_data_log_pcm_info_t *pcm_data_info_ptr = (ar_data_log_pcm_info_t *)(
            &pcm_log_pkt_info->data_info.pcm_data_fmt);

        ar_log_pkt_pcm_data_format_t *pcm_data_fmt = (ar_log_pkt_pcm_data_format_t *)(
            &(log_pkt_pcm->header.pcm_data_fmt));

        log_pkt_pcm->header.cmn_struct.tag = AR_AUDIOLOG_CNTR_LOG_HEADER;
        log_pkt_pcm->header.cmn_struct.size = sizeof(ar_log_pkt_pcm_header_t);
        log_pkt_pcm->header.cmn_struct.log_session_id = info->session_id;
        log_pkt_pcm->header.cmn_struct.log_fragment_number = 0;
        log_pkt_pcm->header.cmn_struct.fragment_size = info->buffer_size;
        log_pkt_pcm->header.cmn_struct.fragment_offset = 0;

        log_pkt_pcm->header.cmn_struct.user_session_info.tag = AR_AUDIOLOG_CNTR_USER_SESSION;
        log_pkt_pcm->header.cmn_struct.user_session_info.size = sizeof(ar_log_pkt_user_session_t);
        log_pkt_pcm->header.cmn_struct.user_session_info.user_session_id = 0;
        uint64_t timestamp = 0;// posal_timer_get_time(); ar osal needs to support timer op
        log_pkt_pcm->header.cmn_struct.user_session_info.time_stamp = timestamp;

        log_pkt_pcm->header.pcm_data_fmt.tag = AR_AUDIOLOG_CNTR_PCM_DATA_FORMAT;
        log_pkt_pcm->header.pcm_data_fmt.size = sizeof(ar_log_pkt_pcm_data_format_t);
        log_pkt_pcm->header.pcm_data_fmt.log_tap_id = info->log_tap_id;
        log_pkt_pcm->header.pcm_data_fmt.sampling_rate = pcm_log_pkt_info->data_info.pcm_data_fmt.sampling_rate;
        log_pkt_pcm->header.pcm_data_fmt.num_channels = pcm_log_pkt_info->data_info.pcm_data_fmt.num_channels;
        //  log_pkt_pcm->header.pcm_data_fmt.pcm_width     = pcm_log_pkt_info->data_info.pcm_data_fmt.pcm_width;
        log_pkt_pcm->header.pcm_data_fmt.interleaved = pcm_log_pkt_info->data_info.pcm_data_fmt.interleaved;

        if (NULL != pcm_data_info_ptr->channel_mapping)
        {
            for (i = 0; i < pcm_data_info_ptr->num_channels; i++)
            {
                pcm_data_fmt->channel_mapping[i] = (uint8_t)(
                    pcm_data_info_ptr->channel_mapping[i]);
            }
        }
        else /* Provide the default mapping */
        {
            for (i = 0; i < pcm_data_info_ptr->num_channels; i++)
            {
                pcm_data_fmt->channel_mapping[i] = (uint8_t)i + 1;
            }
        }

        /* Set the remaining channels elements as un-used */
        for (i = pcm_data_info_ptr->num_channels; i < AR_LOGGING_MAX_NUM_CH; i++)
        {
            pcm_data_fmt->channel_mapping[i] = 0;
        }

        log_pkt = (void*)log_pkt_pcm;
        break;

    }
    case AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM:
    {
        ar_data_log_pkt_bit_stream_t *log_pkt_bitstream =
            (ar_data_log_pkt_bit_stream_t *)(
            (uint8_t *)info->log_pkt_data - sizeof(ar_data_log_pkt_bit_stream_t));

        log_pkt_bitstream->header.cmn_struct.tag = AR_AUDIOLOG_CNTR_LOG_HEADER;
        log_pkt_bitstream->header.cmn_struct.size = sizeof(ar_log_pkt_bitstream_header_t);
        log_pkt_bitstream->header.cmn_struct.log_session_id = info->session_id;
        log_pkt_bitstream->header.cmn_struct.log_fragment_number = 0;
        log_pkt_bitstream->header.cmn_struct.fragment_size = info->buffer_size;
        log_pkt_bitstream->header.cmn_struct.fragment_offset = 0;

        log_pkt_bitstream->header.cmn_struct.user_session_info.tag = AR_AUDIOLOG_CNTR_USER_SESSION;
        log_pkt_bitstream->header.cmn_struct.user_session_info.size = sizeof(ar_log_pkt_user_session_t);
        log_pkt_bitstream->header.cmn_struct.user_session_info.user_session_id = 0;
        uint64_t timestamp = 0;//posal_timer_get_time(); ar osal needs to support timer op
        log_pkt_bitstream->header.cmn_struct.user_session_info.time_stamp = timestamp;

        log_pkt_bitstream->header.bs_data_fmt.tag = AR_AUDIOLOG_CNTR_BS_DATA_FORMAT;
        log_pkt_bitstream->header.bs_data_fmt.size = sizeof(ar_log_pkt_bitstream_data_format_t);
        log_pkt_bitstream->header.bs_data_fmt.log_tap_id = info->log_tap_id;
        log_pkt_bitstream->header.bs_data_fmt.media_fmt_id = 0;

        log_pkt = (void*)log_pkt_bitstream;
        break;
    }
    case AR_DATA_LOG_PKT_TYPE_GENERIC:
    {
        ar_data_log_generic_pkt_info_t *pkt_info =
            (ar_data_log_generic_pkt_info_t*)info->pkt_info;

        ar_data_log_pkt_generic_t *log_pkt_generic =
            (ar_data_log_pkt_generic_t *)(
            (uint8_t *)info->log_pkt_data - sizeof(ar_data_log_pkt_generic_t));

        log_pkt_generic->header.info.header_length = sizeof(ar_log_pkt_fragment_info_t) - sizeof(uint32_t);
        log_pkt_generic->header.info.fragment_count = 1;
        log_pkt_generic->header.info.fragment_num = 1;
        log_pkt_generic->header.info.fragment_length = (uint16_t)info->buffer_size;
        log_pkt_generic->header.info.fragment_offset = 0;
        log_pkt_generic->header.info.buffer_length = info->buffer_size;
        log_pkt_generic->header.info.time_stamp = pkt_info->log_time_stamp;

        log_pkt_generic->header.cmd.header_length = 1;
        log_pkt_generic->header.cmd.version = 1;
        log_pkt_generic->header.cmd.format_id = pkt_info->format;

        log_pkt = (void*)log_pkt_generic;
        break;
    }
    case AR_DATA_LOG_PKT_TYPE_RAW:
        log_pkt = info->log_pkt_data;
        break;
    default:
        AR_DATA_LOG_ERR("Status[%d]: The log packet Packet Type#%d given does"
            " not support the commit operation.",
            AR_EUNSUPPORTED, info->pkt_type);
        return AR_EUNSUPPORTED;
    }

    status = ar_log_pkt_commit(log_pkt);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: Unable to commit log packet for Packet Type#%d.",
            AR_EUNSUPPORTED, info->pkt_type);
    }

    return status;
}

int32_t ar_data_log_submit(ar_data_log_submit_info_t *info)
{
    int32_t     status = AR_EOK;
    int8_t      *buffer_ptr = NULL;
    uint32_t    remaining_buffer_size = 0;
    void        *log_pkt = NULL;
    uint32_t    log_pkt_size = 0;
    uint32_t    max_log_pkt_size = 0;
    uint8_t     interleaved = 0;
    uint32_t    num_channels = 0;
    bool_t      is_first_seg = TRUE;
    fragment_info_t fragment = { 0 };

    if (!info)
    {
        AR_DATA_LOG_ERR("Status[%d]: Bad input parameter", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (!ar_data_log_code_status(info->log_code))
    {
        AR_DATA_LOG_DBG("Log code 0x%x is not enabled.");
        return AR_EOK;
    }

    status = _get_max_log_pkt_data_size(info->pkt_type, &max_log_pkt_size);
    if (AR_FAILED(status))
    {
        return status;
    }

    buffer_ptr = info->buffer;
    remaining_buffer_size = info->buffer_size;

    fragment.total_count = (remaining_buffer_size % max_log_pkt_size) == 0 ?
        (remaining_buffer_size / max_log_pkt_size) :
        (remaining_buffer_size / max_log_pkt_size) + 1;

    while (remaining_buffer_size > 0)
    {
        if (remaining_buffer_size < max_log_pkt_size)
        {
            log_pkt_size = remaining_buffer_size;
        }
        else
        {
            log_pkt_size = max_log_pkt_size;
        }

        log_pkt = _log_alloc_pkt(
            log_pkt_size, info->log_code, TRUE, info->pkt_type);
        if (!log_pkt)
        {
            AR_DATA_LOG_ERR("Status[%d]: _log_alloc_pkt failed", AR_ENOMEMORY);
            return AR_ENOMEMORY;
        }
        fragment.length = log_pkt_size;

        switch (info->pkt_type)
        {
        case AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM:
            status = _log_bitsream_pkt(
                log_pkt, buffer_ptr, log_pkt_size,
                &fragment, info);
            break;
        case AR_DATA_LOG_PKT_TYPE_AUDIO_PCM:

            interleaved = ((ar_data_log_pcm_pkt_info_t*)
                info->pkt_info)->data_info.pcm_data_fmt.interleaved;
            num_channels = ((ar_data_log_pcm_pkt_info_t*)
                info->pkt_info)->data_info.pcm_data_fmt.num_channels;

            if ((max_log_pkt_size == log_pkt_size) &&
                (info->buffer_size > max_log_pkt_size) &&
                (TRUE == is_first_seg) &&
                (!interleaved))
            {
                is_first_seg = FALSE;
            }

            if (FALSE == is_first_seg)
            {
                fragment.number = AR_SEG_PKT;
            }

            status = _log_pcm_pkt(
                log_pkt, buffer_ptr, info->buffer_size,
                &fragment, info);

            break;
        case AR_DATA_LOG_PKT_TYPE_GENERIC:
            status = _log_generic_pkt(
                log_pkt, buffer_ptr, info->buffer_size,
                &fragment, info);
            break;
        case AR_DATA_LOG_PKT_TYPE_RAW:
            status = _log_raw_pkt(
                log_pkt, buffer_ptr, log_pkt_size);
            break;
        default:
            break;
        }

        if (AR_FAILED(status))
        {
            ar_log_pkt_free(log_pkt);
            return status;
        }

        fragment.number++;
        fragment.offset += log_pkt_size;
        remaining_buffer_size -= log_pkt_size;

        if (info->pkt_type == AR_DATA_LOG_PKT_TYPE_AUDIO_PCM && !interleaved)
        {
            buffer_ptr += log_pkt_size / num_channels;
            continue;
        }

        buffer_ptr += log_pkt_size;
    }

    buffer_ptr  = NULL;
    log_pkt     = NULL;

    return status;
}

void ar_data_log_free(void *log_pkt_payload_ptr, ar_log_pkt_type_t pkt_type)
{
    uint32_t log_header_size = 0;
    uint8_t *log_pkt_ptr = NULL;

    if (NULL == log_pkt_payload_ptr ||
        pkt_type == AR_DATA_LOG_PKT_TYPE_UNKNOWN)
    {
        AR_DATA_LOG_ERR("Status[%d]: Bad input parameter(s)",
            AR_EBADPARAM);
        return;
    }

    switch (pkt_type)
    {
    case AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM:
        log_header_size = (sizeof(ar_data_log_pkt_bit_stream_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_AUDIO_PCM:
        log_header_size = (sizeof(ar_data_log_pkt_pcm_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_GENERIC:
        log_header_size = (sizeof(ar_data_log_pkt_generic_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_RAW:
        break;
    default:
        break;
    }

    log_pkt_ptr = (uint8_t*)log_pkt_payload_ptr - log_header_size;

    ar_log_pkt_free(log_pkt_ptr);
}

/*
-------------------------------------------------------------------------------
|    Internal Helper Functions
-------------------------------------------------------------------------------
*/

int32_t _get_max_log_pkt_data_size(
    ar_log_pkt_type_t pkt_type, uint32_t *max_log_pkt_data_size)
{
    int32_t status = AR_EOK;
    uint32_t max_log_pkt_size = ar_log_pkt_get_max_size();
    uint32_t log_header_size = 0;

    if (0 == max_log_pkt_size)
    {
        AR_DATA_LOG_ERR("Status[%d]: The transport layer returned a "
            "max packet size of zero", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    switch (pkt_type)
    {
    case AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM:
        log_header_size = (uint32_t)sizeof(ar_data_log_pkt_bit_stream_t);
        break;
    case AR_DATA_LOG_PKT_TYPE_AUDIO_PCM:
        log_header_size = (uint32_t)sizeof(ar_data_log_pkt_pcm_t);
        break;
    case AR_DATA_LOG_PKT_TYPE_GENERIC:
        log_header_size = (uint32_t)sizeof(ar_data_log_pkt_generic_t);
        break;
    case AR_DATA_LOG_PKT_TYPE_RAW:
        break;
    default:
        status = AR_EUNSUPPORTED;

        AR_DATA_LOG_ERR("Status[%d]: Unsupported packet type %d",
            status, pkt_type);
        max_log_pkt_size = 0;
        log_header_size = 0;
    }

    *max_log_pkt_data_size = max_log_pkt_size - log_header_size;

    return status;
}

void *_log_alloc_pkt(
    uint32_t buffer_size,   uint32_t log_code,
    bool_t handle_fragments,  ar_log_pkt_type_t pkt_type)
{
    uint32_t log_pkt_size = 0;
    uint32_t log_header_size = 0;
    void     *log_pkt_ptr = NULL;
    void     *log_pkt_payload_ptr = NULL;

    switch (pkt_type)
    {
    case AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM:
        log_header_size = (sizeof(ar_data_log_pkt_bit_stream_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_AUDIO_PCM:
        log_header_size = (sizeof(ar_data_log_pkt_pcm_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_GENERIC:
        log_header_size = (sizeof(ar_data_log_pkt_generic_t));
        break;
    case AR_DATA_LOG_PKT_TYPE_RAW:
        break;
    default:
        AR_DATA_LOG_ERR("Status[%d]: Unsupported packet type %d",
            AR_EUNSUPPORTED, pkt_type);

        return NULL;
    }

    /* Caclulate total packet size including the data payload */
    log_pkt_size = (log_header_size + buffer_size);

    /* Allocate the log packet
    * log_alloc() returns pointer to the allocated log packet
    * Returns NULL if log code is disabled on the GUI
    */

    //AR_DATA_LOG_DBG("Req Pkt Size %u : bytes for log code 0x%X",
    //    log_pkt_size, log_code);

    log_pkt_ptr = ar_log_pkt_alloc((uint16_t)log_code, log_pkt_size);
    if (!log_pkt_ptr)
        return NULL;

    if (handle_fragments)
        return log_pkt_ptr;

    log_pkt_payload_ptr = (void*)((uint8_t*)log_pkt_ptr + log_header_size);

    return log_pkt_payload_ptr;
}

static int32_t _log_bitsream_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info)

{
    int32_t                             status = AR_EOK;
    ar_log_pkt_cmn_audio_header_t       *log_header_cmn;
    ar_log_pkt_bitstream_data_format_t  *bs_data_fmt;
    uint8_t                             *log_dst_ptr = NULL;
    ar_data_log_pkt_bit_stream_t        *bs_log_pkt;
    ar_data_log_pcm_pkt_info_t          *pcm_log_pkt_info = NULL;

    if (!log_pkt || !buffer || !fragment || !info)
    {
        AR_DATA_LOG_ERR("Status[%d]: Bad input parameter(s)",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (info->pkt_type != AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM)
    {
        AR_DATA_LOG_ERR("Status[%d]: Invalid packet type: "
            "%u for log code 0x%X", AR_EBADPARAM,
            info->pkt_type,
            info->log_code);
        return AR_EBADPARAM;
    }

    if (!info->pkt_info)
    {
        AR_DATA_LOG_ERR("Status[%d]: Packet info is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    pcm_log_pkt_info = (ar_data_log_pcm_pkt_info_t*)info->pkt_info;

    bs_log_pkt = (ar_data_log_pkt_bit_stream_t *)log_pkt;
    bs_data_fmt = (ar_log_pkt_bitstream_data_format_t *)(
        &(bs_log_pkt->header.bs_data_fmt));
    log_header_cmn = &(bs_log_pkt->header.cmn_struct);

    /*************** AUDIO_LOG_HEADER ***************/
    log_header_cmn->tag = AR_AUDIOLOG_CNTR_LOG_HEADER;
    log_header_cmn->size = sizeof(ar_log_pkt_bitstream_header_t);
    log_header_cmn->log_session_id = info->session_id;
    log_header_cmn->fragment_size = buffer_size;
    log_header_cmn->fragment_offset = fragment->offset;

    /* if pcm_log_pkt_info->seq_number_ptr is null, use
    * default fragment numbering scheme */
    if (!pcm_log_pkt_info->seq_number_ptr)
        log_header_cmn->log_fragment_number = fragment->number;
    else
        log_header_cmn->log_fragment_number =
        (*(pcm_log_pkt_info->seq_number_ptr))++;

    /*************** AUDIO_LOG_USER_SESSION ***************/
    log_header_cmn->user_session_info.tag = AR_AUDIOLOG_CNTR_USER_SESSION;
    log_header_cmn->user_session_info.size = sizeof(ar_log_pkt_user_session_t);
    /* User session ID is un-used */
    log_header_cmn->user_session_info.user_session_id = 0;
    log_header_cmn->user_session_info.time_stamp =
        pcm_log_pkt_info->log_time_stamp;

    /********** AUDIOLOG_BITSTREAM_DATA_FORAMT *************/
    bs_data_fmt->tag = AR_AUDIOLOG_CNTR_BS_DATA_FORMAT;
    bs_data_fmt->size = sizeof(ar_log_pkt_bitstream_data_format_t);
    bs_data_fmt->log_tap_id = info->log_tap_id;
    bs_data_fmt->media_fmt_id = pcm_log_pkt_info->data_info.media_fmt_id;

    log_dst_ptr = ((ar_data_log_pkt_bit_stream_t *)log_pkt)->payload;

    /* Populate the log packet payload with the buffer to be logged */
    status = ar_mem_cpy(
        log_dst_ptr, buffer_size,
        buffer, buffer_size);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_DBG("Status[%d]: Failed to mem-copy buffer "
            "fragment to log packet", status);
        return status;
    }

    status = ar_log_pkt_commit(log_pkt);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: Unable to commit bitstream log packet.",
            status);
    }

    return status;
}

static int32_t _log_pcm_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info)

{
    int32_t                             status = AR_EOK;
    ar_log_pkt_cmn_audio_header_t       *log_header_cmn = NULL;
    ar_log_pkt_pcm_data_format_t        *pcm_data_fmt = NULL;
    ar_data_log_pcm_info_t              *pcm_data_info_ptr = NULL;
    uint16_t                            i = 0;
    uint8_t                             *log_dst_ptr = NULL;
    ar_data_log_pkt_pcm_t               *pcm_log_pkt = NULL;
    bool_t                              is_seg_pkt = FALSE;
    uint16_t                            num_channels = 0;
    uint32_t                            num_bytes_per_channel = 0;
    uint32_t                            total_num_bytes_per_channel = 0;
    ar_data_log_pcm_pkt_info_t          *pcm_log_pkt_info = NULL;
    __UNREFERENCED_PARAM(buffer_size);
    if (!log_pkt || !buffer || !fragment || !info)
    {
        AR_DATA_LOG_ERR("Status[%d]: Bad input parameter(s)",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (info->pkt_type != AR_DATA_LOG_PKT_TYPE_AUDIO_PCM)
    {
        AR_DATA_LOG_ERR("Status[%d]: Invalid packet type: "
            "%u for log code 0x%X", AR_EBADPARAM,
            info->pkt_type,
            info->log_code);
        return AR_EBADPARAM;
    }

    if (!info->pkt_info)
    {
        AR_DATA_LOG_ERR("Status[%d]: Packet info is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    pcm_log_pkt         = (ar_data_log_pkt_pcm_t *)log_pkt;
    pcm_log_pkt_info    = (ar_data_log_pcm_pkt_info_t*)info->pkt_info;
    pcm_data_fmt        = (ar_log_pkt_pcm_data_format_t *)(
        &(pcm_log_pkt->header.pcm_data_fmt));
    pcm_data_info_ptr   = (ar_data_log_pcm_info_t *)(
        &pcm_log_pkt_info->data_info.pcm_data_fmt);

    log_header_cmn = &(pcm_log_pkt->header.cmn_struct);
    num_channels = pcm_data_info_ptr->num_channels;

    if (AR_SEG_PKT == fragment->number)
    {
        is_seg_pkt = TRUE;

        total_num_bytes_per_channel =
            info->buffer_size / num_channels;
    }

    /*************** AUDIO_LOG_HEADER ***************/
    log_header_cmn->tag = AR_AUDIOLOG_CNTR_LOG_HEADER;
    log_header_cmn->size = sizeof(ar_log_pkt_pcm_header_t);
    log_header_cmn->log_session_id = info->session_id;
    log_header_cmn->fragment_size = fragment->length;
    log_header_cmn->fragment_offset = fragment->offset;

    /* if pcm_log_pkt_info->seq_number_ptr is null, use
    * default fragment numbering scheme */
    if (!pcm_log_pkt_info->seq_number_ptr)
        log_header_cmn->log_fragment_number = fragment->number;
    else
        log_header_cmn->log_fragment_number =
        (*(pcm_log_pkt_info->seq_number_ptr))++;

    /*************** AUDIO_LOG_USER_SESSION ***************/
    log_header_cmn->user_session_info.tag = AR_AUDIOLOG_CNTR_USER_SESSION;
    log_header_cmn->user_session_info.size = sizeof(ar_log_pkt_user_session_t);
    /* User session ID is un-used */
    log_header_cmn->user_session_info.user_session_id = 0;
    log_header_cmn->user_session_info.time_stamp =
        pcm_log_pkt_info->log_time_stamp;

    /*************** AUDIOLOG_PCM_DATA_FORAMT ***************/
    pcm_data_fmt->tag = AR_AUDIOLOG_CNTR_PCM_DATA_FORMAT;
    pcm_data_fmt->size = sizeof(ar_log_pkt_pcm_data_format_t);
    pcm_data_fmt->log_tap_id = info->log_tap_id;
    pcm_data_fmt->sampling_rate = pcm_data_info_ptr->sampling_rate;
    pcm_data_fmt->num_channels = pcm_data_info_ptr->num_channels;
    pcm_data_fmt->pcm_width = pcm_data_info_ptr->bits_per_sample;
    pcm_data_fmt->interleaved = (pcm_data_info_ptr->interleaved == 0) ? 1 : 0;

    if (NULL != pcm_data_info_ptr->channel_mapping)
    {
        for (i = 0; i < pcm_data_info_ptr->num_channels; i++)
        {
            pcm_data_fmt->channel_mapping[i] = (uint8_t)(
                pcm_data_info_ptr->channel_mapping[i]);
        }
    }
    else /* Provide the default mapping */
    {
        for (i = 0; i < pcm_data_info_ptr->num_channels; i++)
        {
            pcm_data_fmt->channel_mapping[i] = (uint8_t)(i + 1);
        }
    }

    /* Set the remaining channels elements as un-used */
    for (i = pcm_data_info_ptr->num_channels; i < AR_LOGGING_MAX_NUM_CH; i++)
    {
        pcm_data_fmt->channel_mapping[i] = 0;
    }

    log_dst_ptr = ((ar_data_log_pkt_pcm_t *)log_pkt)->payload;


    /* Populate the log packet payload with the buffer to be logged */

    if (FALSE == is_seg_pkt)
    {
        status = ar_mem_cpy(
            log_dst_ptr, fragment->length,
            buffer, fragment->length);
    }
    else /* True */
    {
        num_bytes_per_channel = (fragment->length / num_channels);

        for (i = 0; i < num_channels; i++)
        {
            status = ar_mem_cpy(
                log_dst_ptr, num_bytes_per_channel,
                buffer, num_bytes_per_channel);
            log_dst_ptr += num_bytes_per_channel;
            buffer += total_num_bytes_per_channel;

            if (AR_FAILED(status))
                break;
        }
    }

    if (AR_FAILED(status))
    {
        if (is_seg_pkt)
        {
            AR_DATA_LOG_DBG("Status[%d]: Failed to mem-copy buffer "
                "fragment to log packet", AR_EFAILED);
        }
        else
        {
            AR_DATA_LOG_DBG("Status[%d]: Failed to mem-copy buffer "
                "fragment to log packet while looping through channels",
                AR_EFAILED);
        }
    }

    status = ar_log_pkt_commit(log_pkt);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: Unable to commit pcm log packet.",
            status);
    }

    return status;
}

static int32_t _log_generic_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size,
    fragment_info_t *fragment,
    ar_data_log_submit_info_t *info)
{
    int32_t                         status = AR_EOK;
    ar_data_log_generic_pkt_info_t  *pkt_info = NULL;
    ar_data_log_pkt_generic_t       *generic_log_pkt = NULL;

    if (info->pkt_type != AR_DATA_LOG_PKT_TYPE_GENERIC)
    {
        AR_DATA_LOG_ERR("Status[%d]: Invalid packet type: "
            "%u for log code 0x%X", AR_EBADPARAM,
            info->pkt_type,
            info->log_code);
        return AR_EBADPARAM;
    }

    pkt_info =
        (ar_data_log_generic_pkt_info_t*)info->pkt_info;
    generic_log_pkt =
        (ar_data_log_pkt_generic_t *)log_pkt;

    generic_log_pkt->header.info.header_length =
        sizeof(ar_log_pkt_fragment_info_t) - sizeof(uint32_t);
    generic_log_pkt->header.info.fragment_count = (uint16_t)fragment->total_count;
    generic_log_pkt->header.info.buffer_length = buffer_size;
    generic_log_pkt->header.info.session_id = info->session_id;
    generic_log_pkt->header.info.tap_point_id = info->log_tap_id;
    generic_log_pkt->header.info.token_id = pkt_info->token_id;
    generic_log_pkt->header.info.reserved = 0;
    generic_log_pkt->header.info.fragment_num = (uint16_t)fragment->number;
    generic_log_pkt->header.info.fragment_length = (uint16_t)fragment->length;
    generic_log_pkt->header.info.fragment_offset = fragment->offset;
    generic_log_pkt->header.info.time_stamp = pkt_info->log_time_stamp;

    generic_log_pkt->header.cmd.header_length = sizeof(ar_log_pkt_data_format_header_t) - sizeof(uint32_t);
    generic_log_pkt->header.cmd.version = 1;
    generic_log_pkt->header.cmd.format_id = (uint32_t)pkt_info->format;

    status = ar_mem_cpy(
        (uint8_t*)log_pkt + sizeof(ar_data_log_pkt_generic_t), fragment->length,
        (void*)buffer, fragment->length);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_DBG("Status[%d]: Failed to mem-copy buffer "
            "fragment to log packet", status);
        return status;
    }

    status = ar_log_pkt_commit(log_pkt);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: Unable to commit generic log packet.",
            status);
    }

    return status;
}

static int32_t _log_raw_pkt(
    void *log_pkt, int8_t *buffer, uint32_t buffer_size)
{
    int32_t     status = AR_EOK;
    uint32_t    max_log_pkt_size = ar_log_pkt_get_max_size();

    if (buffer_size > max_log_pkt_size)
    {
        return AR_EBADPARAM;
    }

    status = ar_mem_cpy(
        log_pkt, buffer_size,
        buffer, buffer_size);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_DBG("Status[%d]: Failed to mem-copy buffer "
            "fragment to log packet", status);
        return status;
    }

    status = ar_log_pkt_commit(log_pkt);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_ERR("Status[%d]: Unable to commit raw log packet.",
            status);
    }

    return status;
}
