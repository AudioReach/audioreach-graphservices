/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_file_io.h"
#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "ar_osal_test.h"
#include "ar_osal_log.h"
#include "ar_osal_heap.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_string.h"
#include "ar_osal_log_pkt_op.h"
#include "ar_util_data_log.h"
#include "ar_util_data_log_codes.h"
#include "ar_util_log_pkt_i.h"

/* Test Notes
*
*
*/

#define AR_DATA_LOG_TEST_LOG_TAG "AR Data Logger Test"
#define AR_DATA_LOG_TEST_ERR(...) AR_LOG_ERR(AR_DATA_LOG_TEST_LOG_TAG, __VA_ARGS__)
#define AR_DATA_LOG_TEST_DBG(...) AR_LOG_DEBUG(AR_DATA_LOG_TEST_LOG_TAG, __VA_ARGS__)
#define AR_DATA_LOG_TEST_INFO(...) AR_LOG_INFO(AR_DATA_LOG_TEST_LOG_TAG, __VA_ARGS__)

#define AR_TEST_DATA_LOG_FILE "ar_util_data_log_commit.bin"
#define AR_TEST_DIAG_PKT_HEADER_LENGTH 12

typedef struct ar_test_buffer_t
{
    size_t size;
    uint32_t offset;
    void* buffer;
}ar_test_buffer_t;

/*****************************************************************************
* Function Callbacks
******************************************************************************/

typedef int32_t (*ar_test_read_pkt_callback_t)(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    void *info,
    ar_test_buffer_t *rsp_buffer);

typedef int32_t(*ar_test_reassemble_msg_callback_t)(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func);

/*****************************************************************************
* Function Prototypes
******************************************************************************/

int32_t ar_test_pcm_data_logging(ar_heap_info *heap_info);
int32_t ar_test_bitstream_data_logging(ar_heap_info *heap_info);
int32_t ar_test_generic_data_logging(ar_heap_info *heap_info);
int32_t ar_test_raw_data_logging(ar_heap_info *heap_info);
int32_t ar_util_test_data_log_file_read(
    const char_t *file, uint32_t file_access,
    void *read_data, size_t read_size, size_t *file_size, size_t *bytes_read);
int32_t ar_test_verify_message(ar_heap_info *heap_info,
    ar_test_buffer_t *expected_buffer,
    ar_test_read_pkt_callback_t read_pkt_func,
    ar_test_reassemble_msg_callback_t reassemble_pkt_buffer_func);

int32_t ar_test_read_pcm_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_cmn_audio_header_t *info,
    ar_test_buffer_t *rsp_buffer);
int32_t ar_test_read_bitstream_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_cmn_audio_header_t *info,
    ar_test_buffer_t *rsp_buffer);
int32_t ar_test_read_generic_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_fragment_info_t *info,
    ar_test_buffer_t *rsp_buffer);
int32_t ar_test_read_raw_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    void *info,
    ar_test_buffer_t *rsp_buffer);

int32_t ar_test_reassemble_pcm_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func);
int32_t ar_test_reassemble_bitstream_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func);
int32_t ar_test_reassemble_generic_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func);
int32_t ar_test_reassemble_raw_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func);

void ar_test_data_log_submit();
void ar_test_data_log_commit();

int32_t ar_test_pcm_data_logging_commit(ar_heap_info *heap_info);
int32_t ar_test_bitstream_data_logging_commit(ar_heap_info *heap_info);
int32_t ar_test_generic_data_logging_commit(ar_heap_info *heap_info);
int32_t ar_test_raw_data_logging_commit(ar_heap_info *heap_info);

/*****************************************************************************
* Test Functions
******************************************************************************/

void ar_test_data_log_main()
{
    AR_DATA_LOG_TEST_DBG("START: Data Logging 'Submit' tests");
    ar_test_data_log_submit();
    AR_DATA_LOG_TEST_DBG("END: Data Logging 'Submit' tests");

    AR_DATA_LOG_TEST_DBG("START: Data Logging 'Commit' tests");
    ar_test_data_log_commit();
    AR_DATA_LOG_TEST_DBG("END: Data Logging 'Commit' tests");
}

void ar_test_data_log_submit()
{
    // Create *.bin file to store test data
    char_t *file = "ar_util_data_log_commit.bin";
    int32_t status = AR_EOK;
    uint32_t num_tests = 0;
    //Heap
    ar_heap_info heap_info =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };

    /* PCM Logging:         Submit a buffer */
    ar_fdelete(file);
    ar_test_pcm_data_logging(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* Bitstream Logging:   Submit a buffer */
    ar_fdelete(file);
    ar_test_bitstream_data_logging(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* Generic Logging:     Submit a buffer */
    ar_fdelete(file);
    ar_test_generic_data_logging(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* RAW Logging:         Submit a buffer */
    ar_fdelete(file);
    ar_test_raw_data_logging(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;
}

void ar_test_data_log_commit()
{
    // Create *.bin file to store test data
    char_t *file = "ar_util_data_log_commit.bin";
    int32_t status = AR_EOK;
    uint32_t num_tests = 0;
    //Heap
    ar_heap_info heap_info =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };

    /* PCM Logging:         Commit a packet */
    ar_fdelete(file);
    status = ar_test_pcm_data_logging_commit(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* Bitstream Logging:   Commit a packet */
    ar_fdelete(file);
    status = ar_test_bitstream_data_logging_commit(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* Generic Logging:     Commit a packet */
    ar_fdelete(file);
    status = ar_test_generic_data_logging_commit(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;

    /* Raw Logging:         Commit a packet */
    ar_fdelete(file);
    status = ar_test_raw_data_logging_commit(&heap_info);
    if (AR_SUCCEEDED(status)) num_tests++;
}
/*****************************************************************************
* Data logging 'Commit' Tests
******************************************************************************/

int32_t ar_test_pcm_data_logging_commit(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    uint32_t max_pkt_length = ar_data_log_get_max_packet_size();
    uint32_t data_length = max_pkt_length  - sizeof(ar_data_log_pkt_pcm_t);
    ar_test_buffer_t expected_buffer = { 0 };
    ar_data_log_pcm_pkt_info_t pkt_info = { 0 };
    ar_data_log_commit_info_t commit_info = { 0 };
    ar_data_log_alloc_info_t dla_info = { 0 };
    void* log_pkt_data = NULL;

    const int16_t square_wave[] =
    {
        /* Start of channel 1 */
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
    };

    expected_buffer.buffer = (void*)square_wave;
    expected_buffer.size = sizeof(square_wave);

    /* Allocate one log packet */
    dla_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    dla_info.pkt_type = AR_DATA_LOG_PKT_TYPE_AUDIO_PCM;
    dla_info.buffer_size = data_length;
    log_pkt_data = ar_data_log_alloc(&dla_info);

    ar_mem_cpy(log_pkt_data, sizeof(square_wave),
        square_wave, sizeof(square_wave));

    /* Set up packet information */
    uint32_t seq_number = 0xFEED0000;
    pkt_info.seq_number_ptr = &seq_number;
    pkt_info.log_time_stamp = 0;
    pkt_info.data_info.media_fmt_id = 0;
    pkt_info.data_info.pcm_data_fmt.num_channels = 2;
    pkt_info.data_info.pcm_data_fmt.bits_per_sample = 16;
    pkt_info.data_info.pcm_data_fmt.sampling_rate = 8000;
    pkt_info.data_info.pcm_data_fmt.interleaved = 0;
    /* use default channel map */
    pkt_info.data_info.pcm_data_fmt.channel_mapping = NULL;

    commit_info.buffer_size = max_pkt_length;
    commit_info.log_pkt_data = log_pkt_data;
    commit_info.log_tap_id = 0;
    commit_info.pkt_info = &pkt_info;
    commit_info.pkt_type = dla_info.pkt_type;
    commit_info.session_id = 0;

    status = ar_data_log_commit(&commit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to commit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &expected_buffer, ar_test_read_pcm_pkt,
        ar_test_reassemble_pcm_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "PCM Packet Logging 'commit' test failed", status);
    }

    return status;
}

int32_t ar_test_bitstream_data_logging_commit(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    uint32_t max_pkt_length = ar_data_log_get_max_packet_size();
    uint32_t data_length = max_pkt_length - sizeof(ar_data_log_pkt_bit_stream_t);
    ar_test_buffer_t expected_buffer = { 0 };
    ar_data_log_pcm_pkt_info_t pkt_info = { 0 };
    ar_data_log_commit_info_t commit_info = { 0 };
    ar_data_log_alloc_info_t dla_info = { 0 };
    void* log_pkt_data = NULL;

    const int16_t square_wave[] =
    {
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
    };

    expected_buffer.buffer = (void*)square_wave;
    expected_buffer.size = sizeof(square_wave);

    /* Allocate one log packet */
    dla_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    dla_info.pkt_type = AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM;
    dla_info.buffer_size = data_length;
    log_pkt_data = ar_data_log_alloc(&dla_info);

    ar_mem_cpy(log_pkt_data, sizeof(square_wave),
        square_wave, sizeof(square_wave));

    /* Set up packet information */
    uint32_t seq_number = 0xFEED0000;
    pkt_info.seq_number_ptr = &seq_number;
    pkt_info.log_time_stamp = 0;
    pkt_info.data_info.media_fmt_id = 0;
    pkt_info.data_info.pcm_data_fmt.num_channels = 2;
    pkt_info.data_info.pcm_data_fmt.bits_per_sample = 16;
    pkt_info.data_info.pcm_data_fmt.sampling_rate = 8000;
    pkt_info.data_info.pcm_data_fmt.interleaved = 0;
    /* use default channel map */
    pkt_info.data_info.pcm_data_fmt.channel_mapping = NULL;

    commit_info.buffer_size = dla_info.buffer_size;
    commit_info.log_pkt_data = log_pkt_data;
    commit_info.log_tap_id = 0;
    commit_info.pkt_info = &pkt_info;
    commit_info.pkt_type = dla_info.pkt_type;
    commit_info.session_id = 0;

    status = ar_data_log_commit(&commit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to commit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &expected_buffer, ar_test_read_bitstream_pkt,
        ar_test_reassemble_bitstream_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Bitstream Packet Logging 'commit' test failed", status);
    }

    return status;
}

int32_t ar_test_generic_data_logging_commit(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    uint32_t max_pkt_length = ar_data_log_get_max_packet_size();
    uint32_t data_length = max_pkt_length - sizeof(ar_data_log_pkt_generic_t);
    ar_test_buffer_t expected_buffer = { 0 };
    ar_data_log_generic_pkt_info_t pkt_info = { 0 };
    ar_data_log_commit_info_t commit_info = { 0 };
    ar_data_log_alloc_info_t dla_info = { 0 };
    void* log_pkt_data = NULL;

    const char_t msg[] =
        "This is a carefully written 68 byte"
        " message to test generic packets";

    expected_buffer.buffer = (void*)msg;
    expected_buffer.size = sizeof(msg);

    /* Allocate one log packet */
    dla_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    dla_info.pkt_type = AR_DATA_LOG_PKT_TYPE_GENERIC;
    dla_info.buffer_size = data_length;
    log_pkt_data = ar_data_log_alloc(&dla_info);

    ar_mem_cpy(log_pkt_data, sizeof(msg),
        msg, sizeof(msg));

    /* Set up packet information */
    pkt_info.format = AR_LOG_PKT_GENERIC_FMT_RAW;
    pkt_info.log_time_stamp = 0;

    commit_info.buffer_size = dla_info.buffer_size;
    commit_info.log_pkt_data = log_pkt_data;
    commit_info.log_tap_id = 0;
    commit_info.pkt_info = &pkt_info;
    commit_info.pkt_type = dla_info.pkt_type;
    commit_info.session_id = 0;

    status = ar_data_log_commit(&commit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to commit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &expected_buffer, ar_test_read_generic_pkt,
        ar_test_reassemble_generic_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Bitstream Packet Logging 'commit' test failed", status);
    }

    return status;
}

int32_t ar_test_raw_data_logging_commit(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    uint32_t max_pkt_length = ar_data_log_get_max_packet_size();
    ar_test_buffer_t expected_buffer = { 0 };
    ar_data_log_commit_info_t commit_info = { 0 };
    ar_data_log_alloc_info_t dla_info = { 0 };
    void* log_pkt_data = NULL;

    const char_t msg[] =
        "This is a carefully written 116 byte message for testing"
        "the raw packet 'commit' functionality for sending a packet.";

    expected_buffer.buffer = (void*)msg;
    expected_buffer.size = sizeof(msg);

    /* Allocate one log packet */
    dla_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    dla_info.pkt_type = AR_DATA_LOG_PKT_TYPE_RAW;
    dla_info.buffer_size = max_pkt_length;
    log_pkt_data = ar_data_log_alloc(&dla_info);

    ar_mem_cpy(log_pkt_data, sizeof(msg),
        msg, sizeof(msg));

    /* Set up packet information */
    commit_info.buffer_size = dla_info.buffer_size;
    commit_info.log_pkt_data = log_pkt_data;
    commit_info.log_tap_id = 0;
    commit_info.pkt_info = NULL;
    commit_info.pkt_type = dla_info.pkt_type;
    commit_info.session_id = 0;

    status = ar_data_log_commit(&commit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to commit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &expected_buffer, ar_test_read_raw_pkt,
        ar_test_reassemble_raw_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Raw Packet Logging 'commit' test failed", status);
    }

    return status;
}

/*****************************************************************************
* Data logging 'Submit' Tests
******************************************************************************/

int32_t ar_test_pcm_data_logging(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    ar_test_buffer_t data_buffer = { 0 };
    ar_test_buffer_t expected_buffer = { 0 };
    ar_data_log_pcm_pkt_info_t pkt_info = { 0 };
    ar_data_log_submit_info_t submit_info = { 0 };

    /* Generate data to submit */
    const int16_t square_wave[] =
    {
        /* Start of channel 1 */
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,

        /* Start of channel 2 */
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,
    };

    const int16_t expected_square_wave[] =
    {
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,/*Channel 1*/
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,/*Channel 2*/
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,/*Channel 1*/
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,/*Channel 2*/
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,/*Channel 1*/
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,/*Channel 2*/
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,/*Channel 1*/
        0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA, 0xDDAA,/*Channel 2*/
    };

    data_buffer.buffer = (void*)square_wave;
    data_buffer.size = sizeof(square_wave);

    expected_buffer.buffer = (void*)expected_square_wave;
    expected_buffer.size = sizeof(square_wave);

    /* Set up packet information */
    uint32_t seq_number = 0xFEED0000;
    pkt_info.seq_number_ptr = &seq_number;
    pkt_info.log_time_stamp = 0;
    pkt_info.data_info.media_fmt_id = 0;
    pkt_info.data_info.pcm_data_fmt.num_channels = 2;
    pkt_info.data_info.pcm_data_fmt.bits_per_sample = 16;
    pkt_info.data_info.pcm_data_fmt.sampling_rate = 8000;
    pkt_info.data_info.pcm_data_fmt.interleaved = 0;
    /* use default channel map */
    pkt_info.data_info.pcm_data_fmt.channel_mapping = NULL;

    submit_info.buffer = (int8_t*)data_buffer.buffer;
    submit_info.buffer_size = (uint32_t)data_buffer.size;
    submit_info.pkt_info = &pkt_info;
    submit_info.pkt_type = AR_DATA_LOG_PKT_TYPE_AUDIO_PCM;
    submit_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    submit_info.log_tap_id = 0;
    submit_info.session_id = 0;

    status = ar_data_log_submit(&submit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to submit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &expected_buffer, ar_test_read_pcm_pkt,
        ar_test_reassemble_pcm_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "PCM Packet Logging test failed", status);
    }

    return status;
}

int32_t ar_test_bitstream_data_logging(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    ar_test_buffer_t data_buffer = { 0 };
    ar_data_log_pcm_pkt_info_t pkt_info = { 0 };
    ar_data_log_submit_info_t submit_info = { 0 };

    /* Generate data to submit */
    const int16_t square_wave[] =
    {
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,
        0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021, 0x0021,

        0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF,
        0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF,
        0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF,
        0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF, 0xFFDF,

        0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011,
        0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011,
        0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011,
        0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011,

        0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF,
        0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF,
        0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF,
        0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF, 0xCCDF,

        0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
        0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
        0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
        0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,

        0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF,
        0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF,
        0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF,
        0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF, 0xAADF,
    };

    data_buffer.buffer = (void*)square_wave;
    data_buffer.size = sizeof(square_wave);

    /* Set up packet information */
    uint32_t seq_number = 0xFEED0000;
    pkt_info.seq_number_ptr = &seq_number;
    pkt_info.log_time_stamp = 0;
    pkt_info.data_info.media_fmt_id = 0;
    pkt_info.data_info.pcm_data_fmt.num_channels = 2;
    pkt_info.data_info.pcm_data_fmt.bits_per_sample = 16;
    pkt_info.data_info.pcm_data_fmt.sampling_rate = 8000;
    pkt_info.data_info.pcm_data_fmt.interleaved = 1;
    /* use default channel map */
    pkt_info.data_info.pcm_data_fmt.channel_mapping = NULL;

    submit_info.buffer = (int8_t*)data_buffer.buffer;
    submit_info.buffer_size = (uint32_t)data_buffer.size;
    submit_info.pkt_info = &pkt_info; /* Null for RAW packets */
    submit_info.pkt_type = AR_DATA_LOG_PKT_TYPE_AUDIO_BITSTREAM;
    submit_info.log_code = AR_DATA_LOG_CODE_UNUSED;
    submit_info.log_tap_id = 0;
    submit_info.session_id = 0;

    status = ar_data_log_submit(&submit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to submit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &data_buffer, ar_test_read_bitstream_pkt,
        ar_test_reassemble_bitstream_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Bitstream Packet Logging test failed", status);
    }

    return status;
}

int32_t ar_test_generic_data_logging(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t param_count = 5;
    uint32_t param_data_size = 2 * sizeof(uint32_t);
    ar_test_buffer_t cal_data_buffer = { 0 };
    ar_data_log_generic_pkt_info_t pkt_info = { 0 };
    ar_data_log_submit_info_t submit_info = { 0 };

    struct test_param {
        uint32_t value;
        uint32_t reserved;
    };

    struct spf_cal_data_header {
        uint32_t instance_id;
        uint32_t param_id;
        uint32_t size;
        uint32_t error_code;
    };

    struct spf_cal_data_header param_cal_header = { 0 };
    struct test_param param_cal = { 0 };

    /* Generate data to submit */
    cal_data_buffer.size = param_count * (sizeof(struct spf_cal_data_header) + param_data_size);
    cal_data_buffer.buffer = ar_heap_malloc(
        cal_data_buffer.size, heap_info);

    param_cal_header.param_id   = 0xfeeddead;//Feed Dead
    param_cal_header.error_code = AR_EOK;
    param_cal_header.size       = param_data_size;
    param_cal.value             = 0xfade0000;//Fade

    for (uint32_t i = 0; i < param_count; i++)
    {
        param_cal_header.instance_id = i;

        status = ar_mem_cpy(
            (uint8_t*)cal_data_buffer.buffer + offset, sizeof(param_cal_header),
            (void*)&param_cal_header, sizeof(param_cal_header));
        offset += sizeof(param_cal_header);
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR(
                "Status[%d]: Unable to memcpy cal data header", status);
            goto end;
        }

        status = ar_mem_cpy(
            (uint8_t*)cal_data_buffer.buffer + offset, sizeof(param_cal),
            (void*)&param_cal, sizeof(param_cal));
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR(
                "Status[%d]: Unable to memcpy cal data", status);
            goto end;
        }

        offset += param_data_size;
        param_cal.value++;
    }

    /* Set up packet information */
    pkt_info.format = AR_LOG_PKT_GENERIC_FMT_CAL_BLOB;
    pkt_info.log_time_stamp = 0;

    submit_info.buffer = (int8_t*)cal_data_buffer.buffer;
    submit_info.buffer_size = (uint32_t)cal_data_buffer.size;
    submit_info.pkt_info = &pkt_info;
    submit_info.pkt_type = AR_DATA_LOG_PKT_TYPE_GENERIC;
    submit_info.log_code = AR_DATA_LOG_CODE_ATS;
    submit_info.log_tap_id = 0;
    submit_info.session_id = 0;

    status = ar_data_log_submit(&submit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to submit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &cal_data_buffer, ar_test_read_generic_pkt,
        ar_test_reassemble_generic_msg);

end:
    if(cal_data_buffer.buffer)
        ar_heap_free(cal_data_buffer.buffer, heap_info);

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Generic Packet Logging test failed", status);
    }
    return status;
}

int32_t ar_test_raw_data_logging(ar_heap_info *heap_info)
{
    int32_t status = AR_EOK;
    ar_test_buffer_t data_buffer = { 0 };
    ar_data_log_submit_info_t submit_info = { 0 };
    char_t *phrase = NULL;

    /* Generate data to submit
     *
     * The message needs to be long enough to make the data logging
     * utility split the message into multiple packets
     *
     * Lorem ipsum text
     */
    phrase =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
        "do eiusmod tempor incididunt ut labore et dolore magna "
        "aliqua. Ut enim ad minim veniam, quis nostrud exercitation "
        "ullamco laboris nisi ut aliquip ex ea commodo consequat. "
        "Duis aute irure dolor in reprehenderit in voluptate velit "
        "esse cillum dolore eu fugiat nulla pariatur. Excepteur "
        "sint occaecat cupidatat non proident, sunt in culpa qui "
        "officia deserunt mollit anim id est laborum.";

    data_buffer.buffer = phrase;
    data_buffer.size = 446;

    /* Set up packet information */
    submit_info.buffer = (int8_t*)data_buffer.buffer;
    submit_info.buffer_size = (uint32_t)data_buffer.size;
    submit_info.pkt_info = NULL; /* Null for RAW packets */
    submit_info.pkt_type = AR_DATA_LOG_PKT_TYPE_RAW;
    submit_info.log_code = AR_DATA_LOG_CODE_ATS;
    submit_info.log_tap_id = 0;
    submit_info.session_id = 0;

    status = ar_data_log_submit(&submit_info);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to submit buffer", status);
        goto end;
    }

    //parse pkt_data and compare payload
    status = ar_test_verify_message(heap_info,
        &data_buffer, ar_test_read_raw_pkt,
        ar_test_reassemble_raw_msg);

end:

    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Raw Packet Logging test failed", status);
    }

    return status;
}

/*****************************************************************************
* Parse Packets and return the submitted message buffer
******************************************************************************/

int32_t ar_test_read_pcm_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_cmn_audio_header_t *info,
    ar_test_buffer_t *rsp_buffer)
{
    int32_t status = AR_EOK;
    uint8_t *pkt_ptr = NULL;
    ar_data_log_pkt_pcm_t *log_pkt = NULL;

    if (!pkt_buffer || !heap_info || !info || !rsp_buffer)
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "One ore more input parameters are null", status);
        return AR_EBADPARAM;
    }

    pkt_ptr = (uint8_t*)pkt_buffer->buffer + pkt_buffer->offset;

    pkt_ptr += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    pkt_buffer->offset += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    log_pkt = (ar_data_log_pkt_pcm_t*)pkt_ptr;

    pkt_ptr += sizeof(ar_data_log_pkt_pcm_t)
        + log_pkt->header.cmn_struct.fragment_size;
    pkt_buffer->offset += sizeof(ar_data_log_pkt_pcm_t)
        + log_pkt->header.cmn_struct.fragment_size;

    info->fragment_size = log_pkt->header.cmn_struct.fragment_size;
    info->log_fragment_number = log_pkt->header.cmn_struct.log_fragment_number;
    info->fragment_offset = log_pkt->header.cmn_struct.fragment_offset;

    if (!rsp_buffer->buffer)
    {
        rsp_buffer->buffer = ar_heap_malloc(rsp_buffer->size, heap_info);
        if (!rsp_buffer->buffer)
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Not enough memory to allocate buffer", status);
            return AR_ENOMEMORY;
        }
    }

    status = ar_mem_cpy(
        (uint8_t*)rsp_buffer->buffer + info->fragment_offset,
        info->fragment_size,
        log_pkt->payload, info->fragment_size);
    if (AR_FAILED(status))
    {
        ar_heap_free(rsp_buffer->buffer, heap_info);

        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to copy packet to response buffer", status);
    }

    return status;
}

int32_t ar_test_read_bitstream_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_cmn_audio_header_t *info,
    ar_test_buffer_t *rsp_buffer)
{
    int32_t status = AR_EOK;
    uint8_t *pkt_ptr = NULL;
    ar_data_log_pkt_bit_stream_t *log_pkt = NULL;

    if (!pkt_buffer || !heap_info || !info || !rsp_buffer)
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "One ore more input parameters are null", status);
        return AR_EBADPARAM;
    }

    pkt_ptr = (uint8_t*)pkt_buffer->buffer + pkt_buffer->offset;

    pkt_ptr += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    pkt_buffer->offset += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    log_pkt = (ar_data_log_pkt_bit_stream_t*)pkt_ptr;

    pkt_ptr += sizeof(ar_data_log_pkt_bit_stream_t)
        + log_pkt->header.cmn_struct.fragment_size;
    pkt_buffer->offset += sizeof(ar_data_log_pkt_bit_stream_t)
        + log_pkt->header.cmn_struct.fragment_size;

    info->fragment_size = log_pkt->header.cmn_struct.fragment_size;
    info->log_fragment_number = log_pkt->header.cmn_struct.log_fragment_number;
    info->fragment_offset = log_pkt->header.cmn_struct.fragment_offset;

    if (!rsp_buffer->buffer)
    {
        rsp_buffer->buffer = ar_heap_malloc(rsp_buffer->size, heap_info);
        if (!rsp_buffer->buffer)
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Not enough memory to allocate buffer", status);
            return AR_ENOMEMORY;
        }
    }

    status = ar_mem_cpy(
        (uint8_t*)rsp_buffer->buffer + info->fragment_offset,
        info->fragment_size,
        log_pkt->payload, info->fragment_size);
    if (AR_FAILED(status))
    {
        ar_heap_free(rsp_buffer->buffer, heap_info);

        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to copy packet to response buffer", status);
    }

    return status;
}

int32_t ar_test_read_generic_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    ar_log_pkt_fragment_info_t *info,
    ar_test_buffer_t *rsp_buffer)
{
    int32_t status = AR_EOK;
    uint8_t *pkt_ptr = NULL;
    ar_data_log_pkt_generic_t *log_pkt = NULL;

    if (!pkt_buffer || !heap_info || !info || !rsp_buffer)
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "One ore more input parameters are null", status);
        return AR_EBADPARAM;
    }

    pkt_ptr = (uint8_t*)pkt_buffer->buffer + *pkt_buffer_offset;

    pkt_ptr += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    *pkt_buffer_offset += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    log_pkt = (ar_data_log_pkt_generic_t*)pkt_ptr;

    pkt_ptr += sizeof(ar_data_log_pkt_generic_t)
        + log_pkt->header.info.fragment_length;
    *pkt_buffer_offset += sizeof(ar_data_log_pkt_generic_t)
        + log_pkt->header.info.fragment_length;

    //pkt_buffer->offset += *pkt_buffer_offset;

    info->buffer_length = log_pkt->header.info.buffer_length;
    info->fragment_count = log_pkt->header.info.fragment_count;
    info->fragment_length = log_pkt->header.info.fragment_length;
    info->fragment_num = log_pkt->header.info.fragment_num;
    info->fragment_offset = log_pkt->header.info.fragment_offset;

    if (!rsp_buffer->buffer)
    {
        rsp_buffer->size = info->buffer_length;
        rsp_buffer->buffer = ar_heap_malloc(info->buffer_length, heap_info);
        if (!rsp_buffer->buffer)
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Not enough memory to allocate buffer", status);
            return AR_ENOMEMORY;
        }
    }

    status = ar_mem_cpy(
        (uint8_t*)rsp_buffer->buffer + info->fragment_offset,
        info->fragment_length,
        log_pkt->payload, info->fragment_length);
    if (AR_FAILED(status))
    {
        ar_heap_free(rsp_buffer->buffer, heap_info);

        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to copy packet to response buffer", status);
    }

    return status;
}

int32_t ar_test_read_raw_pkt(
    ar_heap_info *heap_info,
    ar_test_buffer_t *pkt_buffer,
    uint32_t *pkt_buffer_offset,
    void *info,
    ar_test_buffer_t *rsp_buffer)
{
    __UNREFERENCED_PARAM(info);

    int32_t status = AR_EOK;
    uint8_t *pkt_ptr = NULL;
    uint8_t *log_pkt = NULL;
    uint32_t pkt_data_length = 0;
    uint32_t pkt_length = 0;
    uint32_t size_remaining = 0;

    if (!pkt_buffer || !heap_info || !rsp_buffer)
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "One ore more input parameters are null", status);
        return AR_EBADPARAM;
    }

    size_remaining = (uint32_t)pkt_buffer->size - *pkt_buffer_offset;
    pkt_data_length = ar_log_pkt_get_max_size();
    pkt_length = AR_TEST_DIAG_PKT_HEADER_LENGTH + pkt_data_length;
    pkt_ptr = (uint8_t*)pkt_buffer->buffer + *pkt_buffer_offset;

    pkt_ptr += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    *pkt_buffer_offset += AR_TEST_DIAG_PKT_HEADER_LENGTH;
    log_pkt = pkt_ptr;

    if (!rsp_buffer->buffer)
    {
        rsp_buffer->buffer = ar_heap_malloc(rsp_buffer->size, heap_info);
        if (!rsp_buffer->buffer)
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Not enough memory to allocate buffer", status);
            return AR_ENOMEMORY;
        }
    }

    if (size_remaining < pkt_data_length)
        pkt_data_length = size_remaining - AR_TEST_DIAG_PKT_HEADER_LENGTH;

    status = ar_mem_cpy(
        (uint8_t*)rsp_buffer->buffer + rsp_buffer->offset,
        pkt_data_length,
        log_pkt, pkt_data_length);
    if (AR_FAILED(status))
    {
        ar_heap_free(rsp_buffer->buffer, heap_info);

        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to copy packet to response buffer", status);
    }

    *pkt_buffer_offset += pkt_data_length;

    return status;
}


//int32_t ar_test_parse_generic_pkt_file(ar_heap_info *heap_info, ar_test_buffer_t *expected_buffer)
//{
//    int32_t status = AR_EOK;
//    size_t bytes_read = 0;
//    uint32_t offset = 0;
//    uint32_t pkt_buffer_offset = 0;
//    char_t *file = "ar_util_data_log_commit.bin";
//    ar_test_buffer_t pkt_buffer = { 0 };
//    ar_test_buffer_t rsp_buffer = { 0 };
//    ar_log_pkt_fragment_info_t info = { 0 };
//
//    if (!heap_info || !expected_buffer)
//    {
//        AR_DATA_LOG_TEST_ERR("Status[%d]: "
//            "One ore more input parameters are null", status);
//        return AR_EBADPARAM;
//    }
//
//    /* Read file and reassemble buffer to ensure the same
//     * contents were sent successfully */
//    status = ar_util_test_data_log_file_read(
//        file, AR_FOPEN_READ_ONLY, pkt_buffer.buffer,
//        0, &pkt_buffer.size, &bytes_read);
//    if (AR_FAILED(status))
//    {
//        AR_DATA_LOG_TEST_ERR("Status[%d]: "
//            "Failed to get file size: %s", status, file);
//    }
//
//    pkt_buffer.buffer = ar_heap_malloc(pkt_buffer.size, heap_info);
//
//    status = ar_util_test_data_log_file_read(
//        file, AR_FOPEN_READ_ONLY, pkt_buffer.buffer,
//        pkt_buffer.size, &pkt_buffer.size, &bytes_read);
//    if (AR_FAILED(status))
//    {
//        AR_DATA_LOG_TEST_ERR("Status[%d]: "
//            "Failed to read file: %s", status, file);
//    }
//
//    /* Reassemble buffer by extracting payload from each packet.
//     * Get the first packet */
//    status = ar_test_read_generic_pkt(heap_info, &pkt_buffer,
//        &pkt_buffer_offset, &info, &rsp_buffer);
//    if (AR_FAILED(status))
//    {
//        AR_DATA_LOG_TEST_ERR("Status[%d]: "
//            "Failed to read file: %s", status, file);
//        return status;
//    }
//
//    //Read remaining packets if any
//    offset = info.fragment_length;
//    while (offset < info.buffer_length)
//    {
//        status = ar_test_read_generic_pkt(heap_info, &pkt_buffer,
//            &pkt_buffer_offset, &info, &rsp_buffer);
//        if (AR_FAILED(status))
//        {
//            AR_DATA_LOG_TEST_ERR("Status[%d]: "
//                "Failed to read file: %s", status, file);
//        }
//
//        offset += info.fragment_length;
//    }
//
//    //Compare response from packet to expected response
//    if ((expected_buffer->size != rsp_buffer.size) ||
//        0 != ar_mem_cmp(
//            expected_buffer->buffer, rsp_buffer.buffer, expected_buffer->size))
//    {
//        status = AR_EFAILED;
//        AR_DATA_LOG_TEST_ERR("Status[%d]: The expected response and "
//            "the packet response are different", status);
//    }
//
//    ar_heap_free(rsp_buffer.buffer, heap_info);
//
//    status = ar_fdelete(file);
//    if (AR_FAILED(status))
//    {
//        AR_DATA_LOG_TEST_ERR("Status[%d]: Failed to delete file", status);
//    }
//
//    return status;
//}

int32_t ar_test_reassemble_pcm_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t pkt_buffer_offset = 0;
    ar_log_pkt_cmn_audio_header_t info = { 0 };
    uint32_t pkt_data_length = ar_log_pkt_get_max_size()
        - sizeof(ar_log_pkt_pcm_header_t);
    uint32_t max_pkt_size = ar_log_pkt_get_max_size()
        + AR_TEST_DIAG_PKT_HEADER_LENGTH;
    uint32_t last_pkt_size = pkt_buffer->size % max_pkt_size;
    uint32_t last_pkt_data_length = last_pkt_size == 0 ? 0 :
        last_pkt_size
        - AR_TEST_DIAG_PKT_HEADER_LENGTH
        - sizeof(ar_log_pkt_pcm_header_t);
    uint32_t num_pkts = last_pkt_size == 0 ?
        (uint32_t)pkt_buffer->size / max_pkt_size :
        (uint32_t)pkt_buffer->size / max_pkt_size + 1;
    uint32_t pkt_index = 0;

    //determine total size of response msg buffer
    rsp_buffer->size = last_pkt_size == 0 ?
        (pkt_data_length)* num_pkts :
        (pkt_data_length) * (num_pkts - 1)
        + last_pkt_data_length;

    /* Reassemble buffer by extracting payload from each packet.
    * Get the first packet */
    status = read_pkt_func(heap_info, pkt_buffer,
        &pkt_buffer_offset, &info, rsp_buffer);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to generic pkt buffer", status);
        return status;
    }

    //Read remaining packets if any
    while (pkt_buffer->offset < pkt_buffer->size)
    {
        status = read_pkt_func(heap_info, pkt_buffer,
            &pkt_buffer_offset, &info, rsp_buffer);
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Failed to read raw pkt buffer", status);
        }
    }

    return status;
}

int32_t ar_test_reassemble_bitstream_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t pkt_buffer_offset = 0;
    ar_log_pkt_cmn_audio_header_t info = { 0 };
    uint32_t pkt_data_length = ar_log_pkt_get_max_size()
        - sizeof(ar_log_pkt_bitstream_header_t);
    uint32_t max_pkt_size = ar_log_pkt_get_max_size()
        + AR_TEST_DIAG_PKT_HEADER_LENGTH;
    uint32_t last_pkt_size = pkt_buffer->size % max_pkt_size;
    uint32_t last_pkt_data_length = last_pkt_size == 0 ? 0 :
        last_pkt_size
        - AR_TEST_DIAG_PKT_HEADER_LENGTH
        - sizeof(ar_log_pkt_bitstream_header_t);
    uint32_t num_pkts = last_pkt_size == 0 ?
        (uint32_t)pkt_buffer->size / max_pkt_size :
        (uint32_t)pkt_buffer->size / max_pkt_size + 1;
    uint32_t pkt_index = 0;

    //determine total size of response msg buffer
    rsp_buffer->size = last_pkt_size == 0 ?
        (pkt_data_length)* num_pkts :
        (pkt_data_length) * (num_pkts - 1)
        + last_pkt_data_length;

    /* Reassemble buffer by extracting payload from each packet.
    * Get the first packet */
    status = read_pkt_func(heap_info, pkt_buffer,
        &pkt_buffer_offset, &info, rsp_buffer);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to generic pkt buffer", status);
        return status;
    }

    //Read remaining packets if any
    while (pkt_buffer->offset < pkt_buffer->size)
    {
         status = read_pkt_func(heap_info, pkt_buffer,
            &pkt_buffer_offset, &info, rsp_buffer);
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Failed to read raw pkt buffer", status);
        }
    }

    return status;
}

int32_t ar_test_reassemble_generic_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t pkt_buffer_offset = 0;
    ar_log_pkt_fragment_info_t info = { 0 };

    /* Reassemble buffer by extracting payload from each packet.
    * Get the first packet */
    status = read_pkt_func(heap_info, pkt_buffer,
        &pkt_buffer_offset, &info, rsp_buffer);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to generic pkt buffer", status);
        return status;
    }

    //Read remaining packets if any
    offset = info.fragment_length;
    while (offset < info.buffer_length)
    {
        status = read_pkt_func(heap_info, pkt_buffer,
            &pkt_buffer_offset, &info, rsp_buffer);
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Failed to generic pkt buffer", status);
        }

        offset += info.fragment_length;
    }

    return status;
}

int32_t ar_test_reassemble_raw_msg(
    ar_test_buffer_t *pkt_buffer, ar_test_buffer_t *rsp_buffer,
    ar_heap_info *heap_info, ar_test_read_pkt_callback_t read_pkt_func)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t pkt_buffer_offset = 0;
    uint32_t pkt_data_length = ar_log_pkt_get_max_size();
    uint32_t max_pkt_size = ar_log_pkt_get_max_size()
        + AR_TEST_DIAG_PKT_HEADER_LENGTH;
    uint32_t last_pkt_size = pkt_buffer->size % max_pkt_size;
    uint32_t last_pkt_data_length = last_pkt_size == 0? 0:
        last_pkt_size - AR_TEST_DIAG_PKT_HEADER_LENGTH;
    uint32_t num_pkts = last_pkt_size == 0 ?
        (uint32_t)pkt_buffer->size / max_pkt_size :
        (uint32_t)pkt_buffer->size / max_pkt_size + 1;
    uint32_t pkt_index = 0;
    //determine total size of response buffer for raw packet data
    rsp_buffer->size = last_pkt_size == 0 ?
        (pkt_data_length) * num_pkts:
        (pkt_data_length) * (num_pkts - 1)
        + last_pkt_data_length;

    //Read remaining packets if any
    while (offset < pkt_buffer->size)
    {
        status = read_pkt_func(heap_info, pkt_buffer,
            &pkt_buffer_offset, NULL, rsp_buffer);
        if (AR_FAILED(status))
        {
            AR_DATA_LOG_TEST_ERR("Status[%d]: "
                "Failed to read raw pkt buffer", status);
        }

        if(pkt_index == num_pkts - 1 && last_pkt_size != 0)
            rsp_buffer->offset += last_pkt_data_length;
        else
            rsp_buffer->offset += pkt_data_length;


        offset += max_pkt_size;
        pkt_index++;
    }

    return status;
}

int32_t ar_test_verify_message(ar_heap_info *heap_info,
    ar_test_buffer_t *expected_msg,
    ar_test_read_pkt_callback_t read_pkt_func,
    ar_test_reassemble_msg_callback_t reassemble_msg_func)
{
    int32_t status = AR_EOK;
    size_t bytes_read = 0;
    uint32_t offset = 0;
    uint32_t pkt_buffer_offset = 0;
    char_t *file = "ar_util_data_log_commit.bin";
    ar_test_buffer_t pkt_buffer = { 0 };
    ar_test_buffer_t rsp_buffer = { 0 };

    if (!heap_info || !expected_msg)
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "One ore more input parameters are null", status);
        return AR_EBADPARAM;
    }

    /* Read file and reassemble buffer to ensure the same
    * contents were sent successfully */
    status = ar_util_test_data_log_file_read(
        file, AR_FOPEN_READ_ONLY, pkt_buffer.buffer,
        0, &pkt_buffer.size, &bytes_read);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to get file size: %s", status, file);
    }

    pkt_buffer.buffer = ar_heap_malloc(pkt_buffer.size, heap_info);

    status = ar_util_test_data_log_file_read(
        file, AR_FOPEN_READ_ONLY, pkt_buffer.buffer,
        pkt_buffer.size, &pkt_buffer.size, &bytes_read);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to read file: %s", status, file);
    }

    /* Reassemble buffer by extracting payload from each packet */
    status = reassemble_msg_func(
        &pkt_buffer, &rsp_buffer, heap_info, read_pkt_func);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: "
            "Failed to reassemble buffer", status);
        return status;
    }

    /* Compare response from packet to expected response */
    if ((expected_msg->size != rsp_buffer.size) ||
        0 != ar_mem_cmp(
            expected_msg->buffer, rsp_buffer.buffer, expected_msg->size))
    {
        status = AR_EFAILED;
        AR_DATA_LOG_TEST_ERR("Status[%d]: The expected response and "
            "the packet response are different", status);
    }

    ar_heap_free(rsp_buffer.buffer, heap_info);

    status = ar_fdelete(file);
    if (AR_FAILED(status))
    {
        AR_DATA_LOG_TEST_ERR("Status[%d]: Failed to delete file", status);
    }

    return status;
}

/*****************************************************************************
* Read Operations
******************************************************************************/

int32_t ar_util_test_data_log_file_read(
    const char_t *file, uint32_t file_access,
    void *read_data, size_t read_size, size_t *file_size, size_t *bytes_read)
{
    int32_t status = AR_EOK;
    ar_fhandle fhandle = NULL;

    status = ar_fopen(&fhandle, file, file_access);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "failed to open the file:%s:error:%d ", file, status);
        goto end;
    }

    if (!read_data)
    {
        *file_size = ar_fsize(fhandle);
        goto end;
    }

    /* read data */
    status = ar_fread(fhandle, read_data, read_size, bytes_read);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "failed to read the file %d ", status);
        goto end;
    }

    *file_size = ar_fsize(fhandle);

end:
    if (fhandle)
    {
        // close file
        status = ar_fclose(fhandle);
        if (status != AR_EOK)
        {
            AR_LOG_ERR(LOG_TAG, "failed to close file %d ", status);
        }
    }
    return status;
}
