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
#include "ar_util_data_log.h"
#include "ar_util_data_log_codes.h"
#include "ar_osal_log_pkt_op.h"
#include "ar_osal_heap.h"

#define AR_OSAL_LOG_DIAG_HEADER_LENGTH 12

uint32_t glb_curr_packet_length = 0;

int32_t ar_log_pkt_op_init(ar_log_pkt_op_init_info_t *info)
{
    __UNREFERENCED_PARAM(info);
    int32_t status = 0;

    ar_fhandle fhandle = NULL;
    //ar_fopen(&fhandle, ")

    return AR_EOK;
}

int32_t ar_log_pkt_op_deinit()
{
    return AR_EUNSUPPORTED;
}

uint32_t ar_log_pkt_get_max_size()
{
    return 128 - AR_OSAL_LOG_DIAG_HEADER_LENGTH;
}

void *ar_log_pkt_alloc(uint16_t logcode, uint32_t length)
{
    int32_t packet_length =
        AR_OSAL_LOG_DIAG_HEADER_LENGTH + length;
    uint8_t* pkt_ptr = NULL;
    ar_heap_info heap_info =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };

    glb_curr_packet_length = packet_length;
    pkt_ptr = ar_heap_malloc(packet_length, &heap_info);

    if (pkt_ptr)
    {
        *(uint32_t*)pkt_ptr = 0;
        *(uint16_t*)pkt_ptr = logcode;
        return pkt_ptr + AR_OSAL_LOG_DIAG_HEADER_LENGTH;
    }

    return pkt_ptr;
}

int32_t ar_log_pkt_commit(void *ptr)
{
    int32_t status = AR_EOK;
    ar_fhandle fhandle = NULL;
    size_t bytes_written = 0;
    char_t *file = "ar_util_data_log_commit.bin";
    void *pkt_ptr = NULL;

    pkt_ptr = (uint8_t*)ptr - AR_OSAL_LOG_DIAG_HEADER_LENGTH;

    status = ar_fopen(&fhandle, file, AR_FOPEN_WRITE_ONLY_APPEND);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "failed to open the file %s:error:%d ", file, status);
    }

    status = ar_fwrite(fhandle, pkt_ptr,
        glb_curr_packet_length,
        &bytes_written);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "failed to write into the file %d ", status);
        goto end;
    }

    if (bytes_written != glb_curr_packet_length)
    {
        //print
        AR_LOG_INFO(LOG_TAG, "failed write file size not matching ");
    }

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

    ar_log_pkt_free(ptr);
    return status;
}

void ar_log_pkt_free(void *ptr)
{
    ar_heap_info heap_info =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };

    ar_heap_free(
        (uint8_t*)ptr - AR_OSAL_LOG_DIAG_HEADER_LENGTH, &heap_info);
}

bool_t ar_log_code_status(uint16_t logcode)
{
    return TRUE;
}
