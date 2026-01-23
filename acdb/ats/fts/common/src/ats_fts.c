/**
*==============================================================================
* \file ats_fts.c
* \brief
*                  A T S  F T S  S O U R C E  F I L E
*
*     The File Transfer Service(FTS) source file contains all the
*     definitions necessary for ATS to handle requests that operate ACDB SW
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "ats_fts.h"
#include "ats_i.h"
#include "acdb_utility.h"
#include "ats_common.h"

/*------------------------------------------
* Defines, Constants, Globals
*------------------------------------------*/

static FtsFileTable *fts_file_table = NULL;

/*------------------------------------------
* Private Functions
*------------------------------------------*/

int32_t fts_open_file(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t findex = 0;
    AtsCmdFtsOpenFileReq req = { 0 };

    *rsp_buf_bytes_filled = 0;

    if (cmd_buf_size < sizeof(AtsCmdFtsOpenFileReq))
    {
        return AR_EBADPARAM;
    }

    //Read Command Request
    ATS_MEM_CPY_SAFE(&req.file_path_length, sizeof(uint32_t), cmd_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    req.file_path = (char*)cmd_buf + offset;
    offset += req.file_path_length;

    ATS_MEM_CPY_SAFE(&req.access, sizeof(uint32_t), cmd_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    ATS_DBG("Opening/creating %s...", req.file_path);

    //Search for avalible file slot
    for (; findex < FTS_MAX_FILE_COUNT; findex++)
        if (fts_file_table->fhandle[findex] == NULL)
            break;

    if (findex >= FTS_MAX_FILE_COUNT)
    {
        ATS_ERR("Max number of files reached");
        return AR_ENORESOURCE;
    }

    //fts_file_table->fhandle[findex] = ACDB_MALLOC(ar_fhandle, 1);
    //if (IsNull(fts_file_table->fhandle[findex]))
    //{
    //    ATS_ERR("Failed to allocate memory for file handle");
    //    return AR_ENOMEMORY;
    //}

    status = ar_fopen(&fts_file_table->fhandle[findex], req.file_path, req.access);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error(%d), FileAccessType(%d): Failed to open/create %s", status, req.access, req.file_path);
        ACDB_FREE(fts_file_table->fhandle[findex]);
        return status;
    }

    //Add file handle to resonse buffer
    ATS_MEM_CPY_SAFE(rsp_buf, sizeof(uint32_t), &findex, sizeof(uint32_t));
    *rsp_buf_bytes_filled = sizeof(uint32_t);

    return status;
}

int32_t fts_write_file(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    size_t bytes_written = 0;
    AtsCmdFtsWriteFileReq req = { 0 };

    if (cmd_buf_size < sizeof(AtsCmdFtsWriteFileReq))
    {
        return AR_EBADPARAM;
    }

    //Read Command Request
    ATS_MEM_CPY_SAFE(&req.findex, sizeof(uint32_t), cmd_buf, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    ATS_MEM_CPY_SAFE(&req.write_size, sizeof(uint32_t), cmd_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    req.buf_ptr = cmd_buf + offset;

    //ATS_DBG("Writing to %s...", req.file_path);
    ATS_DBG("Writing to file...");

    if (req.findex >= FTS_MAX_FILE_COUNT)
    {
        ATS_ERR("Invalid file index");
        return AR_EHANDLE;
    }

    if (fts_file_table->fhandle[req.findex] == NULL)
    {
        ATS_ERR("Invalid file handle");
        return AR_EHANDLE;
    }

    status = ar_fwrite(fts_file_table->fhandle[req.findex], req.buf_ptr, req.write_size, &bytes_written);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error(%d), WriteSize(%d) BytesWritten(%d): Failed to write data to file.",
            status, req.write_size, bytes_written);
    }

    //Write Command Response - add bytes written to response
    req.bytes_writen = (uint32_t*)&bytes_written;
    ATS_MEM_CPY_SAFE(rsp_buf, sizeof(uint32_t), &bytes_written, sizeof(uint32_t));
    *rsp_buf_bytes_filled = sizeof(uint32_t);
    return status;
}

int32_t fts_close_file(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    AtsCmdFtsCloseFileReq req = { 0 };

    if (cmd_buf_size < sizeof(AtsCmdFtsCloseFileReq))
    {
        return AR_EBADPARAM;
    }

    ATS_MEM_CPY_SAFE(&req.findex, sizeof(uint32_t), cmd_buf, sizeof(uint32_t));

    if (req.findex >= FTS_MAX_FILE_COUNT)
    {
        ATS_ERR("Invalid file index");
        return AR_EHANDLE;
    }

    if (fts_file_table->fhandle[req.findex] == NULL)
    {
        ATS_ERR("Invalid file handle");
        return AR_EHANDLE;
    }

    //ATS_DBG("Closing %s...", req.file_path);
    ATS_DBG("Closing file...");

    status = ar_fclose(fts_file_table->fhandle[req.findex]);
    if (AR_FAILED(status))
    {
        return status;
    }

    *rsp_buf_bytes_filled = 0;

    return status;
}

/*------------------------------------------
* Public Functions
*------------------------------------------*/

int32_t ats_fts_ioctl(
    uint32_t svc_cmd_id,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled
)
{
    int32_t status = AR_EOK;

    int32_t(*func_cb)(
        uint8_t *cmd_buf,
        uint32_t cmd_buf_size,
        uint8_t *rsp_buf,
        uint32_t rsp_buf_size,
        uint32_t *rsp_buf_bytes_filled
        ) = NULL;

    status = ar_osal_mutex_lock(fts_file_table->lock);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to lock.", status);
        return status;
    }

    switch (svc_cmd_id)
    {
    case ATS_CMD_FTS_OPEN_FILE:
        func_cb = fts_open_file;
        break;
    case ATS_CMD_FTS_WRITE_FILE:
        func_cb = fts_write_file;
        break;
    case ATS_CMD_FTS_CLOSE_FILE:
        func_cb = fts_close_file;
        break;
    default:
        ATS_ERR("Command[%x] is not supported", svc_cmd_id);
        status = AR_EUNSUPPORTED;
    }

    if (status == AR_EOK)
    {
        status = func_cb(cmd_buf,
            cmd_buf_size,
            rsp_buf,
            rsp_buf_size,
            rsp_buf_bytes_filled);
    }

    status = ar_osal_mutex_unlock(fts_file_table->lock);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to unlock.", status);
        return status;
    }
    return status;
}


int32_t ats_fts_init(void)
{
    ATS_DBG("Registering File Transfer Service...");

    int32_t status = AR_EOK;

    fts_file_table = ACDB_MALLOC(FtsFileTable, 1);
    if (IsNull(fts_file_table))
    {
        ATS_ERR("Error[%d]: Failed to allocate memory for file table.", status);
        return status;
    }

    ACDB_CLEAR_BUFFER(fts_file_table->fhandle);

    status = ar_osal_mutex_create(&fts_file_table->lock);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to create lock.", status);
        return status;
    }

    //status = ar_osal_mutex_init(fts_file_table->lock);
    //if (AR_FAILED(status))
    //{
    //    ATS_ERR("Error[%d]: Initialize lock.", status);
    //    return status;
    //}

    status = ats_register_service(ATS_FTS_SERVICE_ID, ats_fts_ioctl);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to register the File Transfer Service.", status);
    }

    return status;
}

int32_t ats_fts_deinit(void)
{
    ATS_DBG("Deregistering File Transfer Service...");

    int32_t status = AR_EOK;

    status = ats_deregister_service(ATS_FTS_SERVICE_ID);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to deregister the File Transfer Service.", status);
    }

    status = ar_osal_mutex_destroy(fts_file_table->lock);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to destroy lock.", status);
        return status;
    }

    if (!IsNull(fts_file_table))
        ACDB_FREE(fts_file_table);

    return status;
}

