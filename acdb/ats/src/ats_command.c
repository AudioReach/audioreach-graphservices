/**
*==============================================================================
* \file ats_command.c
* \brief
*                  A T S  C M D  S O U R C E  F I L E
*
*     The ATS CMD source file defines the implementation for processessing
*     requests from ATS clients and retrieves the response from ACDB.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include "ats_command.h"
#include "acdb_command.h"
#include "acdb_file_mgr.h"

int32_t AtsCmdGetHostDatabaseFileSetInfo(AcdbFileManBlob *rsp)
{
    int32_t status = AR_EOK;
    status = acdb_file_man_ioctl(
        ACDB_FILE_MAN_GET_HOST_DATABASE_FILE_SET_INFO,
        NULL, 0,
        rsp, sizeof(AcdbFileManBlob));

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to retrieve loaded acdb "
            "file set info for host database", status);
    }

    return status;
}

int32_t AtsCmdGetAllDatabasesFileSetInfo(AcdbFileManBlob* rsp)
{
    int32_t status = AR_EOK;
    status = acdb_file_man_ioctl(
        ACDB_FILE_MAN_GET_ALL_DATABASE_FILE_SETS,
        NULL, 0,
        rsp, sizeof(AcdbFileManBlob));

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to retrieve loaded acdb "
            "file set info for one or more databases", status);
    }

    return status;
}

int32_t AtsCmdGetLoadedFileData(
    AcdbFileManGetFileDataReq *req, AcdbFileManBlob *rsp)
{
    int32_t status = AR_EOK;
    status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_DATABASE_FILE_SET,
        req, sizeof(AcdbFileManGetFileDataReq),
        rsp, sizeof(AcdbFileManBlob));

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to retrieve loaded acdb file info", status);
    }

    return status;
}

int32_t AtsCmdGetHeapEntryInfo(
    acdb_handle_t acdb_handle, AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
        &acdb_handle, sizeof(acdb_handle_t), NULL, 0);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set context handle. "
            "Provided handle: %d", status, acdb_handle);
        return status;
    }

    status = DataProcGetHeapInfo(rsp);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Faild to get information from the ACDB heap",
            status);
    }
    return status;
}

int32_t AtsCmdGetHeapEntryData(acdb_handle_t acdb_handle,
    AcdbGraphKeyVector *key_vector, AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;
    uint32_t rsp_offset = rsp->bytes_filled;

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
        &acdb_handle, sizeof(acdb_handle_t), NULL, 0);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set context handle. "
            "Provided handle: %d", status, acdb_handle);
        return status;
    }

    status = DataProcGetHeapData(key_vector, rsp, &rsp_offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Faild to get heap data for key vector");
    }

    rsp->bytes_filled = rsp_offset;
    return status;
}

int32_t AtsCmdGetCalDataNonPersist(
    AtsGetSubgraphCalDataReq *req, AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbBlob blob = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = 1;
    subgraph_list.list = &req->subgraph_id;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    blob.buf = rsp->buf;

    status = GetSubgraphCalData(ACDB_DATA_NON_PERSISTENT, ACDB_DATA_ATS_CLIENT,
        &req->cal_key_vector, req->subgraph_id, req->module_iid, req->param_id,
        FALSE, &blob_offset, &blob);

    if(AR_FAILED(status))
        status = AcdbGetParameterCalData(
        (AcdbParameterCalData*)(void*)req, &blob);

    switch (status)
    {
    case AR_EOK:
        break;
    case AR_ENOTEXIST:
        ATS_ERR("No non-persistent calibration found in heap/file for Subgraph(%x) Module Instance(%x) Parameter(%x)",
            req->subgraph_id, req->module_iid, req->param_id);
        break;
    default:
        ATS_ERR_MSG_1("Failed to get non-persistent subgraph calibration from file/heap for Subgraph(%x) Module Instance(%x) Parameter(%x)",
            status, req->subgraph_id, req->module_iid, req->param_id)
        break;
    }

    blob.buf = NULL;
    rsp->bytes_filled = blob.buf_size;

    return status;
}

int32_t AtsCmdSetCalDataNonPersist(
    bool_t should_persist,
    AcdbGraphKeyVector* cal_key_vector,
    AcdbSubgraphParamData* subgraph_param_data)
{
    int32_t status = AR_EOK;

    if (IsNull(cal_key_vector) || IsNull(subgraph_param_data))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_param_data->subgraph_id_list, sizeof(AcdbUintList),
        NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    subgraph_param_data->ignore_error_code = TRUE;
    status = DataProcSetCalData(cal_key_vector, subgraph_param_data);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to set non-persistent subgraph calibration to heap");
        return status;
    }

    if (acdb_delta_data_is_persist_enabled() && should_persist)
    {
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SAVE, NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ATS_ERR("Error(%d) Failed to save delta file", status);
        }
    }

    return status;
}

int32_t AtsCmdGetCalDataPersist(
    AtsGetSubgraphCalDataReq *req, AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbBlob blob = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = 1;
    subgraph_list.list = &req->subgraph_id;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    blob.buf = rsp->buf;

    status = GetSubgraphCalData(ACDB_DATA_PERSISTENT, ACDB_DATA_ATS_CLIENT,
        &req->cal_key_vector, req->subgraph_id, req->module_iid, req->param_id,
        FALSE, &blob_offset, &blob);

    if (AR_FAILED(status))
        status = AcdbGetParameterCalData(
        (AcdbParameterCalData*)(void*)req, &blob);

    switch (status)
    {
    case AR_EOK:
        break;
    case AR_ENOTEXIST:
        ATS_ERR("No persistent calibration found in heap/file for Subgraph(%x) Module Instance(%x) Parameter(%x)",
            req->subgraph_id, req->module_iid, req->param_id);
        break;
    default:
        ATS_ERR_MSG_1("Failed to get persistent subgraph calibration from file/heap for Subgraph(%x) Module Instance(%x) Parameter(%x)",
            status, req->subgraph_id, req->module_iid, req->param_id)
            break;
    }

    blob.buf = NULL;
    rsp->bytes_filled = blob.buf_size;

    return status;
}

int32_t AtsCmdSetCalDataPersist(
    bool_t should_persist,
    AcdbGraphKeyVector* cal_key_vector,
    AcdbSubgraphParamData* subgraph_param_data)
{
    int32_t status = AR_EOK;

    if (IsNull(cal_key_vector) || IsNull(subgraph_param_data))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_param_data->subgraph_id_list, sizeof(AcdbUintList),
        NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    subgraph_param_data->ignore_error_code = TRUE;
    status = DataProcSetCalData(cal_key_vector, subgraph_param_data);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to set persistent subgraph calibration to heap");
        return status;
    }

    if (acdb_delta_data_is_persist_enabled() && should_persist)
    {
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SAVE, NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ATS_ERR("Error(%d) Failed to save delta file", status);
        }
    }

    return status;
}

int32_t AtsCmdGetTagData(
    AtsGetSubgraphTagDataReq* req,
    AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbBlob blob = { 0 };
    AcdbDataPersistanceType persist_type = ACDB_DATA_UNKNOWN;
    AcdbParameterTagData tag_req = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = 1;
    subgraph_list.list = &req->subgraph_id;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    status = DataProcGetPersistenceType(req->param_id, &persist_type);
    if (AR_FAILED(status))
    {
        ATS_ERR("Unable to determine persitence type for Parameter(0x%x)", req->param_id);
        return status;
    }

    blob.buf = rsp->buf;

    status = GetSubgraphCalData(ACDB_DATA_PERSISTENT, ACDB_DATA_ATS_CLIENT,
        &req->tag_key_vector, req->subgraph_id, req->module_iid, req->param_id,
        FALSE, &blob_offset, &blob);

    if (AR_FAILED(status))
    {
        tag_req.subgraph_id = req->subgraph_id;
        tag_req.module_tag.tag_id = req->tag_id;
        tag_req.module_iid = req->module_iid;
        tag_req.parameter_id = req->param_id;
        tag_req.module_tag.tag_key_vector = req->tag_key_vector;
        status = AcdbGetParameterTagData(
            &tag_req, &blob);
    }

    switch (status)
    {
    case AR_EOK:
        break;
    case AR_ENOTEXIST:
        ATS_ERR("No heap tag data exists for Subgraph(%x) Module Instance(%x) Parameter(%x) Tag(%x)",
            req->subgraph_id, req->module_iid, req->param_id, req->tag_id);
        break;
    default:
        ATS_ERR_MSG_1("Failed to get tag data from heap for Subgraph(%x) Module Instance(%x) Parameter(%x) Tag(%x)",
            status, req->subgraph_id, req->module_iid, req->param_id, req->tag_id)
            break;
    }

    blob.buf = NULL;
    rsp->bytes_filled = blob.buf_size;

    return status;
}

int32_t AtsCmdSetTagData(
    bool_t should_persist,
    AcdbModuleTag* module_tag,
    AcdbSubgraphParamData* subgraph_param_data)
{
    int32_t status = AR_EOK;

    if (IsNull(module_tag) || IsNull(subgraph_param_data))
    {
        ACDB_ERR("Error[%d]: One or more input parameteres are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_param_data->subgraph_id_list, sizeof(AcdbUintList),
        NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    subgraph_param_data->ignore_error_code = TRUE;
    status = DataProcSetTagData(module_tag, subgraph_param_data);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to set subgraph tag to heap");
        return status;
    }

    if (acdb_delta_data_is_persist_enabled() && should_persist)
    {
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SAVE, NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ATS_ERR("Error(%d) Failed to save delta file", status);
        }
    }

    return status;
}

int32_t AtsCmdDeleteDeltaFiles(void)
{
    int32_t status = AR_EOK;

    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_DELETE_ALL_FILES,
        NULL, 0, NULL, 0);

    return status;
}

int32_t AtsCmdGetTempFilePath(uint32_t acdb_handle, AtsGetTempPath *path)
{
    int32_t status = AR_EOK;
    acdb_file_man_writable_path_info_256_t tmp_path = { 0 };
    acdb_context_handle_t *ctx_handle = NULL;

    if (IsNull(path))
    {
        ATS_ERR("Error[%d]: Input path parameter is null"
            , AR_EBADPARAM);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE,
        &acdb_handle, sizeof(uint32_t),
        &ctx_handle, sizeof(acdb_context_handle_t));
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get context handle", status);
        return status;
    }

    tmp_path.handle = ctx_handle->file_manager_handle;

    status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_WRITABLE_PATH,
        &tmp_path, sizeof(acdb_file_man_writable_path_info_256_t),
        NULL, 0);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to retrieve temporary path "
            "info", status);
        return status;
    }

    path->path_len = tmp_path.writable_path.path_len;
    ATS_MEM_CPY_SAFE(path->path, path->path_len,
        &tmp_path.writable_path.path[0], path->path_len);

    return status;
}
