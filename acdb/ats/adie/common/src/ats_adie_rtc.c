/**
*==============================================================================
*  \file ats_adie_rtc.c
*  \brief
*                   A T S  A D I E  R T C  S O U R C E  F I L E
*
*      The ADIE(Codec) RTC Service(ARTC) header file contains all the
*      definitions necessary for ATS to handle requests that operate on
*      codec registers.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "ats_adie_rtc.h"
#include "ats_i.h"
#include "acdb_utility.h"
#include "ats_common.h"
#include "adie_rtc_api.h"

/*------------------------------------------
* Defines and Constants
*------------------------------------------*/

/*------------------------------------------
* Private Functions
*------------------------------------------*/

int32_t ats_adie_get_codec_info_v1_1(uint8_t* rsp_buf,
    uint32_t rsp_buf_size, uint32_t* rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    struct adie_rtc_codec_info* rsp = NULL;

    ar_mem_set(rsp_buf, 0, rsp_buf_size);
    uint32_t sz_codec_properties = 0;
    rsp = (struct adie_rtc_codec_info*)rsp_buf;

    // Get Size (number of properties)
    status = adie_rtc_get_codec_info(rsp, sizeof(struct adie_rtc_codec_info));
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get size of codec properties.", status);
        return status;
    }

    sz_codec_properties = sizeof(uint32_t) + rsp->num_of_entries *
        sizeof(struct adie_rtc_codec_handle);
    if (sz_codec_properties > rsp_buf_size)
    {
        ATS_ERR("Not enough memory to store codec properties");
        return AR_ENOMEMORY;
    }

    // Get Data
    status = adie_rtc_get_codec_info(rsp, sz_codec_properties);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get codec properties.", status);
        return status;
    }

    *rsp_buf_bytes_filled = sz_codec_properties;

    return status;
}

int32_t ats_adie_get_codec_info_v1_2(uint8_t* rsp_buf,
    uint32_t rsp_buf_size, uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    uint32_t sz_codec_properties = 0;

    ar_mem_set(rsp_buf, 0, rsp_buf_size);
    struct adie_rtc_codec_info_v2* rsp = NULL;

    rsp = (struct adie_rtc_codec_info_v2*)rsp_buf;

    //Get Size(number of properties)
    status = adie_rtc_get_codec_info_v2(rsp, sizeof(struct adie_rtc_codec_info_v2));
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get size of codec properties.", status);
        return status;
    }

    if (rsp->version == CODEC_INFO_STRUCT_VERSION_V2)
    {
        sz_codec_properties = 2 * sizeof(uint32_t) + rsp->num_of_entries *
            sizeof(struct adie_rtc_codec_handle_v2);
    }

    if (sz_codec_properties > rsp_buf_size)
    {
        ATS_ERR("Error[%d]: Not enough memory to write codec info."
            " Required is %d where as available is %d",
            AR_ENOMEMORY, sz_codec_properties, rsp_buf_size);
        return AR_ENOMEMORY;
    }

    //Get Data
    status = adie_rtc_get_codec_info_v2(rsp, sz_codec_properties);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get codec properties V2.", status);
        return status;
    }

    *rsp_buf_bytes_filled = sz_codec_properties;

    return status;
}

int32_t ats_adie_get_codec_info(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    int32_t status = AR_EOK;
    uint32_t sz_codec_properties = 0;
    struct adie_rtc_version api_version = { 0 };

    ats_adie_rtc_get_version(&api_version.major, &api_version.minor);

    /* Fallback to version 1.0 if latest fails */
    switch (api_version.minor)
    {
    case ADIE_RTC_API_MINOR_VERSION_2:
        status = ats_adie_get_codec_info_v1_2(
            rsp_buf, rsp_buf_size, &sz_codec_properties);

        if(AR_SUCCEEDED(status))
            break;

    case ADIE_RTC_API_MINOR_VERSION_1:
    case ADIE_RTC_API_MINOR_VERSION_0:
    default:
        status = ats_adie_get_codec_info_v1_1(
            rsp_buf, rsp_buf_size, &sz_codec_properties);
        break;
    }

    *rsp_buf_bytes_filled = sz_codec_properties;
    return status;
}

int32_t ats_adie_get_register(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_size);
    int32_t status = AR_EOK;
    uint32_t *reg_value = NULL;
    uint32_t min_req_size =
        sizeof(struct adie_rtc_register_req) - sizeof(uint32_t);
    struct adie_rtc_register_req req = { 0 };

    ACDB_MEM_CPY_SAFE(
        &req, min_req_size,
        cmd_buf, min_req_size);

    if (IsNull(cmd_buf) || IsNull(rsp_buf) || cmd_buf_size < min_req_size)
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    *rsp_buf_bytes_filled = 0;

    status = adie_rtc_get_register(&req);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get register.\
            Handle(0x%x) ID(0x%x) Mask(0x%x)",
            status, req.codec_handle,
            req.reg.register_id, req.reg.register_mask);
        return AR_EFAILED;
    }

    ATS_DBG("Register Info: Handle(0x%x) ID(0x%x) \
            Mask(0x%x) Value(0x%x)",
        req.codec_handle, req.reg.register_id,
        req.reg.register_mask, req.reg.value);

    reg_value = (uint32_t*)rsp_buf;
    *reg_value = req.reg.value;
    *rsp_buf_bytes_filled = sizeof(uint32_t);

    return status;
}

int32_t ats_adie_get_multiple_register(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);

    int32_t status = AR_EOK;
    uint32_t min_req_size =
        sizeof(struct adie_rtc_multi_register_req);
    uint32_t req_size = 0;
    struct adie_rtc_multi_register_req *req = NULL;
    struct adie_rtc_register *codec_reg = NULL;
    uint32_t *reg_values = NULL;

    if (IsNull(cmd_buf) || IsNull(rsp_buf) || cmd_buf_size < min_req_size)
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    *rsp_buf_bytes_filled = 0;

    req = (struct adie_rtc_multi_register_req*)cmd_buf;

    req_size = sizeof(struct adie_rtc_multi_register_req)
        + req->num_registers * sizeof(struct adie_rtc_register);
    status = adie_rtc_get_multiple_registers(req, req_size);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: An error occured while getting multiple registers",
            status);
        return status;
    }

    *rsp_buf_bytes_filled = req->num_registers * sizeof(uint32_t);

    if (rsp_buf_size < *rsp_buf_bytes_filled)
    {
        ATS_ERR("Error[%d]: Not enough memory to copy response. "
            "The memory avalible is %d bytes and the size needed is &d bytes",
            AR_ENEEDMORE, rsp_buf_size, *rsp_buf_bytes_filled);
    }

    reg_values = (uint32_t*)rsp_buf;
    codec_reg = (struct adie_rtc_register*)(req->register_list);

    for (uint32_t i = 0; i < req->num_registers; i++)
    {
        reg_values[i] = codec_reg[i].value;
    }

    return status;
}

int32_t ats_adie_set_register(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    int32_t status = AR_EOK;
    struct adie_rtc_register_req req = { 0 };
    uint32_t min_req_size =
        sizeof(struct adie_rtc_multi_register_req);

    if (IsNull(cmd_buf) || cmd_buf_size < min_req_size)
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    *rsp_buf_bytes_filled = 0;

    ACDB_MEM_CPY_SAFE(
        &req, sizeof(struct adie_rtc_register_req),
        cmd_buf, sizeof(struct adie_rtc_register_req));

    status = adie_rtc_set_register(&req);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set register."
            "Handle(%d) ID(%x) Mask(%x) Value(%d)",
            status,
            req.codec_handle,   req.reg.register_id,
            req.reg.register_mask,  req.reg.value);
        return AR_EFAILED;
    }

    return status;
}

int32_t ats_adie_set_multiple_register(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    uint32_t min_req_size =
        sizeof(struct adie_rtc_multi_register_req);
    uint32_t req_size = 0;
    struct adie_rtc_multi_register_req *req = NULL;

    if (IsNull(cmd_buf) || cmd_buf_size < min_req_size)
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    *rsp_buf_bytes_filled = 0;

    req = (struct adie_rtc_multi_register_req*)cmd_buf;

    req_size = sizeof(struct adie_rtc_multi_register_req)
        + req->num_registers * sizeof(struct adie_rtc_register);
    status = adie_rtc_set_multiple_registers(req, req_size);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: An error occured while setting multiple registers",
            status);
        return status;
    }

    return status;
}


/*------------------------------------------
* Public Functions
*------------------------------------------*/

int32_t ats_adie_rtc_ioctl(
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

    switch (svc_cmd_id)
    {
    case ATS_CMD_ADIE_GET_CODEC_INFO:
        func_cb = ats_adie_get_codec_info;
        break;
    case ATS_CMD_ADIE_GET_REGISTER:
        func_cb = ats_adie_get_register;
        break;
    case ATS_CMD_ADIE_GET_MULTIPLE_REGISTER:
        func_cb = ats_adie_get_multiple_register;
        break;
    case ATS_CMD_ADIE_SET_REGISTER:
        func_cb = ats_adie_set_register;
        break;
    case ATS_CMD_ADIE_SET_MULTIPLE_REGISTER:
        func_cb = ats_adie_set_multiple_register;
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

    return status;
}


int32_t ats_adie_rtc_init(void)
{
    ATS_INFO("Registering ADIE Realtime Calibration Service...");

    int32_t status = AR_EOK;

    status = adie_rtc_init();
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to initialize ADIE RTC.", status);
        return status;
    }

    status = ats_register_service(ATS_CODEC_RTC_SERVICE_ID, ats_adie_rtc_ioctl);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to register the ADIE Realtime Calibration Service.", status);
    }

    return status;
}

int32_t ats_adie_rtc_deinit(void)
{
    ATS_DBG("Deregistering ADIE Realtime Calibration Service...");

    int32_t status = AR_EOK;

    status = ats_deregister_service(ATS_CODEC_RTC_SERVICE_ID);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to deregister the ADIE Realtime Calibration Service.", status);
    }

    status = adie_rtc_deinit();
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to deinitialize ADIE RTC.", status);
        return status;
    }

    return status;
}

int32_t ats_adie_rtc_get_version(uint32_t *major, uint32_t *minor)
{
    int32_t status = AR_EOK;
    struct adie_rtc_version version = { 0 };

    if (IsNull(major) || IsNull(minor))
        return AR_EBADPARAM;

    status = adie_rtc_get_api_version(&version);

    if (AR_FAILED(status))
    {
        /* Default to initial version. There are no api
        differences between 1.0 and 1.1, so 1.1 is used */
        *major = ADIE_RTC_API_MAJOR_VERSION_1;
        *minor = ADIE_RTC_API_MINOR_VERSION_1;
        ATS_ERR("Warning[%d]: Unable to get MCS API version. "
            "Defaulting to v%d.%d", status,
            *major, *minor);
        return AR_EOK;
    }

    *major = version.major;
    *minor = version.minor;

    return status;
}

