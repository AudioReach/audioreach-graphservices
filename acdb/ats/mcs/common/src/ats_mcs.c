/**
*==============================================================================
* \file ats_mcs.c
* \brief
*                  A T S  M C S  S O U R C E  F I L E
*
*     The Media Control Service(MCS) source file contains the
*     implementation for ATS to handle requests that operate the
*     platform media controller. This allows ATS to start and stop
*     playback and capture sessions.
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
#include "ats_mcs.h"
#include "mcs_api.h"
#include "ats_i.h"
#include "ats_common.h"
#include "acdb_utility.h"

/*------------------------------------------
* Defines and Constants Typedefs
*------------------------------------------*/

/*------------------------------------------
* Private Functions
*------------------------------------------*/

int32_t mcs_read_properties(mcs_properties_t *properties, uint8_t* buffer, uint32_t buffer_size, uint32_t* offset)
{
    int32_t status = AR_EOK;
    uint32_t sz_mcs_property = sizeof(mcs_properties_t) - sizeof(size_t);

    if (IsNull(properties) || IsNull(buffer) || IsNull(offset) || buffer_size < sizeof(mcs_properties_t))
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Null parameter passed in.", status);
        return status;
    }

    ATS_MEM_CPY_SAFE(properties, sz_mcs_property,
        buffer + *offset, sz_mcs_property);
    *offset += sz_mcs_property;

    properties->channel_mapping = buffer + *offset;
    *offset += properties->num_channels * sizeof(uint8_t);

    return status;
}

int32_t mcs_read_playback_req(mcs_play_t *req, uint8_t *cmd_buf, uint32_t cmd_buf_size, uint32_t* bytes_read)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;

    if (IsNull(req) || IsNull(cmd_buf) || IsNull(bytes_read) ||
        cmd_buf_size <= 0)
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Null parameter passed in.", status);
        return status;
    }

    //Read Device and Stream Properties
    status = mcs_read_properties(&req->device_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read device properties.");
        return status;
    }

    status = mcs_read_properties(&req->stream_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read stream properties.");
        return status;
    }

    //Read GKV
    ATS_READ_SEEK_UI32(req->graph_key_vector.num_kvps, cmd_buf, offset);
    req->graph_key_vector.kvp =
        (mcs_key_value_pair_t*)(cmd_buf + offset);
    offset += req->graph_key_vector.num_kvps * 2UL * (uint32_t)sizeof(uint32_t);

    //Read Playback Info (Playback file, Duration, Playback Mode)
    //memcpy starting from the address of playback_mode
    ATS_READ_SEEK_UI32(req->playback_mode, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->playback_duration_sec, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->filename_len, cmd_buf, offset);
    ATS_MEM_CPY_SAFE(&req->filename, req->filename_len,
        cmd_buf + offset, req->filename_len);
    offset += req->filename_len;
    *bytes_read = offset;

    return status;
}

int32_t mcs_read_record_req(mcs_record_t *req, uint8_t *cmd_buf, uint32_t cmd_buf_size, uint32_t* bytes_read)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;

    if (IsNull(req) || IsNull(cmd_buf) || IsNull(bytes_read) ||
        cmd_buf_size <= 0)
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Null parameter passed in.", status);
        return status;
    }

    //Read Device and Stream Properties
    status = mcs_read_properties(&req->device_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read device properties.");
        return status;
    }

    status = mcs_read_properties(&req->stream_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read stream properties.");
        return status;
    }

    //Read GKV
    ATS_READ_SEEK_UI32(req->graph_key_vector.num_kvps, cmd_buf, offset);
    req->graph_key_vector.kvp =
        (mcs_key_value_pair_t*)(cmd_buf + offset);
    offset += req->graph_key_vector.num_kvps * 2UL * (uint32_t)sizeof(uint32_t);

    //Read Playback Info (Playback file, Duration, Playback Mode)
    //memcpy starting from the address of record_mode
    ATS_READ_SEEK_UI32(req->record_mode, cmd_buf, offset);
    ATS_READ_SEEK_UI32(req->write_to_file, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->record_duration_sec, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->filename_len, cmd_buf, offset);
    ATS_MEM_CPY_SAFE(&req->filename, req->filename_len,
        cmd_buf + offset, req->filename_len);
    offset += req->filename_len;
    *bytes_read = offset;

    return status;
}

int32_t mcs_read_playback_2_req(mcs_play_2_t* req, uint8_t* cmd_buf, uint32_t cmd_buf_size, uint32_t* bytes_read)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;

    if (IsNull(req) || IsNull(cmd_buf) || IsNull(bytes_read) ||
        cmd_buf_size <= 0)
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Null parameter passed in.", status);
        return status;
    }

    offset = *bytes_read;
    //Read Device and Stream Properties
    status = mcs_read_properties(&req->device_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read device properties.");
        return status;
    }

    status = mcs_read_properties(&req->stream_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read stream properties.");
        return status;
    }

    //Read GKV
    ATS_READ_SEEK_UI32(req->graph_key_vector.num_kvps, cmd_buf, offset);
    req->graph_key_vector.kvp = NULL;
    if (req->graph_key_vector.num_kvps > 0)
    {
        req->graph_key_vector.kvp =
            (mcs_key_value_pair_t*)(cmd_buf + offset);
        offset += req->graph_key_vector.num_kvps
            * 2UL * (uint32_t)sizeof(uint32_t);
    }

    //Read CKV
    ATS_READ_SEEK_UI32(req->cal_key_vector.num_kvps, cmd_buf, offset);
    req->cal_key_vector.kvp = NULL;
    if (req->cal_key_vector.num_kvps > 0)
    {
        req->cal_key_vector.kvp =
            (mcs_key_value_pair_t*)(cmd_buf + offset);
        offset += req->cal_key_vector.num_kvps
            * 2UL * (uint32_t)sizeof(uint32_t);
    }

    //Read TKVs
    ATS_READ_SEEK_UI32(req->num_tag_key_vectors, cmd_buf, offset);
    ATS_READ_SEEK_UI32(req->tkv_list_size, cmd_buf, offset);
    req->tag_key_vectors = NULL;
    if (req->tkv_list_size > 0)
    {
        req->tag_key_vectors =
            (mcs_tag_key_vector_t*)(cmd_buf + offset);
        offset += req->tkv_list_size;
    }

    //Read Playback Info (Playback file, Duration, Playback Mode)
    //memcpy starting from the address of playback_mode
    ATS_READ_SEEK_UI32(req->playback_mode, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->playback_duration_sec, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->filename_len, cmd_buf, offset);
    ATS_MEM_CPY_SAFE(&req->filename, req->filename_len,
        cmd_buf + offset, req->filename_len);
    offset += req->filename_len;// MCS_MAX_FILENAME_LENGTH;

    //Read Tag Data
    ATS_READ_SEEK_UI32(req->tag_data_size, cmd_buf, offset);
    req->tag_data = NULL;
    if (req->tag_data_size > 0)
    {
        req->tag_data = (uint8_t*)(cmd_buf + offset);
        offset += req->tag_data_size;
    }

    *bytes_read = offset;

    return status;
}

int32_t mcs_read_record_2_req(mcs_record_2_t* req, uint8_t* cmd_buf, uint32_t cmd_buf_size, uint32_t* bytes_read)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;

    if (IsNull(req) || IsNull(cmd_buf) || IsNull(bytes_read) ||
        cmd_buf_size <= 0)
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Null parameter passed in.", status);
        return status;
    }

    offset = *bytes_read;
    //Read Device and Stream Properties
    status = mcs_read_properties(&req->device_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read device properties.");
        return status;
    }

    status = mcs_read_properties(&req->stream_properties, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read stream properties.");
        return status;
    }

    //Read GKV
    ATS_READ_SEEK_UI32(req->graph_key_vector.num_kvps, cmd_buf, offset);
    req->graph_key_vector.kvp = NULL;
    if (req->graph_key_vector.num_kvps > 0)
    {
        req->graph_key_vector.kvp =
            (mcs_key_value_pair_t*)(cmd_buf + offset);
        offset += req->graph_key_vector.num_kvps
            * 2UL * (uint32_t)sizeof(uint32_t);
    }

    //Read CKV
    ATS_READ_SEEK_UI32(req->cal_key_vector.num_kvps, cmd_buf, offset);
    req->cal_key_vector.kvp = NULL;
    if (req->cal_key_vector.num_kvps > 0)
    {
        req->cal_key_vector.kvp =
            (mcs_key_value_pair_t*)(cmd_buf + offset);
        offset += req->cal_key_vector.num_kvps
            * 2UL * (uint32_t)sizeof(uint32_t);
    }

    //Read TKVs
    ATS_READ_SEEK_UI32(req->num_tag_key_vectors, cmd_buf, offset);
    ATS_READ_SEEK_UI32(req->tkv_list_size, cmd_buf, offset);
    req->tag_key_vectors = NULL;
    if (req->tkv_list_size > 0)
    {
        req->tag_key_vectors =
            (mcs_tag_key_vector_t*)(cmd_buf + offset);
        offset += req->tkv_list_size;
    }

    //Read Playback Info (Playback file, Duration, Playback Mode)
    //memcpy starting from the address of record_mode
    ATS_READ_SEEK_UI32(req->record_mode, cmd_buf, offset);
    ATS_READ_SEEK_UI32(req->write_to_file, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->record_duration_sec, cmd_buf, offset);
    ATS_READ_SEEK_I32(req->filename_len, cmd_buf, offset);
    ATS_MEM_CPY_SAFE(&req->filename, req->filename_len,
        cmd_buf + offset, req->filename_len);
    offset += req->filename_len;// MCS_MAX_FILENAME_LENGTH;

    //Read Tag Data
    ATS_READ_SEEK_UI32(req->tag_data_size, cmd_buf, offset);
    req->tag_data = NULL;
    if (req->tag_data_size > 0)
    {
        req->tag_data = (uint8_t*)(cmd_buf + offset);
        offset += req->tag_data_size;
    }

    *bytes_read = offset;

    return status;
}

void print_mcs_play_2(mcs_play_2_t* req)
{
    //Device Properties
    ATS_DBG("Device Properties");
    ATS_DBG("Sample Rate: %d", req->device_properties.sample_rate);
    ATS_DBG("Bits per sample: %d", req->device_properties.bits_per_sample);
    ATS_DBG("Bit Width: %d", req->device_properties.bit_width);
    ATS_DBG("Alignment: %d", req->device_properties.alignment);
    ATS_DBG("Endianness: %d", req->device_properties.endianness);
    ATS_DBG("Qfactor %d", req->device_properties.q_factor);
    ATS_DBG("Channel Count: %d", req->device_properties.num_channels);

    for (uint32_t i = 0; i < req->device_properties.num_channels; i++)
    {
        ATS_DBG("Channel #%d: %d", i, req->device_properties.channel_mapping[i]);
    }

    //Stream Properties
    ATS_DBG("Stream Properties");
    ATS_DBG("Sample Rate: %d", req->stream_properties.sample_rate);
    ATS_DBG("Bits per sample: %d", req->stream_properties.bits_per_sample);
    ATS_DBG("Bit Width: %d", req->stream_properties.bit_width);
    ATS_DBG("Alignment: %d", req->stream_properties.alignment);
    ATS_DBG("Endianness: %d", req->stream_properties.endianness);
    ATS_DBG("Qfactor %d", req->stream_properties.q_factor);
    ATS_DBG("Channel Count: %d", req->stream_properties.num_channels);

    for (uint32_t i = 0; i < req->stream_properties.num_channels; i++)
    {
        ATS_DBG("Channel #%d: %d", i, req->stream_properties.channel_mapping[i]);
    }

    ATS_DBG("Graph Key Vector with %d key(s):", req->graph_key_vector.num_kvps);
    for (uint32_t i = 0; i < req->graph_key_vector.num_kvps; i++)
    {
        ATS_DBG("[Key:0x%08x Val:0x%08x]",
            req->graph_key_vector.kvp[i].key,
            req->graph_key_vector.kvp[i].value);
    }

    ATS_DBG("Cal Key Vector with %d key(s):", req->cal_key_vector.num_kvps);
    for (uint32_t i = 0; i < req->cal_key_vector.num_kvps; i++)
    {
        ATS_DBG("[Key:0x%08x Val:0x%08x]",
            req->cal_key_vector.kvp[i].key,
            req->cal_key_vector.kvp[i].value);
    }

    //TKVs
    ATS_DBG("TKV Count: %d", req->num_tag_key_vectors);
    ATS_DBG("TKV list size: %d", req->tkv_list_size);

    ATS_DBG("Mode: %d", req->playback_mode);
    ATS_DBG("Duration: %d", req->playback_duration_sec);
    ATS_DBG("File name len: %d", req->filename_len);
    ATS_DBG("File name: %s", req->filename);
    ATS_DBG("Tag data size: %d", req->tag_data_size);
}

void print_mcs_record_2(mcs_record_2_t* req)
{
    //Device Properties
    ATS_DBG("Device Properties");
    ATS_DBG("Sample Rate: %d", req->device_properties.sample_rate);
    ATS_DBG("Bits per sample: %d", req->device_properties.bits_per_sample);
    ATS_DBG("Bit Width: %d", req->device_properties.bit_width);
    ATS_DBG("Alignment: %d", req->device_properties.alignment);
    ATS_DBG("Endianness: %d", req->device_properties.endianness);
    ATS_DBG("Qfactor %d", req->device_properties.q_factor);
    ATS_DBG("Channel Count: %d", req->device_properties.num_channels);

    for (uint32_t i = 0; i < req->device_properties.num_channels; i++)
    {
        ATS_DBG("Channel #%d: %d", i, req->device_properties.channel_mapping[i]);
    }

    //Stream Properties
    ATS_DBG("Stream Properties");
    ATS_DBG("Sample Rate: %d", req->stream_properties.sample_rate);
    ATS_DBG("Bits per sample: %d", req->stream_properties.bits_per_sample);
    ATS_DBG("Bit Width: %d", req->stream_properties.bit_width);
    ATS_DBG("Alignment: %d", req->stream_properties.alignment);
    ATS_DBG("Endianness: %d", req->stream_properties.endianness);
    ATS_DBG("Qfactor %d", req->stream_properties.q_factor);
    ATS_DBG("Channel Count: %d", req->stream_properties.num_channels);

    for (uint32_t i = 0; i < req->stream_properties.num_channels; i++)
    {
        ATS_DBG("Channel #%d: %d", i, req->stream_properties.channel_mapping[i]);
    }

    ATS_DBG("Graph Key Vector with %d key(s):", req->graph_key_vector.num_kvps);
    for (uint32_t i = 0; i < req->graph_key_vector.num_kvps; i++)
    {
        ATS_DBG("[Key:0x%08x Val:0x%08x]",
            req->graph_key_vector.kvp[i].key,
            req->graph_key_vector.kvp[i].value);
    }

    ATS_DBG("Cal Key Vector with %d key(s):", req->cal_key_vector.num_kvps);
    for (uint32_t i = 0; i < req->cal_key_vector.num_kvps; i++)
    {
        ATS_DBG("[Key:0x%08x Val:0x%08x]",
            req->cal_key_vector.kvp[i].key,
            req->cal_key_vector.kvp[i].value);
    }

    //TKVs
    ATS_DBG("TKV Count: %d", req->num_tag_key_vectors);
    ATS_DBG("TKV list size: %d", req->tkv_list_size);

    ATS_DBG("Mode: %d", req->record_mode);
    ATS_DBG("Write Flag: %d", req->write_to_file);
    ATS_DBG("Duration: %d", req->record_duration_sec);
    ATS_DBG("File name len: %d", req->filename_len);
    ATS_DBG("File name: %s", req->filename);
    ATS_DBG("Tag data size: %d", req->tag_data_size);
}

int32_t mcs_play(
        uint8_t *cmd_buf,
        uint32_t cmd_buf_size,
        uint8_t *rsp_buf,
        uint32_t rsp_buf_size,
        uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    mcs_play_t req = { 0 };
    uint32_t offset = 0;
    status = mcs_read_playback_req(&req, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read MCS Playback Request");
        return status;
    }

    status = mcs_stream_cmd((uint32_t)MCS_CMD_PLAY,
        (uint8_t*)&req, sizeof(mcs_play_t), NULL, 0, NULL);

    return status;
}

int32_t mcs_rec(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    mcs_record_t req = {0};
    uint32_t offset = 0;

    status = mcs_read_record_req(&req, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read MCS Record Request");
        return status;
    }

    status = mcs_stream_cmd((uint32_t)MCS_CMD_REC,
        (uint8_t*)&req, sizeof(mcs_record_t), NULL, 0, NULL);

    return status;
}

int32_t mcs_play_rec(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    mcs_play_rec_t req = { 0 };
    uint32_t offset = 0;

    status = mcs_read_playback_req(&req.playback_session, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read MCS Playback Request");
        return status;
    }

    status = mcs_read_record_req(&req.record_session, cmd_buf + offset, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read MCS Record Request");
        return status;
    }

    status = mcs_stream_cmd((uint32_t)MCS_CMD_PLAY_REC,
        (uint8_t*)&req, sizeof(mcs_play_rec_t), NULL, 0, NULL);

    return status;
}

int32_t mcs_stop(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;

    status = mcs_stream_cmd((uint32_t)MCS_CMD_STOP, NULL, 0, NULL, 0, NULL);

    return status;
}

int32_t mcs_play_2(
    uint8_t* cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t* rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t* rsp_buf_bytes_filled)
{

    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);
    int32_t status = AR_EOK;
    mcs_play_2_t req = { 0 };
    mcs_session_handles_t rsp = { 0 };
    uint32_t offset = 0;

    status = mcs_read_playback_2_req(&req, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to read MCS Playback 2 Request");
        return status;
    }

    print_mcs_play_2(&req);

    rsp.num_handles = 1;
    rsp.handles = (uint32_t*)(rsp_buf + sizeof(uint32_t));

    ATS_INFO("Starting MCS record session");

    status = mcs_stream_cmd((uint32_t)MCS_CMD_PLAY_2,
        (uint8_t*)&req, sizeof(mcs_play_2_t),
        (uint8_t*)&rsp, sizeof(mcs_session_handles_t), rsp_buf_bytes_filled);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Unable to start playback session", status);
        return status;
    }

    *(uint32_t*)(rsp_buf) = rsp.num_handles;
    *rsp_buf_bytes_filled = sizeof(rsp.num_handles) + sizeof(uint32_t);

    if(rsp.handles != NULL)
        ATS_ERR("Started playback session with handle 0x%x", rsp.handles[0]);
    return status;
}

int32_t mcs_rec_2(
    uint8_t* cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t* rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t* rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);
    int32_t status = AR_EOK;
    mcs_record_2_t req = { 0 };
    mcs_session_handles_t rsp = { 0 };
    uint32_t offset = 0;

    status = mcs_read_record_2_req(&req, cmd_buf, cmd_buf_size, &offset);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to read MCS Record 2 Request", status);
        return status;
    }

    print_mcs_record_2(&req);

    rsp.num_handles = 1;
    rsp.handles = (uint32_t*)(rsp_buf + sizeof(uint32_t));

    ATS_INFO("Starting MCS record session");

    status = mcs_stream_cmd((uint32_t)MCS_CMD_REC_2,
        (uint8_t*)&req, sizeof(mcs_record_2_t),
        (uint8_t*)&rsp, sizeof(mcs_session_handles_t), rsp_buf_bytes_filled);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Unable to start record session", status);
        return status;
    }

    *(uint32_t*)(rsp_buf) = rsp.num_handles;
    *rsp_buf_bytes_filled = sizeof(rsp.num_handles) + sizeof(uint32_t);

    if (rsp.handles != NULL)
        ATS_ERR("Started record session with handle 0x%x", rsp.handles[0]);
    return status;
}

int32_t mcs_multi_play_rec(
    uint8_t* cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t* rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t* rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    mcs_multi_play_rec_t req = { 0 };
    mcs_multi_play_rec_handle_list_t rsp = { 0 };

    *rsp_buf_bytes_filled = 0;
    ATS_INFO("Starting mcs multi-play-record session(s)");

    ATS_READ_SEEK_UI32(req.num_sessions, cmd_buf, offset);
    ATS_DBG("============ Multi-play-rec ============");
    ATS_DBG("multi-play-rec config count: %d", req.num_sessions);
    req.sessions = ACDB_MALLOC(mcs_multi_play_rec_session_t, req.num_sessions);
    if (IsNull(req.sessions))
    {
        status = AR_ENOMEMORY;
        ATS_ERR("Error[%d]: mcs multi-play-rec: Unable to allocate memory"
            " for session structure", status);
        goto end;
    }

    ar_mem_set(req.sessions, 0, req.num_sessions * sizeof(mcs_multi_play_rec_session_t));
    for (uint32_t i = 0; i < req.num_sessions; i++)
    {
        uint32_t is_playback_provided = 0;
        uint32_t is_record_provided = 0;

        ATS_READ_SEEK_UI32(is_playback_provided, cmd_buf, offset);
        ATS_READ_SEEK_UI32(is_record_provided, cmd_buf, offset);

        ATS_DBG("------------ Config #%d ------------", i + 1);
        ATS_DBG("Is playback config provided?: %d", is_playback_provided);
        ATS_DBG("Is record config provided?: %d", is_record_provided);

        if (is_playback_provided)
        {
            req.sessions[i].playback = ACDB_MALLOC(mcs_play_2_t, 1);
            if (IsNull(req.sessions[i].playback))
            {
                status = AR_ENOMEMORY;
                ATS_ERR("Error[%d]: mcs multi-play-rec: Unable to allocate memory"
                    " for playback structure #%d", status, i);
                goto cleanup;
            }

            ar_mem_set(req.sessions[i].playback, 0, sizeof(mcs_play_2_t));
            status = mcs_read_playback_2_req(req.sessions[i].playback,
                cmd_buf, cmd_buf_size, &offset);
            if (AR_FAILED(status))
                goto cleanup;

            ATS_DBG("________ playback config #%d ________", i+1);
            print_mcs_play_2(req.sessions[i].playback);
        }

        if (is_record_provided)
        {
            req.sessions[i].record = ACDB_MALLOC(mcs_record_2_t, 1);
            if (IsNull(req.sessions[i].record))
            {
                status = AR_ENOMEMORY;
                ATS_ERR("Error[%d]: mcs multi-play-rec: Unable to allocate memory"
                    " for record structure #%d", status, i);
                goto cleanup;
            }

            ar_mem_set(req.sessions[i].record, 0, sizeof(mcs_record_2_t));
            status = mcs_read_record_2_req(req.sessions[i].record,
                cmd_buf, cmd_buf_size, &offset);
            if (AR_FAILED(status))
                goto cleanup;

            ATS_DBG("________ record config #%d ________", i + 1);
            print_mcs_record_2(req.sessions[i].record);
        }
    }

    rsp.num_sessions = req.num_sessions;
    rsp.handles = (mcs_multi_play_rec_handle_t*)(rsp_buf + sizeof(uint32_t));

    status = mcs_stream_cmd((uint32_t)MCS_CMD_MULTI_PLAY_REC,
        (uint8_t*)&req, sizeof(mcs_multi_play_rec_t),
        (uint8_t*)&rsp, sizeof(mcs_multi_play_rec_handle_list_t), rsp_buf_bytes_filled);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Unable to start multi-play-record session(s)", status);
        return status;
    }

cleanup:

    for (uint32_t i = 0; i < req.num_sessions; i++)
    {
        if (req.sessions[i].playback != NULL)
        {
            ACDB_FREE(req.sessions[i].playback);
        }
        if (req.sessions[i].record != NULL)
        {
            ACDB_FREE(req.sessions[i].record);
        }
    }
    ACDB_FREE(req.sessions);

end:
    if (AR_FAILED(status))
        *rsp_buf_bytes_filled = 0;
    else
    {
        *(uint32_t*)(rsp_buf) = rsp.num_sessions;
        *rsp_buf_bytes_filled = sizeof(rsp.num_sessions)
            + rsp.num_sessions * sizeof(mcs_multi_play_rec_handle_t);

        if (rsp.handles != NULL)
        {
            ATS_ERR("Started multi-play-record session(s) with handles:");
            for (uint32_t j = 0; j < rsp.num_sessions; j++)
            {
                ATS_ERR("[Session %d] playback handle 0x%x, record handle 0x%x",
                    j, rsp.handles[j].playback_handle, rsp.handles[j].record_handle);
            }
        }
    }

    return status;
}

int32_t mcs_stop_2(
    uint8_t* cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t* rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t* rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    mcs_session_handles_t req = { 0 };

    ATS_READ_SEEK_UI32(req.num_handles, cmd_buf, offset);
    req.handles = (uint32_t*)(cmd_buf + offset);

    ATS_INFO("Stopping MCS media session(s)");

    status = mcs_stream_cmd((uint32_t)MCS_CMD_STOP_2, (uint8_t*)&req, sizeof(mcs_session_handles_t),
        NULL, 0, NULL);

    if(AR_FAILED(status))
        ATS_ERR("Error[%d]: Failed to stop session(s)", status);

    return status;
}

/*------------------------------------------
* Public Functions
*------------------------------------------*/


int32_t ats_mcs_ioctl(
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
    case ATS_CMD_MCS_PLAY:
        func_cb = mcs_play;
        break;
    case ATS_CMD_MCS_RECORD:
        func_cb = mcs_rec;
        break;
    case ATS_CMD_MCS_PLAY_RECORD:
        func_cb = mcs_play_rec;
        break;
    case ATS_CMD_MCS_STOP:
        func_cb = mcs_stop;
        break;
    case ATS_CMD_MCS_PLAY_2:
        func_cb = mcs_play_2;
        break;
    case ATS_CMD_MCS_RECORD_2:
        func_cb = mcs_rec_2;
        break;
    case ATS_CMD_MCS_MULTI_PLAY_REC:
        func_cb = mcs_multi_play_rec;
        break;
    case ATS_CMD_MCS_STOP_2:
        func_cb = mcs_stop_2;
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


int32_t ats_mcs_init(void)
{
    ATS_INFO("Registering Media Control Service...");

    int32_t status = AR_EOK;

    status = mcs_init();

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to initialize Media Control Service.", status);
        return status;
    }

    status = ats_register_service(ATS_MCS_SERVICE_ID, ats_mcs_ioctl);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to register the Media Control Service.", status);
    }

    return status;
}

int32_t ats_mcs_deinit(void)
{
    ATS_INFO("Deregistering Media Control Service...");

    int32_t status = AR_EOK;

    status = mcs_deinit();

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to deinitialize Media Control Service.", status);
    }

    status = ats_deregister_service(ATS_MCS_SERVICE_ID);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to deregister the Media Control Service.", status);
    }

    return status;
}

int32_t ats_mcs_get_version(uint32_t* major, uint32_t* minor)
{
    int32_t status = AR_EOK;
    struct mcs_version version = { 0 };

    if (IsNull(major) || IsNull(minor))
        return AR_EBADPARAM;

    status = mcs_get_api_version(&version);

    if (AR_FAILED(status))
    {
        /* Default to initial version. */
        *major = MCS_API_MAJOR_VERSION_1;
        *minor = MCS_API_MINOR_VERSION_0;
        ATS_ERR("Warning[%d]: Unable to get MCS API version. "
            "Defaulting to v%d.%d", status,
            *major, *minor);
        return AR_EOK;
    }

    *major = version.major;
    *minor = version.minor;

    return status;
}


