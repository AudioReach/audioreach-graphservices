/**
*==============================================================================
* \file ats_rtc.h
* \brief
*				A T S  R T C  S O U R C E  F I L E
*
*	The Realtime Calibration Service(RTC) header file contains implementation
*   for ATS to handle requests that operate the DSP
*
* \copyright
*	  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*	  SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*
Notes

size_t is used in in calculating the size of the gsl structure headers b/c the
last element in those structures is a pointer. The size of a pointer may very
between x86 and x64 architectures
*/

#include "ats_i.h"
#include "ats_rtc.h"
#include "ats_common.h"
#include "acdb_utility.h"

/******************************************************************************
* Macros
******************************************************************************/

#define VCPM_PTR(type, vcpm_ptr, offset) ((type*)(vcpm_ptr + offset))
#define ATS_VCPM_MODULE_INST_ID 0x00000004
#define ATS_VCPM_PARAM_ID_CAL_KEYS 0x080011C1

/******************************************************************************
* Type Definitions
******************************************************************************/

typedef struct _ats_vcpm_info_chunk_t AtsVcpmInfoChunk;
struct _ats_vcpm_info_chunk_t
{
    uint32_t subgraph_count;
    uint32_t subgraph_id;
    uint32_t table_size;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t offset_master_key_tbl;
    uint32_t ckv_table_count;
    uint8_t ckv_table_list[0];
};

typedef struct _ats_vcpm_chunk_t AtsVcpmChunk;
struct _ats_vcpm_chunk_t
{
    uint32_t size;
    uint8_t data[0];
};

typedef struct _ats_ckv_data_table_t AtsVcpmCkvDataTable;
struct _ats_ckv_data_table_t
{
    uint32_t table_size;
    uint32_t offset_voice_key_table;
    uint32_t dot_size;
    uint32_t data_obj_count;
    uint8_t data_obj_list[0];
};

typedef struct _ats_cal_data_obj_t AtsVcpmCalDataObj;
struct _ats_cal_data_obj_t
{
    uint32_t offset_ckv_lut;
    uint32_t data_offset_count;
    uint8_t param_info_list[0];
};

typedef struct _ats_vcpm_param_info_t AtsVcpmParamInfo;
struct _ats_vcpm_param_info_t
{
    uint32_t offset_data_pool;
    uint32_t is_persistent;
};

typedef struct _ats_vcpm_master_key_table_t AtsVcpmMasterKeyTable;
struct _ats_vcpm_master_key_table_t
{
    uint32_t total_key_id_count;
    uint8_t key_info_list[0];
};

typedef struct _ats_vcpm_key_info_t AtsVcpmKeyInfo;
struct _ats_vcpm_key_info_t
{
    uint32_t key_id;
    uint32_t is_dynamic;
};

typedef struct _ats_spf_param_cal_t AtsSpfParamCal;
struct _ats_spf_param_cal_t
{
    uint32_t instance_id;
    uint32_t param_id;
    uint32_t size;
    uint32_t error_code;
    uint8_t data[0];
};

typedef struct _ats_iid_pid_pair_t AtsIidPidPair;
struct _ats_iid_pid_pair_t
{
    uint32_t instance_id;
    uint32_t param_id;
};

typedef struct _ats_key_vector_t AtsKeyVector;
struct _ats_key_vector_t
{
    uint32_t key_count;
    AcdbKeyValuePair kv_pair_list[0];
};

typedef struct ats_vcpm_active_ckv_info_t AtsVcpmActiveCkvInfo;
struct ats_vcpm_active_ckv_info_t
{
    /**< The voice Subgraph ID to get the active CKV for.
    This is provided by ATS */
    uint32_t subgraph_id;

    /**< The total number of ckvs defined in the vcpm master table.
    This is provided by ATS*/
    uint32_t num_max_ckv_pairs;
    /** Client fills this value when APM_CMD_GET_CFG is called for this param_id. */

    /**< Number of AcdbKeyValuePair structures that
    follow immediately after this structure. */
    uint32_t num_ckv_pairs;
};

/******************************************************************************
* Function Prototypes
******************************************************************************/

int32_t ats_rtc_get_audio_persist_param_data(
    uint32_t instance_id, uint32_t param_id,
    AcdbSgIdPersistData *subgraph_cal,
    uint8_t **param_cal, uint32_t *param_cal_size);

int32_t ats_rtc_get_active_voice_ckv(AcdbSgIdPersistData *sg_cal_data,
    struct gsl_rtc_param *rtc_param,
    AtsKeyVector **active_ckv);
int32_t ats_rtc_compare_voice_key_ids(AtsVcpmChunk *voice_key_table_chunk,
    uint32_t voice_key_table_offset, AtsKeyVector *active_ckv);

int32_t ats_rtc_compare_voice_key_values(AtsVcpmChunk *voice_lut_chunk,
    uint32_t voice_lut_offset, AtsKeyVector *active_ckv);

int32_t ats_rtc_is_iid_pid_in_list(
    AtsSpfParamCal *param_cal, AtsUintList *id_pair_list);

int32_t ats_rtc_get_vcpm_master_key_table(
    AcdbSgIdPersistData *sg_cal_data,
    AtsVcpmMasterKeyTable **master_key_table);

int32_t ats_rtc_get_vcpm_param_data(
    AcdbSgIdPersistData *sg_cal_data,
    AtsUintList *iid_pid_pair_list,
    AtsKeyVector *active_ckv,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled);

void AtsLogKeyVector(const AtsKeyVector *key_vector, KeyVectorType type);

#if defined(_DEVICE_SIM)
int32_t gsl_rtc_get_active_usecase_info(struct gsl_rtc_active_uc_info *info)
{
    __UNREFERENCED_PARAM(info);
    return 0;
}

int32_t gsl_rtc_get_persist_data(struct gsl_rtc_persist_param *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_rtc_get_non_persist_data(struct gsl_rtc_param *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_rtc_set_persist_data(struct gsl_rtc_persist_param *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_rtc_set_non_persist_data(struct gsl_rtc_param *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_rtc_change_graph(struct gsl_rtc_change_graph_info *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_rtc_prepare_change_graph(
    struct gsl_rtc_prepare_change_graph_info *rtc_persist_param)
{
    __UNREFERENCED_PARAM(rtc_persist_param);
    return 0;
}

int32_t gsl_open(const struct gsl_key_vector *graph_key_vect,
    const struct gsl_key_vector *cal_key_vect, gsl_handle_t *graph_handle)
{
    __UNREFERENCED_PARAM(graph_key_vect);
    __UNREFERENCED_PARAM(cal_key_vect);
    __UNREFERENCED_PARAM(graph_handle);
    return 0;
}

int32_t gsl_close(gsl_handle_t graph_handle)
{
    __UNREFERENCED_PARAM(graph_handle);
    return 0;
}

int32_t gsl_rtc_notify_conn_state(struct gsl_rtc_conn_info *info)
{
    __UNREFERENCED_PARAM(info);
    return 0;
}
#endif

//int32_t get_rtc_version(
//	uint8_t *cmd_buf,
//	uint32_t cmd_buf_size,
//	uint8_t *rsp_buf,
//	uint32_t rsp_buf_size,
//	uint32_t *rsp_buf_bytes_filled)
//{
//	int32_t status = AR_EOK;
//    __UNREFERENCED_PARAM(cmd_buf);
//    __UNREFERENCED_PARAM(cmd_buf_size);
//    __UNREFERENCED_PARAM(rsp_buf);
//    __UNREFERENCED_PARAM(rsp_buf_size);
//    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);
//
//	AtsVersion version = { ATS_RTC_MAJOR_VERSION, ATS_RTC_MINOR_VERSION };
//
//	ATS_MEM_CPY_SAFE(rsp_buf, &version, sizeof(version));
//
//	*rsp_buf_bytes_filled = sizeof(version);
//
//	return status;
//}

int32_t ats_rtc_get_active_usecase_info(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    __UNREFERENCED_PARAM(cmd_buf);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_size);

    struct gsl_rtc_active_uc_info act_uc_info = { 0 };
    uint32_t sz_act_uc_info_header = sizeof(struct gsl_rtc_active_uc_info) - sizeof(size_t);
    //Get Size
    status = gsl_rtc_get_active_usecase_info(&act_uc_info);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get size of active usecase info", status);
        *rsp_buf_bytes_filled = 0;
        return status;
    }

    ATS_MEM_CPY_SAFE(rsp_buf, sz_act_uc_info_header,
        &act_uc_info, sz_act_uc_info_header);
    *rsp_buf_bytes_filled = sz_act_uc_info_header;
    act_uc_info.uc_data = (struct gsl_rtc_uc_data*)(rsp_buf + sz_act_uc_info_header);

    //Data (will be copied directly into the ATS buffer)
    status = gsl_rtc_get_active_usecase_info(&act_uc_info);
    *rsp_buf_bytes_filled = sz_act_uc_info_header + act_uc_info.total_size;

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get active usecase info", status);
    }

    return status;
}

int32_t ats_rtc_get_non_persistent_caldata(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_size);

    struct gsl_rtc_param rtc_param = { 0 };
    int32_t sz_gsl_rtc_param_header = sizeof(rtc_param.graph_handle)
        + sizeof(rtc_param.sgid) + sizeof(rtc_param.total_size);

    ATS_MEM_CPY_SAFE(&rtc_param, sz_gsl_rtc_param_header,
        cmd_buf, sz_gsl_rtc_param_header);
    rtc_param.sg_cal_data = (uint8_t*)(cmd_buf + sz_gsl_rtc_param_header);

    status = gsl_rtc_get_non_persist_data(&rtc_param);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Subgraph(0x%x) | Failed to get realtime "
            "non-persistent calibration data", status, rtc_param.sgid);
    }

    ATS_MEM_CPY_SAFE(
        rsp_buf, sizeof(rtc_param.total_size),
        &rtc_param.total_size, sizeof(rtc_param.total_size));
    ATS_MEM_CPY_SAFE(
        rsp_buf + sizeof(rtc_param.total_size),
        rtc_param.total_size,
        rtc_param.sg_cal_data,
        rtc_param.total_size);

    *rsp_buf_bytes_filled = sizeof(rtc_param.total_size) + rtc_param.total_size;

    return status;
}

int32_t ats_rtc_get_persistent_caldata(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_size);

    struct gsl_rtc_persist_param rtc_param = { 0 };
    int32_t sz_gsl_rtc_persist_param_header =
        sizeof(rtc_param.graph_handle) + sizeof(rtc_param.sgid) +
        sizeof(rtc_param.proc_id);

    ATS_MEM_CPY_SAFE(&rtc_param, sz_gsl_rtc_persist_param_header,
        cmd_buf, sz_gsl_rtc_persist_param_header);
    rtc_param.total_size = &rsp_buf_size;
    rtc_param.sg_cal_data = rsp_buf;

    status = gsl_rtc_get_persist_data(&rtc_param);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get realtime "
            "persistent calibration data", status);
        *rsp_buf_bytes_filled = 0;
        return status;
    }

    *rsp_buf_bytes_filled = *rtc_param.total_size;

    return status;
}

int32_t ats_rtc_get_persistent_caldata_v2(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    uint32_t persist_cal_size = 0;
    uint32_t param_size = 0;
    uint32_t rsp_offset = 0;
    uint32_t *total_size = NULL;
    struct gsl_rtc_persist_param rtc_persist_param = { 0 };
    struct gsl_rtc_param rtc_param_active_voice_ckv = { 0 };
    AtsCmdRtGetCalDataPersistV2Req *req = NULL;
    AtsIidPidPair *iid_pid_pair_list = NULL;
    uint8_t *param_cal = NULL;
    AtsKeyVector *active_ckv = NULL;
    AcdbSgIdPersistData *sg_cal_data = NULL;
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_size);

    struct ats_iid {
        uint32_t instance_id;
        uint32_t param_id;
    };

    req = (AtsCmdRtGetCalDataPersistV2Req*)cmd_buf;
    rtc_persist_param.graph_handle = req->graph_handle;
    rtc_persist_param.proc_id = req->proc_id;
    rtc_persist_param.sgid = req->subgraph_id;
    rtc_persist_param.total_size = &persist_cal_size;

    rtc_param_active_voice_ckv.graph_handle = rtc_persist_param.graph_handle;
    rtc_param_active_voice_ckv.sgid = rtc_persist_param.sgid;
    //rtc_param_active_voice_ckv.proc_id = rtc_persist_param.proc_id;

    //status = ats_test_gsl_rtc_get_persist_data(&rtc_persist_param);
    status = gsl_rtc_get_persist_data(&rtc_persist_param);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to get realtime "
            "persistent calibration data", status);
        *rsp_buf_bytes_filled = 0;
        return status;
    }

    /* Search for IID PID and write to response buffer */
    sg_cal_data = (AcdbSgIdPersistData*)rtc_persist_param.sg_cal_data;
    iid_pid_pair_list = (AtsIidPidPair*)req->iid_pid_pair_list.list;
    rsp_offset = sizeof(uint32_t);

    if (!sg_cal_data)
    {
        ATS_ERR("Unable to get cal data. sg_cal_data is null");
        return AR_EBADPARAM;
    }

    switch (req->cal_type)
    {
    case ATS_CAL_TYPE_AUDIO:

        total_size = (uint32_t*)rsp_buf;
        for (uint32_t i = 0; i < req->iid_pid_pair_list.count; i++)
        {
            status = ats_rtc_get_audio_persist_param_data(
                iid_pid_pair_list[i].instance_id,
                iid_pid_pair_list[i].param_id,
                sg_cal_data,
                &param_cal, &param_size);
            if (AR_FAILED(status))
            {
                ATS_DBG("Error[%d]: No persist cal found for "
                    "<instance, param>[0x%x, 0x%x]", status,
                    iid_pid_pair_list[i].instance_id,
                    iid_pid_pair_list[i].param_id);
                continue;
            }

            ACDB_MEM_CPY_SAFE(rsp_buf + rsp_offset, param_size,
                param_cal, param_size);
            rsp_offset += param_size;
            *rsp_buf_bytes_filled += param_size;
        }

        *rsp_buf_bytes_filled += sizeof(uint32_t);
        *total_size = *rsp_buf_bytes_filled;

        break;

    case ATS_CAL_TYPE_VOICE:

        //Get Active Voice CKV
        rtc_param_active_voice_ckv.sg_cal_data = rsp_buf;
        rtc_param_active_voice_ckv.total_size = rsp_buf_size;

        status = ats_rtc_get_active_voice_ckv(sg_cal_data,
            &rtc_param_active_voice_ckv, &active_ckv);
        if (AR_FAILED(status))
        {
            ATS_ERR("Error[%d]: Unable to get the active voice ckv", status);
            return status;
        }

        status = ats_rtc_get_vcpm_param_data(
            sg_cal_data, &req->iid_pid_pair_list,
            active_ckv, rsp_buf, rsp_buf_size, rsp_buf_bytes_filled);

        break;

    default:
        break;
    }

    return status;
}

int32_t ats_rtc_set_non_persistent_caldata(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    struct gsl_rtc_param rtc_param = { 0 };
    int32_t sz_gsl_rtc_param_header = sizeof(rtc_param.graph_handle) + sizeof(rtc_param.sgid) + sizeof(rtc_param.total_size);

    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    ATS_MEM_CPY_SAFE(&rtc_param, sz_gsl_rtc_param_header,
        cmd_buf, sz_gsl_rtc_param_header);
    rtc_param.sg_cal_data = (uint8_t*)(cmd_buf + sz_gsl_rtc_param_header);

    status = gsl_rtc_set_non_persist_data(&rtc_param);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set realtime non-persistent calibration data", status);
    }
    return status;
}

int32_t ats_rtc_set_persistent_caldata(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    //int32_t sz_gsl_rtc_persist_param_header = sizeof(struct gsl_rtc_persist_param) - sizeof(size_t);
    struct gsl_rtc_persist_param rtc_param = { 0 };
    int32_t sz_gsl_rtc_persist_param_header =
        sizeof(rtc_param.graph_handle) + sizeof(rtc_param.sgid) +
        sizeof(rtc_param.proc_id) + sizeof(*rtc_param.total_size);
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    ATS_MEM_CPY_SAFE(&rtc_param, sz_gsl_rtc_persist_param_header - sizeof(uint32_t),
        cmd_buf, sz_gsl_rtc_persist_param_header - sizeof(uint32_t));
    offset += sz_gsl_rtc_persist_param_header - sizeof(uint32_t);
    rtc_param.total_size = (uint32_t*)(cmd_buf + offset);
    rtc_param.sg_cal_data = (uint8_t*)(cmd_buf + sz_gsl_rtc_persist_param_header);

    status = gsl_rtc_set_persist_data(&rtc_param);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set realtime persistent calibration data", status);
    }
    return status;
}

int32_t ats_rtc_set_persistent_caldata_v2(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    struct gsl_rtc_persist_param rtc_param = { 0 };

    ATS_READ_SEEK_UI32(rtc_param.graph_handle, cmd_buf, offset);
    ATS_READ_SEEK_UI32(rtc_param.sgid, cmd_buf, offset);
    ATS_READ_SEEK_UI32(rtc_param.proc_id, cmd_buf, offset);

    rtc_param.total_size = (uint32_t*)(cmd_buf + offset);
    offset += sizeof(uint32_t);

    if (*rtc_param.total_size > 0)
    {
        rtc_param.sg_cal_data = cmd_buf + offset;
        offset += *rtc_param.total_size;
        ATS_INFO("Directly updating 'shared' calibration memory..");
    }
    else
    {
        rtc_param.sg_cal_data = NULL;
        ATS_INFO("Refreshing 'shared' calibration memory..");
    }

    rtc_param.ckv = (struct gsl_rtc_key_vector*)(cmd_buf + offset);

    AtsLogKeyVector((AtsKeyVector*)rtc_param.ckv, CAL_KEY_VECTOR);

    status = gsl_rtc_set_persist_data(&rtc_param);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set realtime "
            "persistent calibration data", status);
    }

    return status;
}

int32_t ats_rtgm_prepare_change_graph(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    uint32_t num_keys = 0;
    uint32_t offset = 0;
    AcdbGraphKeyVector *tmp_key_vector = NULL;
    struct gsl_rtc_prepare_change_graph_info rtgm_info = { 0 };
    struct gsl_rtc_key_vector *key_vector = NULL;

    ATS_MEM_CPY_SAFE(&rtgm_info.graph_handle, sizeof(uint32_t),
        &cmd_buf[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);

    /* Set the pointers for the Key Vectors to point to the
    * appropriate places within the cmd_buf. GSL will copy
    * the data.
    */
    key_vector = (struct gsl_rtc_key_vector*)&cmd_buf[offset];
    ATS_MEM_CPY_SAFE(&num_keys,
        sizeof(uint32_t), &cmd_buf[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);

    rtgm_info.old_gkv = key_vector;
    offset += num_keys * (sizeof(struct gsl_key_value_pair));

    /* Read and point to Subgraph Connection Info blob
    * num_sgs is apart of the subgraph connection blob.
    */
    rtgm_info.size_of_sg_conn_info =
        *((uint32_t*)&cmd_buf[offset]) - sizeof(uint32_t);
    offset += sizeof(uint32_t);

    //Point to subgraph connections
    rtgm_info.num_sgs = *(uint32_t*)&cmd_buf[offset];
    rtgm_info.sg_conn_info = (uint32_t*)&cmd_buf[offset + sizeof(uint32_t)];
    offset += rtgm_info.size_of_sg_conn_info + sizeof(uint32_t);

    //Read and point to modified subgraph list
    ATS_MEM_CPY_SAFE(&rtgm_info.num_modified_sgs, sizeof(uint32_t),
        &cmd_buf[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (rtgm_info.num_modified_sgs != 0)
    {
        rtgm_info.modified_sgs = (uint32_t*)&cmd_buf[offset];
        offset += rtgm_info.num_modified_sgs * sizeof(uint32_t);

        rtgm_info.size_of_modified_sg_conn_info =
            *((uint32_t*)&cmd_buf[offset]) - sizeof(uint32_t);
        offset += sizeof(uint32_t);

        /* Point to subgraph connections
        * num_modified_sg_connections is apart of the modified
        * subgraph connection blob
        */
        rtgm_info.num_modified_sg_connections =
            *(uint32_t*)&cmd_buf[offset];
        rtgm_info.modified_sg_conn_info =
            (uint32_t*)&cmd_buf[offset + sizeof(uint32_t)];
    }

    status = gsl_rtc_prepare_change_graph(&rtgm_info);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: An error occured durning the runtime graph"
            " update for Graph Handle(%x)", status, rtgm_info.graph_handle);

        //Log Key Vectors
        KeyVectorType kv_type = GRAPH_KEY_VECTOR;
        tmp_key_vector = (void*)rtgm_info.old_gkv;

        if (tmp_key_vector->num_keys != 0)
            tmp_key_vector->graph_key_vector = (AcdbKeyValuePair*)
            ((uint8_t*)tmp_key_vector + sizeof(uint32_t));
        else
            tmp_key_vector->graph_key_vector = NULL;

        LogKeyVector(tmp_key_vector, kv_type);
    }

    return status;
}

int32_t ats_rtgm_change_graph(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(cmd_buf_size);
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    __UNREFERENCED_PARAM(rsp_buf_bytes_filled);

    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    uint32_t key_vector_count = 3;
    AcdbGraphKeyVector *tmp_key_vector = NULL;
    struct gsl_rtc_key_vector *key_vector = NULL;
    struct gsl_rtc_change_graph_info rtgm_info = { 0 };

    ATS_MEM_CPY_SAFE(&rtgm_info.graph_handle, sizeof(uint32_t),
        &cmd_buf[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);

    /* Set the pointers for the Key Vectors to point to the
    * appropriate places within the cmd_buf. GSL will copy
    * the data.
    */
    for (uint32_t i = 0; i < key_vector_count; i++)
    {
        key_vector = (struct gsl_rtc_key_vector*)&cmd_buf[offset];
        ATS_MEM_CPY_SAFE(&num_keys,
            sizeof(uint32_t), &cmd_buf[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);

        switch (i)
        {
        case 0:
            rtgm_info.old_gkv = key_vector;
            break;
        case 1:
            rtgm_info.new_gkv = key_vector;
            break;
        case 2:
            rtgm_info.new_ckv = key_vector;
            break;
        }

        offset += num_keys * (sizeof(struct gsl_key_value_pair));
    }

    if (offset < cmd_buf_size - sizeof(rtgm_info.tag_data_size))
    {
        rtgm_info.tag_data_size = *(uint32_t*)&cmd_buf[offset];
        offset += sizeof(uint32_t);

        if (rtgm_info.tag_data_size > 0)
        {
            rtgm_info.tag_data = &cmd_buf[offset];
        }
    }

    status = gsl_rtc_change_graph(&rtgm_info);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: An error occured durning the runtime graph"
            " update for Graph Handle(%x)", status, rtgm_info.graph_handle);

        //Log Key Vectors
        KeyVectorType kv_type = GRAPH_KEY_VECTOR;
        for (uint32_t i = 0; i < key_vector_count; i++)
        {
            switch (i)
            {
            case 0:
                tmp_key_vector = (void*)rtgm_info.old_gkv;
                break;
            case 1:
                tmp_key_vector = (void*)rtgm_info.new_gkv;
                break;
            case 2:
                tmp_key_vector = (void*)rtgm_info.new_ckv;
                kv_type = CAL_KEY_VECTOR;
                break;
            }

            if (tmp_key_vector->num_keys != 0)
                tmp_key_vector->graph_key_vector = (AcdbKeyValuePair*)
                ((uint8_t*)tmp_key_vector + sizeof(uint32_t));
            else
                tmp_key_vector->graph_key_vector = NULL;

            LogKeyVector(tmp_key_vector, kv_type);
        }
    }

    *rsp_buf_bytes_filled = 0;
    return status;
}

int32_t ats_rt_graph_open(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);

    int32_t status = AR_EOK;
    uint32_t offset = 0;

    struct gsl_key_vector gkv = { 0 };
    struct gsl_key_vector ckv = { 0 };
    //sizeof(gkv.num_keys + ckv.num_keys
    uint32_t min_req_size = 2 * sizeof(uint32_t);
    uint32_t handle = 0;
    gsl_handle_t graph_handle = &handle;

    *rsp_buf_bytes_filled = 0;


    if (IsNull(cmd_buf) || cmd_buf_size < min_req_size)
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    gkv.num_kvps = *((uint32_t*)cmd_buf);
    offset += sizeof(uint32_t);

    if (gkv.num_kvps > 0)
    {
        gkv.kvp = (struct gsl_key_value_pair*)((uint8_t*)cmd_buf + offset);
        offset += gkv.num_kvps * sizeof(struct gsl_key_value_pair);
    }

    ckv.num_kvps = *((uint32_t*)((uint8_t*)cmd_buf + offset));
    offset += sizeof(uint32_t);
    if (ckv.num_kvps > 0)
    {
        ckv.kvp = (struct gsl_key_value_pair*)((uint8_t*)cmd_buf + offset);
        offset += ckv.num_kvps * sizeof(struct gsl_key_value_pair);
    }

    /* If the empty GKV is provided, this means we want to
    * open a special dummy usecase */
    if (gkv.num_kvps == 0)
        status = gsl_open(NULL, NULL, &graph_handle);
    else
        status = gsl_open(&gkv, &ckv, &graph_handle);

    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to open graph", status);
        //LogKeyVector(tmp_key_vector, kv_type);
    }
    else if (AR_SUCCEEDED(status) && !IsNull(graph_handle))
    {
        handle = (uint32_t)(uintptr_t)graph_handle;

        ACDB_MEM_CPY_SAFE(rsp_buf, sizeof(uint32_t), &handle, sizeof(uint32_t));
        *rsp_buf_bytes_filled = sizeof(uint32_t);
    }
    else if (IsNull(graph_handle))
    {
        status = AR_EHANDLE;
        ATS_ERR("Error[%d]: Graph handle is null", status);
    }

    return status;
}

int32_t ats_rt_graph_close(
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf);
    __UNREFERENCED_PARAM(rsp_buf_size);
    int32_t status = AR_EOK;
    uint32_t handle = 0;
    gsl_handle_t graph_handle = NULL;

    *rsp_buf_bytes_filled = 0;

    if (IsNull(cmd_buf) || cmd_buf_size < sizeof(AtsCmdRtGraphCloseReq))
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    handle = *((uint32_t*)cmd_buf);
    graph_handle = (gsl_handle_t)(uintptr_t)handle;

    status = gsl_close(graph_handle);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to close graph");
    }

    return status;
}

int32_t ats_rt_notify_connection_state(
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

    struct gsl_rtc_conn_info session = { 0 };

    if (IsNull(cmd_buf) || cmd_buf_size < sizeof(struct gsl_rtc_conn_info))
    {
        ATS_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    session.state = *((uint32_t*)cmd_buf);

    status = gsl_rtc_notify_conn_state(&session);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to set rt connection state");
    }

    return status;
}

int32_t ats_rtc_ioctl(
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
        //case ATS_CMD_RT_GET_VERSION:
        //	func_cb = get_rtc_version;
        //	break;
    case ATS_CMD_RT_GET_ACTIVE_INFO:
        func_cb = ats_rtc_get_active_usecase_info;
        break;
    case ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT:
        func_cb = ats_rtc_get_non_persistent_caldata;
        break;
    case ATS_CMD_RT_GET_CAL_DATA_PERSISTENT:
        func_cb = ats_rtc_get_persistent_caldata;
        break;
        //case ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT:
        //	func_cb = NULL;
        //	break;
    case ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT:
        func_cb = ats_rtc_set_non_persistent_caldata;
        break;
    case ATS_CMD_RT_SET_CAL_DATA_PERSISTENT:
        func_cb = ats_rtc_set_persistent_caldata;
        break;
    case ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH:
        func_cb = ats_rtgm_prepare_change_graph;
        break;
    case ATS_CMD_RT_GM_CHANGE_GRAPH:
        func_cb = ats_rtgm_change_graph;
        break;
    case ATS_CMD_RT_OPEN_GRAPH:
        func_cb = ats_rt_graph_open;
        break;
    case ATS_CMD_RT_CLOSE_GRAPH:
        func_cb = ats_rt_graph_close;
        break;
        case ATS_CMD_RT_NOTIFY_CONNECTION_STATE:
            func_cb = ats_rt_notify_connection_state;
            break;
    case ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2:
        func_cb = ats_rtc_get_persistent_caldata_v2;
        break;
    case ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2:
        func_cb = ats_rtc_set_persistent_caldata_v2;
        break;
    default:
        status = AR_EUNSUPPORTED;
        ATS_ERR("Error[%d]: Command[%x] is not supported", svc_cmd_id, status);
        break;
    }

    if (!AR_FAILED(status))
    {
        status = func_cb(cmd_buf, cmd_buf_size,
            rsp_buf, rsp_buf_size, rsp_buf_bytes_filled);
    }

    return status;
}

/**
* \brief
*		Initializes the rtc service to allow interaction between
*		ACDB SW and and QST clients.
*
* \return AR_EOK, AR_EFAILED, AR_EHANDLE
*/
int32_t ats_rtc_init(void)
{
    ATS_DBG("Registering ATS Relatime Calibration Service...");

    int32_t status = AR_EOK;

    status = ats_register_service(ATS_RTC_SERVICE_ID, ats_rtc_ioctl);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to register the ATS Realtime Calibration Service.", status);
    }

    return status;
}

/**
* \brief
*		Initializes the rtc service to allow interaction between
*		ACDB SW and and QST clients.
*
* \return AR_EOK, AR_EFAILED, AR_EHANDLE
*/
int32_t ats_rtc_deinit(void)
{
    ATS_DBG("Deregistering ATS Relatime Calibration Service...");

    int32_t status = AR_EOK;

    status = ats_deregister_service(ATS_RTC_SERVICE_ID);
    if (status != AR_EOK)
    {
        ATS_ERR("Error[%d]: Failed to deregister the ATS Realtime Calibration Service.", status);
    }

    return status;
}

/******************************************************************************
* Utility/Helper Functions
******************************************************************************/

int32_t ats_rtc_get_audio_persist_param_data(
    uint32_t instance_id, uint32_t param_id,
    AcdbSgIdPersistData *subgraph_cal,
    uint8_t **param_cal, uint32_t *param_cal_size)
{
    int32_t status = AR_EOK;
    AtsSpfParamCal *m = NULL;
    uint32_t offset = 0;
    bool_t found = FALSE;

    if (IsNull(subgraph_cal) || IsNull(param_cal) || IsNull(param_cal_size))
    {
        ATS_ERR("Error[%d]: One or more input parameter(s) are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    while (offset < subgraph_cal->persist_data_size)
    {
        m = (AtsSpfParamCal*)(subgraph_cal->buf + offset);
        if (m->instance_id == instance_id && m->param_id == param_id)
        {
            *param_cal = (uint8_t*)(subgraph_cal->buf + offset);
            *param_cal_size = sizeof(AtsSpfParamCal) + m->size;
            found = TRUE;
            break;
        }

        offset += sizeof(AtsSpfParamCal) + ACDB_ALIGN_8_BYTE(m->size);
    }

    if (!found)
    {
        status = AR_ENOTEXIST;
        ATS_ERR("Error[%d]: <instance, param>[0x%x, 0x%x] "
            "not found in persist mem.",
            status);
    }

    return status;
}

void AtsLogKeyVector(const AtsKeyVector *key_vector, KeyVectorType type)
{
    if (key_vector == NULL) return;

    switch (type)
    {
    case GRAPH_KEY_VECTOR:
        ATS_INFO("Graph Key Vector with %d key(s):", key_vector->key_count);
        break;
    case CAL_KEY_VECTOR:
        ATS_INFO("Calibration Key Vector with %d key(s):", key_vector->key_count);
        break;
    case TAG_KEY_VECTOR:
        ATS_INFO("Tag Key Vector with %d key(s):", key_vector->key_count);
        break;
    default:
        return;
    }

    for (uint32_t i = 0; i < key_vector->key_count; i++)
    {
        ATS_INFO("[Key:0x%08x Val:0x%08x]",
            key_vector->kv_pair_list[i].key,
            key_vector->kv_pair_list[i].value);
    }
}

int32_t ats_rtc_get_active_voice_ckv(AcdbSgIdPersistData *sg_cal_data,
    struct gsl_rtc_param *rtc_param,
    AtsKeyVector **active_ckv)
{
    int32_t status = AR_EOK;
    uint32_t sg_cal_data_size = 0;
    struct gsl_rtc_param rtc_ckv_param = { 0 };
    AtsSpfParamCal voice_ckv_param = { 0 };
    AtsVcpmActiveCkvInfo vcpm_ckv_info = { 0 };
    AtsVcpmMasterKeyTable *master_key_table = NULL;

    if (IsNull(sg_cal_data) || IsNull(rtc_param) || IsNull(active_ckv))
    {
        if (!sg_cal_data)
            ATS_ERR("subgraph cal data is null");
        if (!master_key_table)
            ATS_ERR("vcpm master key table is null");
        if (!active_ckv)
            ATS_ERR("active ckv is null");

        ATS_ERR("Error[%d]: One or more input parameter(s) are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = ats_rtc_get_vcpm_master_key_table(sg_cal_data, &master_key_table);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Unable to get master key table for Subgraph(0x%x)",
            status, rtc_param->sgid);
        return status;
    }

    if (!IsNull(master_key_table))
    {
        vcpm_ckv_info.num_max_ckv_pairs = master_key_table->total_key_id_count;
        ATS_INFO("Subgraph(0x%x) | VCPM Master Key Table Key Count: %d",
            rtc_param->sgid, vcpm_ckv_info.num_max_ckv_pairs);
    }
    else
    {
        status = AR_EBADPARAM;
        ATS_ERR("Error[%d]: Unable to get master key table is NULL",
            status);
        return status;
    }

    vcpm_ckv_info.subgraph_id = rtc_param->sgid;

    voice_ckv_param.instance_id = ATS_VCPM_MODULE_INST_ID;
    voice_ckv_param.param_id = ATS_VCPM_PARAM_ID_CAL_KEYS;
    voice_ckv_param.error_code = 0;
    voice_ckv_param.size = sizeof(AtsVcpmActiveCkvInfo)
        + vcpm_ckv_info.num_max_ckv_pairs * sizeof(AcdbKeyValuePair);

    sg_cal_data_size = sizeof(AtsSpfParamCal)
        + voice_ckv_param.size;

    //Use response buffer to get CKV
    rtc_ckv_param.graph_handle = rtc_param->graph_handle;
    rtc_ckv_param.sgid = rtc_param->sgid;
    rtc_ckv_param.sg_cal_data = rtc_param->sg_cal_data;
    rtc_ckv_param.total_size = sg_cal_data_size;

    ar_mem_set(rtc_ckv_param.sg_cal_data, 0, sg_cal_data_size);

    /* Copy SPF param header */
    ACDB_MEM_CPY_SAFE(rtc_ckv_param.sg_cal_data, sizeof(AtsSpfParamCal),
        &voice_ckv_param, sizeof(AtsSpfParamCal));

    /* Copy VCPM Active CKV Param Header */
    ACDB_MEM_CPY_SAFE(rtc_ckv_param.sg_cal_data + sizeof(AtsSpfParamCal),
        sizeof(AtsVcpmActiveCkvInfo),
        &vcpm_ckv_info, sizeof(AtsVcpmActiveCkvInfo));

    //status = ats_test_gsl_rtc_get_non_persist_data(&rtc_ckv_param);
    status = gsl_rtc_get_non_persist_data(&rtc_ckv_param);
    if (AR_FAILED(status))
    {
        return status;
    }

    //Parse payload and store it in response buffer
    *active_ckv = (AtsKeyVector*)(rtc_ckv_param.sg_cal_data
        + sizeof(AtsSpfParamCal)
        + sizeof(AtsVcpmActiveCkvInfo) - sizeof(uint32_t));

    AtsLogKeyVector(*active_ckv, CAL_KEY_VECTOR);
    return status;
}

int32_t ats_rtc_compare_voice_key_ids(AtsVcpmChunk *voice_key_table_chunk,
    uint32_t voice_key_table_offset, AtsKeyVector *active_ckv)
{
    int32_t status = AR_EOK;
    uint32_t num_found = 0;
    AtsUintList *voice_key_table = NULL;

    voice_key_table = (AtsUintList*)
        ((uint8_t*)voice_key_table_chunk->data
            + voice_key_table_offset);

    //Compare Key IDs
    if (voice_key_table->count == active_ckv->key_count)
    {
        for (uint32_t i = 0; i < voice_key_table->count; i++)
        {
            for (uint32_t j = 0; j < voice_key_table->count; j++)
            {
                if (voice_key_table->list[i] ==
                    active_ckv->kv_pair_list[j].key)
                {
                    num_found++;
                    break;
                }
            }
        }

        if (voice_key_table->count != num_found)
            return AR_ENOTEXIST;
    }
    else
    {
        status = AR_ENOTEXIST;
    }

    return status;
}

int32_t ats_rtc_compare_voice_key_values(AtsVcpmChunk *voice_lut_chunk,
    uint32_t voice_lut_offset, AtsKeyVector *active_ckv)
{
    int32_t status = AR_EOK;
    uint32_t num_found = 0;
    AtsUintList *voice_lut_table = NULL;

    voice_lut_table = (AtsUintList*)
        ((uint8_t*)voice_lut_chunk->data
            + voice_lut_offset);

    //Compare Key Values
    if (voice_lut_table->count == active_ckv->key_count)
    {
        for (uint32_t i = 0; i < voice_lut_table->count; i++)
        {
            for (uint32_t j = 0; j < voice_lut_table->count; j++)
            {
                if (voice_lut_table->list[i] ==
                    active_ckv->kv_pair_list[j].value)
                {
                    num_found++;
                    break;
                }
            }
        }

        if (voice_lut_table->count != num_found)
            return AR_ENOTEXIST;
    }
    else
    {
        status = AR_ENOTEXIST;
    }

    return status;
}

int32_t ats_rtc_is_iid_pid_in_list(
    AtsSpfParamCal *param_cal, AtsUintList *id_pair_list)
{
    int32_t status = AR_ENOTEXIST;
    AtsIidPidPair *list = (AtsIidPidPair*)
        ((uint8_t*)id_pair_list + sizeof(AtsUintList));

    for (uint32_t i = 0; i < id_pair_list->count; i++)
    {
        if (0 == ar_mem_cmp(param_cal, (void*)&list[i],
            sizeof(AtsIidPidPair)))
            return AR_EOK;
    }

    return status;
}

int32_t ats_rtc_get_vcpm_master_key_table(
    AcdbSgIdPersistData *sg_cal_data,
    AtsVcpmMasterKeyTable **master_key_table)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint8_t *vcpm_cal = NULL;
    AtsVcpmChunk *master_key_table_chunk = NULL;
    AtsVcpmInfoChunk *info = NULL;

    if (IsNull(sg_cal_data) || IsNull(master_key_table))
    {
        if (!sg_cal_data)
            ATS_ERR("subgraph cal data is null");
        if (!master_key_table)
            ATS_ERR("vcpm master key table is null");

        ATS_ERR("Error[%d]: One or more input parameters(s) are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    vcpm_cal = (uint8_t*)sg_cal_data->buf;
    offset += sizeof(AtsSpfParamCal);

    info = VCPM_PTR(AtsVcpmInfoChunk, vcpm_cal, offset);
    offset += sizeof(info->subgraph_count) + sizeof(info->subgraph_id)
        + sizeof(info->table_size) + info->table_size;

    /* Setup chunk pointers */
    master_key_table_chunk = VCPM_PTR(AtsVcpmChunk, vcpm_cal, offset);
    offset += sizeof(AtsVcpmChunk);

    *master_key_table = VCPM_PTR(AtsVcpmMasterKeyTable, vcpm_cal, offset);

    return status;
}

int32_t ats_rtc_get_vcpm_param_data(
    AcdbSgIdPersistData *sg_cal_data,
    AtsUintList *iid_pid_pair_list,
    AtsKeyVector *active_ckv,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    __UNREFERENCED_PARAM(rsp_buf_size);
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t base_dp_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t vckt_offset = 0;
    uint32_t vlut_offset = 0;
    uint32_t dp_offset = 0;
    uint32_t num_params_found = 0;
    uint32_t *total_size = NULL;
    uint8_t *vcpm_cal = NULL;
    AtsVcpmInfoChunk *info = NULL;
    AtsVcpmCkvDataTable *ckv_data_table = NULL;
    AtsVcpmCalDataObj *cal_data_obj = NULL;
    AtsVcpmParamInfo *param_info = NULL;
    AtsSpfParamCal *param_cal = NULL;
    AtsVcpmChunk *master_key_table_chunk = NULL;
    AtsVcpmChunk *voice_key_table_chunk = NULL;
    AtsVcpmChunk *lookup_table_chunk = NULL;
    AtsVcpmChunk *data_pool_chunk = NULL;

    if (IsNull(sg_cal_data) || IsNull(iid_pid_pair_list) ||
        IsNull(active_ckv) || IsNull(rsp_buf) || IsNull(rsp_buf_bytes_filled))
    {
        ATS_ERR("Error[%d]: One or more input parameters(s) are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    /* make space to write total size */
    blob_offset = sizeof(uint32_t);
    total_size = (uint32_t*)rsp_buf;

    vcpm_cal = (uint8_t*)sg_cal_data->buf;
    offset += sizeof(AtsSpfParamCal);

    info = VCPM_PTR(AtsVcpmInfoChunk, vcpm_cal, offset);
    offset += sizeof(info->subgraph_count) + sizeof(info->subgraph_id)
        + sizeof(info->table_size) + info->table_size;

    /* Setup chunk pointers */
    master_key_table_chunk = VCPM_PTR(AtsVcpmChunk, vcpm_cal, offset);
    offset += sizeof(AtsVcpmChunk)
        + master_key_table_chunk->size;
    voice_key_table_chunk = VCPM_PTR(AtsVcpmChunk, vcpm_cal, offset);
    offset += sizeof(AtsVcpmChunk)
        + voice_key_table_chunk->size;
    lookup_table_chunk = VCPM_PTR(AtsVcpmChunk, vcpm_cal, offset);
    offset += sizeof(AtsVcpmChunk)
        + lookup_table_chunk->size;
    data_pool_chunk = VCPM_PTR(AtsVcpmChunk, vcpm_cal, offset);
    base_dp_offset = offset;

    /* Find active CKV Calibration and write matching <iid, pid> to response.
    * The response buffer contains the active CKV, but once the Voice CKV
    * Table is found, the active CKV is no longer needed. At this point the
    * response buffer can be overwritten. */
    offset = sizeof(AtsSpfParamCal) + sizeof(AtsVcpmInfoChunk);

    for (uint32_t i = 0; i < info->ckv_table_count; i++)
    {
        ckv_data_table = VCPM_PTR(AtsVcpmCkvDataTable, vcpm_cal, offset);

        vckt_offset = ckv_data_table->offset_voice_key_table;

        status = ats_rtc_compare_voice_key_ids(
            voice_key_table_chunk, vckt_offset, active_ckv);
        if (AR_FAILED(status))
        {
            offset += sizeof(ckv_data_table->table_size)
                + ckv_data_table->table_size;
            continue;
        }

        offset += sizeof(AtsVcpmCkvDataTable);

        for (uint32_t j = 0; j < ckv_data_table->data_obj_count; j++)
        {
            cal_data_obj = VCPM_PTR(AtsVcpmCalDataObj, vcpm_cal, offset);

            vlut_offset = cal_data_obj->offset_ckv_lut;

            status = ats_rtc_compare_voice_key_values(
                lookup_table_chunk, vlut_offset, active_ckv);
            if (AR_FAILED(status))
            {
                offset += sizeof(AtsVcpmCalDataObj)
                    + cal_data_obj->data_offset_count
                    * sizeof(AtsVcpmParamInfo);
                continue;
            }

            offset += sizeof(AtsVcpmCalDataObj);

            for (uint32_t k = 0; k < cal_data_obj->data_offset_count; k++)
            {
                param_info =
                    VCPM_PTR(AtsVcpmParamInfo, vcpm_cal, offset);

                dp_offset = param_info->offset_data_pool;

                param_cal = VCPM_PTR(AtsSpfParamCal,
                    (uint8_t*)data_pool_chunk + sizeof(uint32_t),
                    dp_offset);

                status = ats_rtc_is_iid_pid_in_list(
                    param_cal, iid_pid_pair_list);
                if (AR_FAILED(status))
                {
                    offset += sizeof(AtsVcpmParamInfo);
                    continue;
                }

                /* Write SPF param header */
                status = ar_mem_cpy(
                    rsp_buf + blob_offset, sizeof(AtsSpfParamCal),
                    param_cal, sizeof(AtsSpfParamCal));
                blob_offset += sizeof(AtsSpfParamCal);
                if (AR_FAILED(status))
                {
                    ATS_ERR("Error[%d]: Unable to copy param header to "
                        "response buffer", status);
                    break;
                }

                /* Write param data */
                status = ar_mem_cpy(
                    rsp_buf + blob_offset, param_cal->size,
                    param_cal->data, param_cal->size);
                blob_offset += param_cal->size;
                if (AR_FAILED(status))
                {
                    ATS_ERR("Error[%d]: Unable to copy param data to "
                        "response buffer", status);
                    break;
                }

                offset += sizeof(AtsVcpmParamInfo);

                num_params_found++;

                if (num_params_found == iid_pid_pair_list->count)
                {
                    break;
                }
            }

            break;
        }

        break;
    }

    if (num_params_found != iid_pid_pair_list->count)
    {
        ATS_INFO("Error[%d]: Found %d/%d params",
            status, num_params_found, iid_pid_pair_list->count);
    }

    if (AR_SUCCEEDED(status))
    {
        *rsp_buf_bytes_filled = blob_offset;
        *total_size = blob_offset;
    }

    return status;
}