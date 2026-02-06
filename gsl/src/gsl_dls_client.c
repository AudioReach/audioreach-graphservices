/**
 *  \file gsl_dls_client.C
 *  \brief
 *        Contains the implementation of the Data Logging Service (DLS)
 *        client.
 *        This module is responsible for delivering binary log
 *        packet data to the gsl realtime tunning client. GSL subscribes
 *        subscription to dls event notifications from SPF. The gsl
 *        realtime tuning client registers the log codes it wants to
 *        recieve data for.
 *
 * \copyright
 *      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *      SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_util_list.h"
#include "ar_osal_shmem.h"
#include "ar_osal_signal.h"
#include "ar_osal_types.h"
#include "ar_osal_mutex.h"
#include "ar_osal_log.h"
#include "ar_osal_file_io.h"
#include "gpr_ids_domains.h"
#include "gpr_api_inline.h"
#include "dls_api.h"
#include "dls_log_pkt_hdr_api.h"
#include "gsl_msg_builder.h"
#include "gsl_dls_client.h"
#include "gsl_mdf_utils.h"
#include "gsl_common.h"

#define ADSP_PROC_ID    0x2

/*dls client context structure */
struct gsl_dls_client_ctxt dls_client_ctxt;

int32_t gsl_dls_client_is_feature_supported()
{
#if defined(ATS_DATA_LOGGING)
    return AR_EOK;
#else
    return AR_EUNSUPPORTED;
#endif
}

static int32_t gsl_dls_client_register_deregister_commit_log_buffer_event(enum gsl_dls_commit_log_buffer_register_enum_t event_register_flag)
{
    int32_t rc = AR_EOK;
    gsl_msg_t gsl_msg;
    apm_cmd_header_t *apm_hdr;
    apm_module_register_events_t *event_payload;
    uint32_t event_param_data_size = GSL_ALIGN_8BYTE(sizeof(apm_module_register_events_t));
    /* Register to APM_MODULE_EVENTS*/

    gsl_memset(&gsl_msg, 0, sizeof(gsl_msg_t));

    if (gsl_mdf_utils_is_master_proc(GSL_GET_SPF_SS_MASK(ADSP_PROC_ID))) {
        rc = gsl_msg_alloc(APM_CMD_REGISTER_MODULE_EVENTS, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_ADSP_V, event_param_data_size, true, &gsl_msg);
    } else {
        rc = gsl_msg_alloc(APM_CMD_REGISTER_MODULE_EVENTS, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_APPS_V, event_param_data_size, false, &gsl_msg);
    }

	if (AR_FAILED(rc)) {
		GSL_ERR("failed to allocate gsl msg. status %d", rc);
		goto exit;
	}

	apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, gsl_msg.gpr_packet);
	apm_hdr->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	apm_hdr->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	apm_hdr->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	apm_hdr->payload_size = event_param_data_size;

    event_payload = (apm_module_register_events_t *)(gsl_msg.payload);
    event_payload->module_instance_id = DLS_MODULE_INSTANCE_ID;
    event_payload->event_id = DLS_DATA_EVENT_ID_COMMIT_LOG_BUFFER;
    event_payload->error_code = 0;
    event_payload->is_register = event_register_flag;
    event_payload->event_config_payload_size = sizeof(apm_module_register_events_t);

    GSL_DBG("registering dls commit buffer event with spf...");

    rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&dls_client_ctxt.sig);
    if (AR_FAILED(rc)){
        GSL_ERR("failed to register to dls commit buffer event. status %d");
    }
    else {
        GSL_DBG("successfully registered dls commit buffer event with spf");
    }

    gsl_msg_free(&gsl_msg);
exit:
    return rc;
}

int32_t gsl_dls_client_alloc_shmem_and_config_dls_buffer()
{
    int32_t rc = AR_EOK;
    gsl_msg_t gsl_msg;
    apm_cmd_header_t *apm_hdr;
    apm_module_param_data_t *param_hdr;
    dls_param_id_config_buffer_t *param_payload;
    uint32_t dls_config_buffer_param_data_size = GSL_ALIGN_8BYTE(sizeof(apm_module_param_data_t) +
                                     sizeof(dls_param_id_config_buffer_t));
    uint32_t dls_buffer_pool_shmem_sz = dls_client_ctxt.buffer_pool_config.buffer_size *
        dls_client_ctxt.buffer_pool_config.buffer_count;

    /*Allocate shared memory for DLS Buffer pool*/
    rc = gsl_shmem_alloc(dls_buffer_pool_shmem_sz, AR_AUDIO_DSP, &dls_client_ctxt.dls_shmem);
    if (rc) {
        GSL_ERR("failed to allocate shmem for dls buffer pool. status %d", rc);
        goto exit;
    }

    gsl_memset(&gsl_msg, 0, sizeof(gsl_msg_t));

    if (gsl_mdf_utils_is_master_proc(GSL_GET_SPF_SS_MASK(ADSP_PROC_ID))) {
        rc = gsl_msg_alloc(APM_CMD_SET_CFG, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_ADSP_V, dls_config_buffer_param_data_size, true, &gsl_msg);
    } else {
        rc = gsl_msg_alloc(APM_CMD_SET_CFG, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_APPS_V, dls_config_buffer_param_data_size, false, &gsl_msg);
    }
	if (AR_FAILED(rc)) {
		GSL_ERR("failed to allocate GSL msg. status %d", rc);
		goto exit;
	}

	apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, gsl_msg.gpr_packet);
	apm_hdr->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	apm_hdr->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	apm_hdr->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	apm_hdr->payload_size = dls_config_buffer_param_data_size;

	param_hdr = (apm_module_param_data_t *)(gsl_msg.payload);
	param_hdr->module_instance_id = DLS_MODULE_INSTANCE_ID;
	param_hdr->param_id = DLS_PARAM_ID_CONFIG_BUFFER;
	param_hdr->param_size = sizeof(dls_param_id_config_buffer_t);
	param_hdr->error_code = 0;

    param_payload = (dls_param_id_config_buffer_t *)(param_hdr + 1);
    param_payload->buf_start_addr_lsw = (uint32_t) dls_client_ctxt.dls_shmem.spf_addr;
    param_payload->buf_start_addr_msw = (uint32_t) (dls_client_ctxt.dls_shmem.spf_addr >> 32);
    param_payload->is_cfg = 1;
    param_payload->max_log_pkt_size = dls_client_ctxt.buffer_pool_config.buffer_size;
    param_payload->mem_map_handle = dls_client_ctxt.dls_shmem.spf_mmap_handle;
    param_payload->total_buf_size = dls_buffer_pool_shmem_sz;

    GSL_DBG("configuring dls buffers on spf");

    rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&dls_client_ctxt.sig);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to configure buffer with size :0x%x and buffer count = 0x%x. status %d",
            dls_client_ctxt.buffer_pool_config.buffer_size, dls_client_ctxt.buffer_pool_config.buffer_count, rc);
    }
    else {
        GSL_DBG("buffer configured with size :0x%x and buffer count = 0x%x",
            dls_client_ctxt.buffer_pool_config.buffer_size, dls_client_ctxt.buffer_pool_config.buffer_count);
    }

    gsl_msg_free(&gsl_msg);
exit:

    return rc;
}

int32_t gsl_dls_client_create_buffer_pool(struct gsl_dls_buffer_pool_config_t *buffer_pool_config)
{
    int32_t rc = AR_EOK;
    if (dls_client_ctxt.is_dls_buffer_configured) {
        rc = gsl_shmem_free(&dls_client_ctxt.dls_shmem);
        if (rc)
        {
            GSL_ERR("unable to unmap shared memory. App restart recommended. status %d", rc);
            return rc;
        }
    }

    if ((buffer_pool_config->buffer_count < GSL_DLS_CLIENT_MIN_BUFFER_COUNT) ||
        (buffer_pool_config->buffer_count > GSL_DLS_CLIENT_MAX_BUFFER_COUNT)) {
        GSL_ERR("invalid buffer configuration request. buffer count limit is :0x%x and 0x%x",
            GSL_DLS_CLIENT_MIN_BUFFER_COUNT, GSL_DLS_CLIENT_MAX_BUFFER_COUNT);
        return AR_EBADPARAM;
    }

    if (buffer_pool_config->buffer_size < GSL_DLS_CLIENT_SHMEM_MIN_BUFFER_SZ ||
        buffer_pool_config->buffer_size > GSL_DLS_CLIENT_SHMEM_MAX_BUFFER_SZ) {
        GSL_ERR("invalid Buffer Configuration request. buffer size limit is :0x%x and 0x%x",
            GSL_DLS_CLIENT_SHMEM_MIN_BUFFER_SZ, GSL_DLS_CLIENT_SHMEM_MAX_BUFFER_SZ);
        return AR_EBADPARAM;
    }

    dls_client_ctxt.buffer_pool_config = *buffer_pool_config;

    rc = gsl_dls_client_register_deregister_commit_log_buffer_event(GLS_DLS_EVENT_FLAG_REGISTER_COMMIT_LOG_BUFFER);
    if (AR_FAILED(rc))
        goto exit;

    rc = gsl_dls_client_alloc_shmem_and_config_dls_buffer();

exit:

    return rc;
}

void gsl_dls_client_get_ready_dls_buffer_list(struct gsl_dls_ready_buffer_index_list_t *ready_buffer_index_list)
{
    dls_buf_hdr_t *dls_buffer_ptr = NULL;
    uint32_t dls_buffer_offset = 0;

    if (!dls_client_ctxt.is_dls_buffer_configured)
        return;

    gsl_memset(ready_buffer_index_list, 0, sizeof(struct gsl_dls_ready_buffer_index_list_t));

    for (uint16_t buffer_index = 0; buffer_index < dls_client_ctxt.buffer_pool_config.buffer_count; buffer_index++)
    {
        dls_buffer_offset = (buffer_index * dls_client_ctxt.buffer_pool_config.buffer_size);
        dls_buffer_ptr = (dls_buf_hdr_t *)((uint8_t *)dls_client_ctxt.dls_shmem.v_addr + dls_buffer_offset);

        if (DLS_BUF_READY != dls_buffer_ptr->buf_state) continue;

        ready_buffer_index_list->buffer_index_list[ready_buffer_index_list->buffer_count] = buffer_index;
        ready_buffer_index_list->buffer_count++;
    }

    if (ready_buffer_index_list->buffer_count == 0)
    {
        GSL_DBG("there are no ready dls buffers");
    }
}

int32_t gsl_dls_client_get_log_buffer(uint32_t log_buffer_index, struct gls_dls_buffer_t *dls_log_buffer)
{
    int32_t rc = AR_EOK;
    dls_buf_hdr_t *dls_buffer_ptr = NULL;
    uint32_t dls_buffer_offset = 0;
    uint8_t *dls_shmem_buffer_pool = NULL;

    if (!dls_client_ctxt.is_dls_buffer_configured)
        return AR_ENOTREADY;

    if (log_buffer_index > dls_client_ctxt.buffer_pool_config.buffer_count)
        return AR_ENOTEXIST;

    dls_buffer_offset = (log_buffer_index * dls_client_ctxt.buffer_pool_config.buffer_size);
    dls_shmem_buffer_pool = (uint8_t *)dls_client_ctxt.dls_shmem.v_addr + dls_buffer_offset;
    dls_buffer_ptr = (dls_buf_hdr_t *)(dls_shmem_buffer_pool);

    /* Skip the dls buffer header before sending it to the client since its not required by the client */
    dls_log_buffer->size = dls_buffer_ptr->buf_size - sizeof(dls_buf_hdr_t);
    dls_log_buffer->buffer = dls_shmem_buffer_pool + sizeof(dls_buf_hdr_t);

    return rc;
}

int32_t gsl_dls_client_set_used_buffers(struct gsl_dls_ready_buffer_index_list_t *buffer_index_list)
{
    //store used buffers in gsl dsl client context
    gsl_memcpy(&dls_client_ctxt.used_buffers, sizeof(dls_client_ctxt.used_buffers), buffer_index_list,
                sizeof(dls_client_ctxt.used_buffers));
}

int32_t gsl_dls_client_return_used_buffers(struct gsl_dls_ready_buffer_index_list_t *buffer_index_list)
{
    int32_t rc = AR_EFAILED;
    apm_cmd_header_t *apm_hdr;
    gsl_msg_t gsl_msg;
    dls_data_cmd_buffer_return_t *dls_buf_ret_cfg;
    uint32_t dls_buf_ret_cfg_size = 0;
    uint32_t signal_flags = 0;
    uint32_t dls_buffer_offset = 0;

    rc = gsl_signal_timedwait(&dls_client_ctxt.ready_buffer_sig, GSL_SPF_TIMEOUT_MS,
        &signal_flags, NULL, NULL);
    if (rc) {
        GSL_ERR("Ready buffer signal wait failed, rc is %d", rc);
        return rc;
    }

    buffer_index_list = &dls_client_ctxt.used_buffers;

    dls_buf_ret_cfg_size =  GSL_ALIGN_8BYTE(sizeof(uint32_t)
                            + (buffer_index_list->buffer_count * sizeof(dls_buf_start_addr_t)));
    if (gsl_mdf_utils_is_master_proc(GSL_GET_SPF_SS_MASK(ADSP_PROC_ID))) {
        rc = gsl_msg_alloc(DLS_DATA_CMD_BUFFER_RETURN, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_ADSP_V, dls_buf_ret_cfg_size, true, &gsl_msg);
    } else {
        rc = gsl_msg_alloc(DLS_DATA_CMD_BUFFER_RETURN, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_APPS_V, dls_buf_ret_cfg_size, false, &gsl_msg);
    }

	if (AR_FAILED(rc)) {
		GSL_ERR("unable to allocate gsl msg for dls buffer return command. status %d", rc);
		goto exit;
	}

    dls_buf_ret_cfg = GPR_PKT_GET_PAYLOAD(dls_data_cmd_buffer_return_t, gsl_msg.gpr_packet);
    dls_buf_ret_cfg->num_bufs = (uint32_t)buffer_index_list->buffer_count;
    for (uint32_t i = 0; i < dls_buf_ret_cfg->num_bufs; i++)
    {
        dls_buffer_offset = (buffer_index_list->buffer_index_list[i] * dls_client_ctxt.buffer_pool_config.buffer_size);
        dls_buf_ret_cfg->buf_start_addr[i].buf_addr_lsw = (uint32_t)(((uint64_t)dls_client_ctxt.dls_shmem.spf_addr + dls_buffer_offset) & 0x00000000FFFFFFFF);
        dls_buf_ret_cfg->buf_start_addr[i].buf_addr_msw = (uint32_t)((((uint64_t)dls_client_ctxt.dls_shmem.spf_addr + dls_buffer_offset) & 0xFFFFFFFF00000000) >> 32);
        dls_buf_ret_cfg->buf_start_addr[i].mem_map_handle = dls_client_ctxt.dls_shmem.spf_mmap_handle;
    }

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
	        &dls_client_ctxt.sig);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to return %d buffers to dls. status %d", dls_buf_ret_cfg->num_bufs, rc);
    }
    else {
        GSL_DBG("returned buffers %d buffers to dls for reuse", dls_buf_ret_cfg->num_bufs);
    }

    gsl_msg_free(&gsl_msg);
exit:
    return rc;
}

int32_t gsl_dls_client_register_deregister_log_code(uint32_t log_code, bool_t is_log_code_enabled)
{
	int32_t rc = AR_EOK;
	apm_cmd_header_t *apm_hdr;
    apm_module_param_data_t *param_hdr;
    dls_param_id_enable_disable_log_code_t *param_payload;
	gsl_msg_t gsl_msg;
    uint16_t num_log_codes = 1;
    uint32_t dls_log_code_cfg_size = GSL_ALIGN_8BYTE(
                                     sizeof(apm_module_param_data_t) +
                                     sizeof(dls_param_id_enable_disable_log_code_t) +
                                     (num_log_codes * sizeof(uint32_t)));

    gsl_memset(&gsl_msg, 0, sizeof(gsl_msg_t));

    if (gsl_mdf_utils_is_master_proc(GSL_GET_SPF_SS_MASK(ADSP_PROC_ID))) {
        rc = gsl_msg_alloc(APM_CMD_SET_CFG, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_ADSP_V, dls_log_code_cfg_size, true, &gsl_msg);
    } else {
        rc = gsl_msg_alloc(APM_CMD_SET_CFG, GSL_DLS_CLIENT_GPR_SRC_PORT, DLS_MODULE_INSTANCE_ID,
          sizeof(*apm_hdr), 0, GPR_IDS_DOMAIN_ID_APPS_V, dls_log_code_cfg_size, false, &gsl_msg);
    }
	if (AR_FAILED(rc)) {
		GSL_ERR("unable to allocate gsl msg for register/deregister log code. status %d", rc);
		goto exit;
	}

	apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, gsl_msg.gpr_packet);
	apm_hdr->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	apm_hdr->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	apm_hdr->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	apm_hdr->payload_size = dls_log_code_cfg_size;

	param_hdr = (apm_module_param_data_t *)(gsl_msg.payload);
	param_hdr->module_instance_id = DLS_MODULE_INSTANCE_ID;
	param_hdr->param_id = DLS_PARAM_ID_ENABLE_DISABLE_LOG_CODE;
	param_hdr->param_size = sizeof(dls_param_id_enable_disable_log_code_t)
                            + (num_log_codes * sizeof(uint32_t));
	param_hdr->error_code = 0;

    param_payload = (dls_param_id_enable_disable_log_code_t *)(param_hdr + 1);
    param_payload->is_enabled = is_log_code_enabled? 1 : 0;
    param_payload->num_log_codes = num_log_codes;
    for (int i = 0; i < num_log_codes; i++) {
        param_payload->log_codes[i] = log_code;
    }
	GSL_LOG_PKT("send_pkt", GSL_DLS_CLIENT_GPR_SRC_PORT, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*apm_hdr), gsl_msg.payload,
		apm_hdr->payload_size);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&dls_client_ctxt.sig);
	if (AR_FAILED(rc) && is_log_code_enabled){
        GSL_ERR("unable to register logcode 0x%x. status %d", log_code, rc);
    }
    else if (AR_FAILED(rc) && !is_log_code_enabled){
        GSL_ERR("unable to de-register logcode 0x%x. status %d", log_code, rc);
    }
    else if (AR_SUCCEEDED(rc) && is_log_code_enabled){
        GSL_DBG("registered logcode 0x%x. status %d", log_code, rc);
    }
    else if (AR_SUCCEEDED(rc) && !is_log_code_enabled){
        GSL_DBG("de-registered logcode 0x%x. status %d", log_code, rc);
    }

	gsl_msg_free(&gsl_msg);

    exit:
    return rc;
}

static uint32_t gsl_dls_client_event_callback(gpr_packet_t *packet, void *callback_data)
{
    callback_data = NULL;
    GSL_DBG("received opcode :0x%x ", packet->opcode);
    switch (packet->opcode) {
    case GPR_IBASIC_RSP_RESULT:
    {
        gpr_ibasic_rsp_result_t *p_gpr_rsp = (gpr_ibasic_rsp_result_t *)GPR_PKT_GET_PAYLOAD(void, packet);
        GSL_DBG(
            "DLS_CLIENT_GPR CB: ISR received GPR_IBASIC_RSP_RESULT, result(%lu),opcode(0x%lx)",
            p_gpr_rsp->status,
            p_gpr_rsp->opcode);

        if (p_gpr_rsp->status != AR_EOK) {
            GSL_DBG(
                "DLS_CLIENT_GPR CB: GPR_IBASIC_RSP_RESULT failed, result(%lu),clientToken(%lu)",
                p_gpr_rsp->status,
                packet->token);
        }

        __gpr_cmd_free(packet);
        gsl_signal_set(&dls_client_ctxt.sig, 0, 0, NULL);
        break;
    }

    case APM_EVENT_MODULE_TO_CLIENT:
    {
        apm_module_event_t *apm_event = NULL;
        apm_event = GPR_PKT_GET_PAYLOAD(apm_module_event_t, packet);
        if (DLS_DATA_EVENT_ID_COMMIT_LOG_BUFFER == apm_event->event_id)
        {
            GSL_DBG(
                "recieved dls commit event: opcode(0x%x) event(0x%x) ",
                packet->opcode, apm_event->event_id);
            dls_client_ctxt.buffer_ready_callback();
            __gpr_cmd_free(packet);
            gsl_signal_set(&dls_client_ctxt.ready_buffer_sig, 0, 0, NULL);
        }
        break;
    }
    default:
        break;
    }
    return AR_EOK;
}

int32_t gsl_dls_client_init(struct gsl_dls_buffer_pool_config_t *buffer_pool_config, GSL_DLS_CLIENT_BUFFER_READY_CALLBACK callback)
{
    int32_t rc = AR_EOK;

    rc = __gpr_cmd_register(GSL_DLS_CLIENT_GPR_SRC_PORT, gsl_dls_client_event_callback, &dls_client_ctxt);
    if (rc) {
        GSL_ERR("unable to register gsl dls client with gpr. status %d", rc);
        return rc;
    }

    rc = gsl_signal_create(&dls_client_ctxt.sig, &dls_client_ctxt.sig_lock);
    if (rc) {
        GSL_ERR("unable to create signal for dls events. status %d", rc);
        __gpr_cmd_deregister(GSL_DLS_CLIENT_GPR_SRC_PORT);
        return rc;
    }

    rc = gsl_signal_create(&dls_client_ctxt.ready_buffer_sig, NULL);
    GSL_ERR("Created ready buffer signal");
    if (rc) {
        GSL_ERR("unable to create signal for ready buffer event. status %d", rc);
        return rc;
    }

    rc = gsl_dls_client_create_buffer_pool(buffer_pool_config);
    if (rc) {
        GSL_ERR("unable to create shared memory pool. status %d", rc);
        gsl_signal_destroy(&dls_client_ctxt.sig);
        __gpr_cmd_deregister(GSL_DLS_CLIENT_GPR_SRC_PORT);
        return rc;
    }

    /* todo : Move dls_client_ctxt.is_dls_buffer_configured = 1 to
     * gsl_dls_client_event_callback, once GPR_Basic_Response
     * contains payload which will identify PID for which it is sent
     */
    dls_client_ctxt.is_dls_buffer_configured = 1;
    dls_client_ctxt.buffer_ready_callback = callback;

    GSL_DBG("gsl dls client is initialized");
    return rc;
}

int32_t gsl_dls_client_deinit()
{
    int32_t rc = AR_EOK;
    GSL_DBG("deinitializing gls dls client");

    gsl_dls_client_register_deregister_commit_log_buffer_event(GLS_DLS_EVENT_FLAG_DEREGISTER_COMMIT_LOG_BUFFER);

    rc = gsl_signal_destroy(&dls_client_ctxt.sig);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to destroy dls client signal. status %d", rc);
    }

    rc = __gpr_cmd_deregister(GSL_DLS_CLIENT_GPR_SRC_PORT);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to deregister dls source port with gpr. status %d", rc);
    }

    rc = gsl_shmem_free(&dls_client_ctxt.dls_shmem);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to free dls client shared memory. status %d", rc);
    }

    rc = gsl_signal_destroy(&dls_client_ctxt.sig);
    if (AR_FAILED(rc)) {
        GSL_ERR("failed to destroy client context signal. status %d", rc);
    }

    dls_client_ctxt.is_dls_buffer_configured = 0;
    dls_client_ctxt.buffer_ready_callback = NULL;
    return rc;
}
