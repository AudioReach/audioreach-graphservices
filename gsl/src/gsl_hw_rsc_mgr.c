/**
 * \file gsl_hw_rsc_mgr.c
 *
 * \brief
 *      Main entry point for GSL hardware resource manager

 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_signal.h"
#include "ar_osal_error.h"
#include "gpr_api_inline.h"
#include "apm_api.h"
#include "prm_api.h"
#include "gsl_hw_rsc_intf.h"
#include "gsl_common.h"
#include "acdb.h"

#define GSL_HW_RSC_SRC_PORT  0x2004

struct gsl_hw_rsc_ctxt_ {
	/**
	 * Refcnt to track mgr's clients
	 */
	int32_t ref_cnt;
	/**
	 * Mutex to be used when resource to be
	 * requested/released
	 */
	 ar_osal_mutex_t rsc_lock;
	/**
	 * Signal used to wait for responses from spf
	 */
	struct gsl_signal sig;
	/**
	 * lock used in conjuction with above signal
	 */
	ar_osal_mutex_t sig_lock;
	/**
	 * buffer in which to store response. Allocated and managed by client.
	 */
	void *rsp_buff;
	/**
	 * size of rsp_buff. Initially holds size allocated by client. GSL sets to
	 * size written into buffer, if any.
	 */
	uint32_t rsp_buff_sz;
} gsl_hw_rsc_ctxt;

static uint32_t gsl_hw_rsc_mgr_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
	struct prm_cmd_rsp_hw_rsc_cfg_t *cmd_rsp;
	struct gsl_hw_rsc_ctxt_ *ctxt;
	struct spf_cmd_basic_rsp *basic_rsp;
	uint32_t ret = 0;

	ctxt = (struct gsl_hw_rsc_ctxt_ *)cb_data;
	switch (packet->opcode) {
	case PRM_CMD_RSP_REQUEST_HW_RSC:
	case PRM_CMD_RSP_RELEASE_HW_RSC:
		cmd_rsp = GPR_PKT_GET_PAYLOAD(
			struct prm_cmd_rsp_hw_rsc_cfg_t, packet);
		ret = cmd_rsp->status;
		if (!cmd_rsp->status) {
			// differentiate request vs release on packet->opcode if needed
			if (gsl_hw_rsc_ctxt.rsp_buff && gsl_hw_rsc_ctxt.rsp_buff_sz
				>= GPR_PKT_GET_PAYLOAD_BYTE_SIZE(packet->header)) {
				gsl_memcpy(gsl_hw_rsc_ctxt.rsp_buff,
					gsl_hw_rsc_ctxt.rsp_buff_sz, (uint8_t *)cmd_rsp,
					GPR_PKT_GET_PAYLOAD_BYTE_SIZE(packet->header));
				gsl_hw_rsc_ctxt.rsp_buff_sz =
					GPR_PKT_GET_PAYLOAD_BYTE_SIZE(packet->header);
			}
		}
		GSL_DBG("Received response 0x%x, status 0x%x", packet->opcode,
			cmd_rsp->status);
		gsl_signal_set(&ctxt->sig, GSL_SIG_EVENT_MASK_SPF_RSP,
			cmd_rsp->status, NULL);
		break;
	case GPR_IBASIC_RSP_RESULT:
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, packet);
		GSL_ERR("Received basic response 0x%x, status 0x%x", packet->opcode,
			basic_rsp->status);
		gsl_signal_set(&ctxt->sig, GSL_SIG_EVENT_MASK_SPF_RSP,
			basic_rsp->status, NULL);
		break;
	default:
		GSL_DBG("Received unsupported opcode 0x%x",	packet->opcode);
		break;
	};

	__gpr_cmd_free(packet);
	return ret;
}

/** Caller of this function should free the AcdbBlob*/
static int32_t gsl_acdb_get_driver_data(uint32_t miid,
	const struct gsl_key_vector *key_vect, AcdbBlob *payload)
{
	AcdbDriverData drv_data;
	AcdbGraphKeyVector *acdb_key_vect = &drv_data.key_vector;
	int32_t rc = AR_EOK;

	if (!payload)
		return AR_EBADPARAM;

	payload->buf = NULL;
	payload->buf_size = 0;
	acdb_key_vect->num_keys = key_vect->num_kvps;
	acdb_key_vect->graph_key_vector = (AcdbKeyValuePair *)key_vect->kvp;
	drv_data.module_id = miid;

	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &drv_data, sizeof(drv_data),
		payload, sizeof(*payload));
	if (rc) {
		GSL_ERR("failed to get size for driver data for miid: 0x%x, rc:%d",
			miid, rc);
		return rc;
	}
	if (payload->buf_size == 0)
		return AR_EFAILED;

	payload->buf = gsl_mem_zalloc(payload->buf_size);
	if (!payload->buf)
		return AR_ENOMEMORY;

	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &drv_data, sizeof(drv_data),
		payload, sizeof(*payload));
	if (rc) {
		GSL_ERR("failed to get driver data for miid: 0x%x, rc:%d", miid, rc);
		gsl_mem_free(payload->buf);
	}

	return rc;
}

static int32_t gsl_command_hw_rsc_config(uint32_t miid,
	const struct gsl_key_vector *key_vect, uint32_t cmd)
{
	/** Retrieve driver data from ACDB using MIID and key_vect */
	int32_t rc = AR_EOK;
	AcdbBlob payload;
	uint32_t cmd_payload_size = 0;
	struct apm_cmd_header_t *cmd_header;
	uint8_t *cmd_payload, *module_param;
	gpr_packet_t *send_pkt = NULL;

	gsl_hw_rsc_ctxt.rsp_buff = NULL;	//not used here, so don't write to it.
	GSL_MUTEX_LOCK(gsl_hw_rsc_ctxt.rsc_lock);
	rc = gsl_acdb_get_driver_data(miid, key_vect, &payload);
	if (rc) {
		GSL_MUTEX_UNLOCK(gsl_hw_rsc_ctxt.rsc_lock);
		return rc;
	}
	cmd_payload_size = sizeof(*cmd_header) + payload.buf_size;
	rc = gsl_allocate_gpr_packet(cmd, GSL_HW_RSC_SRC_PORT,
		PRM_MODULE_INSTANCE_ID, cmd_payload_size, 0,
		GSL_GPR_DST_DOMAIN_ID, &send_pkt);
	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto free_payload_buf;
	}

	cmd_payload = GPR_PKT_GET_PAYLOAD(uint8_t, send_pkt);
	gsl_memset(cmd_payload, 0, cmd_payload_size);

	cmd_header = (struct apm_cmd_header_t *)cmd_payload;
	cmd_header->payload_size = payload.buf_size;
	module_param = cmd_payload + sizeof(*cmd_header);
	gsl_memcpy(module_param, payload.buf_size, (uint8_t *)payload.buf,
		payload.buf_size);
	*(uint32_t *)module_param = PRM_MODULE_INSTANCE_ID;

	GSL_LOG_PKT("send_pkt", GSL_HW_RSC_SRC_PORT, send_pkt, sizeof(*send_pkt) +
		cmd_payload_size, NULL, 0);
	rc = gsl_send_spf_cmd(&send_pkt, &gsl_hw_rsc_ctxt.sig, NULL);
	if (rc)
		GSL_ERR("hw rsc cmd 0x%x failed:%d", cmd, rc);

free_payload_buf:
	gsl_mem_free(payload.buf);
	GSL_MUTEX_UNLOCK(gsl_hw_rsc_ctxt.rsc_lock);
	return rc;
}

static int32_t gsl_command_hw_rsc_custom_config(const uint8_t *payload,
	size_t payload_size, uint32_t cmd, void *buff, uint32_t *buff_size)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	uint8_t *cmd_payload, *module_param;
	gpr_packet_t *send_pkt = NULL;

	GSL_MUTEX_LOCK(gsl_hw_rsc_ctxt.rsc_lock);

	rc = gsl_allocate_gpr_packet(cmd, GSL_HW_RSC_SRC_PORT,
		PRM_MODULE_INSTANCE_ID, sizeof(*cmd_header) +
		GSL_ALIGN_8BYTE(payload_size), 0,
		GSL_GPR_DST_DOMAIN_ID, &send_pkt);

	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto exit;
	}
	cmd_payload = GPR_PKT_GET_PAYLOAD(uint8_t, send_pkt);
	gsl_memset(cmd_payload, 0, sizeof(*cmd_header) +
		GSL_ALIGN_8BYTE(payload_size));

	cmd_header = (struct apm_cmd_header_t *)cmd_payload;
	cmd_header->payload_size = GSL_ALIGN_8BYTE(payload_size);
	module_param = cmd_payload + sizeof(*cmd_header);
	gsl_memcpy(module_param, GSL_ALIGN_8BYTE(payload_size), (void *)payload,
		payload_size);
	*(uint32_t *)module_param = PRM_MODULE_INSTANCE_ID;

	gsl_hw_rsc_ctxt.rsp_buff = buff;
	gsl_hw_rsc_ctxt.rsp_buff_sz = (buff && buff_size) ? *buff_size : 0;

	GSL_LOG_PKT("send_pkt", GSL_HW_RSC_SRC_PORT, send_pkt, sizeof(*send_pkt) +
		sizeof(*cmd_header) + GSL_ALIGN_8BYTE(payload_size), NULL, 0);
	rc = gsl_send_spf_cmd(&send_pkt, &gsl_hw_rsc_ctxt.sig, NULL);
	if (rc)
		GSL_ERR("hw rsc cmd 0x%x failed:%d", cmd, rc);
	if (rc == AR_ETIMEOUT) {
		gsl_hw_rsc_ctxt.rsp_buff = NULL;
		gsl_hw_rsc_ctxt.rsp_buff_sz = 0;
	}
	if (buff && buff_size)
		*buff_size = gsl_hw_rsc_ctxt.rsp_buff_sz;
exit:
	GSL_MUTEX_UNLOCK(gsl_hw_rsc_ctxt.rsc_lock);
	return rc;
}

int32_t gsl_request_hw_rsc_config(uint32_t miid,
	const struct gsl_key_vector *key_vect)
{
	return gsl_command_hw_rsc_config(miid, key_vect,
		PRM_CMD_REQUEST_HW_RSC);
}

int32_t gsl_release_hw_rsc_config(uint32_t miid,
	const struct gsl_key_vector *key_vect)
{
	return gsl_command_hw_rsc_config(miid, key_vect,
		PRM_CMD_RELEASE_HW_RSC);
}

int32_t gsl_request_hw_rsc_custom_config(const uint8_t *payload,
	size_t payload_size, void *buff, uint32_t *buff_size)
{
	return gsl_command_hw_rsc_custom_config(payload, payload_size,
		PRM_CMD_REQUEST_HW_RSC, buff, buff_size);
}

int32_t gsl_release_hw_rsc_custom_config(const uint8_t *payload,
	size_t payload_size, void *buff, uint32_t *buff_size)
{
	return gsl_command_hw_rsc_custom_config(payload, payload_size,
		PRM_CMD_RELEASE_HW_RSC, buff, buff_size);
}

int32_t gsl_hw_rsc_init(void)
{
	int32_t rc = AR_EOK;

	if (gsl_hw_rsc_ctxt.ref_cnt++ > 0) {
		GSL_ERR("already initialized ref_cnt %d", gsl_hw_rsc_ctxt.ref_cnt);
		goto exit;
	}
	rc = __gpr_cmd_register(GSL_HW_RSC_SRC_PORT,
		gsl_hw_rsc_mgr_gpr_callback, &gsl_hw_rsc_ctxt);
	if (rc) {
		GSL_ERR("gpr register failed for src port 0x%x, rc: %d",
			GSL_HW_RSC_SRC_PORT, rc);
		gsl_hw_rsc_ctxt.ref_cnt = 0;
		goto exit;
	}
	rc = ar_osal_mutex_create(&gsl_hw_rsc_ctxt.sig_lock);
	if (rc) {
		GSL_ERR("failed create mutex %d", rc);
		goto gpr_deinit;
	}
	rc = ar_osal_mutex_create(&gsl_hw_rsc_ctxt.rsc_lock);
	if (rc) {
		GSL_ERR("failed create rsc mgr mutex %d", rc);
		goto destroy_sig_mutex;
	}
	rc = gsl_signal_create(&gsl_hw_rsc_ctxt.sig, &gsl_hw_rsc_ctxt.sig_lock);
	if (rc) {
		GSL_ERR("failed to create signal %d", rc);
		goto destroy_rsc_mutex;
	}

	gsl_hw_rsc_ctxt.rsp_buff = NULL;
	gsl_hw_rsc_ctxt.rsp_buff_sz = 0;
exit:
	return rc;
destroy_rsc_mutex:
	ar_osal_mutex_destroy(gsl_hw_rsc_ctxt.rsc_lock);
destroy_sig_mutex:
	ar_osal_mutex_destroy(gsl_hw_rsc_ctxt.sig_lock);
gpr_deinit:
	__gpr_cmd_deregister(GSL_HW_RSC_SRC_PORT);
	return rc;
}

int32_t gsl_hw_rsc_deinit(void)
{
	if (gsl_hw_rsc_ctxt.ref_cnt && (0 < --gsl_hw_rsc_ctxt.ref_cnt)) {
		GSL_ERR("still in use ref_cnt %d", gsl_hw_rsc_ctxt.ref_cnt);
		goto exit;
	}
	gsl_signal_destroy(&gsl_hw_rsc_ctxt.sig);
	ar_osal_mutex_destroy(gsl_hw_rsc_ctxt.sig_lock);
	ar_osal_mutex_destroy(gsl_hw_rsc_ctxt.rsc_lock);
	__gpr_cmd_deregister(GSL_HW_RSC_SRC_PORT);
exit:
	return AR_EOK;
}
