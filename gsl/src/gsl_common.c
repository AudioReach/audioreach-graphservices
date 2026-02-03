/**
 * \file gsl_common.c
 *
 * \brief
 *      Common utilities used by various modules within GSL, this is the
 *      lowest level module within GSL
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_common.h"
#include "ar_osal_error.h"
#include "ar_osal_mutex.h"
#include "ar_osal_sys_id.h"
#include "gpr_api_inline.h"
#include "apm_api.h"
#include "ar_util_err_detection.h"
#include "ar_osal_servreg.h"

uint32_t gsl_signal_create(struct gsl_signal *sig_p, ar_osal_mutex_t *lock)
{
	if (!sig_p)
		return AR_EBADPARAM;

	sig_p->flags = 0;
	sig_p->status = 0;
	sig_p->gpr_packet = NULL;
	sig_p->lock = lock;
	sig_p->expected_packet_token = 0;

	return ar_osal_signal_create(&sig_p->sig);
}

uint32_t gsl_signal_destroy(struct gsl_signal *sig_p)
{
	uint32_t rc = AR_EOK;

	if (!sig_p)
		return AR_EBADPARAM;

	if (sig_p->lock)
		GSL_MUTEX_LOCK(*sig_p->lock);

	/* if there was a pending gpr packet that never got consumed free it */
	if (sig_p->gpr_packet)
		__gpr_cmd_free(sig_p->gpr_packet);
	sig_p->gpr_packet = NULL;
	sig_p->expected_packet_token = 0;

	rc = ar_osal_signal_destroy(sig_p->sig);
	sig_p->sig = NULL;
	if (sig_p->lock)
		GSL_MUTEX_UNLOCK(*sig_p->lock);

	sig_p->lock = NULL;

	return rc;
}

uint32_t gsl_signal_timedwait(struct gsl_signal *sig_p, uint32_t timeout_ms,
	uint32_t *ev_flags, uint32_t *status, gpr_packet_t **gpr_packet)
{
	uint32_t rc = AR_EOK;

	if (!sig_p)
		return AR_EBADPARAM;

	rc = ar_osal_signal_timedwait(sig_p->sig, GSL_TIMEOUT_NS(timeout_ms));
	if (!rc) {
		if (sig_p->lock)
			GSL_MUTEX_LOCK(*sig_p->lock);
		ar_osal_signal_clear(sig_p->sig);
		*ev_flags = sig_p->flags;
		if (status)
			*status = sig_p->status;
		if (gpr_packet)
			*gpr_packet = (gpr_packet_t *) sig_p->gpr_packet;
		sig_p->gpr_packet = NULL;
		sig_p->flags = 0; /* clear */
		sig_p->status = 0;
		if (sig_p->lock)
			GSL_MUTEX_UNLOCK(*sig_p->lock);
	}
	// clear gpr packet token
	sig_p->expected_packet_token = 0;
	return rc;
}

uint32_t gsl_signal_set(struct gsl_signal *sig_p, uint32_t ev_flags,
	int32_t status, void *gpr_packet)
{
	uint32_t rc = AR_EOK;

	if (!sig_p)
		return AR_EBADPARAM;

	if (sig_p->lock)
		GSL_MUTEX_LOCK(*sig_p->lock);
	sig_p->flags |= ev_flags;
	sig_p->status = status;
	/* if there was a pending gpr packet that never got consumed free it */
	if (sig_p->gpr_packet)
		__gpr_cmd_free(sig_p->gpr_packet);
	if (gpr_packet && sig_p->expected_packet_token != ((gpr_packet_t *)gpr_packet)->token) {
		// there is a delay packet received, just ignore it.
		GSL_ERR("received a delay packet, opcode[0x%x], token 0x%08x, ignore it.",
			((gpr_packet_t *)gpr_packet)->opcode, ((gpr_packet_t *)gpr_packet)->token);
		rc = AR_EUNEXPECTED;
		goto exit;
	}
	sig_p->gpr_packet = gpr_packet;
	rc = ar_osal_signal_set(sig_p->sig);

exit:
	if (sig_p->lock)
		GSL_MUTEX_UNLOCK(*sig_p->lock);

	return rc;
}

uint32_t gsl_signal_clear(struct gsl_signal *sig_p, uint32_t ev_flags)
{
	uint32_t rc = AR_EOK;

	if (!sig_p)
		return AR_EBADPARAM;
	if (sig_p->lock)
		GSL_MUTEX_LOCK(*sig_p->lock);
	sig_p->flags &= ~ev_flags;
	rc = ar_osal_signal_clear(sig_p->sig);
	if (sig_p->lock)
		GSL_MUTEX_UNLOCK(*sig_p->lock);

	return rc;
}

int32_t gsl_allocate_gpr_packet(uint32_t opcode, uint32_t src_port,
	uint32_t dst_port, uint32_t payload_size, uint32_t token,
	uint32_t dest_domain, struct gpr_packet_t **alloc_packet)
{
	int32_t rc = AR_EOK;
	gpr_cmd_alloc_ext_t	alloc_params;

	alloc_params.src_domain_id = GSL_GPR_SRC_DOMAIN_ID;
	alloc_params.dst_domain_id = (uint8_t) dest_domain;
	alloc_params.client_data = 0;

	alloc_params.src_port = src_port;
	alloc_params.dst_port = dst_port;
	alloc_params.token = token;
	alloc_params.opcode = opcode;
	alloc_params.payload_size = payload_size;
	alloc_params.ret_packet = alloc_packet;

	rc = __gpr_cmd_alloc_ext(&alloc_params);
	return rc;
}

/* Payload must be 8B aligned for spf */
int32_t gsl_send_spf_cmd(gpr_packet_t **packet, struct gsl_signal *sig_p,
	gpr_packet_t **rsp_pkt)
{
	int32_t rc = AR_EOK;
	uint32_t ev_flags = 0, spf_status = 0, i = 0;
	uint32_t opcode = (*packet)->opcode;
	struct gsl_servreg_handle_list *restart_handle_list;
	bool_t do_restart = false;
	static uint32_t debug_token = 0; /* token is echoed in SPF log */

	#ifdef GSL_DEBUG_ENABLE
	/* Cache debug variables for later
	 * Needed as there is no guarantee of packet surviving beyond async_send
	 */
	uint32_t src_port = (*packet)->src_port,
		dst_port = (*packet)->dst_port;
	#endif
	if(opcode != APM_CMD_REGISTER_MODULE_EVENTS) {
		if ((debug_token << DEBUG_TOKEN_SHIFT) == 0)
			++debug_token;
		INSERT_DEBUG_TOKEN((*packet)->token, debug_token);
		++debug_token;
        	if(sig_p == NULL)
			GSL_VERBOSE("sending pkt opcode 0x%x token 0x%08x", opcode, (*packet)->token);
	}
	if (sig_p != NULL)
		sig_p->expected_packet_token = (*packet)->token;

	rc = __gpr_cmd_async_send(*packet);
	if (rc) {
		__gpr_cmd_free(*packet);
		goto exit;
	}

	if (sig_p != NULL) {
		GSL_DBG("Wait for Rsp opcode[0x%x] src_port[0x%x] dst_port[0x%x] token 0x%08x",
			opcode, src_port, dst_port, (*packet)->token);
		/*
		 * once osal signal is set it remains set till cleared, so if we
		 * got a set before wait is called the below wait will immediately
		 * return
		 */
		if (opcode == APM_CMD_GRAPH_OPEN) {
			rc = gsl_signal_timedwait(sig_p, GSL_GRAPH_OPEN_TIMEOUT_MS,
				&ev_flags, &spf_status, rsp_pkt);
		} else if (opcode == APM_CMD_GRAPH_START || opcode == APM_CMD_GRAPH_STOP) {
			rc = gsl_signal_timedwait(sig_p, GSL_GRAPH_START_STOP_TIMEOUT_MS,
				&ev_flags, &spf_status, rsp_pkt);
		} else if (opcode == APM_CMD_GRAPH_PREPARE) {
			rc = gsl_signal_timedwait(sig_p, GSL_GRAPH_PREPARE_TIMEOUT_MS, &ev_flags,
				&spf_status, rsp_pkt);
		} else {
			rc = gsl_signal_timedwait(sig_p, GSL_SPF_TIMEOUT_MS, &ev_flags,
				&spf_status, rsp_pkt);
		}

		if (opcode != APM_CMD_REGISTER_MODULE_EVENTS) {
			GSL_DBG("rcvd pkt token : 0x%x", (*packet)->token);
			REMOVE_DEBUG_TOKEN((*packet)->token);
		}
		GSL_DBG("Wait done rc[0x%x] opcd[0x%x] src_prt[0x%x] dst_prt[0x%x]",
			rc, opcode, src_port, dst_port);
		GSL_DBG("flags[0x%x] spf_status[0x%x]",	ev_flags, spf_status);

		if (rc) {
			rc = AR_ETIMEOUT;
			spf_status = AR_ETIMEOUT;
		} else if (ev_flags & GSL_SIG_EVENT_MASK_CLOSE)
			rc = AR_EABORTED;
		else if (ev_flags & GSL_SIG_EVENT_MASK_SSR)
			rc = AR_ESUBSYSRESET;
		else if ((ev_flags & GSL_SIG_EVENT_MASK_SPF_RSP)) {
			rc = spf_status;
			if (rsp_pkt && *rsp_pkt) {
				GSL_LOG_PKT("recv_pkt", ((gpr_packet_t *)(*rsp_pkt))->src_port,
					(gpr_packet_t *)(*rsp_pkt),
					GPR_PKT_GET_HEADER_BYTE_SIZE(
					((gpr_packet_t *)(*rsp_pkt))->header) +
					GPR_PKT_GET_PAYLOAD_BYTE_SIZE(
					((gpr_packet_t *)(*rsp_pkt))->header), NULL, 0);
			}
		}

		if (spf_status) {
			/* error detection */
			rc = ar_err_det_detect_spf_error((*packet)->dst_domain_id,
				spf_status, opcode, &do_restart, (void *)&restart_handle_list);

			if (rc) {
				GSL_ERR("Error detection failed. Not restarting");
			} else if (do_restart) {
				/* we get an array of the handles to restart back
				 * first entry is number of array entries following
				 */
				for (i = 0; i < restart_handle_list->num_handles; ++i) {
					ar_osal_servreg_restart_service(
						restart_handle_list->handles[i]);
				}
			}
			rc = spf_status;
		}
	}

exit:
	/* mark packet null to indicate it has been sent */
	*packet = NULL;
	return rc;
}

int32_t gsl_send_spf_cmd_wait_for_basic_rsp(gpr_packet_t **packet,
	struct gsl_signal *sig_p)
{
	int32_t rc = AR_EOK;
	gpr_packet_t *rsp = NULL;
	struct spf_cmd_basic_rsp *basic_rsp = NULL;
	uint32_t cached_opcode = (*packet)->opcode;
	/* cache opcode since packet is freed when sent */

	rc = gsl_send_spf_cmd(packet, sig_p, &rsp);
	if (!rc && rsp && rsp->opcode == GPR_IBASIC_RSP_RESULT) {
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, rsp);
		if (cached_opcode != basic_rsp->opcode) {
			GSL_ERR("Recieved unexpected rsp opcode %x, expected %x",
				basic_rsp->opcode, cached_opcode);
			rc = AR_EUNEXPECTED;
		}
	}

	if (rsp)
		__gpr_cmd_free(rsp);

	return rc;
}

int32_t gsl_send_spf_satellite_info(uint32_t proc_id,
	uint32_t supported_ss_mask, uint32_t src_port, struct gsl_signal *sig_p)
{
	uint32_t i = 0, j = 0;
	gpr_cmd_alloc_ext_t gpr_args;
	int32_t rc = AR_EOK;
	gpr_packet_t *send_pkt = NULL;
	apm_cmd_header_t *apm_hdr;
	apm_param_id_satellite_pd_info_t *sat_pd_info;
	apm_module_param_data_t *param_hdr;

	if (supported_ss_mask == (uint32_t) GSL_GET_SPF_SS_MASK(proc_id))
		return AR_EOK;

	gpr_args.src_domain_id = GPR_IDS_DOMAIN_ID_APPS_V;
	gpr_args.dst_domain_id = (uint8_t) proc_id;
	gpr_args.src_port = src_port;
	gpr_args.dst_port = APM_MODULE_INSTANCE_ID;
	gpr_args.opcode = APM_CMD_SET_CFG;
	gpr_args.token = 0;
	gpr_args.client_data = 0;
	gpr_args.ret_packet = &send_pkt;
	/* below allocate for worst case since payload size is small enough */
	gpr_args.payload_size = sizeof(apm_cmd_header_t)
		+ sizeof(apm_module_param_data_t)
		+ sizeof(apm_param_id_satellite_pd_info_t)
		+ ((AR_SUB_SYS_ID_LAST + 1) * sizeof(uint32_t));

	rc = __gpr_cmd_alloc_ext(&gpr_args);
	if (rc) {
		GSL_ERR("Failed to allocate gpr pkt %d", rc);
		goto exit;
	}

	apm_hdr = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
	apm_hdr->mem_map_handle = 0;
	apm_hdr->payload_address_lsw = 0;
	apm_hdr->payload_address_msw = 0;
	apm_hdr->payload_size = sizeof(apm_module_param_data_t)
		+ sizeof(apm_param_id_satellite_pd_info_t)
		+ ((AR_SUB_SYS_ID_LAST + 1) * sizeof(uint32_t));

	param_hdr = (apm_module_param_data_t *)(apm_hdr + 1);
	param_hdr->module_instance_id = APM_MODULE_INSTANCE_ID;
	param_hdr->param_id = APM_PARAM_ID_SATELLITE_PD_INFO;
	param_hdr->param_size = sizeof(apm_param_id_satellite_pd_info_t)
		+ ((AR_SUB_SYS_ID_LAST + 1) * sizeof(uint32_t));
	param_hdr->error_code = 0;

	sat_pd_info = (apm_param_id_satellite_pd_info_t *)(param_hdr + 1);

	/*
	 * disable ADSP from the bitmask for now as we assume master is on
	 * ADSP. This can be revisited in the future once we add support for
	 * multiple masters
	 */
	supported_ss_mask &= ~proc_id;
	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; ++i) {
		if (GSL_TEST_SPF_SS_BIT(supported_ss_mask, i))
			sat_pd_info->proc_domain_id_list[j++] = i;
	}

	sat_pd_info->num_proc_domain_ids = j;
	if (sat_pd_info->num_proc_domain_ids > 0) {
		GSL_LOG_PKT("send_pkt", src_port, send_pkt, sizeof(*send_pkt)
			+ gpr_args.payload_size, NULL, 0);
		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt, sig_p);
		if (rc)
			GSL_ERR("failed to send spf satellite info rc %d", rc);
	}
exit:
	return rc;
}
