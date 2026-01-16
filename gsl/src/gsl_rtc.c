/**
 * \file gsl_rtc.c
 *
 * \brief
 *      Implement GSL RTC functionalities
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_error.h"
#include "ar_util_list.h"
#include "gsl_rtc.h"
#include "gsl_rtc_intf.h"
#include "gsl_msg_builder.h"
#include "gsl_common.h"
#include "gsl_mdf_utils.h"
#include "apm_api.h"
#include "gpr_ids_domains.h"
#include "gpr_packet.h"
#include "gpr_api_inline.h"

#define GSL_RTC_SRC_PORT 0x2006

static struct gsl_rtc_internal_ctxt {
	struct gsl_signal sig;
	ar_osal_mutex_t sig_lock;
	uint32_t src_port;
} rtc_internal_ctxt;

static struct gsl_subgraph *gsl_graph_get_sg_ptr(struct gsl_graph *graph,
	uint32_t sg_id)
{
	ar_list_node_t *curr = NULL;;
	struct gsl_graph_gkv_node *gkv_node;
	uint32_t i = 0;

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
			if (gkv_node->sg_array[i]->sg_id == sg_id)
				return gkv_node->sg_array[i];
		}
	}
	return NULL;
}

static uint32_t gsl_rtc_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
	struct gsl_rtc_internal_ctxt *ctxt = NULL;
	struct spf_cmd_basic_rsp *basic_rsp;
	uint32_t rc = AR_EOK;

	ctxt = (struct gsl_rtc_internal_ctxt *)cb_data;
	switch (packet->opcode) {
	case GPR_IBASIC_RSP_RESULT:
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, packet);
		switch (basic_rsp->opcode) {
		case APM_CMD_GET_CFG:
		case APM_CMD_SET_CFG:
		case APM_CMD_REGISTER_CFG:
		case APM_CMD_DEREGISTER_CFG:
			gsl_signal_set(&ctxt->sig, GSL_SIG_EVENT_MASK_SPF_RSP,
				basic_rsp->status, NULL);
			break;
		default:
			GSL_DBG("unknown opcode %x freeing GPR rsp packet",
				basic_rsp->opcode);
			break;
		}
		rc = __gpr_cmd_free(packet);
		break;
	case APM_CMD_RSP_GET_CFG:
		rc = gsl_signal_set(&ctxt->sig, GSL_SIG_EVENT_MASK_SPF_RSP,
				    0, packet);
		break;
	default:
		GSL_DBG("unknown opcode %x freeing GPR rsp packet", packet->opcode);
		rc = __gpr_cmd_free(packet);
		break;
	}

	/* Free gpr packet if signal set failed */
	if (rc) {
	    GSL_DBG("signal failed, freeing GPR rsp packet");
	    rc = __gpr_cmd_free(packet);
	}

	return rc;
}

int32_t gsl_rtc_internal_init(void)
{
	int32_t rc = AR_EOK;

	rc = ar_osal_mutex_create(&rtc_internal_ctxt.sig_lock);
	if (rc) {
		GSL_ERR("ar_osal_mutex_create failed %d", rc);
		return rc;
	}

	rc = gsl_signal_create(&rtc_internal_ctxt.sig, &rtc_internal_ctxt.sig_lock);
	if (rc) {
		GSL_ERR("gsl_signal_create failed %d", rc);
		goto destroy_lock;
	}

	rtc_internal_ctxt.src_port = GSL_RTC_SRC_PORT;

	rc = __gpr_cmd_register(rtc_internal_ctxt.src_port,
		gsl_rtc_gpr_callback, &rtc_internal_ctxt);
	if (rc) {
		GSL_ERR("gpr register callback failed %d", rc);
		goto destroy_signal;
	}

	return rc;

destroy_signal:
	gsl_signal_destroy(&rtc_internal_ctxt.sig);
destroy_lock:
	ar_osal_mutex_destroy(rtc_internal_ctxt.sig_lock);
	return rc;
}

int32_t gsl_rtc_internal_deinit(void)
{
	__gpr_cmd_deregister(rtc_internal_ctxt.src_port);
	gsl_signal_destroy(&rtc_internal_ctxt.sig);
	ar_osal_mutex_destroy(rtc_internal_ctxt.sig_lock);

	return AR_EOK;
}


uint32_t gsl_rtc_graph_copy_gkvs(struct gsl_graph *graph, uint8_t *payload,
	uint32_t *num_gkvs)
{
	uint32_t gkv_bytes = 0;
	struct gsl_rtc_key_vector *gkv;
	ar_list_node_t *curr = NULL;;
	struct gsl_graph_gkv_node *gkv_node;

	*num_gkvs = 0;
	gkv_bytes = 0;
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);

		(*num_gkvs)++;
		gkv = (struct gsl_rtc_key_vector *)(payload + gkv_bytes);
		gkv->num_kvps = gkv_node->gkv.num_kvps;

		if (gkv_node->gkv.num_kvps != 0) {
			gsl_memcpy(gkv->kvp,
				gkv->num_kvps * sizeof(struct gsl_key_value_pair),
				gkv_node->gkv.kvp,
				gkv_node->gkv.num_kvps * sizeof(struct gsl_key_value_pair));
		}
		gkv_bytes += GSL_RTC_GKV_SIZE_BYTES(gkv_node->gkv.num_kvps);
	}
	return gkv_bytes;
}

uint32_t gsl_rtc_graph_copy_ckvs(struct gsl_graph *graph, uint8_t *payload,
	uint32_t *num_ckvs)
{
	uint32_t ckv_bytes = 0;
	struct gsl_rtc_key_vector *ckv;
	ar_list_node_t *curr = NULL;;
	struct gsl_graph_gkv_node *gkv_node;

	*num_ckvs = 0;
	ckv_bytes = 0;
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);

		(*num_ckvs)++;
		ckv = (struct gsl_rtc_key_vector *)(payload + ckv_bytes);
		ckv->num_kvps = gkv_node->ckv.num_kvps;

		if (gkv_node->ckv.num_kvps != 0) {
			gsl_memcpy(ckv->kvp,
				ckv->num_kvps * sizeof(struct gsl_key_value_pair),
				gkv_node->ckv.kvp,
				gkv_node->ckv.num_kvps * sizeof(struct gsl_key_value_pair));
		}
		ckv_bytes += GSL_RTC_GKV_SIZE_BYTES(gkv_node->ckv.num_kvps);
	}
	return ckv_bytes;
}

uint32_t gsl_rtc_graph_get_gkv_ckv_size(struct gsl_graph *graph)
{
	ar_list_node_t *curr = NULL;;
	struct gsl_graph_gkv_node *gkv_node;
	uint32_t gkv_node_size = 0;

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		gkv_node_size += GSL_RTC_GKV_SIZE_BYTES(gkv_node->gkv.num_kvps);
		gkv_node_size += GSL_RTC_GKV_SIZE_BYTES(gkv_node->ckv.num_kvps);
	}

	return gkv_node_size;
}

int32_t gsl_rtc_graph_get_persist_data(struct gsl_graph *graph, uint32_t sgid,
	uint32_t proc_id, uint32_t *total_size, uint8_t **sg_cal_data)
{
	struct gsl_subgraph *sg;

	sg = gsl_graph_get_sg_ptr(graph, sgid);
	if (!sg) {
		GSL_ERR("no subgraph with sgid 0x%x", sgid);
		return AR_ENOTEXIST;
	}
	if (!total_size || !sg_cal_data)
		return AR_EFAILED;

	for (int persist_cal_idx = 0; persist_cal_idx < sg->num_proc_ids; persist_cal_idx++) {
		if (sg->persist_cal_data_per_proc[persist_cal_idx].proc_id == proc_id) {
			if (sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr)
				*sg_cal_data = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr;
			*total_size = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size;
		}
	}

	return AR_EOK;
}

int32_t gsl_rtc_graph_get_non_persist_data(struct gsl_graph *graph,
	uint32_t total_size, uint8_t *sg_cal_data)
{
	int32_t rc = AR_EOK;
	apm_cmd_header_t *cmd_header;
	gpr_packet_t *rsp_pkt = NULL;
	gsl_msg_t gsl_msg;
	struct apm_cmd_rsp_get_cfg_t *get_cfg_rsp;
	bool_t is_shmem_supported = TRUE;

	__gpr_cmd_is_shared_mem_supported(graph->proc_id, &is_shmem_supported);
	if (sg_cal_data == NULL) {
		GSL_ERR("sg_cal_data is NULL");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_msg_alloc(APM_CMD_GET_CFG, rtc_internal_ctxt.src_port,
			   APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
			   0, graph->proc_id, total_size, false, &gsl_msg);

	if (rc) {
		GSL_ERR("gsl msg alloc failed %d", rc);
		goto exit;
	}

	gsl_memcpy(gsl_msg.payload, total_size, sg_cal_data, total_size);

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
					 gsl_msg.gpr_packet);
	cmd_header->payload_size = total_size;

	GSL_LOG_PKT("send_pkt", rtc_internal_ctxt.src_port, gsl_msg.gpr_packet,
		    sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header), gsl_msg.payload,
		    cmd_header->payload_size);

	if (!is_shmem_supported) {
		rc = gsl_send_spf_cmd(&gsl_msg.gpr_packet,
				      &rtc_internal_ctxt.sig, &rsp_pkt);
		if (rc || !rsp_pkt) {
			GSL_ERR("Graph get cfg cmd 0x%x failure:%d", APM_CMD_GET_CFG, rc);
			goto free_gsl_msg;
		}

		get_cfg_rsp = GPR_PKT_GET_PAYLOAD(struct apm_cmd_rsp_get_cfg_t,
			rsp_pkt);
		if (get_cfg_rsp->status != AR_EOK) {
			GSL_ERR("Graph get config failed: spf status %d",
				get_cfg_rsp->status);
			rc = AR_EFAILED;
			goto free_gsl_msg;
		}

		gsl_memcpy(sg_cal_data, total_size, (uint8_t *)get_cfg_rsp +
			   sizeof(apm_cmd_rsp_get_cfg_t), total_size);
	} else {
		cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
		cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
		cmd_header->payload_address_msw =
			(uint32_t)(gsl_msg.shmem.spf_addr >> 32);
		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
							 &rtc_internal_ctxt.sig);
		if (rc)
			GSL_ERR("Graph get cfg cmd 0x%x failure:%d", APM_CMD_GET_CFG, rc);

		gsl_memcpy(sg_cal_data, total_size, gsl_msg.payload, total_size);
	}

free_gsl_msg:
	gsl_msg_free(&gsl_msg);

exit:
	if (rsp_pkt != NULL) {
		__gpr_cmd_free(rsp_pkt);
		rsp_pkt = NULL;
	}
	return rc;
}

int32_t gsl_rtc_graph_set_non_persist_data(struct gsl_graph *graph,
	uint32_t total_size, uint8_t *sg_cal_data)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	gsl_msg_t gsl_msg;

	rc = gsl_msg_alloc(APM_CMD_SET_CFG, rtc_internal_ctxt.src_port,
			   APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
			   0, graph->proc_id, total_size, false, &gsl_msg);

	if (rc) {
		GSL_ERR("gsl msg alloc failed %d", rc);
		goto exit;
	}

	gsl_memcpy(gsl_msg.payload, total_size, sg_cal_data, total_size);

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
					 gsl_msg.gpr_packet);
	cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	cmd_header->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	cmd_header->payload_size = total_size;

	GSL_LOG_PKT("send_pkt", rtc_internal_ctxt.src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header), gsl_msg.payload,
		cmd_header->payload_size);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&rtc_internal_ctxt.sig);
	if (rc)
		GSL_ERR("Graph set cfg cmd 0x%x failure:%d", APM_CMD_SET_CFG, rc);

	gsl_msg_free(&gsl_msg);

exit:
	return rc;
}

int32_t gsl_rtc_graph_set_persist_data(struct gsl_graph *graph,
	struct gsl_rtc_persist_param *params)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	struct gsl_subgraph *sg;
	gpr_packet_t *send_pkt = NULL;
	uint64_t cal_paddr_w_offset = 0;

	if (!graph)
		return AR_EFAILED;
	sg = gsl_graph_get_sg_ptr(graph, params->sgid);
	if (!sg)
		return AR_EFAILED;
	GSL_DBG("num procs per SG - %d", sg->num_proc_ids);
	for (int persist_cal_idx = 0; persist_cal_idx < sg->num_proc_ids; persist_cal_idx++) {
		if (sg->persist_cal_data_per_proc[persist_cal_idx].proc_id == params->proc_id) {
			if (!sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr)
				return AR_EFAILED;

			GSL_DBG("proc_id[%d] - %d", persist_cal_idx, sg->persist_cal_data_per_proc[persist_cal_idx].proc_id);

			rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
				rtc_internal_ctxt.src_port, APM_MODULE_INSTANCE_ID,
				sizeof(*cmd_header), 0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto exit;
			}
			/*
			* below offset used to skip acdb header before sending data to
			* spf
			*/
			cal_paddr_w_offset = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.spf_addr +
				sizeof(AcdbSgIdPersistData);
			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t)cal_paddr_w_offset;
			cmd_header->payload_address_msw = (uint32_t)(cal_paddr_w_offset >> 32);
			cmd_header->payload_size = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size -
				sizeof(AcdbSgIdPersistData);

			GSL_LOG_PKT("send_pkt", rtc_internal_ctxt.src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header), sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr,
				cmd_header->payload_size);

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&rtc_internal_ctxt.sig);
			if (rc) {
				GSL_ERR("Graph deregister cfg cmd 0x%x failure:%d",
					APM_CMD_DEREGISTER_CFG, rc);
				return rc;
			}

			/* if user did not pass data, then read from acdb */
			if (!params->sg_cal_data) {
				rc = gsl_subgraph_query_persist_cal_by_mem(sg,
					(struct gsl_key_vector *)params->ckv, ACDB_HW_ACCEL_MEM_DEFAULT,
					graph->proc_id, persist_cal_idx);
				if (rc) {
					GSL_ERR("Failed to query persist cal %d", rc);
					goto exit;
				}
			} else {
				rc = gsl_subgraph_set_persist_cal(sg, params->sg_cal_data,
					*params->total_size, graph->proc_id, persist_cal_idx);
				if (rc) {
					GSL_ERR("Failed to set persist cal %d", rc);
					goto exit;
				}
			}

			rc = gsl_allocate_gpr_packet(APM_CMD_REGISTER_CFG,
				rtc_internal_ctxt.src_port, APM_MODULE_INSTANCE_ID,
				sizeof(*cmd_header), 0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto exit;
			}
			/*
			* below offset used to skip acdb header before sending data to
			* spf
			*/
			cal_paddr_w_offset = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.spf_addr +
				sizeof(AcdbSgIdPersistData);

			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t)cal_paddr_w_offset;
			cmd_header->payload_address_msw = (uint32_t)(cal_paddr_w_offset >> 32);
			cmd_header->payload_size = sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size -
				sizeof(AcdbSgIdPersistData);

			GSL_LOG_PKT("send_pkt", rtc_internal_ctxt.src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header), sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr,
				cmd_header->payload_size);

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&rtc_internal_ctxt.sig);
			if (rc)
				GSL_ERR("Graph register cfg cmd 0x%x failure:%d",
					APM_CMD_REGISTER_CFG, rc);
		}
	}
exit:
	return rc;
}

int32_t gsl_rtc_internal_prepare_change_graph(struct gsl_graph *graph,
	struct gsl_rtc_prepare_change_graph_info *rtc_params,
	ar_osal_mutex_t lock)
{
	struct gsl_prepare_change_graph_single_gkv_params cg_params = { 0, };
	uint32_t *p, num_sgs = 0, i = 0;
	int32_t rc = AR_EOK;

	if (!graph || !rtc_params ||
		(rtc_params->size_of_sg_conn_info == 0 && rtc_params->num_sgs > 0))
		/* last check prevents null deref of cg_params.sgs */
		return AR_EBADPARAM;

	cg_params.old_gkv.num_kvps = rtc_params->old_gkv->num_kvps;
	cg_params.old_gkv.kvp = rtc_params->old_gkv->kvp;

	if (rtc_params->size_of_sg_conn_info > 0) {
		cg_params.sgs = gsl_mem_zalloc(rtc_params->num_sgs * sizeof(uint32_t));
		if (!cg_params.sgs) {
			GSL_ERR("out of memory");
			rc = AR_ENOMEMORY;
			goto exit;
		}
	}
	/*
	 * Below loop is to copy the sgids
	 */
	p = rtc_params->sg_conn_info;
	for (i = 0; i < rtc_params->num_sgs; ++i) {
		cg_params.sgs[i] = *p;
		/* skip over subgraph_id, size and child subgraph list */
		++p;
		p = p + *p + 1;
	}

	gsl_print_sg_conn_info((uint32_t *)rtc_params->sg_conn_info,
		rtc_params->num_sgs);

	cg_params.num_sgs = rtc_params->num_sgs;
	cg_params.sg_conn_info.num_sgs = num_sgs; /* yes duplicated I know... */
	cg_params.sg_conn_info.size = rtc_params->size_of_sg_conn_info;
	cg_params.sg_conn_info.subgraphs =
		(AcdbSubgraph *)rtc_params->sg_conn_info;

	cg_params.num_sgs_to_reopen = rtc_params->num_modified_sgs;
	cg_params.sgs_to_reopen = rtc_params->modified_sgs;
	cg_params.sg_conn_info_to_reopen.num_sgs =
		rtc_params->num_modified_sg_connections;
	cg_params.sg_conn_info_to_reopen.size =
		rtc_params->size_of_modified_sg_conn_info;
	cg_params.sg_conn_info_to_reopen.subgraphs =
		(AcdbSubgraph *)rtc_params->modified_sg_conn_info;

	rc = gsl_graph_prepare_to_change_single_gkv(graph, &cg_params, lock);
	if (rc)
		GSL_ERR("prepare_to_change_single_gkv failed rc %d", rc);

	gsl_mem_free(cg_params.sgs);
exit:
	return rc;
}

int32_t gsl_rtc_internal_change_graph(struct gsl_graph *graph,
	struct gsl_rtc_change_graph_info *rtc_params,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	struct gsl_change_graph_single_gkv_params cg_params;

	if (!graph || !rtc_params)
		return AR_EBADPARAM;

	cg_params.old_gkv.num_kvps = rtc_params->old_gkv->num_kvps;
	cg_params.old_gkv.kvp = rtc_params->old_gkv->kvp;

	cg_params.new_gkv.num_kvps = rtc_params->new_gkv->num_kvps;
	cg_params.new_gkv.kvp = rtc_params->new_gkv->kvp;

	cg_params.new_ckv.num_kvps = rtc_params->new_ckv->num_kvps;
	cg_params.new_ckv.kvp = rtc_params->new_ckv->kvp;

	rc = gsl_graph_change_single_gkv(graph, &cg_params, lock);
	if (rc)
		GSL_ERR("change_single_gkv failed rc %d", rc);

	return rc;
}
