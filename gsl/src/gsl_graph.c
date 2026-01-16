/**
 * \file gsl_graph.c
 *
 * \brief
 *      Implement graph management layer for Graph Service Layer (GSL)
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "acdb.h"
#include "ar_osal_error.h"
#include "ar_osal_shmem.h"
#include "ar_osal_log.h"
#include "ar_util_data_log.h"
#include "ar_util_data_log_codes.h"
#include "gsl_graph.h"
#include "gpr_api_inline.h"
#include "apm_api.h"
#include "apm_sub_graph_api.h"
#include "wr_sh_mem_ep_api.h"
#include "rd_sh_mem_ep_api.h"
#include "sh_mem_pull_push_mode_api.h"
#include "gsl_global_persist_cal.h"
#include "gsl_subgraph_pool.h"
#include "gsl_common.h"
#include "gsl_msg_builder.h"
#include "gsl_spf_ss_state.h"
#include "gsl_mdf_utils.h"

#define GSL_GPR_DST_PORT_APM  (APM_MODULE_INSTANCE_ID)
#define GSL_4KB_MULTIPLE_SIZE(x)  (((x) + 4095) & (~4095))
#define IS_ONE_PARAM(param_size, payload_size) \
	((GSL_ALIGN_8BYTE(param_size) + \
	 sizeof(apm_module_param_data_t)) == payload_size)

/* set config packets less than or equal to this size will be sent in-band  */
#define GSL_IN_BAND_SIZE_THRESHOLD 256

struct gsl_blob {
	uint32_t size; /**< size of the blob */
	void *buf; /**< pointer to the blob */
};

/* Used to return tags and module info data sorted by processor id to client */
struct gsl_module_id_proc_info_entry {
	uint32_t proc_domain_id; // process the modules are running on
	uint32_t num_modules; // number of entries in module list
	struct gsl_module_id_info_entry module_entry[]; // module list
};

struct gsl_module_id_proc_info {
	uint32_t num_procs; // number of processors in proc_module_list
	uint32_t list_size; //size of proc_module_list
	struct gsl_module_id_proc_info_entry *proc_module_list;
	// list of module ids and tags sorted by processor id
};

static uint8_t count_set_bits(uint32_t value)
{
	uint8_t lut[16] = { 0, 1, 1, 2, 1, 2, 2, 3,
		1, 2, 2, 3, 2, 3, 3, 4 };
	uint8_t n_set_bits = 0;

	while (value) {
		n_set_bits += lut[value & 0xf];
		value >>= 4;
	}
	return n_set_bits;
}

static bool_t is_sg_found(uint32_t sgid, struct gsl_subgraph **sgs,
	uint32_t num_of_subgraphs)
{
	uint32_t i;

	for (i = 0; i < num_of_subgraphs; ++i) {
		if (sgid == sgs[i]->sg_id)
			return TRUE;
	}
	return FALSE;
}
static bool_t is_identical_gkv(struct gsl_key_vector *vect1,
	struct gsl_key_vector *vect2)
{
	struct gsl_key_value_pair *kvp1;
	struct gsl_key_value_pair *kvp2;
	uint32_t i, j;
	bool_t kvp_found;

	if (!vect1 || !vect2)
		return AR_EBADPARAM;

	/** return false if dimension does not match */
	if (vect1->num_kvps != vect2->num_kvps)
		return FALSE;

	kvp1 = vect1->kvp;
	for (i = 0; i < vect1->num_kvps; ++i) {
		kvp2 = vect2->kvp;
		kvp_found = FALSE;
		for (j = 0; j < vect2->num_kvps; ++j, ++kvp2) {
			if (kvp2->key != kvp1->key)
				continue;
			if (kvp2->value == kvp1->value) {
				kvp_found = TRUE; /**< key and value both matched */
				break;
			}
		}
		if (kvp_found == FALSE)
			return FALSE; /**< found at least one non-matching kvp */
		++kvp1;
	}
	return TRUE;
}

static void gsl_graph_add_gkv_to_list(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node)
{
	GSL_MUTEX_LOCK(graph->gkv_list_lock);
	ar_list_add_tail(&graph->gkv_list, &gkv_node->node);
	++graph->num_gkvs;
	GSL_MUTEX_UNLOCK(graph->gkv_list_lock);

}

static void gsl_graph_remove_gkv_from_list(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node)
{
	GSL_MUTEX_LOCK(graph->gkv_list_lock);
	ar_list_delete(&graph->gkv_list, &gkv_node->node);
	--graph->num_gkvs;
	GSL_MUTEX_UNLOCK(graph->gkv_list_lock);

}

/**
 * Allocates and returns subgraph objects to the caller.
 * Caller should clear the memory for the subgraph objects after use.
 */
static struct gsl_subgraph **gsl_graph_get_sg_array(struct gsl_graph *graph,
	uint32_t *num_sgs)
{
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node;
	uint32_t total_num_of_subgraphs = 0, num_of_subgraphs = 0, i;
	uint32_t num_sg_to_compare = 0;
	struct gsl_subgraph **sgs = NULL;

	*num_sgs = 0;
	GSL_MUTEX_LOCK(graph->gkv_list_lock);
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		total_num_of_subgraphs += gkv_node->num_of_subgraphs;
	}
	sgs = gsl_mem_zalloc(total_num_of_subgraphs *
		sizeof(struct gsl_subgraph *));
	if (!sgs)
		goto done;

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		num_sg_to_compare = num_of_subgraphs;
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
			if (!is_sg_found(gkv_node->sg_array[i]->sg_id, sgs,
				num_sg_to_compare))
				sgs[num_of_subgraphs++] = gkv_node->sg_array[i];
		}
	}
	*num_sgs = num_of_subgraphs;
done:
	GSL_MUTEX_UNLOCK(graph->gkv_list_lock);
	return sgs;
}

/**
 * Allocates and returns subgraph IDs and objects list to the caller.
 * Caller should clear the memory after use.
 */
static int32_t gsl_graph_get_sgids_and_objs(struct gsl_graph *graph,
	struct gsl_sgid_list *sgid_list, struct gsl_sgobj_list *sg_objs)
{
	uint32_t num_of_subgraphs = 0;
	uint32_t *sgids, i;
	struct gsl_subgraph **sg_array = NULL;

	sg_array = gsl_graph_get_sg_array(graph, &num_of_subgraphs);
	if (!sg_array)
		return AR_EFAILED;

	if (sgid_list && num_of_subgraphs) {
		sgids = gsl_mem_zalloc(num_of_subgraphs * sizeof(uint32_t));
		if (!sgids) {
			gsl_mem_free(sg_array);
			return AR_ENOMEMORY;
		}
		for (i = 0; i < num_of_subgraphs; ++i)
			sgids[i] = sg_array[i]->sg_id;

		sgid_list->sg_ids = sgids;
		sgid_list->len = num_of_subgraphs;
	}

	if (sg_objs && num_of_subgraphs) {
		sg_objs->len = num_of_subgraphs;
		sg_objs->sg_objs = sg_array;
	} else
		gsl_mem_free(sg_array);

	return AR_EOK;
}

/**
 * Search for a matching subgraph object from the list of given SG objects
 * and subgraph ID
 */
static struct gsl_subgraph *gsl_graph_get_sg_ptr(
	struct gsl_sgobj_list *sg_obj_list, uint32_t sgid)
{
	uint32_t i = 0;
	struct gsl_subgraph *sg = NULL;

	for (i = 0; i < sg_obj_list->len; ++i) {
		sg = sg_obj_list->sg_objs[i];
		if (sg->sg_id == sgid)
			return sg;
	}
	return NULL;
}

static void gsl_handle_eos(struct gsl_graph *graph, gpr_packet_t *packet)
{
	struct data_cmd_rsp_wr_sh_mem_ep_eos_rendered_t *spf_eos;
	struct gsl_event_eos_payload eos_pld;
	struct gsl_event_cb_params ev;

	spf_eos = GPR_PKT_GET_PAYLOAD(
		struct data_cmd_rsp_wr_sh_mem_ep_eos_rendered_t, packet);
	/* issue the callback to client */
	eos_pld.module_instance_id = spf_eos->module_instance_id;
	if (spf_eos->render_status == WR_SH_MEM_EP_EOS_RENDER_STATUS_RENDERED) {
		eos_pld.render_status = GSL_EOS_RENDERED;
	} else if (spf_eos->render_status ==
		WR_SH_MEM_EP_EOS_RENDER_STATUS_DROPPED) {
		eos_pld.render_status = GSL_EOS_DROPPED;
	} else {
		eos_pld.render_status = GSL_EOS_RENDERED;
		GSL_ERR("Got invalid eos status %d from Spf",
			spf_eos->render_status);
	}

	ev.event_payload = &eos_pld;
	ev.event_payload_size = sizeof(eos_pld);
	ev.source_module_id = GSL_EVENT_SRC_MODULE_ID_GSL;
	ev.event_id = GSL_EVENT_ID_EOS;
	graph->cb(&ev, graph->client_data);
}

static uint32_t gsl_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
	struct gsl_graph *graph;
	struct spf_cmd_basic_rsp *basic_rsp;
	struct gsl_event_cb_params ev;
	struct apm_module_event_t *module_ev;
	uint32_t rc = AR_EOK, gpr_rc = AR_EOK;

	graph = (struct gsl_graph *)cb_data;

	GSL_DBG("got opcode %x", packet->opcode);

	switch (packet->opcode) {
	case GPR_IBASIC_RSP_RESULT:
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp,
				packet);
		switch (basic_rsp->opcode) {
		/* do not free gpr packet in these cases as it is passed to waiter */
		case APM_CMD_GRAPH_OPEN:
		case APM_CMD_GRAPH_PREPARE:
		case APM_CMD_GRAPH_START:
		case APM_CMD_GRAPH_SUSPEND:
		case APM_CMD_GRAPH_STOP:
			rc = gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG],
				GSL_SIG_EVENT_MASK_SPF_RSP, basic_rsp->status, packet);
			break;
		case APM_CMD_GRAPH_CLOSE:
			rc = gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP3_CMD_SIG],
				GSL_SIG_EVENT_MASK_SPF_RSP, basic_rsp->status, packet);
			break;
		case APM_CMD_GRAPH_FLUSH:
		case APM_CMD_SET_CFG:
		case APM_CMD_GET_CFG:
		case APM_CMD_REGISTER_CFG:
		case APM_CMD_DEREGISTER_CFG:
		case APM_CMD_REGISTER_SHARED_CFG:
		case APM_CMD_DEREGISTER_SHARED_CFG:
		case APM_CMD_REGISTER_MODULE_EVENTS:
			rc = gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG],
				GSL_SIG_EVENT_MASK_SPF_RSP, basic_rsp->status, packet);
			break;
		case DATA_CMD_WR_SH_MEM_EP_MEDIA_FORMAT:
			rc = gsl_handle_media_format_buff_done(&graph->write_info, packet);
			break;
		default:
			/* free the packet if we will ignore it */
			gpr_rc = __gpr_cmd_free(packet);
			break;
		}
		break;
	case APM_CMD_RSP_GET_CFG:
		rc = gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG],
			GSL_SIG_EVENT_MASK_SPF_RSP, 0, packet);
		/* do not free gpr packet as it is passed to waiter */
		break;
	case DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2:
		rc = gsl_handle_write_buff_done(&graph->write_info, packet, graph->cb,
			graph->client_data);
		/*
		 * We only update the processed_buf_cnt if we are in the STARTED state,
		 * note we do "try_lock" here because we want to avoid blocking in the
		 * callback. If locked it means the graph is in the middle of
		 * transitioning to STOPPED or to STARTED states and it's okay to skip
		 * incrementing in both cases
		 *
		 * We do not have access to graph state from within datapath, so we
		 * must check this here
		 */
		if (rc == AR_EOK
			&& ar_osal_mutex_try_lock(graph->graph_lock) == AR_EOK) {
			if (gsl_graph_get_state(graph) == GRAPH_STARTED)
				++graph->write_info.processed_buf_cnt;
			GSL_MUTEX_UNLOCK(graph->graph_lock);
		}
		gpr_rc = __gpr_cmd_free(packet);
		break;
	case DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2:
		rc = gsl_handle_read_buff_done(&graph->read_info, packet, graph->cb,
			graph->client_data);
		/* see comment for WR_SH_MEM_EP_DATA_BUFFER_DONE */
		if (rc == AR_EOK
				&& ar_osal_mutex_try_lock(graph->graph_lock) == AR_EOK) {
			if (gsl_graph_get_state(graph) == GRAPH_STARTED)
				++graph->read_info.processed_buf_cnt;
			GSL_MUTEX_UNLOCK(graph->graph_lock);
		}
		break;
	case DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED:
		graph = (struct gsl_graph *)cb_data;
		gsl_handle_eos(graph, packet);
		gpr_rc = __gpr_cmd_free(packet);
		break;
	case APM_EVENT_MODULE_TO_CLIENT:
		graph = (struct gsl_graph *)cb_data;
		/* issue the callback to client */
		module_ev = GPR_PKT_GET_PAYLOAD(struct apm_module_event_t,
			packet);
		ev.event_id = module_ev->event_id;
		ev.event_payload_size = module_ev->event_payload_size;
		ev.source_module_id = packet->src_port;
		ev.event_payload = (void *)((int8_t *)module_ev +
			sizeof(struct apm_module_event_t));
		graph->cb(&ev, graph->client_data);
		gpr_rc = __gpr_cmd_free(packet);
		break;
	default:
		GSL_DBG("unknown opcode %x freeing GPR rsp packet", packet->opcode);
		gpr_rc = __gpr_cmd_free(packet);
		break;
	}

	if (rc) {
		GSL_DBG("signal failed, freeing GPR rsp packet");
		gpr_rc = __gpr_cmd_free(packet);
	}

	/* if any gpr free above fails all we can do is return error back to gpr */
	return gpr_rc;
}

static int32_t gsl_apm_config_inband(struct gsl_graph *graph,
	const uint8_t *payload, uint32_t payload_size, uint32_t opcode,
	uint32_t dst_port, struct gpr_packet_t **p_rsp_pkt)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *apm_hdr;
	gsl_msg_t gsl_msg;
	struct ar_data_log_submit_info_t info;
	struct ar_data_log_generic_pkt_info_t pkt_info;

	rc = gsl_msg_alloc(opcode, graph->src_port, dst_port, sizeof(*apm_hdr), 0,
		graph->proc_id, GSL_ALIGN_8BYTE(payload_size), true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto exit;
	}

	apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, gsl_msg.gpr_packet);
	gsl_memset(apm_hdr, 0, sizeof(*apm_hdr) + GSL_ALIGN_8BYTE(payload_size));
	apm_hdr->payload_size = GSL_ALIGN_8BYTE(payload_size);

	/* copy payload into in-band buffer */
	if (payload_size > 0)
		gsl_memcpy((uint8_t *)(gsl_msg.payload), GSL_ALIGN_8BYTE(payload_size),
			payload, payload_size);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*apm_hdr) +
		GSL_ALIGN_8BYTE(payload_size), NULL, 0);

	if (opcode == APM_CMD_SET_CFG) {
		if (graph->rtc_conn_active) {
			pkt_info.format = AR_LOG_PKT_GENERIC_FMT_CAL_BLOB;
			pkt_info.token_id = 0;
			pkt_info.log_time_stamp = 0;

			info.buffer = (int8_t *)apm_hdr + sizeof(*apm_hdr);
			info.buffer_size = payload_size;
			info.log_code = AR_DATA_LOG_CODE_ATS;
			info.pkt_info = &pkt_info;
			info.pkt_type = AR_DATA_LOG_PKT_TYPE_GENERIC;
			info.session_id = 0;

			GSL_DBG("set custom config oob: caching buff %x to QACT",
				info.buffer);
			ar_data_log_submit(&info);
		}
		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
			&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
	} else {	//APM_CMD_GET_CFG
		rc = gsl_send_spf_cmd(&gsl_msg.gpr_packet,
			&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG], p_rsp_pkt);
	}
	if (rc)
		GSL_ERR("Graph cfg cmd 0x%x failure:%d", opcode, rc);

exit:
	return rc;
}

static int32_t gsl_apm_get_config_inband(struct gsl_graph *graph,
	uint8_t *payload, uint32_t *payload_size, uint32_t dst_port)
{
	int32_t rc = AR_EOK;
	gpr_packet_t *rsp_pkt = NULL;
	struct apm_cmd_rsp_get_cfg_t *get_cfg_rsp;
	apm_module_param_data_t *param_data = (apm_module_param_data_t *)payload;

	rc = gsl_apm_config_inband(graph, payload, *payload_size, APM_CMD_GET_CFG,
		dst_port, &rsp_pkt);
	if (rc)
		goto exit;

	if (!rsp_pkt) {
		GSL_ERR("Received null response packet");
		rc = AR_EUNEXPECTED;
		goto exit;
	}

	get_cfg_rsp = GPR_PKT_GET_PAYLOAD(struct apm_cmd_rsp_get_cfg_t, rsp_pkt);
	/*
	 * For multiple parameter case, copy payload on partial failures
	 * and success.
	 * For one parameter case, we fail if the rsp status is an error.
	 */
	if (get_cfg_rsp->status != AR_EOK &&
		IS_ONE_PARAM(param_data->param_size, *payload_size)) {
		GSL_ERR("get config failed: spf status %d", get_cfg_rsp->status);
		rc = AR_EFAILED;
		goto exit;
	}

	rc = gsl_memcpy(payload, *payload_size, (uint8_t *)rsp_pkt +
		GPR_PKT_GET_HEADER_BYTE_SIZE(rsp_pkt->header) +
		sizeof(apm_cmd_rsp_get_cfg_t),
		GPR_PKT_GET_PAYLOAD_BYTE_SIZE(rsp_pkt->header) -
		sizeof(apm_cmd_rsp_get_cfg_t));
	/* client allocated buffer, size could be too small and fail memcpy */
	if (rc)
		GSL_ERR("memcpy failed %d", rc);

	/* update with size written */
	*payload_size = GPR_PKT_GET_PAYLOAD_BYTE_SIZE(rsp_pkt->header) -
		sizeof(apm_cmd_rsp_get_cfg_t);

exit:
	if (rsp_pkt)
		__gpr_cmd_free(rsp_pkt);

	return rc;
}

static int32_t gsl_apm_config_oob(struct gsl_graph *graph,
	const uint8_t *payload, uint32_t payload_size,
	uint32_t opcode, uint32_t dst_port)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	gsl_msg_t gsl_msg;
	struct ar_data_log_submit_info_t info;
	struct ar_data_log_generic_pkt_info_t pkt_info;
	struct apm_cmd_rsp_get_cfg_t *get_cfg_rsp;
	gpr_packet_t *rsp_pkt = NULL;
	apm_module_param_data_t *param_data = (apm_module_param_data_t *)payload;

	rc = gsl_msg_alloc(opcode, graph->src_port, dst_port, sizeof(*cmd_header),
		0, graph->proc_id, payload_size, false, &gsl_msg);
	if (rc) {
		GSL_ERR("gsl msg alloc failed:%d", rc);
		goto exit;
	}

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
		gsl_msg.gpr_packet);
	cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	cmd_header->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	cmd_header->payload_size = payload_size;

	/* copy payload into shared memory */
	gsl_memcpy(gsl_msg.payload, payload_size, (void *)payload, payload_size);

	if (opcode == APM_CMD_SET_CFG && graph->rtc_conn_active) {
		/* dump config to QACT for use in RTC */

		pkt_info.format = AR_LOG_PKT_GENERIC_FMT_CAL_BLOB;
		pkt_info.token_id = 0;
		pkt_info.log_time_stamp = 0;

		info.buffer = (int8_t *)gsl_msg.payload;
		info.buffer_size = payload_size;
		info.log_code = AR_DATA_LOG_CODE_ATS;
		info.pkt_info = &pkt_info;
		info.pkt_type = AR_DATA_LOG_PKT_TYPE_GENERIC;
		info.session_id = 0;

		GSL_DBG("set custom config oob: caching buff %x to QACT",
			info.buffer);
		ar_data_log_submit(&info);
	}

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header), gsl_msg.payload,
		payload_size);

	rc = gsl_send_spf_cmd(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG], &rsp_pkt);
	if (rc) {
		GSL_ERR("Graph cfg cmd 0x%x failure:%d", opcode, rc);
		goto free_msg;
	}

	if (opcode == APM_CMD_GET_CFG) {
		get_cfg_rsp = GPR_PKT_GET_PAYLOAD(struct apm_cmd_rsp_get_cfg_t,
			rsp_pkt);
		/*
		 * For multiple parameter case, copy payload on partial failures
		 * and success.
		 * For one parameter case, we fail if the rsp status is an error.
		 */
		if (get_cfg_rsp->status != AR_EOK &&
			IS_ONE_PARAM(param_data->param_size, payload_size)) {
			GSL_ERR("get cfg failed, spf status %d", get_cfg_rsp->status);
			goto free_msg;
		}

		rc = gsl_memcpy((void *)payload, payload_size,
						gsl_msg.payload, payload_size);
		if (rc)
			GSL_ERR("memcpy failed %d", rc);
	}

free_msg:
	if (rsp_pkt)
		__gpr_cmd_free(rsp_pkt);
	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

static int32_t copy_key_vector(struct gsl_key_vector *out_kv,
	const struct gsl_key_vector *inp_kv)
{
	struct gsl_key_value_pair *key_val_pairs;
	size_t kvp_size;

	if (!inp_kv) {
		out_kv->num_kvps = 0;
		out_kv->kvp = NULL;
		return AR_EOK;
	}

	kvp_size = inp_kv->num_kvps * sizeof(struct gsl_key_value_pair);
	key_val_pairs = gsl_mem_zalloc(kvp_size);
	if (!key_val_pairs)
		return AR_ENOMEMORY;

	out_kv->num_kvps = inp_kv->num_kvps;
	if (out_kv->kvp)
		gsl_mem_free(out_kv->kvp);

	gsl_memcpy(key_val_pairs, kvp_size,	inp_kv->kvp,
		inp_kv->num_kvps * sizeof(struct gsl_key_value_pair));

	out_kv->kvp = key_val_pairs;
	return AR_EOK;
}

static void gsl_graph_update_gkv_node(struct gsl_graph_gkv_node *gkv_node,
	const struct gsl_key_vector *gkv, const struct gsl_key_vector *ckv)
{
	copy_key_vector(&gkv_node->gkv, gkv);
	if (ckv)
		copy_key_vector(&gkv_node->ckv, ckv);
	ar_list_init_node(&gkv_node->node);
}

static int32_t gsl_acdb_get_subgraph_connections(AcdbSubgraph *sg_conn,
	uint32_t num_sg_conn, struct gsl_blob *spf_blob)
{
	AcdbSubGraphList cmd_struct;
	AcdbBlob rsp_struct;
	int32_t rc = AR_EOK;

	cmd_struct.num_subgraphs = num_sg_conn;
	cmd_struct.subgraphs = sg_conn;

	gsl_memset(&rsp_struct, 0, sizeof(rsp_struct));
	rsp_struct.buf_size = spf_blob->size;
	rsp_struct.buf = spf_blob->buf;

	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_CONNECTIONS, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));

	if (AR_SUCCEEDED(rc))
		spf_blob->size = rsp_struct.buf_size;

	return rc;
}

static int32_t gsl_acdb_parse_sg_drv_prop_data(struct gsl_graph *graph,
	struct gsl_sgobj_list *sg_obj_list, AcdbDriverPropertyData *prop_data)
{
	AcdbSubGraphPropertyData *p = NULL;
	struct gsl_subgraph *sg;
	uint32_t i, n;
	int8_t *prop_payload;
	AcdbPropertyData *prop_id_data = NULL;
	struct sg_generic_t *sg_prop = NULL;
	struct sg_type_t *sg_type_prop = NULL;
	uint32_t proc_id = 0;

	/** parse driver property data for each SG */
	p = prop_data->sub_graph_prop_data;
	for (i = 0; i < prop_data->num_sgid; ++i) {
		sg = gsl_graph_get_sg_ptr(sg_obj_list, p->sg_id);
		if (!sg) {
			GSL_ERR("SG id %d not found in this GKV", p->sg_id);
			return AR_EFAILED;
		}
		prop_payload = (int8_t *)p->prop_data;
		n = 0;
		while (n++ < p->num_props) {
			prop_id_data = (AcdbPropertyData *)prop_payload;
			switch (prop_id_data->prop_id) {
			case SUB_GRAPH_PROP_ID_GENERIC:
				sg_prop =
				  (struct sg_generic_t *)prop_id_data->prop_payload;
				sg->drv_prop_data.routing_id = sg_prop->routing_id;
				sg->drv_prop_data.is_flushable = sg_prop->is_flushable;

				/* Check if all the subgraphs have same routing id */
				if (proc_id == 0) {
					proc_id = sg_prop->routing_id;
				} else if (proc_id != sg_prop->routing_id) {
					GSL_ERR("Routing id mismatch in graph for %d",
						sg_prop->routing_id);
					return AR_EFAILED;
				}
				break;
			case SUB_GRAPH_PROP_ID_SG_TYPE:
				sg_type_prop = (struct sg_type_t *)prop_id_data->prop_payload;
				sg->sg_type_data.sg_type = sg_type_prop->sg_type;
				break;
			default:
				GSL_ERR("unknown sg property id %d", prop_id_data->prop_id);
				break;
			}
			prop_payload += sizeof(AcdbPropertyData) +
				prop_id_data->prop_payload_size;
		}
		p = (AcdbSubGraphPropertyData *)prop_payload;
	}

	if (proc_id != 0)
		graph->proc_id = proc_id;

	return AR_EOK;
}

static int32_t gsl_acdb_get_subgraph_data(struct gsl_sgid_list *sg_id_list,
	const struct gsl_key_vector *gkv, struct gsl_blob *spf_blob,
	AcdbDriverPropertyData *drv_blob)
{
	AcdbSgIdGraphKeyVector cmd_struct;
	AcdbGetSubgraphDataRsp rsp_struct;
	uint32_t cmd_struct_size, rsp_struct_size;
	int32_t rc = AR_EOK;

	/* Form cmd and rsp structures */
	cmd_struct_size = sizeof(AcdbSgIdGraphKeyVector);
	cmd_struct.num_sgid = sg_id_list->len;
	cmd_struct.sg_ids = sg_id_list->sg_ids;
	cmd_struct.graph_key_vector.num_keys = gkv->num_kvps;
	cmd_struct.graph_key_vector.graph_key_vector =
		(AcdbKeyValuePair *)gkv->kvp;

	rsp_struct_size = sizeof(AcdbGetSubgraphDataRsp);
	gsl_memset(&rsp_struct, 0, rsp_struct_size);
	rsp_struct.spf_blob.buf_size = spf_blob->size;
	rsp_struct.spf_blob.buf = spf_blob->buf;
	rsp_struct.driver_prop.size = drv_blob->size;
	rsp_struct.driver_prop.sub_graph_prop_data = drv_blob->sub_graph_prop_data;

	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_DATA, &cmd_struct,
		cmd_struct_size, &rsp_struct, rsp_struct_size);

	if (AR_SUCCEEDED(rc)) {
		spf_blob->size = rsp_struct.spf_blob.buf_size;
		drv_blob->num_sgid = rsp_struct.driver_prop.num_sgid;
		drv_blob->size = rsp_struct.driver_prop.size;
	}

	return rc;
}

static void gsl_graph_ckv_list_print(AcdbKeyVectorList *rsp)
{
	uint32_t i = 0, j = 0;
	uint8_t* pKv = NULL;
	AcdbKeyVector *kvs = NULL;

	pKv = (uint8_t*)rsp->key_vector_list;
	for (i = 0; i < rsp->num_key_vectors; i++) {
		kvs = (AcdbKeyVector *)pKv;
		if (!kvs) {
			GSL_ERR("kvs is null");
			return;
		}
		GSL_VERBOSE("num_keys %d", kvs->num_keys);
		for (j = 0; j < kvs->num_keys; j++) {
			AcdbKeyValuePair kv = kvs->graph_key_vector[j];
			GSL_VERBOSE("key:0x%x, value:%x", kv.key, kv.value);
		}
		pKv += sizeof(uint32_t) + kvs->num_keys * sizeof(AcdbKeyValuePair);
	}
}

static void gsl_graph_check_ckvs(struct gsl_key_vector *gkv, struct gsl_key_vector *ckv)
{
	AcdbKeyVectorList rsp;
	AcdbKeyVector *kvs = NULL;
	uint8_t* pKv = NULL;
	uint32_t i = 0, j = 0;
	uint32_t key = 0;
	int ckv_count = 0;
	int rc = AR_EOK;

	rsp.list_size = 0;
	rc = gsl_get_graph_ckvs(gkv, (void *)&rsp);
	if (rc) {
		GSL_ERR("gsl_get_graph_ckvs failed: %d", rc);
		return;
	}

	GSL_DBG("num_key_vectors %d, list_size %d", rsp.num_key_vectors, rsp.list_size);
	rsp.key_vector_list = (AcdbKeyVector *)malloc(rsp.list_size);
	if (!rsp.key_vector_list) {
		GSL_ERR("malloc return failed");
		return;
	}

	rc = gsl_get_graph_ckvs(gkv, (void *)&rsp);
	if (rc) {
		GSL_ERR("gsl_get_graph_ckvs failed: %d", rc);
		goto exit;
	}

	gsl_graph_ckv_list_print(&rsp);

	// get CKV count
	pKv = (uint8_t*)rsp.key_vector_list;
	for (i = 0; i < rsp.num_key_vectors; i++) {
		kvs = (AcdbKeyVector *)pKv;
		if (!kvs) {
			GSL_ERR("kvs is null");
			return;
		}
		GSL_VERBOSE("num_keys %d", kvs->num_keys);
		for (j = 0; j < kvs->num_keys; j++) {
			AcdbKeyValuePair kv = kvs->graph_key_vector[j];
			GSL_VERBOSE("key:0x%x, value:%x", kv.key, kv.value);
			if (key != kv.key) {
				key = kv.key;
				ckv_count++;
			}
		}
		pKv += sizeof(uint32_t) + kvs->num_keys * sizeof(AcdbKeyValuePair);
	}

	if (ckv_count != ckv->num_kvps)
			GSL_ERR("CKVs mismatched. ACDB CKVs count %d CKVs sent from HAL count %d", ckv_count, ckv->num_kvps);

	exit:
	if (rsp.key_vector_list) {
		free(rsp.key_vector_list);
	}
}

static int32_t gsl_graph_send_nonpersist_cal(struct gsl_graph *graph,
	struct gsl_sgid_list *sgid_list,
	struct gsl_key_vector *prior_ckv, const struct gsl_key_vector *new_ckv,
	const struct gsl_key_vector *gkv,
	bool isCKVValidated)
{
	AcdbSgIdCalKeyVector cmd_struct;
	AcdbBlob rsp_struct;
	int32_t rc;
	struct apm_cmd_header_t *cmd_header;
	gsl_msg_t gsl_msg;

	cmd_struct.num_sg_ids = sgid_list->len;
	cmd_struct.sg_ids = sgid_list->sg_ids;
	cmd_struct.cal_key_vector_prior.num_keys = prior_ckv->num_kvps;
	cmd_struct.cal_key_vector_prior.graph_key_vector =
		(AcdbKeyValuePair *)prior_ckv->kvp;
	cmd_struct.cal_key_vector_new.num_keys = new_ckv->num_kvps;
	cmd_struct.cal_key_vector_new.graph_key_vector =
		(AcdbKeyValuePair *)new_ckv->kvp;

	rsp_struct.buf = NULL;
	rsp_struct.buf_size = 0;

	if (!isCKVValidated)
		gsl_graph_check_ckvs(gkv, new_ckv);

	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_CALIBRATION_DATA_NONPERSIST,
		&cmd_struct, sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc == AR_ENOTEXIST) {
		/* avoid logging error if not exist */
		return rc;
	} else if (rc) {
		GSL_ERR("get non-persist data (size) failed %d", rc);
		return rc;
	}

	rc = gsl_msg_alloc(APM_CMD_SET_CFG, graph->src_port, GSL_GPR_DST_PORT_APM,
		sizeof(*cmd_header), 0, graph->proc_id, rsp_struct.buf_size, false,
		&gsl_msg);
	if (rc) {
		GSL_ERR("gsl msg alloc failed %d", rc);
		return rc;
	}
	rsp_struct.buf = gsl_msg.payload;
	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_CALIBRATION_DATA_NONPERSIST,
		&cmd_struct, sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("get non-persist data (cal) failed %d", rc);
		goto exit;
	}

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
		gsl_msg.gpr_packet);
	cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	cmd_header->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	cmd_header->payload_size = rsp_struct.buf_size;

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header),	gsl_msg.payload,
		cmd_header->payload_size);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
	if (rc)
		GSL_ERR("send non-perist cal failed %d", rc);

exit:
	gsl_msg_free(&gsl_msg);
	return rc;
}

static int32_t gsl_graph_send_persist_cal(struct gsl_graph *graph,
	struct gsl_sgobj_list *sg_objs,	const struct gsl_key_vector *new_ckv)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	struct gsl_subgraph *sg = NULL;
	uint32_t i;
	gpr_packet_t *send_pkt = NULL;
	uint64_t paddr_w_offset = 0;
	AcdbUintList sg_cma_status_list;
	AcdbHwAccelSubgraphInfoReq cma_sg_info_req;
	AcdbHwAccelSubgraphInfoRsp cma_sg_info;
	bool_t is_shmem_supported = TRUE;
	AcdbCmdGetSubgraphProcIdsReq req = {0,};
	AcdbCmdGetSubgraphProcIdsRsp rsp = {0,};

	if (sg_objs->len == 0)
		return AR_EOK;

	rc = __gpr_cmd_is_shared_mem_supported(graph->proc_id, &is_shmem_supported);
	if (!is_shmem_supported) {
		return AR_EUNSUPPORTED;
	} else if (rc) {
		GSL_ERR("GPR is shmem supported failed %d", rc)
		goto exit;
	}

	/* query for all SGs and their cma mem types */
	sg_cma_status_list.count = sg_objs->len;
	sg_cma_status_list.list = gsl_mem_zalloc(sizeof(uint32_t)*sg_objs->len);
	if (!sg_cma_status_list.list) {
		rc = AR_ENOMEMORY;
		goto exit;
	}

	cma_sg_info.subgraph_list =
		gsl_mem_zalloc(sizeof(AcdbHwAccelSubgraph)*sg_objs->len);
	if (!cma_sg_info.subgraph_list) {
		rc = AR_ENOMEMORY;
		goto free_status_list;
	}
	cma_sg_info.list_size = sizeof(AcdbHwAccelSubgraph)*sg_objs->len;
	cma_sg_info.num_subgraphs = sg_objs->len;

	/* fill request list. Note that these are in order */
	for (i = 0; i < sg_objs->len; ++i) {
		if (sg_objs->sg_objs[i])
			sg_cma_status_list.list[i] = sg_objs->sg_objs[i]->sg_id;
	}
	cma_sg_info_req.subgraph_list = sg_cma_status_list;

	rc = acdb_ioctl(ACDB_CMD_GET_HW_ACCEL_SUBGRAPH_INFO, &cma_sg_info_req,
		sizeof(cma_sg_info_req), &cma_sg_info, sizeof(cma_sg_info));
	if (rc) {
		GSL_ERR("get HW ACCEL info failed %d", rc);
		goto cleanup;
	}

	for (i = 0; i < sg_objs->len; ++i) {
		sg = sg_objs->sg_objs[i];

		if (!sg) {
			continue;
		} else if (sg->start_ref_cnt > 0) {
			/*
			 * persist cal will not be applied to started SGs - creates errors,
			 * especially with CMA
			 */
			GSL_DBG("Skipping persist cal for SG_ID %d: already started",
				sg->sg_id);
			continue;
		}

		/* if persist cal is already regsitered for this SG de-register it */
		GSL_DBG("num procs - %d", sg->num_proc_ids);
		for (int procid = 0; procid < sg->num_proc_ids; procid++) {
			if (sg->persist_cal_data_per_proc[procid].persist_cal_data.handle) {
				GSL_DBG("proc_id[%d] - %d", procid, sg->persist_cal_data_per_proc[procid].proc_id);

				rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
					graph->src_port, APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
					0, graph->proc_id, &send_pkt);
				if (rc) {
					GSL_ERR("Failed to allocate GPR packet %d", rc);
					goto exit;
				}
				/*
				* below offset used to skip acdb header before sending data to
				* spf
				*/
				paddr_w_offset = sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_addr +
					sizeof(AcdbSgIdPersistData);
				cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
				cmd_header->mem_map_handle = sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_mmap_handle;
				cmd_header->payload_address_lsw = (uint32_t)paddr_w_offset;
				cmd_header->payload_address_msw = (uint32_t)(paddr_w_offset >> 32);
				cmd_header->payload_size = sg->persist_cal_data_per_proc[procid].persist_cal_data_size -
					sizeof(AcdbSgIdPersistData);

				GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
					sizeof(*send_pkt) + sizeof(*cmd_header),
					sg->persist_cal_data_per_proc[procid].persist_cal_data.v_addr, cmd_header->payload_size);

				rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
					&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
				if (rc) {
					GSL_ERR("Graph deregister cfg cmd 0x%x failure:%d",
						APM_CMD_DEREGISTER_CFG, rc);
					goto exit;
				}
			}
		}

		/* if cma is already regsitered for this SG de-register it */
		if (sg->cma_persist_cfg_data.handle) {

			rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
				graph->src_port, APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
				0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto exit;
			}
			/*
			 * below offset used to skip acdb header before sending data to
			 * spf
			 */
			paddr_w_offset = sg->cma_persist_cfg_data.spf_addr
				+ sizeof(AcdbSgIdPersistData);
			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle
				= sg->cma_persist_cfg_data.spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t)paddr_w_offset;
			cmd_header->payload_address_msw = (uint32_t)(paddr_w_offset >> 32);
			cmd_header->payload_size = sg->cma_cal_data_size -
				sizeof(AcdbSgIdPersistData);

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header),
				sg->cma_persist_cfg_data.v_addr, cmd_header->payload_size);

			send_pkt->client_data |= GSL_GPR_CMA_FLAG_BIT;

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc) {
				GSL_ERR("Graph deregister cfg cmd 0x%x failure:%d",
					APM_CMD_DEREGISTER_CFG, rc);
				goto exit;
			}

			/* free after deregister (free handles hyp unassign too) */
			gsl_shmem_free(&sg->cma_persist_cfg_data);
			sg->cma_persist_cfg_data.handle = NULL;
			sg->cma_persist_cfg_data.v_addr = NULL;
			sg->cma_cal_data_size = 0;
		}

		/* determine whether there is CMA needed or not */
		switch (cma_sg_info.subgraph_list[i].mem_type) {
		case ACDB_HW_ACCEL_MEM_DEFAULT:
		case ACDB_HW_ACCEL_MEM_BOTH:
			/* this is the non-CMA side */
			/* get num_procs and proc ids per SG from ACDB and store it in sg struct */

			/* first call to get size */
			req.num_sg_ids = 1;
			req.sg_ids = &sg->sg_id;
			rsp.num_sg_ids = 0;
			rsp.size = 0;
			rsp.sg_proc_ids = NULL;
			rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_PROCIDS, &req, sizeof(req), &rsp,
				sizeof(rsp));
			if (rc != AR_EOK && rc != AR_ENOTEXIST) {
				GSL_ERR("ACDB get subgraph procids failed %d", rc);
				return rc;
			}

			rsp.sg_proc_ids = gsl_mem_zalloc(rsp.size);
			if (!rsp.sg_proc_ids) {
				rc = AR_ENOMEMORY;
				return rc;
			}

			/* next call to get data */
			rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_PROCIDS, &req, sizeof(req), &rsp,
				sizeof(rsp));
			if (rc != AR_EOK) {
				GSL_ERR("ACDB get subgraph procids failed %d", rc);
				goto free_sg_proc_ids;
			}
			sg->num_proc_ids = rsp.sg_proc_ids->num_proc_ids;
			GSL_DBG("num procs - %d", sg->num_proc_ids);
			for (int procid = 0; procid < sg->num_proc_ids; procid++) {
				sg->persist_cal_data_per_proc[procid].proc_id = rsp.sg_proc_ids->proc_ids[procid];
				GSL_DBG("proc_id[%d] - %d", procid, sg->persist_cal_data_per_proc[procid].proc_id);
				rc = gsl_subgraph_query_persist_cal_by_mem(sg, new_ckv,
					ACDB_HW_ACCEL_MEM_DEFAULT, graph->proc_id, procid);
				if (rc == AR_ENOTEXIST) {
					goto continue_cma;
				} else if (rc) {
					GSL_ERR("persist cal query for sg_id %d failed %d",
						sg->sg_id, rc);
					goto cleanup;
				}

				rc = gsl_allocate_gpr_packet(APM_CMD_REGISTER_CFG,
					graph->src_port, GSL_GPR_DST_PORT_APM, sizeof(*cmd_header),
					0, graph->proc_id, &send_pkt);
				if (rc) {
					GSL_ERR("Failed to allocate GPR packet for sg_id 0x%x %d",
						sg->sg_id, rc);
					goto cleanup;
				}
				/*
				* below offset used to skip acdb header before sending data to
				* spf
				*/
				paddr_w_offset = sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_addr +
					sizeof(AcdbSgIdPersistData);
				cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
					send_pkt);
				cmd_header->mem_map_handle =
					sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_mmap_handle;
				cmd_header->payload_address_lsw = (uint32_t)(paddr_w_offset);
				cmd_header->payload_address_msw =
					(uint32_t)(paddr_w_offset >> 32);
				cmd_header->payload_size = sg->persist_cal_data_per_proc[procid].persist_cal_data_size
					- sizeof(AcdbSgIdPersistData);

				GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
					sizeof(*send_pkt) + sizeof(*cmd_header),
					(uint8_t *)sg->persist_cal_data_per_proc[procid].persist_cal_data.v_addr +
					sizeof(AcdbSgIdPersistData), cmd_header->payload_size);

				rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
					&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
				if (rc) {
					GSL_ERR("send perist cal for sg_id 0x%x failed %d",
						sg->sg_id, rc);
					goto cleanup;
				}
			}
continue_cma:
			/* do not break for BOTH, continue into cma*/
			if (cma_sg_info.subgraph_list[i].mem_type != ACDB_HW_ACCEL_MEM_BOTH)
				break;

		case ACDB_HW_ACCEL_MEM_CMA:
			/* persist_cal per proc_id support is not there for cma memory from AML */
			rc = gsl_subgraph_query_persist_cal_by_mem(sg, new_ckv,
				ACDB_HW_ACCEL_MEM_CMA, graph->proc_id, 0);
			if (rc == AR_ENOTEXIST) {
				continue;
			} else if (rc) {
				GSL_ERR("cma persist cal query for sg_id %d failed %d",
					sg->sg_id, rc);
				goto cleanup;
			}

			rc = gsl_allocate_gpr_packet(APM_CMD_REGISTER_CFG,
				graph->src_port, GSL_GPR_DST_PORT_APM, sizeof(*cmd_header),
				0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet for sg_id 0x%x %d",
					sg->sg_id, rc);
				goto cleanup;
			}

			/*
			 * below offset used to skip acdb header before sending data to
			 * spf
			 */
			paddr_w_offset = sg->cma_persist_cfg_data.spf_addr +
				sizeof(AcdbSgIdPersistData);
			cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
				send_pkt);
			cmd_header->mem_map_handle =
				sg->cma_persist_cfg_data.spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t)(paddr_w_offset);
			cmd_header->payload_address_msw =
				(uint32_t)(paddr_w_offset >> 32);
			cmd_header->payload_size = sg->cma_cal_data_size
				- sizeof(AcdbSgIdPersistData);

			send_pkt->client_data |= GSL_GPR_CMA_FLAG_BIT;

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header),
				(uint8_t *)sg->cma_persist_cfg_data.v_addr +
				sizeof(AcdbSgIdPersistData), cmd_header->payload_size);

			/* have mem filled, now assign it to the ML mem */
			rc = gsl_shmem_hyp_assign(sg->cma_persist_cfg_data.handle,
				AR_DEFAULT_DSP, AR_APSS);
			if (rc) {
				GSL_ERR("hyp assign failed %d", rc);
				goto cleanup;
			}

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc) {
				GSL_ERR("send cma perist cal for sg_id 0x%x failed %d",
					sg->sg_id, rc);
				goto cleanup;
			}

			break;
		default:
			GSL_ERR("unknown acdb hw accel mem type %d",
				cma_sg_info.subgraph_list[i].mem_type);
			rc = AR_EFAILED;
			goto cleanup;
		}
	}
free_sg_proc_ids:
	if(!rsp.sg_proc_ids)
		gsl_mem_free(rsp.sg_proc_ids);
cleanup:
	gsl_mem_free(cma_sg_info.subgraph_list);
free_status_list:
	gsl_mem_free(sg_cma_status_list.list);

exit:
	return rc;
}

static int32_t gsl_graph_send_global_persist_cal(struct gsl_graph *graph,
	struct gsl_sgid_list *sgid_list, struct gsl_graph_gkv_node *gkv_node,
	struct gsl_key_vector *prior_ckv, const struct gsl_key_vector *new_ckv)
{
	AcdbSgIdCalKeyVector cmd_struct;
	AcdbGlbPsistIdentifierList rsp_id_list;
	AcdbBlob rsp_blob;
	AcdbGlbPsistCalInfo *cal_info;
	uint8_t *cal_info_ptr;
	struct gsl_shmem_alloc_data *cal_data;
	int32_t rc;
	uint32_t i, j;
	uint32_t gpc_id;
	struct apm_cmd_header_t *cmd_header;
	gpr_packet_t *send_pkt = NULL;
	struct gsl_glbl_persist_cal_iid_list *cal_iid_lists;
	bool_t is_shmem_supported = TRUE;

	rc = __gpr_cmd_is_shared_mem_supported(graph->proc_id, &is_shmem_supported);
	if (!is_shmem_supported) {
		return AR_EUNSUPPORTED;
	} else if (rc) {
		GSL_ERR("GPR is shmem supported failed %d", rc)
		goto exit;
	}

	cmd_struct.num_sg_ids = sgid_list->len;
	cmd_struct.sg_ids = sgid_list->sg_ids;
	cmd_struct.cal_key_vector_prior.num_keys = prior_ckv->num_kvps;
	cmd_struct.cal_key_vector_prior.graph_key_vector =
		(AcdbKeyValuePair *)prior_ckv->kvp;
	cmd_struct.cal_key_vector_new.num_keys = new_ckv->num_kvps;
	cmd_struct.cal_key_vector_new.graph_key_vector =
		(AcdbKeyValuePair *)new_ckv->kvp;

	rsp_id_list.global_persistent_cal_info = NULL;
	rsp_id_list.num_glb_persist_identifiers = 0;
	rsp_id_list.size = 0;

	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_IDENTIFIERS,
		&cmd_struct, sizeof(cmd_struct), &rsp_id_list, sizeof(rsp_id_list));
	if (rc == AR_ENOTEXIST) {
		/*
		 * avoid printing error for the case where a graph does not have any
		 * global persist data
		 */
		GSL_DBG("get global persist identifiers size returned %d", rc);
		goto exit;
	} else if (rc) {
		GSL_ERR("get global persist identifiers size failed %d", rc);
		goto exit;
	}

	/* if no global persist cals */
	if (rsp_id_list.size == 0 || rsp_id_list.num_glb_persist_identifiers == 0)
		return AR_EOK;

	rsp_id_list.global_persistent_cal_info = gsl_mem_zalloc(rsp_id_list.size);
	if (!rsp_id_list.global_persistent_cal_info)
		return AR_ENOMEMORY;

	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_IDENTIFIERS,
		&cmd_struct, sizeof(cmd_struct), &rsp_id_list, sizeof(rsp_id_list));
	if (rc) {
		GSL_ERR("get global persist identifiers failed %d", rc);
		goto free_cal_info;
	}

	cal_info_ptr = (uint8_t *) rsp_id_list.global_persistent_cal_info;

	/* now add the cals into the global pool */
	/* allocate space for each */
	gkv_node->glbl_persist_cal_list =
		gsl_mem_zalloc(sizeof(struct gsl_glbl_persist_cal_iid_list)
		* rsp_id_list.num_glb_persist_identifiers);

	if (!gkv_node->glbl_persist_cal_list) {
		rc = AR_ENOMEMORY;
		goto free_cal_info;
	}

	cal_iid_lists = gkv_node->glbl_persist_cal_list;

	for (i = 0; i < rsp_id_list.num_glb_persist_identifiers; ++i) {

		cal_data = NULL;
		rsp_blob.buf = NULL;
		rsp_blob.buf_size = 0;
		cal_info = (AcdbGlbPsistCalInfo *)cal_info_ptr;

		gpc_id = cal_info->cal_identifier;

		rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_CALDATA, &gpc_id,
			sizeof(gpc_id), &rsp_blob, sizeof(rsp_blob));
		if (rc) {
			GSL_ERR("get global persist identifiers size failed %d", rc);
			goto cleanup;
		}

		cal_iid_lists[i].gpcal = gsl_global_persist_cal_pool_add(gpc_id,
			rsp_blob.buf_size, &cal_data, graph->proc_id);

		if (!cal_iid_lists[i].gpcal) {
			GSL_ERR("Add to global cal pool failed for cal ID %d", gpc_id);
			rc = AR_EFAILED;
			goto cleanup;
		}

		/* cal_data will be non-null if we need to fetch data */
		if (cal_data) {
			rsp_blob.buf = cal_data->v_addr;
			rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_CALDATA, &gpc_id,
				sizeof(gpc_id), &rsp_blob, sizeof(rsp_blob));
			if (rc) {
				GSL_ERR("get global persist calibration data failed %d", rc);
				goto cleanup;
			}
		} else {
			/* got null so entry already exists. Just point to it */
			cal_data = &(cal_iid_lists[i].gpcal->cal_data);
		}

		/* register cal on each iid */
		for (j = 0; j < cal_info->num_iids; ++j) {
			rc = gsl_allocate_gpr_packet(APM_CMD_REGISTER_SHARED_CFG,
				graph->src_port, cal_info->iids[j], sizeof(*cmd_header), 0,
				graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto cleanup;
			}

			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle = cal_data->spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t) cal_data->spf_addr;
			cmd_header->payload_address_msw =
				(uint32_t) (cal_data->spf_addr >> 32);

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header), NULL, 0);

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc) {
				GSL_ERR("Register shared cfg for iid %d failed:%d",
					cal_info->iids[j], rc);
				goto cleanup;
			}
			cal_iid_lists[i].iids[j] = cal_info->iids[j];
			++cal_iid_lists[i].num_iids;
		}

		/* AcdbGlbPsistCalInfo has variable size. Advance ptr to next object */
		cal_info_ptr += sizeof(AcdbGlbPsistCalInfo)
			+ sizeof(uint32_t)*cal_info->num_iids;
	}
	goto free_cal_info;

cleanup:
	gsl_mem_free(cal_iid_lists);
free_cal_info:
	gsl_mem_free(rsp_id_list.global_persistent_cal_info);
exit:
	return rc;
}

static int32_t check_and_register_dynamic_pd(struct gsl_graph *graph,
	struct gsl_sgid_list *sgids, uint32_t ss_mask, uint32_t *dyn_ss_mask)
{
	int32_t i = 0, j = 0, rc = AR_EOK;
	uint32_t sg_ss_mask = 0;
	uint32_t tmp_ss_masks[sgids->len];
	uint32_t tmp_dyn_ss_mask = 0;

	*dyn_ss_mask = 0;
	GSL_DBG("proc_id %d, num subgraphs %d, ss_mask 0x%x", graph->proc_id, sgids->len, ss_mask);
	if (ss_mask == (uint32_t) GSL_GET_SPF_SS_MASK(graph->proc_id))
		return AR_EOK;

	for (i = 0; i < sgids->len; ++i) {
		gsl_mdf_utils_query_graph_ss_mask(&sgids->sg_ids[i], 1, &sg_ss_mask);
		GSL_DBG("subgraph: id 0x%x, ss_mask 0x%x", sgids->sg_ids[i], sg_ss_mask);
		if (sg_ss_mask == GSL_GET_SPF_SS_MASK(graph->proc_id))
			continue;
		rc = gsl_mdf_utils_register_dynamic_pd(sg_ss_mask, graph->proc_id, graph->src_port,
			&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG], &tmp_dyn_ss_mask);
		*dyn_ss_mask |= tmp_dyn_ss_mask;
		if (rc) {
			GSL_ERR("dynamic pd registration failed, status %d", rc);
			goto err_exit;
		}
		tmp_ss_masks[j++] = sg_ss_mask;
	}
	return rc;

err_exit:
	while (j-- > 0)
		gsl_mdf_utils_deregister_dynamic_pd(tmp_ss_masks[j], graph->proc_id);
	*dyn_ss_mask = 0;
	return rc;

}

static int32_t check_and_deregister_dynamic_pd(struct gsl_graph *graph,
	struct gsl_sgid_list *sgids)
{
	int32_t i = 0, rc = AR_EOK;
	uint32_t sg_ss_mask = 0;

	GSL_DBG("proc_id %d, num subgraphs %d, ss_mask 0x%x", graph->proc_id, sgids->len, graph->ss_mask);
	if (graph->ss_mask == (uint32_t) GSL_GET_SPF_SS_MASK(graph->proc_id))
		return AR_EOK;

	for (i = 0; i < sgids->len; ++i) {
		gsl_mdf_utils_query_graph_ss_mask(&sgids->sg_ids[i], 1, &sg_ss_mask);
		GSL_DBG("subgraph: id 0x%x, ss_mask 0x%x", sgids->sg_ids[i], sg_ss_mask);
		if (sg_ss_mask == GSL_GET_SPF_SS_MASK(graph->proc_id))
			continue;
		rc = gsl_mdf_utils_deregister_dynamic_pd(sg_ss_mask, graph->proc_id);
		if (rc)
			GSL_ERR("dynamic pd de-init failed, status %d", rc);
	}
	return rc;
}

enum gsl_graph_states gsl_graph_update_state(struct gsl_graph *graph,
	enum gsl_graph_states new_state)
{
	enum gsl_graph_states temp = graph->graph_state;
	/*
	 * error is a sink state, once we go into this state we stay in it to block
	 * any further operations on the graph
	 */
	if (graph->graph_state != GRAPH_ERROR &&
		graph->graph_state != GRAPH_ERROR_ALLOW_CLEANUP)
		graph->graph_state = new_state;

	return temp;	//Return previous state.
}

enum gsl_graph_states gsl_graph_get_state(struct gsl_graph *graph)
{
	return graph->graph_state;
}

void gsl_graph_signal_event_all(struct gsl_graph *graph,
	enum gsl_graph_sig_event_mask ev_flags)
{
	gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG],
		ev_flags, 0, NULL);
	gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG],
		ev_flags, 0, NULL);
	gsl_signal_set(&graph->graph_signal[GRAPH_CTRL_GRP3_CMD_SIG],
		ev_flags, 0, NULL);
	if (graph->write_info.lock)
		gsl_signal_set(&graph->write_info.dp_signal,
			ev_flags, 0, NULL);
	if (graph->read_info.lock)
		gsl_signal_set(&graph->read_info.dp_signal,
			ev_flags, 0, NULL);
}

int32_t gsl_graph_init(struct gsl_graph *graph)
{
	int32_t rc = AR_EOK, i;

	rc = ar_osal_mutex_create(&graph->graph_lock);
	if (rc)
		goto exit;

	rc = ar_osal_mutex_create(&graph->get_set_cfg_lock);
	if (rc)
		goto destroy_graph_lock;

	rc = ar_osal_mutex_create(&graph->gkv_list_lock);
	if (rc)
		goto destroy_get_set_cfg_lock;

	graph->graph_state = GRAPH_IDLE;

	/* Default proc id is assumed to be ADSP */
	graph->proc_id = AR_DEFAULT_DSP;

	for (i = 0; i < GRAPH_CMD_SIG_MAX; ++i) {
		/*
		 * use the same mutex for all signals to save memory, we can have a
		 * mutex per signal if we want to optimize further
		 */
		rc = gsl_signal_create(&graph->graph_signal[i], &graph->graph_lock);
		if (rc)
			goto destroy_graph_signals;	//some signals may have been created
	}

	/* lockless signal */
	rc = gsl_signal_create(&graph->transient_state_info.trans_state_change_sig,
		NULL);
	if (rc)
		goto destroy_graph_signals;

	graph->num_gkvs = 0;
	rc = ar_list_init(&graph->gkv_list, NULL, NULL);
	if (AR_FAILED(rc)) {
		GSL_ERR("failed to initialize gkv list: %d", rc);
		goto destroy_flush_signal;
	}

	gsl_graph_update_state(graph, GRAPH_OPENED);
	goto exit;

destroy_flush_signal:
	ar_osal_signal_destroy(
		graph->transient_state_info.trans_state_change_sig.sig);
destroy_graph_signals:
	for (i = 0; i < GRAPH_CMD_SIG_MAX; ++i)
		ar_osal_signal_destroy(graph->graph_signal[i].sig);
	ar_osal_mutex_destroy(graph->gkv_list_lock);
destroy_get_set_cfg_lock:
	ar_osal_mutex_destroy(graph->get_set_cfg_lock);
destroy_graph_lock:
	ar_osal_mutex_destroy(graph->graph_lock);
exit:
	return rc;
}

int32_t gsl_graph_deinit(struct gsl_graph *graph)
{
	int32_t i;

	for (i = 0; i < GRAPH_CMD_SIG_MAX; ++i)
		gsl_signal_destroy(&graph->graph_signal[i]);

	gsl_signal_destroy(&graph->transient_state_info.trans_state_change_sig);

	ar_osal_mutex_destroy(graph->get_set_cfg_lock);
	ar_osal_mutex_destroy(graph->graph_lock);
	graph->graph_state = GRAPH_IDLE;

	ar_list_clear(&graph->gkv_list);
	ar_osal_mutex_destroy(graph->gkv_list_lock);

	return AR_EOK;
}

int32_t gsl_acdb_get_graph(const struct gsl_key_vector *gkv,
	uint32_t **sg_id_list, AcdbGetGraphRsp *sg_conn_info)
{
	AcdbGetGraphRsp rsp_struct;
	AcdbGraphKeyVector cmd_struct;
	AcdbSubgraph *sgs;
	uint32_t cmd_struct_size, rsp_struct_size, num_dst_sgs;
	int32_t rc, i, payload_size;
	uint32_t num_of_subgraphs, *rsp_p, *sg_ids;

	/* Populate command structure */
	cmd_struct_size = sizeof(AcdbGraphKeyVector);
	cmd_struct.num_keys = gkv->num_kvps;
	cmd_struct.graph_key_vector = (AcdbKeyValuePair *)gkv->kvp;

	/**
	 * Populate response structure
	 * Response size is unknown here, so allocate minimum of 8 bytes,
	 * so ACDB SW can return the size to be allocated
	 */
	rsp_struct.subgraphs = NULL;
	rsp_struct.size = 0;
	rsp_struct.num_subgraphs = 0;
	rsp_struct_size = sizeof(AcdbGetGraphRsp);

	rc = acdb_ioctl(ACDB_CMD_GET_GRAPH, &cmd_struct, cmd_struct_size,
		&rsp_struct, rsp_struct_size);
	if (rc) {
		GSL_ERR("get_graph acdb ioctl for size failed: %d", rc);
		goto exit;
	}
	/*
	 * Getting 0 subgraphs is a valid scenario, GSL should handle it by not
	 * opening any subgraphs on Spf
	 */
	if (rsp_struct.size == 0) {
		GSL_DBG("zero size returned for get_graph: %d, size: %d", rc,
			rsp_struct.size);
		if (sg_conn_info) {
			sg_conn_info->num_subgraphs = 0;
			sg_conn_info->size = 0;
			sg_conn_info->subgraphs = NULL;
		}
		if (sg_id_list)
			*sg_id_list = NULL;
		goto exit;
	}

	sgs = gsl_mem_zalloc(rsp_struct.size);
	if (!sgs) {
		rc = AR_ENOMEMORY;
		goto exit;
	}
	rsp_struct.subgraphs = sgs;

	rc = acdb_ioctl(ACDB_CMD_GET_GRAPH, &cmd_struct, cmd_struct_size,
		&rsp_struct, rsp_struct_size);
	if (rc) {
		GSL_ERR("get_graph acdb ioctl for data failed: %d", rc);
		goto free_sgs;
	}

	/* rsp_struct: {num_of_subgraphs, size, <AcdbSubgraph structure> */
	rsp_p = (uint32_t *)&rsp_struct;
	payload_size = rsp_struct.size;
	num_of_subgraphs = rsp_struct.num_subgraphs;

	/**
	 * create size twice the number of sub-graphs, first half to
	 *  hold the sg_ids read from ACDB, second half to hold the sg_ids
	 *  whose open_ref_cnt is equal to 1
	 */
	sg_ids = gsl_mem_zalloc(2 * (size_t)num_of_subgraphs * sizeof(uint32_t));
	if (!sg_ids) {
		rc = AR_ENOMEMORY;
		goto free_sgs;
	}

	rsp_p = (uint32_t *)rsp_struct.subgraphs;
	i = 0;
	while (payload_size > 0) {
		sg_ids[i++] = *rsp_p++;
		num_dst_sgs = *rsp_p++;
		rsp_p += num_dst_sgs;
		payload_size -= 4 * (2 + num_dst_sgs);
	}
	/**
	 * After successful parsing payload_size should become 0
	 * Check if it becomes negative and return error to avoid
	 * illegal memory accesses
	 */
	if (payload_size < 0) {
		rc = AR_EFAILED;
		GSL_ERR("get_graph response parsing failed: %d", rc);
		goto free_sg_ids;
	}
	*sg_id_list = sg_ids;
	if (sg_conn_info) {
		sg_conn_info->num_subgraphs = rsp_struct.num_subgraphs;
		sg_conn_info->size = rsp_struct.size;
		sg_conn_info->subgraphs = sgs;
	}

	rc = 0;

free_sg_ids:
	if (rc)
		gsl_mem_free(sg_ids);
free_sgs:
	if (rc || !sg_conn_info) {
		gsl_mem_free(sgs);
		if (sg_conn_info)
			sg_conn_info->subgraphs = NULL;
	}
exit:
	return rc;
}

/*
 * allocates and returns module_info for a given tag. Caller is responsible to
 * free the module info.
 */
static int32_t _gsl_graph_get_module_tag_info(uint32_t *sg_id_list,
	uint32_t num_sgs, uint32_t tag, struct gsl_module_id_info **module_info,
	uint32_t *module_info_size)
{
	AcdbGetTaggedModulesReq acdb_req;
	AcdbGetTaggedModulesRsp acdb_rsp;
	struct gsl_module_id_info *mod_info;
	uint32_t mod_info_size;
	int32_t rc = AR_EOK;

	*module_info = NULL;
	*module_info_size = 0;
	acdb_req.num_sg_ids = num_sgs;
	acdb_req.sg_ids = sg_id_list;
	acdb_req.tag_id = tag;
	acdb_rsp.num_tagged_mids = 0;
	acdb_rsp.tagged_mid_list = NULL;
	rc = acdb_ioctl(ACDB_CMD_GET_TAGGED_MODULES, &acdb_req,
		sizeof(acdb_req), &acdb_rsp, sizeof(acdb_rsp));
	if (rc && rc != AR_ENOTEXIST) {
		GSL_ERR("acdb_ioctl failed with err %d", rc);
		return rc;
	}
	if (acdb_rsp.num_tagged_mids == 0) {
		GSL_ERR("number of modules tagged with 0x%x are zero", tag);
		return AR_ENOTEXIST;
	}
	mod_info_size = sizeof(struct gsl_module_id_info) +
	(acdb_rsp.num_tagged_mids * sizeof(struct gsl_module_id_info_entry));
	mod_info = gsl_mem_zalloc(mod_info_size);
	if (!mod_info) {
		rc = AR_ENOMEMORY;
		return rc;
	}
	mod_info->num_modules = acdb_rsp.num_tagged_mids;
	acdb_rsp.tagged_mid_list = (AcdbModuleInstance *)
		&mod_info->module_entry[0];
	rc = acdb_ioctl(ACDB_CMD_GET_TAGGED_MODULES, &acdb_req,
		sizeof(acdb_req), &acdb_rsp, sizeof(acdb_rsp));
	if (rc) {
		GSL_ERR("acdb_ioctl failed with err %d", rc);
		goto cleanup;
	}
	*module_info = mod_info;
	*module_info_size = mod_info_size;

cleanup:
	if (rc)
		gsl_mem_free(mod_info);
	return rc;
}

int32_t _gsl_graph_get_module_proc_tag_info(uint32_t *sg_id_list,
	uint32_t num_sgs, uint32_t tag, struct gsl_module_id_proc_info **proc_module_info)
{
	AcdbGetProcTaggedModulesReq acdb_req;
	AcdbGetProcTaggedModulesRsp acdb_rsp;
	int32_t rc = AR_EOK;
	struct gsl_module_id_proc_info *proc_mod_info;

	acdb_req.num_sg_ids = num_sgs;
	acdb_req.sg_ids = sg_id_list;
	acdb_req.tag_id = tag;
	acdb_rsp.num_procs = 0;
	acdb_rsp.list_size = 0;
	acdb_rsp.proc_tagged_module_list = NULL;
	rc = acdb_ioctl(ACDB_CMD_GET_PROC_TAGGED_MODULES, &acdb_req,
		sizeof(acdb_req), &acdb_rsp, sizeof(acdb_rsp));
	if (rc && rc != AR_ENOTEXIST) {
		GSL_ERR("acdb_ioctl failed with err %d", rc);
		return rc;
	}
	if (acdb_rsp.list_size == 0) {
		GSL_ERR("number of modules tagged with 0x%x are zero", tag);
		return AR_ENOTEXIST;
	}

	//Allocate space for the process module list
	acdb_rsp.proc_tagged_module_list = gsl_mem_zalloc(acdb_rsp.list_size);
	if (!acdb_rsp.proc_tagged_module_list) {
		rc = AR_ENOMEMORY;
		return rc;
	}
	rc = acdb_ioctl(ACDB_CMD_GET_PROC_TAGGED_MODULES, &acdb_req,
		sizeof(acdb_req), &acdb_rsp, sizeof(acdb_rsp));
	if (rc && rc != AR_ENOTEXIST) {
		GSL_ERR("acdb_ioctl failed with err %d", rc);
		if (acdb_rsp.proc_tagged_module_list)
			gsl_mem_free(acdb_rsp.proc_tagged_module_list);
		return rc;
	}
	if (rc) {
		GSL_ERR("acdb_ioctl failed with err %d", rc);
		goto cleanup;
	}
	//Allocate space for the top level gsl_module_id_proc_info struct
	proc_mod_info = gsl_mem_zalloc(acdb_rsp.list_size + 8);
	if (!proc_mod_info) {
		rc = AR_ENOMEMORY;
		return rc;
	}
	proc_mod_info->num_procs = acdb_rsp.num_procs;
	proc_mod_info->list_size = acdb_rsp.list_size;
	proc_mod_info->proc_module_list =
		(struct gsl_module_id_proc_info_entry *)acdb_rsp.proc_tagged_module_list;
	*proc_module_info = proc_mod_info;


	cleanup:
	if (rc && acdb_rsp.proc_tagged_module_list != NULL)
		gsl_mem_free(acdb_rsp.proc_tagged_module_list);
	return rc;
}

int32_t gsl_graph_get_module_tag_info(const struct gsl_key_vector *gkv,
	uint32_t tag, struct gsl_module_id_info **module_info,
	uint32_t *module_info_size)
{
	int32_t rc = AR_EOK;
	uint32_t *sg_id_list;
	AcdbGetGraphRsp sg_conn_info;

	rc = gsl_acdb_get_graph(gkv, &sg_id_list, &sg_conn_info);
	if (rc) {
		GSL_ERR("get graph failed %d", rc);
		return rc;
	}
	/* it's possible to get empty subgraph list from ACDB */
	if (sg_id_list == NULL || sg_conn_info.num_subgraphs == 0) {
		rc = AR_ENOTEXIST;
		return rc;
	}

	rc = _gsl_graph_get_module_tag_info(sg_id_list, sg_conn_info.num_subgraphs,
		tag, module_info, module_info_size);

	gsl_mem_free(sg_id_list);
	gsl_mem_free(sg_conn_info.subgraphs);
	return rc;
}

int32_t gsl_graph_set_custom_config(struct gsl_graph *graph,
	const uint8_t *payload, const uint32_t payload_size,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	apm_module_param_data_t *param_data = (apm_module_param_data_t *)payload;
	uint32_t dst_port = GSL_GPR_DST_PORT_APM;

	GSL_MUTEX_LOCK(lock);
	/* serialize all get/set operations on a graph */
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	/* This condition is satisfied if we have only 1 Param ID &
	 * Payload in the Query. Can be safely sent to the module
	 * itself instead of APM.
	 */
	if ((GSL_ALIGN_8BYTE(param_data->param_size) +
		sizeof(apm_module_param_data_t)) == payload_size) {
		dst_port = param_data->module_instance_id;
	} else {
	    dst_port = GSL_GPR_DST_PORT_APM;
	}

	if (payload_size <= GSL_IN_BAND_SIZE_THRESHOLD)
		rc = gsl_apm_config_inband(graph, payload, payload_size,
			APM_CMD_SET_CFG, dst_port, NULL);
	else
		rc = gsl_apm_config_oob(graph, payload, payload_size, APM_CMD_SET_CFG,
			dst_port);

	if (rc)
		GSL_ERR("Graph set custom cfg failed %d", rc);

	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_get_custom_config(struct gsl_graph *graph,
	uint8_t *payload, uint32_t payload_size, ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	apm_module_param_data_t *param_data = (apm_module_param_data_t *)payload;
	uint32_t dst_port = GSL_GPR_DST_PORT_APM;
	bool_t is_shmem_supported = TRUE;

	GSL_MUTEX_LOCK(lock);
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	/* This condition is satisfied if we have only 1 Param ID &
	 * Payload in the Query. Can be safely sent to the module
	 * itself instead of APM.
	 */
	if ((GSL_ALIGN_8BYTE(param_data->param_size) +
		sizeof(apm_module_param_data_t)) == payload_size) {
		dst_port = param_data->module_instance_id;
	} else {
		dst_port = GSL_GPR_DST_PORT_APM;
	}

	rc = __gpr_cmd_is_shared_mem_supported(graph->proc_id, &is_shmem_supported);
	if (rc) {
		GSL_ERR("GPR is shmem supported failed %d", rc)
		goto exit;
	}

	if (payload_size <= GSL_IN_BAND_SIZE_THRESHOLD || !is_shmem_supported)
		rc = gsl_apm_get_config_inband(graph, payload, &payload_size, dst_port);
	else
		rc = gsl_apm_config_oob(graph, payload, payload_size,
			APM_CMD_GET_CFG, dst_port);

	if (rc)
		GSL_ERR("Graph get custom config failed %d", rc);

exit:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_set_tagged_custom_config(struct gsl_graph *graph,
	uint32_t tag, const uint8_t *payload, const size_t payload_size,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
    struct gsl_sgid_list sg_id_list = {0, NULL};
    struct gsl_module_id_info *module_info;
	struct apm_cmd_header_t *cmd_header;
	uint32_t i, module_info_size;
	uint8_t *cmd_payload;
	gsl_msg_t gsl_msg;

	rc = gsl_graph_get_sgids_and_objs(graph, &sg_id_list, NULL);
	if (rc) {
		GSL_ERR("get sgidlist failed %d", rc);
		return rc;
	}
	/* in-case no subgraphs are found then exit */
	if (!sg_id_list.sg_ids) {
		rc = AR_ENOTEXIST;
		goto exit;
	}

	GSL_MUTEX_LOCK(lock);
	/* serialize all get/set operations on a graph */
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	rc = _gsl_graph_get_module_tag_info(sg_id_list.sg_ids,
		sg_id_list.len, tag, &module_info, &module_info_size);
	if (rc) {
		GSL_ERR("fail to get tagged module iid %d", rc);
		goto cleanup;
	}

	for (i = 0; i < module_info->num_modules; ++i) {
		rc = gsl_msg_alloc(APM_CMD_SET_CFG, graph->src_port,
			module_info->module_entry[i].module_iid, sizeof(*cmd_header), 0,
			graph->proc_id, GSL_ALIGN_8BYTE(payload_size), true, &gsl_msg);
		if (rc) {
			GSL_ERR("Failed to allocate GPR packet %d", rc);
			goto free_mem;
		}

		cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
			gsl_msg.gpr_packet);
		cmd_payload = (uint8_t *)cmd_header + sizeof(*cmd_header);
		cmd_header->payload_size = (uint32_t)GSL_ALIGN_8BYTE(payload_size);

		gsl_memcpy(cmd_payload, GSL_ALIGN_8BYTE(payload_size), payload,
			payload_size);

		/* clients don't know MIID. Set it here */
		*(uint32_t *)cmd_payload = module_info->module_entry[i].module_iid;

		GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
			sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header) +
			GSL_ALIGN_8BYTE(payload_size), NULL, 0);

		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
			&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
		if (rc) {
			GSL_ERR("Graph set config failed:%d, miid: 0x%x", rc,
				module_info->module_entry[i].module_iid);
			goto free_msg;
		}
		gsl_msg_free(&gsl_msg);
	}

	goto free_mem;
free_msg:
	gsl_msg_free(&gsl_msg);
free_mem:
	gsl_mem_free(module_info);
cleanup:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);
	gsl_mem_free(sg_id_list.sg_ids);
exit:
	return rc;
}

int32_t gsl_graph_set_tagged_custom_config_persist(struct gsl_graph *graph,
	uint32_t tag, const uint8_t *payload, const uint32_t payload_size,
	ar_osal_mutex_t lock)
{
	uint32_t i = 0, module_info_size;
	int32_t rc = AR_EOK;
	struct gsl_module_id_info *module_info = NULL;
	uint8_t *cmd_payload;
	struct apm_cmd_header_t *apm_hdr;
	struct gsl_subgraph **sg_objs = NULL;
	uint32_t num_sg_objs = 0;
	gpr_packet_t *send_pkt = NULL;
	bool_t is_shmem_supported = TRUE;

	rc = __gpr_cmd_is_shared_mem_supported(graph->proc_id, &is_shmem_supported);
	if (!is_shmem_supported) {
		return AR_EOK;
	} else if (rc) {
		GSL_ERR("GPR is shmem supported failed %d", rc)
		goto exit;
	}

	sg_objs = gsl_graph_get_sg_array(graph, &num_sg_objs);
	if (!sg_objs) {
		GSL_ERR("get sg objs failed %d", rc);
		goto exit;
	}
	if (num_sg_objs == 0) {
		rc = AR_ENOTEXIST;
		goto free_sg_obs;
	}

	GSL_MUTEX_LOCK(lock);
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	for (i = 0; i < num_sg_objs; ++i) {
		rc = _gsl_graph_get_module_tag_info(&sg_objs[i]->sg_id, 1, tag,
			&module_info, &module_info_size);
		if (rc == AR_ENOTEXIST) {
			rc = AR_EOK;
			continue;
		} else if (rc) {
			GSL_ERR("fail to get tagged module iid %d", rc);
			goto cleanup;
		}

		if (module_info_size == 0)
			continue;
		/*
		 * Check if this SG already has persistent cal we must de-reg and
		 * free it only if SG is in stopped/suspended state
		 */
		if (sg_objs[i]->user_persist_cfg_data.handle &&
			sg_objs[i]->start_ref_cnt == 0) {

			rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
				graph->src_port, module_info->module_entry[0].module_iid,
				sizeof(*apm_hdr), 0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("allocate gpr packet failed %d, miid: 0x%x",
					rc,	module_info->module_entry[0].module_iid);
				continue;
			}
			apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, send_pkt);

			apm_hdr->mem_map_handle =
				sg_objs[i]->user_persist_cfg_data.spf_mmap_handle;
			apm_hdr->payload_address_lsw = (uint32_t)
				sg_objs[i]->user_persist_cfg_data.spf_addr;
			apm_hdr->payload_address_msw =
				(uint32_t)(sg_objs[i]->user_persist_cfg_data.spf_addr >> 32);
			apm_hdr->payload_size = sg_objs[i]->user_persist_cfg_data_size;

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*apm_hdr),
				sg_objs[i]->user_persist_cfg_data.v_addr,
				sg_objs[i]->user_persist_cfg_data_size);

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc != AR_EOK) {
				GSL_ERR("send dereg perist cal for sg_id 0x%x failed %d",
					sg_objs[i]->sg_id, rc);
				goto free_module_info;
			}

			rc = gsl_shmem_free(&sg_objs[i]->user_persist_cfg_data);
			if (rc != AR_EOK)
				goto free_module_info;
		} else if (sg_objs[i]->user_persist_cfg_data.handle) {
			/*
			 * SG already has persistent data and it is already started
			 * do not update persistent cal in this case
			 */
			continue;
		}
		/*
		 * Store the persistent cal in this SGs context and register with
		 * Spf
		 */
		sg_objs[i]->user_persist_cfg_data_size = payload_size;
		rc = gsl_shmem_alloc(sg_objs[i]->user_persist_cfg_data_size,
			graph->proc_id, &sg_objs[i]->user_persist_cfg_data);
		if (rc != AR_EOK)
			goto free_module_info;

		cmd_payload = (uint8_t *)sg_objs[i]->user_persist_cfg_data.v_addr;
		gsl_memcpy(cmd_payload, sg_objs[i]->user_persist_cfg_data_size,
			payload, payload_size);

		rc = gsl_allocate_gpr_packet(APM_CMD_REGISTER_CFG,
			graph->src_port, module_info->module_entry[0].module_iid,
			sizeof(*apm_hdr), 0, graph->proc_id, &send_pkt);
		if (rc) {
			GSL_ERR("allocate gpr packet failed %d", rc);
			goto free_module_info;
		}
		apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, send_pkt);

		apm_hdr->mem_map_handle =
			sg_objs[i]->user_persist_cfg_data.spf_mmap_handle;
		apm_hdr->payload_address_lsw = (uint32_t)
			sg_objs[i]->user_persist_cfg_data.spf_addr;
		apm_hdr->payload_address_msw =
			(uint32_t)(sg_objs[i]->user_persist_cfg_data.spf_addr >> 32);
		apm_hdr->payload_size = payload_size;

		GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
			sizeof(*send_pkt) + sizeof(*apm_hdr),
			sg_objs[i]->user_persist_cfg_data.v_addr,
			sg_objs[i]->user_persist_cfg_data_size);

		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
			&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
		if (rc != AR_EOK) {
			GSL_ERR("send perist cal for sg_id 0x%x failed %d",
				sg_objs[i]->sg_id, rc);
			gsl_shmem_free(&sg_objs[i]->user_persist_cfg_data);
			sg_objs[i]->user_persist_cfg_data_size = 0;
			goto free_module_info;
		}
		gsl_mem_free(module_info);
	}

	goto cleanup; /* skip freeing module_info in success case */

free_module_info:
	gsl_mem_free(module_info);

cleanup:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);

free_sg_obs:
	gsl_mem_free(sg_objs);
exit:
	return rc;
}

int32_t gsl_graph_get_tagged_custom_config(struct gsl_graph *graph,
	uint32_t tag, uint8_t *payload, uint32_t *payload_size,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	struct gsl_sgid_list sg_id_list = {0, NULL};
	struct gsl_module_id_info *module_info = NULL;
	apm_module_param_data_t *param_data = (apm_module_param_data_t *)payload;
	uint32_t module_info_size = 0;
	uint32_t dst_port = GSL_GPR_DST_PORT_APM;

	rc = gsl_graph_get_sgids_and_objs(graph, &sg_id_list, NULL);
	if (rc) {
		GSL_ERR("get sgidlist failed %d", rc);
		goto exit;
	}
	/* if no subgraphs are found then go to exit */
	if (!sg_id_list.sg_ids) {
		*payload_size = 0;
		rc = AR_ENOTEXIST;
		goto exit;
	}

	GSL_MUTEX_LOCK(lock);
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	rc = _gsl_graph_get_module_tag_info(sg_id_list.sg_ids, sg_id_list.len, tag,
		&module_info, &module_info_size);
	if (rc) {
		GSL_ERR("fail to get tagged module iid %d", rc);
		goto cleanup;
	}

	*(uint32_t *)payload = module_info->module_entry[0].module_iid;

	/* This condition is satisfied if we have only 1 Param ID &
	 * Payload in the Query. Can be safely sent to the module
	 * itself instead of APM.
	 */
	if ((GSL_ALIGN_8BYTE(param_data->param_size) +
		sizeof(apm_module_param_data_t))
		== *payload_size) {
		dst_port = module_info->module_entry[0].module_iid;
	} else {
		dst_port = GSL_GPR_DST_PORT_APM;
	}

	if (*payload_size <= GSL_IN_BAND_SIZE_THRESHOLD)
		rc = gsl_apm_get_config_inband(graph, payload, payload_size, dst_port);
	else
		rc = gsl_apm_config_oob(graph, payload, *payload_size,
			APM_CMD_GET_CFG, dst_port);

	if (rc) {
		GSL_ERR("Graph get config failed:%d, miid: 0x%x", rc,
		module_info->module_entry[0].module_iid);
		goto free_module_info;
	}

free_module_info:
	gsl_mem_free(module_info);
cleanup:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);
	gsl_mem_free(sg_id_list.sg_ids);
exit:
	return rc;
}

static int32_t gsl_graph_set_sg_cal(struct gsl_graph *graph,
	struct gsl_sgid_list *sgid_list, struct gsl_graph_gkv_node *gkv_node,
	const struct gsl_key_vector *ckv, const struct gsl_key_vector *gkv,
	bool isCKVValidated)
{
	int32_t rc = AR_EOK;
	struct gsl_key_vector *prior_ckv = &gkv_node->ckv;
	const struct gsl_key_vector *new_ckv = ckv;
	struct gsl_sgobj_list sg_objs_list;

	/*
	 * if no new ckv is given it means we should set only the cal data which is
	 * not ckv depenedent. To get such data from acdb, acdb requires the prior
	 * ckv and new ckv must be set to empty ckv.
	 * Note: Once a ckv dependent cal is set then attempting to set the default
	 * has no affect.
	 */
	if (!ckv) {
		if (prior_ckv->num_kvps == 0) {
			new_ckv = &gkv_node->ckv;
		} else {
			/*
			 * client is attempting to set the default cal even though a ckv
			 * has been set
			 */
			goto exit;
		}
	}

	sg_objs_list.len = gkv_node->num_of_subgraphs;
	sg_objs_list.sg_objs = gkv_node->sg_array;

	rc = gsl_graph_send_nonpersist_cal(graph, sgid_list, prior_ckv, new_ckv, gkv, isCKVValidated);
	if (rc == AR_ENOTEXIST || rc == AR_EUNSUPPORTED) {
		GSL_DBG("graph send non-persist cal warning %d", rc);
		rc = AR_EOK;
	} else if (rc) {
		GSL_ERR("graph send non-persist cal failed %d", rc);
		goto exit;
	}

	/*
	 * persist calibration update in GRAPH_STARTED state is not required to be
	 * supported as there is no dynamic persist calibration supported by any
	 * SPF module without quality issues. persist cal handles this on sg-by-sg
	 * basis, global persist cal just skips if the graph is started.
	 */
	rc = gsl_graph_send_persist_cal(graph, &sg_objs_list, new_ckv);
	if (rc == AR_ENOTEXIST || rc == AR_EUNSUPPORTED) {
		GSL_DBG("graph send persist cal warning %d", rc);
		rc = AR_EOK;
	} else if (rc) {
		GSL_ERR("graph send persist cal failed %d", rc);
		goto exit;
	}

	if (gsl_graph_get_state(graph) != GRAPH_STARTED) {
		rc = gsl_graph_send_global_persist_cal(graph, sgid_list, gkv_node,
			prior_ckv, new_ckv);
		if (rc == AR_ENOTEXIST || rc == AR_EUNSUPPORTED) {
			GSL_DBG("graph send global persist cal warning %d", rc);
			rc = AR_EOK;
		} else if (rc) {
			GSL_ERR("graph send global persist cal failed %d", rc);
			goto exit;
		}
	}

	/* only update cached ckv if a new ckv was provided */
	if (ckv && ckv->num_kvps) {
		if (!gkv_node->ckv.kvp) {
			gkv_node->ckv.kvp = gsl_mem_zalloc(
				sizeof(struct gsl_key_value_pair) * ckv->num_kvps);
			if (!gkv_node->ckv.kvp) {
				rc = AR_ENOMEMORY;
				goto exit;
			}
		} else if (ckv->num_kvps != gkv_node->ckv.num_kvps) {
			GSL_ERR("Size mismatch in Cal key vector");
			rc = AR_EBADPARAM;
			goto exit;
		}
		/* cache the new ckv */
		gkv_node->ckv.num_kvps = ckv->num_kvps;
		gsl_memcpy(gkv_node->ckv.kvp,
			sizeof(struct gsl_key_value_pair) * ckv->num_kvps, ckv->kvp,
			sizeof(struct gsl_key_value_pair) * ckv->num_kvps);
	}
exit:
	return rc;
}

static int32_t gsl_graph_close_sgids_and_connections(struct gsl_graph *graph,
	struct gsl_sgid_list sgids, AcdbSubgraph *sg_conn, uint32_t num_sg_conn)
{
	int32_t rc = AR_EOK;
	struct gsl_blob spf_sg_conn_blob;
	uint32_t close_pld_size = 0, sg_list_pid_size = 0, padded_bytes, i;
	int8_t *close_payload;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *param_data;
	uint32_t param_size;
	gsl_msg_t gsl_msg;

	/* Get subgraph data size for spf and drv blobs */
	GSL_DBG("num_sgid= %d", sgids.len);
	GSL_DBG("sg list:");
	for (i = 0; i < sgids.len; ++i)
		GSL_DBG("%x", sgids.sg_ids[i]);
	gsl_print_sg_conn_info((uint32_t *)sg_conn,
		num_sg_conn);

	/* Get sg connection blob size from ACDB */
	gsl_memset(&spf_sg_conn_blob, 0, sizeof(struct gsl_blob));
	if (num_sg_conn) {
		rc = gsl_acdb_get_subgraph_connections(sg_conn, num_sg_conn,
			&spf_sg_conn_blob);
		if (rc == AR_ENOTEXIST) {
			GSL_ERR("got 0 size for sg connection blob");
			rc = AR_EOK;
		} else if (rc) {/* Continue closing SGs if rc is non-zero  */
			GSL_ERR("failed to get size for sg connection blob %d", rc);
		}
	}

	/*
	 * Compute total size of the close command, it is equal to
	 * size of the SUB_GRAPH_LIST PID payload plus subgraph connection
	 * blob size
	 */
	if (sgids.len)
		sg_list_pid_size = (uint32_t)(sizeof(struct apm_module_param_data_t) +
			(sizeof(uint32_t) * (1 + (size_t)sgids.len)));
	padded_bytes = GSL_PADDING_8BYTE_ALIGN(sg_list_pid_size);
	close_pld_size += (GSL_ALIGN_8BYTE(sg_list_pid_size)) +
		spf_sg_conn_blob.size;

	rc = gsl_msg_alloc(APM_CMD_GRAPH_CLOSE, graph->src_port,
		GSL_GPR_DST_PORT_APM, sizeof(*cmd_header), 0, graph->proc_id,
		close_pld_size, false, &gsl_msg);
	if (rc) {
		GSL_ERR("gsl msg alloc failed for close %d", rc);
		goto exit;
	}

	close_payload = (int8_t *)gsl_msg.payload;
	/* construct SUB_GRAPH_LIST PID */
	if (sgids.len) {
		param_data = (struct apm_module_param_data_t *) close_payload;
		param_size = (1 + sgids.len) * sizeof(uint32_t);
		param_data->module_instance_id = GSL_GPR_DST_PORT_APM;
		param_data->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;
		param_data->param_size = param_size;
		close_payload += sizeof(*param_data);
		*((uint32_t *)close_payload) = sgids.len;
		close_payload += sizeof(uint32_t);
		gsl_memcpy(close_payload, close_pld_size, sgids.sg_ids,
			sizeof(uint32_t) * sgids.len);
		/*
		 * advance the close_payload by sgids.len words
		 * to store the connection blob (if any)
		 */
		close_payload += (sgids.len * sizeof(uint32_t));
		close_payload += padded_bytes;
	}
	/* construct Data/Control link PID by reading it from ACDB */
	if (spf_sg_conn_blob.size) {
		spf_sg_conn_blob.buf = close_payload;
		rc = gsl_acdb_get_subgraph_connections(sg_conn, num_sg_conn,
			&spf_sg_conn_blob);
		if (rc) {
			GSL_ERR("Failed to get subgraph connection blob for close %d", rc);
			/* Subtract sg_conn_blob size from close_pld_size */
			close_pld_size -= spf_sg_conn_blob.size;
		}
	}

	/* skip sending message to spf if SSR happened */
	if (gsl_graph_get_state(graph) != GRAPH_ERROR) {
		cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, gsl_msg.gpr_packet);

		cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
		cmd_header->payload_address_msw =
			(uint32_t)(gsl_msg.shmem.spf_addr >> 32);
		cmd_header->payload_size = close_pld_size;
		cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;

		GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
			sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header), gsl_msg.payload,
			close_pld_size);

		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
			&graph->graph_signal[GRAPH_CTRL_GRP3_CMD_SIG]);
		if (rc)
			GSL_ERR("Graph close failed:%d", rc);
	}

	gsl_msg_free(&gsl_msg);

exit:
	return rc;
}

static int32_t gsl_graph_remove_sgs_w_props(struct gsl_graph_gkv_node *gkv_node,
	struct gsl_cmd_properties *props)
{
	uint32_t i = 0, j = 0, k, num_removed_sgids = 0;
	uint32_t *removed_sgids = 0;
	struct gsl_subgraph **sg_list = gkv_node->sg_array;
	AcdbSubgraph *sg_conn_entry = gkv_node->sg_conn_data.subgraphs;
	AcdbSubgraph *next_sg_conn_entry = NULL;
	size_t entry_size = 0;
	size_t size_to_copy = 0;
	size_t remaining_bytes = gkv_node->sg_conn_data.size;
	size_t updated_total_sg_conn_size = gkv_node->sg_conn_data.size;
	int32_t rc = AR_EOK;
	uint8_t *mem_tmp = NULL;

	if (!props) {
		rc = AR_EBADPARAM;
		return rc;
	}

	if (gkv_node->num_of_subgraphs == 0)
		return AR_EOK;

	mem_tmp = gsl_mem_zalloc(gkv_node->sg_conn_data.size);
	if (!mem_tmp) {
		rc = AR_ENOMEMORY;
		goto exit;
	}

	removed_sgids =
		gsl_mem_zalloc(gkv_node->num_of_subgraphs * sizeof(uint32_t));
	if (!removed_sgids) {
		rc = AR_ENOMEMORY;
		goto cleanup;
	}

	/* next, remove all matching SGs and conns from those SGs*/
	while (i < gkv_node->num_of_subgraphs) {
		/*
		 * find size of current entry in sg_conn data and start of next entry
		 */
		entry_size = sizeof(AcdbSubgraph) +
			sg_conn_entry->num_dst_sgids * sizeof(uint32_t);
		next_sg_conn_entry = (AcdbSubgraph *)((uint8_t *)sg_conn_entry +
			entry_size);
		remaining_bytes -= entry_size;

		/* if match, remove sg from sg_list and global pool */
		if (is_matching_sg_property(gkv_node->sg_array[i], props)) {
			/* store SGID for removing conns later */
			removed_sgids[num_removed_sgids] = gkv_node->sg_array[i]->sg_id;
			++num_removed_sgids;

			gsl_sg_pool_remove(gkv_node->sg_array[i], FALSE);

			/*
			 * Remove the subgraph from this GKV
			 */
			for (k = i; k < gkv_node->num_of_subgraphs - 1; ++k) {
				sg_list[k] = sg_list[k+1];
				/* right shift the bit corresopinging to sg k+1 by 1 */
				gkv_node->sg_start_mask |=
					(gkv_node->sg_start_mask & (1 << (k + 1))) >> 1;
				gkv_node->sg_stop_mask |=
					(gkv_node->sg_stop_mask & (1 << (k + 1))) >> 1;
			}
			clear_bit(gkv_node->sg_start_mask, k);
			clear_bit(gkv_node->sg_stop_mask, k);
			--gkv_node->num_of_subgraphs;

			/*
			 * remove entry for sg from sg conn info blob, note assumption is
			 * that subgraph entries in conn blob are in same order as sg_array
			 */
			gsl_memcpy(mem_tmp, remaining_bytes, next_sg_conn_entry,
				remaining_bytes);
			gsl_memcpy(sg_conn_entry, remaining_bytes, mem_tmp,
				remaining_bytes);
			updated_total_sg_conn_size -= entry_size;
		} else {
			/* move to next entry */
			sg_conn_entry = next_sg_conn_entry;
			++i;
		}
	}

	i = 0;
	remaining_bytes = updated_total_sg_conn_size;
	sg_conn_entry = gkv_node->sg_conn_data.subgraphs;

	/* loop through remaining SG conns and strip conns to removed SGIDs */
	while (i < gkv_node->num_of_subgraphs) {
		/*
		 * find size of current entry in sg_conn data. It may change so find
		 * next entry later
		 */
		entry_size = sizeof(AcdbSubgraph) +
			sg_conn_entry->num_dst_sgids * sizeof(uint32_t);
		remaining_bytes -= entry_size;

		/* for each removed SGID, see if we find a match in the list */
		for (k = 0; k < num_removed_sgids; ++k) {
			j = 0;
			while (j < sg_conn_entry->num_dst_sgids) {
				if (sg_conn_entry->dst_sg_ids[j] == removed_sgids[k]) {
					/*
					 * found  match: this connection needs to be removed
					 * copy the rest of array back 1 uint32_t
					 */
					size_to_copy = remaining_bytes +
						(sg_conn_entry->num_dst_sgids - j - 1)
						* sizeof(uint32_t);
					gsl_memcpy(mem_tmp, size_to_copy,
						sg_conn_entry->dst_sg_ids + j + 1, size_to_copy);
					gsl_memcpy(sg_conn_entry->dst_sg_ids + j, size_to_copy,
						mem_tmp, size_to_copy);
					--sg_conn_entry->num_dst_sgids;
					entry_size -= sizeof(uint32_t);
					updated_total_sg_conn_size -= sizeof(uint32_t);
				} else {
					/* only advance when we didn't overwrite */
					++j;
				}
			}
		}

		/* find start of next entry	*/
		next_sg_conn_entry = (AcdbSubgraph *)((uint8_t *)sg_conn_entry +
			entry_size);

		sg_conn_entry = next_sg_conn_entry;
		++i;
	}

	gkv_node->sg_conn_data.size = updated_total_sg_conn_size;
	gkv_node->sg_conn_data.num_sgs = gkv_node->num_of_subgraphs;

	gsl_mem_free(removed_sgids);
cleanup:
	gsl_mem_free(mem_tmp);
exit:
	return rc;
}

/** Graph close for single GKV. Called with open_close_mutex lock acquired */
static int32_t gsl_graph_close_single_gkv(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node, uint32_t num_force_close_sgs,
	uint32_t *force_close_sgs,
	struct gsl_graph_sg_conn_data *force_close_sg_conn,
	struct gsl_cmd_properties *props, bool_t preserve_gkv_node)
{
	int32_t rc = AR_EOK;
	struct gsl_subgraph *sg;
	AcdbSubgraph *pruned_sg_conn, *sg_conn, *p;
	uint8_t *pruned_sg_info = NULL;
	uint32_t i, j, num_sg_conn = 0;
	size_t pruned_sg_info_sz;
	struct gsl_sgid_list pruned_sg_ids = {0, NULL};
	struct gsl_sgobj_list sg_obj_list;
	uint32_t total_num_sgs_to_close = 0;
	struct gsl_glbl_persist_cal *tmp_gpcal;
	gpr_packet_t *send_pkt = NULL;
	struct apm_cmd_header_t *cmd_header;
	uint64_t paddr_w_offset = 0;
	/* holds the number of pruned sgs plus number of force close sgs */

	/*
	 * Allocate max size required to store pruned sg_id list and sg connection
	 * info. The allocation size takes into account the force close sg list
	 * as well as the force close sg connection info
	 */
	//TODO remove all force_close references
	pruned_sg_info_sz = ((size_t)gkv_node->num_of_subgraphs +
		num_force_close_sgs) * sizeof(uint32_t) + gkv_node->sg_conn_data.size;
	if (force_close_sg_conn)
		pruned_sg_info_sz += force_close_sg_conn->size;

	pruned_sg_info = gsl_mem_zalloc(pruned_sg_info_sz);
	if (!pruned_sg_info)
		return AR_ENOMEMORY;

	/*
	 * Copy the sgs in force close list to the head of pruned_sg_info, these
	 * sgs will always be closed
	 */
	if (force_close_sgs)
		gsl_memcpy(pruned_sg_info, pruned_sg_info_sz, force_close_sgs,
			sizeof(uint32_t) * num_force_close_sgs);
	/* below we offset by num_force_close_sgs */
	pruned_sg_ids.sg_ids = (uint32_t *)(pruned_sg_info + (sizeof(uint32_t) *
		num_force_close_sgs));
	pruned_sg_ids.len = 0;
	(void)gsl_sg_pool_prune_sg_list(gkv_node->sg_array,
		gkv_node->num_of_subgraphs, props, &pruned_sg_ids, NULL);
	total_num_sgs_to_close = pruned_sg_ids.len + num_force_close_sgs;

	pruned_sg_conn = (AcdbSubgraph *)((int8_t *)pruned_sg_ids.sg_ids +
		sizeof(uint32_t) * gkv_node->num_of_subgraphs);

	/*
	 * Copy the force close sg connection entries to head of
	 * pruned_sg_conn, these sg connections will always be closed
	 */
	p = pruned_sg_conn;
	if (force_close_sg_conn) {
		gsl_memcpy(p, force_close_sg_conn->size,
			force_close_sg_conn->subgraphs,	force_close_sg_conn->size);
		p = (AcdbSubgraph *)((uint8_t *)p + force_close_sg_conn->size);
		num_sg_conn = force_close_sg_conn->num_sgs;
	}

	/*
	 * Now remove the children of each subgraph that is to be closed and
	 * update pruned_sg_conn as needed
	 */
	i = 0;
	sg_conn = gkv_node->sg_conn_data.subgraphs;
	while (i < gkv_node->num_of_subgraphs) {
		rc = gsl_subgraph_remove_children(gkv_node->sg_array[i], sg_conn,
			props, p);
		if (p->num_dst_sgids) {
			p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids +
				p->num_dst_sgids);
			++num_sg_conn;
		}
		++i;
		sg_conn = (AcdbSubgraph *)((uint32_t *)sg_conn->dst_sg_ids +
			sg_conn->num_dst_sgids);
	}

	if (total_num_sgs_to_close == 0 && num_sg_conn == 0) {
		/* nothing to close on spf */
		rc = AR_EOK;
		goto free_pruned_sg_info;
	}

	/*
	 * Now we know everything that needs to be closed, send close command to
	 * SPF
	 */
	pruned_sg_ids.sg_ids = (uint32_t *)pruned_sg_info;
	pruned_sg_ids.len = total_num_sgs_to_close;

	/* deregister persistent calibration */
	for (i = 0; i < pruned_sg_ids.len; ++i) {
		sg_obj_list.len = gkv_node->num_of_subgraphs;
		sg_obj_list.sg_objs = gkv_node->sg_array;
		sg = gsl_graph_get_sg_ptr(&sg_obj_list, pruned_sg_ids.sg_ids[i]);
		if (!sg){
			GSL_ERR("Failed to get sg_ptr for index %d", i);
			continue;
		}
		for (int procid = 0; procid < sg->num_proc_ids; procid++) {
			if ( sg->persist_cal_data_per_proc[procid].persist_cal_data.handle) {
				rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
					graph->src_port, APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
					0, graph->proc_id, &send_pkt);
				if (rc) {
					GSL_ERR("Failed to allocate GPR packet %d", rc);
					continue;
				}
				/*
				* below offset used to skip acdb header before sending data to
				* spf
				*/
					paddr_w_offset = sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_addr +
					sizeof(AcdbSgIdPersistData);
				cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
					cmd_header->mem_map_handle = sg->persist_cal_data_per_proc[procid].persist_cal_data.spf_mmap_handle;
				cmd_header->payload_address_lsw = (uint32_t)paddr_w_offset;
				cmd_header->payload_address_msw = (uint32_t)(paddr_w_offset >> 32);
					cmd_header->payload_size = sg->persist_cal_data_per_proc[procid].persist_cal_data_size -
					sizeof(AcdbSgIdPersistData);

				GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
					sizeof(*send_pkt) + sizeof(*cmd_header),
						sg->persist_cal_data_per_proc[procid].persist_cal_data.v_addr, cmd_header->payload_size);

				rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
					&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
				if (rc) {
					GSL_ERR("Graph deregister cfg cmd 0x%x failure:%d",
						APM_CMD_DEREGISTER_CFG, rc);
				}
			}
		}
		if (sg && sg->user_persist_cfg_data.handle) {
			rc = gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_CFG,
				graph->src_port, APM_MODULE_INSTANCE_ID, sizeof(*cmd_header),
				0, graph->proc_id, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				continue;
			}
			/*
			 * below offset used to skip acdb header before sending data to
			 * spf
			 */
			paddr_w_offset = sg->cma_persist_cfg_data.spf_addr
				+ sizeof(AcdbSgIdPersistData);
			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle
				= sg->cma_persist_cfg_data.spf_mmap_handle;
			cmd_header->payload_address_lsw = (uint32_t)paddr_w_offset;
			cmd_header->payload_address_msw = (uint32_t)(paddr_w_offset >> 32);
			cmd_header->payload_size = sg->cma_cal_data_size -
				sizeof(AcdbSgIdPersistData);

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header),
				sg->cma_persist_cfg_data.v_addr, cmd_header->payload_size);

			send_pkt->client_data |= GSL_GPR_CMA_FLAG_BIT;

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc) {
				GSL_ERR("Graph deregister cfg cmd 0x%x failure:%d",
					APM_CMD_DEREGISTER_CFG, rc);
			}
		}
	}

	rc = gsl_graph_close_sgids_and_connections(graph, pruned_sg_ids,
		pruned_sg_conn,	num_sg_conn);

	/** Free persist cal shared memory if exists */
	for (i = 0; i < pruned_sg_ids.len; ++i) {
		sg_obj_list.len = gkv_node->num_of_subgraphs;
		sg_obj_list.sg_objs = gkv_node->sg_array;
		sg = gsl_graph_get_sg_ptr(&sg_obj_list, pruned_sg_ids.sg_ids[i]);
		if (sg) {
			for (int i = 0; i < sg->num_proc_ids; i++) {
				if (sg->persist_cal_data_per_proc[i].persist_cal_data.handle) {
					gsl_shmem_free(&sg->persist_cal_data_per_proc[i].persist_cal_data);
					sg->persist_cal_data_per_proc[i].persist_cal_data.v_addr = NULL;
					sg->persist_cal_data_per_proc[i].persist_cal_data.handle = NULL;
					sg->persist_cal_data_per_proc[i].persist_cal_data_size = 0;
				}
			}
		}
		if (sg && sg->user_persist_cfg_data.handle) {
			gsl_shmem_free(&sg->user_persist_cfg_data);
			sg->user_persist_cfg_data.v_addr = NULL;
			sg->user_persist_cfg_data.handle = NULL;
			sg->user_persist_cfg_data_size = 0;
		}
		if (sg && sg->cma_persist_cfg_data.handle) {
			GSL_VERBOSE("freeing cma data for sg 0x%x", sg->sg_id);

			/* Free handles the hyp_assign for ML memory */
			gsl_shmem_free(&sg->cma_persist_cfg_data);
			sg->cma_persist_cfg_data.v_addr = NULL;
			sg->cma_persist_cfg_data.handle = NULL;
			sg->cma_cal_data_size = 0;
		}
	}

	/*
	 * skip freeing global persist cal if props are provided since gkv node
	 * itself wont be freed in this case. the global persist will be freed once
	 * client closes the entire gkv node
	 */
	if (props)
		goto free_pruned_sg_info;

	/* Close any opened global persist cals */
	for (i = 0; i < gkv_node->num_of_gp_cals; ++i) {

		tmp_gpcal = gkv_node->glbl_persist_cal_list[i].gpcal;

		for (j = 0; j < gkv_node->glbl_persist_cal_list[i].num_iids; ++j) {
			if (gsl_allocate_gpr_packet(APM_CMD_DEREGISTER_SHARED_CFG,
				graph->src_port, gkv_node->glbl_persist_cal_list[i].iids[j],
				sizeof(*cmd_header), 0, graph->proc_id, &send_pkt) != AR_EOK) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				continue;
			}

			cmd_header = GPR_PKT_GET_PAYLOAD(apm_cmd_header_t, send_pkt);
			cmd_header->mem_map_handle = tmp_gpcal->cal_data.spf_mmap_handle;
			cmd_header->payload_address_lsw =
				(uint32_t)tmp_gpcal->cal_data.spf_addr;
			cmd_header->payload_address_msw =
				(uint32_t)(tmp_gpcal->cal_data.spf_addr >> 32);

			GSL_LOG_PKT("send_pkt", graph->src_port, send_pkt,
				sizeof(*send_pkt) + sizeof(*cmd_header), NULL, 0);

			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt,
				&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
			if (rc) {
				GSL_ERR("Deregister shared cfg for iid %d failed:%d",
					gkv_node->glbl_persist_cal_list[i].iids[j], rc);
				continue;
			}
		}
		gsl_global_persist_cal_pool_remove(tmp_gpcal);
	}
	if (gkv_node->glbl_persist_cal_list) {
		gsl_mem_free(gkv_node->glbl_persist_cal_list);
		gkv_node->glbl_persist_cal_list = NULL;
		gkv_node->num_of_gp_cals = 0;
	}

	rc = gsl_mdf_utils_deregister_dynamic_pd(graph->ss_mask, graph->proc_id);
	if (rc)
		GSL_ERR("dynamic pd de-init failed, status %d", rc);

free_pruned_sg_info:
	rc = check_and_deregister_dynamic_pd(graph, &pruned_sg_ids);

	if (props) {
		rc = gsl_graph_remove_sgs_w_props(gkv_node, props);
	} else {
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
			gsl_sg_pool_remove(gkv_node->sg_array[i], FALSE);

		if (!preserve_gkv_node) {
			gsl_mem_free(gkv_node->sg_array);
			gkv_node->sg_array = NULL;
			gsl_mem_free(gkv_node->sg_conn_data.subgraphs);
			gkv_node->sg_conn_data.subgraphs = NULL;

			gsl_mem_free(gkv_node->gkv.kvp);
			gkv_node->gkv.kvp = NULL;
			gsl_mem_free(gkv_node->ckv.kvp);
			gkv_node->ckv.kvp = NULL;
		}
	}
	gsl_mem_free(pruned_sg_info);

	return rc;
}

/*
 * This function adds SG ids and connections to the pool. It also updates the
 * member variables of gkv_node structure:- num_of_subgraphs, sg_array and
 * sg_connections.
 * Output parameters: pruned list of SG ids and sg_connections
 */
static int32_t gsl_graph_add_and_prune_sgs_and_connections(
	struct gsl_graph_gkv_node *gkv_node, struct gsl_sgid_list sg_list,
	AcdbSubgraph *sg_conn_info, size_t sz_sg_conn,
	struct gsl_sgid_list *pruned_sg_list,
	struct gsl_graph_sg_conn_data *pruned_sg_connections,
	struct gsl_sgid_list *existing_sgid_list,
	struct gsl_graph_sg_conn_data *existing_sg_connections)
{
	int32_t rc = AR_EOK;
	uint32_t i, num_sg_conn = 0, num_existing_conn = 0;
	AcdbSubgraph *sg_conn = NULL, *pruned_sg_conn = NULL, *p,
		*existing_sg_conn = NULL, *q = NULL;

	/** Init OUT parameters */
	pruned_sg_list->len = 0;
	pruned_sg_list->sg_ids = NULL;
	pruned_sg_connections->subgraphs = NULL;
	pruned_sg_connections->num_sgs = 0;

	if (existing_sgid_list) {
		existing_sgid_list->len = 0;
		existing_sgid_list->sg_ids = NULL;
	}
	if (existing_sg_connections) {
		existing_sg_connections->subgraphs = NULL;
		existing_sg_connections->num_sgs = 0;
	}

	if (sg_list.len == 0 && sz_sg_conn == 0)
		return AR_EOK; /* nothing to be added */

	gkv_node->num_of_subgraphs = sg_list.len;
	gkv_node->sg_conn_data.num_sgs = sg_list.len;
	gkv_node->sg_conn_data.size = sz_sg_conn;
	/* below pointer is freed as part of graph close */
	gkv_node->sg_conn_data.subgraphs = sg_conn_info;

	/* Add graph's sub-graphs to sub-graph pool */
	gkv_node->sg_array = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
		sizeof(struct gsl_subgraph *));
	if (!gkv_node->sg_array) {
		rc = AR_ENOMEMORY;
		goto exit;
	}

	for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
		gkv_node->sg_array[i] = gsl_sg_pool_add(sg_list.sg_ids[i], FALSE);
	/*
	 * allocate memory to store pruned sg list
	 */
	pruned_sg_list->len = 0;
	pruned_sg_list->sg_ids = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
		sizeof(uint32_t));
	if (!pruned_sg_list->sg_ids) {
		rc = AR_ENOMEMORY;
		goto free_sg_array;
	}
	if (existing_sgid_list) {
		existing_sgid_list->sg_ids = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
			sizeof(uint32_t));
		if (!existing_sgid_list->sg_ids) {
			rc = AR_ENOMEMORY;
			goto free_pruned_list;
		}
	}

	rc = gsl_sg_pool_prune_sg_list(gkv_node->sg_array,
		gkv_node->num_of_subgraphs, NULL, pruned_sg_list,
		existing_sgid_list);
	if (AR_FAILED(rc)) {
		GSL_ERR("subgraph prune for open failed: %d", rc);
		goto remove_from_pool;
	}

	/* Add and prune children for each subgraph-id in the graph */
	pruned_sg_conn = gsl_mem_zalloc(sz_sg_conn);
	if (!pruned_sg_conn) {
		rc = AR_ENOMEMORY;
		goto remove_from_pool;
	}

	if (existing_sg_connections) {
		existing_sg_conn = gsl_mem_zalloc(sz_sg_conn);
		if (!existing_sg_conn) {
			rc = AR_ENOMEMORY;
			goto remove_from_pool;
		}
	}

	i = 0;
	sg_conn = sg_conn_info;
	p = pruned_sg_conn;
	if (existing_sg_conn)
		q = existing_sg_conn;

	while (i < gkv_node->num_of_subgraphs) {
		rc = gsl_subgraph_add_children(gkv_node->sg_array[i], sg_conn, p, q);
		if (p->num_dst_sgids) {
			p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids +
				p->num_dst_sgids); /* move to next pruned_sg_conn row */
			++num_sg_conn;
		}
		/* for existing, store all conn objects even empty from existing SGs.
		 * existing sg list is in same order as sg list.
		 */
		if (q && existing_sgid_list
			&& existing_sgid_list->sg_ids[num_existing_conn]
			== gkv_node->sg_array[i]->sg_id) {
			q = (AcdbSubgraph *)((uint32_t *)q->dst_sg_ids +
				q->num_dst_sgids); /* move to next existing_sg_conn row */
			++num_existing_conn;
		}

		++i;
		sg_conn = (AcdbSubgraph *)((uint32_t *)sg_conn->dst_sg_ids +
			sg_conn->num_dst_sgids); /* move to next sg_conn row */
	}

	/* now that all the children are added to pool, update their references */
	gsl_sg_pool_update_child_refs();

	if (num_sg_conn) {
		pruned_sg_connections->subgraphs = pruned_sg_conn;
		pruned_sg_connections->num_sgs = num_sg_conn;
		pruned_sg_connections->size =
			(uint8_t *)p - (uint8_t *)pruned_sg_conn;
	} else {
		gsl_mem_free(pruned_sg_conn);
		pruned_sg_conn = NULL;
		pruned_sg_connections->num_sgs = 0;
		pruned_sg_connections->size = 0;
		pruned_sg_connections->subgraphs = NULL;
	}

	if (num_existing_conn) {
		existing_sg_connections->subgraphs = existing_sg_conn;
		existing_sg_connections->num_sgs = num_sg_conn;
		existing_sg_connections->size =
			(uint8_t *)q - (uint8_t *)existing_sg_conn;
	} else if (existing_sg_connections) {
		gsl_mem_free(existing_sg_conn);
		existing_sg_conn = NULL;
		existing_sg_connections->num_sgs = 0;
		existing_sg_connections->size = 0;
		existing_sg_connections->subgraphs = NULL;
	}

	rc = gsl_mdf_utils_query_graph_ss_mask(sg_list.sg_ids,
		gkv_node->num_of_subgraphs, &gkv_node->spf_ss_mask);
	if (rc != AR_EOK) {
		GSL_ERR("failed to get spf_ss_mask %d", rc);
		goto remove_sg_children;
	}

	return rc;

remove_sg_children:
	p = sg_conn_info;
	i = 0;
	while (i < gkv_node->num_of_subgraphs) {
		gsl_subgraph_remove_children(gkv_node->sg_array[i++], p, NULL, NULL);
		p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids + p->num_dst_sgids);
	}

	if (existing_sg_conn) {
		gsl_mem_free(existing_sg_conn);
		existing_sg_connections->num_sgs = 0;
		existing_sg_connections->size = 0;
		existing_sg_connections->subgraphs = NULL;
	}
remove_from_pool:
	if (pruned_sg_conn)
		gsl_mem_free(pruned_sg_conn);
	pruned_sg_connections->num_sgs = 0;
	pruned_sg_connections->size = 0;
	pruned_sg_connections->subgraphs = NULL;

	for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
		gsl_sg_pool_remove(gkv_node->sg_array[i], FALSE);
	if (existing_sgid_list) {
		gsl_mem_free(existing_sgid_list->sg_ids);
		existing_sgid_list->len = 0;
		existing_sgid_list->sg_ids = NULL;
	}
free_pruned_list:
	gsl_mem_free(pruned_sg_list->sg_ids);
	pruned_sg_list->len = 0;
	pruned_sg_list->sg_ids = NULL;

free_sg_array:
	gsl_mem_free(gkv_node->sg_array);

exit:
	return rc;
}

/**
 * Opens SG IDS and Connections on Spf. Subgraph_Data and
 * SG_Connections_Data are retrieved from the acdb for the given
 * sgids and sg_connections and sent to Spf. Also applies calibration
 * using ckv for the SGIDS that are opened on spf.
 */
static int32_t gsl_graph_open_sgids_and_connections(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node,
	struct gsl_sgid_list *sgids, struct gsl_graph_sg_conn_data *sg_conn,
	struct gsl_key_vector *gkv, struct gsl_key_vector *ckv)
{
	uint32_t graph_open_size = 0, i;
	struct gsl_blob spf_blob, spf_sg_conn_blob;
	struct apm_cmd_header_t *open_cmd;
	AcdbDriverPropertyData drv_blob;
	int32_t rc = AR_EOK;
	struct gsl_sgobj_list sg_obj_list;
	gsl_msg_t gsl_msg;
	bool_t is_shmem_supported = TRUE;
	bool_t dyn_pd_registered = FALSE;
	uint32_t dyn_ss_mask = 0;

	/* check if there are any sub-graphs or edges to open */
	if ((sgids->len == 0) && (sg_conn->num_sgs == 0))
		return AR_EOK; /**< nothing to open on SPF */

	gsl_memset(&spf_blob, 0, sizeof(struct gsl_blob));
	gsl_memset(&drv_blob, 0, sizeof(AcdbDriverPropertyData));
	gsl_memset(&spf_sg_conn_blob, 0, sizeof(struct gsl_blob));

	/** Get subgraph data size for spf and drv blobs */
	GSL_DBG("num_sgid= %d", sgids->len);
	GSL_DBG("sg list:");
	for (i = 0; i < sgids->len; ++i)
		GSL_DBG("%x", sgids->sg_ids[i]);
	if (sgids->len) {
		rc = gsl_acdb_get_subgraph_data(sgids, gkv, &spf_blob, &drv_blob);
		if (rc) {
			GSL_ERR("get subgraph data for size failed: %d", rc);
			goto exit;
		}

		/*
		 * Get graph proc id. Need driver blob only.
		 * Hence setting spf blob to NULL
		 */
		spf_blob.buf = NULL;
		spf_blob.size = 0;
		/* Alloc memory for SG driver property data */
		drv_blob.sub_graph_prop_data = gsl_mem_zalloc(drv_blob.size);
		if (!drv_blob.sub_graph_prop_data) {
			rc = AR_ENOMEMORY;
			goto exit;
		}

		/*
		 * spf_blob buf is set to NULL & size is set to 0, acdb returns
		 * driver blob, for spf blob we get back size only.
		 */
		rc = gsl_acdb_get_subgraph_data(sgids, gkv, &spf_blob, &drv_blob);
		if (rc) {
			GSL_ERR("get subgraph data failed %d", rc);
			goto free_sg_prop_data;
		}

		/* Parse driver prop data to get routing id */
		sg_obj_list.sg_objs = gkv_node->sg_array;
		sg_obj_list.len = gkv_node->num_of_subgraphs;

		rc = gsl_acdb_parse_sg_drv_prop_data(graph, &sg_obj_list, &drv_blob);
		if (rc) {
			GSL_ERR("gsl_acdb_parse_sg_drv_prop_data failed with status %d",
				rc);
			goto free_sg_prop_data;
		}

		if ((gsl_spf_ss_state_get(graph->proc_id) & gkv_node->spf_ss_mask)
			!= gkv_node->spf_ss_mask) {

			rc = AR_ENOTREADY;
			goto free_sg_prop_data;
		}
		/*
		 * Allocate and map MDF client loaned memory in-case any of the new sgs
		 * requires any procs other than ADSP
		 */
		rc = __gpr_cmd_is_shared_mem_supported(graph->proc_id,
			&is_shmem_supported);
		if (rc) {
			GSL_ERR("GPR is shmem supported failed %d", rc)
			goto free_sg_prop_data;
		}
		if (is_shmem_supported) {
			rc = check_and_register_dynamic_pd(graph, sgids,
					gkv_node->spf_ss_mask, &dyn_ss_mask);
			if (rc) {
				GSL_ERR("dynamic pd create failed, status %d", rc);
				goto free_sg_prop_data;
			}
			dyn_pd_registered = TRUE;
			/*
			 * If there was a dynamic PD, the allocation would have happened
			 * already as part of check_and_register_dynamic_pd.
			 * Remove dynamic PD from ss mask.
			 */
			gsl_mdf_utils_shmem_alloc(gkv_node->spf_ss_mask & ~dyn_ss_mask,
				graph->proc_id);
		}
	}

	/* Get subgraph connection data size for spf */
	if (sg_conn->num_sgs) {
		gsl_print_sg_conn_info((uint32_t *)sg_conn->subgraphs,
			sg_conn->num_sgs);

		rc = gsl_acdb_get_subgraph_connections(sg_conn->subgraphs,
			sg_conn->num_sgs, &spf_sg_conn_blob);
		if (rc == AR_ENOTEXIST) {
			GSL_ERR("got 0 size for subgraph conn data, rc %d", rc);
			rc = AR_EOK;
		} else if (rc) {
			GSL_ERR("get subgraph conn data for size failed: %d, size:%d", rc,
				spf_sg_conn_blob.size);
			goto free_sg_prop_data;
		}
	}

	graph_open_size = spf_blob.size + spf_sg_conn_blob.size;
	if (graph_open_size == 0) {
		GSL_ERR("spf blob size for open is zero");
		rc = AR_EFAILED;
		goto free_sg_prop_data;
	}

	/*
	 * Allocate shared memory to hold spf blob (sg data and connections)
	 * for OPEN command and map on SPF
	 */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_OPEN, graph->src_port,
		GSL_GPR_DST_PORT_APM, sizeof(*open_cmd), 0, graph->proc_id,
		graph_open_size, false, &gsl_msg);
	if (rc) {
		GSL_ERR("GSL MSG alloc failed size: %d rc:%d", graph_open_size, rc);
		goto free_sg_prop_data;
	}

	if (spf_blob.size) {
		spf_blob.buf = gsl_msg.payload;
		/* Get both spf data blob and subgraph driver property blob */
		rc = gsl_acdb_get_subgraph_data(sgids, gkv, &spf_blob, &drv_blob);
		if (rc) {
			GSL_ERR("get subgraph data failed %d", rc);
			goto free_gsl_msg;
		}
	}

	if (spf_sg_conn_blob.size) {
		spf_sg_conn_blob.buf = (int8_t *)gsl_msg.payload +
			spf_blob.size;
		rc = gsl_acdb_get_subgraph_connections(sg_conn->subgraphs,
			sg_conn->num_sgs, &spf_sg_conn_blob);
		if (rc) {
			GSL_ERR("get subgraph conn data failed: %d", rc);
			goto free_gsl_msg;
		}
	}

	open_cmd = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, gsl_msg.gpr_packet);
	open_cmd->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	open_cmd->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	open_cmd->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	open_cmd->payload_size = graph_open_size;

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*open_cmd), gsl_msg.payload,
		graph_open_size);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
	if (rc) {
		GSL_ERR("Graph open failed:%d", rc);
		goto free_gsl_msg;
	}

	sg_obj_list.len = gkv_node->num_of_subgraphs;
	sg_obj_list.sg_objs = gkv_node->sg_array;

	/* Apply cal */
	if (sgids->len) {
		GSL_MUTEX_LOCK(graph->get_set_cfg_lock);
		rc = gsl_graph_set_sg_cal(graph, sgids, gkv_node, ckv, gkv, false);
		GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
		if (rc == AR_EUNSUPPORTED || rc == AR_ENOTEXIST) {
			/*
			 * we let open succeed since ENOTEXIST is benign and EUNSUPPORTED is
			 * widespread. We should get everyone to fix their EUNSUPPORTEDs in
			 * the future by opening CRs.
			 */
			GSL_DBG("graph set cal failed:%d", rc);
			rc = AR_EOK;
		} else if (rc != AR_EOK) {
			/*
			 * for other serious cal failures, we need to send close on SPF
			 * Caller function will handle the internal clean-up
			 * This is to ensure that GSL and SPF and client all have the same
			 * state of a graph. We must fail on set cal fail, since some cals
			 * e.g. speaker protection are  essential
			 *
			 * we ignore RC of close fail -- cleanup function & preserve
			 * original error
			 */
			GSL_ERR("set sg cal failed, closing all opened SGs: %d", rc);
			gsl_graph_close_sgids_and_connections(graph, *sgids,
				sg_conn->subgraphs, sg_conn->num_sgs);
		}
	}

free_gsl_msg:
	gsl_msg_free(&gsl_msg);

free_sg_prop_data:
	gsl_mem_free(drv_blob.sub_graph_prop_data);
	if (rc != AR_EOK && dyn_pd_registered)
		gsl_mdf_utils_deregister_dynamic_pd(graph->ss_mask, graph->proc_id);

exit:
	return rc;
}

/* Graph open for single GKV. Called with open_close_mutex lock acquired */
static int32_t gsl_graph_open_single_gkv(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv, const struct gsl_key_vector *ckv,
	struct gsl_graph_gkv_node *gkv_node)
{
	int32_t rc;
	struct gsl_sgid_list pruned_sgids = {0, NULL};
	struct gsl_sgid_list sgids = {0, NULL};
	uint32_t i = 0;
	AcdbGetGraphRsp sg_conn_info;
	struct gsl_graph_sg_conn_data pruned_sg_conn = {0,};
	AcdbSubgraph *p;

	/* Get graph data from ACDB */
	rc = gsl_acdb_get_graph(gkv, &sgids.sg_ids, &sg_conn_info);
	if (rc) {
		GSL_ERR("acdb get graph failed %d", rc);
		goto cleanup;
	}

	/**
	 * Add SGIDs and connections to the pool. Get pruned sgid list
	 * sg connections after adding them to the pool.
	 */
	sgids.len = sg_conn_info.num_subgraphs;
	pruned_sgids.len = 0;
	pruned_sgids.sg_ids = NULL;
	rc = gsl_graph_add_and_prune_sgs_and_connections(gkv_node, sgids,
		sg_conn_info.subgraphs, sg_conn_info.size, &pruned_sgids,
		&pruned_sg_conn, NULL, NULL);
	if (rc)
		goto cleanup;

	/**
	 * update the graph level ss_mask to reflect this gkv
	 */
	 graph->ss_mask |= gkv_node->spf_ss_mask;

	/** Now open the pruned sgid list and connections */
	rc = gsl_graph_open_sgids_and_connections(graph, gkv_node, &pruned_sgids,
		&pruned_sg_conn, (struct gsl_key_vector *)gkv,
		(struct gsl_key_vector *)ckv);
	if (AR_SUCCEEDED(rc)) {
		/** Add GKV and CKV to GKV_node */
		gsl_graph_update_gkv_node(gkv_node, gkv, ckv);
		gsl_graph_add_gkv_to_list(graph, gkv_node);
	} else {
		/*
		 * in the failure case, remove the sgids and connections
		 * of the given gkv from the pool
		 */
		p = gkv_node->sg_conn_data.subgraphs;
		i = 0;
		while (i < gkv_node->num_of_subgraphs) {
			gsl_subgraph_remove_children(gkv_node->sg_array[i++], p, NULL,
				NULL);
			p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids + p->num_dst_sgids);
		}

		for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
			gsl_sg_pool_remove(gkv_node->sg_array[i], FALSE);

		gsl_mem_free(gkv_node->sg_array);
		gsl_mem_free(gkv_node->sg_conn_data.subgraphs);
	}

cleanup:
	if (pruned_sgids.sg_ids)
		gsl_mem_free(pruned_sgids.sg_ids);
	if (pruned_sg_conn.subgraphs)
		gsl_mem_free(pruned_sg_conn.subgraphs);
	if (sgids.sg_ids)
		gsl_mem_free(sgids.sg_ids);

	return rc;
}

static int32_t gsl_graph_suspend_check_and_stop_instead(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node)
{
	uint32_t *sg_id_list, *num_sg, i;
	int32_t rc = AR_EOK;
	uint32_t *stop_payload, pld_size;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg;
	gsl_msg_t gsl_msg;

	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(
		sizeof(uint32_t) * (1 + (size_t)gkv_node->num_of_subgraphs)));

	/* Allocate the maximum size that could be needed
	 * This stops us from having to memcpy into the packet, but needs larger
	 * initial packet allocation (see where we update payload size below)
	 */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_STOP, graph->src_port,
		GSL_GPR_DST_PORT_APM, pld_size, 0, graph->proc_id, 0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto exit;
	}

	stop_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
	gsl_memset(stop_payload, 0, pld_size);

	module_param = (struct apm_module_param_data_t *)
		((int8_t *)stop_payload + sizeof(*cmd_header));
	module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
	module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

	num_sg = (uint32_t *)((int8_t *)stop_payload +
		sizeof(*cmd_header) + sizeof(*module_param));

	*num_sg = 0;
	sg_id_list = num_sg + 1;
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
		sg = gkv_node->sg_array[i];
		/**
		 * send stop command for SGs
		 * which are stopped from other GKVs but in start state
		 * only in this GKV.
		 */
		if ((sg && test_bit(gkv_node->sg_start_mask, i) &&
			(sg->start_ref_cnt == 1) && (sg->stop_ref_cnt > 0))) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		}
	}
	if ((*num_sg) == 0) {
		GSL_DBG("NO SGs to stop in suspend context");
		rc = AR_EOK;
		goto free_msg;
	}

	/*
	 * update payload sizes based on actual number of subgraphs
	 * that need to be prepared
	 */
	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) * (1 + (size_t)(*num_sg))));
	cmd_header = (struct apm_cmd_header_t *)stop_payload;
	cmd_header->payload_size = pld_size - (uint32_t)sizeof(*cmd_header);
	module_param->param_size = (1 + (*num_sg)) * (uint32_t)sizeof(uint32_t);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
	if (rc)
		GSL_ERR("Graph stop failed:%d", rc);

free_msg:
	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

static int32_t gsl_graph_suspend_single_gkv(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node)
{
	uint32_t *sg_id_list, *num_sg, i;
	int32_t rc = AR_EOK;
	uint32_t *suspend_payload, pld_size;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg;
	gsl_msg_t gsl_msg;

	/* If some subgraphs are previously stopped from another GKV
	 * then send STOP instead of SUSPEND.
	 */
	rc = gsl_graph_suspend_check_and_stop_instead(graph, gkv_node);
	if (rc) {
		GSL_ERR("Failed to send stop in suspend context %d", rc);
		goto exit;
	}
	/* now continue to suspend remaining subgraphs. */

	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(
			sizeof(uint32_t) * (1 + (size_t)gkv_node->num_of_subgraphs)));

	/* Allocate the maximum size that could be needed
	 * This stops us from having to memcpy into the packet, but needs larger
	 * initial packet allocation (see where we update payload size below)
	 */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_SUSPEND, graph->src_port,
		GSL_GPR_DST_PORT_APM, pld_size,
		0, graph->proc_id, 0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto exit;
	}

	suspend_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
	gsl_memset(suspend_payload, 0, pld_size);

	module_param = (struct apm_module_param_data_t *)
			((int8_t *)suspend_payload + sizeof(*cmd_header));
	module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
	module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

	num_sg = (uint32_t *)((int8_t *)suspend_payload +
		sizeof(*cmd_header) + sizeof(*module_param));

	*num_sg = 0;
	sg_id_list = num_sg + 1;
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
		sg = gkv_node->sg_array[i];
		/*
		 * send suspend command to SGs started only by this GKV
		 * and are not stopped from any other GKV.
		 */
		if (sg && test_bit(gkv_node->sg_start_mask, i) &&
			(sg->start_ref_cnt == 1) && (sg->stop_ref_cnt == 0)) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		}
	}
	if ((*num_sg) == 0) {
		GSL_DBG("NO SGs to suspend");
		rc = AR_EOK;
		goto decrement_ref_cnt;
	}

	/*
	 * update payload sizes based on actual number of subgraphs
	 * that need to be prepared
	 */
	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) * (1 + (size_t)(*num_sg))));
	cmd_header = (struct apm_cmd_header_t *)suspend_payload;
	cmd_header->payload_size = pld_size - (uint32_t)sizeof(*cmd_header);
	module_param->param_size = (1 + (*num_sg)) * (uint32_t)sizeof(uint32_t);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
	if (rc) {
		GSL_ERR("Graph suspend failed:%d", rc);
		goto free_msg;
	}

decrement_ref_cnt:
	/* decrement start ref count for all SGs */
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
		sg = gkv_node->sg_array[i];
		if (sg && test_bit(gkv_node->sg_start_mask, i)) {
			if (sg->start_ref_cnt > 0)
				--sg->start_ref_cnt;
			clear_bit(gkv_node->sg_start_mask, i);
		}
	}

free_msg:
	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

/* optional: props */
static int32_t gsl_graph_stop_single_gkv(struct gsl_graph *graph,
	struct gsl_graph_gkv_node *gkv_node, struct gsl_cmd_properties *props)
{
	uint32_t *sg_id_list, *num_sg, i;
	int32_t rc = AR_EOK;
	uint32_t *stop_payload, pld_size;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg;
	gsl_msg_t gsl_msg;

	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) *
			((size_t)1 + gkv_node->num_of_subgraphs)));

	/* Allocate the maximum size that could be needed
	 * This stops us from having to memcpy into the packet, but needs larger
	 * initial packet allocation (see where we update payload size below)
	 */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_STOP, graph->src_port,
		GSL_GPR_DST_PORT_APM, pld_size, 0, graph->proc_id, 0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto exit;
	}

	stop_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
	gsl_memset(stop_payload, 0, pld_size);

	module_param = (struct apm_module_param_data_t *)
		((int8_t *)stop_payload + sizeof(*cmd_header));
	module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
	module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

	num_sg = (uint32_t *)((int8_t *)stop_payload +
		sizeof(*cmd_header) + sizeof(*module_param));

	*num_sg = 0;
	sg_id_list = num_sg + 1;
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
		if (gkv_node->sg_array[i]) {
			sg = gkv_node->sg_array[i];
		} else {
			GSL_ERR("gkv_node->sg_array[%d] is NULL, continuing", i);
			continue;
		}

		/*
		 * send stop command for SGs
		 * 1. if SG is started only by this GKV
		 * 2. if SG is suspended.
		 */
		if ((sg && test_bit(gkv_node->sg_start_mask, i) &&
			(sg->start_ref_cnt == 1)) &&
			(!props || is_matching_sg_property(sg, props))) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		} else if ((sg && (sg->stop_ref_cnt == 0) &&
				(sg->start_ref_cnt == 0)) &&
				(!props || is_matching_sg_property(sg, props))) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		}
	}
	if ((*num_sg) == 0) {
		GSL_DBG("NO SGs to stop");
		rc = AR_EOK;
		goto decrement_ref_cnt;
	}

	/*
	 * update payload sizes based on actual number of subgraphs
	 * that need to be prepared
	 */
	pld_size = sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) * ((size_t)1 + (*num_sg)));
	cmd_header = (struct apm_cmd_header_t *)stop_payload;
	cmd_header->payload_size = (uint32_t)(pld_size - sizeof(*cmd_header));
	module_param->param_size = (1 + (*num_sg)) * sizeof(uint32_t);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);

	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
	if (rc) {
		GSL_ERR("Graph stop failed:%d", rc);
		goto free_msg;
	}

decrement_ref_cnt:
	/* decrement start ref count and increment stop ref count for all SGs */
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
		if (gkv_node->sg_array[i]) {
			sg = gkv_node->sg_array[i];
		} else {
			GSL_ERR("gkv_node->sg_array[%d] is NULL, continuing", i);
			continue;
		}
		if ((sg && test_bit(gkv_node->sg_start_mask, i)) &&
			(!props || is_matching_sg_property(sg, props))) {
			if (sg->start_ref_cnt > 0)
				sg->start_ref_cnt--;
			clear_bit(gkv_node->sg_start_mask, i);
		}
		if ((sg && !test_bit(gkv_node->sg_stop_mask, i)) &&
		    (!props || is_matching_sg_property(sg, props))) {
			sg->stop_ref_cnt++;
			set_bit(gkv_node->sg_stop_mask, i);
		}
	}

free_msg:
	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

int32_t gsl_graph_set_config(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv, uint32_t tag,
	const struct gsl_key_vector *tkv, ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	struct gsl_sgid_list sg_id_list = {0, NULL};
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	bool_t is_found = FALSE;
	uint32_t i = 0;
	AcdbSgIdModuleTag cmd_struct;
	AcdbBlob rsp_struct;
	struct apm_cmd_header_t *cmd_header;
	gsl_msg_t gsl_msg;
	struct ar_data_log_submit_info_t info;
	struct ar_data_log_generic_pkt_info_t pkt_info;

	if (!graph || !tkv)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	if (gkv && gkv->num_kvps != 0) {
		ar_list_for_each_entry(curr, &graph->gkv_list) {
			gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
				node);
			if (is_identical_gkv(&gkv_node->gkv,
				(struct gsl_key_vector *)gkv)) {
				is_found = TRUE;
				break;
			}
		}
		if (!is_found) {
			GSL_ERR("input gkv not opened/added, cannot set config");
			rc = AR_EBADPARAM;
			goto exit;
		}

		sg_id_list.sg_ids = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
			sizeof(uint32_t));
		if (!sg_id_list.sg_ids) {
			rc = AR_ENOMEMORY;
			goto exit;
		}

		sg_id_list.len = gkv_node->num_of_subgraphs;
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
			sg_id_list.sg_ids[i] = gkv_node->sg_array[i]->sg_id;
	} else {
		rc = gsl_graph_get_sgids_and_objs(graph, &sg_id_list, NULL);
		if (rc) {
			GSL_ERR("failed to get sgid list %d", rc);
			goto exit;
		}
		if (sg_id_list.len == 0) {
			rc = AR_ENOTEXIST;
			goto exit;
		}
	}

	/* if there are no subgraphs found then goto exit */
	if (!sg_id_list.sg_ids)
		goto exit;

	cmd_struct.num_sg_ids = sg_id_list.len;
	cmd_struct.sg_ids = sg_id_list.sg_ids;
	cmd_struct.module_tag.tag_id = tag;
	cmd_struct.module_tag.tag_key_vector.num_keys = tkv->num_kvps;
	cmd_struct.module_tag.tag_key_vector.graph_key_vector =
		(AcdbKeyValuePair *)tkv->kvp;
	rsp_struct.buf = NULL;
	rsp_struct.buf_size = 0;
	rc = acdb_ioctl(ACDB_CMD_GET_MODULE_TAG_DATA, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("Get module tag data for size failed %d", rc);
		goto cleanup;
	}

	rc = gsl_msg_alloc(APM_CMD_SET_CFG, graph->src_port, GSL_GPR_DST_PORT_APM,
		sizeof(*cmd_header), 0, graph->proc_id, rsp_struct.buf_size, false,
		&gsl_msg);
	if (rc) {
		GSL_ERR("gsl msg alloc failed %d", rc);
		goto cleanup;
	}

	rsp_struct.buf = gsl_msg.payload;
	rc = acdb_ioctl(ACDB_CMD_GET_MODULE_TAG_DATA, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("Get module tag data for cal failed %d", rc);
		goto free_msg;
	}

	if (graph->rtc_conn_active) {
		/* dump config to QACT */

		pkt_info.format = AR_LOG_PKT_GENERIC_FMT_CAL_BLOB;
		pkt_info.token_id = 0;
		pkt_info.log_time_stamp = 0;

		info.buffer = (int8_t *)gsl_msg.payload;
		info.buffer_size = rsp_struct.buf_size;
		info.log_code = AR_DATA_LOG_CODE_ATS;
		info.pkt_info = &pkt_info;
		info.pkt_type = AR_DATA_LOG_PKT_TYPE_GENERIC;
		info.session_id = 0;

		GSL_DBG("set_config: caching buffer %x to QACT", info.buffer);
		ar_data_log_submit(&info);
	}

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
		gsl_msg.gpr_packet);
	cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	cmd_header->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	cmd_header->payload_size = rsp_struct.buf_size;

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header),	gsl_msg.payload,
		cmd_header->payload_size);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
	if (rc)
		GSL_ERR("Graph set config failed %d", rc);

free_msg:
	gsl_msg_free(&gsl_msg);
cleanup:
	gsl_mem_free(sg_id_list.sg_ids);
exit:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_set_cal(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv,
	const struct gsl_key_vector *ckv,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	struct gsl_sgid_list sg_id_list = {0, NULL};
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	bool_t is_found = FALSE;
	uint32_t i = 0;

	if (!graph)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);
	GSL_MUTEX_LOCK(graph->get_set_cfg_lock);

	/** find matching gkv from the gkv node list */
	if (gkv && gkv->num_kvps != 0) {
		ar_list_for_each_entry(curr, &graph->gkv_list) {
			gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
				node);
			if (is_identical_gkv(&gkv_node->gkv,
				(struct gsl_key_vector *)gkv)) {
				is_found = TRUE;
				break;
			}
		}
		if (!is_found) {
			GSL_ERR("input gkv not opened/added, cannot set calibration");
			rc = AR_EBADPARAM;
			goto exit;
		}
	} else {
		curr = ar_list_get_head(&graph->gkv_list);
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
	}

	sg_id_list.sg_ids = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
		sizeof(uint32_t));
	if (!sg_id_list.sg_ids) {
		rc = AR_ENOMEMORY;
		goto exit;
	}
	sg_id_list.len = gkv_node->num_of_subgraphs;
	for (i = 0; i < gkv_node->num_of_subgraphs; ++i)
		sg_id_list.sg_ids[i] = gkv_node->sg_array[i]->sg_id;

	rc = gsl_graph_set_sg_cal(graph, &sg_id_list, gkv_node, ckv, gkv, true);
	if (rc && rc != AR_ENOTEXIST)
		GSL_ERR("set cal failed: %d", rc);
	if (rc == AR_ENOTEXIST)
		rc = AR_EOK; /* it is possible to get if client sends same ckv */
	gsl_mem_free(sg_id_list.sg_ids);

exit:
	GSL_MUTEX_UNLOCK(graph->get_set_cfg_lock);
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_prepare(struct gsl_graph *graph,
	ar_osal_mutex_t lock)
{
	uint32_t *sg_id_list, *num_sg, i, num_subgraphs = 0;
	int32_t rc = AR_EOK;
	uint32_t *prepare_payload, pld_size;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg, **sg_array = NULL;
	struct gsl_sgobj_list sg_obj_list = {0, NULL};
	gsl_msg_t gsl_msg;

	if (!graph)
		return AR_EBADPARAM;

	/* can be called with null GKV. Nothing to do */
	if (ar_list_is_empty(&graph->gkv_list))
		return AR_EOK;

	rc = gsl_graph_get_sgids_and_objs(graph, NULL, &sg_obj_list);
	if (rc) {
		GSL_ERR("failed to get subgraph objects");
		rc = AR_EFAILED;
		goto exit;
	}
	num_subgraphs = sg_obj_list.len;
	sg_array = sg_obj_list.sg_objs;

	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) * ((size_t)1 + num_subgraphs)));

	/* Allocate enough size for worst case */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_PREPARE, graph->src_port,
		GSL_GPR_DST_PORT_APM, pld_size, 0, graph->proc_id, 0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto free_sg_array;
	}

	prepare_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
	module_param = (struct apm_module_param_data_t *)
			((int8_t *)prepare_payload + sizeof(*cmd_header));
	module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
	module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

	num_sg = (uint32_t *)((int8_t *)prepare_payload +
		sizeof(*cmd_header) + sizeof(*module_param));

	GSL_MUTEX_LOCK(lock);

	*num_sg = 0;
	sg_id_list = num_sg + 1;
	for (i = 0; i < num_subgraphs; ++i) {
		sg = sg_array[i];
		/* send prepare command only for SGs that are not in START state */
		if (sg && sg->start_ref_cnt == 0) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		}
	}

	if ((*num_sg) == 0) {
		GSL_DBG("All SGs are in started state, nothing to prepare");
		rc = AR_EOK;
		goto free_msg;
	}
	/*
	 * update payload sizes based on actual number of subgraphs
	 * that need to be prepared
	 */
	pld_size = sizeof(*cmd_header) + sizeof(*module_param) +
		GSL_ALIGN_8BYTE(sizeof(uint32_t) * ((size_t)1 + (*num_sg)));
	cmd_header = (struct apm_cmd_header_t *)prepare_payload;
	cmd_header->payload_size = (uint32_t)(pld_size - sizeof(*cmd_header));
	module_param->param_size = (uint32_t)(1 + (*num_sg)) * sizeof(uint32_t);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
	if (rc)
		GSL_ERR("Graph prepare failed:%d", rc);

free_msg:
	gsl_msg_free(&gsl_msg);
	GSL_MUTEX_UNLOCK(lock);
free_sg_array:
	gsl_mem_free(sg_array);
exit:
	return rc;
}

static int32_t gsl_graph_cache_datapath_miid(struct gsl_graph *graph,
	struct gsl_data_path_info *dp_info, uint32_t tag, uint32_t mode)
{
	int32_t rc = AR_EOK;
	struct gsl_sgid_list sg_id_list = {0, NULL};
	struct gsl_module_id_proc_info *proc_module_info;

	if ((mode & GSL_ATTRIBUTES_DATAPATH_SETUP_MASK) >>
		GSL_ATTRIBUTES_DATAPATH_SETUP_SHIFT
		== GSL_DATAPATH_SETUP_ALLOC_SHMEM_ONLY) {
		/*don't do this for this mode specifically*/
		return AR_EOK;
	}

	/* don't do this twice */
	if (tag == dp_info->cached_tag)
		return AR_EOK;

	rc = gsl_graph_get_sgids_and_objs(graph, &sg_id_list, NULL);
	if (rc) {
		GSL_ERR("failed to get sgid list %d", rc);
		return rc;
	}
	if (!sg_id_list.sg_ids) {
		rc = AR_ENOTEXIST;
		return rc;
	}

	rc = _gsl_graph_get_module_proc_tag_info(sg_id_list.sg_ids,
		sg_id_list.len, tag, &proc_module_info);
	if (rc) {
		GSL_ERR("fail to get write tag module iid %d", rc);
		goto free_sg_ids;
	}
	if (proc_module_info->num_procs != 1) {
		GSL_ERR("number of proc ids returned is %d, expected 1",
			proc_module_info->num_procs);
		rc = AR_EFAILED;
		goto free_module_info;
	}
	/*
	 * cache the module, tag, and proc id, note we only cache for a single tag, it is
	 * assumed that each graph can have at most 1 write EP and 1 read EP
	 */
	dp_info->miid =
		proc_module_info->proc_module_list->module_entry[0].module_iid;
	dp_info->cached_tag = tag;
	dp_info->master_proc_id =
		proc_module_info->proc_module_list->proc_domain_id;

free_module_info:
	gsl_mem_free(proc_module_info->proc_module_list);
	gsl_mem_free(proc_module_info);
free_sg_ids:
	gsl_mem_free(sg_id_list.sg_ids);

	return rc;
}

int32_t gsl_graph_config_data_path(struct gsl_graph *graph,
	enum gsl_data_dir dir, struct gsl_cmd_configure_read_write_params *cfg)
{
	int32_t rc = AR_EOK;
	struct gsl_data_path_info *dp_info;
	uint32_t proc_id = graph->proc_id;

	/*
	 * Have to check graph state and cached miid outside of datapath
	 * module, as state is a property of graph and caching miid needs
	 * to loop through subgraphs
	 */
	GSL_MUTEX_LOCK(graph->graph_lock);
	if (gsl_graph_get_state(graph) == GRAPH_STARTED) {
		GSL_MUTEX_UNLOCK(graph->graph_lock);
		rc = AR_EUNEXPECTED;
		goto exit;
	}
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	if (dir == GSL_DATA_DIR_READ)
		dp_info = &graph->read_info;
	else
		dp_info = &graph->write_info;

	if (cfg->shmem_ep_tag) {
		rc = gsl_graph_cache_datapath_miid(graph, dp_info,
			cfg->shmem_ep_tag, cfg->attributes);
		if (rc) {
			GSL_ERR("cache data path miid failed %d", rc);
			goto exit;
		}
		//Update the process id with the returned value
		proc_id = dp_info->master_proc_id;
	}
	rc = gsl_dp_config_data_path(dp_info, cfg, graph->src_port,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG], dir, NULL,
		proc_id);
	if (rc)
		GSL_ERR("configure data path failed %d", rc);

exit:
	return rc;
}

/*
 * Transfer the SG start mask and stop mask from old_gkv to new_gkv
 */
void gsl_transfer_sg_masks(struct gsl_graph_gkv_node *old_gkv_node,
	struct gsl_graph_gkv_node *new_gkv_node)
{
	uint32_t i, j;

	for (i = 0; i < old_gkv_node->num_of_subgraphs; ++i) {
		if (get_bit(old_gkv_node->sg_start_mask, i)) {
			for (j = 0; j < new_gkv_node->num_of_subgraphs; ++j) {
				if (old_gkv_node->sg_array[i]->sg_id
						== new_gkv_node->sg_array[j]->sg_id) {
					set_bit(new_gkv_node->sg_start_mask, j);
				}
			}
		}

		if (get_bit(old_gkv_node->sg_stop_mask, i)) {
			for (j = 0; j < new_gkv_node->num_of_subgraphs; ++j) {
				if (old_gkv_node->sg_array[i]->sg_id
						== new_gkv_node->sg_array[j]->sg_id) {
					set_bit(new_gkv_node->sg_stop_mask, j);
				}
			}
		}
	}
}

int32_t gsl_graph_start(struct gsl_graph *graph,
	ar_osal_mutex_t lock)
{
	uint32_t *sg_id_list, *num_sg, i;
	int32_t rc = AR_EOK;
	uint32_t *start_payload, pld_size;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg;
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	gsl_msg_t gsl_msg;

	if (!graph)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node, node);
		if (!gkv_node) {
			GSL_ERR("null returned for gkv_node\n");
			rc = AR_EBADPARAM;
			goto unlock_mutex;
		}
		if (gkv_node->num_of_subgraphs ==
			count_set_bits(gkv_node->sg_start_mask))
			continue;

		pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
			GSL_ALIGN_8BYTE(sizeof(uint32_t) *
			((size_t)1 + gkv_node->num_of_subgraphs)));

		/* Allocate enough size for worst case */
		rc = gsl_msg_alloc(APM_CMD_GRAPH_START, graph->src_port,
			GSL_GPR_DST_PORT_APM, pld_size, 0, graph->proc_id, 0, true,
			&gsl_msg);
		if (rc) {
			GSL_ERR("Failed to allocate GPR packet %d", rc);
			goto unlock_mutex;
		}

		start_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
		gsl_memset(start_payload, 0, pld_size);

		module_param = (struct apm_module_param_data_t *)
			((int8_t *)start_payload + sizeof(*cmd_header));
		module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
		module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

		num_sg = (uint32_t *)((int8_t *)start_payload +
			sizeof(*cmd_header) + sizeof(*module_param));

		*num_sg = 0;
		sg_id_list = num_sg + 1;
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
			sg = gkv_node->sg_array[i];
			/* send start command only for SGs that are not in START state */
			if (sg && sg->start_ref_cnt == 0) {
				*sg_id_list++ = sg->sg_id;
				(*num_sg)++;
			}
		}
		if ((*num_sg) == 0) {
			GSL_DBG("All SGs are already in started state");
			rc = AR_EOK;
			goto free_msg;
		}
		/*
		 * update payload sizes based on actual number of subgraphs
		 * that need to be prepared
		 */
		pld_size = sizeof(*cmd_header) + sizeof(*module_param) +
			GSL_ALIGN_8BYTE(sizeof(uint32_t) * ((size_t)1 + (*num_sg)));
		cmd_header = (struct apm_cmd_header_t *)start_payload;
		cmd_header->payload_size = (uint32_t)(pld_size - sizeof(*cmd_header));
		module_param->param_size =
			(uint32_t)((1 + (*num_sg)) * sizeof(uint32_t));

		GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
			sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);
		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
			&graph->graph_signal[GRAPH_CTRL_GRP1_CMD_SIG]);
		if (rc) {
			GSL_ERR("Graph start failed:%d", rc);
			gsl_msg_free(&gsl_msg);
			goto unlock_mutex;
		}

free_msg:
		gsl_msg_free(&gsl_msg);

		/* increment start ref count and decrement stop ref count
		 * for all SGs
		 */
		for (i = 0; i < gkv_node->num_of_subgraphs; ++i) {
			sg = gkv_node->sg_array[i];
			if (sg && !test_bit(gkv_node->sg_start_mask, i)) {
				sg->start_ref_cnt++;
				set_bit(gkv_node->sg_start_mask, i);
			}
			if (sg && test_bit(gkv_node->sg_stop_mask, i)) {
				if (sg->stop_ref_cnt > 0)
					sg->stop_ref_cnt--;
				clear_bit(gkv_node->sg_stop_mask, i);
			}
		}
	}

	/*
	 * if read buffers are configured then go ahead and queue them to spf
	 * but only do so if we are not already in STARTED state. It is
	 * possible that graph start is called multiple times while the graph is
	 * already in STARTED state in such cases we dont want to queue the buffers
	 */
	if (gsl_graph_get_state(graph) != GRAPH_STARTED &&
		graph->read_info.miid != 0)
		gsl_dp_queue_read_buffers_to_spf(&graph->read_info);

	gsl_graph_update_state(graph, GRAPH_STARTED);
unlock_mutex:
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_stop_with_properties(struct gsl_graph *graph,
	struct gsl_cmd_properties *stop_props, ar_osal_mutex_t lock)
{
	struct gsl_key_vector *gkv = &stop_props->gkv;
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	bool_t is_found = FALSE;
	int32_t rc = AR_EOK;

	if (!gkv->kvp || (gkv->num_kvps == 0))
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);

	/** find matching gkv from the gkv node list */
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		if (is_identical_gkv(&gkv_node->gkv,
			(struct gsl_key_vector *)gkv)) {
			is_found = TRUE;
			break;
		}
	}
	if (!is_found) {
		GSL_ERR("input gkv not opened/added, cannot apply stop command");
		rc = AR_EBADPARAM;
		goto exit;
	}
	rc = gsl_graph_stop_single_gkv(graph, gkv_node, stop_props);

	/**
	 * we don't wait for buffers to come back here as client does not use
	 * this to stop the SG with the shared mem endpoint
	 */
exit:
	GSL_MUTEX_UNLOCK(lock);
	return rc;
}

int32_t gsl_graph_suspend(struct gsl_graph *graph,
	ar_osal_mutex_t lock)
{
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	int32_t rc = AR_EOK;

	if (!graph)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);
	/** Proceed only if graph is in start state */
	if (gsl_graph_get_state(graph) != GRAPH_STARTED) {
		rc = AR_EALREADY;
		goto exit;
	}

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		if (!gkv_node) {
			GSL_ERR("null returned for gkv_node\n");
			rc = AR_EBADPARAM;
			goto exit;
		}
		if (gkv_node->sg_start_mask) {
			/**< some or all of the SGs are started within this GKV */
			rc = gsl_graph_suspend_single_gkv(graph, gkv_node);
			if (rc)
				goto exit;
		}
	}

exit:
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_stop(struct gsl_graph *graph,
	ar_osal_mutex_t lock)
{
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	int32_t rc = AR_EOK;
	uint32_t ev_flags = 0;

	if (!graph)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(lock);
	/** Proceed only if graph is in start state */
	if (gsl_graph_get_state(graph) != GRAPH_STARTED) {
		rc = AR_EALREADY;
		goto unlock_mutex;
	}

	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.stop_in_prog = TRUE;
	while (graph->transient_state_info.read_in_prog ||
		graph->transient_state_info.write_in_prog) {
		GSL_MUTEX_UNLOCK(graph->graph_lock);

		/* wake up any blocking reads/writes and abort them */
		gsl_signal_set(&graph->read_info.dp_signal,	GSL_SIG_EVENT_MASK_CLOSE,
			0, NULL);
		gsl_signal_set(&graph->write_info.dp_signal, GSL_SIG_EVENT_MASK_CLOSE,
			0, NULL);

		/* Wait for read & write to complete */
		rc = gsl_signal_timedwait(
			&graph->transient_state_info.trans_state_change_sig,
			GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
		if (rc) {
			GSL_ERR("error waiting for read/write to resolve in graph_stop %d",
				rc);
			GSL_MUTEX_LOCK(graph->graph_lock);
			break;
		} else if (ev_flags & GSL_SIG_EVENT_MASK_SSR) {
			GSL_MUTEX_LOCK(graph->graph_lock);
			break;
		}
		GSL_MUTEX_LOCK(graph->graph_lock);
	}

	gsl_graph_update_state(graph, GRAPH_STOPPED);
	/**
	 * Whole graph is in STOPPED state now, so reset both read and
	 * write processed buf counters
	 */
	graph->write_info.processed_buf_cnt = 0;
	graph->read_info.processed_buf_cnt = 0;
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		if (!gkv_node) {
			GSL_ERR("null returned for gkv_node\n");
			rc = AR_EBADPARAM;
			goto unlock_mutex;
		}
		{
			/**< some or all of the SGs are started within this GKV */
			rc = gsl_graph_stop_single_gkv(graph, gkv_node, NULL);
			if (rc)
				goto stop_done;
		}
	}

	/* Ensure SPF does not hold onto stale buffers */
	if (gsl_graph_get_state(graph) != GRAPH_ERROR) {
		gsl_wait_for_all_buffs_to_be_avail(&graph->read_info);
		gsl_wait_for_all_buffs_to_be_avail(&graph->write_info);
	}

stop_done:
	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.stop_in_prog = FALSE;
	GSL_MUTEX_UNLOCK(graph->graph_lock);

unlock_mutex:
	GSL_MUTEX_UNLOCK(lock);

	return rc;
}

int32_t gsl_graph_flush(struct gsl_graph *graph, ar_osal_mutex_t lock)
{
	uint32_t *sg_id_list, *num_sg, i, num_of_subgraphs;
	int32_t rc = AR_EOK;
	uint32_t *flush_payload, pld_size, ev_flags = 0;
	struct apm_cmd_header_t *cmd_header;
	struct apm_module_param_data_t *module_param;
	struct gsl_subgraph *sg, **sg_array = NULL;
	struct gsl_sgobj_list sg_obj_list = {0, NULL};
	gsl_msg_t gsl_msg;

	if (!graph)
		return AR_EBADPARAM;

	rc = gsl_graph_get_sgids_and_objs(graph, NULL, &sg_obj_list);
	if (rc) {
		GSL_ERR("failed to get sg objects");
		rc = AR_EFAILED;
		goto exit;
	}
	num_of_subgraphs = sg_obj_list.len;
	sg_array = sg_obj_list.sg_objs;

	pld_size = (uint32_t)(sizeof(*cmd_header) + sizeof(*module_param) +
		sizeof(uint32_t) * ((size_t)1 + num_of_subgraphs));

	/** Allocate enough size for worst case */
	rc = gsl_msg_alloc(APM_CMD_GRAPH_FLUSH, graph->src_port,
		GSL_GPR_DST_PORT_APM, pld_size, 0, graph->proc_id, 0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto free_sg_array;
	}

	flush_payload = GPR_PKT_GET_PAYLOAD(uint32_t, gsl_msg.gpr_packet);
	gsl_memset(flush_payload, 0, pld_size);

	module_param = (struct apm_module_param_data_t *)
			((int8_t *)flush_payload + sizeof(*cmd_header));
	module_param->module_instance_id = GSL_GPR_DST_PORT_APM;
	module_param->param_id = APM_PARAM_ID_SUB_GRAPH_LIST;

	num_sg = (uint32_t *)((int8_t *)flush_payload +
		sizeof(*cmd_header) + sizeof(*module_param));

	GSL_MUTEX_LOCK(lock);

	*num_sg = 0;
	sg_id_list = num_sg + 1;
	for (i = 0; i < num_of_subgraphs; ++i) {
		sg = sg_array[i];
		/* send flush command only for SGs marked with flushable */
		if (sg && sg->drv_prop_data.is_flushable == 1) {
			*sg_id_list++ = sg->sg_id;
			(*num_sg)++;
		}
	}
	if ((*num_sg) == 0) {
		GSL_DBG("None of the SGs in the graph are flushable");
		rc = AR_EOK;
		goto free_msg;
	}
	/*
	 * update payload sizes based on actual number of subgraphs
	 * that need to be flushed
	 */
	pld_size = sizeof(*cmd_header) + sizeof(*module_param) +
		sizeof(uint32_t) * ((size_t)1 + (*num_sg));
	cmd_header = (struct apm_cmd_header_t *)flush_payload;
	cmd_header->payload_size = (uint32_t)(pld_size - sizeof(*cmd_header));
	module_param->param_size = (uint32_t)((1 + (*num_sg)) * sizeof(uint32_t));


	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.flush_in_prog = TRUE;
	while (graph->transient_state_info.read_in_prog ||
		graph->transient_state_info.write_in_prog) {
		GSL_MUTEX_UNLOCK(graph->graph_lock);

		/* wake up any blocking reads/writes and abort them */
		gsl_signal_set(&graph->write_info.dp_signal,
			GSL_SIG_EVENT_MASK_CLOSE, 0, NULL);
		gsl_signal_set(&graph->read_info.dp_signal,
			GSL_SIG_EVENT_MASK_CLOSE, 0, NULL);

		/* Wait for read & write to complete */
		rc = gsl_signal_timedwait(
			&graph->transient_state_info.trans_state_change_sig,
			GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
		if (rc) {
			GSL_ERR("error waiting for read/write to resolve in flush %d", rc);
			GSL_MUTEX_LOCK(graph->graph_lock);
			break;
		}
		GSL_MUTEX_LOCK(graph->graph_lock);
	}
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + pld_size, NULL, 0);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
	if (rc) {
		GSL_ERR("Graph flush failed:%d", rc);
		GSL_MUTEX_LOCK(graph->graph_lock);
		graph->transient_state_info.flush_in_prog = FALSE;
		GSL_MUTEX_UNLOCK(graph->graph_lock);
		goto free_msg;
	}

	/* Ensure SPF does not hold onto stale buffers */
	if (gsl_graph_get_state(graph) != GRAPH_ERROR) {
		gsl_wait_for_all_buffs_to_be_avail(&graph->read_info);
		gsl_wait_for_all_buffs_to_be_avail(&graph->write_info);
	}

	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.flush_in_prog = FALSE;
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	/* graph will not be restarted so we need to queue the buffers back now */
	gsl_dp_queue_read_buffers_to_spf(&graph->read_info);

free_msg:
	gsl_msg_free(&gsl_msg);
	GSL_MUTEX_UNLOCK(lock);
free_sg_array:
	gsl_mem_free(sg_array);
exit:
	return rc;
}

int32_t gsl_graph_write(struct gsl_graph *graph, uint32_t tag,
	struct gsl_buff *buff, uint32_t *consumed_size)
{
	uint32_t rc = AR_EOK;

	/* if graph is in STOPPED or flush is in progress fail write */
	GSL_MUTEX_LOCK(graph->graph_lock);
	if (graph->transient_state_info.flush_in_prog ||
		graph->transient_state_info.stop_in_prog) {
		GSL_MUTEX_UNLOCK(graph->graph_lock);
		GSL_DBG("Write skipped because graph is stopping or flushing");
		rc = AR_EIODATA;
		goto exit;
	}
	graph->transient_state_info.write_in_prog = TRUE;
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	/* look-up module id from tag */
	if (graph->write_info.cached_tag != tag) {
		rc = gsl_graph_cache_datapath_miid(graph, &graph->write_info, tag,
			GSL_DATAPATH_SETUP_MODE(&graph->write_info.config));
		if (rc) {
			GSL_ERR("cache write miid failed rc %d", rc);
			goto end_write_state;
		}
	}

	rc = gsl_dp_write(&graph->write_info, buff, consumed_size);

end_write_state:
	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.write_in_prog = FALSE;
	gsl_signal_set(&graph->transient_state_info.trans_state_change_sig, 0, 0,
			NULL);
	GSL_MUTEX_UNLOCK(graph->graph_lock);

exit:
	return rc;
}

int32_t gsl_graph_read(struct gsl_graph *graph, uint32_t tag,
	struct gsl_buff *buff, uint32_t *filled_size)
{
	uint32_t rc = AR_EOK;

	/* if flush is in progress or graph is stopped fail the read */
	GSL_MUTEX_LOCK(graph->graph_lock);
	if (graph->transient_state_info.flush_in_prog ||
		graph->transient_state_info.stop_in_prog) {
		GSL_MUTEX_UNLOCK(graph->graph_lock);
		GSL_DBG("Read skipped because graph is stopping or flushing");
		rc = AR_EIODATA;
		goto exit;
	}
	graph->transient_state_info.read_in_prog = TRUE;
	GSL_MUTEX_UNLOCK(graph->graph_lock);

	/* look-up module id from tag if not yet set */
	if (graph->read_info.cached_tag != tag) {
		rc = gsl_graph_cache_datapath_miid(graph, &graph->read_info, tag,
			GSL_DATAPATH_SETUP_MODE(&graph->read_info.config));
		if (rc) {
			GSL_ERR("Failed to find MIID from tag %d", rc);
			goto end_read_state;
		}
	}

	rc = gsl_dp_read(&graph->read_info, buff, filled_size);

end_read_state:
	GSL_MUTEX_LOCK(graph->graph_lock);
	graph->transient_state_info.read_in_prog = FALSE;
	gsl_signal_set(&graph->transient_state_info.trans_state_change_sig, 0, 0,
			NULL);
	GSL_MUTEX_UNLOCK(graph->graph_lock);

exit:
	return rc;
}

int32_t gsl_graph_register_custom_event(struct gsl_graph *graph,
	struct gsl_cmd_register_custom_event *reg_ev)
{
	int32_t rc = AR_EOK;
	uint32_t spf_blob_sz =
		GSL_ALIGN_8BYTE(sizeof(apm_module_register_events_t) +
		reg_ev->event_config_payload_size);
	struct apm_cmd_header_t *cmd_header;
	apm_module_register_events_t *payload = NULL;
	gsl_msg_t gsl_msg;

	rc = gsl_msg_alloc(APM_CMD_REGISTER_MODULE_EVENTS, graph->src_port,
		reg_ev->module_instance_id, sizeof(struct apm_cmd_header_t), 0,
		graph->proc_id, spf_blob_sz, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate gsl msg %d", rc);
		goto exit;
	}

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
		gsl_msg.gpr_packet);
	gsl_memset(cmd_header, 0, spf_blob_sz + sizeof(struct apm_cmd_header_t));
	cmd_header->payload_size =
		GSL_ALIGN_8BYTE(sizeof(apm_module_register_events_t) +
		reg_ev->event_config_payload_size);
	payload = (apm_module_register_events_t *)((uint8_t *)cmd_header +
		sizeof(struct apm_cmd_header_t));
	payload->event_id = reg_ev->event_id;
	payload->module_instance_id = reg_ev->module_instance_id;
	payload->is_register = reg_ev->is_register;
	payload->event_config_payload_size = reg_ev->event_config_payload_size;
	gsl_memcpy((uint8_t *)payload + sizeof(apm_module_register_events_t),
		reg_ev->event_config_payload_size, reg_ev->event_config_payload,
		reg_ev->event_config_payload_size);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(struct apm_cmd_header_t) +
		spf_blob_sz, NULL, 0);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);

	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

int32_t gsl_graph_open(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv, const struct gsl_key_vector *ckv,
	ar_osal_mutex_t lock)
{
	struct gsl_graph_gkv_node *gkv_node = NULL;
	int32_t rc = AR_EOK;

	if (!graph)
		return AR_EBADPARAM;

	if (gkv && gkv->num_kvps != 0) {
		/** Memory to hold GKV, CKV, sg_array and num_of_subgraphs */
		gkv_node = gsl_mem_zalloc(sizeof(struct gsl_graph_gkv_node));
		if (!gkv_node)
			return AR_ENOMEMORY;
	}

	rc = __gpr_cmd_register(graph->src_port, gsl_gpr_callback, graph);
	if (rc)
		goto free_gkv_node;

	GSL_MUTEX_LOCK(lock);
	/* It is possible to open a graph with a null GKV */
	if (gkv && gkv->num_kvps != 0) {
		rc = gsl_graph_open_single_gkv(graph, gkv, ckv, gkv_node);
		if (rc) {
			GSL_ERR("graph open for single gkv failed %d", rc);
			goto dereg_cmd;
		}
	}
	GSL_MUTEX_UNLOCK(lock);

	return rc;

dereg_cmd:
	gsl_graph_update_state(graph, GRAPH_IDLE);
	GSL_MUTEX_UNLOCK(lock);
		__gpr_cmd_deregister(graph->src_port);
free_gkv_node:
		gsl_mem_free(gkv_node);
	return rc;
}

int32_t gsl_graph_close(struct gsl_graph *graph, ar_osal_mutex_t lock)
{
	ar_list_node_t *curr = NULL;
	int32_t first_rc = AR_EOK, rc = AR_EOK;
	struct gsl_graph_gkv_node *gkv_node = NULL;

	GSL_MUTEX_LOCK(lock);

	while (!ar_list_is_empty(&graph->gkv_list)) {
		curr = ar_list_get_tail(&graph->gkv_list);
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		rc = gsl_graph_close_single_gkv(graph, gkv_node, 0, NULL, NULL, NULL,
			0);
		/* in case of SSR we will get AR_ESUBSYSRESET treat it as success */
		if (rc != AR_EOK && rc != AR_ESUBSYSRESET) {
			if (first_rc == AR_EOK)
				first_rc = rc;
			GSL_ERR("graph_close failed for the cached key vector %d", rc);
		}

		gsl_graph_remove_gkv_from_list(graph, gkv_node);
		gsl_mem_free(gkv_node);
	}

	/*
	 * signal close event to the graph to unblock any
	 * anyone waiting on spf reponse
	 */
	gsl_graph_signal_event_all(graph, GSL_SIG_EVENT_MASK_CLOSE);

	/*
	 * wait for any data buffers currently with Spf to get released, skip if
	 * we are in SSR state
	 */
	if (gsl_graph_get_state(graph) != GRAPH_ERROR) {
		gsl_wait_for_all_buffs_to_be_avail(&graph->read_info);
		gsl_wait_for_all_buffs_to_be_avail(&graph->write_info);
	}

	if (graph->read_info.lock)
		gsl_data_path_deinit(&graph->read_info);
	if (graph->write_info.lock)
		gsl_data_path_deinit(&graph->write_info);

	__gpr_cmd_deregister(graph->src_port);

	GSL_MUTEX_UNLOCK(lock);

	return first_rc;
}

int32_t gsl_graph_close_with_properties(struct gsl_graph *graph,
	struct gsl_cmd_properties *props, ar_osal_mutex_t lock)
{
	struct gsl_key_vector *gkv;
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;

	bool_t is_found = FALSE;
	int32_t rc = AR_EOK;

	if (!graph || !props)
		return AR_EBADPARAM;

	gkv = &props->gkv;

	GSL_MUTEX_LOCK(lock);

	/** find matching gkv from the gkv node list */
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		if (is_identical_gkv(&gkv_node->gkv, (struct gsl_key_vector *)gkv)) {
			is_found = TRUE;
			break;
		}
	}
	if (!is_found) {
		GSL_ERR("input gkv not opened/added");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_close_single_gkv(graph, gkv_node, 0, NULL, NULL, props, 0);
	if (rc)
		GSL_ERR("graph close singe gkv failed %d", rc);
	/**
	 * we don't wait for buffers to come back here as client does not use
	 * this to close the SG with the shared mem endpoint
	 */
exit:
	GSL_MUTEX_UNLOCK(lock);
	return rc;
}

int32_t gsl_graph_add_new(struct gsl_graph *graph,
	struct gsl_cmd_graph_select *new_graph, ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	struct gsl_key_vector *ckv = NULL;

	/* Memory to hold GKV, CKV, sg_array and num_of_subgraphs */
	gkv_node = gsl_mem_zalloc(sizeof(struct gsl_graph_gkv_node));
	if (!gkv_node)
		return AR_ENOMEMORY;

	/* if no CKV passed, send null for default cal. Otherwise pass CKV */
	if (new_graph->cal_key_vect.num_kvps > 0)
		ckv = &new_graph->cal_key_vect;

	GSL_MUTEX_LOCK(lock);
	rc = gsl_graph_open_single_gkv(graph, &new_graph->graph_key_vector,
		ckv, gkv_node);
	GSL_MUTEX_UNLOCK(lock);
	if (rc) {
		GSL_ERR("graph open single gkv failed %d", rc);
		gsl_mem_free(gkv_node);
	}

	return rc;
}

int32_t gsl_graph_remove_old(struct gsl_graph *graph,
	struct gsl_cmd_remove_graph *old_graph,
	ar_osal_mutex_t oc_lock, ar_osal_mutex_t ss_lock)
{
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *gkv_node = NULL;
	bool_t is_found = FALSE;
	int32_t rc = AR_EOK;

	/** Find matching gkv_node with old_graph->gkv */
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		gkv_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		if (is_identical_gkv(&gkv_node->gkv, &old_graph->graph_key_vector)) {
			is_found = TRUE;
			break;
		}
	}
	if (!is_found) {
		GSL_ERR("gkv not found, cannot remove from graph");
		rc = AR_EBADPARAM;
		goto exit;
	}
	/** First issue stop for the SGs that need to be closed */
	GSL_MUTEX_LOCK(ss_lock);
	if (gkv_node->sg_start_mask) {
		rc = gsl_graph_stop_single_gkv(graph, gkv_node, NULL);
		if (rc)
			GSL_ERR("graph stop failed for single gkv %d", rc);
	}
	GSL_MUTEX_UNLOCK(ss_lock);

	/** Close the Subgraphs*/
	GSL_MUTEX_LOCK(oc_lock);
	rc = gsl_graph_close_single_gkv(graph, gkv_node, 0, NULL, NULL, NULL, 0);
	if (rc)
		GSL_ERR("graph_close failed for single gkv %d", rc);

	gsl_graph_remove_gkv_from_list(graph, gkv_node);
	gsl_mem_free(gkv_node);
	GSL_MUTEX_UNLOCK(oc_lock);

exit:
	return rc;
}

int32_t gsl_graph_change(struct gsl_graph *graph,
	struct gsl_cmd_graph_select *cg, ar_osal_mutex_t lock)
{
	struct gsl_graph_gkv_node *gkv_node = NULL, *temp_node = NULL;
	struct gsl_key_vector *gkv = &cg->graph_key_vector;
	struct gsl_key_vector *ckv = &cg->cal_key_vect;
	struct gsl_sgid_list sgids = {0, NULL};
	struct gsl_sgid_list pruned_sgids = {0, NULL};
	struct gsl_sgid_list existing_sgids = {0, NULL};
	AcdbGetGraphRsp sg_conn_info;
	AcdbSubgraph *p;
	struct gsl_graph_sg_conn_data pruned_sg_conn = { 0, },
		existing_sg_conn = { 0, };
	uint32_t i = 0;
	int32_t rc = AR_EOK;
	ar_list_node_t *curr = NULL;
	bool_t is_gkv_node_added = false;

	/** Memory to hold GKV, CKV, sg_array and num_of_subgraphs */
	gkv_node = gsl_mem_zalloc(sizeof(struct gsl_graph_gkv_node));
	if (!gkv_node)
		return AR_ENOMEMORY;

	/* Get graph data from ACDB */
	rc = gsl_acdb_get_graph(gkv, &sgids.sg_ids, &sg_conn_info);
	if (rc) {
		GSL_ERR("acdb get graph failed %d", rc);
		goto exit;
	}
	/* if acdb returned empty list of subgraphs then do nothing */
	if (!sgids.sg_ids || sg_conn_info.num_subgraphs == 0) {
		gsl_mem_free(gkv_node);
		goto exit;
	}

	GSL_MUTEX_LOCK(lock);

	/*
	 * Add new SGIDs and connections to the pool. Get pruned sgid list
	 * sg connections after adding them to the pool.
	 * We collect existing SG list and conns in case of error
	 */
	sgids.len = sg_conn_info.num_subgraphs;
	pruned_sgids.len = 0;
	pruned_sgids.sg_ids = NULL;
	existing_sgids.len = 0;
	existing_sgids.sg_ids = NULL;
	rc = gsl_graph_add_and_prune_sgs_and_connections(gkv_node,
		sgids, sg_conn_info.subgraphs, sg_conn_info.size, &pruned_sgids,
		&pruned_sg_conn, &existing_sgids, &existing_sg_conn);
	if (rc)
		goto unlock_mutex;

	/* Close all the existing GKVs from the gkv_list nodes */
	gkv_node->sg_start_mask = 0;
	gkv_node->sg_stop_mask = 0;
	while (!ar_list_is_empty(&graph->gkv_list)) {
		curr = ar_list_get_tail(&graph->gkv_list);
		temp_node = get_container_base(curr, struct gsl_graph_gkv_node,
			node);
		gsl_transfer_sg_masks(temp_node, gkv_node);

		rc = gsl_graph_close_single_gkv(graph, temp_node,
			0, NULL, NULL, NULL, 0);
		if (rc) {
			GSL_ERR("graph_close failed for graph key vector %d", rc);
			/* teardown error. Log it and continue -- nothing we can do here */
		}

		gsl_graph_remove_gkv_from_list(graph, temp_node);
		gsl_mem_free(temp_node);
	}

	/** Now open the pruned sgid list and connections */
	rc = gsl_graph_open_sgids_and_connections(graph, gkv_node,
		&pruned_sgids, &pruned_sg_conn, gkv, ckv);

	/*
	 * Add GKV and CKV to GKV_node
	 * we do this for both success and failure since we update the SG list in
	 * failure case
	 */
	gsl_graph_update_gkv_node(gkv_node, gkv, ckv);
	gsl_graph_add_gkv_to_list(graph, gkv_node);
	is_gkv_node_added = true;

	if (rc) {
		/*
		 * in the failure case, remove only the pruned SGIDs and conns from pool
		 * -- these are what is not open on SPF. Anything which was unmodified
		 * will still be open
		 * We preserve the GKV node so when client calls graph_close  later, we
		 * will clean up those SGs properly. (may see an error in that close --
		 * this would be benign and we would still close properly)
		 */

		/*
		 * remove the conns which were new -- these do not necessarily belong
		 * only to new SGs
		 */
		p = pruned_sg_conn.subgraphs;
		for (i = 0; i < pruned_sg_conn.num_sgs; ++i) {
			gsl_subgraph_remove_children(
				gsl_sg_pool_find(pruned_sg_conn.subgraphs[i].sg_id), p, NULL,
					NULL);
			p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids + p->num_dst_sgids);
		}
		/* then remove the new SGs */
		for (i = 0; i < pruned_sgids.len; ++i)
			gsl_sg_pool_remove(gsl_sg_pool_find(pruned_sgids.sg_ids[i]), FALSE);

		/*
		 * now we must adjust the GKV node to represent what is still open
		 * on SPF. This is the set intersection of old GKV + new GKV,
		 * i.e. all the SGs & conns which were *not* pruned. We stored those
		 * when we did add & prune.
		 */

		gsl_mem_free(gkv_node->sg_array);
		gsl_mem_free(gkv_node->sg_conn_data.subgraphs);

		gkv_node->num_of_subgraphs = existing_sgids.len;
		gkv_node->sg_array = gsl_mem_zalloc(gkv_node->num_of_subgraphs *
			sizeof(struct gsl_subgraph *));
		if (!gkv_node->sg_array) {
			rc = AR_ENOMEMORY;
			goto cleanup;
		}

		for (i = 0; i < existing_sgids.len; ++i)
			gkv_node->sg_array[i] = gsl_sg_pool_find(existing_sgids.sg_ids[i]);

		gkv_node->sg_conn_data.subgraphs = existing_sg_conn.subgraphs;
		gkv_node->sg_conn_data.size = existing_sg_conn.size;
		gkv_node->sg_conn_data.num_sgs = existing_sg_conn.num_sgs;

		/* prevent this from being freed */
		existing_sg_conn.subgraphs = NULL;
	}

cleanup:
	gsl_mem_free(pruned_sgids.sg_ids);
	gsl_mem_free(pruned_sg_conn.subgraphs);

	gsl_mem_free(existing_sgids.sg_ids);
	if (existing_sg_conn.subgraphs)
		gsl_mem_free(existing_sg_conn.subgraphs);

unlock_mutex:
	GSL_MUTEX_UNLOCK(lock);
exit:
	if (rc && !is_gkv_node_added)
		gsl_mem_free(gkv_node);

	return rc;
}

int32_t gsl_graph_prepare_to_change_single_gkv(struct gsl_graph *graph,
	struct gsl_prepare_change_graph_single_gkv_params *params,
	ar_osal_mutex_t lock)
{
	struct gsl_graph_gkv_node *old_node = NULL;
	int32_t rc = AR_EOK;
	uint32_t i, j, k = 0;
	ar_list_node_t *curr = NULL;
	bool_t old_gkv_found = false, skip_reopen_sg = false;
	struct gsl_key_vector new_ckv = {0, NULL};
	struct gsl_sgid_list *preserved_sgids = NULL;
	struct gsl_graph_sg_conn_data *pruned_plus_reopen_sg_conn = NULL;
	AcdbSubgraph *sg_conn, *p;

	ar_list_for_each_entry(curr, &graph->gkv_list) {
		old_node = get_container_base(curr, struct gsl_graph_gkv_node, node);
		if (is_identical_gkv(&params->old_gkv, &old_node->gkv)) {
			old_gkv_found = true;
			GSL_DBG("Found the old gkv node");
			break;
		}
	}

	if (!old_gkv_found) {
		rc = AR_ENOTEXIST;
		goto exit;
	}
	uint32_t num_children = 0, num_sg_conn = old_node->sg_conn_data.num_sgs;
	uint32_t *q = (uint32_t *)old_node->sg_conn_data.subgraphs;

	GSL_ERR("num_sg_conn = %d", num_sg_conn);
	for (i = 0; i < num_sg_conn; ++i) {
		GSL_ERR("sg %x has %d children:", *(q), num_children = *(q + 1));
		q += 2;
		while (num_children) {
			GSL_ERR("%x, ", *(q++));
			--num_children;
		}
	}
	num_sg_conn = params->num_sgs;
	q = (uint32_t *)params->sg_conn_info.subgraphs;

	GSL_ERR("num_sg_conn = %d", num_sg_conn);
	for (i = 0; i < num_sg_conn; ++i) {
		GSL_ERR("sg %x has %d children:", *(q), num_children = *(q + 1));
		q += 2;
		while (num_children) {
			GSL_ERR("%x, ", *(q++));
			--num_children;
		}
	}

	num_sg_conn = params->sg_conn_info_to_reopen.num_sgs;
	q = (uint32_t *)params->sg_conn_info_to_reopen.subgraphs;

	GSL_ERR("num_sg_conn = %d", num_sg_conn);
	for (i = 0; i < num_sg_conn; ++i) {
		GSL_ERR("sg %x has %d children:", *(q), num_children = *(q + 1));
		q += 2;
		while (num_children) {
			GSL_ERR("%x, ", *(q++));
			--num_children;
		}
	}

	GSL_MUTEX_LOCK(lock);

	preserved_sgids = &old_node->rtc_cache.preserved_sgids;
	pruned_plus_reopen_sg_conn =
		&old_node->rtc_cache.pruned_plus_reopen_sg_conn;

	preserved_sgids->len = params->num_sgs + params->num_sgs_to_reopen;
	if (preserved_sgids->len > 0) {
		preserved_sgids->sg_ids =
			gsl_mem_zalloc(preserved_sgids->len * sizeof(uint32_t));
		if (!preserved_sgids->sg_ids) {
			rc = AR_ENOMEMORY;
			GSL_MUTEX_UNLOCK(lock);
			goto exit;
		}
	}

	pruned_plus_reopen_sg_conn->size = params->sg_conn_info.size +
		params->sg_conn_info_to_reopen.size;
	if (pruned_plus_reopen_sg_conn->size) {
		pruned_plus_reopen_sg_conn->subgraphs =
			gsl_mem_zalloc(pruned_plus_reopen_sg_conn->size);
		if (!pruned_plus_reopen_sg_conn->subgraphs) {
			rc = AR_ENOMEMORY;
			goto free_pruned_sgs;
		}
	}

	/*
	 * All SGs which should stay open have their refcount incremented by 1
	 * When we close on old GKV, they will stay open, but re-open SGs will be
	 * closed.
	 * We will do the opposite of this in change_single_GKV to
	 * restore the correct refcount.
	 * SGs to preserve are unmodified, existing SGs
	 */

	for (i = 0; i < params->num_sgs; ++i) {
		skip_reopen_sg = false;
		/* skip modified SGs */
		for (j = 0; j < params->num_sgs_to_reopen; ++j) {
			if (params->sgs[i] == params->sgs_to_reopen[j]) {
				skip_reopen_sg = true;
				break;
			}
		}
		if (skip_reopen_sg)
			continue;
		/* skip new SGs */
		if (!gsl_sg_pool_find(params->sgs[i]))
			continue;

		gsl_sg_pool_add(params->sgs[i], FALSE);
		preserved_sgids->sg_ids[i] = params->sgs[i];
		++k;
	}
	/* Was set to maximum for malloc. set to real size */
	preserved_sgids->len = k;

	/*
	 * For connections, we add all the new ones, then remove the pruned and
	 * reopen. This has the effect of only incrementing the conns which already
	 * existed (shared between old & new GKV) and which are not in reopen list.
	 * We preserve the list of conns we removed for use in change_single_gkv
	 */

	sg_conn = params->sg_conn_info.subgraphs;
	p = pruned_plus_reopen_sg_conn->subgraphs;

	i = 0;
	k = 0;
	while (i < params->num_sgs) {
		gsl_subgraph_add_children(gsl_sg_pool_find(params->sgs[i]),
			sg_conn, p, NULL);
		if (p->num_dst_sgids) {
			p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids +
				p->num_dst_sgids); /* move to next pruned_sg_conn row */
			++k;
		}
		++i;
		sg_conn = (AcdbSubgraph *)((uint32_t *)sg_conn->dst_sg_ids +
			sg_conn->num_dst_sgids); /* move to next sg_conn row */
	}

	pruned_plus_reopen_sg_conn->num_sgs = k;
	if (k) {
		pruned_plus_reopen_sg_conn->size =
			(uint8_t *)p - (uint8_t *)pruned_plus_reopen_sg_conn;
	} else {
		pruned_plus_reopen_sg_conn->size = 0;
	}

	/* copy reopen SGs in after pruned SGs */
	if (params->sg_conn_info_to_reopen.num_sgs) {
		pruned_plus_reopen_sg_conn->size += params->sg_conn_info_to_reopen.size;
		gsl_memcpy(p, params->sg_conn_info.size
			+ params->sg_conn_info_to_reopen.size
			- pruned_plus_reopen_sg_conn->size,
			params->sg_conn_info_to_reopen.subgraphs,
			params->sg_conn_info_to_reopen.size);
		pruned_plus_reopen_sg_conn->num_sgs +=
			params->sg_conn_info_to_reopen.num_sgs;
	}

	/* now close the pruned plus reopened to decrement refcount */
	p = pruned_plus_reopen_sg_conn->subgraphs;
	for (i = 0; i < pruned_plus_reopen_sg_conn->num_sgs; ++i) {
		gsl_subgraph_remove_children(gsl_sg_pool_find(p->sg_id), p, NULL, NULL);
		p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids + p->num_dst_sgids);
	}
	/* haven't added anything new to pool, no need to adjust refs */

	rc = gsl_graph_close_single_gkv(graph, old_node, 0, NULL, NULL, NULL, true);
	if (rc)
		GSL_ERR("graph_close failed for graph key vector %d", rc);

free_pruned_sgs:
	if (new_ckv.kvp)
		gsl_mem_free(new_ckv.kvp);

	if (rc) {
		/*
		 * these pointers are cached, hence only free for error conditions
		 */
		if (preserved_sgids->sg_ids)
			gsl_mem_free(preserved_sgids->sg_ids);
		if (pruned_plus_reopen_sg_conn->subgraphs)
			gsl_mem_free(pruned_plus_reopen_sg_conn->subgraphs);
		pruned_plus_reopen_sg_conn->subgraphs = NULL;
	}
	GSL_MUTEX_UNLOCK(lock);
exit:

	return rc;
}

int32_t gsl_graph_change_single_gkv(struct gsl_graph *graph,
	struct gsl_change_graph_single_gkv_params *params,
	ar_osal_mutex_t lock)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0;
	ar_list_node_t *curr = NULL;
	struct gsl_graph_gkv_node *new_node, *old_node = NULL;
	AcdbSubgraph *p = NULL;
	struct gsl_sgid_list *preserved_sgids = NULL;
	struct gsl_graph_sg_conn_data *pruned_plus_reopen_sg_conn = NULL;
	bool_t gkv_found = false;

	if (graph->gkv_list.size == 0)
		return AR_EBADPARAM;

	/* find the gkv node */
	ar_list_for_each_entry(curr, &graph->gkv_list) {
		old_node = get_container_base(curr, struct gsl_graph_gkv_node, node);
		if (is_identical_gkv(&params->old_gkv, &old_node->gkv)) {
			/* found the gkv_node */
			gkv_found = true;
			GSL_DBG("Found the old gkv node");
			break;
		}
	}

	preserved_sgids = &old_node->rtc_cache.preserved_sgids;
	pruned_plus_reopen_sg_conn =
		&old_node->rtc_cache.pruned_plus_reopen_sg_conn;

	if (!gkv_found || !preserved_sgids || !pruned_plus_reopen_sg_conn)
		return AR_EBADPARAM;

	new_node = gsl_mem_zalloc(sizeof(struct gsl_graph_gkv_node));
	if (!new_node)
		return AR_ENOMEMORY;

	GSL_MUTEX_LOCK(lock);

	/* Now open both the pruned and force re-open sgs */
	rc = gsl_graph_open_single_gkv(graph, &params->new_gkv, &params->new_ckv,
		new_node);
	if (rc) {
		/* This will close all existing open SGs, even if it returns error */
		gsl_graph_close_single_gkv(graph, old_node, 0, NULL, 0, NULL, 0);

		goto cleanup;
	}

	/* decrement refcnt of SGs we incremented in prepare */
	for (i = 0; i < preserved_sgids->len; ++i) {
		gsl_sg_pool_remove(
			gsl_sg_pool_find(preserved_sgids->sg_ids[i]),
				FALSE);
	}

	/* increment refcount on cached list of SG conns (all open now) */
	p = pruned_plus_reopen_sg_conn->subgraphs;
	for (i = 0; i < pruned_plus_reopen_sg_conn->num_sgs; ++i) {
		rc = gsl_subgraph_add_children(gsl_sg_pool_find(p->sg_id),
			p, NULL, NULL);
		p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids +
			p->num_dst_sgids); /* move to next  row */
	}

	/*
	 * decrement all SG conns to restore proper refcount
	 * We decrement all because we incremented the unmodified ones earlier,
	 * and we just incremented the new + re-opened ones so all are 1 too high
	 */
	p = new_node->sg_conn_data.subgraphs;
	for (i = 0; i < new_node->num_of_subgraphs; ++i) {
		gsl_subgraph_remove_children(new_node->sg_array[i], p, NULL, NULL);
		p = (AcdbSubgraph *)((uint32_t *)p->dst_sg_ids + p->num_dst_sgids);
	}

	copy_key_vector(&new_node->gkv, &params->new_gkv);

	gsl_transfer_sg_masks(old_node, new_node);

cleanup:
	GSL_MUTEX_UNLOCK(lock);

	if (pruned_plus_reopen_sg_conn->num_sgs)
		gsl_mem_free(pruned_plus_reopen_sg_conn->subgraphs);
	if (preserved_sgids->sg_ids)
		gsl_mem_free(preserved_sgids->sg_ids);

	if (!rc) {
		if (old_node->ckv.kvp)
			gsl_mem_free(old_node->ckv.kvp);
		/* keep old node for cleanup at graph close in errors */
		gsl_graph_remove_gkv_from_list(graph, old_node);
		gsl_mem_free(old_node);
	}

	return rc;
}

int32_t gsl_graph_change_set_config_helper(struct gsl_graph *graph,
	uint32_t tag_data_size, uint8_t *tag_data)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *cmd_header;
	gsl_msg_t gsl_msg;

	if (tag_data_size == 0 || !tag_data)
		return AR_EBADPARAM;

	gsl_memset(&gsl_msg, 0, sizeof(gsl_msg_t));

	rc = gsl_msg_alloc(APM_CMD_SET_CFG, graph->src_port, GSL_GPR_DST_PORT_APM,
		sizeof(*cmd_header), 0, graph->proc_id, tag_data_size, false, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate GSL msg %d", rc);
		goto exit;
	}

	cmd_header = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t,
		gsl_msg.gpr_packet);
	cmd_header->mem_map_handle = gsl_msg.shmem.spf_mmap_handle;
	cmd_header->payload_address_lsw = (uint32_t)gsl_msg.shmem.spf_addr;
	cmd_header->payload_address_msw = (uint32_t)(gsl_msg.shmem.spf_addr >> 32);
	cmd_header->payload_size = tag_data_size;

	gsl_memcpy(gsl_msg.payload, tag_data_size, (void *)tag_data, tag_data_size);

	GSL_LOG_PKT("send_pkt", graph->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*cmd_header), gsl_msg.payload,
		cmd_header->payload_size);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&gsl_msg.gpr_packet,
		&graph->graph_signal[GRAPH_CTRL_GRP2_CMD_SIG]);
	if (rc)
		GSL_ERR("Graph set config failed %d", rc);

	gsl_msg_free(&gsl_msg);
exit:
	return rc;
}

int32_t gsl_graph_get_tags_with_module_info(
	const struct gsl_key_vector *graph_key_vect,
	struct gsl_tag_module_info *tag_module_info,
	size_t *tag_module_info_size)
{
	int32_t rc = AR_EOK;
	AcdbCmdGetTagsFromGkvReq cmd_struct;
	AcdbCmdGetTagsFromGkvRsp rsp_struct;
	AcdbGraphKeyVector gkv;

	gkv.num_keys = graph_key_vect->num_kvps;
	gkv.graph_key_vector = (AcdbKeyValuePair *)graph_key_vect->kvp;
	cmd_struct.graph_key_vector = &gkv;

	rsp_struct.num_tags = 0;
	if (!tag_module_info || *tag_module_info_size == 0) {
		rsp_struct.list_size = 0;
		rsp_struct.tag_module_list = NULL;
	} else {
		rsp_struct.list_size = (uint32_t)(*tag_module_info_size -
			sizeof(struct gsl_tag_module_info));
		rsp_struct.tag_module_list = (AcdbTagModule *)
			tag_module_info->tag_module_entry;
	}
	rc = acdb_ioctl(ACDB_CMD_GET_TAGS_FROM_GKV, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("acdb get tags from gkv failed with %d", rc);
		return rc;
	}
	if (tag_module_info)
		tag_module_info->num_tags = rsp_struct.num_tags;

	*tag_module_info_size = rsp_struct.list_size +
		sizeof(struct gsl_tag_module_info);

	return rc;
}

int32_t gsl_graph_get_tagged_data(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag,
	struct gsl_key_vector *tag_key_vect,
	uint8_t *payload, size_t *payload_size)
{
	int32_t rc = AR_EOK;
	AcdbSgIdModuleTag cmd_struct = { 0 };
	AcdbBlob rsp_struct;
	uint32_t *sgid_list = NULL;
	AcdbGetGraphRsp sg_conn_info;

	rc = gsl_acdb_get_graph(graph_key_vect, &sgid_list, &sg_conn_info);
	if (rc) {
		GSL_ERR("acdb get graph failed for the given gkv %d", rc);
		return rc;
	}
	/* it is possible that the GKV results in 0 subgraphs */
	if (!sgid_list || sg_conn_info.num_subgraphs == 0) {
		*payload_size = 0;
		return rc;
	}

	cmd_struct.num_sg_ids = sg_conn_info.num_subgraphs;
	cmd_struct.sg_ids = sgid_list;
	cmd_struct.module_tag.tag_id = tag;
	if (tag_key_vect) {
		cmd_struct.module_tag.tag_key_vector.num_keys = tag_key_vect->num_kvps;
		cmd_struct.module_tag.tag_key_vector.graph_key_vector =
			(AcdbKeyValuePair *)tag_key_vect->kvp;
	}
	rsp_struct.buf = NULL;
	rsp_struct.buf_size = 0;
	rc = acdb_ioctl(ACDB_CMD_GET_MODULE_TAG_DATA, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("failed to get module tag data size %d", rc);
		goto cleanup;
	}

	if (payload) {
		if (*payload_size < rsp_struct.buf_size) {
			GSL_ERR("memory not sufficient for module tag data");
			rc = AR_ENEEDMORE;
			goto set_payload_size;
		}
		rsp_struct.buf = payload;
		rc = acdb_ioctl(ACDB_CMD_GET_MODULE_TAG_DATA, &cmd_struct,
			sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
		if (rc)
			GSL_ERR("failed to get module tag data %d", rc);
	}
set_payload_size:
	*payload_size = rsp_struct.buf_size;
cleanup:
	gsl_mem_free(sgid_list);
	gsl_mem_free(sg_conn_info.subgraphs);
	return rc;
}
