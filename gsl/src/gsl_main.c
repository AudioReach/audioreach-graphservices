/**
 * \file gsl_main.c
 *
 * \brief
 *      Main entry point for Graph Service Layer (GSL)
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_intf.h"
#include "acdb.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
#include "ar_osal_shmem.h"
#include "ar_util_list.h"
#include "ar_util_data_log.h"
#include "ar_util_err_detection.h"
#include "ar_osal_mutex.h"
#include "ar_osal_sleep.h"
#include "ar_osal_string.h"
#include "ar_osal_sys_id.h"
#include "gsl_graph.h"
#include "gsl_subgraph_pool.h"
#include "gsl_global_persist_cal.h"
#include "gsl_common.h"
#include "gsl_shmem_mgr.h"
#include "gsl_spf_ss_state.h"
#include "gsl_mdf_utils.h"
#include "gsl_rtc_main.h"
#include "gsl_rtc.h"
#include "gsl_rtc_intf.h"
#include "gsl_dynamic_module_mgr.h"
#include "gpr_api.h"
#include "gpr_api_inline.h"
#include "gpr_ids_domains.h"
#include "apm_api.h"
#include "apm_memmap_api.h"
#include "apm_graph_properties.h"
#include <string.h>
#include <stdio.h>

#if defined(GSL_LOG_PKT_ENABLE) || defined(GSL_LOG_DATA_ENABLE)
ar_fhandle pkt_log_fd = NULL;
char *gsl_str = "gsl_log_";
ar_osal_mutex_t log_mutex;
#endif

 /*
  * Increment if a change breaks backwards compatability
  */
#define GSL_MAJOR_VERSION 1

/*
 * Increment if one or more new features are added
 */
#define GSL_MINOR_VERSION 0

/** max. number of use-case graphs, initialize to 16 */
#define MAX_UC_GRAPHS 16
#define GSL_MAGIC_WORD  0x47534C  /* 'GSL' */
#define GSL_MAGIC_WORD_MASK  0xFFFFFF
#define GSL_GRAPH_IDX_SHIFT 24
#define GSL_GRAPH_SRC_PORT_MIN  0x2010
#define GSL_GRAPH_SRC_PORT_MAX  0x2100

#define get_src_port(i)  ((((i) + GSL_GRAPH_SRC_PORT_MIN) > \
				GSL_GRAPH_SRC_PORT_MAX) ? \
				GSL_GRAPH_SRC_PORT_MIN : ((i) + GSL_GRAPH_SRC_PORT_MIN))

#define GSL_MAIN_SRC_PORT 0x2003

#define GSL_DYN_DL_RETRY_MS (500)
#define GSL_DYN_DL_NUM_RETRIES 4
#define GSL_DYN_DL_NUM_RETRIES_SSR 6

#define GSL_SS_RETRY_MS (10)

struct gsl_rtgm_state_info {

	/*
	 * when non-zero it means rtgm operation is in progress
	 * QACT sends all prepares then all change
	 */
	uint32_t num_rtgm_in_prog;

	/*
	 * when true it means non-rtgm client operation is in progress such as
	 * read/write or set_cfg
	 */
	bool_t client_op_in_prog;

	/*
	 * signal to tell waiting rtgm operation when it is safe to proceed
	 */
	struct gsl_signal sig;
};

struct gsl_acdb_client_info {
	ar_list_node_t node; /**< list node of each acdb client */
	struct gsl_acdb_data_files acdb_files; /**< client acdb file path info */
	struct gsl_acdb_file acdb_delta_file;
		/**< client delta acdb file path info */
	gsl_acdb_handle_t acdb_handle; /**< acdb handle returned from AML */
};

static struct gsl_ctxt_ {
	void **graph_list; /**< list of all graphs, one per GSL handle */
	uint8_t graph_list_size; /**< size of graph list */
	uint32_t num_graphs; /**< number of active graphs */
	ar_osal_mutex_t open_close_lock;
	    /**< used to serialize open and close operations */
	ar_osal_mutex_t start_stop_lock;
	/**< used to serialize start and stop operations */
	ar_osal_mutex_t graph_hdl_lock;
	/**< used to serialize get/set graph_handle operations */
	struct gsl_signal rsp_signal;
	/**< holds the status received in the readiness response */
	gsl_global_cb_func_ptr global_cb;
	/**< callback used to notify global events to client */
	void *global_cb_client_data;
	/**< client data that is passed back to client in the callback */
	struct gsl_rtgm_state_info rtgm_state_info;
	/**< info used to sychronize rtgm and non-rtgm operations */
	bool_t spf_restart[AR_SUB_SYS_ID_LAST + 1];
	/**< on SPF SSR/PDR, we need to reconfigure shmem and dyn modules */
	bool_t rtc_conn_active;
	/**< whether there is an active RTC session or not */
	ar_list_t acdb_client_list; /**< list of acdb clients from PVM and GVM */
	ar_osal_mutex_t acdb_client_lock;
} gsl_ctxt;

static inline gsl_handle_t to_gsl_handle(uint8_t index)
{
	return (gsl_handle_t)((uintptr_t)(GSL_MAGIC_WORD |
		(index << GSL_GRAPH_IDX_SHIFT)));
}

static inline uint8_t to_gsl_graph_index(gsl_handle_t hdl)
{
	return ((uintptr_t)hdl >> GSL_GRAPH_IDX_SHIFT) & 0xff;
}

static bool_t is_valid_gsl_hdl(gsl_handle_t hdl)
{
	if (((uintptr_t)hdl & GSL_MAGIC_WORD_MASK) != GSL_MAGIC_WORD)
		return 0;

	return 1;
}

/*
 * If RTGM is in progrss returns failure. Otherwise sets the rtgm_state_info to
 * "clint_operation_in_progress" and returns success
 */
static bool_t gsl_main_start_client_op(struct gsl_ctxt_ *ctxt)
{
	GSL_MUTEX_LOCK(ctxt->graph_hdl_lock);
	if (ctxt->rtgm_state_info.num_rtgm_in_prog > 0) {
		GSL_MUTEX_UNLOCK(ctxt->graph_hdl_lock);
		return false;
	}
	ctxt->rtgm_state_info.client_op_in_prog = true;
	GSL_MUTEX_UNLOCK(ctxt->graph_hdl_lock);
	return true;
}

static int32_t gsl_main_start_client_op_blocking(struct gsl_ctxt_ *ctxt)
{
	int32_t rc = AR_EOK;
	uint32_t ev_flags = 0;

	GSL_MUTEX_LOCK(ctxt->graph_hdl_lock);
	/* if RTGM is in-progress block */
	while (ctxt->rtgm_state_info.num_rtgm_in_prog > 0) {
		GSL_MUTEX_UNLOCK(ctxt->graph_hdl_lock);
		GSL_DBG("blocked due to RTGM");
		rc = gsl_signal_timedwait(
			&ctxt->rtgm_state_info.sig,
			GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
		if (rc != AR_EOK) {
			GSL_ERR("signal timed wait returned err %d", rc);
			return rc;
		}
		GSL_MUTEX_LOCK(ctxt->graph_hdl_lock);
	}
	ctxt->rtgm_state_info.client_op_in_prog = true;
	GSL_MUTEX_UNLOCK(ctxt->graph_hdl_lock);

	return rc;
}

/*
 * Clears "client_operation_in_progress" state if it was set
 */
static void gsl_main_end_client_op(struct gsl_ctxt_ *ctxt)
{
	GSL_MUTEX_LOCK(ctxt->graph_hdl_lock);
	ctxt->rtgm_state_info.client_op_in_prog = false;
	gsl_signal_set(&ctxt->rtgm_state_info.sig, GSL_SIG_EVENT_CLIENT_OP_DONE,
		0, NULL);
	GSL_MUTEX_UNLOCK(ctxt->graph_hdl_lock);
}

static struct gsl_graph *to_gsl_graph(gsl_handle_t graph_handle)
{
	struct gsl_graph *graph = NULL;

	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);

	if (!is_valid_gsl_hdl(graph_handle))
		goto cleanup;

	graph = (struct gsl_graph *)
		gsl_ctxt.graph_list[to_gsl_graph_index(graph_handle)];

cleanup:
	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);

	return graph;
}

/** callback handles RTC callbacks */
static int32_t gsl_rtc_callback(enum gsl_rtc_request_type req, void *cb_data)
{
	struct gsl_rtc_active_uc_info *info;
	uint32_t size_remaining = 0, ev_flags = 0;
	uint32_t size_to_copy = 0, gkv_node_size;
	uint32_t gkv_bytes = 0, ckv_bytes = 0;
	static uint32_t restart_list_position, restart_list_size;
	static uint32_t *restart_handle_list;
	struct gsl_graph *graph = NULL;
	struct gsl_rtc_uc_data *uc_data = NULL;
	uint8_t *payload;
	uint8_t i;
	struct gsl_rtc_param *rtc_cal_data;
	struct gsl_rtc_persist_param *rtc_persist_cal_data;
	struct gsl_rtc_prepare_change_graph_info *prep_change_graph_params;
	struct gsl_rtc_change_graph_info *change_graph_params;
	struct gsl_rtc_conn_info *rtc_conn_info;

	int32_t rc = AR_EOK;

	if (!cb_data)
		return AR_EFAILED;

	GSL_ERR("GSL rtc request %d start", req);
	switch (req) {
	case GSL_RTC_GET_UC_INFO:
		info = (struct gsl_rtc_active_uc_info *)cb_data;
		GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
		size_remaining = info->total_size;
		info->total_size = 0;
		info->num_usecases = 0;
		uc_data = info->uc_data;
		if (uc_data)
			gsl_memset(uc_data, 0, size_remaining);
		GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
		for (i = 0; i < gsl_ctxt.graph_list_size; ++i) {
			graph = (struct gsl_graph *)(gsl_ctxt.graph_list[i]);
			if (graph &&
				(gsl_graph_get_state(graph) >= GRAPH_OPENED) &&
				(gsl_graph_get_state(graph) != GRAPH_ERROR) &&
				(gsl_graph_get_state(graph) != GRAPH_ERROR_ALLOW_CLEANUP)) {
				gkv_node_size = gsl_rtc_graph_get_gkv_ckv_size(graph);
				size_to_copy = gkv_node_size + sizeof(struct gsl_rtc_uc_data);
				++info->num_usecases;
				info->total_size += size_to_copy;
				if (uc_data && size_remaining >= size_to_copy) {
					uc_data->graph_handle =
						(uint32_t)(uintptr_t)to_gsl_handle(i);
					payload = &uc_data->payload[0];
					gkv_bytes = gsl_rtc_graph_copy_gkvs(graph, payload,
						&uc_data->num_gkvs);
					ckv_bytes = gsl_rtc_graph_copy_ckvs(graph,
						payload+gkv_bytes, &uc_data->num_ckvs);
					payload = payload + gkv_bytes + ckv_bytes;
					uc_data = (struct gsl_rtc_uc_data *)payload;
					size_remaining -= size_to_copy;
				}
			}
		}
		GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
		GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
		break;

	case GSL_RTC_PREPARE_CHANGE_GRAPH:
		/*
		 * check that no other client operation is in progress before starting
		 * RTGM, if it is then wait for it to complete
		 */
		GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
		while (gsl_ctxt.rtgm_state_info.client_op_in_prog) {
			GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
			rc = gsl_signal_timedwait(&gsl_ctxt.rtgm_state_info.sig,
				GSL_SPF_TIMEOUT_MS, &ev_flags, NULL, NULL);
			if (rc) {
				GSL_ERR("signal timedwait failed %d", rc);
				goto exit;
			}
			GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
		}
		++gsl_ctxt.rtgm_state_info.num_rtgm_in_prog;
		GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);

		GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
		prep_change_graph_params = (struct gsl_rtc_prepare_change_graph_info *)
			cb_data;
		graph = to_gsl_graph(
			(gsl_handle_t)(uintptr_t)prep_change_graph_params->graph_handle);
		if (!graph) {
			GSL_ERR("rtc failed got invalid graph_handle %d",
				prep_change_graph_params->graph_handle);
			rc = AR_EBADPARAM;
			goto unlock_mutex;
		}

		if (gsl_graph_get_state(graph) == GRAPH_STARTED) {

			if (!restart_handle_list) {
				/* allocate list of graphs to restart. max size is all  graphs*/
				restart_list_position = 0;
				restart_list_size = 0;
				/* we use restart_list_size when stopping
				 * and restart_list_position when starting
				 */
				restart_handle_list =
					gsl_mem_zalloc(gsl_ctxt.num_graphs * sizeof(uint32_t));
				if (!restart_handle_list) {
					rc = AR_ENOMEMORY;
					goto unlock_mutex;
				}
			}

			rc = gsl_graph_stop(graph, gsl_ctxt.start_stop_lock);
			if (rc) {
				GSL_ERR("rtc failed to stop graph rc %d", rc);
				GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
				break;
			}

			/* keep track of all graphs we stop here
			 * Client must sends change cmds in exact same order
			 */
			restart_handle_list[restart_list_size] =
				prep_change_graph_params->graph_handle;
			++restart_list_size;
		}
		rc = gsl_rtc_internal_prepare_change_graph(graph,
			prep_change_graph_params, NULL);
		if (rc) {
			GSL_ERR("rtc failed to prepare for change graph rc %d", rc);
			GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock); //todo fix
		}
		GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
		break;

	case GSL_RTC_CHANGE_GRAPH:
		GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
		change_graph_params = (struct gsl_rtc_change_graph_info *)cb_data;
		graph = to_gsl_graph((gsl_handle_t)(uintptr_t)
			change_graph_params->graph_handle);
		if (!graph) {
			GSL_ERR("rtc failed got invalid graph_handle %d",
				change_graph_params->graph_handle);
			rc = AR_EBADPARAM;
			goto unlock_mutex;
		}

		rc = gsl_rtc_internal_change_graph(graph, change_graph_params, NULL);
		if (rc) {
			GSL_ERR("rtc failed to change graph rc %d", rc);
			GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
			break; // TODO This is bad state forever .
		}

		if (change_graph_params->tag_data_size) {
			rc = gsl_graph_change_set_config_helper(graph,
				change_graph_params->tag_data_size,
				change_graph_params->tag_data);
			if (rc) {
				GSL_ERR("failed to set cfg on changed graph %d", rc);
				GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
				break;
			}
		}
		/*
		 * the graph would have been stopped by PREPARE_CHANGE_GRAPH so start
		 * it back again here
		 */
		if (restart_handle_list && change_graph_params->graph_handle
			== restart_handle_list[restart_list_position]) {

			/* clear restart list if no more to be restarted */
			if (++restart_list_position == restart_list_size) {
				gsl_mem_free(restart_handle_list);
				restart_list_position = 0;
				restart_list_size = 0;
				restart_handle_list = NULL;
			}

			rc = gsl_graph_start(graph, gsl_ctxt.start_stop_lock);
			if (rc)
				GSL_ERR("rtc failed to restart graph rc %d", rc);
		}
		GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);

		/* Decrement counter to finish this rtgm operation. Signal if no more */
		GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
		if (--gsl_ctxt.rtgm_state_info.num_rtgm_in_prog == 0)
			gsl_signal_set(&gsl_ctxt.rtgm_state_info.sig,
				GSL_SIG_EVENT_MASK_RTGM_DONE, 0, NULL);
		GSL_ERR("tvl end of RTGM, num in prog: %d",
			gsl_ctxt.rtgm_state_info.num_rtgm_in_prog);
		GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
		break;

	case GSL_RTC_CONN_INFO_CHANGE:
		GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
		rtc_conn_info = (struct gsl_rtc_conn_info *)cb_data;
		switch (rtc_conn_info->state) {
		case GSL_RTC_CONNECTION_STATE_START:
			gsl_ctxt.rtc_conn_active = true;
			break;
		case GSL_RTC_CONNECTION_STATE_STOP:
			gsl_ctxt.rtc_conn_active = false;
			/* stop graphs from logging cfg info to diag */
			for (i = 0; i < gsl_ctxt.graph_list_size; ++i) {
				/* list not necessarily contiguous, check for null */
				if (!gsl_ctxt.graph_list[i])
					continue;

				((struct gsl_graph *)gsl_ctxt.graph_list[i])
					->rtc_conn_active = false;
			}
			break;
		default:
			rc = AR_EUNSUPPORTED;

		}
		GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
		break;
	default:
		GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
		if ((req == GSL_RTC_GET_PERSIST_DATA) ||
			(req == GSL_RTC_SET_PERSIST_DATA)) {
			rtc_persist_cal_data = (struct gsl_rtc_persist_param *)cb_data;
			graph = to_gsl_graph(
				(gsl_handle_t)(uintptr_t)rtc_persist_cal_data->graph_handle);
			if (!graph) {
				rc = AR_EBADPARAM;
				goto unlock_mutex;
			}
			if (req == GSL_RTC_GET_PERSIST_DATA)
				rc = gsl_rtc_graph_get_persist_data(graph,
					rtc_persist_cal_data->sgid, rtc_persist_cal_data->proc_id,
					rtc_persist_cal_data->total_size,
					&rtc_persist_cal_data->sg_cal_data);
			else
				rc = gsl_rtc_graph_set_persist_data(graph,
					rtc_persist_cal_data);
		} else if ((req == GSL_RTC_GET_NON_PERSIST_DATA) ||
			(req == GSL_RTC_SET_NON_PERSIST_DATA)) {
			rtc_cal_data = (struct gsl_rtc_param *)cb_data;
			graph = to_gsl_graph((gsl_handle_t)
				(uintptr_t)rtc_cal_data->graph_handle);
			if (!graph) {
				rc = AR_EBADPARAM;
				goto unlock_mutex;
			}
			if (req == GSL_RTC_GET_NON_PERSIST_DATA)
				rc = gsl_rtc_graph_get_non_persist_data(graph,
					rtc_cal_data->total_size, rtc_cal_data->sg_cal_data);
			else
				rc = gsl_rtc_graph_set_non_persist_data(graph,
					rtc_cal_data->total_size, rtc_cal_data->sg_cal_data);
		} else {
			rc = AR_EFAILED;
		}
unlock_mutex:
		GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);
		break;
	}
exit:
	if (rc)
		GSL_ERR("GSL rtc request %d failed %d", req, rc);

	return rc;
}

/**
 * callback handles ssr events and returns the list of impacted
 * graph handles
 * \param[in] state: indicates whether the subsystems are up or dn
 * \param[in] spf_ss_state: bitmask indicating impacted subsystems
 */
static void gsl_main_ssr_callback(enum spf_ss_state_t state,
				  uint32_t spf_ss_mask)
{
	struct gsl_global_event_svc_dn_payload client_pld = {.num_handles = 0,
		.handle_list = NULL};
	uint32_t num_graph_handles = 0;
	uint8_t i = 0;
	struct gsl_graph *graph;
	bool_t master_proc_ssr = gsl_mdf_utils_is_master_proc(spf_ss_mask);
	uint32_t master_proc = gsl_mdf_utils_get_master_proc_id(spf_ss_mask);

	/*
	 * Invalid subsystem mask.
	 * The subsystem mask provided should be present in one of the processor
	 * groups.
	 */
	if (master_proc == 0)
		return;

	if (state == GSL_SPF_SS_STATE_DN) {
		/*
		 * unblock any memory map operations in progress, for now assume master
		 * is ADSP this assumption may need to be revisited in the future
		 */
		if (master_proc_ssr)
			gsl_shmem_signal_ssr(master_proc);

		/* allocate memory to store the graph handles to be sent to client */
		GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);

		if (gsl_ctxt.num_graphs > 0) {
			client_pld.handle_list =
				gsl_mem_zalloc(sizeof(gsl_handle_t)*gsl_ctxt.num_graphs);
			if (!client_pld.handle_list) {
				GSL_ERR("No memory");
				GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
				return;
			}

			/* build the list of impacted handles */
			for (i = 0; i < gsl_ctxt.graph_list_size; ++i) {
				if (!gsl_ctxt.graph_list[i])
					continue;

				graph = (struct gsl_graph *)(gsl_ctxt.graph_list[i]);

				/* check if a ss this graph depends is down */
				if ((spf_ss_mask & graph->ss_mask) == 0)
					continue;

				if (gsl_graph_get_state(graph) != GRAPH_IDLE &&
					gsl_graph_get_state(graph) != GRAPH_ERROR &&
					gsl_graph_get_state(graph) != GRAPH_ERROR_ALLOW_CLEANUP) {

					/*
					 * if master is down go to GRAPH_ERROR state as no cleanup
					 * on SPF is required. If a satellite is down go to
					 * GRAPH_ERROR_ALLOW_CLEANUP as we still need to issue
					 * close to to SPF for this graph
					 */
					if (master_proc_ssr)
						gsl_graph_update_state(graph, GRAPH_ERROR);
					else
						gsl_graph_update_state(graph,
							GRAPH_ERROR_ALLOW_CLEANUP);
					/*
					 * signal SSR event to the graph to unblock
					 * anyone waiting on spf reponse,
					 * if it's not already closed
					 */
					gsl_graph_signal_event_all(graph,
						GSL_SIG_EVENT_MASK_SSR);
				}

				client_pld.handle_list[num_graph_handles++] =
					to_gsl_handle(i);
			}
		}
		GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
		client_pld.num_handles = num_graph_handles;

		/*
		 * notify mdf utils that some ss are restarted, ideally this should be
		 * done as part of UP handling but since some clients dont wait for
		 * the UP call back before attempting to re-open graphs we have to do
		 * it here
		 */
		gsl_mdf_utils_notify_ss_restarted(spf_ss_mask);

		/* reset error detection context */
		ar_err_det_reset_ctxt(master_proc);

		/* issue callback to client */
		if (gsl_ctxt.global_cb)
			gsl_ctxt.global_cb(GSL_GLOBAL_EVENT_AUDIO_SVC_DN, &client_pld,
			sizeof(client_pld), gsl_ctxt.global_cb_client_data);
		/* free the handle_list memory  */
		if (client_pld.handle_list)
			gsl_mem_free(client_pld.handle_list);
	} else { /* GSL_SPF_SS_STATE_UP */
		if (master_proc_ssr) {
			gsl_ctxt.spf_restart[master_proc] = TRUE;
			/* clear ssr state from shmem mgr */
			gsl_shmem_clear_ssr(master_proc);
		}

		/* issue callback to client */
		if (gsl_ctxt.global_cb)
			gsl_ctxt.global_cb(GSL_GLOBAL_EVENT_AUDIO_SVC_UP, NULL, 0,
			gsl_ctxt.global_cb_client_data);
	}
}

static uint32_t gsl_main_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
	struct apm_cmd_rsp_get_spf_status_t *spf_status_rsp;
	struct spf_cmd_basic_rsp *basic_rsp;
	struct gsl_ctxt_ *ctxt;
	uint32_t status = AR_EOK;

	switch (packet->opcode) {
	case APM_CMD_RSP_GET_SPF_STATE:
		spf_status_rsp =
			GPR_PKT_GET_PAYLOAD(struct apm_cmd_rsp_get_spf_status_t, packet);
		ctxt = (struct gsl_ctxt_ *)cb_data;
		gsl_signal_set(&ctxt->rsp_signal, GSL_SIG_EVENT_MASK_SPF_RSP,
			spf_status_rsp->status, NULL);
		__gpr_cmd_free(packet);
		break;
	case GPR_IBASIC_RSP_RESULT:
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, packet);
		ctxt = (struct gsl_ctxt_ *)cb_data;
		/*
		 * Ignore basic rsp for APM_CMD_RSP_GET_SPF_STATE, SPF will send this
		 * with status EFAILED if the APM service is not yet regsitered with
		 * GPR. We treat this as a regular polling timeout and retry sending by
		 * sending the GET_SPF_STATE again after timeout.
		 */
		if (basic_rsp->opcode != APM_CMD_GET_SPF_STATE)
			gsl_signal_set(&ctxt->rsp_signal, GSL_SIG_EVENT_MASK_SPF_RSP,
				basic_rsp->status, packet);
			/* do not free, it will be freed by waiter */
		else
			__gpr_cmd_free(packet);
		break;
	default:
		__gpr_cmd_free(packet);
		status = AR_EFAILED;
		break;
	}

	return status;
}

static gsl_handle_t get_graph_handle(struct gsl_graph *graph)
{
	void **tmp;
	gsl_handle_t hdl = 0;
	uint8_t i;

	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);

	for (i = 0; i < gsl_ctxt.graph_list_size; i++) {
		if (!gsl_ctxt.graph_list[i])
			break;
	}
	if (i == gsl_ctxt.graph_list_size) {
		tmp = gsl_mem_realloc(gsl_ctxt.graph_list,
			sizeof(void *) * ((size_t)gsl_ctxt.graph_list_size),
			sizeof(void *) * ((size_t)gsl_ctxt.graph_list_size +
			(MAX_UC_GRAPHS >> 1)));
		if (!tmp)
			goto exit;

		gsl_ctxt.graph_list_size +=  (MAX_UC_GRAPHS >> 1);
		gsl_ctxt.graph_list = tmp;
	}

	hdl = to_gsl_handle(i);
	graph->src_port = get_src_port(i);
	gsl_ctxt.graph_list[i] = (void *)graph;
	++gsl_ctxt.num_graphs;
exit:
	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
	return hdl;
}

static void release_graph_handle(gsl_handle_t hdl)
{
	int32_t i;

	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);

	i = to_gsl_graph_index(hdl);
	gsl_ctxt.graph_list[i] = NULL;
	--gsl_ctxt.num_graphs;

	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
}

void gsl_get_version(uint32_t *major, uint32_t *minor)
{
	if (!major || !minor)
		return;

	*major = GSL_MAJOR_VERSION;
	*minor = GSL_MINOR_VERSION;
}

static int32_t gsl_do_spf_readiness_check(
	uint32_t max_num_ready_checks, uint32_t ready_check_interval_ms,
	uint32_t proc_id)
{
	uint32_t i = 0, event_flags = 0, spf_status = 0;
	gpr_cmd_alloc_ext_t gpr_args;
	int32_t rc = AR_EOK;
	gpr_packet_t *send_pkt = NULL;

	gpr_args.src_domain_id = GPR_IDS_DOMAIN_ID_APPS_V;
	gpr_args.dst_domain_id = (uint8_t) proc_id;
	gpr_args.src_port = GSL_MAIN_SRC_PORT;
	gpr_args.dst_port = APM_MODULE_INSTANCE_ID;
	gpr_args.opcode = APM_CMD_GET_SPF_STATE;
	gpr_args.token = 0;
	gpr_args.client_data = 0;
	gpr_args.payload_size = 0;
	gpr_args.ret_packet = &send_pkt;

	for (i = 0; i < max_num_ready_checks; ++i) {
		rc = __gpr_cmd_alloc_ext(&gpr_args);
		if (rc) {
			GSL_ERR("Failed to allocate shmem map pkt %d", rc);
			goto exit;
		}

		GSL_LOG_PKT("send_pkt", GSL_MAIN_SRC_PORT, send_pkt, sizeof(*send_pkt),
			NULL, 0);

		rc = __gpr_cmd_async_send(send_pkt);
		if (rc == AR_ENOTREADY) {
			/* Remote side not UP yet. Retry */
			ar_osal_micro_sleep(GSL_TIMEOUT_US(ready_check_interval_ms));
			continue;
		} else if (rc) {
			GSL_ERR("GPR async send failed %d", rc);
			__gpr_cmd_free(send_pkt);
			goto exit;
		}

		GSL_DBG("Wait for Spf readiness rsp");
		rc = gsl_signal_timedwait(&gsl_ctxt.rsp_signal,
			ready_check_interval_ms, &event_flags, &spf_status, NULL);
		if (rc == AR_ETIMEOUT) {
			/* timed out continue polling */
			rc = AR_ENOTREADY;
			continue;
		} else {
			if (event_flags & GSL_SIG_EVENT_MASK_SSR) {
				/** SSR occured, bailout */
				rc = AR_ESUBSYSRESET;
				goto exit;
			} else if (event_flags & GSL_SIG_EVENT_MASK_SPF_RSP) {
				GSL_DBG("Got Spf readiness rsp with %d", spf_status);
				if (spf_status == APM_SPF_STATE_READY) {
					/* Spf is Ready */
					rc = AR_EOK;
					goto exit;
				} else {
					rc = AR_ENOTREADY;
				}
			}
			ar_osal_micro_sleep(GSL_TIMEOUT_US(ready_check_interval_ms));
		}
	}
exit:
	return rc;
}

int32_t gsl_get_driver_data(const uint32_t module_id,
	const struct gsl_key_vector *key_vect, void *data_payload,
	uint32_t *data_payload_size)
{
	AcdbDriverData acdb_req = { 0, };
	AcdbBlob acdb_rsp = { 0, };
	int32_t rc = AR_EOK;

	/* query acdb */
	acdb_req.key_vector.num_keys = key_vect->num_kvps;
	acdb_req.key_vector.graph_key_vector =
		(AcdbKeyValuePair *)key_vect->kvp;
	acdb_req.module_id = module_id;
	acdb_rsp.buf = data_payload;
	acdb_rsp.buf_size = *data_payload_size;
	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &acdb_req, sizeof(acdb_req),
		&acdb_rsp, sizeof(acdb_rsp));
	if (rc != AR_EOK)
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_DATA failed %d", rc);

	*data_payload_size = acdb_rsp.buf_size;
	return rc;
}

int32_t gsl_get_graph_tkvs(const struct gsl_key_vector *graph_key_vect,
	struct gsl_tag_key_vector_list *data_payload)
{
	int32_t rc = AR_EOK;

	if (graph_key_vect == NULL)
		return AR_EBADPARAM;
	/* query acdb */
	rc = acdb_ioctl(ACDB_CMD_GET_GRAPH_TAG_KVS, graph_key_vect,
		sizeof(*graph_key_vect), (void *)data_payload, sizeof(struct gsl_tag_key_vector_list));
	if (rc != AR_EOK)
		GSL_ERR("acdb query ACDB_CMD_GET_GRAPH_TAG_KVS failed %d", rc);

	return rc;
}

int32_t gsl_get_graph_ckvs(const struct gsl_key_vector *graph_key_vect,
	struct gsl_key_vector_list *data_payload)
{

	int32_t rc = AR_EOK;
	AcdbGraphKeyVector cmd_struct;

	if (graph_key_vect == NULL) {
		GSL_ERR("graph_key_vect is NULL");
		return AR_EBADPARAM;
	}

	/* need to construct AcdbKeyVector because it is packed, gsl_kv isn't */
	cmd_struct.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector = (AcdbKeyValuePair *)graph_key_vect->kvp;

	/* query acdb */
	rc = acdb_ioctl(ACDB_CMD_GET_GRAPH_CAL_KVS, &cmd_struct,
		sizeof(cmd_struct), (void *)data_payload, sizeof(struct gsl_key_vector_list));
	if (rc != AR_EOK)
		GSL_ERR("acdb query ACDB_CMD_GET_GRAPH_CAL_KVS failed %d", rc);

	return rc;
}

int32_t gsl_get_driver_module_kvs(uint32_t driver_id,
	struct gsl_key_vector_list *data_payload)
{
	int32_t rc = AR_EOK;

	/* query acdb */
	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_MODULE_KVS, &driver_id,
		sizeof(driver_id), (void *)data_payload, sizeof(struct gsl_key_vector_list));
	if (rc != AR_EOK)
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_MODULE_KVS failed %d", rc);

	return rc;
}

int32_t gsl_get_supported_gkvs(uint32_t *key_ids,
	const uint32_t num_key_ids, struct gsl_key_vector_list *data_payload)
{
	AcdbUintList uint_list = { 0, };
	int32_t rc = AR_EOK;

	/* query acdb */
	uint_list.count = num_key_ids;
	uint_list.list = key_ids;

	rc = acdb_ioctl(ACDB_CMD_GET_SUPPORTED_GKVS, &uint_list,
		sizeof(uint_list), (void *)data_payload, sizeof(struct gsl_key_vector_list));
	if (rc != AR_EOK)
		GSL_ERR("acdb query ACDB_CMD_GET_SUPPORTED_GKVS failed %d", rc);

	return rc;
}

int32_t gsl_init(struct gsl_init_data *init_data)
{
	uint32_t rc = AR_EOK;
	uint32_t supported_ss_mask = 0, tmp_supported_ss_mask = 0;
	uint32_t i = 0, j = 0;
	uint32_t num_master_procs = 0;
	uint32_t *master_procs = NULL;
	uint32_t num_procs = 0;
	struct proc_domain_type *proc_domains = NULL;
	bool_t is_shmem_supported = TRUE;

	ar_log_init();

	rc = gpr_init();
	if (rc) {
		GSL_ERR("gpr init failed %d", rc);
		return rc;
	}

	/* initialize data logging */
	rc = ar_data_log_init();
	if (rc) {
		GSL_ERR("ar data logging init failed %d", rc);
		rc = AR_EOK;
	}

	/* initialize acdb */
	rc = acdb_init((AcdbDataFiles *)init_data->acdb_files,
		(AcdbFile *)init_data->acdb_delta_file);

	if (rc) {
		GSL_ERR("acdb_init failed %d", rc);
		goto deinit_gpr;
	}

	gsl_spf_timeouts_init();

	rc = gsl_sg_pool_init();
	if (rc) {
		GSL_ERR("gsl_sg_pool_init failed %d", rc);
		goto deinit_acdb;
	}

	rc = gsl_global_persist_cal_pool_init();
	if (rc) {
		GSL_ERR("gsl_global_persist_cal_pool_init failed %d", rc);
		goto deinit_sgpool;
	}

	ar_list_init(&gsl_ctxt.acdb_client_list, NULL, NULL);
	ar_osal_mutex_create(&gsl_ctxt.acdb_client_lock);
	gsl_ctxt.graph_list_size = MAX_UC_GRAPHS;
	gsl_ctxt.graph_list = gsl_mem_zalloc(gsl_ctxt.graph_list_size *
				sizeof(void *));
	if (!gsl_ctxt.graph_list) {
		rc = AR_ENOMEMORY;
		goto deinit_gpcpool;
	}

	gsl_ctxt.num_graphs = 0;

	rc = ar_osal_mutex_create(&gsl_ctxt.open_close_lock);
	if (rc) {
		GSL_ERR("ar_osal_mutex_init failed %d", rc);
		goto free_graph_list;
	}

	rc = ar_osal_mutex_create(&gsl_ctxt.graph_hdl_lock);
	if (rc) {
		GSL_ERR("graph hdl lock create failed %d", rc);
		goto destroy_open_close_lock;
	}

	rc = ar_osal_mutex_create(&gsl_ctxt.start_stop_lock);
	if (rc) {
		GSL_ERR("start_stop mutex create failed %d", rc);
		goto destroy_graph_hdl_lock;
	}

	rc = gsl_dp_create_cache_refcount_lock();
	if (rc) {
		GSL_ERR("external mem cache refcount mutex create failed %d", rc);
		goto destroy_start_stop_lock;
	}

	GSL_PKT_LOG_INIT();
	GSL_PKT_LOG_OPEN(AR_FOPEN_WRITE_ONLY);

	/*
	 * use open close_lock here as no sessions will be active at init time
	 * so this lock is available for use to use.
	 */
	rc = gsl_signal_create(&gsl_ctxt.rsp_signal, &gsl_ctxt.open_close_lock);
	if (rc) {
		GSL_ERR("signal create failed %d", rc);
		goto destroy_ext_mem_cache_lock;
	}

	rc = gsl_signal_create(&gsl_ctxt.rtgm_state_info.sig, NULL);
	if (rc) {
		GSL_ERR("signal create failed %d", rc);
		goto destroy_rsp_signal;
	}
	gsl_ctxt.rtgm_state_info.client_op_in_prog = false;
	gsl_ctxt.rtgm_state_info.num_rtgm_in_prog = 0;

	rc = __gpr_cmd_register(GSL_MAIN_SRC_PORT, gsl_main_gpr_callback,
		&gsl_ctxt);
	if (rc) {
		GSL_ERR("gpr register failed");
		goto destroy_rtgm_state_signal;
	}

	rc = gsl_mdf_utils_init();
	if (rc) {
		GSL_ERR("gsl_mdf_utils_init failed %d", rc);
		goto gpr_deregister;
	}

	/* Get no of master proc ids */
	gsl_mdf_utils_get_master_proc_ids(&num_master_procs,
					  master_procs);
	master_procs = gsl_mem_zalloc(
				sizeof(uint32_t)*(num_master_procs));

	if (master_procs == NULL) {
		rc = AR_ENOMEMORY;
		goto gpr_deregister;
	}

	/* Get all master proc ids */
	gsl_mdf_utils_get_master_proc_ids(&num_master_procs,
					  master_procs);
	gsl_mdf_utils_get_proc_domain_info(&proc_domains, &num_procs);
	if (!proc_domains)
		num_procs = 0;

	for (i = 0; i < num_master_procs; i++) {
		/* perform Spf readiness check */
		rc = gsl_do_spf_readiness_check(init_data->max_num_ready_checks,
			init_data->ready_check_interval_ms, master_procs[i]);
		if (rc)
			goto mdf_utils_deinit;

		gsl_mdf_utils_get_supported_ss_info_from_master_proc(
							master_procs[i],
							&supported_ss_mask);
		tmp_supported_ss_mask = supported_ss_mask;
		/* Reset dynamic PD mask. Dynamic PDs will be handled
		 * during use case boundary
		 */
		for (j = 0; j < num_procs; ++j) {
			if (proc_domains[j].proc_type == DYNAMIC_PD)
				supported_ss_mask &=
					~(GSL_GET_SPF_SS_MASK(proc_domains[j].proc_id));
		}

		rc = gsl_send_spf_satellite_info(master_procs[i],
			supported_ss_mask, GSL_MAIN_SRC_PORT, &gsl_ctxt.rsp_signal);
		if (rc) {
			GSL_ERR("gsl_send_spf_satellite_info failed %d", rc);
			goto mdf_utils_deinit;
		}

		rc = gsl_spf_ss_state_init(master_procs[i], tmp_supported_ss_mask,
					   gsl_main_ssr_callback);
		if (rc) {
			GSL_ERR("gsl_spf_ss_state_init failed %d", rc);
			goto mdf_utils_deinit;
		}
		/* @TODO: Remove below code once we rely on UP notifications from Spf */
		gsl_spf_ss_state_set(master_procs[i], AR_SUB_SYS_IDS_MASK,
					//GSL_GET_SPF_SS_MASK(master_procs[i]),
					GSL_SPF_SS_STATE_UP);
	}

	rc = gsl_msg_builder_init(num_master_procs, master_procs);
	if (rc) {
		GSL_ERR("msg builder init failed %d", rc);
		goto spf_ss_state_deinit;
	}

	for (i = 0; i < num_master_procs; i++) {
		gsl_mdf_utils_get_supported_ss_info_from_master_proc(
							master_procs[i],
							&supported_ss_mask);

		/* Reset dynamic PD mask. Dynamic PDs will
		 * be handled during use case boundary
		 */
		for (j = 0; j < num_procs; ++j) {
			if (proc_domains[j].proc_type == DYNAMIC_PD)
				supported_ss_mask &=
					~(GSL_GET_SPF_SS_MASK(proc_domains[j].proc_id));
		}
		__gpr_cmd_is_shared_mem_supported(master_procs[i], &is_shmem_supported);

		if (is_shmem_supported) {
			/* Temp fix: Map memory to other MDF modules.
			 * assume all up by now
			 */
			rc = gsl_mdf_utils_shmem_alloc(supported_ss_mask,
							master_procs[i]);
			if ((rc != AR_EOK) && (rc != AR_EUNSUPPORTED)) {
				GSL_ERR("failed to alloc loaned shmem %d", rc)
					goto msg_builder_deinit;
			}
		}
	}

	rc = gsl_dynamic_module_mgr_init(num_master_procs, master_procs);
	if (rc) {
		GSL_ERR("dynamic module registration failed %d", rc)
		goto msg_builder_deinit;
	}

	for (i = 0; i < num_master_procs; i++) {
		/* retry for up to 2 seconds to help in cases
		 * where ADSP RPC thread not ready
		 *
		 * TODO: Remove this once we are checking for
		 * dynamic download readiness with IPC
		 */
		for (j = 0; j < GSL_DYN_DL_NUM_RETRIES; ++j) {
			rc = gsl_do_load_bootup_dyn_modules(master_procs[i], NULL);
			if (rc)
				ar_osal_micro_sleep(GSL_TIMEOUT_US(GSL_DYN_DL_RETRY_MS));
			else
				break;
		}

		if (rc != AR_EOK && rc != AR_ENOTEXIST) {
			GSL_ERR("dynamic module load failed %d", rc);
			goto dyn_module_mgr_deinit;
		}
	}

	/** initialize gsl rtc layer */
	rc = gsl_rtc_init(gsl_rtc_callback);
	if (rc) {
		GSL_ERR("gsl rtc init failed %d", rc);
		goto dyn_module_mgr_deinit;
	}

	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; i++)
		gsl_ctxt.spf_restart[i] = FALSE;

	GSL_PKT_LOG_CLOSE();
	gsl_mem_free(master_procs);
	return rc;

dyn_module_mgr_deinit:
	gsl_dynamic_module_mgr_deinit();
msg_builder_deinit:
	gsl_msg_builder_deinit();
spf_ss_state_deinit:
	for (j = 0; j < num_master_procs; j++)
		gsl_spf_ss_state_deinit(master_procs[j]);
mdf_utils_deinit:
	for (; j < i; j++)
		gsl_spf_ss_state_deinit(master_procs[j]);
	gsl_mdf_utils_deinit();
gpr_deregister:
	__gpr_cmd_deregister(GSL_MAIN_SRC_PORT);
destroy_rtgm_state_signal:
	gsl_signal_destroy(&gsl_ctxt.rtgm_state_info.sig);
destroy_rsp_signal:
	gsl_signal_destroy(&gsl_ctxt.rsp_signal);
destroy_ext_mem_cache_lock:
	gsl_dp_destroy_cache_refcount_lock();
destroy_start_stop_lock:
	GSL_PKT_LOG_CLOSE();
	ar_osal_mutex_destroy(gsl_ctxt.start_stop_lock);
destroy_graph_hdl_lock:
	ar_osal_mutex_destroy(gsl_ctxt.graph_hdl_lock);
destroy_open_close_lock:
	ar_osal_mutex_destroy(gsl_ctxt.open_close_lock);
free_graph_list:
	gsl_mem_free(gsl_ctxt.graph_list);
deinit_gpcpool:
	gsl_global_persist_cal_pool_deinit();
deinit_sgpool:
	gsl_sg_pool_deinit();
deinit_acdb:
	acdb_deinit();
deinit_gpr:
	ar_data_log_deinit();
	gpr_deinit();
	ar_log_deinit();

	gsl_mem_free(master_procs);
	return rc;
}

void gsl_deinit(void)
{
	uint32_t i;
	uint32_t num_master_procs = 0;
	uint32_t *master_procs = NULL;

	for (uint8_t j = 0; j < gsl_ctxt.graph_list_size; ++j) {
		if (gsl_ctxt.graph_list[j])
			gsl_close(to_gsl_handle(j));
	}

	GSL_PKT_LOG_OPEN(AR_FOPEN_WRITE_ONLY_APPEND);

	/* Get no of master procs */
	gsl_mdf_utils_get_master_proc_ids(&num_master_procs,
					  master_procs);
	master_procs = gsl_mem_zalloc(
				sizeof(uint32_t)*(num_master_procs));

	if (master_procs != NULL) {
		/* Get all master proc ids */
		gsl_mdf_utils_get_master_proc_ids(&num_master_procs,
						master_procs);

		for (i = 0; i < num_master_procs; i++)
			gsl_do_unload_bootup_dyn_modules(master_procs[i], NULL);
	}

	gsl_dynamic_module_mgr_deinit();
	gsl_rtc_deinit();
	gsl_mdf_utils_deinit();
	gsl_msg_builder_deinit();
	if (master_procs != NULL) {
		for (i = 0; i < num_master_procs; i++)
			gsl_spf_ss_state_deinit(master_procs[i]);
		gsl_mem_free(master_procs);
	}
	acdb_deinit();
	gsl_global_persist_cal_pool_deinit();
	gsl_sg_pool_deinit();
	__gpr_cmd_deregister(GSL_MAIN_SRC_PORT);
	gsl_signal_destroy(&gsl_ctxt.rsp_signal);
	gsl_signal_destroy(&gsl_ctxt.rtgm_state_info.sig);
	gsl_dp_destroy_cache_refcount_lock();
	ar_osal_mutex_destroy(gsl_ctxt.open_close_lock);
	ar_osal_mutex_destroy(gsl_ctxt.start_stop_lock);
	ar_osal_mutex_destroy(gsl_ctxt.graph_hdl_lock);
	gsl_mem_free(gsl_ctxt.graph_list);
	ar_data_log_deinit();
	gpr_deinit();
	GSL_PKT_LOG_CLOSE();
	GSL_PKT_LOG_DEINIT();
	ar_log_deinit();
}

int32_t gsl_register_global_event_cb(gsl_global_cb_func_ptr global_cb,
	void *client_data)
{
	gsl_ctxt.global_cb = global_cb;
	gsl_ctxt.global_cb_client_data = client_data;

	return AR_EOK;
}

int32_t gsl_open(const struct gsl_key_vector *graph_key_vect,
	const struct gsl_key_vector *cal_key_vect, gsl_handle_t *graph_handle)
{
	int32_t rc = AR_EOK;
	struct gsl_graph *graph = NULL;
	gsl_handle_t hdl = 0;
	uint32_t supported_ss_mask = 0;
	uint32_t num_procs = 0;
	struct proc_domain_type *proc_domains = NULL;
	bool_t is_shmem_supported = TRUE;
	uint8_t i = 0;
	uint8_t j = 0;
	int32_t ss_retry_count = 10;

	if (graph_handle == NULL)
		return AR_EBADPARAM;

	GSL_PKT_LOG_OPEN(AR_FOPEN_WRITE_ONLY_APPEND);

	graph = gsl_mem_zalloc(sizeof(struct gsl_graph));
	if (graph == NULL)
		return AR_ENOMEMORY;

	/** get graph handle and assign a source port */
	hdl = get_graph_handle(graph);
	if (!hdl) {
		rc = AR_ENOMEMORY;
		goto cleanup;
	}

	GSL_MUTEX_LOCK(gsl_ctxt.open_close_lock);
	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; i++) {
		if (gsl_ctxt.spf_restart[i]) {

			// handle master proc restarting
			gsl_shmem_remap_pre_alloc(i);
			gsl_mdf_utils_get_supported_ss_info_from_master_proc(i, &supported_ss_mask);
			gsl_mdf_utils_get_proc_domain_info(&proc_domains, &num_procs);
			if (!proc_domains)
				num_procs = 0;
			/* Reset dynamic PD mask. It will be handled after dynamic PD is initialized. */
			for (j = 0; j < num_procs; ++j) {
				if (proc_domains[j].proc_type == DYNAMIC_PD)
					supported_ss_mask &= ~(GSL_GET_SPF_SS_MASK(proc_domains[j].proc_id));
			}
			rc = gsl_send_spf_satellite_info(i, supported_ss_mask,
				GSL_MAIN_SRC_PORT, &gsl_ctxt.rsp_signal);
			if (rc) {
				GSL_ERR("gsl_send_spf_satellite_info failed for master_proc %d rc %d", i, rc);
				continue;
			}

			__gpr_cmd_is_shared_mem_supported(i, &is_shmem_supported);
			if (is_shmem_supported) {
				rc = gsl_mdf_utils_shmem_alloc(supported_ss_mask, i);
				if (rc != AR_EOK && rc != AR_EUNSUPPORTED) {
					GSL_ERR("failed to alloc loaned shmem for master_proc %d rc %d", i, rc);
					continue;
				}
			}
            /* retry for up to 3 seconds to help in cases
			    where ADSP RPC thread not ready */
			for (j = 0; j < GSL_DYN_DL_NUM_RETRIES_SSR; ++j) {
				rc = gsl_do_load_bootup_dyn_modules(i, NULL);
				if (rc) {
					ar_osal_micro_sleep(GSL_TIMEOUT_US(GSL_DYN_DL_RETRY_MS));
				} else {
					gsl_ctxt.spf_restart[i] = FALSE;
					break;
				}
			}
		}
	}
	GSL_MUTEX_UNLOCK(gsl_ctxt.open_close_lock);

    /*
     * Initialize graph instance and register to GPR to
     * receive/send commands/events/data from spf
     * State is updated under lock to sync with SSR
     */
	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
	rc = gsl_graph_init(graph);
	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
	if (rc) {
		GSL_ERR("graph_init failed %d", rc);
		goto release_handle;
	}

	while (ss_retry_count--) {
		rc = gsl_graph_open(graph, graph_key_vect, cal_key_vect, gsl_ctxt.open_close_lock);
		if (AR_ESUBSYSRESET == rc) {
			GSL_INFO("wait subsystem online, remaining retry count: %d", ss_retry_count);
			ar_osal_micro_sleep(GSL_TIMEOUT_US(GSL_SS_RETRY_MS));
			continue;
		} else if (rc) {
			GSL_ERR("graph_open failed %d", rc);
			goto deinit;
		}
		break;
	}
    // If it comes out from while() with a AR_ESUBSYSRESET even after ss_retry_count's retry,
    // we should goto deinit.
	if (AR_ESUBSYSRESET == rc)
		goto deinit;

	*graph_handle = hdl;

	if (gsl_ctxt.rtc_conn_active)
		graph->rtc_conn_active = true;

	return rc;

deinit:
	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
	gsl_graph_deinit(graph);
	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);
release_handle:
	release_graph_handle(hdl);
cleanup:
	gsl_mem_free(graph);
	GSL_PKT_LOG_CLOSE();
	return rc;
}

int32_t gsl_close(gsl_handle_t graph_handle)
{
	int32_t rc = AR_EOK;
	struct gsl_graph *graph = NULL;

	/* if RTGM is in-progress block close */
	rc = gsl_main_start_client_op_blocking(&gsl_ctxt);
	if (rc)
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph)
		return AR_EBADPARAM;

	/** Stop graph if not already done */
	rc = gsl_graph_stop(graph, gsl_ctxt.start_stop_lock);
	if (rc && (rc != AR_EALREADY))
		GSL_ERR("graph stop failed %d", rc);

	rc = gsl_graph_close(graph, gsl_ctxt.open_close_lock);
	if (rc)
		GSL_ERR("gsl_graph_close failed %d", rc);

	release_graph_handle(graph_handle);

	GSL_MUTEX_LOCK(gsl_ctxt.graph_hdl_lock);
	gsl_graph_deinit(graph);
	GSL_MUTEX_UNLOCK(gsl_ctxt.graph_hdl_lock);

	gsl_mem_free(graph);

	gsl_main_end_client_op(&gsl_ctxt);
	GSL_PKT_LOG_CLOSE();

	return rc;
}

int32_t gsl_set_cal(gsl_handle_t graph_handle,
	const struct gsl_key_vector *graph_key_vect,
	const struct gsl_key_vector *cal_key_vect)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	/* check if graph is in SSR */
	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!cal_key_vect) {
		GSL_ERR("cal key vector not specified");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_set_cal(graph, graph_key_vect, cal_key_vect,
		gsl_ctxt.open_close_lock);
	if (rc != AR_EOK && rc != AR_ENOTEXIST)	{
		GSL_ERR("graph set cal failed: %d", rc);
		goto exit;
	}
	/* in-cases where the new CKV is same as old CKV we should not fail */
	if (rc == AR_ENOTEXIST)
		rc = AR_EOK;
exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_set_config(gsl_handle_t graph_handle,
	const struct gsl_key_vector *graph_key_vect,
	uint32_t tag, const struct gsl_key_vector *tag_key_vect)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!tag_key_vect) {
		GSL_ERR("tag key vector not specified");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_set_config(graph, graph_key_vect, tag, tag_key_vect,
		NULL);
	if (rc)
		GSL_ERR("graph set config failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_set_custom_config(gsl_handle_t graph_handle,
	const uint8_t *payload, const uint32_t payload_size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!payload || (payload_size == 0)) {
		GSL_ERR("payload is null or size is zero");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_set_custom_config(graph, payload, payload_size, NULL);
	if (rc)
		GSL_ERR("graph set custom config failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_set_tagged_custom_config(gsl_handle_t graph_handle, uint32_t tag,
	const uint8_t *payload, const size_t payload_size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!payload || (payload_size == 0)) {
		GSL_ERR("payload is null or size is zero");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_set_tagged_custom_config(graph, tag, payload,
		payload_size, NULL);
	if (rc)
		GSL_ERR("graph set tagged custom config failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_set_tagged_custom_config_persist(gsl_handle_t graph_handle,
	uint32_t tag, const uint8_t *payload, const uint32_t payload_size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!payload || (payload_size == 0)) {
		GSL_ERR("payload is null or size is zero");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_set_tagged_custom_config_persist(graph, tag, payload,
		payload_size, gsl_ctxt.start_stop_lock);
	if (rc)
		GSL_ERR("graph set tagged custom config persist failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_get_custom_config(gsl_handle_t graph_handle, uint8_t *payload,
	uint32_t size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!payload || (size == 0)) {
		GSL_ERR("payload is null or size is zero");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_get_custom_config(graph, payload, size, NULL);
	if (rc)
		GSL_ERR("graph get custom config failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_get_tagged_custom_config(gsl_handle_t graph_handle, uint32_t tag,
	uint8_t *payload, uint32_t *size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	if (!gsl_main_start_client_op(&gsl_ctxt))
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!payload || (size == 0)) {
		GSL_ERR("payload is null or size is zero");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_get_tagged_custom_config(graph, tag, payload, size, NULL);
	if (rc)
		GSL_ERR("graph get tagged custom config failed: %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_ioctl(gsl_handle_t graph_handle,
	enum gsl_cmd_id cmd_id, void *cmd_payload, size_t cmd_payload_sz)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;
	uint32_t i;
	struct gsl_cmd_graph_select *ag = NULL, *cg = NULL;
	struct gsl_cmd_remove_graph *rg = NULL;

	if (!gsl_main_start_client_op(&gsl_ctxt)) {
		rc = AR_ENOTREADY;
		goto exit;
	}

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	switch (cmd_id) {
	case GSL_CMD_PREPARE:
		rc = gsl_graph_prepare(graph, gsl_ctxt.start_stop_lock);
		if (rc)
			GSL_ERR("graph prepare ioctl failed %d", rc);
		break;

	case GSL_CMD_START:
		rc = gsl_graph_start(graph, gsl_ctxt.start_stop_lock);
		if (rc)
			GSL_ERR("graph start ioctl failed %d", rc);
		break;

	case GSL_CMD_SUSPEND:
		rc = gsl_graph_suspend(graph, gsl_ctxt.start_stop_lock);
		if (rc)
			GSL_ERR("graph suspend ioctl failed %d", rc);
		break;

	case GSL_CMD_STOP:
		if (cmd_payload &&
			(cmd_payload_sz != sizeof(struct gsl_cmd_properties))) {
			rc = AR_EBADPARAM;
			break;
		}

		if (cmd_payload)
			rc = gsl_graph_stop_with_properties(graph,
				(struct gsl_cmd_properties *)cmd_payload,
				gsl_ctxt.start_stop_lock);
		else
			rc = gsl_graph_stop(graph, gsl_ctxt.start_stop_lock);
		if (rc)
			GSL_ERR("graph stop ioctl failed %d", rc);
		break;

	case GSL_CMD_CONFIGURE_READ_PARAMS:
		if (cmd_payload_sz !=
			sizeof(struct gsl_cmd_configure_read_write_params)) {
			rc = AR_EBADPARAM;
			GSL_ERR("cfg read params ioctl, inv payload size %d expected %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_configure_read_write_params));
			break;
		}

		rc = gsl_graph_config_data_path(graph, GSL_DATA_DIR_READ,
			(struct gsl_cmd_configure_read_write_params *) cmd_payload);
		if (rc)
			GSL_ERR("configure read params ioctl failed %d", rc);
		break;

	case GSL_CMD_CONFIGURE_WRITE_PARAMS:
		if (cmd_payload_sz !=
			sizeof(struct gsl_cmd_configure_read_write_params)) {
			rc = AR_EBADPARAM;
			GSL_ERR("cfg write params ioctl, inv payload size %d expected %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_configure_read_write_params));
			break;
		}

		rc = gsl_graph_config_data_path(graph, GSL_DATA_DIR_WRITE,
			(struct gsl_cmd_configure_read_write_params *) cmd_payload);
		if (rc)
			GSL_ERR("configure write params ioctl failed %d", rc);
		break;

	case GSL_CMD_GET_READ_BUFF_INFO:
		if (cmd_payload_sz < sizeof(struct gsl_cmd_get_shmem_buf_info)) {
			rc = AR_EBADPARAM;
			GSL_ERR("read buff info ioctl, inv payload size %d expected gt %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_get_shmem_buf_info));
			break;
		}

		rc = gsl_dp_get_buff_info(&graph->read_info,
			(struct gsl_cmd_get_shmem_buf_info *)cmd_payload);
		if (rc)
			GSL_ERR("get read params ioctl failed %d", rc);
		break;

	case GSL_CMD_GET_WRITE_BUFF_INFO:
		if (cmd_payload_sz < sizeof(struct gsl_cmd_get_shmem_buf_info)) {
			rc = AR_EBADPARAM;
			GSL_ERR("write buff info ioctl, inv payload size %d, expected %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_get_shmem_buf_info));
			break;
		}

		rc = gsl_dp_get_buff_info(&graph->write_info,
			(struct gsl_cmd_get_shmem_buf_info *)cmd_payload);
		if (rc)
			GSL_ERR("get write params ioctl failed %d", rc);
		break;

	case GSL_CMD_GET_READ_POS_BUFF_INFO:
		if (cmd_payload_sz < sizeof(struct gsl_cmd_get_shmem_buf_info)) {
			rc = AR_EBADPARAM;
			GSL_ERR("get rd pos buf ioctl, inv payload size %d expected gt %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_get_shmem_buf_info));
			break;
		}

		rc = gsl_dp_get_pos_buff_info(&graph->read_info,
			(struct gsl_cmd_get_shmem_buf_info *)cmd_payload);
		if (rc)
			GSL_ERR("get rd pos buf ioctl failed %d", rc);
		break;

	case GSL_CMD_GET_WRITE_POS_BUFF_INFO:
		if (cmd_payload_sz < sizeof(struct gsl_cmd_get_shmem_buf_info)) {
			rc = AR_EBADPARAM;
			GSL_ERR("get wr pos buf ioctl, inv payload size %d expected gt %d",
				cmd_payload_sz,
				sizeof(struct gsl_cmd_get_shmem_buf_info));
			break;
		}

		rc = gsl_dp_get_pos_buff_info(&graph->write_info,
			(struct gsl_cmd_get_shmem_buf_info *)cmd_payload);
		if (rc)
			GSL_ERR("get wr pos buf ioctl failed %d", rc);
		break;

	case GSL_CMD_FREE_READ_BUFF:
		for (i = 0; i < graph->write_info.config.num_buffs; ++i)
			gsl_msg_free(&graph->write_info.buff_list[i].gsl_msg);
		break;

	case GSL_CMD_FREE_WRITE_BUFF:
		for (i = 0; i < graph->read_info.config.num_buffs; ++i)
			gsl_msg_free(&graph->read_info.buff_list[i].gsl_msg);
		break;

	case GSL_CMD_EOS:
		rc = gsl_dp_write_send_eos(&graph->write_info);
		if (rc)
			GSL_ERR("eos ioctl failed %d", rc);
		break;

	case GSL_CMD_REGISTER_CUSTOM_EVENT:
		if (cmd_payload_sz < sizeof(struct gsl_cmd_register_custom_event)) {
			rc = AR_EBADPARAM;
			GSL_ERR("reg cust event ioctl, inv payload size %d, expected %d",
				cmd_payload_sz,	sizeof(struct gsl_cmd_register_custom_event));
			break;
		}

		rc = gsl_graph_register_custom_event(graph,
			(struct gsl_cmd_register_custom_event *) cmd_payload);
		if (rc)
			GSL_ERR("register custom event failed %d", rc);
		break;

	case GSL_CMD_FLUSH:
		rc = gsl_graph_flush(graph, gsl_ctxt.open_close_lock);
		if (rc)
			GSL_ERR("graph flush ioctl failed %d", rc);
		break;

	case GSL_CMD_ADD_GRAPH:
		ag = (struct gsl_cmd_graph_select *)cmd_payload;

		if (!ag || !ag->graph_key_vector.kvp ||
			(ag->graph_key_vector.num_kvps == 0)) {
			GSL_ERR("add_graph: graph key vector not specified");
			break;
		}
		rc = gsl_graph_add_new(graph, ag, gsl_ctxt.open_close_lock);
		if (rc)
			GSL_ERR("add graph ioctl failed %d", rc);
		break;

	case GSL_CMD_REMOVE_GRAPH:
		rg = (struct gsl_cmd_remove_graph *)cmd_payload;

		if (!rg || !rg->graph_key_vector.kvp ||
			(rg->graph_key_vector.num_kvps == 0)) {
			GSL_ERR("remove_graph: graph key vector not specified");
			break;
		}
		rc = gsl_graph_remove_old(graph, rg, gsl_ctxt.open_close_lock,
			gsl_ctxt.start_stop_lock);
		if (rc)
			GSL_ERR("remove graph ioctl failed %d", rc);
		break;

	case GSL_CMD_CHANGE_GRAPH:
		cg = (struct gsl_cmd_graph_select *)cmd_payload;

		if (!cg || !cg->graph_key_vector.kvp ||
			(cg->graph_key_vector.num_kvps == 0)) {
			GSL_ERR("change_graph: graph key vector not specified");
			break;
		}
		rc = gsl_graph_change(graph, cg, gsl_ctxt.open_close_lock);
		if (rc)
			GSL_ERR("change graph ioctl failed %d", rc);
		break;

	case GSL_CMD_CLOSE_WITH_PROPS:
		if (cmd_payload &&
			(cmd_payload_sz != sizeof(struct gsl_cmd_properties))) {
			rc = AR_EBADPARAM;
			break;
		}
		rc = gsl_graph_close_with_properties(graph,
			(struct gsl_cmd_properties *)cmd_payload,
			gsl_ctxt.open_close_lock);
		if (rc)
			GSL_ERR("close with properties ioctl failed %d", rc);
		break;

	case GSL_CMD_QUERY_GRAPH_DELAY:
	case GSL_CMD_MAX:
		break;

	}

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_read(gsl_handle_t graph_handle, uint32_t tag,
	struct gsl_buff *buff, uint32_t *filled_size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	GSL_VERBOSE("ENTER handle=%d, buff size=%d", graph_handle, buff->size);

	/* if RTGM is in-progress block read */
	rc = gsl_main_start_client_op_blocking(&gsl_ctxt);
	if (rc)
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!buff) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_read(graph, tag, buff, filled_size);
	if (rc != AR_EOK && rc != AR_ENORESOURCE)
		GSL_ERR("gsl_graph_read failed err %d", rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_write(gsl_handle_t graph_handle, uint32_t tag,
	struct gsl_buff *buff, uint32_t *consumed_size)
{
	struct gsl_graph *graph;
	int32_t rc = AR_EOK;

	GSL_VERBOSE("ENTER handle=%d, buff size=%d", graph_handle, buff->size);

	/* if RTGM is in-progress block write */
	rc = gsl_main_start_client_op_blocking(&gsl_ctxt);
	if (rc)
		return rc;

	graph = to_gsl_graph(graph_handle);
	if (!graph) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (gsl_graph_get_state(graph) == GRAPH_ERROR ||
		gsl_graph_get_state(graph) == GRAPH_ERROR_ALLOW_CLEANUP) {
		rc = AR_ESUBSYSRESET;
		goto exit;
	}

	if (!buff) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_graph_write(graph, tag, buff, consumed_size);
	if (rc != AR_EOK && rc != AR_ENORESOURCE)
		GSL_ERR("gsl_graph_write failed: consumed_size:%d, rc:%d",
			*consumed_size, rc);

exit:
	gsl_main_end_client_op(&gsl_ctxt);

	return rc;
}

int32_t gsl_register_event_cb(gsl_handle_t graph_handle,
	gsl_cb_func_ptr cb, void *client_data)
{
	struct gsl_graph *graph = NULL;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	graph = to_gsl_graph(graph_handle);
	if (!graph)
		return AR_EBADPARAM;

	graph->cb = cb;
	graph->client_data = client_data;

	return AR_EOK;
}

int32_t gsl_get_tagged_data(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag,
	struct gsl_key_vector *tag_key_vect, uint8_t *payload,
	size_t *payload_size)
{
	int32_t rc = AR_EOK;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	if (!graph_key_vect)
		return AR_EBADPARAM;

	if (!payload_size)
		return AR_EBADPARAM;

	rc = gsl_graph_get_tagged_data(graph_key_vect, tag, tag_key_vect,
		payload, payload_size);

	return rc;
}

int32_t gsl_get_tagged_module_info(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag,
	struct gsl_module_id_info **module_info, uint32_t *module_info_size)
{
	int32_t rc = AR_EOK;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	if (!graph_key_vect)
		return AR_EBADPARAM;

	if (!module_info || !module_info_size)
		return AR_EBADPARAM;

	*module_info = NULL;
	*module_info_size = 0;
	rc = gsl_graph_get_module_tag_info(graph_key_vect, tag,
		module_info, module_info_size);

	return rc;
}

int32_t gsl_get_tags_with_module_info(
	const struct gsl_key_vector *graph_key_vect, void *tag_module_info,
	size_t *tag_module_info_size)
{
	int32_t rc = AR_EOK;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	if (!graph_key_vect)
		return AR_EBADPARAM;

	if (!tag_module_info_size)
		return AR_EBADPARAM;

	rc = gsl_graph_get_tags_with_module_info(graph_key_vect,
		(struct gsl_tag_module_info *)tag_module_info,
		tag_module_info_size);

	return rc;
}

int32_t gsl_enable_acdb_persistence(uint8_t enable_flag)
{
	return acdb_ioctl(ACDB_CMD_ENABLE_PERSISTANCE, &enable_flag,
		sizeof(enable_flag), NULL, 0);
}

int32_t gsl_set_cal_data_to_acdb(
	const struct gsl_key_vector *graph_key_vect,
	const struct gsl_key_vector *cal_key_vect,  uint8_t *payload,
	uint32_t payload_size)
{
	int32_t rc = AR_EOK;
	AcdbSetCalDataReq cmd_struct;

	cmd_struct.graph_key_vector.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector.graph_key_vector =
		(AcdbKeyValuePair *) graph_key_vect->kvp;
	cmd_struct.cal_key_vector.num_keys = cal_key_vect->num_kvps;
	cmd_struct.cal_key_vector.graph_key_vector
		= (AcdbKeyValuePair *)cal_key_vect->kvp;
	cmd_struct.cal_blob_size = payload_size;
	cmd_struct.cal_blob = payload;

	rc = acdb_ioctl(ACDB_CMD_SET_CAL_DATA, &cmd_struct,
		sizeof(cmd_struct), NULL, 0);
	if (rc)
		GSL_ERR("acdb set calibration data failed with %d", rc);

	return rc;
}

int32_t gsl_get_cal_data_from_acdb(
	const struct gsl_key_vector *graph_key_vect,
	const struct gsl_key_vector *cal_key_vect, uint32_t num_modules,
	uint8_t *param_list, void *payload, uint32_t *payload_size)
{
	int32_t rc = AR_EOK;
	AcdbGetCalDataReq cmd_struct;
	AcdbBlob rsp_struct = { 0 };

	if (!payload_size)
		return AR_EBADPARAM;

	cmd_struct.graph_key_vector.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector.graph_key_vector =
		(AcdbKeyValuePair *) graph_key_vect->kvp;
	cmd_struct.cal_key_vector.num_keys = cal_key_vect->num_kvps;
	cmd_struct.cal_key_vector.graph_key_vector
		= (AcdbKeyValuePair *)cal_key_vect->kvp;
	cmd_struct.num_module_instance = num_modules;
	cmd_struct.instance_param_list = (AcdbModuleParamList *)param_list;

	if (payload) {
		rsp_struct.buf = payload;
		rsp_struct.buf_size = *payload_size;
	}

	rc = acdb_ioctl(ACDB_CMD_GET_CAL_DATA, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc)
		GSL_ERR("acdb get calibration data failed with %d", rc);

	*payload_size = rsp_struct.buf_size;

	return rc;
}

int32_t gsl_set_tag_data_to_acdb(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag_id,
	const struct gsl_key_vector *tag_key_vect, uint8_t *payload,
	uint32_t payload_size)
{
	int32_t rc = AR_EOK;
	AcdbSetTagDataReq cmd_struct;

	cmd_struct.graph_key_vector.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector.graph_key_vector =
		(AcdbKeyValuePair *) graph_key_vect->kvp;
	cmd_struct.module_tag.tag_id = tag_id;
	cmd_struct.module_tag.tag_key_vector.num_keys = tag_key_vect->num_kvps;
	cmd_struct.module_tag.tag_key_vector.graph_key_vector
		= (AcdbKeyValuePair *)tag_key_vect->kvp;
	cmd_struct.blob_size = payload_size;
	cmd_struct.blob = payload;

	rc = acdb_ioctl(ACDB_CMD_SET_TAG_DATA, &cmd_struct,
		sizeof(cmd_struct), NULL, 0);
	if (rc)
		GSL_ERR("acdb set tag data failed with %d", rc);

	return rc;
}

int32_t gsl_get_tag_data_from_acdb(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag_id,
	const struct gsl_key_vector *tag_key_vect, uint32_t num_modules,
	uint8_t *param_list, void *payload, uint32_t *payload_size)
{
	int32_t rc = AR_EOK;
	AcdbGetTagDataReq cmd_struct;
	AcdbBlob rsp_struct = { 0 };

	if (!payload_size)
		return AR_EBADPARAM;

	cmd_struct.graph_key_vector.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector.graph_key_vector =
		(AcdbKeyValuePair *) graph_key_vect->kvp;
	cmd_struct.module_tag.tag_id = tag_id;
	cmd_struct.module_tag.tag_key_vector.num_keys = tag_key_vect->num_kvps;
	cmd_struct.module_tag.tag_key_vector.graph_key_vector =
		(AcdbKeyValuePair *) tag_key_vect->kvp;
	cmd_struct.num_module_instance = num_modules;
	cmd_struct.instance_param_list = (AcdbModuleParamList *)param_list;

	if (payload) {
		rsp_struct.buf = payload;
		rsp_struct.buf_size = *payload_size;
	}

	rc = acdb_ioctl(ACDB_CMD_GET_TAG_DATA, &cmd_struct,
		sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc)
		GSL_ERR("acdb get tag data failed with %d", rc);

	*payload_size = rsp_struct.buf_size;

	return rc;
}

int32_t gsl_set_temp_path_to_acdb(uint32_t path_length, const char_t *temp_path)
{
	int32_t rc = AR_EOK;
	AcdbSetTempPathReq cmd_struct;

	cmd_struct.path_length = path_length;

	ar_strcpy((char_t *)cmd_struct.path, MAX_FILENAME_LENGTH - 1,
		temp_path, path_length);

	rc = acdb_ioctl(ACDB_CMD_SET_TEMP_PATH, &cmd_struct,
		sizeof(cmd_struct), NULL, 0);
	if (rc)
		GSL_ERR("acdb set temp path failed with %d", rc);

	return rc;
}

int32_t gsl_get_graph_alias(const struct gsl_key_vector *graph_key_vect,
	char_t *alias, uint32_t *alias_len)
{
	int32_t rc = AR_EOK;
	AcdbString rsp_struct = { 0, };
	AcdbGraphKeyVector cmd_struct;

	/* need to construct AcdbKeyVector because it is packed, gsl_kv isn't */

	cmd_struct.num_keys = graph_key_vect->num_kvps;
	cmd_struct.graph_key_vector = (AcdbKeyValuePair *)graph_key_vect->kvp;

	rsp_struct.length = *alias_len;
	rsp_struct.string = alias;

	rc = acdb_ioctl(ACDB_CMD_GET_GRAPH_ALIAS, &cmd_struct, sizeof(cmd_struct),
		&rsp_struct, sizeof(rsp_struct));
	*alias_len = rsp_struct.length;
	if (rc)
		GSL_ERR("acdb get graph alias failed %d, len %d", rc, *alias_len);

	return rc;
}

int32_t gsl_get_processed_buff_cnt(gsl_handle_t graph_handle,
	enum gsl_data_dir dir, uint32_t *cnt)
{
	struct gsl_graph *graph;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	graph = to_gsl_graph(graph_handle);
	if (!graph)
		return AR_EBADPARAM;

	if (gsl_graph_get_state(graph) == GRAPH_ERROR)
		return AR_ESUBSYSRESET;

	if (dir == GSL_DATA_DIR_READ)
		*cnt = gsl_dp_get_processed_buff_cnt(&graph->read_info);
	else
		*cnt = gsl_dp_get_processed_buff_cnt(&graph->write_info);

	return AR_EOK;
}

int32_t gsl_get_avail_buffer_size(gsl_handle_t graph_handle, enum gsl_data_dir dir,
	uint32_t *bytes)
{
	struct gsl_graph *graph;

	/* no need to synchronize with rtgm as it doesnt do anything with spf */

	graph = to_gsl_graph(graph_handle);
	if (!graph)
		return AR_EBADPARAM;

	if (gsl_graph_get_state(graph) == GRAPH_ERROR)
		return AR_ESUBSYSRESET;

	if (dir == GSL_DATA_DIR_READ)
		*bytes = gsl_dp_get_avail_buffer_size(&graph->read_info);
	else
		*bytes = gsl_dp_get_avail_buffer_size(&graph->write_info);

	return AR_EOK;
}

int32_t gsl_add_database(struct gsl_acdb_data_files *acdb_data_files,
	struct gsl_acdb_file *writable_file_path,
	gsl_acdb_handle_t *acdb_handle)
{
	int32_t rc = AR_EOK;
	acdb_handle_t acdb_hdl;
	struct gsl_acdb_client_info *client = NULL;

	client = gsl_mem_zalloc(sizeof(struct gsl_acdb_client_info));
	if (!client)
		return AR_ENOMEMORY;
	GSL_MUTEX_LOCK(gsl_ctxt.acdb_client_lock);
	rc = acdb_add_database((AcdbDatabaseFiles *)acdb_data_files,
					(AcdbFile *)writable_file_path, &acdb_hdl);
	if (rc != AR_EOK) {
		GSL_ERR("add acdb database into global heap failure");
		goto exit;
	}
	rc = gsl_do_load_bootup_dyn_modules(AR_DEFAULT_DSP,
				(gsl_acdb_handle_t)acdb_hdl);
	if (rc) {
		GSL_ERR("load bootup dync modules failure when adding acdb database");
		goto remove_acdb;
	}
	gsl_memcpy((uint8_t *)&client->acdb_files,
		sizeof(struct gsl_acdb_data_files),
		acdb_data_files, sizeof(struct gsl_acdb_data_files));

	if (writable_file_path != NULL)
		gsl_memcpy((uint8_t *)&client->acdb_delta_file,
				sizeof(struct gsl_acdb_file),
				writable_file_path, sizeof(struct gsl_acdb_file));

	client->acdb_handle = (gsl_acdb_handle_t)acdb_hdl;
	ar_list_init_node(&client->node);
	rc = ar_list_add_tail(&gsl_ctxt.acdb_client_list, &client->node);
	*acdb_handle = (gsl_acdb_handle_t)acdb_hdl;
	GSL_MUTEX_UNLOCK(gsl_ctxt.acdb_client_lock);
	return rc;

remove_acdb:
	acdb_remove_database(&acdb_hdl);
exit:
	gsl_mem_free(client);
	GSL_MUTEX_UNLOCK(gsl_ctxt.acdb_client_lock);
	return rc;
}

int32_t gsl_remove_database(gsl_acdb_handle_t acdb_handle)
{
	uint32_t rc = AR_EOK;
	ar_list_node_t *client_node = NULL;
	struct gsl_acdb_client_info *client = NULL;
	bool_t client_found = FALSE;

	GSL_MUTEX_LOCK(gsl_ctxt.acdb_client_lock);

	ar_list_for_each_entry(client_node, &gsl_ctxt.acdb_client_list) {
		client = get_container_base(client_node,
					struct gsl_acdb_client_info, node);
		if (acdb_handle == client->acdb_handle) {
			client_found = TRUE;
			break;
		}
	}

	if (client_found == FALSE) {
		GSL_ERR("invalid acdb handle");
		rc = AR_EBADPARAM;
		goto exit;
	}

	rc = gsl_do_unload_bootup_dyn_modules(AR_DEFAULT_DSP, acdb_handle);
	if (rc) {
		GSL_ERR("deregister dyn module by handle exited");
		goto exit;
	}

	rc = acdb_remove_database(&client->acdb_handle);
	if (rc) {
		GSL_ERR("remove acdb files from data base exited");
		goto exit;
	}

	ar_list_delete(&gsl_ctxt.acdb_client_list, &client->node);
exit:
	GSL_MUTEX_UNLOCK(gsl_ctxt.acdb_client_lock);
	return rc;
}
