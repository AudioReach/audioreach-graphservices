/**
 * \file ar_util_err_detection.c
 *
 * \brief
 *		SPF error detection framework
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "ar_util_err_detection.h"
#include "ar_osal_error.h"
#include "ar_util_list.h"
#include "ar_osal_log.h"
#include "ar_osal_heap.h"
#include "ar_osal_timer.h"
#include "apm_api.h"

#define MAX_TIMEOUTS_IN_PERIOD 7
#define MAX_EDUPLICATE_IN_PERIOD 60
#define ACCUMULATION_PERIOD_MS (30*1000) /* 30 secs */
#define MIN_TIME_ANY_RESTART_MS (60*1000) /* 1 minute */
#define MIN_TIME_EDUPLICATE_RESTART_MS (10*60*1000) /* 10 minutes */

/* Goes to zero if would overflow. Only used to compare to cur time (> zero) */
#define overflow_safe_add(x,y) (UINT64_MAX - (x) > (y)) ? ((x) + (y)) : 0;

#define AR_ERR_DET_LOG_TAG "AR Error Detection Logger"
#define AR_ERR_DET_ERR(...) AR_LOG_ERR(AR_ERR_DET_LOG_TAG, __VA_ARGS__)
#define AR_ERR_DET_DBG(...) AR_LOG_DEBUG(AR_ERR_DET_LOG_TAG, __VA_ARGS__)
#define AR_ERR_DET_INFO(...) AR_LOG_INFO(AR_ERR_DET_LOG_TAG, __VA_ARGS__)

//TODO move this into the ar list header. Use name from GSL verison?
#define get_struc_base(p, type, member) ((type *)( \
	(int8_t *)(p)- \
	(uintptr_t)(&((type *)0)->member)))

typedef struct err_det_ctxt err_det_ctxt;

struct err_det_ctxt {
	ar_list_node_t node;

	uint32_t master_proc_handle;
	uint64_t last_restart_time_ms;

	uint32_t num_timeouts_curr_period;
	uint64_t first_timeout_time_ms;

	uint32_t num_eduplicate_curr_period;
	uint64_t first_eduplicate_time_ms;

	void* client_data;
};

static ar_list_t context_list;
static bool_t list_inited = false;

static err_det_ctxt* find_ctxt_by_proc_handle(uint32_t proc_handle) {
	ar_list_node_t *curr;
	err_det_ctxt *ctxt = NULL;

	if (!list_inited || ar_list_is_empty(&context_list))
		return NULL;

	ar_list_for_each_entry(curr, &context_list) {
		ctxt = get_struc_base(curr, err_det_ctxt, node);
		if (ctxt->master_proc_handle == proc_handle)
			return ctxt;
	}

	AR_ERR_DET_ERR("Unable to find context for proc ID %d", proc_handle);
	return NULL;
}

int32_t ar_err_det_init_ctxt(uint32_t proc_handle, void *client_data)
{
	int32_t status = AR_EOK;
	err_det_ctxt *new_ctxt;
	ar_heap_info heap_info = {
		.align_bytes = AR_HEAP_ALIGN_DEFAULT,
		.pool_type = AR_HEAP_POOL_DEFAULT,
		.heap_id = AR_HEAP_ID_DEFAULT,
		.tag = AR_HEAP_TAG_DEFAULT
	};

	if (!list_inited) {
		status = ar_list_init(&context_list, NULL, NULL);
		if (AR_EOK != status)
			goto end;

		list_inited = true;
	}

	if (find_ctxt_by_proc_handle(proc_handle) != NULL) {
		status = AR_EALREADY;
		goto end;
	}

	new_ctxt = ar_heap_calloc(sizeof(struct err_det_ctxt), &heap_info);
	if (!new_ctxt) {
		status = AR_ENOMEMORY;
		goto end;
	}

	new_ctxt->master_proc_handle = proc_handle;
	new_ctxt->client_data = client_data;
	status = ar_list_init_node(&new_ctxt->node);
	if (status)
		goto free_new_ctxt;

	status = ar_list_add_tail(&context_list, &new_ctxt->node);
	if (status)
		goto free_new_ctxt;

	/* don't free in success case */
	goto end;

free_new_ctxt:
	ar_heap_free(new_ctxt, &heap_info);

end:
	return status;
}

int32_t ar_err_det_destroy_ctxt(uint32_t proc_handle)
{
	err_det_ctxt *ctxt;
	ar_heap_info heap_info = {
		.align_bytes = AR_HEAP_ALIGN_DEFAULT,
		.pool_type = AR_HEAP_POOL_DEFAULT,
		.heap_id = AR_HEAP_ID_DEFAULT,
		.tag = AR_HEAP_TAG_DEFAULT
	};

	ctxt = find_ctxt_by_proc_handle(proc_handle);

	if (!ctxt)
		return AR_EBADPARAM;

	ar_list_delete(&context_list, &ctxt->node);
	ar_heap_free(ctxt->client_data, &heap_info);
	ar_heap_free(ctxt, &heap_info);

	return AR_EOK;
}

int32_t ar_err_det_reset_ctxt(uint32_t proc_handle)
{
	err_det_ctxt *ctxt = find_ctxt_by_proc_handle(proc_handle);

	if (!ctxt)
		return AR_EBADPARAM;

	ctxt->first_timeout_time_ms = 0;
	ctxt->num_timeouts_curr_period = 0;
	ctxt->first_eduplicate_time_ms = 0;
	ctxt->num_eduplicate_curr_period = 0;

	return AR_EOK;
}

int32_t ar_err_det_detect_spf_error(uint32_t proc_handle, int32_t err_code,
	uint32_t opcode, bool_t *do_restart, void **client_data)
{
	err_det_ctxt *ctxt = find_ctxt_by_proc_handle(proc_handle);
	uint64_t curr_time = ar_timer_get_time_in_ms();
	uint64_t sum = 0;
	uint32_t rc = AR_EOK;

	*do_restart = false;

	/* Don't trigger SSR if we don't find the context */
	if (!ctxt)
		return AR_EBADPARAM;

	*client_data = ctxt->client_data;

	switch (err_code) {
	/*
	 * For timeout we have specific handling for OPEN/CLOSE operations, and
	 * a case for other generic operations
	 */
	case AR_ETIMEOUT:
		switch (opcode) {
		/*
		 * For graph OPEN and CLOSE, any timeout can create desync between
		 * SPF and GSL, resulting in SGs being open by mistake.
		 * Thus, on any timeout for graph OPEN or CLOSE, treat it as a fatal
		 * error and immediately restart.
		 */
		case APM_CMD_GRAPH_OPEN:
		case APM_CMD_GRAPH_CLOSE:
			AR_ERR_DET_ERR("Graph open/close timeout. Desync likely. Restarting");
			*do_restart = true;
			break;

		/*
		 * Timeout with generic commands is not immediately a problem. However
		 * if a lot of timeouts come in at once, likely there is something wrong
		 * on SPF.
		 * Thus, if we get enough timeouts in a short period of time, restart.
		 *
		 * If we get a few timeouts and then another one much later, we want to
		 * count these separately, so we will reset the number of timeouts counter
		 * and start our accumulation period from the later time.
		 */
		default:
			sum = overflow_safe_add(ctxt->first_timeout_time_ms, ACCUMULATION_PERIOD_MS);
			if (curr_time < sum) {
				++(ctxt->num_timeouts_curr_period);
				if (ctxt->num_timeouts_curr_period >= MAX_TIMEOUTS_IN_PERIOD) {
					AR_ERR_DET_ERR("Too many timeouts in short time. Restarting");
					*do_restart = true;
				}
			} else {
				ctxt->first_timeout_time_ms = curr_time;
				ctxt->num_timeouts_curr_period = 1;
			}
		}
		break;

	/*
	 * EDUPLICATE indicates either 1) GSL + SPF are out of sync and we should restart
	 * or 2) the graph being opened is badly drawn and we can't do anything at
	 * runtime to fix it.
	 * Thus, if we get enough EDUPLICATE in a short period of time, assume it's
	 * case 1) and restart.
	 * However, if we continue getting EDUPLICATE after restarting, we can be reasonably
	 * sure it's case 2) and we ignore it for some time. Eventually, the probability
	 * of case 1) goes up and we can try restarting again.
	 *
	 * As with timeouts, if we get a few EDUPLICATE and then another one much later,
	 * we want to count these separately, so we will reset the number of EDUPLICATE
	 * counter and start our accumulation period from the later time.
	 */
	case AR_EDUPLICATE:
		sum = overflow_safe_add(ctxt->first_eduplicate_time_ms, ACCUMULATION_PERIOD_MS);
		if (curr_time < sum){
			++(ctxt->num_eduplicate_curr_period);
			if (ctxt->num_eduplicate_curr_period >= MAX_EDUPLICATE_IN_PERIOD) {
				AR_ERR_DET_ERR("Too many EDuplicate. GSL/SPF desync or bad graph. Restarting");
				*do_restart = true;
			}
		} else {
			ctxt->first_eduplicate_time_ms = curr_time;
			ctxt->num_eduplicate_curr_period = 1;
		}

		if (*do_restart) {
			/* not all 1 if to avoid calculating this sum when no rc*/
			sum = overflow_safe_add(ctxt->last_restart_time_ms, MIN_TIME_EDUPLICATE_RESTART_MS);
			if (curr_time < sum) {
				AR_ERR_DET_INFO("Last DUPLICATE restart too recent. Silencing detected error");
				*do_restart = false;
			}
		}
		break;
	}

	/*
	 * We don't want to get stuck in a loop of constantly restarting, so we check
	 * that some time has passed since the last restart and avoid restarting if
	 * it's still too soon since.
	 */
	if (*do_restart) {
		/* not all 1 if to avoid calculating this sum when no rc*/
		sum = overflow_safe_add(ctxt->last_restart_time_ms, MIN_TIME_ANY_RESTART_MS);
		if (curr_time < sum) {
			AR_ERR_DET_INFO("Last restart too recent. Silencing detected error");
			*do_restart = false;
		} else {
			ctxt->last_restart_time_ms = curr_time;
		}
	}

	return rc;
}

