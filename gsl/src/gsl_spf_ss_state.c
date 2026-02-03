/**
 * \file gsl_spf_ss_state.c
 *
 * \brief
 * Maintains the state of Spf framework across all subsystems. With MDF
 * (Multi-DSP framework) capabilities there will be a Spf master service that
 * runs in a certain subsystem (typically ADSP) and Spf satelite services
 * run in other subsystems suchs as MDSP or CDSP.
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_spf_ss_state.h"
#include "gsl_common.h"
#include "gsl_intf.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "ar_osal_mutex.h"
#include "ar_osal_servreg.h"
#include "ar_osal_shmem.h"
#include "ar_util_err_detection.h"
#include "gsl_mdf_utils.h"

#define GSL_AUDIO_PD_DOMAIN_STR "msm/adsp/audio_pd"
#define GSL_COMPUTE_PD_DOMAIN_STR "msm/cdsp/audio_pd"
#define GSL_COMPUTE_ROOT_PD_DOMAIN_STR "msm/cdsp/root_pd"
#define GSL_MODEM_PD_DOMAIN_STR "msm/mdsp/audio_pd"
#define GSL_SENSOR_PD_DOMAIN_STR "msm/sdsp/audio_pd"
#define GSL_AUDIO_PD_SERVICE_STR "avs/audio"

struct gsl_spf_ss_state {
	/*
	 * bit mask that represents which subsystems are supported
	 */
	uint32_t ss_supported_flags;
	/*
	 * bit mask representing the state of each subsystem
	 */
	uint32_t ss_state_flags;
	/*
	 * Used to sychronize accesses to the global subsystem state
	 */
	ar_osal_mutex_t lock;
	/*
	 * callback invoked whenever there is an SSR up or down event
	 */
	gsl_spf_ss_cb_t ssr_cb;
};

/*
 * A cluster has 1 master and N satellites
 * This array stores state information for all the masters and corresponding
 * satellites.
 */
struct gsl_spf_ss_state *_spf_cluster_ss_state[AR_SUB_SYS_ID_LAST + 1] = {NULL};

static uint32_t spf_cluster_ref_count;

/*
 * Store servreg handles from registration for re-use
 */

struct gsl_servreg_handle_list *servreg_handle_list;

static uint32_t gsl_find_proc_id_from_name(char_t *name)
{
	uint32_t proc_id = AR_SUB_SYS_ID_INVALID;

	if (!strcmp(name, GSL_AUDIO_PD_DOMAIN_STR))
		proc_id = AR_AUDIO_DSP;
	else if (!strcmp(name, GSL_COMPUTE_PD_DOMAIN_STR) ||
			!strcmp(name, GSL_COMPUTE_ROOT_PD_DOMAIN_STR))
		proc_id = AR_COMPUTE_DSP;
	else if (!strcmp(name, GSL_MODEM_PD_DOMAIN_STR))
		proc_id = AR_MODEM_DSP;
	else if (!strcmp(name, GSL_SENSOR_PD_DOMAIN_STR))
		proc_id = AR_SENSOR_DSP;

	return proc_id;
}

static void servreg_callback(ar_osal_servreg_t servreg_handle,
	ar_osal_servreg_cb_event_type event_id, void *cb_context, void *payload,
	uint32_t payload_size)
{
	uint32_t ss_mask = 0;
	uint32_t master_proc = AR_SUB_SYS_ID_INVALID;
	uint32_t proc_id = AR_SUB_SYS_ID_INVALID;
	uint32_t sys_id = AR_SUB_SYS_ID_FIRST;
	uint32_t supported_ss_mask = 0, tmp_ss_mask = 0;
	/*
	 * reference unused variables to make compiler happy. Can't change function
	 * signature because it needs to match what OSAL expects.
	 */
	(void)servreg_handle;
	(void)cb_context;
	(void)payload_size;

	ar_osal_servreg_state_notify_payload_type *serv_ntfy_pld =
		(ar_osal_servreg_state_notify_payload_type *)payload;

	if (event_id == AR_OSAL_SERVICE_STATE_NOTIFY) {
		proc_id = gsl_find_proc_id_from_name(serv_ntfy_pld->domain.name);
		if (proc_id != AR_SUB_SYS_ID_INVALID) {
			ss_mask = GSL_GET_SPF_SS_MASK(proc_id);
		} else {
			GSL_ERR("could not recognize domain %s",
				serv_ntfy_pld->domain.name);
			return;
		}

		master_proc = gsl_mdf_utils_get_master_proc_id(ss_mask);
		if (master_proc == 0) {
			GSL_ERR("Invalid proc id %d", master_proc);
			return;
		}
		if (serv_ntfy_pld->service_state == AR_OSAL_SERVICE_STATE_DOWN) {
			GSL_INFO("AR_OSAL_SERVICE_STATE_DOWN proc_id %d", proc_id);
			/*
			 * For dynamic PD down notification, restart master proc.
			 * PD down notification can also be sent for normal PD close
			 * as part of PD deinitialization. Check and ignore notification
			 * for such case.
			 */
			if (gsl_mdf_utils_is_dynamic_pd(proc_id)) {
				if (gsl_mdf_utils_get_dynamic_pd_state(proc_id)) {
					gsl_spf_ss_state_set(master_proc, ss_mask, GSL_SPF_SS_STATE_DN);
					GSL_INFO("Restart master proc %d for dynamic pd %d crash",
						master_proc, proc_id);
					ar_osal_servreg_restart_service(
						servreg_handle_list->handles[master_proc]);
				}
					return;
			}
			gsl_spf_ss_state_set(master_proc, ss_mask, GSL_SPF_SS_STATE_DN);
			/*
			 * For dynamic PD down notification, restart master proc.
			 * PD down notification can also be sent for normal PD close
			 * as part of PD deinitialization. Check and ignore notification
			 * for such case.
			 */
			/* notify gsl_main */
			_spf_cluster_ss_state[master_proc]->ssr_cb(GSL_SPF_SS_STATE_DN,
								   ss_mask);
		} else if (serv_ntfy_pld->service_state == AR_OSAL_SERVICE_STATE_UP) {
			GSL_INFO("AR_OSAL_SERVICE_STATE_UP proc_id %d", proc_id);
			if (gsl_mdf_utils_is_dynamic_pd(proc_id)) {
				/* PD up notification can also be sent when PD is loaded part of
				 * normal pd initialization. Skip SSR callback notification.
				 */
				gsl_spf_ss_state_set(master_proc, ss_mask, GSL_SPF_SS_STATE_UP);
				return;
			}
			if (gsl_mdf_utils_is_master_proc(ss_mask)) {
				/*
				 * If there is an associated dynamic PD satellite add it to
				 * ss_mask as up, since dynamic PD crash would have forced this
				 * master proc restart.
				 */
				gsl_mdf_utils_get_supported_ss_info_from_master_proc(master_proc,
					&supported_ss_mask);
				tmp_ss_mask = supported_ss_mask;
				while (tmp_ss_mask && (sys_id <= AR_SUB_SYS_ID_LAST)) {
					if (GSL_TEST_SPF_SS_BIT(supported_ss_mask, sys_id) &&
						gsl_mdf_utils_is_dynamic_pd(sys_id)) {
							ss_mask |= GSL_GET_SPF_SS_MASK(sys_id);
					}
					++sys_id;
					tmp_ss_mask >>= 1;
				}
			}
			/* update the global Spf SS state */
			GSL_DBG("set ss state with ss_mask 0x%x", ss_mask);
			 gsl_spf_ss_state_set(master_proc, ss_mask, GSL_SPF_SS_STATE_UP);
			/* notify gsl_main */
			_spf_cluster_ss_state[master_proc]->ssr_cb(GSL_SPF_SS_STATE_UP,
								   ss_mask);
		}
	}
}

static uint32_t gsl_servreg_setup(void)
{
	int32_t rc = AR_EOK;
	ar_osal_servreg_entry_type service = { GSL_AUDIO_PD_SERVICE_STR, 0 };
	ar_osal_servreg_entry_type *domain_list = NULL;
	uint32_t i = 0, domain_list_size = 0, proc_id;
	ar_osal_servreg_t servreg_handle;

	rc = ar_osal_servreg_init();
	if (rc) {
		GSL_ERR("failed to initialize ar_osal state notifier %d", rc);
		goto exit;
	}

	/* first we query for number of entries in domain list */
	rc = ar_osal_servreg_get_domainlist(&service, NULL, &domain_list_size);
	if (rc != AR_ENOMEMORY) {
		GSL_ERR("failed to get num domains with ar_osal state notifier %d",
			rc);
		goto deinit_state_notify;
	}

	/* next we query for actual list */
	domain_list = gsl_mem_zalloc(domain_list_size *
		sizeof(ar_osal_servreg_entry_type));
	if (!domain_list) {
		rc = AR_ENOMEMORY;
		goto deinit_state_notify;
	}
	rc = ar_osal_servreg_get_domainlist(&service, domain_list,
		&domain_list_size);
	if (rc) {
		GSL_ERR("failed to get domains with ar_osal state notifier %d", rc);
		goto free_domain_list;
	}

	/* add 1 to num handles since domain 0 is invalid */
	servreg_handle_list =
		gsl_mem_zalloc(sizeof(struct gsl_servreg_handle_list) +
			(AR_SUB_SYS_ID_LAST + 1) * sizeof(ar_osal_servreg_t));
	if (!servreg_handle_list) {
		rc = AR_ENOMEMORY;
		goto free_domain_list;
	}
	servreg_handle_list->num_handles = domain_list_size + 1;

	/* add 1 for offset since domain 0 is invalid */
	/* scan through domain list and register for notification */
	for (i = 0; i < domain_list_size; ++i) {
		proc_id = gsl_find_proc_id_from_name(domain_list[i].name);
		if (proc_id == AR_SUB_SYS_ID_INVALID)
			continue;
		servreg_handle = ar_osal_servreg_register(AR_OSAL_CLIENT_LISTENER,
						servreg_callback, _spf_cluster_ss_state[proc_id],
						domain_list + i, &service);
		/*
		 * On some platform variants, the proc may not be present. Ideally the servereg
		 * domain list could indicate this, but it may not be possible due to cross platform
		 * build dependencies. So, ignore the error to avoid failing to initialize GSL.
		 */
		if (!servreg_handle)
			GSL_ERR("failed to register for %s : %s, continue", domain_list[i].name, service.name);

		servreg_handle_list->handles[proc_id] = servreg_handle;
	}

	gsl_mem_free(domain_list);
	return rc;

free_domain_list:
	gsl_mem_free(domain_list);
deinit_state_notify:
	ar_osal_servreg_deinit();
exit:
	return rc;
}

static int32_t gsl_register_err_det_ctxt(uint32_t master_proc)
{
	struct gsl_spf_ss_state *cluster;
	int32_t rc = AR_EOK;
	uint32_t i = 0, j = 0, num_handles = 0;
	struct gsl_servreg_handle_list *input_handle_list;

	cluster = _spf_cluster_ss_state[master_proc];

	if (!cluster)
		return AR_EBADPARAM;

	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; ++i) {
		if (gsl_spf_ss_state_is_ss_supported(master_proc, i))
			++num_handles;
	}

	input_handle_list =
		(struct gsl_servreg_handle_list *)gsl_mem_zalloc(
			sizeof(struct gsl_servreg_handle_list) +
			(num_handles) * sizeof(ar_osal_servreg_t));
	if (!input_handle_list)
		return AR_ENOMEMORY;

	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; ++i) {
		if (gsl_spf_ss_state_is_ss_supported(master_proc, i) &&
			servreg_handle_list->handles[i] != NULL) {
			input_handle_list->handles[j] = servreg_handle_list->handles[i];
			++j;
		}
	}

	input_handle_list->num_handles = j;

	rc = ar_err_det_init_ctxt(master_proc, input_handle_list);

	return rc;
}

bool_t gsl_spf_ss_state_is_ss_supported(uint32_t master_proc, uint32_t proc_id)
{
	uint32_t ss_mask = 0;

	if (_spf_cluster_ss_state[master_proc] != NULL) {
		ss_mask = _spf_cluster_ss_state[master_proc]->ss_supported_flags;
		if (GSL_TEST_SPF_SS_BIT(ss_mask, proc_id))
		return TRUE;
	}

	return FALSE;
}

int32_t gsl_spf_ss_state_init(uint32_t master_proc, uint32_t supported_ss_mask,
	gsl_spf_ss_cb_t cb)
{
	int32_t rc = AR_EOK;

	if (master_proc <= AR_SUB_SYS_ID_INVALID ||
	    master_proc > AR_SUB_SYS_ID_LAST)
		return AR_EBADPARAM;
	_spf_cluster_ss_state[master_proc] =
				gsl_mem_zalloc(sizeof(struct gsl_spf_ss_state));

	rc = ar_osal_mutex_create(&_spf_cluster_ss_state[master_proc]->lock);
	if (rc)
		goto exit;

	if (spf_cluster_ref_count == 0) {
		rc = gsl_servreg_setup();
		if (rc)
			goto cleanup;
	}
	_spf_cluster_ss_state[master_proc]->ss_supported_flags = supported_ss_mask;
	_spf_cluster_ss_state[master_proc]->ssr_cb = cb;
	++spf_cluster_ref_count;

	rc = gsl_register_err_det_ctxt(master_proc);

	return rc;
cleanup:
	ar_osal_mutex_destroy(_spf_cluster_ss_state[master_proc]->lock);
exit:
	gsl_mem_free(_spf_cluster_ss_state[master_proc]);
	_spf_cluster_ss_state[master_proc] = NULL;
	return rc;
}

void gsl_spf_ss_state_deinit(uint32_t master_proc)
{
	if (master_proc <= AR_SUB_SYS_ID_INVALID ||
	    master_proc > AR_SUB_SYS_ID_LAST)
		return;

	if (_spf_cluster_ss_state[master_proc] != NULL) {
		_spf_cluster_ss_state[master_proc]->ss_supported_flags = 0;
		_spf_cluster_ss_state[master_proc]->ssr_cb = NULL;
		ar_osal_mutex_destroy(_spf_cluster_ss_state[master_proc]->lock);
		gsl_mem_free(_spf_cluster_ss_state[master_proc]);
		_spf_cluster_ss_state[master_proc] = NULL;
		--spf_cluster_ref_count;

		ar_err_det_destroy_ctxt(master_proc);
	}

	if (spf_cluster_ref_count == 0) {
		ar_osal_servreg_deinit();
		gsl_mem_free(servreg_handle_list);
	}
}

uint32_t gsl_spf_ss_state_set(uint32_t master_proc, uint32_t ss_mask,
	enum spf_ss_state_t state)
{
	uint32_t updated_ss_state = 0;

	if (master_proc <= AR_SUB_SYS_ID_INVALID ||
	    master_proc > AR_SUB_SYS_ID_LAST)
		return AR_EBADPARAM;
	if (_spf_cluster_ss_state[master_proc] == NULL)
		return AR_EBADPARAM;
	GSL_MUTEX_LOCK(_spf_cluster_ss_state[master_proc]->lock);
	if ((ss_mask & _spf_cluster_ss_state[master_proc]->ss_supported_flags) &&
	    (state == GSL_SPF_SS_STATE_UP))
		_spf_cluster_ss_state[master_proc]->ss_state_flags |= ss_mask;
	else if ((ss_mask &
		 _spf_cluster_ss_state[master_proc]->ss_supported_flags) &&
		 (state == GSL_SPF_SS_STATE_DN)) {
		_spf_cluster_ss_state[master_proc]->ss_state_flags &= ~ss_mask;
		/* @TODO free mdf shared mem for proc_ids that went down */
	}
	updated_ss_state = _spf_cluster_ss_state[master_proc]->ss_state_flags;
	GSL_MUTEX_UNLOCK(_spf_cluster_ss_state[master_proc]->lock);

	return updated_ss_state;
}

uint32_t gsl_spf_ss_state_get(uint32_t master_proc)
{
	if (master_proc <= AR_SUB_SYS_ID_INVALID ||
	    master_proc > AR_SUB_SYS_ID_LAST)
		return AR_EBADPARAM;
	if (_spf_cluster_ss_state[master_proc] != NULL)
		return _spf_cluster_ss_state[master_proc]->ss_state_flags;
	return AR_EOK;
}

