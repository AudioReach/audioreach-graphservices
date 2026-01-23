/**
 * \file gsl_global_persist_cal.c
 *
 * \brief
 *      Manages global persist cal for subgraphs
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "gsl_global_persist_cal.h"
#include "gsl_common.h"
#include "ar_osal_mutex.h"
#include "ar_osal_error.h"
#include "ar_util_list.h"

struct gsl_global_persist_cal_pool {
	ar_list_t cal_list; /**< list of all GP cals in the system */
	uint32_t num_cals; /**< number of entries in GP cal pool */
	ar_osal_mutex_t lock; /**< used to serialize operations on pool */
} gpc_pool;

static int32_t gsl_gp_cal_init(struct gsl_glbl_persist_cal *gpc,
	uint32_t cal_id, uint32_t cal_data_size, uint32_t master_proc)
{
	uint32_t rc = AR_EOK;

	if (gpc == NULL)
		return AR_EBADPARAM;

	gpc->ref_cnt = 0;
	gpc->cal_id = cal_id;
	gpc->cal_data_size = cal_data_size;

	rc = ar_list_init_node(&gpc->node);
	if (rc) {
		GSL_ERR("ar_list_init_node failed %d", rc);
		goto exit;
	}

	rc = gsl_shmem_alloc(cal_data_size, master_proc, &gpc->cal_data);
	if (rc) {
		GSL_ERR("shmem alloc for glbl persistent cal id %d failed %d", cal_id,
			rc);
		goto delete_list_node;
	}

	/* skip in success case */
	goto exit;
delete_list_node:
	ar_list_delete(&gpc_pool.cal_list, &gpc->node);
exit:
	return rc;
}

static int32_t gsl_gp_cal_deinit(struct gsl_glbl_persist_cal *gpc)
{
	uint32_t rc = AR_EOK;

	rc = gsl_shmem_free(&gpc->cal_data);
	if (rc)
		GSL_ERR("shmem free for glbl persistent cal id %d failed %d",
			gpc->cal_id, rc);

	return rc;
}

/*
 * GLOBAL PERSIST CAL POOL MANAGEMENT
 */

int32_t gsl_global_persist_cal_pool_init(void)
{
	int32_t rc = AR_EOK;

	gsl_memset(&gpc_pool, 0, sizeof(gpc_pool));
	rc = ar_osal_mutex_create(&gpc_pool.lock);
	if (rc) {
		GSL_ERR("ar_osal_mutex_create failed %d", rc);
		goto exit;
	}

	rc = ar_list_init(&gpc_pool.cal_list, NULL, NULL);
	if (rc)
		GSL_ERR("ar_list_init failed %d", rc);
exit:
	return rc;
}

int32_t gsl_global_persist_cal_pool_deinit(void)
{
	ar_osal_mutex_destroy(gpc_pool.lock);
	ar_list_clear(&gpc_pool.cal_list);
	return AR_EOK;
}

struct gsl_glbl_persist_cal *gsl_global_persist_cal_pool_add(uint32_t cal_id,
	uint32_t cal_data_size, struct gsl_shmem_alloc_data **cal_data,
	uint32_t master_proc)
{
	ar_list_node_t *curr = NULL;
	struct gsl_glbl_persist_cal *curr_gpc = NULL;
	uint8_t cal_found = 0;
	int32_t rc;

	GSL_MUTEX_LOCK(gpc_pool.lock);

	/* check if cal_id already exists in the pool */
	ar_list_for_each_entry(curr, &gpc_pool.cal_list) {
		curr_gpc = get_container_base(curr, struct gsl_glbl_persist_cal, node);
		if (!curr_gpc) {
			GSL_ERR("null returned for curr_gpc\n");
			goto exit;
		}

		if (curr_gpc->cal_id == cal_id) {
			cal_found = 1;
			break;
		}
	}
	if (!cal_found) {
		/* cal does not exist, so add it to pool */
		curr_gpc = gsl_mem_zalloc(sizeof(struct gsl_glbl_persist_cal));
		if (curr_gpc == NULL)
			goto exit;

		rc = gsl_gp_cal_init(curr_gpc, cal_id, cal_data_size, master_proc);
		if (rc) {
			GSL_ERR("gsl_gp_cal_init failed %d", rc);
			goto cleanup;
		}

		rc = ar_list_add_tail(&gpc_pool.cal_list, &curr_gpc->node);
		if (rc) {
			GSL_ERR("ar_list_add_tail failed, %d", rc);
			goto deinit;
		}

		*cal_data = &curr_gpc->cal_data;
		/* we only set cal_data if we need to fetch the data from ACDB */

		++(curr_gpc->ref_cnt);
		++gpc_pool.num_cals;
	} else {
		*cal_data = NULL;
	}
	goto exit;

deinit:
	gsl_gp_cal_deinit(curr_gpc);
cleanup:
	gsl_mem_free(curr_gpc);
	curr_gpc = NULL;
exit:
	GSL_MUTEX_UNLOCK(gpc_pool.lock);
	return curr_gpc;
}

int32_t gsl_global_persist_cal_pool_remove(struct gsl_glbl_persist_cal *gpc)
{
	int32_t rc = AR_EOK;

	if (!gpc)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(gpc_pool.lock);
	if (gpc->ref_cnt > 0)
		--gpc->ref_cnt;

	if (gpc->ref_cnt == 0) {
		rc = gsl_shmem_free(&gpc->cal_data);
		if (rc) {
			GSL_ERR("gsl_shmem_free failed %d", rc);
			goto exit;
		}

		rc = ar_list_delete(&gpc_pool.cal_list, &gpc->node);
		if (rc) {
			GSL_ERR("ar_list_delete failed %d", rc);
			goto exit;
		}
		--gpc_pool.num_cals;
		/*
		 * Do not free if we fail to remove from list, to preserve the
		 * integrity of the linked list
		 */
		gsl_gp_cal_deinit(gpc);
		gsl_mem_free(gpc);
	}
exit:
	GSL_MUTEX_UNLOCK(gpc_pool.lock);
	return rc;
}
