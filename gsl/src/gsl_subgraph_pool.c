/**
 * \file gsl_subgraph_pool.c
 *
 * \brief
 *      Implements a store for all subgraphs active in Spf, note this is a
 *      singleton.
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_subgraph_pool.h"
#include "ar_util_list.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
#include "gsl_subgraph.h"
#include "gsl_common.h"
#include "ar_osal_mutex.h"
#include <string.h>
#include <stdlib.h>


struct gsl_sg_pool {
	ar_list_t sg_list; /**< list of all subgraphs in the system */
	uint32_t num_subgraphs; /**< number of entries in subgraph pool */
	ar_osal_mutex_t lock; /**< used to serialize operations on pool */
} sg_pool;

int32_t gsl_sg_pool_init(void)
{
	int32_t rc = AR_EOK;

	gsl_memset(&sg_pool, 0, sizeof(sg_pool));
	rc = ar_osal_mutex_create(&sg_pool.lock);
	if (rc) {
		GSL_ERR("ar_osal_mutex_create failed %d", rc);
		goto exit;
	}

	rc = ar_list_init(&sg_pool.sg_list, NULL, NULL);
	if (rc)
		GSL_ERR("ar_list_init failed %d", rc);
exit:
	return rc;
}

int32_t gsl_sg_pool_deinit(void)
{
	ar_osal_mutex_destroy(sg_pool.lock);
	ar_list_clear(&sg_pool.sg_list);
	return AR_EOK;
}

/* todo find SG from graph SG list */
struct gsl_subgraph *gsl_sg_pool_find(uint32_t sgid)
{
	ar_list_node_t *curr = NULL;
	struct gsl_subgraph *curr_sg = NULL;

	ar_list_for_each_entry(curr, &sg_pool.sg_list) {
		curr_sg = get_container_base(curr, struct gsl_subgraph, node);
		if (curr_sg->sg_id == sgid)
			goto exit;
	}
	curr_sg = NULL;
exit:
	return curr_sg;
}

struct gsl_subgraph *gsl_sg_pool_add(uint32_t sg_id, bool_t preload_only)
{
	struct gsl_subgraph *curr_sg = NULL;

	GSL_MUTEX_LOCK(sg_pool.lock);

	/* check if sg_id already exists in the pool */
	curr_sg = gsl_sg_pool_find(sg_id);

	if (!curr_sg) {
		/* subgraph does not exist, so add it to pool */
		curr_sg = gsl_mem_zalloc(sizeof(struct gsl_subgraph));
		if (curr_sg == NULL)
			goto exit;
		if (gsl_subgraph_init(curr_sg, sg_id) != AR_EOK) {
			/* GSL_ERR("gsl_subgraph_init failed %d", rc); */
			goto cleanup;
		}

		if (ar_list_add_tail(&sg_pool.sg_list, &curr_sg->node)
			!= AR_EOK) {
			/* GSL_ERR("ar_list_add_tail failed %d", rc); */
			goto cleanup;
		}
		++sg_pool.num_subgraphs;
	}
	if (preload_only == FALSE)
		++curr_sg->open_ref_cnt;
	goto exit;

cleanup:
	gsl_mem_free(curr_sg);
	curr_sg = NULL;
exit:
	GSL_MUTEX_UNLOCK(sg_pool.lock);
	return curr_sg;
}


int32_t gsl_sg_pool_remove(struct gsl_subgraph *sg, bool_t unload_only)
{
	int32_t rc = AR_EOK;

	if (sg == NULL)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(sg_pool.lock);
	if (sg->open_ref_cnt > 0 && (unload_only == FALSE))
		sg->open_ref_cnt--;

	if (sg->open_ref_cnt == 0) {
		rc = ar_list_delete(&sg_pool.sg_list, &sg->node);
		if (rc) {
			GSL_ERR("ar list delete failed %d", rc);
			goto exit;
		}
		--sg_pool.num_subgraphs;
		/*
		 * Do not free if we fail to remove from list, to preserve the
		 * integrity of the linked list
		 */
		gsl_mem_free(sg);
	}
exit:
	GSL_MUTEX_UNLOCK(sg_pool.lock);
	return rc;
}

uint32_t gsl_sg_pool_prune_sg_list(struct gsl_subgraph **subgraphs,
	uint32_t num_sgs, struct gsl_cmd_properties *props,
	struct gsl_sgid_list *pruned_sgids, struct gsl_sgid_list *existing_sgids)
{
	uint32_t i = 0;

	if (!subgraphs || !pruned_sgids)
		return AR_EBADPARAM;

	pruned_sgids->len = 0;
	if (existing_sgids)
		existing_sgids->len = 0;

	GSL_MUTEX_LOCK(sg_pool.lock);
	for (; i < num_sgs; ++i) {
		if (subgraphs[i]->open_ref_cnt == 1 &&
			(!props || is_matching_sg_property(subgraphs[i], props)))
			pruned_sgids->sg_ids[pruned_sgids->len++] = subgraphs[i]->sg_id;
		else if (existing_sgids)
			existing_sgids->sg_ids[existing_sgids->len++] = subgraphs[i]->sg_id;
	}
	GSL_MUTEX_UNLOCK(sg_pool.lock);

	return AR_EOK;
}

void gsl_sg_pool_update_child_refs(void)
{
	ar_list_node_t *parent = NULL;
	ar_list_node_t *child = NULL;
	struct gsl_subgraph *parent_sg = NULL;
	struct gsl_child_sg *child_entry = NULL;

	/* scan through the children of every subgraph in the pool */
	ar_list_for_each_entry(parent, &sg_pool.sg_list) {
		parent_sg = get_container_base(parent, struct gsl_subgraph, node);
		ar_list_for_each_entry(child, &parent_sg->children)	{
			/*
			 * update the sg_obj for this child only if not already set,
			 * gsl_sg_pool_find does a linear search through the entire pool
			 * so we only want to call it when necessary
			 */
			child_entry = get_container_base(child, struct gsl_child_sg, node);
			if (!child_entry->sg_obj)
				child_entry->sg_obj = gsl_sg_pool_find(child_entry->sg_id);
		}
	}
}
