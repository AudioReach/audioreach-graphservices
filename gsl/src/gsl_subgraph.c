/**
 * \file gsl_subgraph.c
 *
 * \brief
 *      Represents a single sub-graph
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_subgraph.h"
#include "ar_osal_error.h"
#include "ar_util_list.h"
#include "gsl_common.h"
#include "gsl_intf.h"
#include "gsl_shmem_mgr.h"
#include "gsl_mdf_utils.h"

uint32_t gsl_subgraph_init(struct gsl_subgraph *sg, uint32_t sg_id)
{
	uint32_t rc = AR_EOK;

	if (sg == NULL)
		return AR_EBADPARAM;

	rc = ar_list_init_node(&sg->node);
	if (rc) {
		GSL_ERR("ar init list failed %d", rc);
		goto exit;
	}

	sg->open_ref_cnt = 0;
	sg->start_ref_cnt = 0;
	sg->stop_ref_cnt = 0;
	sg->sg_id = sg_id;

	for (int i = 0; i < AR_SUB_SYS_ID_LAST; i++) {
		gsl_memset(&sg->persist_cal_data_per_proc[i].persist_cal_data, 0, sizeof(sg->persist_cal_data_per_proc[i].persist_cal_data));
	}
	gsl_memset(&sg->user_persist_cfg_data, 0,
		sizeof(sg->user_persist_cfg_data));

	rc = ar_list_init(&sg->children, NULL, NULL);

exit:
	return rc;
}

uint32_t gsl_subgraph_add_children(struct gsl_subgraph *sg,
	AcdbSubgraph *child_sgids, AcdbSubgraph *pruned_child_sgids,
	AcdbSubgraph *existing_child_sgids)
{
	uint32_t i = 0, is_found = 0;
	struct gsl_child_sg *child = NULL;
	struct ar_list_node_t *itr = NULL;

	if (!sg || !child_sgids)
		return AR_EBADPARAM;

	/* initialize number of sgids to 0 */
	if (pruned_child_sgids) {
		pruned_child_sgids->sg_id = child_sgids->sg_id;
		pruned_child_sgids->num_dst_sgids = 0;
	}
	if (existing_child_sgids) {
		existing_child_sgids->sg_id = child_sgids->sg_id;
		existing_child_sgids->num_dst_sgids = 0;
	}

	for (; i < child_sgids->num_dst_sgids; ++i) {
		/* check if child already exists */
		is_found = 0;
		ar_list_for_each_entry(itr, &sg->children) {
			child = get_container_base(itr, struct gsl_child_sg, node);
			if (!child) {
				GSL_ERR("null returned for child\n");
				return AR_EBADPARAM;
			}
			if (child->sg_id == child_sgids->dst_sg_ids[i]) {
				/* child already exists */
				++child->ref_cnt;
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			child = gsl_mem_zalloc(sizeof(struct gsl_child_sg));
			if (!child)
				return AR_ENOMEMORY;

			child->sg_id = child_sgids->dst_sg_ids[i];
			child->ref_cnt = 1;
			ar_list_init_node((struct ar_list_node_t *)child);
			ar_list_add_tail(&sg->children, &child->node);
			if (pruned_child_sgids) {
				/* add child to pruned list */
				pruned_child_sgids->dst_sg_ids[
					pruned_child_sgids->num_dst_sgids] = child->sg_id;
				/* increment number of pruned sgids */
				++pruned_child_sgids->num_dst_sgids;
			}
		} else if (existing_child_sgids) {
			/* child was found, so add child to exitsting list */
			existing_child_sgids->dst_sg_ids[
				existing_child_sgids->num_dst_sgids] = child->sg_id;
			++existing_child_sgids->num_dst_sgids;
		}

	}
	return AR_EOK;
}

uint32_t gsl_subgraph_remove_children(struct gsl_subgraph *sg,
	AcdbSubgraph *child_sgids, struct gsl_cmd_properties *props,
	AcdbSubgraph *pruned_child_sgids)
{
	uint32_t i = 0;
	struct gsl_child_sg *child = NULL;
	struct ar_list_node_t *itr = NULL;

	if (!sg || !child_sgids)
		return AR_EBADPARAM;

	if (pruned_child_sgids) {
		pruned_child_sgids->sg_id = child_sgids->sg_id;
		pruned_child_sgids->num_dst_sgids = 0;
	}

	/*
	 * in case the parent matches the properties we remove all of its
	 * children this is the same behavior as if props was set to NULL
	 */
	if (props && is_matching_sg_property(sg, props))
		 props = NULL;

	for (; i < child_sgids->num_dst_sgids; ++i) {
		/* check if child already exists */
		ar_list_for_each_entry(itr, &sg->children) {
			child = get_container_base(itr, struct gsl_child_sg, node);
			if (!child) {
				GSL_ERR("null returned for child\n");
				return AR_EBADPARAM;
			}
			if (child->sg_id != child_sgids->dst_sg_ids[i])
				continue;
			/*
			 * found child, only remove it if no properties are passed or
			 * if the child matched the properties
			 */
			if (!props || is_matching_sg_property(child->sg_obj, props)) {
				if (--child->ref_cnt == 0) {
					/* update pruned list */
					if (pruned_child_sgids) {
						/* add sgid to list */
						pruned_child_sgids->dst_sg_ids[
							pruned_child_sgids->num_dst_sgids] =
							child->sg_id;
						/* increment count */
						++(pruned_child_sgids->num_dst_sgids);
					}
					/* remove child */
					ar_list_delete(&sg->children, itr);
					gsl_mem_free(child);
					break;
				}
			}
		}
	}

	return AR_EOK;
}

int32_t gsl_subgraph_query_persist_cal_by_mem(struct gsl_subgraph *sg_obj,
	const struct gsl_key_vector *ckv, const	AcdbHwAccelMemType mem_type,
	uint32_t master_proc, uint32_t persist_cal_idx)
{
	/* used for grabbing data differentiated on hw accel/not */
	AcdbProcSubgraphPersistCalReq cmd_struct;
	AcdbSgIdPersistCalData rsp_struct;
	int32_t rc = AR_EOK;
	uint32_t sg_ss_mask = 0;
	AcdbSubgraphProcPair sg_pair;

	if (!sg_obj || !ckv)
		return AR_EBADPARAM;

         if (persist_cal_idx < 0 || persist_cal_idx > sg_obj->num_proc_ids)
		return AR_EBADPARAM;

	sg_pair.subgraph_id = sg_obj->sg_id;
	sg_pair.proc_id = ACDB_HW_ACCEL_MEM_TYPE_MASK(
		sg_obj->persist_cal_data_per_proc[persist_cal_idx].proc_id, mem_type);
	/* actual proc_id where persist_cal needs to be applied. */

	cmd_struct.num_subgraphs = 1;
	cmd_struct.subgraph_list = &sg_pair;

	/*
	 * always query with empty prior CKV for persist cal as we want to get
	 * the full set of parameters so we can replace entire cal blob
	 */
	cmd_struct.cal_key_vector_prior.num_keys = 0;
	cmd_struct.cal_key_vector_prior.graph_key_vector = NULL;
	cmd_struct.cal_key_vector_new.num_keys = ckv->num_kvps;
	cmd_struct.cal_key_vector_new.graph_key_vector =
		(AcdbKeyValuePair *)ckv->kvp;

	rsp_struct.cal_data = NULL;
	rsp_struct.num_sg_ids = 0;
	rsp_struct.cal_data_size = 0;

	rc = acdb_ioctl(ACDB_CMD_GET_PROC_SUBGRAPH_CAL_DATA_PERSIST,
		&cmd_struct, sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc == AR_ENOTEXIST) {
		/*
		 * avoid printing error log for the case where a subgraph does not have
		 * any persistent data
		 */
		GSL_DBG("get proc persist cal size failed %d", rc);
		return rc;
	} else if (rc) {
		GSL_ERR("get proc persist cal size failed %d", rc);
		return rc;
	}

	if (rsp_struct.num_sg_ids == 0) { /**< no persist cal data for memtype */
		return AR_ENOTEXIST;
	}

	rc = gsl_mdf_utils_query_graph_ss_mask(&sg_obj->sg_id, 1, &sg_ss_mask);
	if (rc) {
		GSL_ERR("query ss mask for sg_id 0x%x failed %d", sg_obj->sg_id, rc);
		goto exit;
	}

	if (mem_type == ACDB_HW_ACCEL_MEM_DEFAULT) {
		/* reuse existing allocation if at all possible */
		if (sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr == NULL ||
			sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size != rsp_struct.cal_data_size) {

			if (sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr != NULL)
				gsl_shmem_free(&sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data);

			rc = gsl_shmem_alloc_ext(rsp_struct.cal_data_size, sg_ss_mask, 0, 0,
				master_proc, &sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data);
			if (rc) {
				GSL_ERR("shmem alloc failed %d", rc);
				goto exit;
			}
		}
		sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size = rsp_struct.cal_data_size;
		rsp_struct.cal_data = sg_obj->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr;
	} else {
		/* do not re-use cma allocations */
		if (sg_obj->cma_persist_cfg_data.v_addr != NULL) {
			gsl_shmem_free(&sg_obj->cma_persist_cfg_data);
			sg_obj->cma_persist_cfg_data.v_addr = NULL;
		}

		rc = gsl_shmem_alloc_ext(rsp_struct.cal_data_size, sg_ss_mask,
			GSL_SHMEM_CMA, 0, master_proc, &sg_obj->cma_persist_cfg_data);
		if (rc) {
			GSL_ERR("shmem alloc failed %d", rc);
			goto exit;
		}

		sg_obj->cma_cal_data_size = rsp_struct.cal_data_size;
		rsp_struct.cal_data = sg_obj->cma_persist_cfg_data.v_addr;
	}

	rc = acdb_ioctl(ACDB_CMD_GET_PROC_SUBGRAPH_CAL_DATA_PERSIST,
		&cmd_struct, sizeof(cmd_struct), &rsp_struct, sizeof(rsp_struct));
	if (rc) {
		GSL_ERR("get persist cal failed %d", rc);
		goto exit;
	}

exit:
	return rc;
}

int32_t gsl_subgraph_set_persist_cal(struct gsl_subgraph *sg,
	uint8_t *persistent_cal, uint32_t persistent_cal_sz,
	uint32_t master_proc, uint32_t persist_cal_idx)
{
	int32_t rc = AR_EOK;
	uint32_t sg_ss_mask;

	if (!sg || !persistent_cal)
		return AR_EBADPARAM;

        if (persist_cal_idx < 0 || persist_cal_idx > sg->num_proc_ids)
		return AR_EBADPARAM;


	rc = gsl_mdf_utils_query_graph_ss_mask(&sg->sg_id, 1, &sg_ss_mask);
	if (rc) {
		GSL_ERR("query ss mask for sg_id 0x%x failed %d", sg->sg_id, rc);
		goto exit;
	}

	/* try to use existing allocation if at all possible */
	if (sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr != NULL &&
		sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size < persistent_cal_sz) {
		gsl_shmem_free(&sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data);

		rc = gsl_shmem_alloc_ext(persistent_cal_sz +
			sizeof(AcdbSgIdPersistData), sg_ss_mask, 0, 0,
			master_proc, &sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data);
		if (rc) {
			GSL_ERR("shmem alloc failed %d", rc);
			goto exit;
		}
	}

	sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data_size = persistent_cal_sz +
		sizeof(AcdbSgIdPersistData);
	gsl_memcpy((uint8_t *)sg->persist_cal_data_per_proc[persist_cal_idx].persist_cal_data.v_addr +
		sizeof(AcdbSgIdPersistData), persistent_cal_sz, persistent_cal,
		persistent_cal_sz);

exit:
	return rc;
}

bool_t is_matching_sg_property(struct gsl_subgraph *sg,
	struct gsl_cmd_properties *props)
{
	uint32_t n;

	switch (props->property_id) {
	case SUB_GRAPH_PROP_ID_SG_TYPE:
		for (n = 0; n < props->num_property_values; ++n) {
			if (props->property_values[n] == sg->sg_type_data.sg_type)
				return TRUE;
		}
		break;
	}
	return FALSE;
}

