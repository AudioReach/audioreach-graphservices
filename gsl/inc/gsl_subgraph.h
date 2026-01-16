#ifndef GSL_SUBGRAPH_H
#define GSL_SUBGRAPH_H
/**
 * \file gsl_subgraph.h
 *
 * \brief
 *      Represents a single sub-graph
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "ar_util_list.h"
#include "gsl_intf.h"
#include "gsl_shmem_mgr.h"
#include "gsl_subgraph_driver_props.h"
#include "gsl_subgraph_driver_props_generic.h"
#include "acdb.h"
#include "ar_osal_sys_id.h"

struct gsl_child_sg {
	struct ar_list_node_t node; /**< list node for subgraph children */
	uint32_t ref_cnt;
	uint32_t sg_id;
	struct gsl_subgraph *sg_obj;
};

struct gsl_subgraph {
	struct ar_list_node_t node;
	uint32_t sg_id;
	uint32_t open_ref_cnt;
	uint32_t start_ref_cnt;
	uint32_t stop_ref_cnt;
	uint32_t num_proc_ids;
	/*  below shmem pointer points to data of type AcdbSgIdPersistData */
	struct gsl_shmem_alloc_data_per_proc persist_cal_data_per_proc[AR_SUB_SYS_ID_LAST];
	/*  below shmem pointer points to data of type AcdbSgIdPersistData */
	struct gsl_shmem_alloc_data user_persist_cfg_data;
	uint32_t user_persist_cfg_data_size;
	/*  below shmem pointer points to data of type AcdbSgIdPersistData */
	struct gsl_shmem_alloc_data cma_persist_cfg_data;
	uint32_t cma_cal_data_size;
	struct sg_generic_t drv_prop_data;
	struct sg_type_t sg_type_data;
	struct ar_list_t children;
};

struct gsl_sgid_list {
	uint32_t len;
	uint32_t *sg_ids;
};

struct gsl_sgobj_list {
	uint32_t len;
	struct gsl_subgraph **sg_objs;
};

/**
 * \brief initialize a subgraph object
 *
 * \param[in] sg: subgraph object to be initialized
 * calibration
 * \param[in] sg_id: subgraph id to be used for this object
 *
 * \return GSL_EOK on success, error code otherwise
 */
uint32_t gsl_subgraph_init(struct gsl_subgraph *sg, uint32_t sg_id);

/**
 * \brief Add child subgraphs to a given subgraph object
 *
 * \param[in] sg: the subgraph to add children to
 * \param[in] child_sgids: contains information about the child subgraphs
 *  to add.
 * \param[out] pruned_child_sgids: OPTIONAL if not NULL will be set to
 *  a list of child subgraphs with corresponding refcnt of 1. These will
 *  be edges that need to be opened on Spf.
 * \param[out] existing_child_sgids: OPTIONAL if not NULL will be set to
 *  the subgraphs NOT in pruned_child_sgids, i.e. the ones which do not
 *  need to be opened on SPF
 *
 * \return GSL_EOK on success, error code otherwise
 */
uint32_t gsl_subgraph_add_children(struct gsl_subgraph *sg,
	AcdbSubgraph *child_sgids, AcdbSubgraph *pruned_child_sgids,
	AcdbSubgraph *existing_child_sgids);

/**
 * \brief Remove child subgraphs from a given subgraph object
 *
 * \param[in] sg: the subgraph to remove children from
 * \param[in] child_sgids: contains information about the child subgraphs
 *  to remove.
 * \param[in] props: SG properties. If not NULL only remove a child if it
 *  matches the properties. In case the parent matches the properties then
 *  remove all of its children.
 * \param[out] pruned_child_sgids: OPTIONAL if not NULL will be set to
 *  a list of child subgraphs whose refrence count became 0 and got deleted
 *  from the subgraph. These will be edges that need to be closed on Spf.
 *
 * \return GSL_EOK on success, error code otherwise
 */
uint32_t gsl_subgraph_remove_children(struct gsl_subgraph *sg,
	AcdbSubgraph *child_sgids, struct gsl_cmd_properties *props,
	AcdbSubgraph *pruned_child_sgids);

/**
 * \brief Read persistent cal pertaining to this subgraph from ACDB and
 * store inside the subgraph object
 *
 * \param[in] sg: the subgraph whose persistent cal data we want to read
 * \param[in] ckv: new ckv that is being set. we do not use delta ckv here
 * \param[in] mem_type: what type of memory (cma/normal) to query ACDB for
 * \param[in] master_proc: SPF master proc id
 *
 * \return GSL_EOK on success, error code otherwise
 */
int32_t gsl_subgraph_query_persist_cal_by_mem(struct gsl_subgraph *sg_obj,
	const struct gsl_key_vector *ckv, const	AcdbHwAccelMemType mem_type,
	uint32_t master_proc, uint32_t persist_cal_idx);

/**
 * \brief Copy perstent data provided by caller into this subgraphs shared
 * memory buffer
 *
 * \param[in] sg: the subgraph whose persistent cal data we want to read
 * \param[in] persistent_cal:  pointer to blob of persistent cal data
 * \param[in] persistent_cal_sz: size of persistent_cal in bytes
 * \param[in] master_proc: SPF master proc id
 *
 * \return GSL_EOK on success, error code otherwise
 */
int32_t gsl_subgraph_set_persist_cal(struct gsl_subgraph *sg,
	uint8_t *persistent_cal, uint32_t persistent_cal_sz,
	uint32_t master_proc, uint32_t persist_cal_idx);

/**
 * \brief Checks if the given subgraph matches at least one of the property
 * values in the given set
 *
 * \param[in] sg: subgraph object
 * \param[in] props: containts a property id and a set of values to match
 * against
 *
 * \return TRUE if sg contains the same property_id with a value that matches
 * one of the values in the set of values in props. FALSE otherwise.
 */
bool_t is_matching_sg_property(struct gsl_subgraph *sg,
	struct gsl_cmd_properties *props);
#endif /* GSL_SUBGRAPH */
