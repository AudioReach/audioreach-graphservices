#ifndef GSL_SUBGRAPH_POOL_H
#define GSL_SUBGRAPH_POOL_H
/**
 * \file gsl_subgraph_pool.h
 *
 * \brief
 *      Implements a store for all subgraphs active in Spf, note this is a
 *      singleton.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_subgraph.h"

/**
 * \brief initialize the data structure used for the pool
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_sg_pool_init(void);

/**
 * \brief Deinitialize the data structure used for the pool
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_sg_pool_deinit(void);

/**
 * \brief Find a subgraph by SGID in the pool
 *
 * \param[in] sgid: the subgraph ID find
 *
 * \return pointer to the SG object
 */
struct gsl_subgraph *gsl_sg_pool_find(uint32_t sgid);

/**
 * \brief Add a subgraph to the pool
 *
 * \return AR_EOK on success, error code otherwise
 */
struct gsl_subgraph *gsl_sg_pool_add(uint32_t sg_id, bool_t preload_only);

/**
 * \brief Remove a subgraph from pool
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_sg_pool_remove(struct gsl_subgraph *sg, bool_t unload_only);

/**
 * \brief Determine which subgraphs out of the provided list have a refrence
 *	count of 1 and return the corresponding subgraph ids
 *
 * \param[in] subgraphs: the set of subgraphs to prune from
 * \param[in] num_sgs: number of subgraphs in sg_objs
 * \param[in] props: OPTIONAL subgrah properties, all subgraphs that do not
 *		match the properties will be pruned out
 * \param[out] pruned_sgids: subgraph ids of the subgraph objs that have a
 *		refcnt of 1
 *
 * \return GSL_EOK on success, error code otherwise
 */
uint32_t gsl_sg_pool_prune_sg_list(struct gsl_subgraph **subgraphs,
	uint32_t num_sgs, struct gsl_cmd_properties *props,
	struct gsl_sgid_list *pruned_sgids, struct gsl_sgid_list *existing_sgids);

/**
 * \brief Scan through the child subgraphs of each entry in the pool and set
 * its obj_ref to gsl_subgraph entry in the pool if it is not already set
 */
void gsl_sg_pool_update_child_refs(void);
#endif //GSL_SUBGRAPH_POOL_H
