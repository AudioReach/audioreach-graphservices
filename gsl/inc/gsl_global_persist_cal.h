#ifndef GSL_GLOBAL_PERSIST_CAL_H
#define GSL_GLOBAL_PERSIST_CAL_H
/**
 * \file gsl_global_persist_cal.h
 *
 * \brief
 *      Manages global persist cal for subgraphs
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "gsl_shmem_mgr.h"
#include "acdb.h"
#include "ar_util_list.h"

#define GSL_MAX_IIDS_PER_GP_CAL 10

struct gsl_glbl_persist_cal {
	struct ar_list_node_t node;
	uint32_t cal_id;
	uint32_t ref_cnt;
	struct gsl_shmem_alloc_data cal_data;
	uint32_t cal_data_size;
};

struct gsl_glbl_persist_cal_iid_list {
	/* assumed that there is a maximum number of IIDs per cal for ease of
	 * allocating space
	 */
	uint32_t iids[GSL_MAX_IIDS_PER_GP_CAL];
	uint8_t num_iids;
	struct gsl_glbl_persist_cal *gpcal;
};

/* ********************************** */
/* GLOBAL PERSIST CAL POOL MANAGEMENT */
/* ********************************** */

 /**
  * \brief initialize the data structure used for the pool
  *
  * \return AR_EOK on success, error code otherwise
  */
int32_t gsl_global_persist_cal_pool_init(void);

/**
 * \brief Deinitialize the data structure used for the pool
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_global_persist_cal_pool_deinit(void);

/**
 * \brief Add a cal to the pool
 *
 * \param[in] cal_id: identifier of global persist cal to add to/find in pool
 * \param[in] cal_data_size: size of ACDB data associated with this cal_id
 * \param[in] master_proc: SPF master proc id
 * \param[out] cal_data: Set to NULL when we already have ACDB data for this
 *						 cal_id in the pool. Otherwise holds pointer to shmem
 *						 object into which to fill the data for this cal_id
 *
 * \return pointer to global persist cal object which was added to pool
 */
struct gsl_glbl_persist_cal *gsl_global_persist_cal_pool_add(uint32_t cal_id,
	uint32_t cal_data_size, struct gsl_shmem_alloc_data **cal_data,
	uint32_t master_proc);

/**
 * \brief Remove a cal from pool
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_global_persist_cal_pool_remove(struct gsl_glbl_persist_cal *gpc);

#endif /* GSL_GLOBAL_PERSIST_CAL */
