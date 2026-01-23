#ifndef GSL_RTC_H
#define GSL_RTC_H
/**
 * \file gsl_rtc.h
 *
 * \brief
 *      Include file for gsl rtc graph functionality
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_types.h"
#include "gsl_graph.h"
#include "gsl_rtc_intf.h"


 /*
  * Initialize signals in GSL RTC layer
  *
  * \return AR_EOK for success, error otherwise
  */
int32_t gsl_rtc_internal_init(void);

/*
 * De-initialize signals in GSL RTC layer
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_internal_deinit(void);

/**
 * \brief Get total size in bytes of all the graph key vectors
 * and calibration key vectors in a single graph
 *
 * \param[in] graph: graph obj
 *
 * \return size of graph and calibration key vectors in the graph
 */
uint32_t gsl_rtc_graph_get_gkv_ckv_size(struct gsl_graph *graph);

/**
 * \brief Copy CKVs (in-band) from a single graph in the form -
 *   {{CKV1}, {CKV2}, ... }, where each CKVn is in the form-
 *   {num_kvps, {kvp1}, {kvp2}, ... }
 *
 * \param[in] graph: graph obj
 * \param[in] payload: buffer to copy the ckv data
 * \param[out] num_ckvs: number of ckvs in the graph
 *
 * \return size in bytes of all the cal key vectors in a graph
 */
uint32_t gsl_rtc_graph_copy_ckvs(struct gsl_graph *graph, uint8_t *payload,
	uint32_t *num_ckvs);

/**
 * \brief Copy GKVs (in-band) from a single graph in the form -
 *   {{GKV1}, {GKV2}, ... }, where each GKVn is in the form-
 *   {num_kvps, {kvp1}, {kvp2}, ... }
 *
 * \param[in] graph: graph obj
 * \param[in] payload: buffer to copy the gkv data
 * \param[out] num_gkvs: number of gkvs in the graph
 *
 * \return size in bytes of all the cal key vectors in a graph
 */
uint32_t gsl_rtc_graph_copy_gkvs(struct gsl_graph *graph, uint8_t *payload,
	uint32_t *num_gkvs);

/**
 * \brief Get persist data for the given subgraph in the graph
 *
 * \param[in] graph: graph obj
 * \param[in] sgid: subgraph ID
 * \param[in] proc_id: processor ID
 * \param[in/out] total_size: total size of the persist data
 * \param[out] sg_cal_data: Pointer to buffer containing the persistent data
 *	for this subgraph
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_graph_get_persist_data(struct gsl_graph *graph, uint32_t sgid,
	uint32_t proc_id, uint32_t *total_size, uint8_t **sg_cal_data);

/**
 * \brief Get non-persist data for the given subgraph in the graph
 *
 * \param[in] graph: graph obj
 * \param[in] total_size: total size of the non-persist data
 * \param[in/out] sg_cal_data: Pointer to store non-persist data
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_graph_get_non_persist_data(struct gsl_graph *graph,
	uint32_t total_size, uint8_t *sg_cal_data);

/**
 * \brief Set non-persist data for the given subgraph in the graph
 *
 * \param[in] graph: graph obj
 * \param[in] total_size: total size of the non-persist data
 * \param[in] sg_cal_data: Pointer to non-persist data to be set
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_graph_set_non_persist_data(struct gsl_graph *graph,
	uint32_t total_size, uint8_t *sg_cal_data);

/**
 * \brief Set persist data for the given subgraph in the graph
 *
 * \param[in] graph: graph obj
 * \param[in] params: structure containing all the parameters needed to set
 * persistent data
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_graph_set_persist_data(struct gsl_graph *graph,
	struct gsl_rtc_persist_param *params);

/**
 * \brief Prepare for RTGM graph change operation. This function will do the
 * RTGM related steps that must be done prior to updating the ACDB data
 *
 * \param[in] graph: graph obj
 * \param[in] rtc_params: parameters relating to the graph change
 * \param[in] lock: OPTIONAL lock
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_internal_prepare_change_graph(struct gsl_graph *graph,
	struct gsl_rtc_prepare_change_graph_info *rtc_params,
	ar_osal_mutex_t lock);

/**
 * \brief Perform an RTGM graph change operation. This function will do the
 * RTGM related steps that must be done after updating the ACDB data
 *
 * \param[in] graph: graph obj
 * \param[in] rtc_params: parameters relating to the graph change
 * \param[in] lock: OPTIONAL lock
 *
 * \return AR_EOK for success, error otherwise
 */
int32_t gsl_rtc_internal_change_graph(struct gsl_graph *graph,
	struct gsl_rtc_change_graph_info *rtc_params, ar_osal_mutex_t lock);
#endif /* GSL_RTC_H */
