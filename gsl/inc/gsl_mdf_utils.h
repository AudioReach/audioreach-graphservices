#ifndef GSL_MDF_UTILS_H
#define GSL_MDF_UTILS_H
/**
 * \file gsl_mdf_utils.h
 *
 * \brief
 *      Multi-DSP framework utilities library
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */


 /**
  * @h2xml_title_date {08/01/2018}
  */
 #include "ar_osal_types.h"
 #include "gsl_common.h"

#define GSL_MULTI_DSP_FWK_DATA_MID 0x2005

 /**
  * @h2xmlm_module  {"GSL_MULTI_DSP_FWK_DATA_MID", GSL_MULTI_DSP_FWK_DATA_MID}
  * @h2xmlm_displayName  {"GSL_MULTI_DSP_FWK_DATA_MID"}
  * @h2xmlm_description  {Processor group shared memory information \n}
  *
  * -  This module supports the following parameter IDs: \n
  * - #PARAM_ID_PROC_GROUP_INFO_PARAMS \n
  * - #PARAM_ID_PROC_DOMAIN_INFO \n
  *
  * @{                   <-- Start of the Module -->
  */
#define PARAM_ID_PROC_GROUP_INFO_PARAMS 0x0001
#define PARAM_ID_PROC_DOMAIN_INFO 0x0002

/** @h2xmle_description {Shared memory info of each group}
 * @h2xmlp_subStruct
 */
struct per_group_shmem_info_t {
	/** @h2xmle_description {Size of the shared memory}
	 * @h2xmle_default     {1024}
	 */
	uint32_t shmem_size;

	/** @h2xmle_description {Number of satellite procs in this group}
	 * @h2xmle_default     {1}
	 */
	uint32_t num_satellite_procs;

	/** @h2xmle_description {Master proc in this group}
	 * @h2xmle_default     {1}
	 */
	uint32_t master_proc;

	/** @h2xmle_description {Satellite processor IDs.}
	 * @h2xmle_variableArraySize {num_satellite_procs}
	 */
	uint32_t satellite_proc_ids[];

};

/* Shared memory information for each processor group. */
typedef struct per_group_shmem_info_t per_group_shmem_info_t;


/**
 * @h2xmlp_parameter   {"PARAM_ID_PROC_GROUP_INFO_PARAMS",
 *   PARAM_ID_PROC_GROUP_INFO_PARAMS}
 * @h2xmlp_description {Used to configure processor group info}
 */
struct proc_group_info_params_t {
	/** @h2xmle_description  {Number of processor group.}
	 * @h2xmle_default      {1}
	 */
	uint32_t num_proc_groups;

#ifdef __H2XML__
	/**
	 * @h2xmle_variableArraySize {num_proc_groups}
	 */
	per_group_shmem_info_t shmem_info[];
#endif
};

typedef struct proc_group_info_params_t proc_group_info_params_t;

/** @h2xmle_description {Processor domain type for each processor}
 * @h2xmlp_subStruct
 */
struct proc_domain_type {
	/** @h2xmle_description {Processor id}
	 * @h2xmle_default      {2}
	 */
	uint32_t proc_id;
	/** @h2xmle_description {Proc domain type, 1: static 2: dynamic}
	 * @h2xmle_default      {1}
	 */
	uint32_t proc_type;
};

typedef struct proc_domain_type proc_domain_type_t;

/**
 * @h2xmlp_parameter   {"PARAM_ID_PROC_DOMAIN_INFO",
 *   PARAM_ID_PROC_DOMAIN_INFO}
 * @h2xmlp_description {Used to identify processor domain type}
 */
struct proc_domain_info {
	/** @h2xmle_description {Number of processors}
	 * @h2xmle_default      {1}
	 */
	uint32_t num_procs;
	/**
	 * @h2xmle_variableArraySize {num_procs}
	 */
	proc_domain_type_t domain_type[];
};
/**
 * @}
 */

/*
 * \brief Returns all proc domain ids
 *  Returns number of SPF processors and fills proc_domain_type
 *  array with SPF proc domain id and type
 *
 * \param[out] proc_domains: SPF processors domain info.
 * \param[out] num_procs: number of SPF processors.
 */
int32_t gsl_mdf_utils_get_proc_domain_info(
	proc_domain_type_t **proc_domains, uint32_t *num_procs);

/*
 * \brief Returns all master proc ids
 *  Returns number of SPF masters if master_proc_ids is NULL
 *  Else, fills master_proc_ids array with SPF master proc ids
 *
 * \param[out] num_master_procs: number of SPF masters.
 * \param[out] master_proc_ids: Array of SPF master proc ids
 */
int32_t gsl_mdf_utils_get_master_proc_ids(uint32_t *num_master_procs,
					  uint32_t master_proc_ids[]);

/*
 * \brief Returns the susbsytem mask of master proc and it's satellites
 *
 * \param[in] master_proc: SPF master proc id
 * \param[out] supported_ss_mask: Subsystem mask including master proc mask
 *
 */
int32_t gsl_mdf_utils_get_supported_ss_info_from_master_proc(
						     uint32_t master_proc,
						     uint32_t *supported_ss_mask);

/*
 * \brief Returns if the subsystem mask is of a master proc
 *
 * \param[in] supported_ss_mask: Subsystem mask
 *
 */
bool_t gsl_mdf_utils_is_master_proc(uint32_t spf_ss_mask);

/*
 * \brief Returns the master proc corresponding to the mask.
 *  Returns 0 if it doesn't exist in proc group of any master proc.
 *
 * \param[in] supported_ss_mask: Subsystem mask
 *
 */
uint32_t gsl_mdf_utils_get_master_proc_id(uint32_t spf_ss_mask);

/*
 * \brief Looks up the spf susbsytem ids from ACDB
 *
 * \param[in] sg_list: subgraph id list comprising a graph
 * \param[in] num_sg: number of subgraphs in sg list
 * \param[out] ss_mask: mask comprising this subsystems this graph requires,
 * use macros from gsl_spf_ss_state.h to test if a subsystem is present
 * \return AR_EOK on success, error code otherwise
 */
uint32_t gsl_mdf_utils_query_graph_ss_mask(uint32_t *sg_id_list,
	uint32_t num_sgs, uint32_t *ss_mask);

/*
 * \brief allocate the loaned MDF shmem for a given ss_mask if not already
 * done so
 *
 *  \param[in] ss_mask: mask representing the set of subsystems for which to
 * allocate the shared loaned memory
 * \param[in] master_proc: SPF master proc id
 *
 */
int32_t gsl_mdf_utils_shmem_alloc(uint32_t ss_mask, uint32_t master_proc);

/*
 * \brief notify mdf utils that some ss have been restarted. This is to remap
 * the loaned memory to those ss.
 *
 *  \param[in] restarted_ss_mask: mask representing the set of subsystems which
 * have been restarted
 */
void gsl_mdf_utils_notify_ss_restarted(uint32_t restarted_ss_mask);

/*
 * \brief frees or unmap the mdf shmem for all ss groups.
 *
 *  \param[in] ss_mask: mask representing the set of subsystems for which to
 * de-allocate or un map the shared loaned memory
 */
int32_t gsl_mdf_utils_shmem_free(uint32_t ss_mask);

/*
 * \brief Creates dynamic PD and allocates shared memory for given
 * subsystems
 *
 * \param[in] ss_mask: mask representing the subsystems
 * \param[in] master_proc_id: Master proc id
 */
int32_t gsl_mdf_utils_register_dynamic_pd(uint32_t ss_mask,
	uint32_t master_proc_id, uint32_t src_port,
	struct gsl_signal *sig, uint32_t *dyn_ss_mask);

/*
 * \brief Releases dynamic PD and deallocates shared memory for given
 * subsystems
 * \param[in] ss_mask: mask representing the subsystems
 * \param[in] master_proc_id: Master proc id
 */
int32_t gsl_mdf_utils_deregister_dynamic_pd(uint32_t ss_mask,
	uint32_t master_proc_id);

/*
 * \brief Check if the given subsystem is of dynamic PD type
 * \param[in] sys_id: proc id
 * \return TRUE if dynamic PD, FALSE otherwise.
 */
bool_t gsl_mdf_utils_is_dynamic_pd(uint32_t proc_id);

/*
 * \brief Check if dynamic PD is active for a given subsystem
 * \param[in] sys_id: proc id
 * \return TRUE if pending, FALSE otherwise.
 */
bool_t gsl_mdf_utils_get_dynamic_pd_state(uint32_t proc_id);

/*
 * \brief initialize MDF utils, internally queries ACDB to get supported SS info
 *
 */
int32_t gsl_mdf_utils_init(void);

int32_t gsl_mdf_utils_deinit(void);
#endif
