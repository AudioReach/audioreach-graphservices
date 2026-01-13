/**
 * \file gsl_mdf_utils.c
 *
 * \brief
 *      Multi-DSP framework utilities library
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_mdf_utils.h"
#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "ar_osal_sys_id.h"
#include "ar_osal_shmem.h"
#include "ar_osal_dyn_pd.h"
#include "acdb.h"
#include "gsl_common.h"
#include "gsl_msg_builder.h"
#include "gpr_api_inline.h"

 /**
  * This structure represents a goup of susbsytems that share a common client
  * loaned memory allocation
  */
struct gsl_spf_ss_group {
	/* bit mask that represents the set of subsystems in this group */
	uint32_t ss_mask;

	/* bit mask indicates if the corresponding ss has been restarted */
	uint32_t ss_restarted_flags;
	/*
	 * used to store the size of client loaned memory in bytes, this is read
	 * from ACDB
	 */
	uint32_t loaned_mem_sz;
	/*
	 * master proc id
	 */
	uint32_t master_proc;
	/* hold the shmem allocation */
	struct gsl_shmem_alloc_data loaned_mem;
};


struct gsl_mdf_info {
	/*
	 * number of ss groups
	 */
	uint32_t num_ss_groups;
	/*
	 * list of ss groups
	 */
	struct gsl_spf_ss_group *ss_groups;
	/*
	 * master proc mask
	 */
	uint32_t master_proc_mask;
	/* number of subsystems */
	uint32_t num_procs;
	/* susbystems domain type information */
	struct proc_domain_type *pd_info;
	/* dynamic pd reference count */
	uint32_t pd_init_ref_cnt[AR_SUB_SYS_ID_LAST + 1];
	/* dynamic pd deinit pending used to skip PD DOWN treated as crash */
	bool_t pd_deinit_pending[AR_SUB_SYS_ID_LAST + 1];

} _gsl_glb_mdf_info = {0, NULL, 0, 0, NULL, {0}, {FALSE}};

static bool_t is_initialized = FALSE;

bool_t gsl_mdf_utils_is_dynamic_pd(uint32_t proc_id)
{
	uint32_t i = 0;

	for (i = 0; i < _gsl_glb_mdf_info.num_procs; ++i) {
		if (_gsl_glb_mdf_info.pd_info[i].proc_id == proc_id &&
			_gsl_glb_mdf_info.pd_info[i].proc_type == DYNAMIC_PD)
				return TRUE;
	}
	return FALSE;
}

bool_t gsl_mdf_utils_get_dynamic_pd_state(uint32_t proc_id)
{
	if ((proc_id >= AR_SUB_SYS_ID_FIRST && proc_id <= AR_SUB_SYS_ID_LAST) &&
		_gsl_glb_mdf_info.pd_init_ref_cnt[proc_id] &&
		!_gsl_glb_mdf_info.pd_deinit_pending[proc_id])
		return TRUE;

	return FALSE;
}

uint32_t gsl_mdf_utils_query_graph_ss_mask(uint32_t *sg_id_list,
	uint32_t num_sgs, uint32_t *ss_mask)
{
	int32_t rc = AR_EOK;
	AcdbCmdGetSubgraphProcIdsReq req = {0,};
	AcdbCmdGetSubgraphProcIdsRsp rsp;
	uint32_t i = 0, j = 0;
	AcdbSgProcIdsMap *p = NULL;

	if (!ss_mask || !sg_id_list)
		return AR_EBADPARAM;

	/* first call to get size */
	req.num_sg_ids = num_sgs;
	req.sg_ids = sg_id_list;
	rsp.num_sg_ids = 0;
	rsp.size = 0;
	rsp.sg_proc_ids = NULL;
	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_PROCIDS, &req, sizeof(req), &rsp,
		sizeof(rsp));
	if (rc != AR_EOK && rc != AR_ENOTEXIST) {
		GSL_ERR("ACDB get subgraph procids failed %d", rc);
		return rc;
	} else if (rc == AR_ENOTEXIST) {
		/* if not ss*/
		*ss_mask = GSL_GET_SPF_SS_MASK(AR_DEFAULT_DSP);
		return AR_EOK;
	}

	rsp.sg_proc_ids = gsl_mem_zalloc(rsp.size);
	if (!rsp.sg_proc_ids) {
		rc = AR_ENOMEMORY;
		return rc;
	}

	/* next call to get data */
	rc = acdb_ioctl(ACDB_CMD_GET_SUBGRAPH_PROCIDS, &req, sizeof(req), &rsp,
		sizeof(rsp));
	if (rc != AR_EOK) {
		GSL_ERR("ACDB get subgraph procids failed %d", rc);
		goto free_sg_proc_ids;
	}

	*ss_mask = 0;
	p = rsp.sg_proc_ids;
	for (i = 0; i < rsp.num_sg_ids; ++i) {
		for (j = 0; j < p->num_proc_ids; ++j)
			*ss_mask |= GSL_GET_SPF_SS_MASK(p->proc_ids[j]);
		/* move p forward to the next SG entry */
		p = (AcdbSgProcIdsMap *)((uint32_t *)p + 2 + p->num_proc_ids);
	}

free_sg_proc_ids:
	gsl_mem_free(rsp.sg_proc_ids);
	return AR_EOK;
}

int32_t gsl_mdf_utils_get_master_proc_ids(uint32_t *num_masters,
					  uint32_t master_proc_ids[])
{
	uint32_t i = 0;

	if (num_masters == NULL)
		return AR_EBADPARAM;
	if (master_proc_ids == NULL) {
		*num_masters = _gsl_glb_mdf_info.num_ss_groups;
	} else {
		for (i = 0; i < _gsl_glb_mdf_info.num_ss_groups; i++)
			master_proc_ids[i] = _gsl_glb_mdf_info.ss_groups[i].master_proc;
	}
	return AR_EOK;
}

int32_t gsl_mdf_utils_get_supported_ss_info_from_master_proc(
							uint32_t master_proc,
							uint32_t *supported_ss_mask)
{
	int32_t rc = AR_ENOTEXIST;
	uint32_t i = 0;

	for (; i < _gsl_glb_mdf_info.num_ss_groups; i++) {
		if (_gsl_glb_mdf_info.ss_groups[i].master_proc == master_proc) {
			*supported_ss_mask = _gsl_glb_mdf_info.ss_groups[i].ss_mask;
			rc = AR_EOK;
			return rc;
		}
	}
	return rc;
}

int32_t gsl_mdf_utils_get_proc_domain_info(
	proc_domain_type_t **proc_domains, uint32_t *num_procs)
{
	if (!proc_domains || !num_procs)
		return AR_EBADPARAM;
	*num_procs = _gsl_glb_mdf_info.num_procs;
	*proc_domains = _gsl_glb_mdf_info.pd_info;
	return AR_EOK;
}

bool_t gsl_mdf_utils_is_master_proc(uint32_t spf_ss_mask)
{
	if (spf_ss_mask & _gsl_glb_mdf_info.master_proc_mask)
		return TRUE;
	return FALSE;
}

uint32_t gsl_mdf_utils_get_master_proc_id(uint32_t spf_ss_mask)
{
	uint32_t i = 0;

	for (; i < _gsl_glb_mdf_info.num_ss_groups; i++) {
		if (_gsl_glb_mdf_info.ss_groups[i].ss_mask & spf_ss_mask)
			return _gsl_glb_mdf_info.ss_groups[i].master_proc;
	}
	return 0;
}

int32_t gsl_mdf_utils_get_supported_ss_info_from_acdb(void)
{
	AcdbDriverData acdb_req = { 0, };
	AcdbBlob acdb_rsp = { 0, };
	struct proc_group_info_params_t  *grps = NULL;
	struct per_group_shmem_info_t *p = { 0, };
	struct proc_domain_info *pd = NULL;
	struct proc_domain_type *pt = NULL;
	int32_t rc = AR_EOK;
	uint32_t i = 0, j = 0, *tmp_p = NULL, *tmp_pos = NULL;
	bool_t found = FALSE;

	/* first query for size */
	acdb_req.key_vector.num_keys = 0;
	acdb_req.module_id = GSL_MULTI_DSP_FWK_DATA_MID;
	acdb_rsp.buf = NULL;
	acdb_rsp.buf_size = 0;
	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &acdb_req, sizeof(acdb_req),
		&acdb_rsp, sizeof(acdb_rsp));
	if (rc != AR_EOK && rc != AR_ENOTEXIST) {
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_DATA failed %d", rc);
		return rc;
	} else if (rc == AR_ENOTEXIST) {
		/* if MDF driver data is not found, assume we only have ADSP */
		_gsl_glb_mdf_info.num_ss_groups = 1;
		_gsl_glb_mdf_info.num_procs = 0;
		_gsl_glb_mdf_info.pd_info = NULL;
		_gsl_glb_mdf_info.ss_groups =
					gsl_mem_zalloc(sizeof(struct gsl_spf_ss_group));

		if (_gsl_glb_mdf_info.ss_groups == NULL) {
			rc = AR_ENOMEMORY;
			return rc;
		}

		_gsl_glb_mdf_info.ss_groups[0].master_proc = AR_DEFAULT_DSP;
		_gsl_glb_mdf_info.ss_groups[0].ss_mask =
						GSL_GET_SPF_SS_MASK(AR_DEFAULT_DSP);
		_gsl_glb_mdf_info.ss_groups[0].loaned_mem_sz = 0;
		_gsl_glb_mdf_info.master_proc_mask =
						GSL_GET_SPF_SS_MASK(AR_DEFAULT_DSP);

		return AR_EOK;
	}

	acdb_rsp.buf = gsl_mem_zalloc(acdb_rsp.buf_size);
	if (!acdb_rsp.buf) {
		rc = AR_ENOMEMORY;
		return rc;
	}

	rc = acdb_ioctl(ACDB_CMD_GET_DRIVER_DATA, &acdb_req, sizeof(acdb_req),
		&acdb_rsp, sizeof(acdb_rsp));
	if (rc != AR_EOK) {
		GSL_ERR("acdb query ACDB_CMD_GET_DRIVER_DATA failed %d", rc);
		goto exit;
	}

	tmp_p = (uint32_t *)acdb_rsp.buf;
	/* MID */
	if (*tmp_p++ != GSL_MULTI_DSP_FWK_DATA_MID) {
		GSL_ERR("got incorrect MID from ACDB %d", *((uint32_t *)acdb_rsp.buf));
		goto exit;
	}

	acdb_rsp.buf_size -= 4; /* PARAM ID GSL_MULTI_DSP_FWK_DATA_MID size */
	while (acdb_rsp.buf_size > 0) {
		if (*tmp_p == PARAM_ID_PROC_GROUP_INFO_PARAMS) {
			tmp_pos = tmp_p;
			++tmp_p; /* Skip Param ID */
			++tmp_p; /* skip SIZE */
			grps = (struct proc_group_info_params_t *)tmp_p;
			_gsl_glb_mdf_info.num_ss_groups = grps->num_proc_groups;

			_gsl_glb_mdf_info.ss_groups = gsl_mem_zalloc(
							grps->num_proc_groups *
							sizeof(struct gsl_spf_ss_group));

			if (_gsl_glb_mdf_info.ss_groups == NULL) {
				rc = AR_ENOMEMORY;
				goto exit;
			}

			/* make p point to group list */
			p = (struct  per_group_shmem_info_t *)((uint8_t *)grps +
				sizeof(struct proc_group_info_params_t));
			for (; i < grps->num_proc_groups; ++i) {
				_gsl_glb_mdf_info.ss_groups[i].ss_mask = 0;
				_gsl_glb_mdf_info.ss_groups[i].master_proc = p->master_proc;
				_gsl_glb_mdf_info.ss_groups[i].ss_mask |=
								GSL_GET_SPF_SS_MASK(p->master_proc);
				_gsl_glb_mdf_info.master_proc_mask |=
								GSL_GET_SPF_SS_MASK(p->master_proc);
				for (j = 0; j < p->num_satellite_procs; ++j) {
					_gsl_glb_mdf_info.ss_groups[i].ss_mask |=
						GSL_GET_SPF_SS_MASK(p->satellite_proc_ids[j]);
				}
				/* store the client loaned mem size for this group */
				_gsl_glb_mdf_info.ss_groups[i].loaned_mem_sz = p->shmem_size;

				/* add this group's subsystems to global supported ss mask */

				/* move p forward to next  processor group */
				p = (struct per_group_shmem_info_t *)((uint8_t *)p +
					sizeof(struct per_group_shmem_info_t) +
					p->num_satellite_procs * sizeof(uint32_t));
			}
			acdb_rsp.buf_size -= ((void *)p - (void *)tmp_pos);
			tmp_p = (uint32_t *)p;
		} else if (*tmp_p == PARAM_ID_PROC_DOMAIN_INFO) {
			tmp_pos = tmp_p;
			++tmp_p; /* Skip Param ID */
			++tmp_p; /* Skip Size */
			pd = (struct proc_domain_info *)tmp_p;
			_gsl_glb_mdf_info.num_procs = pd->num_procs;
			_gsl_glb_mdf_info.pd_info = gsl_mem_zalloc(
							pd->num_procs * sizeof(struct proc_domain_type));

			if (_gsl_glb_mdf_info.pd_info == NULL) {
				rc = AR_ENOMEMORY;
				goto exit;
			}
			pt = pd->domain_type;
			for (i = 0; i < pd->num_procs; ++i) {
				_gsl_glb_mdf_info.pd_info[i].proc_id = pt->proc_id;
				_gsl_glb_mdf_info.pd_info[i].proc_type = pt->proc_type;
				++pt;
			}
			acdb_rsp.buf_size -= ((void *)pt - (void *)tmp_pos);
			tmp_p = (uint32_t *)pt;
		} else {
			GSL_ERR("got incorrect PID from ACDB %d",
					*((uint32_t *)acdb_rsp.buf));
			goto exit;
		}
	}
	if (grps == NULL) {
		rc = AR_ENOTEXIST;
		goto exit;
	}
	for (i = 0; i < _gsl_glb_mdf_info.num_procs; ++i) {
		found = FALSE;
		for (j = 0; j <  grps->num_proc_groups; ++j) {
			if ((GSL_TEST_SPF_SS_BIT(_gsl_glb_mdf_info.ss_groups[j].ss_mask,
				_gsl_glb_mdf_info.pd_info[i].proc_id))) {
					found = TRUE;
					break;
			}
		}
		if (found == FALSE) {
			GSL_ERR("group info does not have proc %d",
				_gsl_glb_mdf_info.pd_info[i].proc_id);
			break;
		}
	}

exit:
	gsl_mem_free(acdb_rsp.buf);
	if (rc && _gsl_glb_mdf_info.ss_groups)
		 free(_gsl_glb_mdf_info.ss_groups);
	if (rc && _gsl_glb_mdf_info.pd_info)
		 free(_gsl_glb_mdf_info.pd_info);

	return rc;
}

void gsl_mdf_utils_notify_ss_restarted(uint32_t restarted_ss_mask)
{
	uint32_t i = 0;
	struct gsl_spf_ss_group *grp = NULL;
	uint32_t tmp_ss_mask = 0;

	/* search through the group proc_ids and find matching ss_mask */
	for (i = 0; i < _gsl_glb_mdf_info.num_ss_groups; ++i) {
		grp = &_gsl_glb_mdf_info.ss_groups[i];

		/*
		 * if master is crashed then mark all ss in the group as restarted
		 * this is required because we need to remap to all satellites if
		 * the master crashed. For now we assume ADSP is the master.
		 */
		if (GSL_TEST_SPF_SS_BIT(restarted_ss_mask, grp->master_proc)) {
			grp->ss_restarted_flags = grp->ss_mask;
		} else {
			tmp_ss_mask = grp->ss_mask & restarted_ss_mask;
			/*
			 * Check if any ss in the current group is restarted
			 */
			if (tmp_ss_mask)
				grp->ss_restarted_flags = tmp_ss_mask;
		}
	}
}

/*
 * finds the proc group object matching ss_mask and allocates the loaned memory
 * for it
 */
int32_t gsl_mdf_utils_shmem_alloc(uint32_t ss_mask, uint32_t master_proc)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0;
	struct gsl_spf_ss_group *grp = NULL;
	uint32_t tmp_ss_mask = 0;

	/* noop if this graph only depends on master proc */
	if (ss_mask == (uint32_t) GSL_GET_SPF_SS_MASK(master_proc))
		goto exit;

	/* search through the group proc_ids and find matching ss_mask */
	for (i = 0; i < _gsl_glb_mdf_info.num_ss_groups; ++i) {
		grp = &_gsl_glb_mdf_info.ss_groups[i];
		/*
		 * If ss_mask is all clear it means we have allocated for all the
		 * required subsystems.
		 */
		if (!ss_mask)
			break;
		/*
		 * If loaned shmem for this group is already allocated, see if remap
		 * is required to any ss due to ssr or map if dynamic pd.
		 */
		if (grp->loaned_mem.handle) {
			if (grp->ss_restarted_flags) {
				gsl_shmem_map_allocation_to_spf(&grp->loaned_mem,
					GSL_SHMEM_LOANED, grp->ss_restarted_flags,
					master_proc);
				grp->ss_restarted_flags = 0;
				/*
				 * Clear bits corresponding to current group to indicate that
				 * we have already allocated memory for them
				 */
				ss_mask &= ~grp->ss_mask;
			}
			/*
			* If a group contains both dynamic and static dynamic pds,
			* the loaned memory already gets allocated at boot up but the
			* mapping for dynamic pd gets skipped as dynamic pd is created
			* and released during use case boundary. Check and map memory
			* for dynamic pd.
			*/
			tmp_ss_mask = grp->ss_mask & ss_mask;
			if (tmp_ss_mask) {
				GSL_DBG("map dyn pd loaned mem, ss_mask 0x%x", tmp_ss_mask);
				rc = gsl_shmem_map_dynamic_pd(&grp->loaned_mem,
					GSL_SHMEM_LOANED, tmp_ss_mask, grp->master_proc);
				if (rc != AR_EOK)
					goto exit;
			}
			ss_mask &= ~tmp_ss_mask;
			continue;
		} else if (grp->ss_restarted_flags) {
			/*
			 * ss_restarted_flags is used to indicate if remap
			 * is needed for allocated loaned shmem. If there's
			 * no loaned shmem allocated, this flag can be reset.
			 */
			grp->ss_restarted_flags = 0;
		}

		tmp_ss_mask = grp->ss_mask & ss_mask;
		/*
		 * Check if any ss in the current group is needed by the graph (note:
		 * a ss can appear in only one group)
		 */
		if (tmp_ss_mask) {
			GSL_DBG("Allocate loaned memory, ss_mask 0x%x", tmp_ss_mask);
			rc = gsl_shmem_alloc_ext(grp->loaned_mem_sz, tmp_ss_mask,
				GSL_SHMEM_LOANED, 0, grp->master_proc, &grp->loaned_mem);
			if (rc != AR_EOK) {
				GSL_ERR("shmem alloc failed %d", rc);
				break;
			}
			/*
			 * Clear bits corresponding to current group to indicate that we
			 * have already allocated memory for them'
			 */
			ss_mask &= ~tmp_ss_mask;
		}
	}
	/* if we did not find a matching group for atleast one ss then error out */
	if (ss_mask)
		rc = AR_ENOTEXIST;

exit:
	return rc;
}

/*
 * frees the mdf shmem for the request ss_mask.
 */
int32_t gsl_mdf_utils_shmem_free(uint32_t ss_mask)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0;
	struct gsl_spf_ss_group *grp = NULL;
	uint32_t tmp_ss_mask = 0;

	/* loop through the groups and free the shmem for each */
	for (i = 0; i < _gsl_glb_mdf_info.num_ss_groups; ++i) {
		grp = &_gsl_glb_mdf_info.ss_groups[i];
		if (grp->loaned_mem.handle) {
			if (ss_mask == AR_SUB_SYS_IDS_MASK ||
				gsl_shmem_get_mapped_ss_mask(&grp->loaned_mem) == ss_mask) {

				GSL_DBG("free loaned memory, ss_mask 0x%x", ss_mask);
				rc = gsl_shmem_free(&grp->loaned_mem);
				if (rc == AR_EOK)
					grp->loaned_mem.handle = NULL;
				else
					GSL_ERR("shmem free failed %d", rc);
			} else {
				/*
				 * if both static and dynamic pd are present,
				 * unmap dynamic pd memory.
				 */
				tmp_ss_mask = grp->ss_mask & ss_mask;
				if (tmp_ss_mask) {
					GSL_DBG("unmap dyn pd loaned mem, ss_mask 0x%x", tmp_ss_mask);
					gsl_shmem_unmap_dynamic_pd(&grp->loaned_mem,
						tmp_ss_mask, grp->master_proc);
				}
				ss_mask &= ~tmp_ss_mask;
				if (!ss_mask)
					break;
			}
		}
	}

	return rc;
}

/*
 * Creates dynamic PD and allocates shared memory.
 */
int32_t gsl_mdf_utils_register_dynamic_pd(uint32_t ss_mask,
	uint32_t master_proc_id, uint32_t src_port,
	struct gsl_signal *sig, uint32_t *dyn_ss_mask)
{
	int32_t rc = AR_EOK;
	uint32_t sys_id = AR_SUB_SYS_ID_FIRST, tmp_ss_mask = 0, sm = 0;
	uint32_t tmp_pd_list[AR_SUB_SYS_ID_LAST] = {0}, pd_cnt = 0;

	if (!dyn_ss_mask)
		return AR_EBADPARAM;
	*dyn_ss_mask = 0;
	tmp_ss_mask = ss_mask;
	while (tmp_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(ss_mask, sys_id)) {
			if (sys_id == master_proc_id ||
				!gsl_mdf_utils_is_dynamic_pd(sys_id))
				goto next;

			*dyn_ss_mask |= GSL_GET_SPF_SS_MASK(sys_id);
			if (_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id] == 0) {
				GSL_DBG("initialize dynamic pd %d", sys_id);
				rc = ar_osal_dyn_pd_init(sys_id);
				if (rc) {
					GSL_ERR("ar_osal_dyn_pd_init failed %d", rc);
					goto de_init_pd;
				}
				++_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id];
				tmp_pd_list[pd_cnt++] = sys_id;
				sm = GSL_GET_SPF_SS_MASK(sys_id) |
					GSL_GET_SPF_SS_MASK(master_proc_id);
				GSL_DBG("Allocate memory ss_mask 0x%x", sm);
				rc = gsl_mdf_utils_shmem_alloc(sm, master_proc_id);
				if (rc != AR_EOK) {
					GSL_ERR("failed to alloc loaned shmem %d", rc);
					goto de_init_pd;
				}
				GSL_DBG("send spf satellite info, ss_mask 0x%x", sm);
				rc = gsl_send_spf_satellite_info(master_proc_id, sm, src_port, sig);
				if (rc != AR_EOK) {
					GSL_ERR("failed to send satellite info, error %d, ss_mask 0x%x",
						rc, ss_mask);
					gsl_mdf_utils_shmem_free(sm);
					goto de_init_pd;
				}
			} else {
				++_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id];
				tmp_pd_list[pd_cnt++] = sys_id;
			}
		}
	next:
		++sys_id;
		tmp_ss_mask >>= 1;
	}
	return rc;

de_init_pd:
	while (pd_cnt > 0) {
		--pd_cnt;
		if (_gsl_glb_mdf_info.pd_init_ref_cnt[tmp_pd_list[pd_cnt]] == 1)
			ar_osal_dyn_pd_deinit(tmp_pd_list[pd_cnt]);
		--_gsl_glb_mdf_info.pd_init_ref_cnt[tmp_pd_list[pd_cnt]];
	}
	return rc;
}

/*
 * Releases dynamic PD and deallocates shared memory.
 */
int32_t gsl_mdf_utils_deregister_dynamic_pd(uint32_t ss_mask,
	uint32_t master_proc_id)
{
	int32_t rc = AR_EOK;
	uint32_t sys_id = AR_SUB_SYS_ID_FIRST, tmp_ss_mask = 0, sm = 0;
	uint32_t tmp_pd_list[AR_SUB_SYS_ID_LAST] = {0}, pd_cnt = 0;

	tmp_ss_mask = ss_mask;
	while (tmp_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(ss_mask, sys_id)) {
			if (sys_id == master_proc_id ||
				!gsl_mdf_utils_is_dynamic_pd(sys_id)) {
				goto next;
			}
			if (_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id] == 1) {
				sm = GSL_GET_SPF_SS_MASK(sys_id) |
					GSL_GET_SPF_SS_MASK(master_proc_id);
				GSL_DBG("Free memory ss_mask 0x%x", sm);
				rc = gsl_mdf_utils_shmem_free(sm);
				if (rc != AR_EOK)
					GSL_ERR("failed to free loaned shmem %d", rc);
				GSL_DBG("deinitialize dynamic pd %d", sys_id);

				_gsl_glb_mdf_info.pd_deinit_pending[sys_id] = TRUE;
				ar_osal_dyn_pd_deinit(sys_id);
				_gsl_glb_mdf_info.pd_deinit_pending[sys_id] = FALSE;
			}
			if (_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id] > 0)
				--_gsl_glb_mdf_info.pd_init_ref_cnt[sys_id];
		}
	next:
		++sys_id;
		tmp_ss_mask >>= 1;
	}
	return rc;
}

int32_t gsl_mdf_utils_init(void)
{
	if (!is_initialized) {
		gsl_memset(&_gsl_glb_mdf_info, 0, sizeof(_gsl_glb_mdf_info));
		is_initialized = TRUE;
		return gsl_mdf_utils_get_supported_ss_info_from_acdb();
	}
	return AR_EOK;
}

int32_t gsl_mdf_utils_deinit(void)
{
	int32_t rc = AR_EOK;

	if (is_initialized) {
		is_initialized = FALSE;
		rc = gsl_mdf_utils_shmem_free(AR_SUB_SYS_IDS_MASK);
		gsl_mem_free(_gsl_glb_mdf_info.ss_groups);
		gsl_mem_free(_gsl_glb_mdf_info.pd_info);
		gsl_memset(&_gsl_glb_mdf_info, 0, sizeof(_gsl_glb_mdf_info));
	}
	return rc;
}
