#ifndef GSL_SHMEM_MGR_H
#define GSL_SHMEM_MGR_H
/**
 * \file gsl_shmem_mgr.h
 *
 * \brief
 *   Manages shared memory that is mapped to Spf, tries to reuse existing
 *    unused memory blocks that are already mapped with Spf across multiple
 *   GSL sessions
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "ar_osal_error.h"
#include "ar_osal_types.h"

#define GSL_SHMEM_MGR_FRAME_SZ_SHIFT 10 /* frame size = 1024 */
#define GSL_SHMEM_MGR_FRAME_SZ (1 << GSL_SHMEM_MGR_FRAME_SZ_SHIFT)

/* flags that can get or'ed and passed to alloc functions */
#define GSL_SHMEM_LOANED 0x1
#define GSL_SHMEM_DEDICATED_PAGE 0x2
#define GSL_SHMEM_MAP_UNCACHED 0x4
#define GSL_SHMEM_CMA 0x8

/* used to tell SPF we're doing something with CMA */
#define GSL_GPR_CMA_FLAG_BIT 0x2

typedef struct gsl_shmem_page *gsl_shmem_handle_t;

struct gsl_shmem_alloc_data {
	gsl_shmem_handle_t handle; /*< shmem mgr handle */
	void *v_addr; /*< address to be used by client for accessing buffer */
	uint32_t spf_mmap_handle; /*< handle to be passed to Spf */
	uint64_t spf_addr; /*< spf addr <msw,lsw> populated from ipa */
	uint64_t metadata; /*< metadata returned from OSAL */
};

struct gsl_shmem_alloc_data_per_proc {
	uint32_t proc_id;
	struct gsl_shmem_alloc_data persist_cal_data;
	uint32_t persist_cal_data_size;
};

/*
 * master_proc id values can vary from AR_SUB_SYS_ID_FIRST - AR_SUB_SYS_ID_LAST
 * proc_ids as defined in ar_osal_sys_id.h
 */
int32_t gsl_shmem_init(uint32_t num_master_procs, uint32_t *master_procs);

int32_t gsl_shmem_deinit(void);

int32_t gsl_shmem_alloc(uint32_t size_bytes, uint32_t master_proc_id,
	struct gsl_shmem_alloc_data *alloc_data);

int32_t gsl_shmem_alloc_ext(uint32_t size_bytes, uint32_t spf_ss_mask,
	uint32_t flags, uint32_t platform_info, uint32_t master_proc_id,
	struct gsl_shmem_alloc_data *alloc_data);

int32_t gsl_shmem_map_extern_mem(uint64_t ext_mem_hdl, uint32_t size_bytes,
	uint32_t master_proc_id, struct gsl_shmem_alloc_data *alloc_data);

int32_t gsl_shmem_unmap_extern_mem(struct gsl_shmem_alloc_data alloc_data);

uint64_t gsl_shmem_get_metadata(
	const struct gsl_shmem_alloc_data *alloc_data);

int32_t gsl_shmem_get_mapped_ss_mask(
	const struct gsl_shmem_alloc_data *alloc_data);

int32_t gsl_shmem_free(struct gsl_shmem_alloc_data *alloc_data);

void gsl_shmem_signal_ssr(uint32_t master_proc_id);
void gsl_shmem_clear_ssr(uint32_t master_proc_id);
void gsl_shmem_remap_pre_alloc(uint32_t master_proc_id);
int32_t gsl_shmem_map_allocation(const struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask_to_map_to, uint32_t master_proc_id);
int32_t gsl_shmem_map_allocation_to_spf(
	const struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask_to_map_to,
	uint32_t master_proc_id);
int32_t gsl_shmem_unmap_allocation(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t ss_mask_to_unmap_to);
int32_t gsl_shmem_map_dynamic_pd(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask, uint32_t master_proc_id);
int32_t gsl_shmem_unmap_dynamic_pd(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t ss_mask, uint32_t master_proc_id);
void gsl_shmem_cache_pending_memmap_packets(uint32_t master_proc_id, void *gpr_packet);
uint32_t gsl_shmem_check_and_unmap_cache_pending_packets(uint32_t master_proc_id);

int32_t gsl_shmem_hyp_assign(gsl_shmem_handle_t alloc_handle,
	uint64_t dest_sys, uint64_t src_sys);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif
