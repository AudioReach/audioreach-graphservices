/**
 * \file gsl_shmem_mgr.c
 *
 * \brief
 *      Manages shared memory allocations across all graphs in the system
 *
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include "gsl_shmem_mgr.h"
#include "ar_osal_shmem.h"
#include "ar_util_list.h"
#include "ar_osal_mutex.h"
#include "ar_osal_signal.h"
#include "ar_osal_error.h"
#include "ar_osal_sys_id.h"
#include "gsl_common.h"
#include "apm_memmap_api.h"
#include "apm_api.h"
#include "gpr_ids_domains.h"
#include "gpr_api_inline.h"
#include "gsl_spf_ss_state.h"
#include "gsl_mdf_utils.h"

/**
 * all pages must have size that is a multiple of this
 */
#define GSL_SHMEM_MGR_PAGE_SZ_SHIFT 12 /* page size = 4096 */
#define GSL_SHMEM_MGR_PAGE_SZ (1 << GSL_SHMEM_MGR_PAGE_SZ_SHIFT)
#define GSL_SHMEM_MGR_CONVERT_BYTES_TO_PAGES(size_bytes)\
((size_bytes) >> GSL_SHMEM_MGR_PAGE_SZ_SHIFT)

/* set maximum scratch memory allocation size to be equal to 4 pages */
#define GSL_SHMEM_MAX_SCRATCH_ALLOC_SZ (GSL_SHMEM_MGR_PAGE_SZ<<2)
#define GSL_SHMEM_MAX_FRAMES_IN_SCRATCH_ALLOC \
(GSL_SHMEM_MAX_SCRATCH_ALLOC_SZ >> GSL_SHMEM_MGR_FRAME_SZ_SHIFT)

/* size of the pre-allocated page, set to 32K */
#define GSL_SHMEM_PRE_ALLOC_SIZE (GSL_SHMEM_MAX_SCRATCH_ALLOC_SZ<<1)

/**
 * A single page contains multiple frames
 */
#define GSL_SHMEM_MGR_CONVERT_BYTES_TO_FRAMES(size_bytes)\
((size_bytes) >> GSL_SHMEM_MGR_FRAME_SZ_SHIFT)

/**
 * number of bins
 */
#define GSL_SHMEM_MGR_NUM_BINS 3
#define GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH 0
#define GSL_SHMEM_MGR_BIN_IDX_SCRATCH 1
#define GSL_SHMEM_MGR_BIN_IDX_DEDICATED 2

 /** we use LSB in size field to indicate whether a block is used or free */
#define GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK 0x0001
#define GSL_SHMEM_SRC_PORT 0x2002

#define GSL_SHMEM_IS_OFFSET_MODE(type) \
(((ar_shmem_buffer_index_type_t)(type)) == AR_SHMEM_BUFFER_OFFSET)

struct gsl_apm_mem_map {
	struct apm_cmd_shared_mem_map_regions_t mmap_header;
	struct apm_shared_map_region_payload_t mmap_payload;
};

struct gsl_apm_mem_map_satellite {
	struct apm_cmd_shared_satellite_mem_map_regions_t mmap_header;
	struct apm_shared_map_region_payload_t mmap_payload;
};

struct gsl_shmem_block {
	/**
	 * Address of the block that is returned back to caller
	 */
	void *base_addr;
	/**
	 * Since size is FRAME aligned use LSB as used/free bit.
	 * USED = 1
	 * FREE = 0
	 */
	uint32_t size_bytes;
	/**
	 * index of the preceeding block, used in merge operation
	 * -1 indicates there is no predecessor
	 */
	int16_t predecessor_idx;
	/**
	 * index of the successor block, used in merge operation
	 * -1 indicates there is no successor
	 */
	int16_t successor_idx;
#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	/**
	 * Actual size that was requested by client for this block, this might be
	 * smaller than the block size as it need not be a multiple of FRAME_SIZE
	 */
	int32_t requested_size_bytes;
#endif

};

struct gsl_shmem_page {
	ar_list_node_t node;
	/** size of this page */
	uint32_t size_bytes;
	/** maximum number of blocks */
	uint32_t max_num_blocks;
	/** holds information returned from ar_osal shmem during allocation */
	ar_shmem_info shmem_info;
	/** holds the handle returned from spf once the page is mapped */
	uint32_t spf_handle;
	/** bitmask used to store the spf subsystems this page is mapped to */
	uint32_t spf_ss_mask;
	/** index of the bin this page belongs to */
	uint32_t bin_idx;
	/* we need to keep this list around as it is needed in free */
	ar_shmem_proc_info ss_id_list[AR_SUB_SYS_ID_LAST];
	/** master proc id to which this page is mapped to */
	uint32_t master_proc;
	/** list of all used and empty blocks */
	struct gsl_shmem_block blocks[];
};

/**
 * Represents a single bin which hold a set of pages
 */
struct gsl_shmem_bin {
	/** number of pages in this bin */
	uint32_t num_pages;
	/** holds the page metadata objects for this bin, one per page */
	struct ar_list_t page_list;
};

#define MAX_PENDING_MEMMAP_PACKETS 3
struct gsl_shmem_mgr_ctxt {
	/** lock used to synchronize alloc and free operations */
	ar_osal_mutex_t mutex;
	/**
	 * array of bins
	 * Pages fall into different bins based on attributes and page size
	 * according to below set of rules:
	 * bins[0] holds scratch memory pages that are pre-allocated, these are
	 *  pages that get allocated at init time and freed at de-init
	 * bins[1] scratch memory growth space, holds pages of size up to 16K
	 * bins[2] holds dedicated pages and pages >16K which are also treated as
	 * dedicated
	 * bins[3] holds CMA pages, which are specifically for offloading to other
	 * mem allocations on SPF and need to be handled with different flags
	 * through osal and SPF
	 */
	struct gsl_shmem_bin bins[GSL_SHMEM_MGR_NUM_BINS];

	/**
	 * holds a pointer the page that is currently being mapped to spf, this
	 * used to store the spf handle when we receive a response from spf
	 */
	struct gsl_shmem_page *page_being_mapped;
	/**
	 * Signal used to wait for responses from spf
	 */
	struct gsl_signal sig;
	/**
	 * lock used in conjuction with above signal
	 */
	 ar_osal_mutex_t sig_lock;
	/**
	 * gpr unconsumed pending memory map packet pointer
	 */
	void *pending_memmap_packet_list[MAX_PENDING_MEMMAP_PACKETS];
	/**
	 * gpr unconsumed pending memory map handle
	 */
	uint32_t pending_memmap_handle_list[MAX_PENDING_MEMMAP_PACKETS];
	/**
	 * gpr unconsumed pending memory map packet list index
	 */
	int32_t pending_memmap_packet_index;
	/**
	 * cache gpr memory map shared memory info flags if error happened
	 */
	uint32_t error_memmap_shmem_info_flags;
	/**
	 * gpr memory map count
	 */
	int32_t memmap_count;
};

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
static struct gsl_shmem_stats {
	/**
	 * size in bytes of memory currently mapped to Spf, this will be a
	 * multiple of page size
	 */
	uint32_t curr_bytes_mapped;
	/**
	 * size in bytes of memory currently allocated to GSL, this will be a
	 * multiple of frame size
	 */
	uint32_t curr_bytes_allocated;
	/**
	 * size in bytes of memory currently requested by client
	 */
	uint32_t curr_bytes_requested;
	/**
	 * size in bytes of peak memory mapped to Spf, this will be a multiple
	 * of page size
	 */
	uint32_t max_bytes_mapped;
	/**
	 * size in bytes of peak memory mapped to Spf, this will be a multuple
	 * of frame size
	 */
	uint32_t max_bytes_allocated;
	/**
	 * size in bytes of peak memory requested by client
	 */
	uint32_t max_bytes_requested;
} stats;
#endif

static struct gsl_shmem_mgr_ctxt *ctxt[AR_SUB_SYS_ID_LAST + 1] = {NULL};

static uint32_t gsl_shmem_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
	uint32_t rc = AR_EOK;
	uint32_t master_proc = packet->src_domain_id;

	cb_data; /* Referencing to keep compiler happy */

	if (ctxt[master_proc] != NULL) {
		if (ctxt[master_proc]->sig.gpr_packet) {
			// if there was a pending gpr packet that never got consumed
			gpr_packet_t *unconsumed_packet =
						(gpr_packet_t *)ctxt[master_proc]->sig.gpr_packet;
			if (unconsumed_packet->opcode == APM_CMD_RSP_SHARED_MEM_MAP_REGIONS &&
				ctxt[master_proc]->memmap_count > 0) {
				/**
				 * the uncomsumed gpr packet was for memory map, need to
				 * unmap it from spf. Since it's not good to handle in the
				 * callback here which may break the sequence. So, cache the
				 * unconsumed pending packet and unmap it later.
				 */
				gsl_shmem_cache_pending_memmap_packets(master_proc,
					ctxt[master_proc]->sig.gpr_packet);
			}
		}
		if (packet->token != ctxt[master_proc]->sig.expected_packet_token) {
			// there is a delay packet received which may be caused by timeout before.
			if (packet->opcode == APM_CMD_RSP_SHARED_MEM_MAP_REGIONS &&
				ctxt[master_proc]->memmap_count > 0) {
				/**
				 * same way to cache the delay memory map rsp packet
				 * and unmap it later
				 */
				gsl_shmem_cache_pending_memmap_packets(master_proc, (void *)packet);
			}
		}
		rc = gsl_signal_set(&ctxt[master_proc]->sig, GSL_SIG_EVENT_MASK_SPF_RSP,
				AR_EOK, packet);
		if (rc)
			__gpr_cmd_free(packet);
	}

	/* do not free packet, it will be freed by waiter */
	return 0;
}

static int32_t gsl_shmem_handle_rsp(gpr_packet_t *rsp, uint32_t master_proc_id,
	uint32_t expected_opcode)
{
	struct apm_cmd_rsp_shared_mem_map_regions_t *mmap_regions;
	struct apm_cmd_rsp_shared_satellite_mem_map_regions_t *mdf_mmap_regions;
	struct spf_cmd_basic_rsp *basic_rsp;
	int32_t rc = AR_EOK;
	if (expected_opcode != rsp->opcode) {
		GSL_ERR("Recieved unexpected rsp opcode %x, expected %x",
			rsp->opcode, expected_opcode);
		rc = AR_EUNEXPECTED;
		goto end;
	}
	switch (rsp->opcode) {
	case APM_CMD_RSP_SHARED_MEM_MAP_REGIONS:
		mmap_regions = GPR_PKT_GET_PAYLOAD(
			struct apm_cmd_rsp_shared_mem_map_regions_t, rsp);
		ctxt[master_proc_id]->page_being_mapped->spf_handle =
						mmap_regions->mem_map_handle;
		if (ctxt[master_proc_id]->page_being_mapped->spf_handle == 0) {
			GSL_ERR("received null handle from spf");
			rc = AR_EFAILED;
		}
		break;

	case APM_CMD_RSP_SHARED_SATELLITE_MEM_MAP_REGIONS:
		mdf_mmap_regions = GPR_PKT_GET_PAYLOAD(
			struct apm_cmd_rsp_shared_satellite_mem_map_regions_t, rsp);
		if (mdf_mmap_regions->mem_map_handle == 0) {
			GSL_ERR("received null satellite handle from spf");
			rc = AR_EFAILED;
		}
		break;

	case GPR_IBASIC_RSP_RESULT:
		basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp,
			rsp);
		switch (basic_rsp->opcode) {
		case APM_CMD_SHARED_MEM_MAP_REGIONS:
		case APM_CMD_SHARED_SATELLITE_MEM_MAP_REGIONS:
		case APM_CMD_RSP_SHARED_SATELLITE_MEM_MAP_REGIONS:
		case APM_CMD_SHARED_MEM_UNMAP_REGIONS:
		case APM_CMD_SHARED_SATELLITE_MEM_UNMAP_REGIONS:
			if (basic_rsp->status) {
				GSL_ERR("received failure %x from spf", basic_rsp->status);
				rc = AR_EFAILED;
			}
			break;

		default:
			GSL_ERR("unsupported opcode %d encountered in GPR SHMEM response",
				basic_rsp->opcode);
			rc = AR_EFAILED;
			break;
		};
		break;
	};
end:
	__gpr_cmd_free(rsp);
	return rc;
}

/* Memory map 1-region of given size */
static int32_t gsl_shmem_map_page_to_spf(struct gsl_shmem_page *page,
	uint32_t flags, uint32_t spf_ss_map_mask)
{
	struct gsl_apm_mem_map *mmap;
	struct gsl_apm_mem_map_satellite *mmap_sat;
	int32_t rc = AR_EOK;
	gpr_cmd_alloc_ext_t gpr_args;
	uint32_t tmp_spf_ss_mask, spf_ss_mask_sans_adsp;
	uint32_t sys_id = AR_SUB_SYS_ID_FIRST;
	gpr_packet_t *send_pkt = NULL, *rsp_pkt = NULL;
	uint8_t cma_client_data = 0;
	uint32_t master_proc_id = page->master_proc;
	bool_t dynamic_pd = FALSE;

	/* if this is a CMA page we need to set client data on all gpr packets */
	if ((page->shmem_info.flags & (AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
		<< AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0)
			cma_client_data = GSL_GPR_CMA_FLAG_BIT;

	/*
	 * if the spf master or any of the satellites is down skip mapping and
	 * retrun ENOTREADY
	 */
	if ((gsl_spf_ss_state_get(master_proc_id) & spf_ss_map_mask) !=
		spf_ss_map_mask)
			return AR_ENOTREADY;

	// check if there are some peneding memmap packets need to be unmmaped.
	gsl_shmem_check_and_unmap_cache_pending_packets(master_proc_id);

	spf_ss_mask_sans_adsp = spf_ss_map_mask &
		~GSL_GET_SPF_SS_MASK(master_proc_id);
	tmp_spf_ss_mask = spf_ss_mask_sans_adsp;
	while (tmp_spf_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(spf_ss_mask_sans_adsp, sys_id)) {
			if (gsl_mdf_utils_is_dynamic_pd(sys_id)) {
				dynamic_pd = TRUE;
				break;
			}
		}
		++sys_id;
		tmp_spf_ss_mask >>= 1;
	}

	/* first map to master (assumed to be adsp currently) */
	if (GSL_TEST_SPF_SS_BIT(spf_ss_map_mask, master_proc_id)) {
		/*
		 * Set client_data based on is_offset flag, this tells gpr in kernel to
		 * replace the MSW/LSW fields in the MMAP with actual physical address
		 * instead of the handle that got returned from osal, this is a hack to
		 * get around linux limitation where PA cannot be returned to
		 * user-space from kernel
		 */
		gpr_args.client_data = GSL_SHMEM_IS_OFFSET_MODE(
			page->shmem_info.index_type);

		gpr_args.src_domain_id = GPR_IDS_DOMAIN_ID_APPS_V;
		gpr_args.dst_domain_id = (uint8_t) master_proc_id;
		gpr_args.src_port = GSL_SHMEM_SRC_PORT;
		gpr_args.dst_port = APM_MODULE_INSTANCE_ID;
		gpr_args.opcode = APM_CMD_SHARED_MEM_MAP_REGIONS;
		gpr_args.payload_size = sizeof(*mmap);
		gpr_args.token = 0;
		gpr_args.ret_packet = &send_pkt;
		rc = __gpr_cmd_alloc_ext(&gpr_args);
		if (rc) {
			GSL_ERR("Failed to allocate shmem map pkt %d", rc);
			goto exit;
		}

		mmap = GPR_PKT_GET_PAYLOAD(struct gsl_apm_mem_map, send_pkt);
		mmap->mmap_header.mem_pool_id = APM_MEMORY_MAP_SHMEM8_4K_POOL;
		mmap->mmap_header.num_regions = 1;
		mmap->mmap_header.property_flag = page->shmem_info.index_type <<
			APM_MEMORY_MAP_SHIFT_IS_OFFSET_MODE;
		mmap->mmap_header.property_flag |= page->shmem_info.mem_type <<
			APM_MEMORY_MAP_SHIFT_IS_VIRTUAL;
		if (flags & GSL_SHMEM_LOANED)
			mmap->mmap_header.property_flag |=
			APM_MEMORY_MAP_BIT_MASK_IS_MEM_LOANED;
		if (flags & GSL_SHMEM_MAP_UNCACHED)
			mmap->mmap_header.property_flag |=
				APM_MEMORY_MAP_BIT_MASK_IS_UNCACHED;
		if (dynamic_pd)
			mmap->mmap_header.property_flag |=
				APM_MEMORY_MAP_LOANED_MEMORY_HEAP_MNGR_TYPE_SAFE_HEAP <<
					APM_MEMORY_MAP_SHIFT_LOANED_MEMORY_HEAP_MNGR_TYPE;

		mmap->mmap_payload.shm_addr_lsw = page->shmem_info.ipa_lsw;
		mmap->mmap_payload.shm_addr_msw = page->shmem_info.ipa_msw;
		mmap->mmap_payload.mem_size_bytes = page->size_bytes;

		send_pkt->client_data |= cma_client_data;

		/*
		 * set current page being mapped so handle can be updated in the
		 * callback
		 */
		ctxt[master_proc_id]->page_being_mapped = page;

		GSL_LOG_PKT("send_pkt", GSL_SHMEM_SRC_PORT, send_pkt,
			sizeof(*send_pkt) +	sizeof(*mmap), NULL, 0);

		ctxt[master_proc_id]->memmap_count++;
		rc = gsl_send_spf_cmd(&send_pkt, &ctxt[master_proc_id]->sig, &rsp_pkt);
		if (rc) {
			GSL_ERR("send spf cmd failed with err %d", rc);
			if (rsp_pkt)
				__gpr_cmd_free(rsp_pkt);
			goto exit;
		}
		if (!rsp_pkt) {
			GSL_ERR("Received null response packet");
			rc = AR_EUNEXPECTED;
			goto exit;
		}

		rc = gsl_shmem_handle_rsp(rsp_pkt, master_proc_id,
					  APM_CMD_RSP_SHARED_MEM_MAP_REGIONS);
		if (rc) {
			GSL_ERR("handle shmem response failed %d", rc);
			goto exit;
		}
	}

	/* map the shared memory to satellite subsystems if any */
	sys_id = AR_SUB_SYS_ID_FIRST;
	tmp_spf_ss_mask = spf_ss_mask_sans_adsp;
	while (tmp_spf_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(spf_ss_mask_sans_adsp, sys_id)) {
			rc = gsl_allocate_gpr_packet(
				APM_CMD_SHARED_SATELLITE_MEM_MAP_REGIONS, GSL_SHMEM_SRC_PORT,
				APM_MODULE_INSTANCE_ID, sizeof(*mmap_sat), 0, master_proc_id,
				&send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet:%d", rc);
				goto exit;
			}

			mmap_sat = GPR_PKT_GET_PAYLOAD(struct gsl_apm_mem_map_satellite,
				send_pkt);

			mmap_sat->mmap_header.satellite_proc_domain_id = sys_id;
			mmap_sat->mmap_header.master_mem_handle = page->spf_handle;
			mmap_sat->mmap_header.mem_pool_id =
				APM_MEMORY_MAP_SHMEM8_4K_POOL;
			mmap_sat->mmap_header.num_regions = 1;
			mmap_sat->mmap_header.property_flag =
				page->shmem_info.index_type <<
				APM_MEMORY_MAP_SHIFT_IS_OFFSET_MODE;
			mmap_sat->mmap_header.property_flag |=
				page->shmem_info.mem_type << APM_MEMORY_MAP_SHIFT_IS_VIRTUAL;
			if (flags & GSL_SHMEM_LOANED)
				mmap_sat->mmap_header.property_flag |=
				APM_MEMORY_MAP_BIT_MASK_IS_MEM_LOANED;
			/*
			 * For dynamic PD set address type to indicate gpr kernel
			 * driver to skip conversion to physical address and pass
			 *    the handle as is to DSP.
			 */
			if (dynamic_pd)
				mmap_sat->mmap_header.property_flag |=
					APM_MEMORY_MAP_MEMORY_ADDRESS_TYPE_FD <<
						APM_MEMORY_MAP_SHIFT_MEMORY_ADDRESS_TYPE;

			mmap_sat->mmap_payload.shm_addr_lsw = page->shmem_info.ipa_lsw;
			mmap_sat->mmap_payload.shm_addr_msw = page->shmem_info.ipa_msw;
			mmap_sat->mmap_payload.mem_size_bytes = page->size_bytes;

			send_pkt->client_data |= cma_client_data;

			GSL_LOG_PKT("send_pkt", GSL_SHMEM_SRC_PORT, send_pkt,
				sizeof(*send_pkt) + sizeof(*mmap_sat), NULL, 0);

			rc = gsl_send_spf_cmd(&send_pkt, &ctxt[master_proc_id]->sig,
					      &rsp_pkt);
			if (rc) {
				GSL_ERR("Mem map satellite failed:%d", rc);
				if (rsp_pkt)
					__gpr_cmd_free(rsp_pkt);
				goto exit;
			}
			if (!rsp_pkt) {
				GSL_ERR("Received null response packet");
				rc = AR_EUNEXPECTED;
				goto exit;
			}
			rc = gsl_shmem_handle_rsp(rsp_pkt, master_proc_id,
				APM_CMD_RSP_SHARED_SATELLITE_MEM_MAP_REGIONS);
			if (rc) {
				GSL_ERR("handle shmem response failed %d", rc);
				goto exit;
			}
		}
		++sys_id;
		tmp_spf_ss_mask >>= 1;
	}

exit:
	if (rc){
		ctxt[master_proc_id]->error_memmap_shmem_info_flags = page->shmem_info.flags;
	}
	return rc;
}

static int32_t gsl_shmem_unmap_page_from_spf(struct gsl_shmem_page *page,
	uint32_t spf_ss_unmap_mask)
{
	struct apm_cmd_shared_mem_unmap_regions_t *payload;
	struct apm_cmd_shared_satellite_mem_unmap_regions_t *payload_sat;
	int32_t rc = AR_EOK;
	uint32_t tmp_spf_ss_mask, spf_ss_mask_sans_adsp;
	uint32_t sys_id = AR_MODEM_DSP;
	gpr_packet_t *send_pkt = NULL, *rsp_pkt = NULL;
	uint8_t cma_client_data = 0;
	uint32_t master_proc_id = page->master_proc;

	/* if the spf master or any satellites are down silently skip unmap */
	if ((gsl_spf_ss_state_get(master_proc_id) & spf_ss_unmap_mask) !=
		page->spf_ss_mask)
		return AR_EOK;

	/* if this is a CMA page we need to set client data on all gpr packets */
	if ((page->shmem_info.flags & (AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
		<< AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0)
		cma_client_data = GSL_GPR_CMA_FLAG_BIT;

	/*
	 * firstly unmap from satellites, adsp does not require this step hence we
	 * clear its bit to skip.
	 */
	spf_ss_mask_sans_adsp = spf_ss_unmap_mask &
		~GSL_GET_SPF_SS_MASK(master_proc_id);
	tmp_spf_ss_mask = spf_ss_mask_sans_adsp;
	while (tmp_spf_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(spf_ss_mask_sans_adsp, sys_id)) {
			rc = gsl_allocate_gpr_packet(
				APM_CMD_SHARED_SATELLITE_MEM_UNMAP_REGIONS, GSL_SHMEM_SRC_PORT,
				APM_MODULE_INSTANCE_ID, sizeof(*payload_sat), 0, master_proc_id,
				&send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto exit;
			}
			payload_sat = GPR_PKT_GET_PAYLOAD(
				struct apm_cmd_shared_satellite_mem_unmap_regions_t, send_pkt);
			payload_sat->satellite_proc_domain_id = sys_id;
			payload_sat->master_mem_handle = page->spf_handle;

			send_pkt->client_data |= cma_client_data;

			GSL_LOG_PKT("send_pkt", GSL_SHMEM_SRC_PORT, send_pkt,
				sizeof(*send_pkt) + sizeof(*payload_sat), NULL, 0);
			rc = gsl_send_spf_cmd(&send_pkt, &ctxt[master_proc_id]->sig,
					      &rsp_pkt);
			if (rc || !rsp_pkt) {
				if (rsp_pkt)
					__gpr_cmd_free(rsp_pkt);
				goto exit;
			}
			rc = gsl_shmem_handle_rsp(rsp_pkt, master_proc_id,
						  GPR_IBASIC_RSP_RESULT);
			if (rc)
				goto exit;
		}
		++sys_id;
		tmp_spf_ss_mask >>= 1;
	}

	/* now unmap from master */
	if (GSL_TEST_SPF_SS_BIT(spf_ss_unmap_mask, master_proc_id)) {
		rc = gsl_allocate_gpr_packet(APM_CMD_SHARED_MEM_UNMAP_REGIONS,
			GSL_SHMEM_SRC_PORT, APM_MODULE_INSTANCE_ID, sizeof(*payload), 0,
			master_proc_id, &send_pkt);
		if (rc) {
			GSL_ERR("Failed to allocate GPR packet %d", rc);
			goto exit;
		}
		payload = GPR_PKT_GET_PAYLOAD(
			struct apm_cmd_shared_mem_unmap_regions_t, send_pkt);
		payload->mem_map_handle = page->spf_handle;

		send_pkt->client_data |= cma_client_data;

		GSL_LOG_PKT("send_pkt", GSL_SHMEM_SRC_PORT, send_pkt,
			sizeof(*send_pkt) +	sizeof(*payload), NULL, 0);
		ctxt[master_proc_id]->memmap_count--;
		rc = gsl_send_spf_cmd(&send_pkt, &ctxt[master_proc_id]->sig, &rsp_pkt);
		if (rc || !rsp_pkt) {
			if (rsp_pkt)
				__gpr_cmd_free(rsp_pkt);
			goto exit;
		}
		rc = gsl_shmem_handle_rsp(rsp_pkt, master_proc_id,
					  GPR_IBASIC_RSP_RESULT);
	}
exit:
	return rc;
}

/**
 * Allocates a new page of a given size and adds it to the provided bin,
 * it is callers responsibility to ensure that the correct bin_idx is
 * provided that matches the size being allocated.
 * note, this function does not do error checking on parameters
 *
 * /param[in] page_size: size of the page to allocate, must be a multiple of
 *	GSL_SHMEM_MGR_MIN_PAGE_SZ
 */
static int32_t allocate_page(uint32_t page_size, uint32_t bin_idx,
	uint32_t spf_ss_mask, uint32_t flags, uint32_t platform_info,
	uint64_t ext_mem_hdl, uint32_t master_proc_id,
	struct gsl_shmem_page **new_page)
{
	int32_t rc = AR_EOK;
	struct gsl_shmem_bin *bin = &ctxt[master_proc_id]->bins[bin_idx];
	struct gsl_shmem_page *page = NULL;
	uint32_t tmp_spf_ss_mask = spf_ss_mask;
	uint8_t sys_id = AR_SUB_SYS_ID_FIRST;
	uint32_t max_num_blocks = 1;
	uint32_t num_procs = 0;
	struct proc_domain_type *proc_domains = NULL;
	uint32_t dynamic_proc_ss_mask = 0, i = 0;

	/*
	 * if we are in the dedicated bin then we only need one block since we
	 * dont allow multiple client allocations in this bin, otherwise determine
	 * max number of blocks based on page size
	 */
	if (bin_idx != GSL_SHMEM_MGR_BIN_IDX_DEDICATED)
		max_num_blocks = GSL_SHMEM_MGR_CONVERT_BYTES_TO_FRAMES(page_size);

	/* create a page entry */
	page = gsl_mem_zalloc(sizeof(struct gsl_shmem_page) +
		max_num_blocks * sizeof(struct gsl_shmem_block));
	if (page == NULL) {
		*new_page = NULL;
		return AR_ENOMEMORY;
	}
	page->max_num_blocks = max_num_blocks;
	page->master_proc = master_proc_id;

	/* allocate shared memory for page */
	page->shmem_info.platform_info = platform_info;
	page->shmem_info.buf_size = page_size;
	page->shmem_info.cache_type = AR_SHMEM_UNCACHED;

	page->shmem_info.num_sys_id = 0;
	page->shmem_info.sys_id = page->ss_id_list;

	gsl_mdf_utils_get_proc_domain_info(&proc_domains, &num_procs);
	if (!proc_domains)
		num_procs = 0;
	for (i = 0; i < num_procs; ++i) {
		if (proc_domains[i].proc_type == DYNAMIC_PD)
			dynamic_proc_ss_mask |=
				GSL_GET_SPF_SS_MASK(proc_domains[i].proc_id);
	}
	/* populate ss_id_list based on spf_ss_mask */
	while (tmp_spf_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(spf_ss_mask, sys_id)) {
			page->ss_id_list[page->shmem_info.num_sys_id].proc_id = sys_id;
			if (GSL_TEST_SPF_SS_BIT(dynamic_proc_ss_mask, sys_id)) {
				page->ss_id_list[page->shmem_info.num_sys_id].proc_type =
					DYNAMIC_PD;
				page->ss_id_list[page->shmem_info.num_sys_id].is_active =
					TRUE;
			} else {
				page->ss_id_list[page->shmem_info.num_sys_id].proc_type =
					STATIC_PD;
			}
			++page->shmem_info.num_sys_id;
		}
		++sys_id;
		tmp_spf_ss_mask >>= 1;
	}

	/* set special flag for CMA allocations */
	if (flags & GSL_SHMEM_CMA)
		page->shmem_info.flags =
			AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
			<< AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG;

	if (ext_mem_hdl == GSL_EXT_MEM_HDL_NOT_ALLOCD) {
		rc = ar_shmem_alloc(&page->shmem_info);
		if (rc) {
			GSL_ERR("ar_shmem_alloc failed with error %d", rc);
			goto free_gsl_mem;
		}
	} else {
		/* pass the alloc handle on the PA. This will be converted by OSAL */
		page->shmem_info.pa_lsw = (uint32_t)ext_mem_hdl;
		page->shmem_info.pa_msw = (uint32_t)(ext_mem_hdl >> 32);

		GSL_VERBOSE("map ext mem page extmemhdl: 0x%x pamsw 0x%x, palsw 0x%x",
			ext_mem_hdl, page->shmem_info.pa_msw, page->shmem_info.pa_lsw);

		rc = ar_shmem_map(&page->shmem_info);
		if (rc) {
			GSL_ERR("ar_shmem_map failed with error %d", rc);
			goto free_gsl_mem;
		}
	}

	if (page->shmem_info.mem_type == AR_SHMEM_VIRTUAL_MEMORY) {
		page->shmem_info.ipa_lsw =
			(uint32_t)((uintptr_t)page->shmem_info.vaddr);
		page->shmem_info.ipa_msw =
			(uint64_t)((uintptr_t)page->shmem_info.vaddr) >> 32;
	}
	page->bin_idx = bin_idx;
	page->size_bytes = page_size;
	page->spf_ss_mask = spf_ss_mask;
	rc = gsl_shmem_map_page_to_spf(page, flags, page->spf_ss_mask);
	if (rc) {
		GSL_ERR("failed to map page with spf error %d", rc);
		goto free_shmem;
	}

	/*
	 * initialize free and used block lists,
	 */
	/* add page entry to bin */
	rc = ar_list_init_node(&page->node);
	if (rc) {
		GSL_ERR("ar_list_init_node failed with error %d", rc);
		goto unmap_page;
	}

	rc = ar_list_add_tail(&bin->page_list, &page->node);
	if (rc) {
		GSL_ERR("ar_list_add_tail failed with error %d", rc);
		goto unmap_page;
	}

	/* mark entire page as a single free block */
	page->blocks[0].base_addr = page->shmem_info.vaddr;
	page->blocks[0].size_bytes = page_size; /* LSB of size is assumed 0 */
	page->blocks[0].predecessor_idx = -1;
	page->blocks[0].successor_idx = -1;

	bin->num_pages += 1;
	*new_page = page;
#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	stats.curr_bytes_mapped += page_size;
	if (stats.curr_bytes_mapped > stats.max_bytes_mapped)
		stats.max_bytes_mapped = stats.curr_bytes_mapped;
#endif

	goto exit;

unmap_page:
	gsl_shmem_unmap_page_from_spf(page, page->spf_ss_mask);
free_shmem:
	if (ext_mem_hdl == GSL_EXT_MEM_HDL_NOT_ALLOCD)
		ar_shmem_free(&page->shmem_info);
	else
		ar_shmem_unmap(&page->shmem_info);
	page->shmem_info.vaddr = NULL;
	page->shmem_info.pa_lsw = 0;
	page->shmem_info.pa_msw = 0;

free_gsl_mem:
	gsl_mem_free(page);
	*new_page = NULL;
exit:
	return rc;
}

static int32_t free_page(int32_t bin_idx,
	struct gsl_shmem_page *page, bool_t is_ext_mem)
{
	int32_t rc = AR_EOK, rc1 = AR_EOK;
	uint32_t master_proc_id = page->master_proc;
	uint32_t sys_id = AR_SUB_SYS_ID_FIRST;
	struct gsl_shmem_bin *bin = &ctxt[master_proc_id]->bins[bin_idx];

	rc = gsl_shmem_unmap_page_from_spf(page, page->spf_ss_mask);
	if (rc) {
		GSL_ERR("failed to unmap page from spf %d", rc);
		rc1 = rc;
	}
	/*
	 * Dynamic pd DSP unmap happens in OSAL. If this page is getting
	 * freed during pd is down, indicate OSAL to skip sending unmap
	 * command to DSP.
	 */
	if ((gsl_spf_ss_state_get(master_proc_id) & page->spf_ss_mask) !=
		page->spf_ss_mask) {
		while (sys_id < AR_SUB_SYS_ID_LAST) {
			if (page->ss_id_list[sys_id].proc_type == DYNAMIC_PD) {
				GSL_DBG("set pd down flag for proc_id %d",
					page->ss_id_list[sys_id].proc_id);
				page->ss_id_list[sys_id].is_active = FALSE;
			}
			++sys_id;
		}
	}
	/* if this is a CMA page, hyp-unassign here */
	if ((page->shmem_info.flags & (AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
		<< AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0)
		gsl_shmem_hyp_assign(page, AR_APSS,	AR_DEFAULT_DSP);
	if (!is_ext_mem) {
		rc = ar_shmem_free(&page->shmem_info);
		if (rc) {
			GSL_ERR("ar_shmem_free failed with error %d", rc);
			if (!rc1)
				rc1 = rc;
		}
	} else {
		GSL_VERBOSE("unmap ext_mem page %d vaddr 0x%x pa_msw 0x%x, pa_lsw 0x%x",
			is_ext_mem, page->shmem_info.vaddr, page->shmem_info.pa_msw,
			page->shmem_info.pa_lsw);

		rc = ar_shmem_unmap(&page->shmem_info);
		if (rc) {
			GSL_ERR("ar_shmem_unmap failed with error %d", rc);
			if (!rc1)
				rc1 = rc;
		}
	}

	rc = ar_list_delete(&bin->page_list, &page->node);
	if (rc) {
		GSL_ERR("ar_list_delete failed with error %d", rc);
		if (!rc1)
			rc1 = rc;
	}

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	stats.curr_bytes_mapped -= page->size_bytes;
#endif

	gsl_mem_free(page);
	bin->num_pages -= 1;

	return rc1;
}

static void *do_alloc_block(struct gsl_shmem_page *page,
	int16_t found_block_idx, uint32_t frame_aligned_sz)
{
	uint32_t i = 0;
	/* Validate block index is within bounds */
	if (found_block_idx < 0 || found_block_idx >= (int16_t)page->max_num_blocks) {
		GSL_ERR("do_alloc_block: invalid block index %d (max=%u)",
			found_block_idx, page->max_num_blocks);
		return NULL;
	}

	/* Retrieve the original size of the current block (excluding the used bit) */
	uint32_t old_sz = page->blocks[found_block_idx].size_bytes &
				~GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK;
	if (!old_sz) {
		GSL_ERR("do_alloc_block: zero-size block page=%p idx=%d",
			page, found_block_idx);
		return NULL;
    }

	/* Requested size cannot be larger than the original free size */
	if (old_sz < frame_aligned_sz) {
		GSL_ERR("do_alloc_block: block too small sz=0x%x < req=0x%x page=%p idx=%d",
			old_sz, frame_aligned_sz, page, found_block_idx);
		return NULL;
    }

	int32_t found_block_successor_idx =
		page->blocks[found_block_idx].successor_idx;

	if (page->blocks[found_block_idx].size_bytes > frame_aligned_sz) {
		/*
		 * find available entry in block list and use it for new free block
		 * Note: max_num_blocks is set to page_size/frame_size,  this ensures
		 * that there is always an entry available in blocks[] for the worst
		 * case fragmenation
		 */
		for (i = 0; i < page->max_num_blocks; ++i) {
			if (page->blocks[i].base_addr == NULL) {
				/* found an available entry, use it as a new free block */
				page->blocks[i].base_addr =
					(char *)(page->blocks[found_block_idx].base_addr) +
					frame_aligned_sz;
				page->blocks[i].size_bytes =
					page->blocks[found_block_idx].size_bytes -
					frame_aligned_sz;
				/*
				 * make the successor of the found block point to the new block
				 */
				if (found_block_successor_idx != -1)
					page->blocks[found_block_successor_idx].predecessor_idx =
						(int16_t) i;

				/* make the new empty block a successor of the found block */
				page->blocks[i].predecessor_idx = found_block_idx;
				page->blocks[i].successor_idx =
					page->blocks[found_block_idx].successor_idx;
				page->blocks[found_block_idx].successor_idx = (int16_t) i;
				break;
			}
		}
	}

	/* update used block info and mark it as used */
	page->blocks[found_block_idx].size_bytes = frame_aligned_sz;
	page->blocks[found_block_idx].size_bytes |=
		GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK;

	return page->blocks[found_block_idx].base_addr;
}

/**
 * returns the size of the resulting free block after freeing and merging with
 * neighbors
 */
static uint32_t do_free_block(struct gsl_shmem_page *page,
	uint16_t freed_block_idx)
{
	int16_t successor_idx = page->blocks[freed_block_idx].successor_idx;
	int16_t predecessor_idx = page->blocks[freed_block_idx].predecessor_idx;
	int16_t successor_successor_idx = 0;
	uint32_t resulting_free_block_sz = 0;

	/* found block, mark it as free */
	page->blocks[freed_block_idx].size_bytes &=
		~GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK;

	/*
	 * if successor is available and marked as free,
	 * merge successor into freed block
	 */
	if ((successor_idx != -1) && !(page->blocks[successor_idx].size_bytes &
		GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK)) {
		successor_successor_idx = page->blocks[successor_idx].successor_idx;

		page->blocks[freed_block_idx].size_bytes +=
			page->blocks[successor_idx].size_bytes;
		page->blocks[freed_block_idx].successor_idx = successor_successor_idx;

		if (successor_successor_idx != -1)
			page->blocks[successor_successor_idx].predecessor_idx =
			freed_block_idx;

		/* mark successor entry as available */
		page->blocks[successor_idx].base_addr = NULL;
		page->blocks[successor_idx].predecessor_idx = -1;
		page->blocks[successor_idx].successor_idx = -1;
		page->blocks[successor_idx].size_bytes = 0;
	}

	/*
	 * store the size this is the resulting free block size so far
	 */
	resulting_free_block_sz = page->blocks[freed_block_idx].size_bytes;

	/*
	 * if predecessor is availble and marked as free,
	 * merge freed block into predecessor
	 */
	if ((predecessor_idx != -1) && !(page->blocks[predecessor_idx].size_bytes &
		GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK)) {
		page->blocks[predecessor_idx].size_bytes +=
			page->blocks[freed_block_idx].size_bytes;
		successor_idx = page->blocks[freed_block_idx].successor_idx;
		page->blocks[predecessor_idx].successor_idx = successor_idx;

		if (successor_idx != -1)
			page->blocks[successor_idx].predecessor_idx = predecessor_idx;

		/* mark freed block entry as available */
		page->blocks[freed_block_idx].base_addr = NULL;
		page->blocks[freed_block_idx].predecessor_idx = -1;
		page->blocks[freed_block_idx].successor_idx = -1;
		page->blocks[freed_block_idx].size_bytes = 0;

		/*
		 * update resulting free block size to reflect the size of the
		 * resulting free block after we merged with predecessor
		 */
		resulting_free_block_sz = page->blocks[predecessor_idx].size_bytes;
	}

	return resulting_free_block_sz;
}

int32_t gsl_shmem_alloc(uint32_t size_bytes, uint32_t master_proc_id,
	struct gsl_shmem_alloc_data *alloc_data)
{
	return gsl_shmem_alloc_ext(size_bytes,
		GSL_GET_SPF_SS_MASK(master_proc_id), 0, 0, master_proc_id,
		alloc_data);
}

int32_t gsl_shmem_alloc_ext(uint32_t size_bytes, uint32_t spf_ss_mask,
	uint32_t flags,	uint32_t platform_info, uint32_t master_proc_id,
	struct gsl_shmem_alloc_data *alloc_data)
{
	int32_t rc = AR_EOK;
	uint32_t size_frame_aligned = 0, size_page_aligned = 0, bin_idx = 0;
	struct gsl_shmem_page *page;
	uint64_t offset = 0;
	uint32_t i = 0;
	int16_t j;
	bool_t block_found = false;
	ar_list_node_t *itr = NULL;

	if (!alloc_data || size_bytes == 0)
		return AR_EBADPARAM;

	if (!ctxt[master_proc_id])
		return AR_EUNSUPPORTED;

	size_frame_aligned = (size_bytes + GSL_SHMEM_MGR_FRAME_SZ - 1) &
		(~(GSL_SHMEM_MGR_FRAME_SZ - 1));
	size_page_aligned = (size_frame_aligned + GSL_SHMEM_MGR_PAGE_SZ - 1) &
		(~(GSL_SHMEM_MGR_PAGE_SZ - 1));

	/*
	 * if the memory is requested as dedicated page or is used for any non
	 * SPF master SS or larger than 16K, then keep it in the last bin so it
	 * wont be shared across allocations
	 */
	if (flags & GSL_SHMEM_DEDICATED_PAGE || flags & GSL_SHMEM_CMA ||
		spf_ss_mask & ~GSL_GET_SPF_SS_MASK(master_proc_id) ||
		size_page_aligned >= GSL_SHMEM_MAX_SCRATCH_ALLOC_SZ)
		bin_idx = GSL_SHMEM_MGR_BIN_IDX_DEDICATED;
	else
		bin_idx = GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH;

	/*
	 * since we do not divide the pages in the last bin to frames, we set
	 * size_frame_aligned to be same as size_page_aligned
	 */
	if (bin_idx == GSL_SHMEM_MGR_BIN_IDX_DEDICATED)
		size_frame_aligned = size_page_aligned;

	GSL_MUTEX_LOCK(ctxt[master_proc_id]->mutex);
	/*
	 * scan through all bins and try to find if a suitable free block is
	 * available. Note: We purposely dont search in the last bin as this
	 * holds either dedicated pages or very large size pages which are meant
	 * for single allocations only
	 */
	for (i = bin_idx; i <= GSL_SHMEM_MGR_BIN_IDX_SCRATCH; ++i) {
		if (ctxt[master_proc_id]->bins[i].num_pages == 0)
			continue;

		ar_list_for_each_entry(itr, &ctxt[master_proc_id]->bins[i].page_list) {
			page = get_container_base(itr, struct gsl_shmem_page, node);

			/* search for free block */
			j = 0;
			while (j != -1) {
				if (!(page->blocks[j].size_bytes &
					GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK) &&
					(size_frame_aligned <= page->blocks[j].size_bytes)) {

					/* found suitable block */
					alloc_data->handle = page;
					alloc_data->spf_mmap_handle = page->spf_handle;
					alloc_data->v_addr = do_alloc_block(page, j,
						size_frame_aligned);
					/* add null check for do_alloc_block */
					if (!alloc_data->v_addr) {
						GSL_ERR("do_alloc_block returned NULL "
							"for current page %p", page);
						alloc_data->handle = NULL;
						alloc_data->spf_mmap_handle = 0;
						rc = AR_EFAILED;
						goto exit;
					}
					/* compute PA for this block */
					uintptr_t base = (uintptr_t)page->shmem_info.vaddr;
					uintptr_t addr = (uintptr_t)alloc_data->v_addr;
					if (addr >= base) {
						offset = (uint64_t)(addr - base);
					} else {
						GSL_ERR("Failed to calculate offset because"
							"addr(0x%lx)<base(0x%lx)",
							(unsigned long)addr, (unsigned long)base);
						/* Free the allocated block */
						do_free_block(page, j);
						alloc_data->v_addr = NULL;
						alloc_data->handle = NULL;
                        alloc_data->spf_mmap_handle = 0;
						/* Break inner loop to try next page */
						break;
					}
					if (GSL_SHMEM_IS_OFFSET_MODE(page->shmem_info.index_type)) {
						alloc_data->spf_addr = offset;
					} else {
						alloc_data->spf_addr =
							((uint64_t)page->shmem_info.ipa_msw << 32) +
							page->shmem_info.ipa_lsw + offset;
					}
					alloc_data->metadata = page->shmem_info.metadata;
					block_found = true;
#ifdef GSL_SHMEM_MGR_STATS_ENABLE
					page->blocks[j].requested_size_bytes = size_bytes;
#endif
					break;
				}
				j = page->blocks[j].successor_idx;
			}
			if (block_found)
				break;
		}
		if (block_found)
			break;
	}

	if (!block_found) {
		/* no suitable block found in existing pages, allocate a new page */

		if (bin_idx == GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH)
			bin_idx = GSL_SHMEM_MGR_BIN_IDX_SCRATCH;

		rc = allocate_page(size_page_aligned, bin_idx, spf_ss_mask, flags,
			platform_info, GSL_EXT_MEM_HDL_NOT_ALLOCD, master_proc_id, &page);
		if (rc)
			goto exit;
		alloc_data->handle = page;
		alloc_data->v_addr = do_alloc_block(page, 0, size_frame_aligned);
		alloc_data->spf_mmap_handle = page->spf_handle;
		/* add null check for do_alloc_block */
		if (!alloc_data->v_addr) {
			GSL_ERR("do_alloc_block returned NULL for new page %p free it", page);
			alloc_data->handle = NULL;
			alloc_data->spf_mmap_handle = 0;
			rc = free_page(bin_idx, page, 0);
			if (rc) {
				GSL_ERR("Failed to free page after allocation failure: %d", rc);
				goto exit;
			}
			rc = AR_EFAILED;
			goto exit;
		}
		/* compute PA for this block */
		uintptr_t base = (uintptr_t)page->shmem_info.vaddr;
		uintptr_t addr = (uintptr_t)alloc_data->v_addr;
		if (addr >= base) {
			offset = (uint64_t)(addr - base);
		} else {
			GSL_ERR("Failed to calculate offset because addr(0x%lx)<base(0x%lx)",
				(unsigned long)addr, (unsigned long)base);
			/* Free the allocated block */
			do_free_block(page, 0);
			alloc_data->v_addr = NULL;
			alloc_data->handle = NULL;
			alloc_data->spf_mmap_handle = 0;
			rc = free_page(bin_idx, page, 0);
			if (rc) {
				GSL_ERR("Failed to free page after allocation failure: %d", rc);
				goto exit;
			}
			rc = AR_EFAILED;
			goto exit;
		}
		if (GSL_SHMEM_IS_OFFSET_MODE(page->shmem_info.index_type))
			alloc_data->spf_addr = offset;
		else
			alloc_data->spf_addr =
				((uint64_t) page->shmem_info.ipa_msw << 32) +
				page->shmem_info.ipa_lsw + offset;
		alloc_data->metadata = page->shmem_info.metadata;
#ifdef GSL_SHMEM_MGR_STATS_ENABLE
		page->blocks[0].requested_size_bytes = size_bytes;
#endif
	}

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	stats.curr_bytes_requested += size_bytes;
	if (stats.curr_bytes_requested >= stats.max_bytes_requested)
		stats.max_bytes_requested = stats.curr_bytes_requested;

	stats.curr_bytes_allocated += size_frame_aligned;
	if (stats.curr_bytes_allocated >= stats.max_bytes_allocated)
		stats.max_bytes_allocated = stats.curr_bytes_allocated;
	GSL_LOG_PKT("mem_stat", GSL_SHMEM_SRC_PORT, &stats,
		sizeof(struct gsl_shmem_stats), NULL, 0);
#endif

exit:
	GSL_MUTEX_UNLOCK(ctxt[master_proc_id]->mutex);
	return rc;
}

int32_t gsl_shmem_free(struct gsl_shmem_alloc_data *alloc_data)
{
	struct gsl_shmem_page *page;
	int16_t freed_block_idx = 0;
	uint32_t resulting_free_block_sz = 0, bin_idx = 0;
	int32_t rc = AR_EOK;
	bool_t found_block = false;
	uint32_t master_proc_id;

	if (!alloc_data)
		return AR_EBADPARAM;

	if (!alloc_data->handle)
		return AR_EBADPARAM;

	page = alloc_data->handle;
	master_proc_id = page->master_proc;
	bin_idx = page->bin_idx;

	if (!ctxt[master_proc_id])
		return AR_EUNSUPPORTED;

	GSL_MUTEX_LOCK(ctxt[master_proc_id]->mutex);

	/* find the block in page and free it */
	while (freed_block_idx != (int16_t)(-1)) {
		if (page->blocks[freed_block_idx].base_addr == alloc_data->v_addr) {
#ifdef GSL_SHMEM_MGR_STATS_ENABLE
			stats.curr_bytes_requested -=
				page->blocks[freed_block_idx].requested_size_bytes;
			stats.curr_bytes_allocated -=
				page->blocks[freed_block_idx].size_bytes &
				~GSL_SHMEM_MGR_BLOCK_SZ_USED_BIT_MASK;
#endif
			/* found the block being freed */
			resulting_free_block_sz = do_free_block(page, freed_block_idx);
			found_block = true;
			break;
		}

		freed_block_idx = page->blocks[freed_block_idx].successor_idx;
	}

	 /* check if the page can be freed back to system */
	if (found_block && resulting_free_block_sz == page->size_bytes) {
		/*
		 * do not free page if it belongs to bin 0, this will be freed during
		 * deinit
		 */
		if (bin_idx > GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH)
			rc = free_page(bin_idx, page, 0);
	}

	if (!found_block)
		rc = AR_ENOTEXIST;

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	GSL_LOG_PKT("mem_stat", GSL_SHMEM_SRC_PORT, &stats,
		sizeof(struct gsl_shmem_stats), NULL, 0);
#endif
	GSL_MUTEX_UNLOCK(ctxt[master_proc_id]->mutex);

	return rc;
}

int32_t gsl_shmem_unmap_allocation(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t ss_mask_to_unmap_to)
{
	int32_t rc = AR_EOK;
	struct gsl_shmem_page *page = alloc_data->handle;
	uint32_t master_proc_id = page->master_proc;

	rc = gsl_shmem_unmap_page_from_spf(page, ss_mask_to_unmap_to);
	if (rc)
		GSL_ERR("failed to unmap page from spf %d", rc);

	ar_shmem_unmap(&page->shmem_info);

	return rc;
}
int32_t gsl_shmem_map_extern_mem(uint64_t ext_mem_hdl, uint32_t size_bytes,
	uint32_t master_proc_id, struct gsl_shmem_alloc_data *alloc_data)
{
	int32_t rc = AR_EOK;
	uint32_t size_page_aligned = 0;
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id]) {
		rc = AR_EUNSUPPORTED;
		return rc;
	}

	size_page_aligned = (size_bytes + GSL_SHMEM_MGR_PAGE_SZ - 1) &
		(~(GSL_SHMEM_MGR_PAGE_SZ - 1));

	GSL_MUTEX_LOCK(ctxt[master_proc_id]->mutex);

	// won't actually allocate when we send an ext_mem_handle, it will only map
	rc = allocate_page(size_page_aligned, GSL_SHMEM_MGR_BIN_IDX_DEDICATED,
		GSL_GET_SPF_SS_MASK(master_proc_id), 0, 0, ext_mem_hdl, master_proc_id,
		&page);
	if (rc) {
		GSL_ERR("failed to allocate page %d", rc);
		goto exit;
	}

	alloc_data->handle = page;
	alloc_data->v_addr = page->shmem_info.vaddr;
	alloc_data->spf_mmap_handle = page->spf_handle;
	alloc_data->metadata = page->shmem_info.metadata;
	/* compute PA for this block */
	if (GSL_SHMEM_IS_OFFSET_MODE(page->shmem_info.index_type))
		alloc_data->spf_addr = 0;
	else
		alloc_data->spf_addr =
			((uint64_t)page->shmem_info.ipa_msw << 32) +
			page->shmem_info.ipa_lsw;

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	GSL_LOG_PKT("mem_stat", GSL_SHMEM_SRC_PORT, &stats,
		sizeof(struct gsl_shmem_stats), NULL, 0);
#endif

exit:
	GSL_MUTEX_UNLOCK(ctxt[master_proc_id]->mutex);
	return rc;
}

int32_t gsl_shmem_unmap_extern_mem(struct gsl_shmem_alloc_data alloc_data)
{
	int32_t rc = AR_EOK;
	struct gsl_shmem_page *page = alloc_data.handle;
	uint32_t master_proc_id = 0;

	if (!alloc_data.handle)
		return AR_EBADPARAM;

	if (!page)
		return AR_EBADPARAM;

	master_proc_id = page->master_proc;

	if (!ctxt[master_proc_id]) {
		rc = AR_EUNSUPPORTED;
		goto exit;
	}

	GSL_MUTEX_LOCK(ctxt[master_proc_id]->mutex);
	/*
	 * we know that external mem is always in dedicated
	 * and must be allocated before free
	 */
	rc = free_page(GSL_SHMEM_MGR_BIN_IDX_DEDICATED, alloc_data.handle,
		       TRUE);

	GSL_MUTEX_UNLOCK(ctxt[master_proc_id]->mutex);

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	GSL_LOG_PKT("mem_stat", GSL_SHMEM_SRC_PORT, &stats,
		sizeof(struct gsl_shmem_stats), NULL, 0);
#endif

exit:
	return rc;
}

void gsl_shmem_signal_ssr(uint32_t master_proc_id)
{
	if (!ctxt[master_proc_id])
		return;

	gsl_signal_set(&ctxt[master_proc_id]->sig, GSL_SIG_EVENT_MASK_SSR, 0, NULL);
}

void gsl_shmem_clear_ssr(uint32_t master_proc_id)
{
	if (!ctxt[master_proc_id])
		return;

	gsl_signal_clear(&ctxt[master_proc_id]->sig, GSL_SIG_EVENT_MASK_SSR);
}

/* re-map pre-allocated pages to ADSP after it restarts */
void gsl_shmem_remap_pre_alloc(uint32_t master_proc_id)
{
	ar_list_node_t *iter = NULL;
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id])
		return;

	iter = ctxt[master_proc_id]->bins[GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH]
		.page_list.dummy.next;
	while (iter !=
		&ctxt[master_proc_id]->bins[GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH]
			.page_list.dummy) {
		page = (struct gsl_shmem_page *) iter;
		gsl_shmem_map_page_to_spf(page, 0, page->spf_ss_mask);
		iter = iter->next;
	}
}

void gsl_shmem_cache_pending_memmap_packets(uint32_t master_proc_id, void *gpr_packet)
{
	for (int i = 0; i < MAX_PENDING_MEMMAP_PACKETS; i++) {
		//check if the packet is duplicated
		if(ctxt[master_proc_id]->pending_memmap_packet_list[i] &&
			((struct gpr_packet_t *)ctxt[master_proc_id]->
			pending_memmap_packet_list[i])->token ==
			((struct gpr_packet_t *)gpr_packet)->token) {
			return;
		}
	}
	int32_t index = ctxt[master_proc_id]->pending_memmap_packet_index;
	struct apm_cmd_rsp_shared_mem_map_regions_t *mmap_regions;
	mmap_regions = GPR_PKT_GET_PAYLOAD(
                    struct apm_cmd_rsp_shared_mem_map_regions_t, gpr_packet);

	if (!ctxt[master_proc_id]->pending_memmap_packet_list[index])
		ctxt[master_proc_id]->pending_memmap_packet_list[index] =
			(struct gpr_packet_t *)gsl_mem_zalloc(sizeof(struct gpr_packet_t));
	if (ctxt[master_proc_id]->pending_memmap_packet_list[index]) {
		gsl_memcpy(ctxt[master_proc_id]->pending_memmap_packet_list[index],
			sizeof(struct gpr_packet_t),
			gpr_packet,
			sizeof(struct gpr_packet_t));
		ctxt[master_proc_id]->pending_memmap_handle_list[index] =
			mmap_regions->mem_map_handle;
	} else {
		GSL_ERR("Failed to allocate mem for caching the pending memory packet!");
		return;
	}
	if (++index == MAX_PENDING_MEMMAP_PACKETS) {
		GSL_INFO("Warning: buffer limit exceeded. Resetting index to 0.");
		index = 0;
	}
	ctxt[master_proc_id]->pending_memmap_packet_index = index;
}

uint32_t gsl_shmem_check_and_unmap_cache_pending_packets(uint32_t master_proc_id) {
	int32_t rc = AR_EOK;
	gpr_packet_t *unmap_send_pkt = NULL, *unmap_rsp_pkt = NULL;
	gpr_packet_t *pending_pkt = NULL;
	uint8_t cma_client_data = 0;
	struct apm_cmd_shared_mem_unmap_regions_t *unmap_payload;
	for (int i = 0; i < MAX_PENDING_MEMMAP_PACKETS &&
			ctxt[master_proc_id]->pending_memmap_packet_list[i]; i++) {
		pending_pkt = (gpr_packet_t *)ctxt[master_proc_id]->pending_memmap_packet_list[i];
		if ((ctxt[master_proc_id]->error_memmap_shmem_info_flags &
			(AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
			<< AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0) {
				cma_client_data = GSL_GPR_CMA_FLAG_BIT;
			} else {
				cma_client_data = 0;
			}
		switch (pending_pkt->opcode) {
			case APM_CMD_RSP_SHARED_MEM_MAP_REGIONS:
				if (ctxt[master_proc_id]->memmap_count == 0) {
					GSL_DBG("the pending packet has been handled.");
					break;
				}
				rc = gsl_allocate_gpr_packet(APM_CMD_SHARED_MEM_UNMAP_REGIONS,
							GSL_SHMEM_SRC_PORT, APM_MODULE_INSTANCE_ID,
							sizeof(*unmap_payload), 0,
							pending_pkt->src_domain_id,
							&unmap_send_pkt);
				if (rc) {
					GSL_ERR("Failed to allocate GPR packet %d", rc);
					break;
				}
				unmap_payload =
					GPR_PKT_GET_PAYLOAD(struct
						apm_cmd_shared_mem_unmap_regions_t,
						unmap_send_pkt);
				unmap_payload->mem_map_handle =
					ctxt[master_proc_id]->pending_memmap_handle_list[i];
				unmap_send_pkt->client_data |= cma_client_data;
				GSL_LOG_PKT("send_pkt", GSL_SHMEM_SRC_PORT,
						unmap_send_pkt,
						sizeof(*unmap_send_pkt) +
						sizeof(*unmap_payload),
						NULL, 0);
				ctxt[master_proc_id]->memmap_count--;
				rc = gsl_send_spf_cmd(&unmap_send_pkt,
								&ctxt[master_proc_id]->sig,
								&unmap_rsp_pkt);
				if (rc || !unmap_rsp_pkt) {
					if (unmap_rsp_pkt)
						__gpr_cmd_free(unmap_rsp_pkt);
					break;
				}
				rc = gsl_shmem_handle_rsp(unmap_rsp_pkt,
					pending_pkt->src_domain_id, GPR_IBASIC_RSP_RESULT);
				gsl_mem_free(ctxt[master_proc_id]->pending_memmap_packet_list[i]);
				ctxt[master_proc_id]->pending_memmap_packet_list[i] = NULL;
				break;

			default:
				GSL_ERR("unsupported opcode %d encountered in unmap pending mem packet from spf",
					pending_pkt->opcode);
				rc = AR_EFAILED;
				break;
		};
	}

exit:
	return rc;
}

/*
 * map an allocation to specified subsystems only
 */
int32_t gsl_shmem_map_allocation_to_spf(
	const struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask_to_map_to, uint32_t master_proc_id)
{
	int32_t rc = AR_EBADPARAM;
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id])
		return AR_EUNSUPPORTED;

	if (alloc_data) {
		page = (struct gsl_shmem_page *)alloc_data->handle;
		rc = gsl_shmem_map_page_to_spf(page, flags, ss_mask_to_map_to);
	}

	return rc;
}

int32_t gsl_shmem_map_allocation(const struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask_to_map_to, uint32_t master_proc_id)
{
	int32_t rc = AR_EBADPARAM;
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id] || !alloc_data)
		return AR_EUNSUPPORTED;

	page = (struct gsl_shmem_page *)alloc_data->handle;
	rc = ar_shmem_map(&page->shmem_info);
	if (rc) {
		GSL_ERR("shmem_map is failed %d", rc);
		return rc;
	}
	rc = gsl_shmem_map_page_to_spf(page, flags, ss_mask_to_map_to);
	if (rc) {
		GSL_ERR("gsl_shmem_map_page_to_spf is failed %d", rc);
		ar_shmem_unmap(&page->shmem_info);
	}
	return rc;
}

int32_t gsl_shmem_map_dynamic_pd(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t flags, uint32_t ss_mask, uint32_t master_proc_id)
{
	int32_t rc = 0;
	uint32_t dyn_ss_mask = 0;
	uint32_t num_sys_id = 0, sys_id = AR_SUB_SYS_ID_FIRST;
	uint32_t dyn_pd_list[AR_SUB_SYS_ID_LAST], dyn_pd_cnt = 0;
	ar_shmem_proc_info ss_id_list[AR_SUB_SYS_ID_LAST];
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id] || !alloc_data)
		return AR_EBADPARAM;

	page = alloc_data->handle;
	/*
	 * The page spf_ss_mask contains the mapped pds,
	 * check and skip mapping for those.
	 */
	ss_mask &= ~GSL_GET_SPF_SS_MASK(master_proc_id);
	ss_mask &= ~page->spf_ss_mask;
	if (!ss_mask)
		return rc;

	/* back up ss_id_list to restore after mapping dynamic pd */
	gsl_memcpy(ss_id_list, sizeof(ss_id_list), page->ss_id_list,
		page->shmem_info.num_sys_id * sizeof(ar_shmem_proc_info));
	num_sys_id = page->shmem_info.num_sys_id;
	page->shmem_info.num_sys_id = 0;
	dyn_pd_cnt = 0;
	dyn_ss_mask = ss_mask;
	while (dyn_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(ss_mask, sys_id)) {
			page->ss_id_list[page->shmem_info.num_sys_id].proc_id =
				sys_id;
			page->ss_id_list[page->shmem_info.num_sys_id].proc_type =
				DYNAMIC_PD;
			page->ss_id_list[page->shmem_info.num_sys_id++].is_active =
				TRUE;
			dyn_pd_list[dyn_pd_cnt++] = sys_id;
		}
		++sys_id;
		dyn_ss_mask >>= 1;
	}

	rc = gsl_shmem_map_allocation(alloc_data, flags, ss_mask, master_proc_id);
	if (rc != AR_EOK) {
		GSL_ERR("dynamic pd mapping failed %d", rc);
		/* restore page ss_id_list */
		page->shmem_info.num_sys_id = num_sys_id;
		gsl_memcpy(page->ss_id_list, sizeof(page->ss_id_list), ss_id_list,
			num_sys_id * sizeof(ar_shmem_proc_info));
		return rc;
	}
	/*
	 * ss_id_list contains only static PDs as the dynamic PDs
	 * are skipped during boot up. So, add the dynamic PDs
	 * to the list after memory is mapped for dynamic PDs.
	 */
	page->shmem_info.num_sys_id = num_sys_id;
	gsl_memcpy(page->ss_id_list, sizeof(page->ss_id_list), ss_id_list,
		num_sys_id * sizeof(ar_shmem_proc_info));
	while (dyn_pd_cnt) {
		--dyn_pd_cnt;
		page->ss_id_list[page->shmem_info.num_sys_id].proc_id =
			dyn_pd_list[dyn_pd_cnt];
		page->ss_id_list[page->shmem_info.num_sys_id++].proc_type =
			DYNAMIC_PD;
	}
	page->spf_ss_mask |= ss_mask;
	return rc;
}

int32_t gsl_shmem_unmap_dynamic_pd(struct gsl_shmem_alloc_data *alloc_data,
	uint32_t ss_mask, uint32_t master_proc_id)
{
	int32_t rc = 0;
	uint32_t tmp_ss_mask = 0;
	uint32_t num_sys_id = 0, sys_id = AR_SUB_SYS_ID_FIRST;
	ar_shmem_proc_info ss_id_list[AR_SUB_SYS_ID_LAST];
	struct gsl_shmem_page *page = NULL;

	if (!ctxt[master_proc_id] || !alloc_data)
		return AR_EBADPARAM;

	/* Back up page ss_id_list to preserve other pds. */
	page = alloc_data->handle;
	gsl_memcpy(ss_id_list, sizeof(ss_id_list), page->ss_id_list,
		page->shmem_info.num_sys_id * sizeof(ar_shmem_proc_info));
	num_sys_id = page->shmem_info.num_sys_id;
	page->shmem_info.num_sys_id = 0;
	ss_mask &= ~GSL_GET_SPF_SS_MASK(master_proc_id);
	tmp_ss_mask = ss_mask;
	while (tmp_ss_mask) {
		if (GSL_TEST_SPF_SS_BIT(ss_mask, sys_id)) {
			page->ss_id_list[page->shmem_info.num_sys_id].proc_id =
				sys_id;
			page->ss_id_list[page->shmem_info.num_sys_id].proc_type =
				DYNAMIC_PD;
			/* Skip unmap command to DSP if proc is down */
			if ((gsl_spf_ss_state_get(page->master_proc) & ss_mask) != ss_mask)
				page->ss_id_list[page->shmem_info.num_sys_id].is_active = FALSE;
			++page->shmem_info.num_sys_id;
		}
		++sys_id;
		tmp_ss_mask >>= 1;
	}
	/*
	 * ss_mask contains only dynamic pd, so unmap
	 * happens only for dynamic pd.
	 */
	rc = gsl_shmem_unmap_allocation(alloc_data, ss_mask);
	if (rc != AR_EOK)
		GSL_ERR("dynamic pd unmap failed %d", rc);
	/*
	 * Restore page ss_id_list by removing unmapped
	 * dynamic pds.
	 */
	page->shmem_info.num_sys_id = 0;
	for (int j = 0; j < num_sys_id; j++) {
		if ((ss_id_list[j].proc_type == DYNAMIC_PD) &&
			(GSL_TEST_SPF_SS_BIT(ss_mask,
				ss_id_list[j].proc_id)))
			continue;
		page->ss_id_list[page->shmem_info.num_sys_id].proc_id =
			ss_id_list[j].proc_id;
		page->ss_id_list[page->shmem_info.num_sys_id++].proc_type =
			ss_id_list[j].proc_type;
	}
	page->spf_ss_mask &= ~ss_mask;
	return rc;
}

int32_t gsl_shmem_get_mapped_ss_mask(
	const struct gsl_shmem_alloc_data *alloc_data)
{
	if (alloc_data && alloc_data->handle)
		return alloc_data->handle->spf_ss_mask;
	return 0;
}

uint64_t gsl_shmem_get_metadata(
	const struct gsl_shmem_alloc_data *alloc_data)
{
	return (alloc_data->handle)->shmem_info.metadata;
}

int32_t gsl_shmem_hyp_assign(gsl_shmem_handle_t alloc_handle,
	uint64_t dest_sys, uint64_t src_sys)
{
	int32_t rc = AR_EOK;
	ar_shmem_hyp_assign_phys_info hyp_assn_info = { 0 };
	ar_shmem_hyp_assign_phys_addr hyp_phys_addr;
	ar_shmem_hyp_assign_dest_sys_info hyp_dst_sys;

	hyp_phys_addr.phys_addr =
		((uint64_t)alloc_handle->shmem_info.ipa_msw << 32) +
		alloc_handle->shmem_info.ipa_lsw;
	hyp_phys_addr.size = alloc_handle->shmem_info.buf_size;
	hyp_dst_sys.dest_sys_id = dest_sys;
	hyp_dst_sys.dest_perm = DEST_SYS_PERM_WRITE_READ;

	hyp_assn_info.phys_addr_list = &hyp_phys_addr;
	hyp_assn_info.dest_sys_list = &hyp_dst_sys;
	hyp_assn_info.src_sys_list = &src_sys;
	hyp_assn_info.phys_addr_list_size =
		sizeof(hyp_phys_addr) / sizeof(ar_shmem_hyp_assign_phys_addr);
	hyp_assn_info.dest_sys_list_size =
		sizeof(hyp_dst_sys) / sizeof(ar_shmem_hyp_assign_dest_sys_info);
	hyp_assn_info.src_sys_list_size = 1;
	hyp_assn_info.metadata = alloc_handle->shmem_info.metadata;

	rc = ar_shmem_hyp_assign_phys(&hyp_assn_info);
	if (rc)
		GSL_ERR("ar hyp_assign_phys failed %d", rc);

	return rc;
}

int32_t gsl_shmem_init(uint32_t num_master_procs, uint32_t *master_procs)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0, j = 0;
	struct gsl_shmem_page *page = NULL;
	bool_t is_shmem_supported = FALSE;
	uint32_t bin_idx = 0;

	/* register with GPR */
	rc = __gpr_cmd_register(GSL_SHMEM_SRC_PORT,
		gsl_shmem_gpr_callback, ctxt);
	if (rc) {
		GSL_ERR("Registering shmem src port failed");
		return rc;
	}

	rc = ar_shmem_init();
	if (rc)
		goto deregister;

	for (; i < num_master_procs; i++) {
		__gpr_cmd_is_shared_mem_supported(master_procs[i],
						  &is_shmem_supported);
		if (!is_shmem_supported)
			continue;

		ctxt[master_procs[i]] =
				gsl_mem_zalloc(sizeof(struct gsl_shmem_mgr_ctxt));

		if (!ctxt[master_procs[i]]) {
			GSL_ERR("Unable to allocate memory");
			rc = AR_ENOMEMORY;
			goto free_ctxt;
		}

		for (bin_idx = 0; bin_idx < GSL_SHMEM_MGR_NUM_BINS; ++bin_idx) {
			rc = ar_list_init(&(ctxt[master_procs[i]]->bins[bin_idx].page_list),
					  NULL, NULL);
			if (rc) {
				GSL_ERR("ar init list failed %d", rc);
				goto free_ctxt;
			}
			ctxt[master_procs[i]]->bins[bin_idx].num_pages = 0;
		}
	}

	for (i = 0; i < num_master_procs; i++) {
		if (!ctxt[master_procs[i]])
			continue;

		rc = ar_osal_mutex_create(&ctxt[master_procs[i]]->mutex);
		if (rc) {
			GSL_ERR("ar mutex create failed %d", rc);
			goto cleanup;
		}
		rc = ar_osal_mutex_create(&ctxt[master_procs[i]]->sig_lock);
		if (rc) {
			GSL_ERR("ar mutex create failed %d", rc);
			goto cleanup_mutex;
		}
		rc = gsl_signal_create(&ctxt[master_procs[i]]->sig,
				       &ctxt[master_procs[i]]->sig_lock);
		if (rc) {
			GSL_ERR("ar signal create failed %d", rc);
			goto cleanup_sig_lock;
		}

#ifdef GSL_SHMEM_MGR_STATS_ENABLE
	stats.curr_bytes_mapped = 0;
	stats.curr_bytes_requested = 0;
	stats.curr_bytes_allocated = 0;
	stats.max_bytes_mapped = 0;
	stats.max_bytes_requested = 0;
	stats.max_bytes_allocated = 0;
#endif
		/*
		 * allocate a page and keep it mapped till de-init, this is to somewhat
		 * reduce the amount of mapping/unmapping that takes place
		 */
		allocate_page(GSL_SHMEM_PRE_ALLOC_SIZE,
			GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH,
			GSL_GET_SPF_SS_MASK(master_procs[i]), 0, 0,
			GSL_EXT_MEM_HDL_NOT_ALLOCD,
			master_procs[i], &page);
	}

	goto exit;

cleanup_sig_lock:
	if (ctxt[master_procs[i]])
		ar_osal_mutex_destroy(ctxt[master_procs[i]]->sig_lock);
cleanup_mutex:
	if (ctxt[master_procs[i]])
		ar_osal_mutex_destroy(ctxt[master_procs[i]]->mutex);
cleanup:
	for (j = 0; j < i; j++) {
		if (ctxt[master_procs[j]]) {
			ar_osal_mutex_destroy(ctxt[master_procs[j]]->sig_lock);
			ar_osal_mutex_destroy(ctxt[master_procs[j]]->mutex);
		}
	}
free_ctxt:
	for (j = 0; j < num_master_procs; j++) {
		if (ctxt[master_procs[j]]) {
			gsl_mem_free(ctxt[master_procs[j]]);
			ctxt[master_procs[j]] = NULL;
		}
	}
deregister:
	__gpr_cmd_deregister(GSL_SHMEM_SRC_PORT);
exit:
	return rc;
}

int32_t gsl_shmem_deinit(void)
{
	int32_t rc1 = AR_EOK, rc = AR_EOK;
	ar_list_node_t *iter = NULL, *iter_look_ahead = NULL;
	struct gsl_shmem_page *page = NULL;
	uint32_t bin_idx = GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH;
	uint32_t i = 0;

	for (; i <= AR_SUB_SYS_ID_LAST; i++) {
		if (ctxt[i] == NULL)
			continue;

		/* free all pages that were allocated at init time */
		iter = ctxt[i]->bins[GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH]
			.page_list.dummy.next;
		while (iter != &ctxt[i]->bins[bin_idx].page_list.dummy) {
			/*
			 * below look ahead logic is needed because we are deleting
			 * nodes as we traverse the list
			 */
			iter_look_ahead = iter->next;
			page = get_container_base(iter, struct gsl_shmem_page, node);
			free_page(GSL_SHMEM_MGR_BIN_IDX_PRE_ALLOC_SCRATCH, page, 0);
			iter = iter_look_ahead;
		}

		rc = gsl_signal_destroy(&ctxt[i]->sig);
		if (rc)
			rc1 = rc;

		rc = ar_osal_mutex_destroy(ctxt[i]->sig_lock);
		if (rc && !rc1)
			rc1 = rc;

		rc = ar_osal_mutex_destroy(ctxt[i]->mutex);
		if (rc && !rc1)
			rc1 = rc;

		gsl_mem_free(ctxt[i]);
		ctxt[i] = NULL;
	}

	rc = ar_shmem_deinit();
	if (rc && !rc1)
		rc1 = rc;

	rc = __gpr_cmd_deregister(GSL_SHMEM_SRC_PORT);
	if (rc && !rc1)
		rc1 = AR_EFAILED;

	return rc1;
}
