/**
 * \file gsl_datapath.c
 *
 * \brief
 *      Implement data path handling for Graph Service Layer (GSL)
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_error.h"
#include "ar_osal_sys_id.h"
#include "apm_api.h"
#include "rd_sh_mem_ep_api.h"
#include "wr_sh_mem_ep_api.h"
#include "sh_mem_pull_push_mode_api.h"

#include "gsl_datapath.h"
#include "gsl_common.h"
#include "gpr_api_inline.h"

#define GSL_MAX_RETRIES 3
#define GSL_MAX_CACHE_UNMAP_RETRIES  3
#define GSL_MAX_CACHE_SIZE 32

#define GSL_METADATA_TO_DATA_FACTOR 2

#define GSL_EXT_MEM_HANDLE_CHANGING UINT64_MAX

#define GSL_TO_64_BIT(MSW_32_BIT, LSW_32_BIT)\
(((uint64_t)(MSW_32_BIT) << 32) + (LSW_32_BIT))

struct gsl_ext_mem_cache_entry {
	uint64_t alloc_handle;
	uint32_t alloc_size;
	uint32_t num_bufs_in_flight;
	uint64_t last_used;		// used when finding LRU eviction candidate
	// todo: state
	struct gsl_shmem_alloc_data shmem_data;
	ar_osal_mutex_t lock;	// protects alloc_handle and num_bufs_in_flight
};

/* Global cache object for external memory */
static struct gsl_external_mem_cache {
	struct gsl_ext_mem_cache_entry *entries; // array of [GSL_MAX_CACHE_SIZE];
	uint64_t age_counter;					// for updating last used
	uint32_t num_extern_mem_datapaths;		// refcount, essentially
	ar_osal_mutex_t num_dps_lock;			// lock for refcount
	ar_osal_mutex_t global_cache_lock;		// lock to serialise maps & evicts
} ext_mem_cache;

static void ext_mem_cache_init(void)
{
	uint32_t i;

	/* hold lock through init process so that next thread has an inited cache */
	GSL_MUTEX_LOCK(ext_mem_cache.num_dps_lock);
	/* check then post-increment */
	if (ext_mem_cache.num_extern_mem_datapaths++ == 0) {
		GSL_DBG("Init ext mem cache");

		/* if first UC, instantiate the cache array and locks.*/
		ext_mem_cache.entries = gsl_mem_zalloc(
			sizeof(struct gsl_ext_mem_cache_entry) * GSL_MAX_CACHE_SIZE);
		ext_mem_cache.age_counter = 0;
		ar_osal_mutex_create(&ext_mem_cache.global_cache_lock);

		for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i)
			ar_osal_mutex_create(&ext_mem_cache.entries[i].lock);
	}
	GSL_MUTEX_UNLOCK(ext_mem_cache.num_dps_lock);
}

static void ext_mem_cache_deinit(void)
{
	uint32_t i;

	/* hold lock through deinit process */
	GSL_MUTEX_LOCK(ext_mem_cache.num_dps_lock);
	/* decrement then check whether to tear down the cache */
	if (--ext_mem_cache.num_extern_mem_datapaths == 0) {
		GSL_DBG("Deinit ext mem cache");

		/* unmap all entries */
		for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i) {
			//state...
			if (ext_mem_cache.entries[i].alloc_handle
				!= GSL_EXT_MEM_HDL_NOT_ALLOCD)
				gsl_shmem_unmap_extern_mem(ext_mem_cache.entries[i].shmem_data);
			ar_osal_mutex_destroy(ext_mem_cache.entries[i].lock);
		}
		ar_osal_mutex_destroy(ext_mem_cache.global_cache_lock);
		gsl_mem_free(ext_mem_cache.entries);
		ext_mem_cache.entries = NULL;
	}
	GSL_MUTEX_UNLOCK(ext_mem_cache.num_dps_lock);
}

/*
 * note this does not increment bufs in flight
 * -- that's done in get_entry for concurrency reasons
 */
static void ext_mem_cache_update_entry_last_used(uint32_t index)
{
	uint32_t i;
	uint64_t least_recently_used = UINT64_MAX;

	/*
	 * Not protecting this:
	 * it does not matter if age counter is same for 2 buffers
	 */
	ext_mem_cache.entries[index].last_used = ext_mem_cache.age_counter++;

	/* int rollover handling for age counter */
	if (ext_mem_cache.age_counter == UINT64_MAX) {
		for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i) {
			if (ext_mem_cache.entries[i].last_used < least_recently_used)
				least_recently_used = ext_mem_cache.entries[i].last_used;
		}
		for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i)
			ext_mem_cache.entries[i].last_used -= least_recently_used;

		ext_mem_cache.age_counter = 0;
	}
}

/*
 * This only copies required fields out:  alloc_handle, alloc_size, spf_addr
 * If you need more, you need to add the copy.
 * input: index is the token set on the buffer we sent to DSP
 */
static void ext_mem_cache_buf_done(uint32_t index,
	struct gsl_ext_mem_cache_entry *cache_entry_data)
{
	/*
	 * copy required data out before we decrement buffs in flight.
	 * Once we decrement, cache entry could go away
	 */
	cache_entry_data->alloc_handle = ext_mem_cache.entries[index].alloc_handle;
	cache_entry_data->alloc_size = ext_mem_cache.entries[index].alloc_size;
	cache_entry_data->shmem_data.spf_addr
		= ext_mem_cache.entries[index].shmem_data.spf_addr;

	GSL_MUTEX_LOCK(ext_mem_cache.entries[index].lock);
	--ext_mem_cache.entries[index].num_bufs_in_flight;
	GSL_MUTEX_UNLOCK(ext_mem_cache.entries[index].lock);
}

static int32_t ext_mem_cache_evict_entry(uint32_t *evicted_idx,
	struct gsl_shmem_alloc_data *to_unmap)
{
	uint32_t i, lru_idx = UINT32_MAX, num_tries = 0;
	uint64_t least_recently_used = UINT64_MAX;
	bool_t entry_locked = FALSE;

	while (!entry_locked) {
		/*
		 * bail if our candidate LRU gets repeatedly re-used from under us
		 * This means all buffers are being used frequently (cache too small)
		 */
		if (num_tries++ == GSL_MAX_CACHE_UNMAP_RETRIES)
			goto cache_full;

		for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i) {
			/* this is the eviction strategy */
			if (ext_mem_cache.entries[i].num_bufs_in_flight == 0 &&
				ext_mem_cache.entries[i].last_used < least_recently_used) {
				lru_idx = i;
				least_recently_used = ext_mem_cache.entries[i].last_used;
			}
		}

		if (lru_idx == UINT32_MAX) {
			/* bail with failure -- all bufs in use */
			goto cache_full;
		}

		/*
		 * get lock and invalidate the alloc handle so other threads
		 * can't grab it from under this one, and make sure no thread sent a buf
		 * in the mean-time (i.e. dodge check-then-use issues)
		 */
		GSL_MUTEX_LOCK(ext_mem_cache.entries[lru_idx].lock);
		if (ext_mem_cache.entries[lru_idx].num_bufs_in_flight == 0)	{
			/* if bufs in flight non-zero, our candidate got used */
			ext_mem_cache.entries[lru_idx].alloc_handle
				= GSL_EXT_MEM_HDL_NOT_ALLOCD;

			entry_locked = TRUE;	/* exit this loop */
		}
		GSL_MUTEX_UNLOCK(ext_mem_cache.entries[lru_idx].lock);
	}

	/* the unmap is sent outside the global mapping lock */
	gsl_memcpy(to_unmap, sizeof(struct gsl_shmem_alloc_data),
		&ext_mem_cache.entries[lru_idx].shmem_data,
		sizeof(struct gsl_shmem_alloc_data));

	ext_mem_cache.entries[lru_idx].alloc_size = 0;
	ext_mem_cache.entries[lru_idx].last_used = UINT64_MAX;
	gsl_memset(&ext_mem_cache.entries[lru_idx].shmem_data, 0,
		sizeof(struct gsl_shmem_alloc_data));

	*evicted_idx = lru_idx;

	return AR_EOK;

cache_full:
	GSL_ERR("Cache all in use. Increase your cache size");
	/* todo: map one-time use buffer for this case */
	return AR_ENORESOURCE;
}

/*
 * output: alloc_data is constructed as a copy, idx is the index into the array
 * Use idx as the token to send to gecko
 * This function increments num_bufs_in_flight for synchronization reasons.
 */
static uint32_t ext_mem_cache_get_entry(uint32_t proc_id,
	struct gsl_extern_alloc_buff_info ext_mem_data,
	struct gsl_shmem_alloc_data *alloc_data, uint32_t *idx)
{
	int32_t rc = AR_EOK;
	uint32_t i, first_unused = UINT32_MAX;
	struct gsl_shmem_alloc_data to_unmap = { 0 };

	/*
	 * locking here only for cache disabled, to prevent double unmap
	 * Should be moved back to where it is commented out when cache enabled.
	 * Could make disable flow more efficient (no other locks) with this,
	 * but effort is better spent on enabling the cache as designed...
	 */
	GSL_MUTEX_LOCK(ext_mem_cache.global_cache_lock);

	/*
	 * Checking if item is in the cache already
	 * Not locking every check as this is costly. We will re-check under lock.
	 */
	for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i) {

#ifdef GSL_EXT_MEM_CACHE_DISABLE
		if (ext_mem_cache.entries[i].num_bufs_in_flight == 0 &&
			ext_mem_cache.entries[i].alloc_handle
			!= GSL_EXT_MEM_HDL_NOT_ALLOCD) {

			GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
			/*
			 * check again that handle is valid -- other thread may
			 * have unmapped already
			 */
			if (ext_mem_cache.entries[i].num_bufs_in_flight == 0 &&
				ext_mem_cache.entries[i].alloc_handle
				!= GSL_EXT_MEM_HDL_NOT_ALLOCD) {
				GSL_DBG("Unmapping entry %d, handle 0x%x",
					i, ext_mem_cache.entries[i].alloc_handle);

				ext_mem_cache.entries[i].alloc_handle
					= GSL_EXT_MEM_HDL_NOT_ALLOCD;

				//unmapping within lock... not efficient
				rc = gsl_shmem_unmap_extern_mem(
					ext_mem_cache.entries[i].shmem_data);
				if (rc != AR_EOK)
					GSL_DBG("unmap extern mem failed rc=%d", rc);
			}

			GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);

		}
		/* we will never hit the next check in cache disabled path. */
#endif // GSL_EXT_MEM_CACHE_DISABLE

		if (ext_mem_cache.entries[i].alloc_handle
			== ext_mem_data.alloc_handle) {

			/* found cache entry. mark it in use safely */
			GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
			if (ext_mem_cache.entries[i].alloc_handle
				== ext_mem_data.alloc_handle) {
				++ext_mem_cache.entries[i].num_bufs_in_flight;
				GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);

				goto exit_success;
			}

			/* implied else */
			/* Our entry got sniped by an eviction. Log and map later */
			GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);
			GSL_DBG("gsl extmem cache entry got sniped. increase cache size?");
		}
	}

	/* We did not find our buffer in the cache. We need to map it */
	/* see note at top of function re lock */
	//GSL_MUTEX_LOCK(ext_mem_cache.global_cache_lock);
	/* all mappings are serialised to avoid double-mapping the same alloc */

	/*
	 * Check if our handle got added to the cache while we were waiting for
	 * the global lock
	 */
	for (i = 0; i < GSL_MAX_CACHE_SIZE; ++i) {
		if (ext_mem_cache.entries[i].alloc_handle
			== ext_mem_data.alloc_handle) {
			/* our buffer got mapped by another thread. We can stop. */
			GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
			++ext_mem_cache.entries[i].num_bufs_in_flight;
			GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);

			/* see note at top of function re lock */
			//GSL_MUTEX_UNLOCK(ext_mem_cache.global_cache_lock);
			goto exit_success;
		}

		/*
		 * continue even if we see an unused buff, since desired buffer could be
		 * after first unused once we add aging out
		 */
		if (first_unused == UINT32_MAX
			&& ext_mem_cache.entries[i].alloc_handle
			== GSL_EXT_MEM_HDL_NOT_ALLOCD) {
			first_unused = i;
		}
	}

	/*
	 * Buffer is not already in cache. If we saw empty space, take it
	 * if no empty space, find a buffer to evict.
	 */
	if (first_unused != UINT32_MAX) {
		i = first_unused;
	} else {
		/* there was no unused buffer. We need to evict an entry */
		rc = ext_mem_cache_evict_entry(&i, &to_unmap);
		if (rc != AR_EOK) {
			GSL_ERR("Unable to evict: cache all in use right now. rc=%d", rc);
			goto exit_error;
		}
	}

	/* we evicted entry i and it's available, or we saw i was unused */
	GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
	ext_mem_cache.entries[i].num_bufs_in_flight = 1;
	GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);

	GSL_DBG("mapping entry %d, handle 0x%x", i, ext_mem_data.alloc_handle);

	/* map inside the global lock in case 2 graphs call on the same handle */
	rc = gsl_shmem_map_extern_mem(ext_mem_data.alloc_handle,
		ext_mem_data.alloc_size, proc_id, &ext_mem_cache.entries[i].shmem_data);
	if (rc != AR_EOK) {
		GSL_ERR("map extern mem failed rc=%d", rc);
		GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
		ext_mem_cache.entries[i].num_bufs_in_flight = 0;
		GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);
		goto exit_error;
	}

	GSL_MUTEX_LOCK(ext_mem_cache.entries[i].lock);
	ext_mem_cache.entries[i].alloc_size = ext_mem_data.alloc_size;
	ext_mem_cache.entries[i].last_used = ext_mem_cache.age_counter;
	ext_mem_cache.entries[i].alloc_handle = ext_mem_data.alloc_handle;
	GSL_MUTEX_UNLOCK(ext_mem_cache.entries[i].lock);

	/* see note at top of function re lock */
	//GSL_MUTEX_UNLOCK(ext_mem_cache.global_cache_lock);

	/*
	 * Unmapping from outside the global lock.
	 * This is to allow shmem mgr in future to not be serialised.
	 */
	if (to_unmap.handle) {
		GSL_DBG("Unmapping because evicted, handle 0x%x",
			ext_mem_cache.entries[i].alloc_handle);
		rc = gsl_shmem_unmap_extern_mem(to_unmap);
		if (rc != AR_EOK) {
			/* ignore this, we have torn down the entry anyway */
			GSL_DBG("unmap extern mem failed rc=%d", rc);
		}
	}

exit_success:
	gsl_memcpy(alloc_data, sizeof(struct gsl_shmem_alloc_data),
		&ext_mem_cache.entries[i].shmem_data,
		sizeof(struct gsl_shmem_alloc_data));
	*idx = i;

	/*
	 * see note at top of function re lock
	 * for now with disable just use the unlock here
	 */
	//return rc;

exit_error:
	GSL_MUTEX_UNLOCK(ext_mem_cache.global_cache_lock);
	return rc;
}

static struct gsl_buff_internal *gsl_dp_find_buff_from_va(
	struct gsl_data_path_info *dp_info, uint8_t *vaddr, uintptr_t *offset,
	uint32_t *idx)
{
	uint32_t i = 0;
	struct gsl_buff_internal *buff;

	/*
	 * find the corresponding allocation, this also serves as a sanity check
	 * on the vaddr passed from client
	 */
	for (i = 0; i < dp_info->config.num_buffs; ++i) {
		buff = &dp_info->buff_list[i];
		if (vaddr >= (uint8_t *)buff->gsl_msg.shmem.v_addr) {
			*offset = vaddr - (uint8_t *)buff->gsl_msg.shmem.v_addr;
			*idx = i;
			if (*offset < dp_info->config.buff_size)
				return buff;
		}
	}

	return NULL;
}

/*
 * Marks a buffer as available, available here means the buffer is with GSL and
 * not with Spf. So GSL can only read/write buffers that are available.
 */
static void gsl_mark_buffer_as_avail(struct gsl_data_path_info *dp_info,
	uint32_t buf_index)
{
	GSL_MUTEX_LOCK(dp_info->lock);

	if (buf_index <= dp_info->config.num_buffs)
		clear_bit(dp_info->buff_used_status, buf_index);

	GSL_MUTEX_UNLOCK(dp_info->lock);
}

/* reset the internal metadata buff queue to empty state */
static void gsl_clear_internal_md_buff(struct gsl_data_path_info *dp_info)
{
	GSL_MUTEX_LOCK(dp_info->lock);
	dp_info->md_buff_list_head = 0;
	dp_info->md_buff_list_tail = 0;
	dp_info->md_buff_list_acked = 0;
	GSL_MUTEX_UNLOCK(dp_info->lock);
}

static struct gsl_metadata_buff_internal *gsl_enqueue_internal_md_buff(
	struct gsl_data_path_info *dp_info)
{
	struct gsl_metadata_buff_internal *gsl_md_buff = NULL;
	uint32_t tmp_head;
	int32_t rc;

	GSL_MUTEX_LOCK(dp_info->lock);

	/*
	 * note this logic depends on the fact that similiar to data buffers,
	 * metadata buffers come in the order of FIFO
	 */
	tmp_head = (dp_info->md_buff_list_head + 1) % dp_info->md_buff_list_size;

	if (tmp_head == dp_info->md_buff_list_tail) {
		/* queue full */
		GSL_MUTEX_UNLOCK(dp_info->lock);
		GSL_ERR("internal md buff queue full");
		gsl_md_buff = NULL;
		goto exit;
	}

	gsl_md_buff = &dp_info->md_buff_list[dp_info->md_buff_list_head];
	dp_info->md_buff_list_head = tmp_head;
	GSL_MUTEX_UNLOCK(dp_info->lock);

	/*
	 * alloc shared memroy if needed, only allocate md memory if not already
	 * done, we free this in gsl_data_path_deinit once we are done with the
	 * usecase
	 */
	if (dp_info->oob_metadata_flag && !gsl_md_buff->gsl_msg.shmem.handle) {
		rc = gsl_shmem_alloc(dp_info->config.max_metadata_size,
			dp_info->master_proc_id, &gsl_md_buff->gsl_msg.shmem);
		if (rc) {
			GSL_ERR("failed to allocate shmem for metadata err %d", rc);
			goto exit;
		}
	}
exit:
	return gsl_md_buff;
}

/*
 * dequeues and frees the oldest internal metadata buffer. Copies to client
 * memory if requested by caller and returns the client buffer
 * note: this function does not free shared memory so that the allocations can
 * be reused, they get freed in gsl_data_path_deinit
 */
static struct gsl_metadata_buff_internal *gsl_dequeue_internal_md_buff(
	struct gsl_data_path_info *dp_info)
{
	struct gsl_metadata_buff_internal *gsl_md_buff = NULL;

	GSL_MUTEX_LOCK(dp_info->lock);

	/*
	 * note this logic depends on the fact that metadata buffers come in the
	 * order of FIFO
	 */
	if (dp_info->md_buff_list_tail == dp_info->md_buff_list_head) {
		/* empty condition */
		GSL_ERR("internal md buff queue empty");
		goto exit;
	}

	gsl_md_buff = &dp_info->md_buff_list[dp_info->md_buff_list_tail];

	dp_info->md_buff_list_tail = (dp_info->md_buff_list_tail + 1) %
		dp_info->md_buff_list_size;
exit:
	GSL_MUTEX_UNLOCK(dp_info->lock);

	return gsl_md_buff;
}

/*
 * update the spf returned metadata status and size to tail entry in the
 * internal metadata buff list
 */
static void gsl_store_md_status_from_spf(struct gsl_data_path_info *dp_info,
	uint32_t size_from_spf, uint32_t status_from_spf)
{
	struct gsl_metadata_buff_internal *gsl_md_buff = NULL;

	GSL_MUTEX_LOCK(dp_info->lock);

	gsl_md_buff = &dp_info->md_buff_list[dp_info->md_buff_list_acked];
	gsl_md_buff->md_size_from_spf = size_from_spf;
	gsl_md_buff->md_status_from_spf = status_from_spf;
	dp_info->md_buff_list_acked = (dp_info->md_buff_list_acked + 1) %
		dp_info->md_buff_list_size;
	GSL_MUTEX_UNLOCK(dp_info->lock);
}

static void gsl_handle_buff_done_shmem(struct gsl_data_path_info *dp_info,
	gsl_cb_func_ptr cb,
	struct gsl_event_read_write_done_payload *rw_done_payload,
	uint32_t buff_idx, uint64_t pa,	uint32_t status,
	struct gsl_buff_internal *gsl_buff, uint32_t ev_id, void *client_data,
	struct gsl_metadata_buff_internal *gsl_md_buff, uint32_t md_status)
{
	/* used to pass to client in callback */
	uint64_t offset;
	struct gsl_event_cb_params ev;
	struct gsl_ext_mem_cache_entry cache_entry = { 0 };

	ev.event_id = ev_id;
	ev.source_module_id = GSL_EVENT_SRC_MODULE_ID_GSL;
	rw_done_payload->tag = dp_info->cached_tag;

	switch (GSL_DP_DATA_MODE(dp_info)) {
	case GSL_DATA_MODE_BLOCKING:
		gsl_mark_buffer_as_avail(dp_info, buff_idx);
		gsl_signal_set(&dp_info->dp_signal,	GSL_SIG_EVENT_MASK_SPF_RSP,
			status, NULL);
		break;
	case GSL_DATA_MODE_NON_BLOCKING:
		gsl_mark_buffer_as_avail(dp_info, buff_idx);
		ev.event_payload = NULL;
		ev.event_payload_size = 0;
		if (cb)
			cb(&ev, client_data);

		/*
		 * below signal set is needed during close as gsl_graph_close waits for
		 * all buffers to come back from Spf
		 */
		gsl_signal_set(&dp_info->dp_signal,
			GSL_SIG_EVENT_MASK_SPF_RSP, status, NULL);
		break;
	case GSL_DATA_MODE_SHMEM:
		offset = pa - gsl_buff->gsl_msg.shmem.spf_addr;
		rw_done_payload->buff.addr =
			(uint8_t *)(gsl_buff->gsl_msg.shmem.v_addr) + offset;
		rw_done_payload->buff.size = gsl_buff->size_from_spf;
		rw_done_payload->status = status;

		if (gsl_md_buff) {
			rw_done_payload->buff.metadata = gsl_md_buff->client_md_ptr;
			rw_done_payload->buff.metadata_size = gsl_md_buff->md_size_from_spf;
			rw_done_payload->md_status = gsl_md_buff->md_status_from_spf;
		} else {
			rw_done_payload->buff.metadata = NULL;
			rw_done_payload->buff.metadata_size = 0;
			rw_done_payload->md_status = md_status;
		}
		if (ev_id == GSL_EVENT_ID_READ_DONE) {
			GSL_PKT_LOG_DATA("rd__data", dp_info->src_port,
				rw_done_payload.buff.addr, rw_done_payload.buff.size);
		}

		/* issue the callback to client */
		/* note client must copy in cb context */
		ev.event_payload = rw_done_payload;
		ev.event_payload_size =
			sizeof(struct gsl_event_read_write_done_payload);
		if (cb)
			cb(&ev, client_data);
		break;
	case GSL_DATA_MODE_EXTERN_MEM:

		/*
		 * This only copies required fields:  alloc_handle, alloc_size, spf_addr
		 * If you need more, you need to add the copy to the function
		 */
		ext_mem_cache_buf_done(buff_idx, &cache_entry);

		offset = pa - cache_entry.shmem_data.spf_addr;
		rw_done_payload->buff.size = gsl_buff->size_from_spf;

		rw_done_payload->buff.alloc_info.alloc_size = cache_entry.alloc_size;
		rw_done_payload->buff.alloc_info.alloc_handle
			= cache_entry.alloc_handle;
		rw_done_payload->buff.alloc_info.offset = (uint32_t)offset;
		// this can technically lose data... if the offset is > 4 Gigs...

		ev.event_payload = rw_done_payload;
		ev.event_payload_size =
			sizeof(struct gsl_event_read_write_done_payload);

		rw_done_payload->status = status;

		if (gsl_md_buff) {
			rw_done_payload->buff.metadata = gsl_md_buff->client_md_ptr;
			rw_done_payload->buff.metadata_size = gsl_md_buff->md_size_from_spf;
			rw_done_payload->md_status = gsl_md_buff->md_status_from_spf;
		} else {
			rw_done_payload->buff.metadata = NULL;
			rw_done_payload->buff.metadata_size = 0;
			rw_done_payload->md_status = md_status;
		}

		if (cb)
			cb(&ev, client_data);

		break;
	default:
		GSL_ERR("got handle buff done for unknown data mode %d",
			GSL_DP_DATA_MODE(dp_info));
	}
}

static int32_t gsl_handle_buff_done_nonshmem(struct gsl_data_path_info *dp_info,
	gpr_packet_t *gpr_packet, uint32_t ev_id, gsl_cb_func_ptr cb,
	void *client_data, uint32_t status,	uint32_t index)
{
	struct gsl_buff_internal *buff = &dp_info->buff_list[index];
	struct gsl_event_cb_params ev;

	ev.event_id = ev_id;
	ev.source_module_id = GSL_EVENT_SRC_MODULE_ID_GSL;
	ev.event_payload = NULL;
	ev.event_payload_size = 0;
	if (!buff) {
		GSL_ERR("No buff available");
		return AR_EBADPARAM;
	}
	buff->gsl_msg.payload = (uint8_t *)gpr_packet;
	gsl_mark_buffer_as_avail(dp_info, index);

	if (cb)
		cb(&ev, client_data);

	/*
	 * below signal set is needed during close as gsl_graph_close waits for
	 * all buffers to come back from Spf
	 */
	gsl_signal_set(&dp_info->dp_signal,
		GSL_SIG_EVENT_MASK_SPF_RSP, status, NULL);

	return AR_EOK;
}

static struct gsl_buff_internal *gsl_find_next_avail_buffer(
	struct gsl_data_path_info *dp_info, uint32_t *buf_idx)
{
	struct gsl_buff_internal *gsl_buff = NULL;

	GSL_MUTEX_LOCK(dp_info->lock);

	if (dp_info->config.num_buffs == 0)
		goto exit;

	if (test_bit(dp_info->buff_used_status, dp_info->curr_buff_index))
		goto exit;

	gsl_buff = &dp_info->buff_list[dp_info->curr_buff_index];
	*buf_idx = dp_info->curr_buff_index;
	set_bit(dp_info->buff_used_status, dp_info->curr_buff_index);
	dp_info->curr_buff_index = (dp_info->curr_buff_index + 1) %
		dp_info->config.num_buffs;

exit:
	GSL_MUTEX_UNLOCK(dp_info->lock);

	return gsl_buff;
}

/*
 * used to send push pull bufs to shared mem EP
 */
static int32_t gsl_dp_configure_pull_push_on_spf(
	struct gsl_data_path_info *dp_info, struct gsl_signal *signal)
{
	int32_t rc = AR_EOK;
	struct apm_cmd_header_t *apm_hdr = NULL;
	struct apm_module_param_data_t *param_hdr = NULL;
	struct sh_mem_pull_push_mode_cfg_t *pull_push_cfg = NULL;
	uint8_t *spf_cmd;
	uint32_t spf_cmd_sz = 0;
	gpr_packet_t *send_pkt = NULL;

	/* configure pull_push mode buffers on spf */
	spf_cmd_sz = GSL_ALIGN_8BYTE(sizeof(*apm_hdr) + sizeof(*param_hdr) +
		sizeof(*pull_push_cfg));

	rc = gsl_allocate_gpr_packet(APM_CMD_SET_CFG, dp_info->src_port,
		dp_info->miid, spf_cmd_sz, 0, dp_info->master_proc_id, &send_pkt);
	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto exit;
	}
	spf_cmd = GPR_PKT_GET_PAYLOAD(uint8_t, send_pkt);
	gsl_memset(spf_cmd, 0, spf_cmd_sz);

	apm_hdr = (struct apm_cmd_header_t *)spf_cmd;
	param_hdr = (struct apm_module_param_data_t *)
		(spf_cmd + sizeof(*apm_hdr));
	pull_push_cfg = (struct sh_mem_pull_push_mode_cfg_t *)(spf_cmd +
		sizeof(*apm_hdr) + sizeof(*param_hdr));

	apm_hdr->payload_size = spf_cmd_sz - sizeof(*apm_hdr);
	param_hdr->module_instance_id = dp_info->miid;
	param_hdr->param_id = PARAM_ID_SH_MEM_PULL_PUSH_MODE_CFG;
	param_hdr->param_size = sizeof(*pull_push_cfg);

	pull_push_cfg->circ_buf_mem_map_handle =
		dp_info->buff_list[0].gsl_msg.shmem.spf_mmap_handle;
	pull_push_cfg->shared_circ_buf_addr_lsw =
		(uint32_t)dp_info->buff_list[0].gsl_msg.shmem.spf_addr;
	pull_push_cfg->shared_circ_buf_addr_msw =
		(uint32_t)(dp_info->buff_list[0].gsl_msg.shmem.spf_addr >> 32);
	pull_push_cfg->shared_circ_buf_size = dp_info->config.buff_size;

	pull_push_cfg->pos_buf_mem_map_handle =
		dp_info->buff_list[1].gsl_msg.shmem.spf_mmap_handle;
	pull_push_cfg->shared_pos_buf_addr_lsw =
		(uint32_t)dp_info->buff_list[1].gsl_msg.shmem.spf_addr;
	pull_push_cfg->shared_pos_buf_addr_msw =
		(uint32_t)(dp_info->buff_list[1].gsl_msg.shmem.spf_addr >> 32);

	GSL_LOG_PKT("send_pkt", dp_info->src_port, send_pkt, sizeof(*send_pkt) +
		spf_cmd_sz, NULL, 0);
	rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt, signal);
	if (rc)
		GSL_ERR("set config inband failed rc %d", rc);

exit:
	return rc;
}

/*
 * allocate the buffers for push pull mode, but don't send them to spf yet
 */
static int32_t gsl_dp_allocate_push_pull_buffers(
	struct gsl_data_path_info *dp_info, enum gsl_data_dir dir)
{
	int32_t rc = AR_EOK;
	uint32_t flags = 0;
	struct gsl_cmd_configure_read_write_params *cfg = &dp_info->config;

	/*
	 * in push_pull mode we allocate two dedicated buffers one for data
	 * requested by client and another for the position buffer
	 */
	if (cfg->num_buffs > 2 || cfg->num_buffs < 1) {
		GSL_ERR("num buffs %d in push_pull mode exceeds 2 or less than 1",
			cfg->num_buffs);
		return AR_EBADPARAM;
	}
	dp_info->config.num_buffs = 2;

	/* allocate memory for internal buffers */
	dp_info->buff_list = gsl_mem_zalloc(
		dp_info->config.num_buffs * sizeof(struct gsl_buff_internal));
	if (!dp_info->buff_list) {
		rc = AR_ENOMEMORY;
		goto exit;
	}

	if (dir == GSL_DATA_DIR_READ)
		flags = GSL_SHMEM_DEDICATED_PAGE | GSL_SHMEM_MAP_UNCACHED;
	else
		flags = GSL_SHMEM_DEDICATED_PAGE;

	rc = gsl_shmem_alloc_ext(cfg->buff_size,
		GSL_GET_SPF_SS_MASK(dp_info->master_proc_id), flags,
		cfg->platform_info, dp_info->master_proc_id,
		&dp_info->buff_list[0].gsl_msg.shmem);
	if (rc) {
		GSL_ERR("shmem alloc failed rc %d", rc);
		goto free_buff_list;
	}

	/* allocate position buffer as a dedicated page */
	rc = gsl_shmem_alloc_ext(
		sizeof(struct sh_mem_pull_push_mode_position_buffer_t),
		GSL_GET_SPF_SS_MASK(dp_info->master_proc_id),
		GSL_SHMEM_DEDICATED_PAGE | GSL_SHMEM_MAP_UNCACHED,
		cfg->platform_info, dp_info->master_proc_id,
		&dp_info->buff_list[1].gsl_msg.shmem);
	if (rc) {
		GSL_ERR("shmem alloc failed rc %d", rc);
		goto cleanup;
	}

	return rc;

cleanup:
	gsl_shmem_free(&dp_info->buff_list[0].gsl_msg.shmem);
free_buff_list:
	gsl_mem_free(dp_info->buff_list);
	dp_info->buff_list = NULL;
exit:
	return rc;
}

static int32_t reconfigure_buffers(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg)
{
	int32_t rc = AR_EOK;
	uint32_t i;
	/* handle the scenario where buffers were already configured */
	if (cfg->attributes == dp_info->config.attributes &&
		cfg->buff_size == dp_info->config.buff_size &&
		cfg->num_buffs == dp_info->config.num_buffs) {
		/* client requested same configuration no-op */
		return AR_EALREADY;
	}

	/* free current buffers */
	for (i = 0; i < dp_info->config.num_buffs; ++i) {
		rc = gsl_msg_free(&dp_info->buff_list[i].gsl_msg);
		if (rc != AR_EOK) {
			GSL_ERR("Failed to free gsl msg %d", rc);
			return rc;
		}
	}

	/* free internal buffer object */
	if (dp_info->buff_list) {
		gsl_mem_free(dp_info->buff_list);
		dp_info->buff_list = NULL;
	}
	if (dp_info->md_buff_list) {
		gsl_mem_free(dp_info->md_buff_list);
		dp_info->md_buff_list = NULL;
	}

	if (GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_EXTERN_MEM
		&& (cfg->attributes & GSL_ATTRIBUTES_DATA_MODE_MASK)
		!= GSL_DATA_MODE_EXTERN_MEM) {
		/* if reconfiguring out of extern mem mode, tell the extmem cache */
		ext_mem_cache_deinit();
	}

	return rc;
}

static int32_t gsl_dp_config_nonshmem(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg)
{
	int rc = AR_EOK;

	if (cfg->num_buffs > GSL_MAX_NUM_DATA_BUFFERS) {
		GSL_ERR("num_buffs greater than %d", GSL_MAX_NUM_DATA_BUFFERS);
		rc = AR_EBADPARAM;
		goto exit;
	}

	/* allocate memory for internal buffers and md buffers */
	dp_info->buff_list = gsl_mem_zalloc(cfg->num_buffs * sizeof(struct
		gsl_buff_internal));
	if (!dp_info->buff_list) {
		rc = AR_ENOMEMORY;
		goto exit;
	}

	if (cfg->max_metadata_size > 0) {
		dp_info->md_buff_list_size = GSL_METADATA_TO_DATA_FACTOR *
			cfg->num_buffs;
		dp_info->md_buff_list = gsl_mem_zalloc(dp_info->md_buff_list_size *
			sizeof(struct gsl_metadata_buff_internal));
		if (!dp_info->md_buff_list) {
			rc = AR_ENOMEMORY;
			goto free_internal_buffs;
		}
	}

	dp_info->config = *cfg; /* copy the cfg sent by client */
	goto exit;

free_internal_buffs:
	gsl_mem_free(dp_info->buff_list);
exit:
	return rc;
}

/* specific push pull configuration */
static int32_t gsl_dp_config_push_pull_mode(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg,
	struct gsl_signal *signal, enum gsl_data_dir dir)
{
	int32_t rc = AR_EOK;
	uint32_t i;

	if (GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_ALLOC_SHMEM_ONLY
		|| GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_DEFAULT) {

		if (cfg->num_buffs > GSL_MAX_NUM_DATA_BUFFERS) {
			GSL_ERR("num_buffs greater than %d", GSL_MAX_NUM_DATA_BUFFERS);
			rc = AR_EBADPARAM;
			goto exit;
		}

		if (dp_info->config.num_buffs > 0) {
			rc = reconfigure_buffers(dp_info, cfg);
			if (rc == AR_EALREADY)
				return AR_EOK;
			else if (rc)
				return rc;
		}

		dp_info->config = *cfg; /* copy the cfg sent by client */

		rc = gsl_dp_allocate_push_pull_buffers(dp_info, dir);
		if (rc) {
			GSL_ERR("failed to allocate push pull buffers %d", rc);
			goto clean_cfg;
		}
		/* if we didn't bail, we successfully allocated 2 buffs */
	}

	if (GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_SPF_PROVISION_ONLY
		|| GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_DEFAULT) {
		/**
		 * send now-allocated push pull buffers
		 */
		rc = gsl_dp_configure_pull_push_on_spf(dp_info, signal);
		if (rc) {
			GSL_ERR("failed to send push pull buffers to spf %d", rc);
			goto free_buffers;
		}
	}

	return rc;

free_buffers:
	if (GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_DEFAULT)
		for (i = 0; i < 2; ++i)
			gsl_shmem_free(&dp_info->buff_list[i].gsl_msg.shmem);
clean_cfg:
	if (GSL_DATAPATH_SETUP_MODE(cfg) != GSL_DATAPATH_SETUP_SPF_PROVISION_ONLY)
		gsl_memset(&dp_info->config, 0, sizeof(dp_info->config));
exit:
	return rc;
}

static int32_t gsl_dp_config_extern_mem_mode(
	struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg)
{
	int32_t rc = AR_EOK;

	/*
	 * for extern mem mode, we don't get _any_ buffer info from cfg
	 * we also don't need to do much
	 */

	/* Handle case where DP was in a different mode: deallocate buffers */
	if (dp_info->config.num_buffs > 0) {
		rc = reconfigure_buffers(dp_info, cfg);
		if (rc == AR_EALREADY) {
			rc = AR_EOK;
			goto exit;
		} else if (rc) {
			goto exit;
		}
	}

	/* allocate internal md buffers */
	if (cfg->max_metadata_size > 0) {
		dp_info->md_buff_list_size = GSL_METADATA_TO_DATA_FACTOR *
			GSL_MAX_NUM_DATA_BUFFERS;
		dp_info->md_buff_list = gsl_mem_zalloc(dp_info->md_buff_list_size *
			sizeof(struct gsl_metadata_buff_internal));
		if (!dp_info->md_buff_list) {
			rc = AR_ENOMEMORY;
			goto exit;
		}
	}

	if (GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_EXTERN_MEM) {
		/* tell cache if this DP was not previously in extern mem mode */
		ext_mem_cache_init();
	}

	dp_info->config = *cfg; /* copy the cfg sent by client */

	/* sanity: ensure non-existent DP buffers are never accessed later */
	dp_info->config.num_buffs = 0;
	dp_info->config.buff_size = 0;

exit:
	return rc;
}

static int32_t gsl_dp_config_common_modes(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0, j = 0;
	uint32_t flags = 0;

	/*
	 * if dp was already configured, either free the existing buffs or
	 * return early if configuration is the same.
	 */
	if (dp_info->config.num_buffs > 0) {
		rc = reconfigure_buffers(dp_info, cfg);
		if (rc == AR_EALREADY)
			return AR_EOK;
		else if (rc)
			goto exit;
	}

	if (cfg->num_buffs > GSL_MAX_NUM_DATA_BUFFERS) {
		GSL_ERR("num_buffs greater than %d", GSL_MAX_NUM_DATA_BUFFERS);
		rc = AR_EBADPARAM;
		goto exit;
	}

	dp_info->config = *cfg; /* copy the cfg sent by client */

	/* allocate memory for internal buffers and md buffers */
	dp_info->buff_list = gsl_mem_zalloc(cfg->num_buffs * sizeof(struct
		gsl_buff_internal));
	if (!dp_info->buff_list) {
		rc = AR_ENOMEMORY;
		goto exit;
	}
	if (cfg->max_metadata_size > 0) {
		dp_info->md_buff_list_size = GSL_METADATA_TO_DATA_FACTOR *
			cfg->num_buffs;
		dp_info->md_buff_list = gsl_mem_zalloc(dp_info->md_buff_list_size *
			sizeof(struct gsl_metadata_buff_internal));
		if (!dp_info->md_buff_list) {
			rc = AR_ENOMEMORY;
			goto free_internal_buffs;
		}
	}
	/*
	 * if client passed any sort of platform info then use a dedicated
	 * page for shmem
	 */
	if (cfg->platform_info != 0)
		flags = GSL_SHMEM_DEDICATED_PAGE;

	for (i = 0; i < cfg->num_buffs; ++i) {
		rc = gsl_shmem_alloc_ext(cfg->buff_size,
			GSL_GET_SPF_SS_MASK(dp_info->master_proc_id),
			flags, cfg->platform_info, dp_info->master_proc_id,
			&dp_info->buff_list[i].gsl_msg.shmem);
		if (rc) {
			GSL_ERR("shmem alloc failed rc %d", rc);
			goto cleanup;
		}
	}

	return rc;

cleanup:
	for (j = 0; j < i; ++j)
		gsl_shmem_free(&dp_info->buff_list[j].gsl_msg.shmem);

	gsl_memset(&dp_info->config, 0, sizeof(dp_info->config));
free_internal_buffs:
	gsl_mem_free(dp_info->buff_list);
	dp_info->buff_list = NULL;
	if (dp_info->md_buff_list) {
		gsl_mem_free(dp_info->md_buff_list);
		dp_info->md_buff_list = NULL;
		dp_info->md_buff_list_size = 0;
	}
exit:
	return rc;
}

static int32_t gsl_dp_write_shmem(struct gsl_data_path_info *dp_info,
	struct gsl_buff_internal *buff, struct gsl_metadata_buff_internal *md_buff,
	uintptr_t offset, uint32_t buff_idx, uint32_t  size,
	struct gsl_buff *client_buff)
{
	data_cmd_wr_sh_mem_ep_data_buffer_v2_t *write_cmd;
	media_format_t *media_fmt;
	int32_t rc;
	uint64_t tmp;
	gpr_packet_t *send_pkt = NULL;
	uint32_t gpr_pld_size;
	uint32_t opcode = DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2;

	GSL_VERBOSE("Send WRITE flag %d", client_buff->flags);

	if (client_buff->flags & GSL_BUFF_FLAG_MEDIA_FORMAT) {
		opcode = DATA_CMD_WR_SH_MEM_EP_MEDIA_FORMAT;
		gpr_pld_size = client_buff->size;
	} else if (!dp_info->oob_metadata_flag) {
		gpr_pld_size = sizeof(*write_cmd) + client_buff->metadata_size;
	} else {
		gpr_pld_size = sizeof(*write_cmd);
	}

	rc = gsl_allocate_gpr_packet(opcode, dp_info->src_port, dp_info->miid,
		gpr_pld_size, buff_idx, dp_info->master_proc_id, &send_pkt);
	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto exit;
	}

	if (client_buff->flags & GSL_BUFF_FLAG_MEDIA_FORMAT) {
		media_fmt = GPR_PKT_GET_PAYLOAD(media_format_t, send_pkt);
		gsl_memcpy(media_fmt, client_buff->size, client_buff->addr,
			client_buff->size);
		GSL_PKT_LOG_DATA("wr__data", dp_info->src_port, client_buff->addr,
			client_buff->size);
		GSL_VERBOSE("Send WRITE buffer addr 0x%llX, size %u",
			client_buff->addr, client_buff->size);
	} else {
		write_cmd =
			GPR_PKT_GET_PAYLOAD(data_cmd_wr_sh_mem_ep_data_buffer_v2_t,
				send_pkt);

		tmp = buff->gsl_msg.shmem.spf_addr + offset;
		write_cmd->data_buf_addr_lsw = (uint32_t)tmp;
		write_cmd->data_buf_addr_msw = (uint32_t)(tmp >> 32);
		write_cmd->data_buf_size = size;
		write_cmd->data_mem_map_handle = buff->gsl_msg.shmem.spf_mmap_handle;
		write_cmd->flags = 0;
		if (client_buff->flags & GSL_BUFF_FLAG_TS_VALID) {
			write_cmd->flags |= RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG;
			write_cmd->timestamp_lsw = (uint32_t)client_buff->timestamp;
			write_cmd->timestamp_msw = client_buff->timestamp >> 32;
		} else {
			write_cmd->timestamp_lsw = 0;
			write_cmd->timestamp_msw = 0;
		}

		if (client_buff->flags & GSL_BUFF_FLAG_EOF)
			write_cmd->flags |= WR_SH_MEM_EP_BIT_MASK_EOF_FLAG;
		write_cmd->md_buf_size = 0;
		write_cmd->md_buf_addr_lsw = 0;
		write_cmd->md_buf_addr_msw = 0;
		write_cmd->md_mem_map_handle = 0;

		if (dp_info->oob_metadata_flag && md_buff) {
			/* updata address of oob metadata to gpr packet */
			tmp = md_buff->gsl_msg.shmem.spf_addr;
			write_cmd->md_buf_addr_lsw = (uint32_t)tmp;
			write_cmd->md_buf_addr_msw = (uint32_t)(tmp >> 32);
			write_cmd->md_mem_map_handle =
				md_buff->gsl_msg.shmem.spf_mmap_handle;
		} else if (client_buff->metadata_size) {
			/* copy in-band metadata directly to gpr packet */
			tmp = sizeof(gpr_packet_t) + sizeof(*write_cmd);
			gsl_memcpy((uint8_t *)send_pkt + tmp,
				dp_info->config.max_metadata_size, client_buff->metadata,
				client_buff->metadata_size);
		}
		write_cmd->md_buf_size = client_buff->metadata_size;
		GSL_PKT_LOG_DATA("wr__data", dp_info->src_port, buff->addr,
			buff->size);

		GSL_VERBOSE("Send WRITE to Spf p_addr 0x%llX, size %u",
			tmp, write_cmd->data_buf_size);
	}

	GSL_LOG_PKT("send_pkt", dp_info->src_port, send_pkt, sizeof(*send_pkt) +
		gpr_pld_size, NULL, 0);

	rc = gsl_send_spf_cmd(&send_pkt, NULL, NULL);
	if (rc)
		GSL_ERR("wite shmem failed with %d", rc);

exit:
	return rc;
}

static int32_t gsl_dp_read_shmem(struct gsl_data_path_info *dp_info,
	struct gsl_buff_internal *internal_buf,
	struct gsl_metadata_buff_internal *md_buff, uintptr_t offset,
	uint32_t read_sz, uint32_t buff_idx)
{
	data_cmd_rd_sh_mem_ep_data_buffer_v2_t *read_cmd;
	int32_t rc;
	uint64_t tmp;
	gpr_packet_t *send_pkt = NULL;

	rc = gsl_allocate_gpr_packet(DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,
		dp_info->src_port, dp_info->miid,
		sizeof(*read_cmd), buff_idx, dp_info->master_proc_id, &send_pkt);
	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto exit;
	}
	read_cmd =
		GPR_PKT_GET_PAYLOAD(data_cmd_rd_sh_mem_ep_data_buffer_v2_t, send_pkt);

	tmp = internal_buf->gsl_msg.shmem.spf_addr + offset;
	read_cmd->data_buf_addr_lsw = (uint32_t)tmp;
	read_cmd->data_buf_addr_msw = (uint32_t)(tmp >> 32);
	read_cmd->data_buf_size = read_sz;
	read_cmd->data_mem_map_handle = internal_buf->gsl_msg.shmem.spf_mmap_handle;
	read_cmd->md_buf_addr_lsw = 0;
	read_cmd->md_buf_addr_msw = 0;
	read_cmd->md_mem_map_handle = 0;
	read_cmd->md_buf_size = 0;
	if (dp_info->oob_metadata_flag && md_buff) {
		/* updata address of oob metadata to gpr packet */
		tmp = md_buff->gsl_msg.shmem.spf_addr;
		read_cmd->md_buf_addr_lsw = (uint32_t)tmp;
		read_cmd->md_buf_addr_msw = (uint32_t)(tmp >> 32);
		read_cmd->md_mem_map_handle = md_buff->gsl_msg.shmem.spf_mmap_handle;
		read_cmd->md_buf_size = md_buff->size;
	}

	GSL_VERBOSE("Send READ to Spf p_addr 0x%llX, size %u",
		tmp, read_cmd->data_buf_size);

	GSL_LOG_PKT("send_pkt", dp_info->src_port, send_pkt, sizeof(*send_pkt) +
		sizeof(*read_cmd), NULL, 0);

	rc = gsl_send_spf_cmd(&send_pkt, NULL, NULL);
	if (rc)
		GSL_ERR("failed send spf cmd %d", rc);

exit:
	return rc;
}

static int32_t gsl_dp_read_nonshmem(struct gsl_data_path_info *dp_info,
	uint32_t md_buff_size, uint32_t read_sz, uint32_t buff_idx)
{
	data_cmd_rd_sh_mem_ep_data_buffer_v2_t *read_cmd;
	int32_t rc;
	gsl_msg_t gsl_msg;

	rc = gsl_msg_alloc(DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,
		dp_info->src_port, dp_info->miid,
		sizeof(*read_cmd), buff_idx, dp_info->master_proc_id,
		0, true, &gsl_msg);
	if (rc) {
		GSL_ERR("Failed to allocate GSL msg %d", rc);
		goto exit;
	}

	read_cmd =
		GPR_PKT_GET_PAYLOAD(data_cmd_rd_sh_mem_ep_data_buffer_v2_t,
			gsl_msg.gpr_packet);

	read_cmd->data_buf_size = read_sz;
	read_cmd->md_buf_size = md_buff_size;
	read_cmd->data_mem_map_handle = 0;
	read_cmd->md_mem_map_handle = 0;

	GSL_VERBOSE("Send READ of size %u", read_cmd->data_buf_size);

	GSL_LOG_PKT("send_pkt", dp_info->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*read_cmd), NULL, 0);

	rc = gsl_send_spf_cmd(&gsl_msg.gpr_packet, NULL, NULL);
	if (rc)
		GSL_ERR("failed send spf cmd %d", rc);

exit:
	return rc;
}

static int32_t gsl_dp_write_nonshmem(struct gsl_data_path_info *dp_info,
	struct gsl_buff *buff, uint32_t *consumed_size)
{
	int32_t rc = AR_EOK, retries = 0;
	uint32_t buff_size, write_buff_size, buf_idx, ev_flags = 0;
	uint8_t *buff_addr;
	data_cmd_wr_sh_mem_ep_data_buffer_v2_t *write_cmd;
	uint32_t gpr_pld_size;
	struct gsl_buff_internal *internal_buf = NULL;
	struct gsl_signal *sig_p = &dp_info->dp_signal;

	*consumed_size = 0;
	buff_size = buff->size;
	buff_addr = buff->addr;

	while (buff_size > 0) {
		retries = 0;
		do {
			internal_buf = gsl_find_next_avail_buffer(dp_info,
				&buf_idx);
			if (!internal_buf) {
				if (GSL_DP_DATA_MODE(dp_info) ==
					GSL_DATA_MODE_NON_BLOCKING) {
					/* NON-BLOCKING mode */
					GSL_VERBOSE("No buff available");
					return AR_ENORESOURCE;
				}

				/* BLOCKING mode */
				GSL_VERBOSE("Waiting for buff done");

				rc = gsl_signal_timedwait(sig_p,
					GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
				if (rc) {
					GSL_VERBOSE("Came out of wait with err %d", rc);
					return rc;
				}
				GSL_VERBOSE("Came out of wait flags[0x%x]", ev_flags);
				if (ev_flags & GSL_SIG_EVENT_MASK_CLOSE) {
					rc = AR_EIODATA;
					goto exit;
				} else if (ev_flags & GSL_SIG_EVENT_MASK_SSR) {
					rc = AR_ESUBSYSRESET;
					goto exit;
				}
			}
		} while ((internal_buf == NULL) && (retries++ < GSL_MAX_RETRIES));

		if (!internal_buf) {
			rc = AR_ENOMEMORY;
			goto exit;
		}

		gpr_pld_size = sizeof(*write_cmd);

		if (buff_size > dp_info->config.buff_size)
			write_buff_size = dp_info->config.buff_size;
		else
			write_buff_size = buff_size;

		rc = gsl_msg_alloc(DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2,
			dp_info->src_port, dp_info->miid,
			gpr_pld_size, buf_idx, dp_info->master_proc_id,
			write_buff_size + buff->metadata_size, true,
			&internal_buf->gsl_msg);

		gsl_memcpy(internal_buf->gsl_msg.payload, buff_size, buff_addr,
			write_buff_size);

		if (buff->metadata_size)
			gsl_memcpy((uint8_t *)internal_buf->gsl_msg.payload
				+ write_buff_size,
				dp_info->config.max_metadata_size,
				buff->metadata, buff->metadata_size);

		write_cmd =
			GPR_PKT_GET_PAYLOAD(data_cmd_wr_sh_mem_ep_data_buffer_v2_t,
				internal_buf->gsl_msg.gpr_packet);
		write_cmd->data_buf_size = write_buff_size;
		write_cmd->md_buf_size = buff->metadata_size;
		write_cmd->data_mem_map_handle = 0;
		write_cmd->md_mem_map_handle = 0;
		write_cmd->flags = 0;

		if (buff->flags & GSL_BUFF_FLAG_TS_VALID) {
			write_cmd->flags |= RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG;
			write_cmd->timestamp_lsw = (uint32_t)buff->timestamp;
			write_cmd->timestamp_msw = buff->timestamp >> 32;
		} else {
			write_cmd->timestamp_lsw = 0;
			write_cmd->timestamp_msw = 0;
		}

		rc = gsl_send_spf_cmd(&internal_buf->gsl_msg.gpr_packet, NULL, NULL);
		if (rc != AR_EOK) {
			GSL_VERBOSE("%s fail rc = %d", __func__, rc);
			goto exit;
		}

		*consumed_size += write_buff_size;
		buff_addr += write_buff_size;
		buff_size -= write_buff_size;
	}

	/* send eos if it was marked in the buff */
	if (buff->flags & GSL_BUFF_FLAG_EOS)
		gsl_dp_write_send_eos(dp_info);

exit:
	return rc;
}

static int32_t gsl_dp_write_heap(struct gsl_data_path_info *dp_info,
	struct gsl_buff *buff, uint32_t *consumed_size)
{
	struct gsl_buff_internal *internal_buf = NULL;
	struct gsl_metadata_buff_internal *internal_md_buf = NULL;
	int32_t rc = AR_EOK, retries = 0;
	uint32_t buff_size, write_buff_size, buf_idx, ev_flags = 0;
	uint8_t *buff_addr;
	struct gsl_signal *sig_p = &dp_info->dp_signal;

	*consumed_size = 0;
	buff_size = buff->size;
	buff_addr = buff->addr;
	while (buff_size > 0) {
		retries = 0;
		do {
			internal_buf = gsl_find_next_avail_buffer(dp_info,
				&buf_idx);
			if (!internal_buf) {
				if (GSL_DP_DATA_MODE(dp_info) ==
					GSL_DATA_MODE_NON_BLOCKING) {
					/* NON-BLOCKING mode */
					GSL_ERR("No buff available");
					return AR_ENORESOURCE;
				}

				/* BLOCKING mode */
				GSL_VERBOSE("Waiting for buff done");

				rc = gsl_signal_timedwait(sig_p,
					GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
				if (rc) {
					GSL_ERR("Came out of wait with err %d", rc);
					return rc;
				}
				GSL_VERBOSE("Came out of wait flags[0x%x]", ev_flags);
				if (ev_flags & GSL_SIG_EVENT_MASK_CLOSE) {
					rc = AR_EIODATA;
					goto exit;
				} else if (ev_flags & GSL_SIG_EVENT_MASK_SSR) {
					rc = AR_ESUBSYSRESET;
					goto exit;
				}
			}
		} while ((internal_buf == NULL) && (retries++ < GSL_MAX_RETRIES));

		if (!internal_buf) {
			rc = AR_ENOMEMORY;
			goto exit;
		}

		if (buff_size > dp_info->config.buff_size)
			write_buff_size = dp_info->config.buff_size;
		else
			write_buff_size = buff_size;

		GSL_VERBOSE("Write buf idx %d, bytes: %d", buf_idx, write_buff_size);

		gsl_memcpy(internal_buf->gsl_msg.shmem.v_addr, buff_size, buff_addr,
			write_buff_size);

		/*
		 * Copy the metadata to shared memory, note that for blocking and
		 * non-blocking modes GSL always uses out-of-band metadata. This to
		 * avoid copying the metadata from gpr packet to a temporary storage on
		 * read_done handling
		 */
		if (dp_info->config.max_metadata_size > 0 && buff->metadata) {
			gsl_dequeue_internal_md_buff(dp_info);
			/* enqueue a new metadata buffer to go with the next shmem write */
			internal_md_buf = gsl_enqueue_internal_md_buff(dp_info);
			if (!internal_md_buf) {
				GSL_ERR("failed to enqueue internal md buff");
				rc = AR_ENORESOURCE;
				goto exit;
			}
		}

		rc = gsl_dp_write_shmem(dp_info, internal_buf, internal_md_buf, 0,
			buf_idx, write_buff_size, buff);
		if (rc != AR_EOK) {
			GSL_VERBOSE("gsl_dp_write_shmem fail rc=%d", rc);
			goto exit;
		}

		*consumed_size += write_buff_size;
		buff_addr += write_buff_size;
		buff_size -= write_buff_size;
	}

	/* send eos if it was marked in the buff */
	if (buff->flags & GSL_BUFF_FLAG_EOS)
		gsl_dp_write_send_eos(dp_info);

exit:
	return rc;
}

/*
 * data_buff_addr: this points to a location within the client passed
 * buff that we copy the data into. Needed to sequentially write into
 * client buffer as this function can be called multiple times per
 * client buffer.
 * client_buff: this is client created object that we copy metadata
 * and flags into.
 */
static void gsl_dp_fill_client_buff(struct gsl_data_path_info *dp_info,
	struct gsl_buff_internal *internal_buf,
	struct gsl_metadata_buff_internal *md_buf,
	uint8_t *data_buff_addr, uint32_t *buff_size,
	bool_t *captured_timestamp, struct gsl_buff *client_buff)
{
	gpr_packet_t *packet = NULL;
	uint8_t *payload = NULL;

	if (!dp_info->is_shmem_supported) {
		data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t *rd_done;

		packet = (gpr_packet_t *)internal_buf->gsl_msg.payload;
		rd_done = (data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t *)
			GPR_PKT_GET_PAYLOAD(
				data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t,
				packet);
		payload = (uint8_t *)rd_done +
			sizeof(data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t);
		*buff_size = rd_done->data_size;
		gsl_memcpy(data_buff_addr, *buff_size, payload, *buff_size);

		if (rd_done->md_size != 0) {
			client_buff->metadata_size = rd_done->md_size;
			gsl_memcpy(client_buff->metadata,
				client_buff->metadata_size,
				payload + rd_done->data_size,
				client_buff->metadata_size);
		}

		internal_buf->spf_timestamp =
			((uint64_t)rd_done->timestamp_msw << 32) |
			rd_done->timestamp_lsw;
		internal_buf->spf_flags = rd_done->flags;
		__gpr_cmd_free(packet);
	} else {
		/*
		 * @TODO: Assumption that spf always returns buffer of size <=
		 * requested size by client. Check if that's correct
		 */
		*buff_size = internal_buf->size_from_spf;

		gsl_memcpy(data_buff_addr, *buff_size,
			internal_buf->gsl_msg.shmem.v_addr, *buff_size);

		if (md_buf != NULL) {
			gsl_memcpy(client_buff->metadata, client_buff->metadata_size,
				md_buf->gsl_msg.shmem.v_addr,
				md_buf->md_size_from_spf);
			client_buff->metadata_size = md_buf->md_size_from_spf;
		}
	}

	/*
	 * update time-stamp to client, in-case we have already put a timestamp
	 * in clients shmem_buff we dont update it again as we want to keep the
	 * timestamp of very first buffer returned from spf.
	 */
	if (!(*captured_timestamp)) {
		client_buff->flags = 0;
		if (internal_buf->spf_flags &
			RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG) {
			client_buff->flags |= GSL_BUFF_FLAG_TS_VALID;
			client_buff->timestamp = internal_buf->spf_timestamp;
		}
		*captured_timestamp = true;
	}
}

static int32_t gsl_dp_read_heap(struct gsl_data_path_info *dp_info,
	struct gsl_buff *buff, uint32_t *filled_size)
{
	struct gsl_buff_internal *internal_buf = NULL;
	struct gsl_metadata_buff_internal *internal_md_buf = NULL;
	int32_t rc = AR_EOK, retries = 0;
	uint32_t buff_size, read_buff_size, buf_idx, ev_flags = 0;
	uint8_t *buff_addr;
	struct gsl_signal *sig_p =
		&dp_info->dp_signal;
	bool_t captured_timestamp = false;

	*filled_size = 0;
	buff_size = buff->size;
	buff_addr = buff->addr;
	if (buff_size < dp_info->config.buff_size)
		GSL_ERR("Client read size less than configured buff size, %u < %u",
			buff_size, dp_info->config.buff_size);
	/*
	 * below while is to handle the case where client tries to read more than
	 * one buffer size
	 */
	while (buff_size >= dp_info->config.buff_size) {
		retries = 0;
		do {
			/*
			 * in the context of read, buffer avail means the buffer is filled
			 * with data
			 */
			internal_buf = gsl_find_next_avail_buffer(dp_info,
				&buf_idx);
			if (!internal_buf) {
				if (GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_NON_BLOCKING) {
					/* NON-BLOCKING mode */
					GSL_VERBOSE("No buff available");
					return AR_ENORESOURCE;
				}

				/** BLOCKING mode */
				GSL_VERBOSE("Waiting for buff done");
				rc = gsl_signal_timedwait(sig_p,
					GSL_SPF_READ_WRITE_TIMEOUT_MS, &ev_flags, NULL, NULL);
				if (rc) {
					GSL_VERBOSE("Came out of wait with err %d", rc);
					return rc;
				}
				GSL_VERBOSE("Came out of wait flags[0x%x]", ev_flags);
				if (ev_flags & GSL_SIG_EVENT_MASK_CLOSE) {
					rc = AR_EIODATA;
					goto exit;
				} else if (ev_flags & GSL_SIG_EVENT_MASK_SSR) {
					rc = AR_ESUBSYSRESET;
					goto exit;
				}
			}
		} while ((internal_buf == NULL) && (retries++ < GSL_MAX_RETRIES));

		if (!internal_buf) {
			rc = AR_ENOMEMORY;
			goto exit;
		}

		if (dp_info->config.max_metadata_size > 0 && buff->metadata) {
			internal_md_buf = gsl_dequeue_internal_md_buff(dp_info);
			if (!internal_md_buf) {
				GSL_ERR("failed to dequeue internal md buff");
				rc = AR_ENORESOURCE;
			}
		}

		gsl_dp_fill_client_buff(dp_info, internal_buf, internal_md_buf,
			buff_addr, &read_buff_size,
			&captured_timestamp, buff);

		GSL_PKT_LOG_DATA("rd__data", dp_info->src_port,
			buff_addr, read_buff_size);

		/* queue the buffer back to spf */
		if (!dp_info->is_shmem_supported) {
			rc = gsl_dp_read_nonshmem(dp_info, buff->metadata_size,
				dp_info->config.buff_size, buf_idx);
			if (rc != AR_EOK)
				goto exit;
		} else {
			if (dp_info->config.max_metadata_size > 0 &&
				buff->metadata) {
				if (buff->metadata_size == 0) {
					GSL_ERR("got 0 md size from spf");
					rc = AR_EFAILED;
				}

				/* enqueue a new metadata buffer to go with the next
				 * shmem read
				 */
				internal_md_buf = gsl_enqueue_internal_md_buff(dp_info);
				if (!internal_md_buf) {
					GSL_ERR("failed to enqueue internal md buff");
					rc = AR_ENORESOURCE;
				} else {
					internal_md_buf->size = buff->metadata_size;
				}
			}

			/* queue the shmem buffer back to spf */
			rc = gsl_dp_read_shmem(dp_info, internal_buf, internal_md_buf, 0,
				dp_info->config.buff_size, buf_idx);
			if (rc != AR_EOK)
				goto exit;
		}

		*filled_size += read_buff_size;
		buff_addr += read_buff_size;
		buff_size -= read_buff_size;
	}
exit:
	return rc;
}

static int32_t gsl_dp_write_extern_mem(struct gsl_data_path_info *dp_info,
	struct gsl_buff *buff)
{
	struct gsl_buff_internal internal_buf = { 0, };
	struct gsl_metadata_buff_internal *internal_md_buf = NULL;

	int32_t rc = AR_EOK;
	uint32_t cache_idx = 0;

	/* This will find or map buffer in cache. Fails when cache full */
	rc = ext_mem_cache_get_entry(dp_info->master_proc_id, buff->alloc_info,
		&internal_buf.gsl_msg.shmem, &cache_idx);
	if (rc != AR_EOK)
		return rc;

	ext_mem_cache_update_entry_last_used(cache_idx);

	if (dp_info->config.max_metadata_size > 0) {
		/* enqueue a new metadata buffer */
		internal_md_buf = gsl_enqueue_internal_md_buff(dp_info);
		if (!internal_md_buf) {
			GSL_ERR("failed to enqueue internal md buff");
			rc = AR_ENORESOURCE;
			goto exit;
		}

		if (dp_info->oob_metadata_flag) {
			internal_md_buf->size = buff->metadata_size;
			gsl_memcpy(internal_md_buf->gsl_msg.shmem.v_addr,
				internal_md_buf->size, buff->metadata, buff->metadata_size);
		}
	}

	rc = gsl_dp_write_shmem(dp_info, &internal_buf,	internal_md_buf,
		buff->alloc_info.offset, cache_idx, buff->size, buff);
	if (rc != AR_EOK) {
		GSL_VERBOSE("gsl_dp_write_shmem fail rc=%d", rc);
		goto exit;
	}

	/* send eos if it was marked in the buff */
	if (buff->flags & GSL_BUFF_FLAG_EOS)
		gsl_dp_write_send_eos(dp_info);
exit:
	return rc;
}

static int32_t gsl_dp_read_extern_mem(struct gsl_data_path_info *dp_info,
	struct gsl_buff *buff)
{
	struct gsl_buff_internal internal_buf = { 0, };
	struct gsl_metadata_buff_internal *internal_md_buf = NULL;

	int32_t rc = AR_EOK;
	uint32_t cache_idx;

	/* This will find or map buffer in cache. Fails when cache full */
	rc = ext_mem_cache_get_entry(dp_info->master_proc_id, buff->alloc_info,
		&internal_buf.gsl_msg.shmem, &cache_idx);
	if (rc != AR_EOK)
		return rc;

	ext_mem_cache_update_entry_last_used(cache_idx);
	if (dp_info->config.max_metadata_size > 0) {
		/* enqueue a new metadata buffer */
		internal_md_buf = gsl_enqueue_internal_md_buff(dp_info);
		if (!internal_md_buf) {
			GSL_ERR("failed to enqueue internal md buff");
			rc = AR_ENORESOURCE;
			goto exit;
		}

		internal_md_buf->size = buff->metadata_size;
		internal_md_buf->client_md_ptr = buff->metadata;
	}

	rc = gsl_dp_read_shmem(dp_info, &internal_buf, internal_md_buf,
		buff->alloc_info.offset, buff->size, cache_idx);
	if (rc != AR_EOK) {
		GSL_VERBOSE("gsl_dp_read_shmem fail rc=%d", rc);
		goto exit;
	}

exit:
	return rc;
}

/* we need to create the refcount lock at GSL init time*/
int32_t gsl_dp_create_cache_refcount_lock(void)
{
	int32_t rc = AR_EOK;

	rc = ar_osal_mutex_create(&ext_mem_cache.num_dps_lock);
	if (rc)
		GSL_ERR("failed to create mutex: %d", rc);

	return rc;
}

/* similarly, can only be destroyed at GSL deinit time*/
void gsl_dp_destroy_cache_refcount_lock(void)
{
	ar_osal_mutex_destroy(ext_mem_cache.num_dps_lock);
}

/* This should be called only once. Check if lock exists. */
int32_t gsl_data_path_init(struct gsl_data_path_info *dp_info)
{
	int32_t rc = AR_EOK;

	rc = ar_osal_mutex_create(&dp_info->lock);
	if (rc) {
		GSL_ERR("failed to create mutex: %d", rc);
		goto exit;
	}
	/*
	 * use dp lock for this signal
	 * Could split to more locks later if necessary
	 */
	rc = gsl_signal_create(&dp_info->dp_signal, &dp_info->lock);
	if (rc) {
		GSL_ERR("failed to create mutex: %d", rc);
		goto cleanup;
	}

	return rc;

cleanup:
	ar_osal_mutex_destroy(dp_info->lock);
exit:
	return rc;
}

void gsl_data_path_deinit(struct gsl_data_path_info *dp_info)
{
	uint32_t i = 0;
	struct gsl_metadata_buff_internal *internal_md_buff;

	/* decrement refcount in cache if extern mem */
	if (GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_EXTERN_MEM)
		ext_mem_cache_deinit();

	/* free data buffers, num_buffs will be 0 if data path not configured */
	for (i = 0; i < dp_info->config.num_buffs; ++i)
		gsl_msg_free(&dp_info->buff_list[i].gsl_msg);

	/* free all oob metadata buffers */
	if (dp_info->config.max_metadata_size > 0) {
		for (i = 0; i < dp_info->md_buff_list_size; ++i) {
			internal_md_buff = &dp_info->md_buff_list[i];
			if (internal_md_buff->gsl_msg.shmem.v_addr)
				gsl_shmem_free(&internal_md_buff->gsl_msg.shmem);
		}
	}

	if (dp_info->buff_list) {
		gsl_mem_free(dp_info->buff_list);
		dp_info->buff_list = NULL;
	}
	if (dp_info->md_buff_list) {
		gsl_mem_free(dp_info->md_buff_list);
		dp_info->md_buff_list_size = 0;
		dp_info->md_buff_list = NULL;
	}

	gsl_signal_destroy(&dp_info->dp_signal);
	ar_osal_mutex_destroy(dp_info->lock);
}

int32_t gsl_dp_config_data_path(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg, uint32_t src_port,
	struct gsl_signal *push_pull_cfg_signal, enum gsl_data_dir dir,
	ar_osal_mutex_t lock, uint32_t proc_id)
{
	/*
	 * Push pull config requires us to send a SET_CFG to SPF. This is
	 * done with the GRP_2 signal from graph. We pass this in here specifically
	 * for use configuring push pull mode.
	 *
	 * Similarly, dir is only used when configuring push pull mode, to set
	 * flags on allocated shmem buffers differently in read/write mode.
	 */

	int32_t rc = AR_EOK;
	struct gpr_cmd_gpr_packet_pool_info_t gpr_pkt_info;
	uint32_t max_rw_cmd_sz;

	if (!dp_info || !cfg)
		return AR_EBADPARAM;

	/* Need to no-op in provision only with non-push pull mode, alrdy set up*/
	if (GSL_DATAPATH_SETUP_MODE(cfg) == GSL_DATAPATH_SETUP_SPF_PROVISION_ONLY
		&& GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_PUSH_PULL)
		return AR_EOK;

	/* this will no-op if already inited */
	if (!dp_info->lock) {
		rc = gsl_data_path_init(dp_info);
		if (rc)
			return rc;
	}

	dp_info->src_port = src_port;  //needed for sending packets
	dp_info->master_proc_id = proc_id;

	GSL_MUTEX_LOCK(lock);
	dp_info->src_port = src_port;

	/*
	 * Used to determine whether or not metadata will be in-band or out-of-band
	 */
	gsl_memset(&gpr_pkt_info, 0, sizeof(gpr_pkt_info));
	rc = __gpr_cmd_get_gpr_packet_info(&gpr_pkt_info);
	max_rw_cmd_sz = sizeof(gpr_packet_t) +
		sizeof(data_cmd_rd_sh_mem_ep_data_buffer_v2_t) + cfg->max_metadata_size;
	if (rc) {
		GSL_ERR("failed to get gpr packet info rc = %d", rc);
		goto exit;
	}

	dp_info->oob_metadata_flag = false;

	/* Check if proc supports shared memory */
	__gpr_cmd_is_shared_mem_supported(dp_info->master_proc_id,
		&dp_info->is_shmem_supported);

	switch (cfg->attributes & GSL_ATTRIBUTES_DATA_MODE_MASK) {
	case GSL_DATA_MODE_PUSH_PULL:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		rc = gsl_dp_config_push_pull_mode(dp_info, cfg,
			push_pull_cfg_signal, dir);
		if (rc)
			goto exit;
		/* nothing more to set up if provision only */
		if (GSL_DATAPATH_SETUP_MODE(cfg)
			== GSL_DATAPATH_SETUP_SPF_PROVISION_ONLY)
			goto exit;
		/* push/pull mode doesnt support meta data */
		break;
	case GSL_DATA_MODE_EXTERN_MEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		rc = gsl_dp_config_extern_mem_mode(dp_info, cfg);
		if (rc)
			goto exit;
		if (max_rw_cmd_sz > gpr_pkt_info.bytes_per_min_size_packet)
			dp_info->oob_metadata_flag = true;
		break;
	case GSL_DATA_MODE_BLOCKING:
	case GSL_DATA_MODE_NON_BLOCKING:
		if (!dp_info->is_shmem_supported) {
			rc = gsl_dp_config_nonshmem(dp_info, cfg);
			if (rc)
				goto exit;
			dp_info->oob_metadata_flag = false;
			break;
		}

		/* for blocking/non-blocking modes always use oob metadata */
		if (cfg->max_metadata_size > 0)
			dp_info->oob_metadata_flag = true;
	case GSL_DATA_MODE_SHMEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		rc = gsl_dp_config_common_modes(dp_info, cfg);
		if (rc)
			goto exit;
		if (max_rw_cmd_sz > gpr_pkt_info.bytes_per_min_size_packet)
			dp_info->oob_metadata_flag = true;
		break;

	default:
		GSL_ERR("invalid data mode %d", GSL_DP_DATA_MODE(dp_info));
		rc = AR_EBADPARAM;
		goto exit;
	}

	/** mark all buffers available for use */
	dp_info->buff_used_status = 0;
	dp_info->curr_buff_index = 0; /**< start with buf 0 */
	dp_info->processed_buf_cnt = 0;
	dp_info->md_buff_list_head = 0;
	dp_info->md_buff_list_tail = 0;

	GSL_MUTEX_UNLOCK(lock);

	return rc;

exit:
	GSL_MUTEX_UNLOCK(lock);
	return rc;
}

int32_t gsl_dp_read(struct gsl_data_path_info *dp_info, struct gsl_buff *buff,
	uint32_t *filled_size)
{
	uint32_t rc = AR_EOK, buff_idx;
	struct gsl_buff_internal *internal_buff;
	struct gsl_metadata_buff_internal *internal_md_buff = NULL;
	uintptr_t offset;

	switch (GSL_DP_DATA_MODE(dp_info)) {
	case GSL_DATA_MODE_SHMEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		internal_buff = gsl_dp_find_buff_from_va(dp_info, buff->addr, &offset,
			&buff_idx);
		if (internal_buff == NULL) {
			rc = AR_EHANDLE;
			goto exit;
		}
		if (dp_info->config.max_metadata_size > 0) {
			internal_md_buff = gsl_enqueue_internal_md_buff(dp_info);
			if (!internal_md_buff) {
				GSL_ERR("failed to create shmem for metadata");
				rc = AR_ENORESOURCE;
				goto exit;
			}
			internal_md_buff->client_md_ptr = buff->metadata;
			internal_md_buff->size = buff->metadata_size;
		}
		rc = gsl_dp_read_shmem(dp_info, internal_buff, internal_md_buff,
			offset, buff->size, buff_idx);
		/*
		 * in shared memory mode the read is returned immediately and no data
		 * is filled till we get buff done
		 */
		*filled_size = 0;
		break;
	case GSL_DATA_MODE_EXTERN_MEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		rc = gsl_dp_read_extern_mem(dp_info, buff);
		break;
	case GSL_DATA_MODE_BLOCKING:
	case GSL_DATA_MODE_NON_BLOCKING:
		rc = gsl_dp_read_heap(dp_info, buff, filled_size);
		break;
	default:
		GSL_ERR("unsupported read mode 0x%X",
			GSL_DP_DATA_MODE(dp_info));
		rc = AR_EUNSUPPORTED;
	}

exit:
	return rc;
}

int32_t gsl_dp_write(struct gsl_data_path_info *dp_info, struct gsl_buff *buff,
	uint32_t *consumed_size)
{
	uint32_t rc = AR_EOK, buff_idx;
	struct gsl_buff_internal *internal_buff;
	struct gsl_metadata_buff_internal *internal_md_buff = NULL;
	uintptr_t offset;

	switch (GSL_DP_DATA_MODE(dp_info)) {
	case GSL_DATA_MODE_SHMEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		internal_buff = gsl_dp_find_buff_from_va(dp_info,
			buff->addr, &offset, &buff_idx);
		if (internal_buff == NULL) {
			rc = AR_EHANDLE;
			goto exit;
		}
		if (dp_info->config.max_metadata_size > 0) {
			internal_md_buff = gsl_enqueue_internal_md_buff(dp_info);
			if (!internal_md_buff) {
				GSL_ERR("failed to enqueue metadata");
				rc = AR_ENORESOURCE;
				goto exit;
			}

			if (internal_md_buff && dp_info->oob_metadata_flag) {
				gsl_memcpy(internal_md_buff->gsl_msg.shmem.v_addr,
					buff->metadata_size, buff->metadata, buff->metadata_size);
			}
		}
		rc = gsl_dp_write_shmem(dp_info, internal_buff, internal_md_buff,
			offset, buff_idx, buff->size, buff);
		*consumed_size = buff->size;

		if (buff->flags & GSL_BUFF_FLAG_EOS)
			gsl_dp_write_send_eos(dp_info);

		break;
	case GSL_DATA_MODE_EXTERN_MEM:
		if (!dp_info->is_shmem_supported) {
			rc = AR_EUNSUPPORTED;
			goto exit;
		}

		rc = gsl_dp_write_extern_mem(dp_info, buff);
		*consumed_size = buff->size;

		break;
	case GSL_DATA_MODE_BLOCKING:
	case GSL_DATA_MODE_NON_BLOCKING:
		if (!dp_info->is_shmem_supported) {
			rc = gsl_dp_write_nonshmem(dp_info, buff,
				consumed_size);
		} else {
			rc = gsl_dp_write_heap(dp_info, buff, consumed_size);
		}
		break;
	default:
		GSL_ERR("unsupported write mode 0x%X",
			GSL_DP_DATA_MODE(dp_info));
		rc = AR_EUNSUPPORTED;
	}

exit:
	return rc;
}

int32_t gsl_dp_write_send_eos(struct gsl_data_path_info *dp_info)
{
	data_cmd_wr_sh_mem_ep_eos_t *eos_cmd;
	int32_t rc;
	gsl_msg_t gsl_msg;

	rc = gsl_msg_alloc(DATA_CMD_WR_SH_MEM_EP_EOS, dp_info->src_port,
		dp_info->miid, sizeof(*eos_cmd), 0,
		dp_info->master_proc_id, 0, true, &gsl_msg);

	if (rc) {
		GSL_ERR("Failed to allocate GPR packet %d", rc);
		goto exit;
	}
	eos_cmd =
		GPR_PKT_GET_PAYLOAD(struct data_cmd_wr_sh_mem_ep_eos_t,
			gsl_msg.gpr_packet);
	eos_cmd->policy = WR_SH_MEM_EP_EOS_POLICY_LAST;

	GSL_VERBOSE("Send EOS to Spf dst miid=%d", dp_info->miid);

	GSL_LOG_PKT("send_pkt", dp_info->src_port, gsl_msg.gpr_packet,
		sizeof(*gsl_msg.gpr_packet) + sizeof(*eos_cmd), NULL, 0);
	rc = gsl_send_spf_cmd(&gsl_msg.gpr_packet, NULL, NULL);
	if (rc)
		GSL_ERR("failed to send EOS err %d", rc);

exit:
	return rc;
}

int32_t gsl_handle_read_buff_done(struct gsl_data_path_info *dp_info,
	gpr_packet_t *packet, gsl_cb_func_ptr cb, void *client_data)
{
	data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t *rd_done;
	uint32_t buff_idx;
	struct gsl_buff_internal *gsl_buff = NULL;
	struct gsl_buff_internal tmp = { 0 };
	int32_t status;
	struct gsl_metadata_buff_internal *gsl_md_buff;
	/* used to pass to client in callback */
	struct gsl_event_read_write_done_payload rw_done_payload = { 0 };
	uint64_t pa;
	uint8_t  *spf_metadata = NULL;
	int32_t rc = AR_EOK;

	REMOVE_DEBUG_TOKEN(packet->token);
	buff_idx = packet->token;

	/* token is used differently for external mem */
	if (GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_EXTERN_MEM) {
		if (buff_idx > GSL_MAX_NUM_DATA_BUFFERS) {
			GSL_VERBOSE("Buff_idx %d returned as token is invalid", buff_idx);
			rc = AR_EBADPARAM;
			goto free_pkt;
		}

		if (dp_info->is_shmem_supported)
			gsl_buff = &dp_info->buff_list[buff_idx];
	} else {
		/* hacky. Allocate on stack since ext mem mode has no buff list */
		gsl_buff = &tmp;
	}

	rd_done = GPR_PKT_GET_PAYLOAD(
		data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t, packet);
	status = rd_done->data_status;
	pa = GSL_TO_64_BIT(rd_done->data_buf_addr_msw, rd_done->data_buf_addr_lsw);

	/*
	 * In cases of non shmem usecase, gsl_handle_buff_done_nonshmem
	 * frees gpr packet after copying the data to client buffer.
	 */
	if (!dp_info->is_shmem_supported) {
		/* packet is freed in nonshmem after fill_client_buff */
		rc = gsl_handle_buff_done_nonshmem(dp_info,
			packet, GSL_EVENT_ID_READ_DONE, cb, client_data, status, buff_idx);
		goto exit;
	} else {
		gsl_buff->size_from_spf = rd_done->data_size;
		gsl_buff->spf_timestamp =
			((uint64_t)rd_done->timestamp_msw << 32) | rd_done->timestamp_lsw;
		gsl_buff->spf_flags = rd_done->flags;

		/* below needed to pass data back to client in shmem mode */
		rw_done_payload.buff.flags = 0;
		rw_done_payload.buff.timestamp = 0;
		if (gsl_buff->spf_flags & RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG) {
			rw_done_payload.buff.timestamp = gsl_buff->spf_timestamp;
			rw_done_payload.buff.flags |= GSL_BUFF_FLAG_TS_VALID;
		}
		GSL_VERBOSE("Read_Done buf idx %d, size_from_spf %d", packet->token,
			gsl_buff->size_from_spf);

		if ((GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_SHMEM ||
			GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_EXTERN_MEM) &&
			dp_info->config.max_metadata_size > 0) {

			gsl_md_buff = gsl_dequeue_internal_md_buff(dp_info);
			if (gsl_md_buff) {
				if (dp_info->oob_metadata_flag)
					spf_metadata = gsl_md_buff->gsl_msg.shmem.v_addr;
				else
					spf_metadata = (uint8_t *)rd_done +
					sizeof(data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t);
				if (gsl_memcpy(gsl_md_buff->client_md_ptr, gsl_md_buff->size,
					spf_metadata, rd_done->md_size)) {
					/* if copy failed return ENEEDMORE to client */
					gsl_md_buff->md_size_from_spf = rd_done->md_size;
					gsl_md_buff->md_status_from_spf = AR_ENEEDMORE;
				} else {
					gsl_md_buff->md_size_from_spf = rd_done->md_size;
					gsl_md_buff->md_status_from_spf = rd_done->md_status;
				}
			} else {
				GSL_ERR("failed to dequeue internal md buff. No md returned");
			}

			gsl_handle_buff_done_shmem(dp_info, cb, &rw_done_payload, buff_idx,
				pa, status, gsl_buff, GSL_EVENT_ID_READ_DONE, client_data,
				gsl_md_buff, 0);

		} else {
			if (dp_info->config.max_metadata_size > 0)
				gsl_store_md_status_from_spf(dp_info, rd_done->md_size,
					rd_done->md_status);
			gsl_handle_buff_done_shmem(dp_info, cb, &rw_done_payload, buff_idx,
				pa, status, gsl_buff, GSL_EVENT_ID_READ_DONE, client_data,
				NULL, 0);
		}

	}
free_pkt:
	__gpr_cmd_free(packet);
exit:
	return rc;
}

int32_t gsl_handle_media_format_buff_done(struct gsl_data_path_info *dp_info,
	gpr_packet_t *packet)
{
	uint32_t buff_idx;
	int32_t status = AR_EOK;

	REMOVE_DEBUG_TOKEN(packet->token);
	buff_idx = packet->token;
	gsl_mark_buffer_as_avail(dp_info, buff_idx);
	gsl_signal_set(&dp_info->dp_signal, GSL_SIG_EVENT_MASK_SPF_RSP, status,
		NULL);
	GSL_VERBOSE("Media_format_buff Write_Done buf idx %d", packet->token);
	__gpr_cmd_free(packet);
	return AR_EOK;
}

int32_t gsl_handle_write_buff_done(struct gsl_data_path_info *dp_info,
	gpr_packet_t *packet, gsl_cb_func_ptr cb, void *client_data)
{
	data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_v2_t *wr_done;
	uint32_t buff_idx;
	struct gsl_buff_internal *gsl_buff = NULL;
	struct gsl_buff_internal tmp = { 0 };
	int32_t status;
	/* used to pass to client in callback */
	struct gsl_event_read_write_done_payload rw_done_payload = { 0 };
	uint64_t pa;

	REMOVE_DEBUG_TOKEN(packet->token);
	buff_idx = packet->token;

	/* token is used differently for external mem */
	if (GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_EXTERN_MEM) {
		if (buff_idx > GSL_MAX_NUM_DATA_BUFFERS) {
			GSL_VERBOSE("Buff_idx %d returned as token is invalid", buff_idx);
			return AR_EBADPARAM;
		}

		if (dp_info->is_shmem_supported)
			gsl_buff = &dp_info->buff_list[buff_idx];
	} else {
		/* hacky. Allocate on stack since ext mem mode has no buff list */
		gsl_buff = &tmp;
	}

	wr_done = GPR_PKT_GET_PAYLOAD(
		data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_v2_t, packet);
	status = wr_done->data_status;
	pa = GSL_TO_64_BIT(wr_done->data_buf_addr_msw, wr_done->data_buf_addr_lsw);

	if (!dp_info->is_shmem_supported)
		return gsl_handle_buff_done_nonshmem(dp_info, packet,
			GSL_EVENT_ID_WRITE_DONE, cb, client_data, status, buff_idx);

	gsl_buff->size_from_spf = 0;
	GSL_VERBOSE("Write_Done buf idx %d", packet->token);

	gsl_handle_buff_done_shmem(dp_info, cb, &rw_done_payload, buff_idx, pa,
		status, gsl_buff, GSL_EVENT_ID_WRITE_DONE, client_data, NULL,
		wr_done->md_status);

	if ((GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_SHMEM ||
		GSL_DP_DATA_MODE(dp_info) == GSL_DATA_MODE_EXTERN_MEM) &&
		dp_info->config.max_metadata_size > 0) {
		/* free oldest metadata shmem buffer if any */
		if (dp_info->config.max_metadata_size > 0)
			gsl_dequeue_internal_md_buff(dp_info);
	}
	return AR_EOK;
}

int32_t gsl_dp_get_buff_info(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_get_shmem_buf_info *cfg)
{
	uint32_t i = 0, num_dp_buffs;

	if (!dp_info || !cfg)
		return AR_EBADPARAM;

	if ((dp_info->config.attributes & GSL_ATTRIBUTES_DATA_MODE_MASK) ==
		GSL_DATA_MODE_PUSH_PULL)
		/* Do not expose the push pull position buffer */
		num_dp_buffs = 1;
	else
		num_dp_buffs = dp_info->config.num_buffs;

	if (cfg->num_buffs >= num_dp_buffs) {
		for (i = 0; i < num_dp_buffs; ++i) {
			cfg->buffs[i].addr =
				dp_info->buff_list[i].gsl_msg.shmem.v_addr;
			cfg->buffs[i].metadata =
				dp_info->buff_list[i].gsl_msg.shmem.metadata;
		}
	}
	cfg->size = dp_info->config.buff_size;
	cfg->num_buffs = num_dp_buffs;

	return AR_EOK;
}

int32_t gsl_dp_get_pos_buff_info(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_get_shmem_buf_info *cfg)
{
	if (!dp_info || !cfg)
		return AR_EBADPARAM;

	if (GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_PUSH_PULL)
		return AR_EUNSUPPORTED;

	if (cfg->num_buffs >= 1) {
		/*
		 * note in push_pull mode first internal buffer is data and next
		 * internal buffer is position buffer ALWAYS
		 */
		cfg->buffs[0].addr = dp_info->buff_list[1].gsl_msg.shmem.v_addr;
		cfg->buffs[0].metadata = dp_info->buff_list[1].gsl_msg.shmem.metadata;
	}
	cfg->size = sizeof(struct sh_mem_pull_push_mode_position_buffer_t);
	cfg->num_buffs = 1;

	return AR_EOK;
}

uint32_t gsl_dp_get_processed_buff_cnt(struct gsl_data_path_info *dp_info)
{
	return dp_info->processed_buf_cnt;
}

uint32_t gsl_dp_get_avail_buffer_size(struct gsl_data_path_info *dp_info)
{
	uint32_t buff_used_status = 0;
	uint32_t available_buff_cnt = 0;
	uint32_t available_bytes = 0;

	if (!dp_info)
		return AR_EBADPARAM;

	GSL_MUTEX_LOCK(dp_info->lock);
	available_buff_cnt = dp_info->config.num_buffs;
	buff_used_status = dp_info->buff_used_status;
	for (int i = 0; i < dp_info->config.num_buffs && buff_used_status != 0; i++) {
		if (buff_used_status % 2 == 1)
			available_buff_cnt--;
		buff_used_status >>= 1;
	}

	available_bytes = available_buff_cnt * dp_info->config.buff_size;
	GSL_MUTEX_UNLOCK(dp_info->lock);

	return available_bytes;
}

static void gsl_clear_internal_buf(struct gsl_data_path_info *dp_info)
{
	uint32_t i = 0;
	uint32_t buf_idx = 0;
	struct gsl_buff_internal *internal_buf = NULL;
	gpr_packet_t *packet = NULL;

	if (dp_info->is_shmem_supported)
		return;
	/*
	 * This is to handle the scenario where the packets received at the GSL
	 * client is not freed, due to reasons like state change in client,
	 * there by eating up GPR datalink buffers.
	 */
	for (i = 0; i < dp_info->config.num_buffs; i++) {
		internal_buf = gsl_find_next_avail_buffer(dp_info, &buf_idx);

		if (!internal_buf)
			break;

		packet = (gpr_packet_t *)internal_buf->gsl_msg.payload;
		__gpr_cmd_free(packet);
		GSL_MUTEX_LOCK(dp_info->lock);
		clear_bit(dp_info->buff_used_status, buf_idx);
		GSL_MUTEX_UNLOCK(dp_info->lock);
	}
}

int32_t gsl_wait_for_all_buffs_to_be_avail(struct gsl_data_path_info *dp_info)
{
	int32_t rc = AR_EOK, local_buff_used_status;
	uint32_t wait_flags = 0;

	GSL_MUTEX_LOCK(dp_info->lock);
	local_buff_used_status = dp_info->buff_used_status;
	GSL_MUTEX_UNLOCK(dp_info->lock);

	while (local_buff_used_status != 0) {
		/*
		 * if a buffer came back after we release mutex and before we call
		 * below wait the signal status would be set and below wait will exit
		 * immediately. For SSR we only get this signal once, so bail.
		 */
		rc = gsl_signal_timedwait(&dp_info->dp_signal,
			GSL_SPF_READ_WRITE_TIMEOUT_MS, &wait_flags, NULL, NULL);
		if (rc != AR_EOK || wait_flags & GSL_SIG_EVENT_MASK_SSR)
			break;

		GSL_MUTEX_LOCK(dp_info->lock);
		local_buff_used_status = dp_info->buff_used_status;
		GSL_MUTEX_UNLOCK(dp_info->lock);
	}

	/* clear any metadata buffs */
	gsl_clear_internal_md_buff(dp_info);
	/* clear any internal buffs */
	gsl_clear_internal_buf(dp_info);

	return rc;
}

int32_t gsl_dp_queue_read_buffers_to_spf(struct gsl_data_path_info *dp_info)
{
	uint32_t rc = AR_EOK, i, j;
	struct gsl_buff_internal *internal_buff = NULL;
	struct gsl_metadata_buff_internal *internal_md_buf = NULL;
	/*
	 * In-case of first read in blocking or non-blocking heap mode, push
	 * all buffers to spf
	 */
	if (GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_SHMEM &&
		GSL_DP_DATA_MODE(dp_info) != GSL_DATA_MODE_PUSH_PULL) {
		for (j = 0; j < dp_info->config.num_buffs; ++j) {
			internal_buff = gsl_find_next_avail_buffer(dp_info, &i);
			if (internal_buff) {
				if (!dp_info->is_shmem_supported) {
					gsl_dp_read_nonshmem(dp_info,
						dp_info->config.max_metadata_size,
						dp_info->config.buff_size, i);
					continue;
				}

				if (dp_info->config.max_metadata_size > 0) {
					/*
					 * blocking and non-blocking modes always use oob
					 * metadata if any
					 */
					internal_md_buf = gsl_enqueue_internal_md_buff(dp_info);
					if (!internal_md_buf) {
						GSL_ERR("failed to enqueue internal md buff");
						rc = AR_ENORESOURCE;
					} else {
						internal_md_buf->size =
							dp_info->config.max_metadata_size;
					}
				}

				gsl_dp_read_shmem(dp_info, internal_buff,
					internal_md_buf, 0,	dp_info->config.buff_size, i);
			}
		}
	}

	return rc;
}
