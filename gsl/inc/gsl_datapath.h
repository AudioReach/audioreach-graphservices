#ifndef GSL_DATAPATH_H
#define GSL_DATAPATH_H

/**
 * \file gsl_datapath.h
 *
 * \brief
 *      Implement data path handling for Graph Service Layer (GSL)
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */


#include "ar_osal_types.h"
#include "ar_osal_mutex.h"
#include "ar_osal_signal.h"
#include "ar_util_list.h"
#include "ar_osal_error.h"
#include "gsl_intf.h"
#include "gsl_common.h"
#include "gsl_msg_builder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GSL_MAX_NUM_DATA_BUFFERS 16 /* client can at most use this many buffs*/
#define GSL_DP_DATA_MODE(dp) ((dp)->config.attributes \
&GSL_ATTRIBUTES_DATA_MODE_MASK)

#define GSL_DATAPATH_SETUP_MODE(cfg) \
(((cfg)->attributes & GSL_ATTRIBUTES_DATAPATH_SETUP_MASK) \
>> GSL_ATTRIBUTES_DATAPATH_SETUP_SHIFT)

/**
 * represents one buffer in GSL
 */
struct gsl_buff_internal {
	/**
	 * memory allocation for this buffer
	 */
	gsl_msg_t gsl_msg;

	/**
	 * Used in read scenario only, holds the size of data received from spf.
	 * for this buffer
	 */
	uint32_t size_from_spf;

	/**
	 * Used in read scenario only, holds the time-stamp/flags of the
	 * buffer received from Spf.
	 */
	uint64_t spf_timestamp;
	uint32_t spf_flags;
};

struct gsl_metadata_buff_internal {
	/**
	 * memory allocation for this buffer
	 */
	gsl_msg_t gsl_msg;

	/*
	 * metadata buffer passed from clients in read/write
	 */
	uint8_t *client_md_ptr;
	/**
	 * size of metadata buffer above
	 */
	 uint32_t size;

	/**
	 * Used in read scenario only, holds the size of metadata received from spf.
	 * for this buffer
	 */
	uint32_t md_size_from_spf;

	uint32_t md_status_from_spf;
};


/* this is the context for this module */
struct gsl_data_path_info {
	/**
	 * client provided configuration for this set of data buffers
	 */
	struct gsl_cmd_configure_read_write_params config;

	/**
	 * array of gsl internal buffers, actual number of buffers is stored in
	 * config.num_buffs
	 */
	struct gsl_buff_internal *buff_list;

	/**
	 * array of metadata buffers
	 */
	struct gsl_metadata_buff_internal *md_buff_list;

	struct gsl_signal dp_signal;

	/**
	 * buffer avail bitmask - each bit when set indicates corresponding buffer
	 * is used (not with GSL), when clear indicates buffer is available
     * (with GSL)
	 *
	 * bit pos 0: indicates buffer number 0 is used or available
	 * bit pos 1: indicates buffer number 1 is used or available
	 * . . .
	 * bit pos num_buffs - 1: buffer number (num_buffs - 1) is used or avail
	 */
	int32_t buff_used_status;

	/** Buffer available to be queued to spf [0,...,config.num_buffs) */
	int32_t curr_buff_index;

	/**
	 * next metadata buffer available
	 * [0,...,GSL_MAX_NUM_DATA_BUFFERS)
	 *
	 */
	uint32_t md_buff_list_head;

	/**
	 * oldest metadata buffer that is already used
	 * [0,...,GSL_MAX_NUM_DATA_BUFFERS)
	 */
	uint32_t md_buff_list_tail;

	/**
	 * oldest metadata buffer that has not yet been acked by spf
	 * [0,...,GSL_MAX_NUM_DATA_BUFFERS)
	 */
	uint32_t md_buff_list_acked;

	/*
	 * number of md buffers = GSL_METADATA_TO_DATA_FACTOR *
	 * number_of_data_buffers
	 */
	 uint32_t md_buff_list_size;

	/** Lock used to mark buffers as available or used */
	ar_osal_mutex_t lock;

	/**
	 * Used to cache the module iid and tag from previous read/write, if they
	 * are the same then skip acdb look-up
	 */
	uint32_t miid;
	uint32_t cached_tag;

	/**
	 * Keeps count of number of buffers sent to or received from spf
	 * Incremented by 1 everytime we get a read or write done from spf
	 */
	uint32_t processed_buf_cnt;

	uint32_t src_port;

	bool_t oob_metadata_flag;

	uint32_t master_proc_id;

	bool_t is_shmem_supported;
};

/**
 * \brief instantiate global refcount lock
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dp_create_cache_refcount_lock(void);

/**
 * \brief destroy global refcount lock
 */
void gsl_dp_destroy_cache_refcount_lock(void);

/**
 * \brief initialise a new data path for a graph
 *
 * \param[in] dp_info: pointer to datapath to init
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_data_path_init(struct gsl_data_path_info *dp_info);

/**
 * \brief tear down a data path for a graph
 *
 * \param[in] dp_info: pointer to datapath to deinit
 */
void gsl_data_path_deinit(struct gsl_data_path_info *dp_info);

/**
 * \brief Configure a data path
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] cfg: configuration params from client
 *
 * These 3 params are for push pull setup:
 * \param[in] src_port: source port of the parent graph
 * \param[in] cfg_signal: signal used for sending CFG on parent graph (GRP_2)
 * \param[in] dir: whether graph is read or write
 *
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \param[in] proc_id: master proc id corresponding to the usecase.
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dp_config_data_path(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_configure_read_write_params *cfg, uint32_t src_port,
	struct gsl_signal *cfg_signal, enum gsl_data_dir dir,
	ar_osal_mutex_t lock, uint32_t proc_id);

/**
 * \brief Read data from a datapath
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] buff: holds the buffer info for data being read
 * \param[out] filled_size: used to return number of bytes actually read
 *
 * \return AR_EOK on success,
 *			AR_EABORTED when buffer is not queued to spf because of graph
 *			close, stop, or flush (non-fatal error),
 *			error code otherwise
 */
int32_t gsl_dp_read(struct gsl_data_path_info *dp_info, struct gsl_buff *buff,
	uint32_t *filled_size);

/**
 * \brief Write data to a datapath
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] buff: holds the buffer info for data being written
 * \param[out] consumed_size: used to return number of bytes actually written
 *
 * \return AR_EOK on success,
 *			AR_EABORTED when buffer is not queued to spf because of graph
 *			close, stop, or flush (non-fatal error),
 *			error code otherwise
 */
int32_t gsl_dp_write(struct gsl_data_path_info *dp_info, struct gsl_buff *buff,
	uint32_t *consumed_size);

/**
 * \brief Issue an EOS data path command to Spf
 *
 * \param[in] dp_info: pointer to a datapath
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dp_write_send_eos(struct gsl_data_path_info *dp_info);

/**
 * \brief handle buf done on a read datapath
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] packet: GPR packet received in callback
 * \param[in] cb: client callback registered with GSL
 * \param[in] client_data: pointer to payload for client callback
 *
 * \return AR_EOK on success,
 *			error code otherwise
 */

int32_t gsl_handle_read_buff_done(struct gsl_data_path_info *dp_info,
	gpr_packet_t *packet, gsl_cb_func_ptr cb, void *client_data);

/**
 * \brief handle buf done for media format buffer
 * on a write datapath
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] packet: GPR packet received in callback
 *
 * \return AR_EOK on success
 */
int32_t gsl_handle_media_format_buff_done(struct gsl_data_path_info *dp_info,
					gpr_packet_t *packet);

/**
 * \brief handle buf done on a write datapath
 *
 * \param[in] dp_info: pointer to data path
 * \param[in] packet: GPR packet received in callback
 * \param[in] cb: client callback registered with GSL
 * \param[in] client_data: pointer to payload for client callback
 *
 * \return AR_EOK on success,
 *			error code otherwise
 */
int32_t gsl_handle_write_buff_done(struct gsl_data_path_info *dp_info,
	gpr_packet_t *packet, gsl_cb_func_ptr cb, void *client_data);

/**
 * \brief Get data buffer pointers and other info for this datapath
 *
 * \param[in] dp_info: pointer to a datapath
 * \param[in,out] cfg: used to return information regarding the buffers
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dp_get_buff_info(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_get_shmem_buf_info *cfg);

/**
 * \brief Get pos buffer pointers and other info for this datapath
 *
 * \param[in] dp_info: pointer to a datapath
 * \param[in,out] cfg: used to return information regarding the buffers
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dp_get_pos_buff_info(struct gsl_data_path_info *dp_info,
	struct gsl_cmd_get_shmem_buf_info *cfg);

/**
 * \brief  get processed buffer count for a graph
 *
 * \param[in] dp_info: pointer to a datapath
 *
 * \return the number of processed buffers
 */
uint32_t gsl_dp_get_processed_buff_cnt(struct gsl_data_path_info *dp_info);

/**
 * \brief get available buffer size for a graph path
 *
 * \param[in] dp_info: pointer to a datapath
 *
 * \return the size of available buffer (in bytes)
 */
uint32_t gsl_dp_get_avail_buffer_size(struct gsl_data_path_info *dp_info);

/**
 * \brief wait for all buffers to come back on a datapath
 *
 * \param[in] dp_info: pointer to a datapath
 *
 * \return AR_EOK on success, error code otherwise
 */

int32_t gsl_wait_for_all_buffs_to_be_avail(struct gsl_data_path_info *dp_info);

/**
 * \brief queue all buffs on a read datapath to SPF
 *
 * \param[in] dp_info: pointer to a datapath
 *
 * \return AR_EOK on success, error code otherwise
 */

int32_t gsl_dp_queue_read_buffers_to_spf(struct gsl_data_path_info *dp_info);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* GSL_DATAPATH_H */
