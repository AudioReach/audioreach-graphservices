#ifndef GSL_GRAPH_H
#define GSL_GRAPH_H
/**
 * \file gsl_graph.h
 *
 * \brief
 *      Graph management layer header for Graph Service Layer (GSL).
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
#include "gsl_subgraph.h"
#include "gsl_common.h"
#include "gsl_datapath.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GSL_MAX_NUM_DATA_BUFFERS 16 /* client can at most use this many buffs*/

/** Graph states enumeration */
enum gsl_graph_states {
	/** Graph initialized */
	GRAPH_IDLE,
	/** Graph successfully opened on SPF */
	GRAPH_OPENED,
	/** Graph started on SPF */
	GRAPH_STARTED,
	/** Graph stoped on SPF */
	GRAPH_STOPPED,
	/** Graph closed on SPF, but not deinited */
	GRAPH_CLOSED,
	/**
	 * Graph is an error state but clean-up operations (such as close) on SPF
	 * are allowed
	 */
	GRAPH_ERROR_ALLOW_CLEANUP,
	/**
	 * Graph is in an unrecoverable error state no spf operations are allowed
	 */
	GRAPH_ERROR,
};

/** Graph signals enumeration */
enum gsl_graph_sig {
	GRAPH_CTRL_GRP1_CMD_SIG,
	/**<
	 * Signal used to wait for response from group 1 SPF control requests,
	 * it is assumed that requests within this group are serialized by the
	 * client. Group 1 includes: OPEN, PREPARE, START and STOP,
	 * CONFIGURE_READ_BUFFERS, CONFIGURE_WRITE_BUFFERS
	 */
	GRAPH_CTRL_GRP2_CMD_SIG,
	/**<
	 * Signal used to wait for response from group 2 SPF control requests,
	 * it is assumed that these requests are serialized by the client. Group 2
	 * includes: SET_CFG, REGISTER_CFG, FLUSH and REGSITER_MODULE_EVENTS
	 */
	GRAPH_CTRL_GRP3_CMD_SIG,
	/**<
	 * Signal used to wait for response from group 3 SPF control requests,
	 * it is assumed that these requests are serialized by the client.
	 * Group 3 includes: CLOSE
	 * Group 3 should also not conflict with group 1, but is separated here to
	 * prevent improper behaviour when a command of group 1 interferes with a
	 * command of group 3 by e.g. timing out then returning before
	 * ex: start times out, GSL decides to close malfunctioning graph and sends
	 * close, then SPF returns response for start before close
	 */
	GRAPH_CMD_SIG_MAX, /**< Max signals */
};

/** Subgraph connection data structure */
struct gsl_graph_sg_conn_data {
	uint32_t num_sgs;  /**< number of subgraphs in the connection data */
	size_t size; /**< size of the subgraph connection data */
	AcdbSubgraph *subgraphs; /**< subgraph connection data structure */
};

struct gsl_transient_state_info {
	/** flags to indicate when certain transient operations are in progress */
	bool_t flush_in_prog;
	bool_t read_in_prog;
	bool_t write_in_prog;
	bool_t stop_in_prog;

	/**
	 * signal to tell flush and stop when it is safe to proceed
	 * Note that it is not under a lock, so do not use the flags or status
	 */
	struct gsl_signal trans_state_change_sig;
};

/* used to cache some RTC related data for this graph */
struct gsl_graph_rtc_cache {
	/*
	 * these are used as a temporary cache to store the sgids and connections
	 * that will need to be opened at the end of RTGM sequence
	 */
	struct gsl_graph_sg_conn_data pruned_plus_reopen_sg_conn;
	/*
	 * These cache the param data on what was modified only. We need to
	 * decrement and then re-increment the open refcounts so that they close
	 * properly in RTCs which close an SG/conn shared by multiple graphs.
	 */
	struct gsl_sgid_list preserved_sgids;
	struct gsl_graph_sg_conn_data preserved_sg_conn;
};

/** GKV node structure */
struct gsl_graph_gkv_node {
	ar_list_node_t node;
	/** pointer to GKV */
	struct gsl_key_vector gkv;
	/** pointer to CKV */
	struct gsl_key_vector ckv;
	/** Number of subgraphs in gkv */
	uint32_t num_of_subgraphs;
	/** Array of size num_of_subgraphs to hold subgraph memory pointers */
	struct gsl_subgraph **sg_array;
	/** Number of cals in global persist cal list */
	uint32_t num_of_gp_cals;
	/**
	 * Array of size num_of_gp_cals. Holds references to global persist cals
	 * and all IIDs associated with that cal.
	 */
	struct gsl_glbl_persist_cal_iid_list *glbl_persist_cal_list;
	/** subgraph connection data */
	struct gsl_graph_sg_conn_data sg_conn_data;

	/**
	 * Cannot have more than 32 subgraphs in a GKV
	 * Each bit indicate whether that particular subgraph
	 * is stopped or not from this gkv_node
	 */
	uint32_t sg_stop_mask;

	/**
	 * Cannot have more than 32 subgraphs in a GKV
	 * Each bit indicate whether that particular subgraph
	 * is started or not from this gkv_node
	 */
	uint32_t sg_start_mask;
	/**
	 * bit mask: each bit indicates whether the SGs in this GKV require a
	 * specific spf subsystem (e.g. ADSP, CDSP..etc). Use the macros defined
	 * in gsl_spf_ss_state.h in-conjunction with the sys-ids in
	 * ar_osal_sys_id.h to get/set these bits
	 */
	uint32_t spf_ss_mask;
	/*
	 * used to cache data during real-time calibration operations such as graph
	 * change. Not used outside of real-time calibration
	 */
	struct gsl_graph_rtc_cache rtc_cache;
};

/** Graph data structure */
struct gsl_graph {
	/** current state of the graph */
	enum gsl_graph_states graph_state;
	/** lock object to serialize graph operations */
	ar_osal_mutex_t graph_lock;
	/** lock object to serialize get/set config opreations */
	ar_osal_mutex_t get_set_cfg_lock;
	/** Array of graph signal objects for control and data commands */
	struct gsl_signal graph_signal[GRAPH_CMD_SIG_MAX];
	/** control information for flush and RTGM */
	struct gsl_transient_state_info transient_state_info;
	/** control flag for dumping tag cfg to qact */
	bool_t rtc_conn_active;
	/** graph source port to send GPR commands */
	uint32_t src_port;
	/** graph routing id to send GPR commands */
	uint32_t proc_id;
	/** holds information for read data path */
	struct gsl_data_path_info read_info;
	/** holds information for write data path */
	struct gsl_data_path_info write_info;
	/** clients cb function ptr */
	gsl_cb_func_ptr cb;
	/** client data sent as part of cb */
	void *client_data;
	/** number of gkv nodes */
	uint32_t num_gkvs;
	/** List of gkv nodes */
	struct ar_list_t gkv_list;
	/** lock object to serialize gkv_list iterations */
	ar_osal_mutex_t gkv_list_lock;
	/**
	 * bitmask represents the Spf subsystems this graph depends on the
	 * values for this bitmask are provided in gsl_spf_ss_state.h
	 */
	uint32_t ss_mask;
};

struct gsl_prepare_change_graph_single_gkv_params {
	/* gkv that is being prepared for change graph */
	struct gsl_key_vector old_gkv;
	/* num_sgs in sgs */
	uint32_t num_sgs;
	/* list of all the subgraphs that will be present in the new gkv */
	uint32_t *sgs;
	/* sg connection info that represent all sg conncetions in the new gkv */
	struct gsl_graph_sg_conn_data sg_conn_info;
	/*
	 * number of subraphs that must be force closed/reopened even if they exist
	 * in both old and new gkvs, this is used in RTGM scenarios when user
	 * modifies subgraphs
	 */
	uint32_t num_sgs_to_reopen;
	/*
	 * list of all subraphs that must be force closed/reopened
	 */
	uint32_t *sgs_to_reopen;
	/*
	 * list of all subraph connections that must be force closed/reopened
	 */
	struct gsl_graph_sg_conn_data sg_conn_info_to_reopen;
};

struct gsl_change_graph_single_gkv_params {
	struct gsl_key_vector old_gkv;
	struct gsl_key_vector new_gkv;
	struct gsl_key_vector new_ckv;
};

/**
 * \brief initialize a graph's internals
 * Initialize graph instance and register to GPR to
 * receive/send commands/events/data from spf
 * Update state under graph_hdl_lock when calling this
 *
 * \param[in] graph: pointer to graph's memory
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_init(struct gsl_graph *graph);

/**
 * \brief deinitialize a graph's internals
 * call under the graph_hdl_lock to sync with SSR
 *
 * \param[in] graph: pointer to graph's memory
 *
 * \return AR_EOK
 */
int32_t gsl_graph_deinit(struct gsl_graph *graph);

/**
 * \brief Fetch a graph's information from ACDB
 *
 * \param[in] gkv: graph key vector to identify the graph
 *
 * \param[out] sg_id_list: stores the graph's sgs
 * \param[out] sg_conn_info: stores conn info for sgs in graph
 *
 * This function allocates memory that must be freed in *sg_id_list and in
 * sg_conn_info->subgraphs
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_acdb_get_graph(const struct gsl_key_vector *gkv,
	uint32_t **sg_id_list, AcdbGetGraphRsp *sg_conn_info);

/**
 * \brief Load a graph specified by gkv on to SPF. Calibration is also sent
 * if ckv also is specified.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] gkv: graph key vector to identify the graph
 * \param[in] ckv: OPTIONAL used to retrieve calibration for graph
 * \param[in] lock: OPTIONAL operations occur with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_open(struct gsl_graph *graph,
			  const struct gsl_key_vector *gkv,
			  const struct gsl_key_vector *ckv,
			  ar_osal_mutex_t lock);

/**
 * \brief Close the graph on SPF. Releases all resources that belong to
 * the graph.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_close(struct gsl_graph *graph,
			   ar_osal_mutex_t lock);

/**
 * \brief Set graph calibration on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] ckv: pointer to calibration key vector
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_set_cal(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv,
	const struct gsl_key_vector *ckv,
	ar_osal_mutex_t lock);

/**
 * \brief Set graph configuration on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] gkv: OPTIONAL specific graph key vector to apply config to for
 *				SSMD scenarios which have more than 1 GKV in the graph
 * \param[in] tag: tag ID
 * \param[in] tkv: Tag key vector
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_set_config(struct gsl_graph *graph,
	const struct gsl_key_vector *gkv, uint32_t tag,
	const struct gsl_key_vector *tkv, ar_osal_mutex_t lock);

/**
 * \brief Set custom graph configuration on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in,out] payload: pointer to config payload
 * \param[in] payload_size: payload size
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_set_custom_config(struct gsl_graph *graph,
	const uint8_t *payload,	const uint32_t payload_size,
	ar_osal_mutex_t lock);

/**
 * \brief Get custom graph configuration from SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in,out] payload: pointer to config payload
 * \param[in] payload_size: payload size
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_get_custom_config(struct gsl_graph *graph,
	uint8_t *payload, uint32_t payload_size, ar_osal_mutex_t lock);

/**
 * \brief Get tagged custom graph configuration from SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in,out] payload: pointer to config payload
 * \param[in,out] payload_size: payload size
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_get_tagged_custom_config(struct gsl_graph *graph,
	uint32_t tag, uint8_t *payload, uint32_t *payload_size,
	ar_osal_mutex_t lock);

/**
 * \brief Set custom graph configuration on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] tag: tag ID
 * \param[in] payload: pointer to config payload
 * \param[in] payload_size: payload size
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_set_tagged_custom_config(struct gsl_graph *graph,
	uint32_t tag, const uint8_t *payload, const size_t payload_size,
	ar_osal_mutex_t lock);

/**
 * \brief  Set persistent custom graph configuration on SPF
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] tag: tag ID
 * \param[in] payload: pointer to config payload
 * \param[in] payload_size: payload size
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_set_tagged_custom_config_persist(struct gsl_graph *graph,
	uint32_t tag, const uint8_t *payload, const uint32_t payload_size,
	ar_osal_mutex_t lock);

/**
 * \brief Set graph prepare command on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_prepare(struct gsl_graph *graph,
	ar_osal_mutex_t lock);

/**
 * \brief Configure the data path for this graph
 *
 * \param[in] graph: pointer to graph's meory
 * \param[in] read_write_flag: indicates which path is being configured, 1
 *	means READ path, 0 means WRITE path
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_config_data_path(struct gsl_graph *graph,
	enum gsl_data_dir dir, struct gsl_cmd_configure_read_write_params *cfg);

/**
 * \brief Set graph start command on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_start(struct gsl_graph *graph,
	ar_osal_mutex_t lock);

/**
 * \brief Set graph suspend command on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_suspend(struct gsl_graph *graph,
	ar_osal_mutex_t lock);

/**
 * \brief Set graph stop command on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_stop(struct gsl_graph *graph,
	ar_osal_mutex_t lock);

/**
 * \brief Write data to a graph
 *
 * \param[in] graph: pointer to graph's meory
 * \param[in] tag: tag used to indentify the module in spf that will receive
 *  the data
 * \param[in] buff: holds the buffer info for data being written
 * \param[out] consumed_size: used to return number of bytes actually written
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success,
 *			AR_EABORTED when buffer is not queued to spf because of graph
 *			close, stop, or flush (non-fatal error),
 *			error code otherwise
 */
int32_t gsl_graph_write(struct gsl_graph *graph, uint32_t tag,
	struct gsl_buff *buff, uint32_t *consumed_size);

/**
 * \brief Read data from a graph
 *
 * \param[in] graph: pointer to graph
 * \param[in] tag: tag used to identify the module in spf that will provide
 * the data
 * \param[in] buff: holds the buffer info for data being read
 * \param[out] filled_size: used to return number of bytes actually read
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success,
 *			AR_EABORTED when buffer is not queued to spf because of graph
 *			close, stop, or flush (non-fatal error),
 *			error code otherwise
 */
int32_t gsl_graph_read(struct gsl_graph *graph, uint32_t tag,
	struct gsl_buff *buff, uint32_t *filled_size);

/**
 * \brief Get tagged module info
 *
 * \param[in] graph_key_vect: pointer to graph key vector
 * \param[in] tag: tag used to indentify the module
 * \param[out] module_info: holds {MID, MIID} info
 * \param[out] module_info_size: size of the module info buffer
 * allocated by GSL
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_get_module_tag_info(const struct gsl_key_vector *gkv,
	uint32_t tag, struct gsl_module_id_info **module_info,
	uint32_t *module_info_size);

/**
 * \brief Issue custom event registration command to Spf
 *
 * \param[in] graph: pointer to graph
 * \param[in] reg_ev: event registration payload
 */
int32_t gsl_graph_register_custom_event(struct gsl_graph *graph,
	struct gsl_cmd_register_custom_event *reg_ev);

/**
 * \brief Set graph flush command on SPF.
 *
 * \param[in] graph: pointer to graph's memory
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_graph_flush(struct gsl_graph *graph,
	ar_osal_mutex_t lock);

/**
 * \brief Add a new graph to an existing graph on SPF.
 *
 * \param[in] graph: pointer to graph
 * \param[in] new_graph: pointer to GKV and CKV structure
 * \param[in] lock: optional mutex lock
 */
int32_t gsl_graph_add_new(struct gsl_graph *graph,
	struct gsl_cmd_graph_select *new_graph, ar_osal_mutex_t lock);

/**
 * \brief Change to a new graph from an existing graph on SPF.
 *
 * \param[in] graph: pointer to graph
 * \param[in] new_graph: pointer to new GKV and CKV structure
 * \param[in] lock: optional mutex lock
 *
 * \return AR_EOK for success or error code for failure
 */
int32_t gsl_graph_change(struct gsl_graph *graph,
	struct gsl_cmd_graph_select *new_graph, ar_osal_mutex_t lock);

/**
 * \brief Prepare to change a single graph. This function will add a new
 * gkv_node to the graph corresponding to the new gkv and close the old gkv_node
 * that corresponds to the old gkv. It caches the subgraphs that need to be
 * opened on spf without actually opening them. Caller can later
 * call gsl_graph_change_single_gkv to open them on Spf. This separation is
 * needed for RTGM support.
 *
 * \param[in] graph: pointer to graph
 * \param[in] params: Holds parameters related to the new graph
 * \param[in] lock: optional mutex lock
 *
 * \return AR_EOK for success or error code for failure
 */
int32_t gsl_graph_prepare_to_change_single_gkv(struct gsl_graph *graph,
	struct gsl_prepare_change_graph_single_gkv_params *params,
	ar_osal_mutex_t lock);

/**
 * \brief Change only graph corresponding to a single GKV on SPF, must be
 * called only after gsl_graph_prepare_to_change_single_gkv
 *
 * \param[in] graph: pointer to graph
 * \param[in] new_gkv: GKV that will be opened on Spf
 * \param[in] new_ckv: CKV that will be applied to the graph on Spf
 * \param[in] lock: optional mutex lock
 *
 * \return AR_EOK for success or error code for failure
 */
int32_t gsl_graph_change_single_gkv(struct gsl_graph *graph,
	struct gsl_change_graph_single_gkv_params *params,
	ar_osal_mutex_t lock);

/**
 * \brief helper method to set config passed by QACT on changed graphs,
 * must be called between gsl_graph_change_single_gkv and gsl_graph_start
 * Builds and sends a set cfg packet with the given payload.
 *
 * \param[in] graph: pointer to graph
 * \param[in] tag_data_size: size of tag data blob
 * \param[in] tag_data: data blob comprising a valid payload for
 *		APM_CMD_SET_CFG. Will be sent as-is.
 *
 * \return AR_EOK for success or error code for failure
 */
int32_t gsl_graph_change_set_config_helper(struct gsl_graph *graph,
	uint32_t tag_data_size, uint8_t *tag_data);

/**
 * \brief removes an old graph from an existing graph on SPF.
 *
 * \param[in] graph: pointer to graph
 * \param[in] old_graph: pointer to GKV to be removed
 * \param[in] oc_lock: optional mutex lock used for closing graph
 * \param[in] ss_lock: optional mutex lock used for stoping graph
 */
int32_t gsl_graph_remove_old(struct gsl_graph *graph,
	struct gsl_cmd_remove_graph *old_graph, ar_osal_mutex_t oc_lock,
	ar_osal_mutex_t ss_lock);

/**
 * \brief Get the current state of the  graph
 *
 * \param[in] graph: pointer to graph's memory
 *
 * \return the current state
 */

/*
 * \brief Get the current state of the  graph
 *
 * \param[in] graph: pointer to graph's memory
 *
 * \return the current state
 */
enum gsl_graph_states gsl_graph_get_state(struct gsl_graph *graph);

/**
 * \brief Update the graphs state
 *
 * \param[in] graph: graph object
 * \param[in] new_state: New state to set on the graph
 *
 * \return state after it has been updated
 */
enum gsl_graph_states gsl_graph_update_state(struct gsl_graph *graph,
	enum gsl_graph_states new_state);

/**
 * \brief Dispatch an event to the graph on all signals
 *
 * \param[in] graph: graph obj
 * \param[in] ev_mask: indicates what is the event to be raised on the graph
 *
 * \return AR_EOK on success, error code otherwise
 */
void gsl_graph_signal_event_all(struct gsl_graph *graph,
	enum gsl_graph_sig_event_mask ev_mask);

/**
 * \brief Query database for all tags and corresponding module_iid/module_id
 * mapping given a graph key vector
 * \param[in] graph_key_vect: graph key vector
 * \param[in,out] tag_module_info: client buffer where tag module info
 * gets copied to
 * \param[in,out] tag_module_info_size: size of the tag module info
 *
 * \return EOK on success, error code otherwise.
 */
int32_t gsl_graph_get_tags_with_module_info(
	const struct gsl_key_vector *graph_key_vect,
	struct gsl_tag_module_info *tag_module_info,
	size_t *tag_module_info_size);

/**
 * \brief Query database for tagged data
 * \param[in] graph_key_vect: graph key vector
 * \param[in,out] tag_module_info: client buffer where tag module info
 * gets copied to
 * \param[in,out] tag_module_info_size: size of the tag module info
 *
 * \return EOK on success, error code otherwise.
 */
int32_t gsl_graph_get_tagged_data(
	const struct gsl_key_vector *graph_key_vect, uint32_t tag,
	struct gsl_key_vector *tag_key_vect,
	uint8_t *payload, size_t *payload_size);

/**
 * \brief Issue graph stop for the subgraphs with matching properties
 *
 * \param[in] graph: graph object
 * \param[in] stop_props: subgraph properties
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return EOK on success, error code otherwise.
 */
int32_t gsl_graph_stop_with_properties(struct gsl_graph *graph,
	struct gsl_cmd_properties *stop_props, ar_osal_mutex_t lock);

/**
 * \brief Issue graph close for the subgraphs with matching properties
 *
 * \param[in] graph: graph object
 * \param[in] props: subgraph properties
 * \param[in] lock: OPTIONAL all operations happen with this lock acquired
 *
 * \return EOK on success, error code otherwise.
 */
int32_t gsl_graph_close_with_properties(struct gsl_graph *graph,
	struct gsl_cmd_properties *props, ar_osal_mutex_t lock);

/**
 * \brief Set RTGM state for the current graph
 *
 * \param[in] graph: graph object
 * \param[in] rtgm_in_prog: true indicates RTGM in prog
 *
 * \return EOK on success, error code otherwise.
 */
void gsl_graph_set_rtgm_state(struct gsl_graph *graph, bool_t rtgm_in_prog);
#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* GSL_GRAPH_H */

