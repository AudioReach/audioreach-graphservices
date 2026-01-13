#ifndef GSL_RTC_INTF_H
#define GSL_RTC_INTF_H
/**
 * \file gsl_rtc_intf.h
 *
 * \brief
 *      Interface definition for GSL RTC functionality

 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "ar_osal_types.h"
#include "gsl_intf.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200)
#endif
struct gsl_rtc_key_vector {
	uint32_t num_kvps; /**< number of key-value pairs */
	struct gsl_key_value_pair kvp[]; /**< key-value pairs */
};

struct gsl_rtc_uc_data {
	uint32_t graph_handle; /**< graph handle id for the active use-case */
	uint32_t num_gkvs; /**< number of gkvs in the graph */
	uint32_t num_ckvs; /**< number of ckvs in the graph */
	uint8_t payload[];
	/**<
	 * GKV vectors followed by CKV vectors. Each GKV or CKV vector
	 * is in the form - struct gsl_rtc_key_vector
	 */
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

struct gsl_rtc_active_uc_info {
	uint32_t num_usecases; /**< total number of active use-cases */
	uint32_t total_size; /**< total size for gsl_rtc_active_uc_data */
	struct gsl_rtc_uc_data *uc_data;
	/**< memory pointing to active use-case data */
};

struct gsl_rtc_param {
	/** GSL graph handle */
	uint32_t graph_handle;
	/** sgid of the non-persist cal data */
	uint32_t sgid;
	/** total size of the non-persist cal data */
	uint32_t total_size;
	/**
	 * Pointer to non-persist cal data.
	 * The data in this buffer can contain one or more parameters
	 * in the form - {MIID, PID, Size, ErrorCode, VariablePayload}
	 */
	uint8_t *sg_cal_data;
};

struct gsl_rtc_persist_param {
	/** GSL graph handle */
	uint32_t graph_handle;
	/** sgid of the persist cal data */
	uint32_t sgid;
	/** processor id of the persist cal data within the sgid */
	uint32_t proc_id;
	/**
	 * Total size of the perist cal data.
	 * It is both input and output. GSL updates it
	 * with the actual data that is copied into the buffer
	 */
	uint32_t *total_size;
	/**
	 * Pointer to persist cal data.
	 * The data in this buffer can contain one or more parameters
	 * in the form - {MIID, PID, Size, ErrorCode, VariablePayload}
	 *
	 * In the case where this structure is passed in as part of
	 * set this pointer will be set by the caller. In
	 * the case of get it will be set by gsl.
	 *
	 * Setting the pointer to NULL results in GSL to query the data from ACDB
	 * using the CKV below
	 */
	uint8_t *sg_cal_data;
	/** pointer to CKV used to query acdb in-case above pointer is NULL */
	struct gsl_rtc_key_vector *ckv;
};

struct gsl_rtc_prepare_change_graph_info {
	/* GSL graph handle */
	uint32_t graph_handle;
	/**
	 * GKV corresponding to active use-case
	 */
	 struct gsl_rtc_key_vector *old_gkv;
	/*
	 * Number of subgraphs in sg_conn_info
	 */
	uint32_t num_sgs;
	/*
	 * size of sg_conn_info structure below in bytes
	 */
	uint32_t size_of_sg_conn_info;
	/*
	 * sg connection info for sg connections that are in the graph after
	 * RTGM modification
	 *
	 * the data is structured as follows:
	 *             sg_id_1, num_children, child0, child1...
	 *             sg_id_2, num_children, child0, child1...
	 *             ...
	 */
	uint32_t *sg_conn_info;
	 /*
	  * number of existing subgraphs that have module level modifications and
	  * therefore should be closed and reopened
	  */
	 uint32_t num_modified_sgs;
	 /*
	  * list of existing subgraphs that have module level modifications and
	  * therefore should be closed and reopened
	  */
	 uint32_t *modified_sgs;
	 /*
	  * number of entires in modified_sg_conn_info
	  */
	  uint32_t num_modified_sg_connections;
	 /*
	  * size of the modified sg_conn_info strucutre below in bytes
	  */
	 uint32_t size_of_modified_sg_conn_info;
	 /*
	  * sg connection info for sg connections that are either
	  * a. input to or output from modified sgs
	  * or
	  * b. modified by user (source or sink modules changed)
	  *
	  * the data should be structured as follows:
	  *		sg_id_1, num_children, child0, child1...
	  *		sg_id_2, num_children, child0, child1...
	  *		...
	  */
	  uint32_t *modified_sg_conn_info;
};

struct gsl_rtc_change_graph_info {
	/* GSL graph handle */
	uint32_t graph_handle;
	/**
	 * GKV corresponding to active use-case
	 */
	struct gsl_rtc_key_vector *old_gkv;
	/**
	 * GKV used to replace the old_gkv, this typically only changes if there
	 * is a subgraph add or delete, it is allowed to be same as old_gkv
	 */
	struct gsl_rtc_key_vector *new_gkv;
	/**
	 * CKV used to identy calibration data for the new graph
	 */
	struct gsl_rtc_key_vector *new_ckv;
	/**
	 * Size of tag data blob. Set to 0 to indicate none included
	 */
	uint32_t tag_data_size;
	/**
	 * Tag data blob pointer
	 */
	uint8_t *tag_data;
};

typedef enum gsl_rtc_conn_state {
	/**
	 * The rtc connection 'start' state. The RTC client will issue this
	 * command when it establishes a connection with ATS
	 */
	GSL_RTC_CONNECTION_STATE_START,
	/**
	 * The rtc connection 'stop' state. The RTC client will issue this
	 * command when it disconnects from ATS
	 */
	GSL_RTC_CONNECTION_STATE_STOP,
} gsl_rtc_conn_state;

struct gsl_rtc_conn_info {
	/**
	 * The state of an RTC session.
	 */
	gsl_rtc_conn_state state;
};

/**
 * \brief Get active use-case info
 *
 * \param[in/out] rsp: rsp pointer
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_get_active_usecase_info(struct gsl_rtc_active_uc_info *info);

/**
 * \brief get persist calibration data
 *
 * \param[in/out] rtc_param: pointer to struct gsl_rtc_persist_param
 *  RTC client is responsible to allocate/free the memory
 *  for gsl_rtc_persist_param
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_get_persist_data(struct gsl_rtc_persist_param *rtc_param);

/**
 * \brief get non-persist calibration data
 *  RTC client is responsible to allocate/free the memory
 *  for gsl_rtc_param
 *
 * \param[in/out] rtc_param: pointer to struct gsl_rtc_param
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_get_non_persist_data(struct gsl_rtc_param *rtc_param);

/**
 * \brief set persist calibration data
 *  RTC client is responsible to allocate/free the memory
 *  for gsl_rtc_persist_param
 *
 * \param[in/out] rtc_param: pointer to struct gsl_rtc_persist_param
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_set_persist_data(struct gsl_rtc_persist_param *rtc_param);


/**
 * \brief set non-persist calibration data
 *
 * \param[in/out] rtc_param: pointer to struct gsl_rtc_param
 *  RTC client is responsible to allocate/free the memory
 *  for gsl_rtc_param
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_set_non_persist_data(struct gsl_rtc_param *rtc_param);

/**
 * \brief Prepare for graph change operation, this will update GSL state and
 * close subgraphs and connections that are no longer needed but will not open
 * anything on Spf. This must be called before the ACDB data is updated.
 *
 * \param[in] rtc_param: pointer to struct gsl_rtc_prepare_change_graph,
 * carries information about the RTGM operation to be performed
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_prepare_change_graph(
	struct gsl_rtc_prepare_change_graph_info *rtc_param);

/**
 * \brief Complete the graph change operation that is already prepared. Note
 * calling gsl_rtc_prepare_change_graph is mandatory before calling this API
 * also the ACDB data on the device must be updated before calling this API.
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_change_graph(struct gsl_rtc_change_graph_info *rtc_param);

/**
 * \brief Notifies GSL about client connectivity.
 * \sa gsl_rtc_prepare_change_graph
 *	   gsl_rtc_change_graph
 *	   gsl_rtc_rtgm_session_state
 *
 * \param[in]: rtgm_session_info: info about RTC session to store internally
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_rtc_notify_conn_state(struct gsl_rtc_conn_info *rtgm_session_info);

#define GSL_RTC_GKV_SIZE_BYTES(num_kvps)  (sizeof(struct gsl_rtc_key_vector) +\
	((num_kvps) * sizeof(struct gsl_key_value_pair)))

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* GSL_RTC_INTF_H */
