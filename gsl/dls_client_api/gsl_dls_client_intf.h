#ifndef GSL_DLS_CLIENT_INTF_H
#define GSL_DLS_CLIENT_INTF_H
/**
 * \file gsl_dls_client_intf.h
 *
 * \brief
 *      Defines a set of APIs that the realtime tuning client can use to
 *      register log codes and recieve log packet data from the gsl dls
 *      client
 *
 * \copyright
 *      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *      SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

#include "ar_osal_types.h"

 /* The minimum number of DLS buffers allowed*/
#define GSL_DLS_CLIENT_MIN_BUFFER_COUNT 10

/* The maximum number of DLS buffers allowed*/
#define GSL_DLS_CLIENT_MAX_BUFFER_COUNT 256

struct gsl_dls_ready_buffer_index_list_t
{
	/*
	 * The number of buffers that are ready to read from
	 */
	uint16_t buffer_count;
	/*
	 * List of dls log buffer indexes
	 */
	uint16_t buffer_index_list[GSL_DLS_CLIENT_MAX_BUFFER_COUNT];
};

struct gsl_dls_buffer_pool_config_t
{
	/* The size of a single binary log packet buffer */
	uint32_t buffer_size;
	/* The number of binary log buffers */
	uint32_t buffer_count;
};

struct gls_dls_buffer_t
{
	/* The size of the buffer */
	uint32_t size;
	/* A pointer to the buffer */
	uint8_t* buffer;
};

/**
 * \brief callback function that is called when SPF notifies the DLS client
 * about buffers that are ready to read.
 *
 * \return AR_EOK on success, error otherwise
 */
typedef int32_t(*GSL_DLS_CLIENT_BUFFER_READY_CALLBACK)(void);

/**
 * \brief Checks if the DLS feature is enabled in GSL
 * \detdesc
 *    feature needs to be enabled by defining ATS_DATA_LOGGING in your build configuration
 * \return AR_EOK on success, AR_EUNSUPPORTED otherwise
 */
int32_t gsl_dls_client_is_feature_supported();

/**
 * \brief Initializes the DLS Client
 *
 * \param[in] buffer_pool_config: configuration used to setup the dls buffer pool size.
 * \param[in] callback: callback function that is called when SPF notifies the DLS client about buffers that are ready to read.
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_init(struct gsl_dls_buffer_pool_config_t* buffer_pool_config, GSL_DLS_CLIENT_BUFFER_READY_CALLBACK callback);

/**
 * \brief Cleans up resources aquired during gsl_dls_client_init(...)
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_deinit();

/**
 * \brief Allocates and configures shared memory for storing log buffers and registers
 * for log buffer commit notifications from DLS on SPF
 *
 * \param[in] buffer_pool_config: contains the number of DLS Log Buffers and the size of each buffer
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_create_buffer_pool(struct gsl_dls_buffer_pool_config_t* buffer_pool_config);

/**
 * \brief Retrieves a list of buffers index for dls buffers that are ready to read from
 *
 * \param[in] buffer_ready_list:
 *
 * \return AR_EOK on success, error otherwise
 */
void gsl_dls_client_get_ready_dls_buffer_list(struct gsl_dls_ready_buffer_index_list_t* buffer_ready_list);

/**
 * \brief Gets a log buffer from the dls buffer pool
 *
 * \param[in] buffer_index_read: the index of the buffer to read from the dls buffer pool
 * \param[out] dls_log_buffer: contains the size of the log buffer and a pointer to the buffer in the shared memory buffer pool
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_get_log_buffer(uint32_t log_buffer_index, struct gls_dls_buffer_t* dls_log_buffer);

/**
 * \brief Returns used DLS buffers back to SPF
 *
 * \param[out] buffer_index_list: the list of buffers to return to DLS on SPF
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_return_used_buffers(struct gsl_dls_ready_buffer_index_list_t* buffer_index_list);

/**
 * \brief Registers or deregisters a log code. Registered log codes will start to accumulate binary buffers in SPFs DLS
 *
 * \param[in] log_code: The log code to register/de-register
 * \param[in] is_log_code_enabled:true for registering a log code and false for de-registering
 *
 * \return AR_EOK on success, error otherwise
 */
int32_t gsl_dls_client_register_deregister_log_code(uint32_t log_code, bool_t is_log_code_enabled);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*GSL_DLS_CLIENT_INTF_H*/
