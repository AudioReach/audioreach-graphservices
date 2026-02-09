#ifndef GSL_DLS_CLIENT_H
#define GSL_DLS_CLIENT_H
/**
 *  \file gsl_dls_client.h
 *  \brief
 *        Contains definitions used by the Data Logging Service (DLS) client
 *
 *        This module is responsible for delivering binary log
 *        packet data to the gsl realtime tunning client. GSL subscribes
 *        subscription to dls event notifications from SPF. The gsl
 *        realtime tuning client registers the log codes it wants to
 *        recieve data for.
 *
 * \copyright
 *      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *      SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

#include "apm_api.h"
#include "dls_api.h"
#include "gsl_shmem_mgr.h"
#include "gsl_common.h"
#include "gsl_dls_client_intf.h"

#define GSL_DLS_CLIENT_GPR_SRC_PORT 0x3003
#define GSL_DLS_CLIENT_SHMEM_MAX_BUFFER_SZ_SHIFT 13 /* page size = 8192 B*/
#define GSL_DLS_CLIENT_SHMEM_MAX_BUFFER_SZ (1 << GSL_DLS_CLIENT_SHMEM_MAX_BUFFER_SZ_SHIFT)

#define GSL_DLS_CLIENT_SHMEM_MIN_BUFFER_SZ_SHIFT 11 /* page size = 2048 B*/
#define GSL_DLS_CLIENT_SHMEM_MIN_BUFFER_SZ (1 << GSL_DLS_CLIENT_SHMEM_MIN_BUFFER_SZ_SHIFT)

enum gsl_dls_commit_log_buffer_register_enum_t
{
    GLS_DLS_EVENT_FLAG_DEREGISTER_COMMIT_LOG_BUFFER = 0,
    GLS_DLS_EVENT_FLAG_REGISTER_COMMIT_LOG_BUFFER = 1,
};

struct gsl_dls_client_ctxt
{
    GSL_DLS_CLIENT_BUFFER_READY_CALLBACK buffer_ready_callback;
    /**
     * 1 Indicates dls is configured with default configuration
     * 0 Otherwise
     */
    int32_t is_dls_buffer_configured;
    /**
     * The configuration for the buffer pool used throught the session
     */
    struct gsl_dls_buffer_pool_config_t buffer_pool_config;
    /**
     * Shared memory for storing DLS binary log packets used for realtime monitoring
     */
    struct gsl_shmem_alloc_data dls_shmem;
    /**
     * Signal used to wait for responses from spf
     */
    struct gsl_signal sig;
    /**
     * lock used in conjuction with above signal
     */
    ar_osal_mutex_t sig_lock;
    /**
     * for signaling when to retured used buffers to spf
     */
    struct gsl_signal ready_buffer_sig;
    /**
     * List of used buffers to send to spf
     */
    struct gsl_dls_ready_buffer_index_list_t used_buffers;
};

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*GSL_DLS_CLIENT_H*/
