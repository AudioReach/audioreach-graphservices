/**
 * \file ar_osal_dyn_pd.c
 *
 * \brief
 *       This file has implementation of pd init for proc domains.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#define AR_DYN_PD "ar_dyn_pd"
#include "ar_osal_error.h"
#include "ar_osal_types.h"

#ifdef AR_OSAL_USE_DYNAMIC_PD

#include <pthread.h>
#include "AEEStdErr.h"
#include "cdsp_dyn_pd.h"
#include "remote.h"
#include "ar_osal_dyn_pd.h"
#include "ar_osal_sys_id.h"
#include "ar_osal_log.h"

#define STATUS_CONTEXT 0x12345678

/** Maximum length of URI for remote_handle_open() calls */
#define MAX_DOMAIN_URI_SIZE 12

#pragma weak remote_session_control
#pragma weak remote_handle_control

struct fastrpc_domain {
    char_t *pd_URI_domain;
    remote_handle64 pd_handle;
} domain_data[AR_SUB_SYS_ID_LAST + 1];

/** Domain type for multi-domain RPC calls */
typedef struct domain_t {
    /** Domain ID */
    int32_t id;
    /** URI for remote_handle_open */
    char_t uri[MAX_DOMAIN_URI_SIZE];
} domain;

static int32_t dsp_domain_id[AR_SUB_SYS_ID_LAST + 1] = {
    -1, MDSP_DOMAIN_ID, ADSP_DOMAIN_ID, -1, SDSP_DOMAIN_ID, CDSP_DOMAIN_ID, -1
};

static pthread_mutex_t ar_pd_lock = PTHREAD_MUTEX_INITIALIZER;

domain supported_domains[] = {
    {ADSP_DOMAIN_ID, ADSP_DOMAIN},
    {MDSP_DOMAIN_ID, MDSP_DOMAIN},
    {SDSP_DOMAIN_ID, SDSP_DOMAIN},
    {CDSP_DOMAIN_ID, CDSP_DOMAIN}
};

static int32_t ar_map_error_code(int32_t nErr)
{
    int32_t ar_err = AR_EOK;
    switch (nErr) {
        case AEE_SUCCESS:
            ar_err = AR_EOK;
            break;
        case AEE_EFAILED:
            ar_err = AR_EFAILED;
            break;
        case AEE_EBADPARM:
            ar_err = AR_EBADPARAM;
            break;
        case AEE_EUNSUPPORTED:
            ar_err = AR_EUNSUPPORTED;
            break;
        case AEE_EUNSUPPORTEDAPI:
            ar_err = AR_EUNSUPPORTED;
            break;
        case AEE_EVERSIONNOTSUPPORT:
            ar_err = AR_EVERSION;
            break;
        case AEE_ERESOURCENOTFOUND:
            ar_err = AR_EVERSION;
            break;
        case AEE_EINVHANDLE:
            ar_err = AR_EHANDLE;
            break;
        case AEE_EALREADYLOADED:
            ar_err = AR_EHANDLE;
            break;
        case AEE_EACKPENDING:
            ar_err = AR_EPENDING;
            break;
        case AEE_EBUSY:
            ar_err = AR_EBUSY;
            break;
        case AEE_ENEEDMORE:
            ar_err = AR_ENEEDMORE;
            break;
        case AEE_ENOMEMORY:
            ar_err = AR_ENEEDMORE;
            break;
        case AEE_ENOSUCH:
            ar_err = AR_ENOTEXIST;
            break;
        default:
             ar_err = AR_EFAILED;
             break;
    }
    return ar_err;
}

static domain *get_domain(int domain_id)
{
    uint32_t i = 0;
    uint32_t size = sizeof(supported_domains)/sizeof(domain);

    for (i = 0; i < size; ++i) {
        if (supported_domains[i].id == domain_id)
            return &supported_domains[i];
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_osal_dyn_pd_init(_In_ uint32_t proc_id)
{
    int32_t nErr = AEE_SUCCESS;
    uint32_t pd_URI_domain_len = strlen(audio_pd_cdsp_URI) + MAX_DOMAIN_URI_SIZE;
    domain *my_domain = NULL;
    int32_t domain_id = -1;

    pthread_mutex_lock(&ar_pd_lock);
    domain_data[proc_id].pd_handle = -1;
    domain_data[proc_id].pd_URI_domain = NULL;
    domain_id = dsp_domain_id[proc_id];

    my_domain = get_domain(domain_id);
    if (my_domain == NULL) {
        nErr = AEE_EBADPARM;
        AR_LOG_ERR(AR_DYN_PD, "unable to get domain struct %d error 0x%x", domain_id, nErr);
        goto exit;
    }

    if (remote_session_control) {
        struct remote_rpc_control_unsigned_module data;
        data.domain = domain_id;
        data.enable = 1;
        if (AEE_SUCCESS != (nErr = remote_session_control(DSPRPC_CONTROL_UNSIGNED_MODULE,
                                                            (void*)&data, sizeof(data)))) {
            AR_LOG_ERR(AR_DYN_PD, "remote_session_control failed error 0x%x", nErr);
            goto exit;
        }
    } else {
        nErr = AEE_EUNSUPPORTED;
        AR_LOG_ERR(AR_DYN_PD, "remote_session_control interface is not supported on this device error 0x%x", nErr);
        goto exit;
    }

    if ((domain_data[proc_id].pd_URI_domain = (char *)malloc(pd_URI_domain_len)) == NULL) {
        nErr = AEE_ENOMEMORY;
        AR_LOG_ERR(AR_DYN_PD, "unable to allocate memory for pd_URI_domain of size: %d",
            pd_URI_domain_len);
        goto exit;
    }

    nErr = snprintf(domain_data[proc_id].pd_URI_domain, pd_URI_domain_len, "%s%s",
                    audio_pd_cdsp_URI, my_domain->uri);
    if (nErr < 0) {
        AR_LOG_ERR(AR_DYN_PD, "populating pd URI domain failed. error 0x%x", nErr);
        nErr = AEE_EFAILED;
        goto exit;
    }

    if (AEE_SUCCESS == (nErr = audio_pd_cdsp_open(domain_data[proc_id].pd_URI_domain,
                                                    &domain_data[proc_id].pd_handle))) {
        if (AEE_SUCCESS == (nErr = audio_pd_cdsp_init(domain_data[proc_id].pd_handle))) {
            AR_LOG_INFO(AR_DYN_PD, "audio_pd_cdsp init done");
        }
    }

    if (nErr) {
        AR_LOG_ERR(AR_DYN_PD, "Failed to initialize cdsp audio pd on domain %d error 0x%x",
            domain_id, nErr);
        goto exit;
    }
    pthread_mutex_unlock(&ar_pd_lock);
    return ar_map_error_code(nErr);

exit:
    if (domain_data[proc_id].pd_URI_domain) {
        free(domain_data[proc_id].pd_URI_domain);
    }
    pthread_mutex_unlock(&ar_pd_lock);
    return ar_map_error_code(nErr);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_osal_dyn_pd_deinit(_In_ uint32_t proc_id)
{
    int32_t nErr = AEE_SUCCESS;

    pthread_mutex_lock(&ar_pd_lock);
    if (domain_data[proc_id].pd_handle != -1) {
        if (AEE_SUCCESS == (nErr = audio_pd_cdsp_deinit(domain_data[proc_id].pd_handle))) {
            AR_LOG_INFO(AR_DYN_PD, "audio_pd_cdsp deinit done");
        }
        if (AEE_SUCCESS != (nErr = audio_pd_cdsp_close(domain_data[proc_id].pd_handle))) {
            AR_LOG_ERR(AR_DYN_PD, "Failed to close handle error 0x%x", nErr);
        }
        domain_data[proc_id].pd_handle = -1;
    }

    if (domain_data[proc_id].pd_URI_domain) {
        free(domain_data[proc_id].pd_URI_domain);
        domain_data[proc_id].pd_URI_domain = NULL;
    }
    pthread_mutex_unlock(&ar_pd_lock);
    return ar_map_error_code(nErr);
}
#else
int32_t ar_osal_dyn_pd_init(uint32_t proc_id)
{
	return AR_ENOTIMPL;
}
int32_t ar_osal_dyn_pd_deinit(uint32_t proc_id)
{
	return AR_ENOTIMPL;
}
#endif
