/**
 * \file ar_osal_signal.c
 *
 * \brief
 *      This file defines signal variable implementaion.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#define AR_OSAL_SIGNAL_LOG_TAG   "COSI"
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include "ar_osal_signal.h"
#include "ar_osal_log.h"
#include "ar_osal_error.h"

/* Internal condition definition */
typedef struct osal_int_signal {
	pthread_mutex_t osal_mutex;
	pthread_cond_t osal_cond;
	bool signalled;
	bool cond_destroyed; /* Tracks completed condition teardown for repeat destroy. */
} osal_int_signal_t;

_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_init(_In_ ar_osal_signal_t signal __unused)
{
    return AR_ENOTIMPL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_deinit(_In_ ar_osal_signal_t signal __unused)
{
    return AR_ENOTIMPL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
size_t ar_osal_signal_get_size()
{
    return sizeof(osal_int_signal_t);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_create(_Inout_ ar_osal_signal_t *ret_signal)
{
    int32_t rc;
    osal_int_signal_t *the_signal;
    pthread_condattr_t attr;
    if (NULL == ret_signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }
    the_signal = (osal_int_signal_t *)malloc(sizeof(osal_int_signal_t));
    if (NULL == the_signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: failed to allocate signal memory\n", __func__);
        rc = AR_ENOMEMORY;
        goto done;
    }

    rc = pthread_mutex_init(&the_signal->osal_mutex, NULL);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to init mutex, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto err_mutex;
    }
    rc = pthread_condattr_init(&attr);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to init cond attr, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto err_cond;
    }
    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to set cond attr clock, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto err_attr;
    }
    rc = pthread_cond_init(&the_signal->osal_cond, &attr);
    /* Attribute is no longer needed after pthread_cond_init(), regardless
     * of its return value. */
    if (pthread_condattr_destroy(&attr)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to destroy cond attr\n", __func__);
    }
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to init cond, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto err_cond;
    }
    the_signal->signalled = false;
    the_signal->cond_destroyed = false;
    *ret_signal = the_signal;
    goto done;
err_attr:
    if (pthread_condattr_destroy(&attr)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to destroy cond attr\n", __func__);
    }
err_cond:
    pthread_mutex_destroy(&the_signal->osal_mutex);
err_mutex:
    free(the_signal);
done:
   return rc;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_osal_signal_wait(_In_ ar_osal_signal_t signal)
{
    int32_t rc = AR_EOK;
    int32_t ret = 0;
    osal_int_signal_t *the_signal;
    if (NULL == signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }
    the_signal = (osal_int_signal_t *)signal;
    ret = pthread_mutex_lock(&the_signal->osal_mutex);
    if (ret) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to acquire lock, ret = %d\n", __func__, ret);
        rc = AR_EFAILED;
        goto done;
    }
    if (true == the_signal->signalled)
    {
        goto unlock;
    }

    ret = pthread_cond_wait(&the_signal->osal_cond, &the_signal->osal_mutex);
    if (ret) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to wait on signal, rc = %d\n", __func__, ret);
        rc = AR_EFAILED;
    }

unlock:
    if (pthread_mutex_unlock(&the_signal->osal_mutex)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to unlock\n", __func__);
        if (rc == AR_EOK)
            rc = AR_EFAILED;
    }
done:
    return rc;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_osal_signal_timedwait(_In_ ar_osal_signal_t signal, _In_ int64_t timeout_in_nsec)
{
    int32_t rc = AR_EOK;
    int32_t ret = 0;
    osal_int_signal_t *the_signal;
    struct timespec osal_ts;

    if (NULL == signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }

    clock_gettime(CLOCK_MONOTONIC, &osal_ts);
    osal_ts.tv_sec += (timeout_in_nsec / 1000000000);
    osal_ts.tv_nsec += (timeout_in_nsec % 1000000000);

    if (osal_ts.tv_nsec >= 1000000000) {
        osal_ts.tv_sec += 1;
        osal_ts.tv_nsec -= 1000000000;
    }

    the_signal = (osal_int_signal_t *)signal;
    ret = pthread_mutex_lock(&the_signal->osal_mutex);
    if (ret) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to acquire lock, ret = %d\n", __func__, ret);
        rc = AR_EFAILED;
        goto done;
    }

    if (true == the_signal->signalled) {
        goto unlock;
    }

    rc = pthread_cond_timedwait(&the_signal->osal_cond, &the_signal->osal_mutex, &osal_ts);
    if (rc) {
        if (rc == ETIMEDOUT) {
            rc = AR_ETIMEOUT;
        } else {
            AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to wait on signal, rc = %d\n", __func__, rc);
            rc = AR_EFAILED;
        }
    }

unlock:
    if (pthread_mutex_unlock(&the_signal->osal_mutex)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to unlock\n", __func__);
        if (rc == AR_EOK)
            rc = AR_EFAILED;
    }
done:
    return rc;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_set(_In_ ar_osal_signal_t signal)
{
    int32_t rc = AR_EOK;
    int32_t ret = 0;
    osal_int_signal_t *the_signal;

    if (NULL == signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }

    the_signal = (osal_int_signal_t *)signal;
    ret = pthread_mutex_lock(&the_signal->osal_mutex);
    if (ret) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to acquire lock, ret = %d\n", __func__, ret);
        rc = AR_EFAILED;
        goto done;
    }
    the_signal->signalled = true;

    ret = pthread_cond_broadcast(&the_signal->osal_cond);
    if (ret) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to signal on signal, ret = %d\n", __func__, ret);
        rc = AR_EFAILED;
    }

    if (pthread_mutex_unlock(&the_signal->osal_mutex)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to unlock\n", __func__);
        if (rc == AR_EOK)
            rc = AR_EFAILED;
    }
done:
    return rc;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_destroy(_In_ ar_osal_signal_t signal)
{
    int32_t rc;
    osal_int_signal_t *the_signal;

    if (NULL == signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }

    the_signal = (osal_int_signal_t *)signal;
    rc = pthread_mutex_lock(&the_signal->osal_mutex);

    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to acquire lock, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        return rc;
    }
    the_signal->signalled = false;

    /*
     * If mutex cleanup fails after condition destruction succeeds, a later
     * destroy call must not destroy the condition variable a second time.
     */
    if (!the_signal->cond_destroyed) {
        rc = pthread_cond_destroy(&the_signal->osal_cond);
        if (rc) {
            AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to destroy signal, rc = %d\n", __func__, rc);
            rc = AR_EFAILED;
        } else {
            the_signal->cond_destroyed = true;
        }
    }
    if (pthread_mutex_unlock(&the_signal->osal_mutex)) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to unlock\n", __func__);
        if (rc == AR_EOK)
            rc = AR_EFAILED;
    }
    /*
     * A failed condition destroy may mean waiters still reference the signal.
     * A failed unlock leaves mutex ownership uncertain. Retain the signal on
     * either failure so a later destroy call can finish cleanup safely.
     */
    if (rc)
        goto done;
    /* Free only after all synchronization objects are destroyed successfully. */
    rc = pthread_mutex_destroy(&the_signal->osal_mutex);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to destroy mutex, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto done;
    }
    free(signal);
done:
    return rc;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
int32_t ar_osal_signal_clear(_In_ ar_osal_signal_t signal)
{
    int32_t rc;
    osal_int_signal_t *the_signal;

    if (NULL == signal) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: signal is NULL\n", __func__);
        rc = AR_EBADPARAM;
        goto done;
    }

    the_signal = (osal_int_signal_t *)signal;
    rc = pthread_mutex_lock(&the_signal->osal_mutex);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to acquire lock, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
        goto done;
    }

    the_signal->signalled = false;

    rc = pthread_mutex_unlock(&the_signal->osal_mutex);
    if (rc) {
        AR_LOG_ERR(AR_OSAL_SIGNAL_LOG_TAG,"%s: Failed to unlock, rc = %d\n", __func__, rc);
        rc = AR_EFAILED;
    }

done:
    return rc;
}
