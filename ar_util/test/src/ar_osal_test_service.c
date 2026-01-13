 /*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_types.h"
#include "ar_osal_signal.h"
#include "ar_osal_thread.h"
#include "ar_osal_error.h"
#include "ar_osal_test.h"
#include "ar_osal_log.h"
#include "ar_osal_servreg.h"
#include "ar_osal_sleep.h"
#include "ar_osal_sys_id.h"

#define THREADCOUNT  (4)

void* gh_srv_Threads[THREADCOUNT] = { NULL };
uint32_t ActiveThreads = 0;

uint32_t svc_cb_context = 0xFFFF;

void CreateTestThread(uint32_t thread_idx, ar_osal_thread_start_routine thread_func)
{
    ar_osal_thread_attr_t osal_thread_attr = { NULL, 1024, 0 };

    int32_t status = AR_EOK;

    status = ar_osal_thread_attr_init(&osal_thread_attr);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "ar_osal_thread_attr_init error: %d", status);
        return;
    }
    status = ar_osal_thread_create(
        &gh_srv_Threads[thread_idx],
        &osal_thread_attr,
        thread_func,
        NULL);
    if (status != AR_EOK)
    {
        AR_LOG_ERR(LOG_TAG, "ar_osal_thread_create, thread_idx(%d) error: %d", thread_idx, status);
        return;
    }
}

//Service listener callback for service state updates.
void service_state_cb(ar_osal_servreg_t servreg_handle, ar_osal_servreg_cb_event_type event_id,
    void *cb_context, void *payload, uint32_t payload_size)
{
    if (event_id == AR_OSAL_SERVICE_STATE_NOTIFY)
    {
        ar_osal_servreg_state_notify_payload_type *state = (ar_osal_servreg_state_notify_payload_type*)payload;
        if (state->service_state == AR_OSAL_SERVICE_STATE_DOWN)
        {
            AR_LOG_ERR(LOG_TAG, "service_state_cb Service UP servreg_handle(0x%x), service(%s) service_instance(%d) domain(%s) domain_instance(%d)",
                servreg_handle, state->service.name, state->service.instance_id, state->domain.name, state->domain.instance_id );
        }
        else if (state->service_state == AR_OSAL_SERVICE_STATE_UP)
        {
            AR_LOG_ERR(LOG_TAG, "service_state_cb Service DOWN servreg_handle(0x%x), service(%s) service_instance(%d) domain(%s) domain_instance(%d)",
                servreg_handle, state->service.name, state->service.instance_id, state->domain.name, state->domain.instance_id);
        }
        else
        {
            //error
            AR_LOG_ERR(LOG_TAG, "service_state_cb Service INVALID state!!!!");
        }
    }
    return;
}

//service provider to register service states
int32_t ServiceStateUpate(void *context)
{
    int32_t status = AR_EOK;
    ar_osal_servreg_t sHandle = NULL;
    ar_osal_servreg_entry_type svc_name = { "avs/audio", 0 };
    ar_osal_servreg_entry_type dmn_name[AR_SUB_SYS_ID_LAST] = { 0, 0 };
    uint32_t num_domains = 0;

    status = ar_osal_servreg_init();
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, "clientServiceListener ar_osal_servreg_init failed (0x%x)...", status);
        goto end;
    }

    status = ar_osal_servreg_get_domainlist(&svc_name, NULL, &num_domains);
    if (status == AR_ENOMEMORY && AR_SUB_SYS_ID_LAST  >= num_domains)
    {
        status = ar_osal_servreg_get_domainlist(&svc_name, dmn_name, &num_domains);
        if (AR_FAILED(status))
        {
            AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_get_domainlist failed, err: %d ", status);
            goto end;
        }

        for (uint8_t idx = 0; idx < num_domains; idx++)
        {
            AR_LOG_INFO(LOG_TAG, " ServiceStateUpate service_name:%s domain_name:%s ", svc_name.name, dmn_name[idx].name);
        }
    }

    svc_name.instance_id = dmn_name[AR_AUDIO_DSP].instance_id;

    sHandle = ar_osal_servreg_register(AR_OSAL_CLIENT_SERVICE_PROVIDER, NULL, NULL,
                                       &dmn_name[AR_AUDIO_DSP], &svc_name);
    if (NULL == sHandle)
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_register failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_set_state(sHandle, AR_OSAL_SERVICE_STATE_UP);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_set_state UP failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_set_state(sHandle, AR_OSAL_SERVICE_STATE_DOWN);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_set_state DOWN failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_set_state(sHandle, AR_OSAL_SERVICE_STATE_UP);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_set_state UP failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_set_state(sHandle, AR_OSAL_SERVICE_STATE_DOWN);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_set_state DOWN failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_deregister(sHandle);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " ServiceStateUpate ar_osal_servreg_deregister failed, err: %d ", status);
        goto end;
    }

    status = ar_osal_servreg_deinit();
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, "ServiceStateUpate ar_osal_servreg_deinit failed (0x%x)...", status);
        goto end;
    }
end:
    return status;
}

int32_t clientServiceListener(void *context)
{
    int32_t status = AR_EOK;
    ar_osal_servreg_t sHandle = NULL;
    ar_osal_servreg_entry_type svc_name = { "avs/audio", 0 };
    ar_osal_servreg_entry_type dmn_name[AR_SUB_SYS_ID_LAST] = { 0, 0 };
    uint32_t num_domains = 0;

    status = ar_osal_servreg_init();
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, "clientServiceListener ar_osal_servreg_init failed (0x%x)...", status);
        goto end;
    }

    status = ar_osal_servreg_get_domainlist(&svc_name, NULL, &num_domains);
    if (status == AR_ENOMEMORY && AR_SUB_SYS_ID_LAST >= num_domains)
    {
        status = ar_osal_servreg_get_domainlist(&svc_name, dmn_name, &num_domains);
        if (AR_FAILED(status))
        {
            AR_LOG_ERR(LOG_TAG, " clientServiceListener failed, err: %d ", status);
            goto end;
        }
    }

    svc_name.instance_id = dmn_name[AR_AUDIO_DSP].instance_id;

    sHandle = ar_osal_servreg_register(AR_OSAL_CLIENT_LISTENER, service_state_cb,
        (void*)&svc_cb_context, &dmn_name[AR_AUDIO_DSP], &svc_name);
    if (NULL == sHandle)
    {
        AR_LOG_ERR(LOG_TAG, " clientServiceListener ar_osal_servreg_register failed, err: %d ", status);
        goto end;
    }

    //create state update sim thread
    CreateTestThread(ActiveThreads++, ServiceStateUpate);

    //sleep for service to notify,before deregister.
    ar_osal_micro_sleep(300000);

    /* To test case client doesn`t deregister.
    status = ar_osal_servreg_deregister(sHandle);
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, " clientServiceListener ar_osal_servreg_deregister failed, err: %d ", status);
        goto end;
    }*/
    status = ar_osal_servreg_deinit();
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, "clientServiceListener ar_osal_servreg_deinit failed (0x%x)...", status);
        goto end;
    }
end:
    return status;
}

void ar_test_servreg_main()
{
    int32_t status = AR_EOK;
    int32_t test = 0;
    ar_osal_signal_t test_signal = NULL;
    ActiveThreads = 0;

    status = ar_osal_servreg_init();
    if (AR_FAILED(status))
    {
        AR_LOG_ERR(LOG_TAG, "ar_test_service_thread_main ar_osal_servreg_init failed (0x%x)...", status);
        goto end;
    }

    // create first thread to get domain list and register for service notification.
    CreateTestThread(ActiveThreads++, clientServiceListener);

    AR_LOG_INFO(LOG_TAG, "Main thread waiting for threads to exit...");
    for (uint32_t i = 0; i < ActiveThreads; i++)
    {
        status = ar_osal_thread_join_destroy(gh_srv_Threads[i]);
        if (AR_EOK != status)
        {
            AR_LOG_ERR(LOG_TAG, " Thread[%d] ar_osal_thread_join_destroy() failed, err: %d ", i, status);
        }
    }
    //deinit
    ar_osal_servreg_deinit();
end:
    return;
}

