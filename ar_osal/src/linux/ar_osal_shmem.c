/**
 *
 * \file ar_osal_shmem.c
 *
 * \brief
 *      This file has implementation for Virtual Address based shared memory allocation for DSP.

 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */


#include <stdlib.h>
#include "ar_osal_shmem.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"

#define  AR_OSAL_SHMEM_LOG_TAG     "AOSH"
/*Memory pointer to be 4K aligned for ADSP, MDSP,SDSP and CDSP */
#define  SHMEM_4K_ALIGNMENT       (4096)


/**
 * \brief ar_shmem_validate_sys_id
 *       internal function to validate supported SYS IDs.
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_validate_sys_id(_In_ uint8_t num_sys_id, _In_ uint8_t *sys_id)
{
    PAGED_FUNCTION();
    int32_t status = AR_EOK;
    if (0 == num_sys_id || NULL == sys_id)
    {
        status = AR_EBADPARAM;
        goto end;
    }

    for (uint8_t i = 0; i < num_sys_id; i++)
    {
        if (AR_AUDIO_DSP != sys_id[i] &&
            AR_MODEM_DSP != sys_id[i] &&
            AR_SENSOR_DSP != sys_id[i] &&
            AR_COMPUTE_DSP != sys_id[i] &&
            AR_APSS != sys_id[i] &&
            AR_APSS2 != sys_id[i])
        {
            status = AR_EBADPARAM;
            break;
        }
    }

end:
    return status;
}

/*
 *\brief ar_shmem_init
 *        initialize shared memory interface.
 * \return
 * 0 -- Success
 *  Nonzero -- Failure
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_init(void)
{
    PAGED_FUNCTION();
    return AR_EOK;
}

/*
 * \brief Allocates shared memory.
 *  Only non cached memory allocation supported.
 *  Size if multiple of 4KB and the returned is aligned to 4KB boundary.
 *  Buffer start address should be atleast 64bit multiple aligned.
 *
 * \param[in_out] info: pointer to ar_shmem_info.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 *
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_alloc(_Inout_ ar_shmem_info *info)
{
    PAGED_FUNCTION();
    int32_t status = AR_EOK;
    void *p = 0;

    if (NULL == info || 0 == info->buf_size) {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG,"Error: info(NULL)|buf_size(0) passed");
        status = AR_EBADPARAM;
        goto end;
    }

    if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id,info->sys_id)) {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: invalid sys_id(%d) passed", info->sys_id);
        status = AR_EBADPARAM;
        goto end;
    }

    info->ipa_lsw = 0;
    info->ipa_msw = 0;
    info->metadata = 0;
    info->pa_lsw = 0;
    info->pa_msw = 0;
    info->index_type = AR_SHMEM_BUFFER_ADDRESS;
    info->mem_type = AR_SHMEM_VIRTUAL_MEMORY;


    posix_memalign(&p, SHMEM_4K_ALIGNMENT,info->buf_size);
    info->vaddr = p;
    AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "vaddr(0x%p)", info->vaddr);
    if (NULL == info->vaddr)
    {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: no memory available");
        status = AR_ENOMEMORY;
        goto end;
    }
    /*validate address for 64 byte alignment */
    if ((uint64_t)info->vaddr % SHMEM_4K_ALIGNMENT) {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: 4k alignment check failed vaddr(0x%p)", info->vaddr);
        free(info->vaddr);
        info->vaddr = NULL;
        status = AR_EUNEXPECTED;
        goto end;
    }

    info->pa_lsw = info->ipa_lsw = (uint32_t)(uintptr_t)info->vaddr;
    info->pa_msw = info->ipa_msw = (uint32_t)((uint64_t)((uintptr_t)(info->vaddr)) >> 32);

    AR_LOG_VERBOSE(AR_OSAL_SHMEM_LOG_TAG, " SHMEM: cache_type(0x%x)|memory_type(0x%x)|index_type(0x%x)|buf_size(0x%x)|vaddr(0x%p)|status(0x%x) ",
        info->cache_type, info->mem_type, info->index_type, info->buf_size, info->vaddr, status);
end:
    return status;
}

/*
 * Frees shared memory.
 *
 * \param[in] info: pointer to ar_shmem_info.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_free(_In_ ar_shmem_info *info)
{
    PAGED_FUNCTION();
    int32_t status = AR_EOK;
    if (NULL == info || NULL == info->vaddr) {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: handle(NULL) passed");
        status = AR_EBADPARAM;
        goto end;
    }

    if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id, info->sys_id)) {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: invalid sys_id(%d) passed", info->sys_id);
        status = AR_EBADPARAM;
        goto end;
    }

    AR_LOG_VERBOSE(AR_OSAL_SHMEM_LOG_TAG, "SHMEM: freed(0x%p)", info->vaddr);
    free(info->vaddr);
    info->vaddr = NULL;

end:
    return status;
}

/**
 * \brief Helps map memory with SMMU an already allocated shared memory
 * for a give sub system.
 * Size should be multiple of 4KB boundary.
 * Buffer start address should be 64bit aligned.
 *
 * \param[in_out] info: pointer to ar_shmem_info.
 *                     required input parameters in ar_shmem_info
 *                     ar_shmem_info_t.cache_type
 *                     ar_shmem_info_t.buf_size
 *                     ar_shmem_info_t.mem_type
 *                     ar_shmem_info_t.pa_lsw
 *                     ar_shmem_info_t.pa_msw
 *                     ar_shmem_info_t.num_sys_id
 *                     ar_shmem_info_t.sys_id
 *                     required output parameters in ar_shmem_info
 *                     ar_shmem_info_t.ipa_lsw
 *                     ar_shmem_info_t.ipa_msw
 *
 *\return
 * 0 -- Success
 * Nonzero -- Failure
 *
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_map(ar_shmem_info *info)
{
    PAGED_FUNCTION();
    int32_t status = AR_EOK;

    if (NULL == info || 0 == info->buf_size
        || (0 == info->pa_lsw && 0 == info->pa_msw) )
    {
        if(info) {
            AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: buf_size(0)|pa_lsw:0x%x|pa_msw:0x%x passed",
                       info->pa_lsw, info->pa_msw);
        }
        else {
            AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: info(NULL)");
        }
        status = AR_EBADPARAM;
        goto end;
    }

    if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id, info->sys_id))
    {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: invalid sys_id(%d) passed", info->sys_id);
        status = AR_EBADPARAM;
        goto end;
    }

    info->ipa_lsw = info->pa_lsw; /*return pa to ipa*/
    info->ipa_msw = info->pa_msw;

    AR_LOG_VERBOSE(AR_OSAL_SHMEM_LOG_TAG,
                   "SHMEM: cache_type(0x%x)|memory_type(0x%x)|buf_size(0x%x)|ipa_lsw(0x%x)|ipa_msw(0x%x)|status(0x%x) ",
                   info->cache_type, info->mem_type, info->buf_size,
                   info->ipa_lsw, info->ipa_msw, status);
end:
    return status;
}

/**
 *\brief Helps unmap the shared memory allocated externally with SMMU
 *
 *\param[in] info: pointer to ar_shmem_info.
 *            required input parameters in ar_shmem_info
 *                     ar_shmem_info_t.cache_type
 *                     ar_shmem_info_t.buf_size
 *                     ar_shmem_info_t.mem_type
 *                     ar_shmem_info_t.pa_lsw
 *                     ar_shmem_info_t.pa_msw
 *                     ar_shmem_info_t.num_sys_id
 *                     ar_shmem_info_t.sys_id
 *
 *\return
 * 0 -- Success
 * Nonzero -- Failure
 *
 */
int32_t ar_shmem_unmap(ar_shmem_info *info)
{
    PAGED_FUNCTION();
    int32_t status = AR_EOK;

    if (NULL == info || 0 == info->buf_size
        || (0 == info->pa_lsw && 0 == info->pa_msw) )
    {
        if(info) {
            AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: info(NULL)|buf_size(0)|pa_lsw:0x%x|pa_msw:0x%x passed",
                       info->pa_lsw, info->pa_msw);
        }
        else {
            AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: info(NULL)");
        }
        status = AR_EBADPARAM;
        goto end;
    }

    if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id, info->sys_id))
    {
        AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: invalid sys_id(%d) passed", info->sys_id);
        status = AR_EBADPARAM;
        goto end;
    }

    /*no handling required*/
end:
    return status;
}

/**
 * Helps to hyp assign physical memory between source and destination sub systems.
 *
 * \param[in] info: info: pointer to ar_shmem_hyp_assign_phys_info.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_shmem_hyp_assign_phys(ar_shmem_hyp_assign_phys_info *info)
{
    PAGED_FUNCTION();
    __UNREFERENCED_PARAM(info);
    /*no op*/
    return AR_EOK;
}

/*
 * \brief ar_shmem_deinit.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
int32_t ar_shmem_deinit(void)
{
    PAGED_FUNCTION();
    return AR_EOK;
}


/**
 * \brief ar_shmem_get_uid.
 *        Get associated unique identifier(UID) for the shared memory
 *        pointed by alloc_handle, platform which doesn`t support UID
 *        should return alloc_handle as UID with expectation of
 *        alloc_handle being unique.
 *
 * \param[in]  alloc_handle: handle for the shared memory.
 * \param[out] uid: unique identifier to the shmem.
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_shmem_get_uid(uint64_t alloc_handle, uint64_t* uid)
{
    PAGED_FUNCTION();
    int32_t status = AR_EFAILED;

    if (NULL != uid)
    {
        *uid = alloc_handle;
        status = AR_EOK;
    }

    return status;
}
