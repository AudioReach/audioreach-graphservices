/**
 *
 * \file ar_osal_shmem_ap.c
 *
 * \brief
 * This file has implementation for shared memory implementation for ARM master processor.
 *
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include "ar_osal_shmem.h"
#include "ar_osal_shmem_ap.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
/*Memory pointer to be 4K aligned for ADSP, MDSP,SDSP and CDSP */
#define SHMEM_4K_ALIGNMENT (4096)
/**
 * \brief ar_shmem_validate_sys_id
 * internal function to validate supported SYS IDs.
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 */
static int32_t ar_shmem_validate_sys_id(uint8_t num_sys_id, ar_shmem_proc_info *sys_id)
{
    int32_t status = AR_EOK;

    if (0 == num_sys_id || NULL == sys_id)
        return AR_EBADPARAM;

    for (uint8_t i = 0; i < num_sys_id; ++i) {
        if (AR_APSS != sys_id[i].proc_id) {
            status = AR_EBADPARAM;
            break;
        }
    }

    return status;
}
/*
 *\brief ar_shmem_init
 * initialize shared memory interface.
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 */
int32_t ar_shmem_ap_init(void)
{
   return AR_EOK;
}
/*
 * \brief Allocates shared memory.
 * Only non cached memory allocation supported.
 * Size if multiple of 4KB and the returned is aligned to 4KB boundary.
 * Buffer start address should be atleast 64bit multiple aligned.
 *
 * \param[in_out] info: pointer to ar_shmem_info.
 *
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 *
 */
int32_t ar_shmem_ap_alloc(_Inout_ ar_shmem_info *info)
{
   int32_t status = AR_EOK;
   void   *p      = 0;
   if (NULL == info || 0 == info->buf_size)
   {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: info(NULL)\nbuf_size(0) passed");
      status = AR_EBADPARAM;
      goto end;
   }
   if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id, info->sys_id))
   {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: invalid sys_id(%d) passed", info->sys_id);
      status = AR_EBADPARAM;
      goto end;
   }
   info->ipa_lsw    = 0;
   info->ipa_msw    = 0;
   info->metadata   = 0;
   info->pa_lsw     = 0;
   info->pa_msw     = 0;
   info->index_type = AR_SHMEM_BUFFER_ADDRESS;
   info->mem_type   = AR_SHMEM_VIRTUAL_MEMORY;
   if (0 != posix_memalign(&p, SHMEM_4K_ALIGNMENT, info->buf_size)) {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: posix_memalign failed");
      status = AR_ENOMEMORY;
      goto end;
   }
   info->vaddr = p;
   AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "vaddr(0x%p)", info->vaddr);
   if (NULL == info->vaddr)
   {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: no memory available");
      status = AR_ENOMEMORY;
      goto end;
   }
   /*validate address for 64 byte alignment */
   if ((uint64_t)info->vaddr % SHMEM_4K_ALIGNMENT)
   {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: 4k alignment check failed vaddr(0x%p)", info->vaddr);
      free(info->vaddr);
      info->vaddr = NULL;
      status      = AR_EUNEXPECTED;
      goto end;
   }
   info->pa_lsw = info->ipa_lsw = (uint32_t)(uintptr_t)info->vaddr;
   info->pa_msw = info->ipa_msw = (uint32_t)((uint64_t)((uintptr_t)(info->vaddr)) >> 32);
   AR_LOG_VERBOSE(AR_OSAL_SHMEM_LOG_TAG,
                  " SHMEM: "
                  "cache_type(0x%x)\nmemory_type(0x%x)\nindex_type(0x%x)\nbuf_size(0x%x)\nvaddr(0x%p)\nstatus(0x%x) ",
                  info->cache_type,
                  info->mem_type,
                  info->index_type,
                  info->buf_size,
                  info->vaddr,
                  status);
end:
   return status;
}
/*
 * Frees shared memory.
 *
 * \param[in] info: pointer to ar_shmem_info.
 *
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 */
int32_t ar_shmem_ap_free(_In_ ar_shmem_info *info)
{
   int32_t status = AR_EOK;
   if (NULL == info || NULL == info->vaddr)
   {
      AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG, "Error: handle(NULL) passed");
      status = AR_EBADPARAM;
      goto end;
   }
   if (AR_EOK != ar_shmem_validate_sys_id(info->num_sys_id, info->sys_id))
   {
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
 *
 *\return
 * 0 -- Success
 * Nonzero -- Failure
 *
 */
int32_t ar_shmem_ap_map(ar_shmem_info *info)
{
   int32_t status = AR_EOK;
   if (NULL == info || 0 == info->buf_size || (0 == info->pa_lsw && 0 == info->pa_msw))
   {
      if (info)
      {
         AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG,
                    "Error: buf_size(0)\npa_lsw:0x%x\npa_msw:0x%x passed",
                    info->pa_lsw,
                    info->pa_msw);
      }
      else
      {
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
                  "SHMEM: "
                  "cache_type(0x%x)\nmemory_type(0x%x)\nbuf_size(0x%x)\nipa_lsw(0x%x)\nipa_msw(0x%x)\nstatus(0x%x) ",
                  info->cache_type,
                  info->mem_type,
                  info->buf_size,
                  info->ipa_lsw,
                  info->ipa_msw,
                  status);
end:
   return status;
}
/**
 *\brief Helps unmap the shared memory allocated externally with SMMU
 *
 *\param[in] info: pointer to ar_shmem_info.
 *
 *\return
 * 0 -- Success
 * Nonzero -- Failure
 *
 */
int32_t ar_shmem_ap_unmap(ar_shmem_info *info)
{
   int32_t status = AR_EOK;
   if (NULL == info || 0 == info->buf_size || (0 == info->pa_lsw && 0 == info->pa_msw))
   {
      if (info)
      {
         AR_LOG_ERR(AR_OSAL_SHMEM_LOG_TAG,
                    "Error: info(NULL)\nbuf_size(0)\npa_lsw:0x%x\npa_msw:0x%x passed",
                    info->pa_lsw,
                    info->pa_msw);
      }
      else
      {
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
 * 0 -- Success
 * Nonzero -- Failure
 */
int32_t ar_shmem_ap_hyp_assign_phys(ar_shmem_hyp_assign_phys_info *info)
{
   __UNREFERENCED_PARAM(info);
   /*no op*/
   return AR_EOK;
}
/*
 * \brief ar_shmem_deinit.
 *
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 */
int32_t ar_shmem_ap_deinit(void)
{
   return AR_EOK;
}
/**
 * \brief ar_shmem_get_uid.
 * Get associated unique identifier(UID) for the shared memory
 * pointed by alloc_handle, platform which doesn`t support UID
 * should return alloc_handle as UID with expectation of
 * alloc_handle being unique.
 *
 * \param[in] alloc_handle: handle for the shared memory.
 * \param[out] uid: unique identifier to the shmem.
 * \return
 * 0 -- Success
 * Nonzero -- Failure
 */
int32_t ar_shmem_ap_get_uid(uint64_t alloc_handle, uint64_t *uid)
{
   int32_t status = AR_EFAILED;
   if (NULL != uid)
   {
      *uid   = alloc_handle;
      status = AR_EOK;
   }
   return status;
}
