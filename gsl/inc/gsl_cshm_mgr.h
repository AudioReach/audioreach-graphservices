#ifndef GSL_CSHM_MGR_H
#define GSL_CSHM_MGR_H
/**
 * \file gsl_cshm_mgr.h
 *
 * \brief
 *      Manages client shared memory allocations in the system
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include <stdint.h>
#include "ar_osal_shmem.h"
#include "ar_util_list.h"
#include "ar_osal_mutex.h"
#include "ar_osal_signal.h"
#include "ar_osal_error.h"
#include "ar_osal_sys_id.h"
#include "gsl_spf_ss_state.h"

/** Default number of clients supported during initilization.*/
#define CSHM_DEFAULT_INIT_CLIENT_NUM 50
/** Page size used by cshm manager.*/
#define GSL_CSHM_MGR_PAGE_SZ 4096
/** Returns true if shmem buffer uses offset mode.*/
#define GSL_SHMEM_IS_OFFSET_MODE(type) \
(((ar_shmem_buffer_index_type_t)(type)) == AR_SHMEM_BUFFER_OFFSET)
/** Source port identifier for client shmem communication.*/
#define GSL_CSHMEM_SRC_PORT 0x2009
/** Magic word to validate shmem region.GSL*/
#define GSL_CSHM_MAGIC_WORD  0x47534D
/** Mask for validating magic word.*/
#define GSL_MAGIC_WORD_MASK  0xFFFFFF
/** Bit shift used for cshm index encoding.*/
#define GSL_CSHM_IDX_SHIFT 24

struct cshm_info {
    /** unique identifier assigned to the shared memory region.*/
    uint32_t mem_id;
    /** metadata for shmem allocation from AR.*/
    ar_shmem_info *mem_info;
    /** Bitmask of subsystems. */
    uint32_t spf_ss_mask;
    /** Indicates if memory contens needs sync.*/
    bool dirty;
};

typedef struct cshm_info cshm_info_t;

static inline gsl_mem_id_t to_gsl_mem_id(uint8_t index)
{
    return (gsl_mem_id_t)((uintptr_t)(GSL_CSHM_MAGIC_WORD |
        (index << GSL_CSHM_IDX_SHIFT)));
}

static inline uint8_t to_gsl_cshm_indx(gsl_mem_id_t mem_id)
{
    return ((uintptr_t)mem_id >> GSL_CSHM_IDX_SHIFT) & 0xff;
}

static inline bool_t is_valid_gsl_mem_id(gsl_mem_id_t mem_id)
{
    if (((uintptr_t)mem_id & GSL_MAGIC_WORD_MASK) != GSL_CSHM_MAGIC_WORD) {
        return false;
    }

    return true;
}

static inline bool is_mem_id_dirty(cshm_info_t * info)
{
    return info->dirty;
}

static inline void set_mem_id_dirty(cshm_info_t * info, bool val)
{
    info->dirty = val;
}
bool gsl_check_mem_id_present(uint32_t mem_id);
static int32_t gsl_cshm_handle_rsp(gpr_packet_t *rsp, uint32_t expected_opcode);
int32_t gsl_cshm_unmap_to_spf(ar_shmem_info *mem_info, uint32_t mem_id);
int32_t gsl_cshm_map_to_spf(ar_shmem_info *mem_info, uint32_t mem_id);
int32_t gsl_send_glb_msg_to_spf(uint32_t  mem_id, uint32_t  offset, uint32_t  length,
        uint32_t  miid, ar_shmem_info *mem_info, uint32_t prop_flag);
void gsl_cshm_handle_ssr(enum spf_ss_state_t state, uint32_t spf_ss_mask);
#endif