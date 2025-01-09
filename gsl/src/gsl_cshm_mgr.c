/**
 * \file gsl_cshm_mgr.c
 *
 * \brief
 *      Manages client shared memory allocations in the system
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "gsl_intf.h"
#include "gsl_shmem_mgr.h"
#include "gsl_common.h"
#include "gsl_cshm_mgr.h"
#include "apm_memmap_api.h"
#include "apm_api.h"
#include "gpr_ids_domains.h"
#include "gpr_api_inline.h"
#include "ar_spf_cmd_api.h"

#define CLIENT_SHM_ENABLED
#ifdef CLIENT_SHM_ENABLED

typedef struct {
    /* Indicates cshm init done
    */
    bool is_init_done;
    /* Protects cshm info lock
    */
    ar_osal_mutex_t cshm_list_lock;
    /* Max number of cshm allocation can be done at init time. If this limit crosses
    * gsl init num_max_cshm_list * 2 number of info.
    */
    uint32_t num_max_cshm_list;
    /* Array of client memory info
    */
    cshm_info_t** cshm_info_list;
    /* Signal used to wait for responses from spf. Only one event can be sent at a time.
     */
    struct gsl_signal sig;
    /* Lock used in conjuction with above signal
     */
    ar_osal_mutex_t sig_lock;
} cshm_ctx_t;

static cshm_ctx_t cshm_ctx_glb;

struct gsl_apm_mem_map_global {
    struct apm_cmd_global_shared_mem_map_regions_t mmap_header;
    struct apm_shared_map_region_payload_t mmap_payload;
};



gsl_mem_id_t gsl_get_mem_id(cshm_info_t *cmem_info) {

    gsl_mem_id_t mem_id = 0;
    int index = 0;

    GSL_MUTEX_LOCK(cshm_ctx_glb.cshm_list_lock);
    for(index = 0; index < cshm_ctx_glb.num_max_cshm_list; index++) {
        if (!cshm_ctx_glb.cshm_info_list[index]){
            break;
        }
    }

    if (index == cshm_ctx_glb.num_max_cshm_list) {
        cshm_ctx_glb.num_max_cshm_list = cshm_ctx_glb.num_max_cshm_list * 2;
        GSL_INFO("max client list limit reached. Expanding max client list to %d",cshm_ctx_glb.num_max_cshm_list)
        cshm_info_t * mem_info_list = gsl_mem_zalloc(sizeof(cshm_info_t*) *
                                                    cshm_ctx_glb.num_max_cshm_list);
        if (mem_info_list ==   NULL  ) {
            GSL_ERR("Failed to allocate global context");
            cshm_ctx_glb.num_max_cshm_list = cshm_ctx_glb.num_max_cshm_list / 2;
            goto exit;
        }
        gsl_memcpy(mem_info_list, (sizeof(cshm_info_t*) * cshm_ctx_glb.num_max_cshm_list),
                    cshm_ctx_glb.cshm_info_list, sizeof(cshm_info_t*) *
                                                    cshm_ctx_glb.num_max_cshm_list);
        gsl_mem_free(cshm_ctx_glb.cshm_info_list);
        cshm_ctx_glb.cshm_info_list = mem_info_list;
    }
    mem_id = to_gsl_mem_id(index);
    cshm_ctx_glb.cshm_info_list[index] = cmem_info;

exit:
    GSL_MUTEX_UNLOCK(cshm_ctx_glb.cshm_list_lock);
    return mem_id;
}


static uint32_t gsl_cshm_gpr_callback(gpr_packet_t *packet, void *cb_data)
{
    uint32_t rc = AR_EOK;
    uint32_t master_proc = packet->src_domain_id;

    cb_data; /* Referencing to keep compiler happy */
    rc = gsl_signal_set(&cshm_ctx_glb.sig, GSL_SIG_EVENT_MASK_SPF_RSP,
            AR_EOK, packet);
    if (rc)
        __gpr_cmd_free(packet);

    /* do not free packet, it will be freed by waiter */
    return 0;
}

int32_t gsl_cshm_init(uint32_t num_client)
{
    int32_t rc = AR_EOK;

    if (cshm_ctx_glb.is_init_done == true) {
        GSL_INFO("init already done");
        rc = AR_EOK;
        goto exit;
    }
    if (num_client == 0)
        num_client = CSHM_DEFAULT_INIT_CLIENT_NUM;
    cshm_ctx_glb.num_max_cshm_list = num_client;
    cshm_ctx_glb.cshm_info_list = gsl_mem_zalloc(sizeof(cshm_info_t*) *cshm_ctx_glb.num_max_cshm_list);

    if (cshm_ctx_glb.cshm_info_list == NULL  ) {
        GSL_ERR("Failed to allocate global context %d", rc);
        goto exit;
    }

    rc = ar_osal_mutex_create(&cshm_ctx_glb.cshm_list_lock);
    if (rc) {
        GSL_ERR("ar mutex create failed %d", rc);
        goto free_ctxt;
    }
    rc = ar_osal_mutex_create(&cshm_ctx_glb.sig_lock);
    if (rc) {
        GSL_ERR("ar mutex create failed %d", rc);
        goto cleanup_cshm_lock;
    }
    rc = gsl_signal_create(&cshm_ctx_glb.sig,
                    &cshm_ctx_glb.sig_lock);
    if (rc) {
        GSL_ERR("ar signal create failed %d", rc);
        goto cleanup_sig_lock;
    }

    rc = __gpr_cmd_register(GSL_CSHMEM_SRC_PORT, gsl_cshm_gpr_callback, &cshm_ctx_glb);
    if (rc) {
        GSL_ERR("gpr cmd register failed %d", rc);
        goto cleanup_sig_lock;
    }
    cshm_ctx_glb.is_init_done = true;
    goto exit;

cleanup_sig_lock:
    ar_osal_mutex_destroy(cshm_ctx_glb.sig_lock);
cleanup_cshm_lock:
    ar_osal_mutex_destroy(cshm_ctx_glb.cshm_list_lock);
free_ctxt:
    if (cshm_ctx_glb.cshm_info_list != NULL  ) {
        gsl_mem_free(cshm_ctx_glb.cshm_info_list);
        cshm_ctx_glb.cshm_info_list =   NULL  ;
    }
exit:
    return rc;
}

int32_t gsl_cshm_deinit(void) {
    int32_t rc = AR_EOK;

    if (cshm_ctx_glb.is_init_done == false) {
        GSL_INFO("cshm not initilaized");
        rc = AR_EUNSUPPORTED;
    }

    __gpr_cmd_deregister(GSL_CSHMEM_SRC_PORT);

    if(cshm_ctx_glb.sig_lock) {
        ar_osal_mutex_destroy(cshm_ctx_glb.sig_lock);
        cshm_ctx_glb.sig_lock = NULL;
    }

    if(cshm_ctx_glb.cshm_list_lock) {
        ar_osal_mutex_destroy(cshm_ctx_glb.cshm_list_lock);
        cshm_ctx_glb.cshm_list_lock = NULL;
    }

    if(cshm_ctx_glb.cshm_info_list) {
        gsl_mem_free(cshm_ctx_glb.cshm_info_list);
        cshm_ctx_glb.cshm_info_list = NULL;
    }
    cshm_ctx_glb.num_max_cshm_list = 0;
    cshm_ctx_glb.is_init_done = false;
    return rc;
}

void gsl_cshm_handle_ssr(enum spf_ss_state_t state, uint32_t spf_ss_mask)
{
    if (!(GSL_GET_SPF_SS_MASK(AR_AUDIO_DSP) & spf_ss_mask)) {
        return; // SSR handling only for ADSP now
    }
    if (state == GSL_SPF_SS_STATE_DN) {
        gsl_signal_set(&cshm_ctx_glb.sig, GSL_SIG_EVENT_MASK_SSR, 0, NULL);
        /* mark all mem_id dirty*/
        for(int i = 0; i < cshm_ctx_glb.num_max_cshm_list; i++) {
            if (cshm_ctx_glb.cshm_info_list[i] != NULL) {
                 set_mem_id_dirty(cshm_ctx_glb.cshm_info_list[i], true);
                 GSL_DBG("marking dirty %d", cshm_ctx_glb.cshm_info_list[i]->mem_id);
            }
        }
    } else {
        gsl_signal_clear(&cshm_ctx_glb.sig, GSL_SIG_EVENT_MASK_SSR);
    }
}
bool gsl_check_mem_id_present(uint32_t mem_id)
{
    bool found = false;

    for(int i = 0; i < cshm_ctx_glb.num_max_cshm_list; i++) {
        if (cshm_ctx_glb.cshm_info_list[i] != NULL &&
           cshm_ctx_glb.cshm_info_list[i]->mem_id == mem_id) {
            found = true;
            break;
        }
    }
    return found;
}
int32_t gsl_add_mem_info(cshm_info_t *mem_info)
{
    int32_t rc = AR_EFAILED;
    int32_t index_found = cshm_ctx_glb.num_max_cshm_list;

    GSL_MUTEX_LOCK(cshm_ctx_glb.cshm_list_lock);
    for(int i = 0; i < cshm_ctx_glb.num_max_cshm_list; i++) {
        if (cshm_ctx_glb.cshm_info_list[i] == NULL) {
            index_found = i;
            cshm_ctx_glb.cshm_info_list[i]  = mem_info;
            rc = AR_EOK;
            break;
        }
    }
    if ( index_found == cshm_ctx_glb.num_max_cshm_list) {
        /** this case is not ever possible ever possible. New entry will be added already
         * while gsl_get_mem_id. Even if it'sreaching just return failure, can't do anything.
         */
    }
    GSL_MUTEX_UNLOCK(cshm_ctx_glb.cshm_list_lock);

exit:
    return rc;
}

cshm_info_t* gsl_get_mem_info(uint32_t index)
{
    if ( index >= 0 && index < cshm_ctx_glb.num_max_cshm_list) {
       return cshm_ctx_glb.cshm_info_list[index];
    }
    return NULL;
}

int32_t gsl_rem_mem_info(uint32_t index)
{
    int32_t rc = AR_EFAILED;

    if ( index >= 0 && index < cshm_ctx_glb.num_max_cshm_list &&
         cshm_ctx_glb.cshm_info_list[index] != NULL) {
        gsl_mem_free(cshm_ctx_glb.cshm_info_list[index]);
        cshm_ctx_glb.cshm_info_list[index] = NULL;
        rc = AR_EOK;
    }
    return rc;
}

static int32_t gsl_cshm_handle_rsp(gpr_packet_t *rsp, uint32_t expected_opcode)
{

    struct spf_cmd_basic_rsp *basic_rsp;
    int32_t rc = AR_EOK;

    switch (rsp->opcode) {
    case GPR_IBASIC_RSP_RESULT:
        basic_rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, rsp);
        switch (basic_rsp->opcode) {
        case APM_CMD_GLOBAL_SHARED_MEM_MAP_REGIONS:
        case APM_CMD_GLOBAL_SHARED_MEM_UNMAP_REGIONS :
        case AR_SPF_MSG_GLOBAL_SH_MEM:
            if (basic_rsp->status) {
                GSL_ERR("received failure %x from spf", basic_rsp->status);
                rc = AR_EFAILED;
            }
            break;
        default:
            GSL_ERR("unsupported opcode %d encountered in GPR SHMEM response",
                basic_rsp->opcode);
            rc = AR_EFAILED;
            break;
        };
        break;
    };

    if (expected_opcode != rsp->opcode) {
        GSL_ERR("Recieved unexpected rsp opcode %x, expected %x",
            rsp->opcode, expected_opcode);
        rc = AR_EUNEXPECTED;
    }
    __gpr_cmd_free(rsp);
    return rc;
}

int32_t gsl_cshm_map_to_spf(ar_shmem_info *mem_info, uint32_t mem_id)
{
    struct gsl_apm_mem_map_global *mmap;
    apm_shared_map_region_payload_t *region;
    int32_t rc = AR_EOK;
    uint32_t tmp_spf_ss_mask;
    uint32_t sys_id = AR_MODEM_DSP;
    gpr_packet_t *send_pkt, *rsp_pkt =   NULL  ;
    uint8_t cma_client_data = 0;
    uint32_t master_proc_id = AR_AUDIO_DSP;

    /* if this is a CMA page we need to set client data on all gpr packets */
    if ((mem_info->flags & (AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
        << AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0)
            cma_client_data = GSL_GPR_CMA_FLAG_BIT;

    for ( int i =0 ; i < mem_info->num_sys_id; i++) {
        if (!gsl_spf_ss_state_get(mem_info->sys_id[i].proc_id))
            continue;
        rc = gsl_allocate_gpr_packet(APM_CMD_GLOBAL_SHARED_MEM_MAP_REGIONS, GSL_CSHMEM_SRC_PORT,
                APM_MODULE_INSTANCE_ID, sizeof(*mmap) + sizeof(*region), 0, master_proc_id,
                &send_pkt);
        if (rc) {
            GSL_ERR("Failed to allocate shmem map pkt %d", rc);
            goto exit;
        }
        /*
         * Set client_data based on is_offset flag, this tells gpr in kernel to
         * replace the MSW/LSW fields in the MMAP with actual physical address
         * instead of the handle that got returned from osal, this is a hack to
         * get around linux limitation where PA cannot be returned to
         * user-space from kernel
         */

        mmap = GPR_PKT_GET_PAYLOAD(struct gsl_apm_mem_map_global, send_pkt);

        mmap->mmap_header.shmem_id = mem_id;
        mmap->mmap_header.mem_pool_id = APM_MEMORY_MAP_SHMEM8_4K_POOL;
        mmap->mmap_header.num_regions = 1;
        mmap->mmap_header.property_flag = 0;
        if (mem_info->cache_type == AR_SHMEM_UNCACHED)
            mmap->mmap_header.property_flag |=
                APM_MEMORY_MAP_BIT_MASK_IS_UNCACHED;
        mmap->mmap_header.property_flag |= mem_info->index_type <<
            APM_MEMORY_MAP_SHIFT_IS_OFFSET_MODE;
        mmap->mmap_header.property_flag |= mem_info->mem_type <<
            APM_MEMORY_MAP_SHIFT_IS_VIRTUAL;
        /*TODO: kernal mapping*/
        mmap->mmap_payload.shm_addr_lsw = mem_info->ipa_lsw;
        mmap->mmap_payload.shm_addr_msw = mem_info->ipa_msw;
        mmap->mmap_payload.mem_size_bytes = mem_info->buf_size;

        send_pkt->client_data |= cma_client_data;

        GSL_LOG_PKT("send_pkt", GSL_CSHMEM_SRC_PORT, send_pkt,
            sizeof(*send_pkt) +    sizeof(*mmap),   NULL  , 0);
        rc = gsl_send_spf_cmd(&send_pkt, &cshm_ctx_glb.sig, &rsp_pkt);
        if (rc) {
            GSL_ERR("send spf cmd failed with err %d", rc);
            if (rsp_pkt)
                __gpr_cmd_free(rsp_pkt);
            goto exit;
        }
        if (!rsp_pkt) {
            GSL_ERR("Received   NULL   response packet");
            rc = AR_EUNEXPECTED;
            goto exit;
        }

        rc = gsl_cshm_handle_rsp(rsp_pkt, GPR_IBASIC_RSP_RESULT);
        if (rc) {
            GSL_ERR("handle shmem response failed %d", rc);
            goto exit;
        }
    }

exit:
    return rc;
}

int32_t gsl_cshm_unmap_to_spf(ar_shmem_info *mem_info, uint32_t mem_id)
{
    struct apm_cmd_global_shared_mem_unmap_regions_t *payload;
    int32_t rc = AR_EOK;
    gpr_packet_t *send_pkt, *rsp_pkt =   NULL  ;
    uint8_t cma_client_data = 0;

    /* if this is a CMA page we need to set client data on all gpr packets */
    if ((mem_info->flags & (AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
        << AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG)) != 0)
        cma_client_data = GSL_GPR_CMA_FLAG_BIT;

    for ( int i =0 ; i < mem_info->num_sys_id; i++) {
        /* if the DSP is down silently skip unmap */
        if (!gsl_spf_ss_state_get(mem_info->sys_id[i].proc_id))
            continue;

        rc = gsl_allocate_gpr_packet(APM_CMD_GLOBAL_SHARED_MEM_UNMAP_REGIONS,
            GSL_CSHMEM_SRC_PORT, APM_MODULE_INSTANCE_ID, sizeof(*payload), 0,
            mem_info->sys_id[i].proc_id, &send_pkt);
        if (rc) {
            GSL_ERR("Failed to allocate GPR packet %d", rc);
            goto exit;
        }
        payload = GPR_PKT_GET_PAYLOAD(
            struct apm_cmd_global_shared_mem_unmap_regions_t, send_pkt);
        payload->shmem_id = mem_id;

        send_pkt->client_data |= cma_client_data;

        GSL_LOG_PKT("send_pkt", GSL_CSHMEM_SRC_PORT, send_pkt,
            sizeof(*send_pkt) +    sizeof(*payload),   NULL  , 0);
        rc = gsl_send_spf_cmd(&send_pkt, &cshm_ctx_glb.sig, &rsp_pkt);
        if (rc || !rsp_pkt) {
            if (rsp_pkt)
                __gpr_cmd_free(rsp_pkt);
            goto exit;
        }
        rc = gsl_cshm_handle_rsp(rsp_pkt, GPR_IBASIC_RSP_RESULT);
        if (rc) {
            GSL_ERR("handle shmem response failed %d", rc);
            goto exit;
        }
    }
exit:
    return rc;
}

int32_t gsl_send_glb_msg_to_spf(uint32_t  mem_id, uint32_t  offset, uint32_t  length,
        uint32_t  miid, ar_shmem_info *mem_info, uint32_t prop_flag)
{
    int32_t rc = AR_EOK;
    ar_spf_msg_global_sh_mem_t *payload;
    gpr_packet_t *send_pkt, *rsp_pkt = NULL;
    uint8_t cma_client_data = 0;

    for ( int i =0 ; i < mem_info->num_sys_id; i++) {
        /* if the DSP is down silently skip MSG */
        if (!gsl_spf_ss_state_get(mem_info->sys_id[i].proc_id)) {
            continue;
        }
        rc = gsl_allocate_gpr_packet(AR_SPF_MSG_GLOBAL_SH_MEM,
            GSL_CSHMEM_SRC_PORT, miid, sizeof(*payload), 0,
            mem_info->sys_id[i].proc_id, &send_pkt);
        if (rc) {
            GSL_ERR("Failed to allocate GPR packet %d", rc);
            goto exit;
        }
        payload = GPR_PKT_GET_PAYLOAD(
            struct ar_spf_msg_global_sh_mem_t, send_pkt);
        payload->shmem_id = mem_id;
        payload->property_flag = prop_flag;
        payload->shmem_addr_lsw = offset;
        payload->shmem_addr_msw = 0;
        payload->shmem_size = length;

        send_pkt->client_data |= cma_client_data;

        GSL_LOG_PKT("send_pkt", GSL_CSHMEM_SRC_PORT, send_pkt,
            sizeof(*send_pkt) +    sizeof(*payload),   NULL  , 0);
        rc = gsl_send_spf_cmd(&send_pkt, &cshm_ctx_glb.sig, &rsp_pkt);
        if (rc || !rsp_pkt) {
            if (rsp_pkt)
                __gpr_cmd_free(rsp_pkt);
            goto exit;
        }
        rc = gsl_cshm_handle_rsp(rsp_pkt, GPR_IBASIC_RSP_RESULT);
        if (rc) {
            GSL_ERR("handle shmem response failed %d", rc);
            goto exit;
        }
    }

exit:
    return rc;
}

int32_t gsl_cshm_alloc(uint32_t size, gsl_cshm_info_t *info)
{
    int32_t rc = AR_EOK;
    int32_t rc1 = AR_EOK;
    cshm_info_t *client_shm_info = NULL;
    ar_shmem_info *shmem_info = NULL;
    uint8_t sys_id = AR_SUB_SYS_ID_FIRST;
    uint32_t tmp_spf_ss_mask, spf_ss_mask;
    uint8_t sys_ids[AR_SUB_SYS_ID_LAST];

    GSL_INFO("Enter: Alloc with size: 0x%x", size);
    /* spf_ss_mask should come from use case, currently defaulting to ADSP */
    spf_ss_mask = GSL_GET_SPF_SS_MASK(AR_AUDIO_DSP);
    client_shm_info = gsl_mem_zalloc(sizeof(cshm_info_t));
    if (client_shm_info == NULL) {
        GSL_ERR("client shm info alloc failed with error %d", rc);
        goto exit;
    }
    client_shm_info->mem_id =(uint32_t)gsl_get_mem_id(client_shm_info);
    if (client_shm_info->mem_id == 0) {
        GSL_ERR("No mem_id available");
        goto free_client_shm_info;
    }

    client_shm_info->mem_info = gsl_mem_zalloc(sizeof(ar_shmem_info));
    if (client_shm_info->mem_info == NULL) {
        rc = -AR_ENORESOURCE;
        goto free_mem_id;
    }
    shmem_info = client_shm_info->mem_info;
    shmem_info->buf_size = (size + GSL_CSHM_MGR_PAGE_SZ - 1) &
        (~(GSL_CSHM_MGR_PAGE_SZ - 1));
    shmem_info->cache_type = (info->type == GSL_CSHM_CACHED) ? AR_SHMEM_CACHED : AR_SHMEM_UNCACHED;

    shmem_info->num_sys_id = 0;
    shmem_info->sys_id =  gsl_mem_zalloc(sizeof(uint8_t) *AR_SUB_SYS_ID_LAST);
    if (shmem_info->sys_id  == NULL) {
        rc = -AR_ENORESOURCE;
        goto free_shm_info;
    }
    /* populate ss_id_list based on spf_ss_mask */
    tmp_spf_ss_mask = spf_ss_mask;
    while (tmp_spf_ss_mask) {
        if (GSL_TEST_SPF_SS_BIT(spf_ss_mask, sys_id)) {
            shmem_info->sys_id[shmem_info->num_sys_id++].proc_id = sys_id;
        }
        ++sys_id;
        tmp_spf_ss_mask >>= 1;
    }
    /* set special flag for CMA allocations */
    if (info->flag & GSL_SHMEM_CMA)
        shmem_info->flags =
            AR_SHMEM_BIT_MASK_HW_ACCELERATOR_FLAG
            << AR_SHMEM_SHIFT_HW_ACCELERATOR_FLAG;
    client_shm_info->spf_ss_mask = spf_ss_mask;
    rc = ar_shmem_alloc(shmem_info);
    if (rc) {
        GSL_ERR("ar_shmem_alloc failed with error %d", rc);
        goto free_sys_id;
    }

    rc = gsl_cshm_map_to_spf(shmem_info, client_shm_info->mem_id);
    if (rc) {
        GSL_ERR("Failed to map page with spf error %d", rc);
        goto free_shm_mem;
    }
    rc = gsl_add_mem_info(client_shm_info);
    if (rc) {
        GSL_ERR("adding client info failed %d", rc);
        goto unmap_with_spf;
    }
    info->mem_id = client_shm_info->mem_id;
    info->fd = shmem_info->ipa_lsw;
    goto exit;


unmap_with_spf:
    if (shmem_info != NULL) {
        rc1 = gsl_cshm_unmap_to_spf(shmem_info, client_shm_info->mem_id);
        if (rc1) {
            GSL_ERR("unmapping shared memory with mem_id %d failed %d", client_shm_info->mem_id, rc1);
        }
    }
free_shm_mem:
    if (shmem_info != NULL)
        ar_shmem_free(shmem_info);
free_sys_id:
    if (shmem_info->sys_id != NULL)
        gsl_mem_free(shmem_info->sys_id);
free_shm_info:
    if (client_shm_info->mem_info != NULL)
        gsl_mem_free(client_shm_info->mem_info);
free_mem_id:
    rc1 = gsl_rem_mem_info(to_gsl_cshm_indx(client_shm_info->mem_id));
    if (rc1) {
        GSL_ERR("removing client info with mem_id %d failed %d", client_shm_info->mem_id, rc1);
        goto exit;
    }
    client_shm_info = NULL;
free_client_shm_info:
    if (client_shm_info != NULL)
        gsl_mem_free(client_shm_info);

exit:
    return rc;
}

int32_t gsl_cshm_dealloc(gsl_mem_id_t mem_id)
{
    int32_t rc = AR_EOK;
    cshm_info_t *client_shm_info = NULL;

    GSL_INFO("Enter: mem_id 0x%x", mem_id);
    if (!is_valid_gsl_mem_id(mem_id) ||
       (client_shm_info = gsl_get_mem_info(to_gsl_cshm_indx(mem_id))) == NULL) {
        GSL_ERR("invalid mem_id %d", mem_id);
        rc = AR_EBADPARAM;
        goto exit;
    }
    if (is_mem_id_dirty(client_shm_info)) {
         GSL_DBG("releasing a dirty shared memory with mem_id %d", mem_id);
        goto release_mem;
    }
    rc = gsl_cshm_unmap_to_spf(client_shm_info->mem_info, (uint32_t)mem_id);
    if (rc) {
        GSL_ERR("unmapping shared memory with mem_id %d failed %d", mem_id, rc);
        goto exit;
    }
release_mem:
    ar_shmem_free(client_shm_info->mem_info);
    gsl_mem_free(client_shm_info->mem_info->sys_id);
    gsl_mem_free(client_shm_info->mem_info);
    rc = gsl_rem_mem_info(to_gsl_cshm_indx(mem_id));
    if (rc) {
        GSL_ERR("removing client info with mem_id %d failed %d", mem_id, rc);
        goto exit;
    }

exit:
    return rc;
}

int32_t gsl_cshm_msg(gsl_mem_id_t  mem_id, uint32_t  offset, uint32_t  length, uint32_t  miid,
                    uint32_t prop_flag)
{
    int32_t rc = AR_EOK;
    cshm_info_t *client_shm_info = NULL;

    if (!is_valid_gsl_mem_id(mem_id) ||
        (client_shm_info = gsl_get_mem_info(to_gsl_cshm_indx(mem_id))) == NULL) {
        GSL_ERR("invalid mem_id 0x%x", mem_id);
        rc = AR_EBADPARAM;
        goto exit;
    }
    if (is_mem_id_dirty(client_shm_info)) {
        rc = gsl_cshm_map_to_spf(client_shm_info->mem_info, client_shm_info->mem_id);
        if (rc) {
            GSL_ERR("Failed to map page with spf error %d", rc);
            goto exit;
        }
        GSL_DBG("dirty mem_id %d mapping is success", mem_id);
        set_mem_id_dirty(client_shm_info, false);
    }
    rc = gsl_send_glb_msg_to_spf((uint32_t)mem_id, offset, length, miid,client_shm_info->mem_info,
                        prop_flag);
    if (rc) {
        GSL_ERR("unmapping shared memory with mem_id %d failed %d", mem_id, rc);
        goto exit;
    }
exit:
    return rc;
}

#else
int32_t gsl_cshm_alloc(uint32_t size, gsl_cshm_info_t *info)
{
    GSL_ERR("Client shared memory feature is disabled");
    return AR_EUNSUPPORTED;
}
int32_t gsl_cshm_dealloc(gsl_mem_id_t mem_id)
{
    GSL_ERR("Client shared memory feature is disabled");
    return AR_EUNSUPPORTED;
}
int32_t gsl_cshm_msg(gsl_mem_id_t  mem_id, uint32_t  offset, uint32_t  length, uint32_t  miid,
                    uint32_t prop_flag)
{
    GSL_ERR("Client shared memory feature is disabled");
    return AR_EUNSUPPORTED;
}
int32_t gsl_cshm_init(uint32_t num_client)
{
    GSL_ERR("Client shared memory feature is disabled");
    return AR_EUNSUPPORTED;
}
void gsl_cshm_handle_ssr(enum spf_ss_state_t state, uint32_t spf_ss_mask)
{
    return;
}
#endif