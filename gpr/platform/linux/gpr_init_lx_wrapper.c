/*
 * gpr_init_lx_wrapper.c
 *
 * This file has implementation platform wrapper for the GPR datalink layer
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#define LOG_TAG "gpr_lx_wrapper"
#include <errno.h>
#include "gpr_api_i.h"
#include "gpr_lx.h"
#include <unistd.h>

#ifdef GPR_USE_CUTILS
#include <log/log.h>
#else
#include <syslog.h>
#ifndef ALOGD
#define ALOGD(fmt, arg...) syslog (LOG_NOTICE, fmt, ##arg)
#endif
#ifndef ALOGI
#define ALOGI(fmt, arg...) syslog (LOG_INFO, fmt, ##arg)
#endif
#ifndef ALOGE
#define ALOGE(fmt, arg...) syslog (LOG_ERR, fmt, ##arg)
#endif
#endif

#define GPR_NUM_PACKETS_TYPE 3

#define GPR_NUM_PACKETS_1 ( 100 )
#define GPR_DRV_BYTES_PER_PACKET_1 ( 512 )
#define GPR_NUM_PACKETS_2 ( 4 )
#define GPR_DRV_BYTES_PER_PACKET_2 ( 4096 )
#define GPR_NUM_PACKETS_3 ( 0 )
#define GPR_DRV_BYTES_PER_PACKET_3 ( 65536 )

#ifdef PLATFORM_SLATE
#undef GPR_NUM_PACKETS_2
#define GPR_NUM_PACKETS_2 ( 8 )

#undef GPR_NUM_PACKETS_3
#define GPR_NUM_PACKETS_3 ( 2 )
#endif

/*****************************************************************************
 * Global variables                                                          *
 ****************************************************************************/
/* GPR IPC table containing init,deinit functions for datalink layers depending on
domains a given src domain wishes to establish a link with and the availability
of shared memory */
struct ipc_dl_v2_t gpr_lx_ipc_dl_table[GPR_PL_NUM_TOTAL_DOMAINS_V];

struct gpr_packet_pool_info_v2_t gpr_lx_packet_pool_table[GPR_NUM_PACKETS_TYPE]={
   { GPR_HEAP_INDEX_DEFAULT, 0, 0, GPR_NUM_PACKETS_1, GPR_DRV_BYTES_PER_PACKET_1},
   { GPR_HEAP_INDEX_DEFAULT, 0, 0, GPR_NUM_PACKETS_2, GPR_DRV_BYTES_PER_PACKET_2},
   { GPR_HEAP_INDEX_DEFAULT, 1, 0, GPR_NUM_PACKETS_3, GPR_DRV_BYTES_PER_PACKET_3},
};

uint32_t num_domains = 0;

/*****************************************************************************
 * Local function definitions                                                *
 ****************************************************************************/

GPR_INTERNAL void update_gpr_ipc_table(char *drv_path, uint16_t domain_id,
                                        bool_t supp_shared_mem)
{
   int fd = 0;

   if (drv_path != NULL) {
       fd = access(drv_path, F_OK);
       if (fd == -1) {
           ALOGI("%s:%d driver path does not exists, err %d for %s\n", __func__, __LINE__, errno, drv_path);
           return;
       }
   }

   ALOGD("%s:%d num_dom %d %d\n", __func__, __LINE__, num_domains, domain_id);

   gpr_lx_ipc_dl_table[num_domains].domain_id = domain_id;
   gpr_lx_ipc_dl_table[num_domains].init_fn = ipc_dl_lx_init;
   gpr_lx_ipc_dl_table[num_domains].deinit_fn = ipc_dl_lx_deinit;
   gpr_lx_ipc_dl_table[num_domains].supports_shared_mem = supp_shared_mem;

   num_domains++;
}

GPR_INTERNAL uint32_t gpr_drv_init(void)
{
   ALOGD("GPR INIT START");
   uint32_t rc, domain_id;
   uint32_t num_packet_pools =
             sizeof(gpr_lx_packet_pool_table)/sizeof(gpr_packet_pool_info_v2_t);

   /* Reset to 0 to avoid wrong value when gpr_drv_init called multiple times due to failure */
   num_domains = 0;
   memset(&gpr_lx_ipc_dl_table[0], 0, (sizeof(struct ipc_dl_v2_t) * GPR_PL_NUM_TOTAL_DOMAINS_V));

   gpr_lx_ipc_dl_table[num_domains].domain_id = GPR_IDS_DOMAIN_ID_APPS_V;
   gpr_lx_ipc_dl_table[num_domains].init_fn = ipc_dl_local_init;
   gpr_lx_ipc_dl_table[num_domains].deinit_fn = ipc_dl_local_deinit;
   gpr_lx_ipc_dl_table[num_domains].supports_shared_mem = TRUE;

   num_domains++;

/*
 * ToDo: Update gpr init proc domain for ARE on APPS support to
 * GPR_IDS_DOMAIN_ID_APPS_V
 *
 * Modules and Containers in ACDB file does not support APPS PROC domain by
 * default and would require updating definitions for each module in ACDB
 * graph. Due to check in audioreach-engine (SPF) code that matches the
 * container proc domain and GPR proc domain, and existing container domain
 * being ADSP for container, initialize GPR with GPR_IDS_DOMAIN_ID_ADSP_V
 * domain ID instead of GPR_IDS_DOMAIN_ID_APPS_V to support use-cases for
 * ARE on APPS.
 * Update gpr init domain ID back to GPR_IDS_DOMAIN_ID_APPS_V once APPS
 * proc domain is supported for modules and container in ACDB data.
 */
#ifdef ARE_ON_APPS
   gpr_lx_ipc_dl_table[num_domains].domain_id = GPR_IDS_DOMAIN_ID_ADSP_V;
   gpr_lx_ipc_dl_table[num_domains].init_fn = ipc_dl_local_init;
   gpr_lx_ipc_dl_table[num_domains].deinit_fn = ipc_dl_local_deinit;
   gpr_lx_ipc_dl_table[num_domains].supports_shared_mem = TRUE;

   num_domains++;
   domain_id = GPR_IDS_DOMAIN_ID_ADSP_V;
#else
   update_gpr_ipc_table("/dev/aud_pasthru_adsp",
                           GPR_IDS_DOMAIN_ID_ADSP_V,
                           TRUE);
   update_gpr_ipc_table("/dev/aud_pasthru_modem",
                           GPR_IDS_DOMAIN_ID_MODEM_V,
                           TRUE);
   update_gpr_ipc_table("/dev/gpr_channel",
                           GPR_IDS_DOMAIN_ID_CC_DSP_V,
                           FALSE);
   domain_id = GPR_IDS_DOMAIN_ID_APPS_V;
#endif
   rc = gpr_drv_internal_init_v2(domain_id,
                                 num_domains,
                                 gpr_lx_ipc_dl_table,
                                 num_packet_pools,
                                 gpr_lx_packet_pool_table);
   ALOGD("GPR INIT EXIT");
   return rc;
}

GPR_INTERNAL uint32_t gpr_drv_init_domain(uint32_t domain_id)
{
   ALOGD("GPR INIT START, for domain id %d", domain_id);
   uint32_t rc;
   uint32_t num_packet_pools =
             sizeof(gpr_lx_packet_pool_table)/sizeof(gpr_packet_pool_info_v2_t);

   memset(&gpr_lx_ipc_dl_table[0], 0, (sizeof(struct ipc_dl_v2_t) * GPR_PL_NUM_TOTAL_DOMAINS_V));

   gpr_lx_ipc_dl_table[num_domains].domain_id = domain_id;
   gpr_lx_ipc_dl_table[num_domains].init_fn = ipc_dl_local_init;
   gpr_lx_ipc_dl_table[num_domains].deinit_fn = ipc_dl_local_deinit;
   gpr_lx_ipc_dl_table[num_domains].supports_shared_mem = TRUE;

   num_domains++;

   if (domain_id == GPR_IDS_DOMAIN_ID_APPS_V)
   {
      update_gpr_ipc_table("/dev/aud_pasthru_adsp",
                              GPR_IDS_DOMAIN_ID_ADSP_V,
                              TRUE);
      update_gpr_ipc_table("/dev/aud_pasthru_modem",
                              GPR_IDS_DOMAIN_ID_MODEM_V,
                              TRUE);
      update_gpr_ipc_table("/dev/gpr_channel",
                              GPR_IDS_DOMAIN_ID_CC_DSP_V,
                              FALSE);
   }
   else if (domain_id == GPR_IDS_DOMAIN_ID_APPS2_V)
   {
      update_gpr_ipc_table("/dev/aud_pasthru_apps",
                           GPR_IDS_DOMAIN_ID_ADSP_V,
                           TRUE);
   }

   rc = gpr_drv_internal_init_v2(domain_id,
                                 num_domains,
                                 gpr_lx_ipc_dl_table,
                                 num_packet_pools,
                                 gpr_lx_packet_pool_table);
   ALOGD("GPR INIT EXIT");
   return rc;
}
