#ifndef GSL_MSG_BUILDER_H
#define GSL_MSG_BUILDER_H
/**
 * \file gsl_mem_mgr.h
 *
 * \brief
 *   Constructs message that is to be sent to Spf.
 *   Allocates shared memory or does non shared memory operations
 *   depending on the availability of shared memory b/n GSL & SPF domain.
 *
 *   GSL sessions
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "gsl_shmem_mgr.h"
#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "gpr_packet.h"

typedef struct gsl_msg {
	gpr_packet_t *gpr_packet;
	struct gsl_shmem_alloc_data shmem;
	uint8_t *payload;
	uint32_t proc_id;
} gsl_msg_t;

int32_t gsl_msg_builder_init(uint32_t num_master_procs, uint32_t *master_procs);

int32_t gsl_msg_builder_deinit(void);

/* In scenarios, where shared memory availability is mandatory (Ex: persist cal)
 * Use APIs provided by gsl_shmem_mgr.
 *
 * Allocate shared memory & GPR packet
 */
int32_t gsl_msg_alloc(uint32_t opcode, uint32_t src_port,
		      uint32_t dst_port, uint32_t gpr_payload_size,
		      uint32_t token, uint32_t dest_domain,
		      uint32_t oob_payload_size, bool_t force_inband,
		      gsl_msg_t *msg);

/* In scenarios, where shared memory availability is mandatory (Ex: persist cal)
 * Use APIs provided by gsl_shmem_mgr.
 *
 * Allocate GPR packet & shared memory using extra flags
 */
int32_t gsl_msg_alloc_ext(uint32_t opcode, uint32_t src_port,
			  uint32_t dst_port, uint32_t gpr_payload_size,
			  uint32_t token, uint32_t dest_domain,
			  uint32_t oob_payload_size, bool_t force_inband,
			  uint32_t spf_ss_mask, uint32_t flags,
			  uint32_t platform_info, gsl_msg_t *msg);

/* Free gsl msg */
int32_t gsl_msg_free(gsl_msg_t *msg);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif
