/**
 * \file gsl_msg_builder.c
 *
 * \brief
 *   Manages memory that is to be sent to Spf.
 *   Allocates shared memory or does non shared memory operations
 *   depending on the availability of shared memory b/n GSL & SPF domain.
 *
 *   GSL sessions
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "gsl_msg_builder.h"
#include "gsl_shmem_mgr.h"
#include "gpr_api_inline.h"
#include "ar_osal_sys_id.h"
#include "gsl_common.h"

static bool_t supports_shared_mem[AR_SUB_SYS_ID_LAST+1] = {FALSE};

int32_t gsl_msg_free(gsl_msg_t *msg)
{
	if (!msg)
		return AR_EBADPARAM;

	if (msg->shmem.handle != NULL) {
		gsl_shmem_free(&msg->shmem);
		msg->shmem.handle = NULL;
	}

	if (msg->gpr_packet) {
		__gpr_cmd_free(msg->gpr_packet);
		msg->gpr_packet = NULL;
	}

	return AR_EOK;
}

/* Allocate shared memory & GPR packet */
int32_t gsl_msg_alloc(uint32_t opcode, uint32_t src_port,
		      uint32_t dst_port, uint32_t gpr_payload_size,
		      uint32_t token, uint32_t dest_domain,
		      uint32_t oob_payload_size, bool_t force_inband,
		      gsl_msg_t *msg)
{
	return gsl_msg_alloc_ext(opcode, src_port, dst_port, gpr_payload_size,
				 token, dest_domain, oob_payload_size, force_inband,
				 GSL_GET_SPF_SS_MASK(dest_domain), 0, 0, msg);
}

int32_t gsl_msg_alloc_ext(uint32_t opcode, uint32_t src_port,
			  uint32_t dst_port, uint32_t gpr_payload_size,
			  uint32_t token, uint32_t dest_domain,
			  uint32_t oob_payload_size, bool_t force_inband,
			  uint32_t spf_ss_mask, uint32_t flags,
			  uint32_t platform_info, gsl_msg_t *msg)
{
	int32_t rc = AR_EOK;

	if (!msg) {
		rc = AR_EBADPARAM;
		goto exit;
	}

	if (force_inband ||
	    (!supports_shared_mem[dest_domain])) {
		rc = gsl_allocate_gpr_packet(opcode, src_port, dst_port,
					     gpr_payload_size + oob_payload_size,
					     token, dest_domain,
					     &msg->gpr_packet);

		if (rc) {
			GSL_ERR("Failed to allocate gpr packet of size %d",
				gpr_payload_size + oob_payload_size);
			goto exit;
		}

		msg->payload = GPR_PKT_GET_PAYLOAD(uint8_t, msg->gpr_packet);
		gsl_memset(msg->payload, 0, (size_t)gpr_payload_size + oob_payload_size);
		msg->payload += gpr_payload_size;
		gsl_memset(&msg->shmem, 0, sizeof(struct gsl_shmem_alloc_data));
	} else {
		rc =  gsl_allocate_gpr_packet(opcode, src_port, dst_port,
					      gpr_payload_size, token,
					      dest_domain, &msg->gpr_packet);

		if (rc) {
			GSL_ERR("Failed to allocate gpr packet of size %d",
				gpr_payload_size);
			goto exit;
		}

		gsl_memset(&msg->shmem, 0, sizeof(struct gsl_shmem_alloc_data));

		if (oob_payload_size != 0) {
			rc = gsl_shmem_alloc_ext(oob_payload_size, spf_ss_mask, flags,
					platform_info, dest_domain, &msg->shmem);
			if (rc) {
				__gpr_cmd_free(msg->gpr_packet);
				GSL_ERR("Failed to allocate shared mem of size %d",
					oob_payload_size);
				goto exit;
			}
		}
		msg->payload = msg->shmem.v_addr;
	}

	msg->proc_id = dest_domain;
exit:
	return rc;
}

int32_t gsl_msg_builder_init(uint32_t num_master_procs,
			     uint32_t *master_procs)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0;

	for (; i < num_master_procs; i++)
		__gpr_cmd_is_shared_mem_supported(master_procs[i],
					&supports_shared_mem[master_procs[i]]);

	rc = gsl_shmem_init(num_master_procs, master_procs);

	return rc;
}

int32_t gsl_msg_builder_deinit(void)
{
	int32_t rc = AR_EOK;

	rc = gsl_shmem_deinit();

	return rc;
}
