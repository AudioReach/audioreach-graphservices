/**
 * \file gsl_dynamic_module_mgr.c
 *
 * \brief
 *      Manages the loading and unloading of Spf dynamic modules
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "gsl_dynamic_module_mgr.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "amdb_api.h"
#include "gpr_api.h"
#include "gpr_api_inline.h"
#include "gpr_ids_domains.h"
#include "gsl_common.h"
#include "acdb.h"
#include "apm_api.h"
#include "ar_osal_sys_id.h"
#include "gsl_shmem_mgr.h"
#include "gsl_spf_ss_state.h"

#define GSL_DYNAMIC_MODULE_MGR_PORT 0x2005

struct gsl_dyn_modules_ctxt {
	uint32_t num_dyn_modules;

	/*
	 * This is the payload sent from Spf as part of AMDB_CMD_RSP_LOAD_MODULES
	 * we keep the packet with us and dont free it back to GPR untill we send
	 * the unload modules command. This is because the response contains the
	 * handles that must be sent back during unload and the unload command
	 * to Spf takes the same payload
	 */
	struct gpr_packet_t *amdb_rsp[AR_SUB_SYS_ID_LAST + 1];
};

ar_osal_mutex_t rsp_signal_lock;
struct gsl_signal rsp_signal;
struct gsl_dyn_modules_ctxt *gsl_dyn_mod_mgr_ctxt[AR_SUB_SYS_ID_LAST + 1]
								      = {NULL};

static uint32_t gsl_dynamic_mod_mgr_gpr_cb(gpr_packet_t *packet, void *cb_data)
{
	struct spf_cmd_basic_rsp *rsp;
	uint32_t rc = AR_EOK;

	cb_data; /* Referencing to make compiler happy */

	switch (packet->opcode) {
	case GPR_IBASIC_RSP_RESULT:
		rsp = GPR_PKT_GET_PAYLOAD(struct spf_cmd_basic_rsp, packet);
		if (rsp->opcode == AMDB_CMD_REGISTER_MODULES ||
			rsp->opcode == AMDB_CMD_UNLOAD_MODULES ||
			rsp->opcode == AMDB_CMD_DEREGISTER_MODULES) {
			rc = gsl_signal_set(&rsp_signal,
				GSL_SIG_EVENT_MASK_SPF_RSP, rsp->status, packet);
			/* do not free packet here as it will be freed by waiter */
		} else {
			__gpr_cmd_free(packet);
		}
		break;
	case AMDB_CMD_RSP_LOAD_MODULES:
		rc = gsl_signal_set(&rsp_signal,
			GSL_SIG_EVENT_MASK_SPF_RSP, 0, packet);
		/* do not free packet here as it will be freed by waiter */
		break;
	default:
		__gpr_cmd_free(packet);
		break;
	}

	if (rc)
		__gpr_cmd_free(packet);

	return AR_EOK;
}

/*
 * initialize the spf dynamic modules manager
 * @param[in] rsp_signal signal used to wait for responses from spf, the
 * signal should be created and initialized by caller
 */
int32_t gsl_dynamic_module_mgr_init(uint32_t num_master_procs,
				    uint32_t *master_procs)
{
	int32_t rc = AR_EOK;
	uint32_t i = 0;
	uint32_t j = 0;
	bool_t is_shared_mem_supported = TRUE;

	if (!master_procs) {
		GSL_ERR("Invalid argument master_procs");
		rc = AR_EBADPARAM;
		goto exit;
	}

	for (; i < num_master_procs; i++) {
		__gpr_cmd_is_shared_mem_supported(master_procs[i],
						  &is_shared_mem_supported);

		if (!is_shared_mem_supported)
			continue;

		gsl_dyn_mod_mgr_ctxt[master_procs[i]] =
				gsl_mem_zalloc(sizeof(struct gsl_dyn_modules_ctxt));

		if (!gsl_dyn_mod_mgr_ctxt[master_procs[i]]) {
			GSL_ERR("Unable to allocate memory");
			goto free_ctxt;
		}

		gsl_memset(gsl_dyn_mod_mgr_ctxt[master_procs[i]]->amdb_rsp, 0,
			   (AR_SUB_SYS_ID_LAST + 1) * sizeof(uintptr_t));
	}

	rc = ar_osal_mutex_create(&rsp_signal_lock);
	if (rc) {
		GSL_ERR("ar_osal_mutex_init failed %d", rc);
		goto free_ctxt;
	}

	rc = gsl_signal_create(&rsp_signal, &rsp_signal_lock);
	if (rc) {
		GSL_ERR("signal create failed %d", rc);
		goto destroy_lock;
	}

	rc = __gpr_cmd_register(GSL_DYNAMIC_MODULE_MGR_PORT,
			gsl_dynamic_mod_mgr_gpr_cb, gsl_dyn_mod_mgr_ctxt);
	if (rc) {
		GSL_ERR("gpr register failed");
		goto destroy_signal;
	}

	return rc;

destroy_signal:
	gsl_signal_destroy(&rsp_signal);
destroy_lock:
	ar_osal_mutex_destroy(rsp_signal_lock);
free_ctxt:
	for (j = 0; j < i; j++) {
		gsl_mem_free(gsl_dyn_mod_mgr_ctxt[j]);
		gsl_dyn_mod_mgr_ctxt[j] = NULL;
	}
exit:
	return rc;
}

int32_t gsl_dynamic_module_mgr_deinit(void)
{
	uint32_t i = 0;

	__gpr_cmd_deregister(GSL_DYNAMIC_MODULE_MGR_PORT);

	for (; i <= AR_SUB_SYS_ID_LAST; i++) {
		if (gsl_dyn_mod_mgr_ctxt[i]) {
			gsl_mem_free(gsl_dyn_mod_mgr_ctxt[i]);
			gsl_dyn_mod_mgr_ctxt[i] = NULL;
		}
	}

	gsl_signal_destroy(&rsp_signal);
	ar_osal_mutex_destroy(rsp_signal_lock);

	return AR_EOK;
}

static int32_t gsl_do_register_dynamic_modules(uint32_t master_proc,
	bool_t dereg, gsl_acdb_handle_t handle)
{
	uint32_t reg_data_offset = 0, i = 0, rc = AR_EOK, total_reg_data_sz = 0;
	struct gsl_shmem_alloc_data shmem_params;
	AcdbAmdbDbHandle amdb_db_req;
	AcdbBlob acdb_blob_rsp;
	apm_cmd_header_t *apm_hdr;
	uint64_t tmp_spf_addr = 0;
	gpr_packet_t *send_pkt = NULL;
	uint32_t spf_opcode = AMDB_CMD_REGISTER_MODULES;
	uint32_t acdb_cmdid = ACDB_CMD_GET_AMDB_REGISTRATION_DATA_V2;
	uint32_t found_proc_ids = 0x0;

	if (dereg) {
		spf_opcode = AMDB_CMD_DEREGISTER_MODULES;
		acdb_cmdid = ACDB_CMD_GET_AMDB_DEREGISTRATION_DATA_V2;
	}
	/*
	 * loop computes the size for module registration data for all proc_ids
	 */
	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; ++i) {

		/* if the current proc_id is not supported, skip */
		if (!gsl_spf_ss_state_is_ss_supported(master_proc, i))
			continue;

		amdb_db_req.proc_id = i;
		amdb_db_req.acdb_handle = handle;
		acdb_blob_rsp.buf_size = 0;
		acdb_blob_rsp.buf = NULL;
		rc = acdb_ioctl(acdb_cmdid, &amdb_db_req, sizeof(amdb_db_req),
			&acdb_blob_rsp, sizeof(acdb_blob_rsp));
		if (rc != AR_EOK && rc != AR_ENOTEXIST) {
			GSL_ERR("acdb get amdb_registration data failed %d", rc);
			goto exit;
		}

		if (rc == AR_ENOTEXIST || acdb_blob_rsp.buf_size == 0) {
			/*
			 * no dynamic module related registration data exists for this
			 * module, move on to next proc_id
			 */
			rc = AR_EOK;
			continue;
		}

		set_bit(found_proc_ids, (i - 1));
		GSL_DBG("proc id: %d, found proc bit field: %d", i, found_proc_ids);

		/* 8 byte alignment required by Spf */
		total_reg_data_sz += GSL_ALIGN_8BYTE(acdb_blob_rsp.buf_size);
	}

	if (total_reg_data_sz > 0) {
		rc = gsl_shmem_alloc(total_reg_data_sz, master_proc, &shmem_params);
		if (rc)
			goto exit;
	} else {
		/* no  dynamic registration data so we can skip */
		goto exit;
	}

	/* for every proc_id query and register dynamic modules */
	reg_data_offset = 0;
	for (i = AR_SUB_SYS_ID_FIRST; i <= AR_SUB_SYS_ID_LAST; ++i) {

		/* if the current proc_id is not supported, skip */
		if (!gsl_spf_ss_state_is_ss_supported(master_proc, i))
			continue;

		if (get_bit(found_proc_ids, i - 1) == 0) {
			GSL_DBG("skipping proc id: %d, found proc bit field: %d",
				i, found_proc_ids);
			continue;
		}

		amdb_db_req.proc_id = i;
		amdb_db_req.acdb_handle = handle;
		acdb_blob_rsp.buf = (uint8_t *)shmem_params.v_addr + reg_data_offset;
		acdb_blob_rsp.buf_size = total_reg_data_sz; /* acdb returns fill sz */
		rc = acdb_ioctl(acdb_cmdid, &amdb_db_req, sizeof(amdb_db_req),
			&acdb_blob_rsp, sizeof(acdb_blob_rsp));
		if (rc == AR_ENOTEXIST) {
			/* continue to next proc id if no registration data */
			rc = AR_EOK;
			continue;
		}
		if (rc != AR_EOK) {
			GSL_ERR("acdb_ioctl get amdb registration data failed %d", rc);
			goto free_shmem;
		}
		if (acdb_blob_rsp.buf_size != 0) {
			/* send to spf */
			rc = gsl_allocate_gpr_packet(spf_opcode,
				GSL_DYNAMIC_MODULE_MGR_PORT, AMDB_MODULE_INSTANCE_ID,
				sizeof(*apm_hdr), 0, master_proc, &send_pkt);
			if (rc) {
				GSL_ERR("Failed to allocate GPR packet %d", rc);
				goto free_shmem;
			}

			apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, send_pkt);
			apm_hdr->mem_map_handle = shmem_params.spf_mmap_handle;
			tmp_spf_addr = shmem_params.spf_addr + reg_data_offset;
			apm_hdr->payload_address_lsw = (uint32_t)(tmp_spf_addr);
			apm_hdr->payload_address_msw = (uint32_t)(tmp_spf_addr >> 32);
			apm_hdr->payload_size = acdb_blob_rsp.buf_size;

			GSL_LOG_PKT("send_pkt", GSL_DYNAMIC_MODULE_MGR_PORT, send_pkt,
				sizeof(*send_pkt) + sizeof(*apm_hdr), acdb_blob_rsp.buf,
				acdb_blob_rsp.buf_size);
			rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt, &rsp_signal);
			if (rc) {
				GSL_ERR("Register modules cmd 0x%x failure:%d", spf_opcode, rc);
				goto free_shmem;
			}

			/* increment offset to be used in next loop iteration */
			reg_data_offset += GSL_ALIGN_8BYTE(acdb_blob_rsp.buf_size);
			total_reg_data_sz -= GSL_ALIGN_8BYTE(acdb_blob_rsp.buf_size);
		}
	}
free_shmem:
	gsl_shmem_free(&shmem_params);

exit:
	return rc;
}

/*
 * load bootup time modules to spf
 */
int32_t gsl_do_load_bootup_dyn_modules(uint32_t master_proc,
									gsl_acdb_handle_t handle)
{
	int32_t rc = AR_EOK;
	uint32_t proc_id  = AR_SUB_SYS_ID_FIRST;
	AcdbAmdbDbHandle amdb_db_req;
	AcdbBlob acdb_blob_rsp;
	apm_cmd_header_t *apm_hdr;
	uint8_t *spf_cmd = NULL;
	gpr_packet_t *p_rsp_pkt = NULL, *send_pkt = NULL;
	struct amdb_module_load_unload_t *load_cmd;

	if (gsl_dyn_mod_mgr_ctxt[master_proc] == NULL)
		goto exit;

	/* TODO: only register if master proc is booting up */
	rc = gsl_do_register_dynamic_modules(master_proc, FALSE, handle);
	if (rc) {
		GSL_ERR("failed to register dynamic modules %d", rc);
		goto exit;
	}

	/* TODO: loop over all sybsystems. This is temporary. Non-preloaded
	 * modules will be loaded by spf on demand
	 */
	for (; proc_id <= AR_SUB_SYS_ID_LAST; ++proc_id) {
		/*
		 * if the current proc_id is not supported, or we're handling SSR and
		 * this subsystem did NOT restart, skip
		 */
		if (!gsl_spf_ss_state_is_ss_supported(master_proc, proc_id))
			continue;

		/* query and load bootup time modules for current proc_id */
		amdb_db_req.proc_id = proc_id;
		amdb_db_req.acdb_handle = handle;

		/* first query is for size */
		acdb_blob_rsp.buf = NULL;
		acdb_blob_rsp.buf_size = 0;
		rc = acdb_ioctl(ACDB_CMD_GET_AMDB_BOOTUP_LOAD_MODULES_V2,
			&amdb_db_req, sizeof(amdb_db_req),
			&acdb_blob_rsp, sizeof(acdb_blob_rsp));
		if (rc != AR_EOK && rc != AR_ENOTEXIST) {
			GSL_ERR("acdb_ioctl failed %d", rc);
			goto exit;
		}

		if (rc == AR_ENOTEXIST || acdb_blob_rsp.buf_size == 0) {
			/* its possible that a proc_id contains no bootup time modules */
			rc = AR_EOK;
			continue;
		}

		/* allocate memory and query for blob */
		rc = gsl_allocate_gpr_packet(AMDB_CMD_LOAD_MODULES,
			GSL_DYNAMIC_MODULE_MGR_PORT, AMDB_MODULE_INSTANCE_ID,
			acdb_blob_rsp.buf_size + sizeof(*apm_hdr),
			0, master_proc, &send_pkt);
		if (rc) {
			GSL_ERR("Failed to allocate GPR packet %d", rc);
			goto exit;
		}

		spf_cmd = GPR_PKT_GET_PAYLOAD(uint8_t, send_pkt);
		apm_hdr = (apm_cmd_header_t *)spf_cmd;
		gsl_memset(apm_hdr, 0, sizeof(*apm_hdr));
		apm_hdr->payload_size = acdb_blob_rsp.buf_size;
		acdb_blob_rsp.buf = spf_cmd + sizeof(*apm_hdr);
		rc = acdb_ioctl(ACDB_CMD_GET_AMDB_BOOTUP_LOAD_MODULES_V2,
			&amdb_db_req, sizeof(amdb_db_req),
			&acdb_blob_rsp, sizeof(acdb_blob_rsp));
		if (rc) {
			GSL_ERR("acdb get amdb bootup load modules failed %d", rc);
			goto free_gpr_pkt;
		}

		GSL_LOG_PKT("send_pkt", GSL_DYNAMIC_MODULE_MGR_PORT, send_pkt,
			sizeof(*send_pkt) + acdb_blob_rsp.buf_size + sizeof(*apm_hdr),
			NULL, 0);
		/* send to spf */
		rc = gsl_send_spf_cmd(&send_pkt, &rsp_signal, &p_rsp_pkt);
		if (rc) {
			GSL_ERR("Load modules cmd 0x%x failure:%d",
				AMDB_CMD_LOAD_MODULES, rc);
			goto exit;
		}
		if (p_rsp_pkt) {
			load_cmd = GPR_PKT_GET_PAYLOAD(struct amdb_module_load_unload_t,
				p_rsp_pkt);
			if (load_cmd->error_code != AR_EOK) {
				GSL_ERR("load cmd failed: spf status %d",
					load_cmd->error_code);
				rc = AR_EFAILED;
				__gpr_cmd_free(p_rsp_pkt);
				goto undo_module_registration;
			}

			/* store the handles to be used in unload */
			if (gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id])
				__gpr_cmd_free(
				      gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id]);
			gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id] = p_rsp_pkt;
		}
	}

	goto exit;
undo_module_registration:
	GSL_ERR("Deregistering modules due to load modules failure");
	gsl_do_register_dynamic_modules(master_proc, true, handle);
	goto exit;

free_gpr_pkt:
	__gpr_cmd_free(send_pkt);
exit:
	return rc;
}

/*
 * unload bootup time modules from spf
 */
int32_t gsl_do_unload_bootup_dyn_modules(uint32_t master_proc,
					gsl_acdb_handle_t handle)
{
	int32_t first_rc = AR_EOK, rc = AR_EOK;
	uint32_t proc_id = AR_SUB_SYS_ID_FIRST, load_rsp_pld_sz = 0;
	struct amdb_module_load_unload_t *load_rsp_pld = NULL;
	gpr_packet_t *send_pkt = NULL;
	apm_cmd_header_t *apm_hdr = NULL;

	if (gsl_dyn_mod_mgr_ctxt[master_proc] == NULL)
		return first_rc;

	for (; proc_id <= AR_SUB_SYS_ID_LAST; ++proc_id) {
		/*
		 * if the current proc_id is not supported, skip. Also skip if no
		 * modules were loaded for current proc_id
		 */
		if (!gsl_spf_ss_state_is_ss_supported(master_proc, proc_id) ||
			!gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id])
			continue;

		/*
		 * use the stored load rsp packet to do unload since it has the exact
		 * same payload. However we need to add apm_header_t in-between hence
		 * we need to allocate a new packet and do memcpy.
		 */
		load_rsp_pld = GPR_PKT_GET_PAYLOAD(
			struct amdb_module_load_unload_t,
			gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id]);
		load_rsp_pld_sz = GPR_PKT_GET_PAYLOAD_BYTE_SIZE(
			gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id]->header);

		rc = gsl_allocate_gpr_packet(AMDB_CMD_UNLOAD_MODULES,
			GSL_DYNAMIC_MODULE_MGR_PORT, AMDB_MODULE_INSTANCE_ID,
			sizeof(*apm_hdr) + load_rsp_pld_sz, 0, master_proc,
			&send_pkt);
		if (rc) {
			if (!first_rc)
				first_rc = rc;
			GSL_ERR("Failed to allocate GPR packet %d", rc);
			continue;
		}

		apm_hdr = GPR_PKT_GET_PAYLOAD(struct apm_cmd_header_t, send_pkt);
		gsl_memset((uint8_t *)apm_hdr, 0, sizeof(*apm_hdr));
		apm_hdr->payload_size = load_rsp_pld_sz;
		gsl_memcpy((uint8_t *)apm_hdr+sizeof(*apm_hdr), load_rsp_pld_sz,
			load_rsp_pld, load_rsp_pld_sz);

		/* we can now free the response packet */
		__gpr_cmd_free(gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id]);
		gsl_dyn_mod_mgr_ctxt[master_proc]->amdb_rsp[proc_id] = NULL;

		GSL_LOG_PKT("send_pkt", GSL_DYNAMIC_MODULE_MGR_PORT, send_pkt,
			sizeof(*send_pkt) + sizeof(*apm_hdr) + load_rsp_pld_sz, NULL, 0);
		/*
		 * send to spf
		 */
		rc = gsl_send_spf_cmd_wait_for_basic_rsp(&send_pkt, &rsp_signal);
		if (rc) {
			if (!first_rc)
				first_rc = rc;
			GSL_ERR("Unload modules cmd 0x%x failure:%d",
				AMDB_CMD_UNLOAD_MODULES, rc);
		}
	}

	rc = gsl_do_register_dynamic_modules(master_proc, true, handle);
	if (rc)
		GSL_ERR("failed to de-register dynamic modules %d", rc);

	return first_rc;
}
