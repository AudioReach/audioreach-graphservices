#ifndef GSL_SPF_SS_STATE_H
#define GSL_SPF_SS_STATE_H
/**
 * \file gsl_spf_ss_state.h
 *
 * \brief
 *	Maintains the state of all the audio proc_ids such as ADSP, CDSP, MDSP
 *	etc.
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "ar_osal_types.h"
#include "ar_osal_sys_id.h"

enum spf_ss_state_t {
	GSL_SPF_SS_STATE_DN = 0,
	GSL_SPF_SS_STATE_UP = 1
};

typedef void (*gsl_spf_ss_cb_t)(enum spf_ss_state_t state,
	uint32_t ss_mask);

/*
 * Initialize the global spf subsystem state
 * \param[in] master_proc: SPF master proc id
 * \param[in] supported_ss_mask: bitmask which represents which subsystems are
 * supported, a 1 in bit N means the subsystem with id N is supported.
 * \param[in] cb callback to notify other modules within GSL of state changes
 */
int32_t gsl_spf_ss_state_init(uint32_t master_proc, uint32_t supported_ss_mask,
	gsl_spf_ss_cb_t cb);

/*
 * Deinitialize the global spf subsystem state
 * \param[in] master_proc: SPF master proc id
 */
void gsl_spf_ss_state_deinit(uint32_t master_proc);

/*
 * update the state of one or more spf subsystems, returns the new state
 * after it has been updated
 * \param[in] master_proc: SPF master proc id
 * \param[in] ss_mask bitmask indicating which subsystems state to change
 * \param[in] the new state for the subsystems indicated in ss_mask
 */
uint32_t gsl_spf_ss_state_set(uint32_t master_proc, uint32_t ss_mask,
			      enum spf_ss_state_t state);

/*
 * Retrieve the current state of the spf subsystems
 * \return ss_state_mask bitmask indicating the state of each subsystem a
 * 1 in this field means the corresponding subsystem is both supported and up
 * \param[in] master_proc: SPF master proc id
 */
uint32_t gsl_spf_ss_state_get(uint32_t master_proc);

/*
 * Checks if a proc_id is supported for a particular master_proc on
 * this platform.
 * \param[in] master_proc: SPF master proc id
 * \param[in] proc_id proc_ids as defined in ar_osal_sys_id.h
 */
bool_t gsl_spf_ss_state_is_ss_supported(uint32_t master_proc, uint32_t proc_id);

#endif /* GSL_SPF_SS_STATE_H */

