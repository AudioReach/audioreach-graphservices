#ifndef GSL_SPF_DYN_MODULE_MGR_H
#define GSL_SPF_DYN_MODULE_MGR_H
/**
 * \file gsl_dynamic_module_mgr.h
 *
 * \brief
 *      Manages the loading and unloading of Spf dynamic modules
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "ar_osal_types.h"
#include "gsl_common.h"
#include "gsl_intf.h"


/*
 * \brief initialise dynamic module mgr
 *
 * \param[in] num_master_procs: Number of SPF masters
 * \param[in] master_procs: Array of SPF master proc ids
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dynamic_module_mgr_init(uint32_t num_master_procs,
				    uint32_t *master_procs);


/*
 * \brief deinitialise dynamic module mgr
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_dynamic_module_mgr_deinit(void);

/*
 * \brief Load or reload bootup dynamic modules to spf
 *
 * \param[in] master_proc: SPF master proc id
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_do_load_bootup_dyn_modules(uint32_t master_proc,
					gsl_acdb_handle_t handle);

/*
 * \brief Unload bootup dynamic modules to spf
 *
 * \param[in] master_proc: SPF master proc id
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_do_unload_bootup_dyn_modules(uint32_t master_proc,
					gsl_acdb_handle_t handle);


#endif //GSL_SPF_DYN_MODULE_MGR_H
