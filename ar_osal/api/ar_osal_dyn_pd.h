#ifndef AR_OSAL_DYN_PD_H
#define AR_OSAL_DYN_PD_H

/**
 * \file ar_osal_dyn_pd.h
 *
 * \brief
 *      Defines APIs to create dynamic PD
 *      for the given processor domain.
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * \brief initialize dynamic pd.
 *
 * \param[in]   proc_id: satellite proc_id.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 *
 */
int32_t ar_osal_dyn_pd_init(uint32_t proc_id);

/**
 * \brief de-initialize dynamic pd.
 *
 * \param[in]   proc_id: satellite proc_id.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 *
 */
int32_t ar_osal_dyn_pd_deinit(uint32_t proc_id);

#endif
