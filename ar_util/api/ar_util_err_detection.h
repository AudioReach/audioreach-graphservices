#ifndef AR_UTIL_ERR_DET_H
#define AR_UTIL_ERR_DET_H
/**
 * \file ar_util_err_detection.h
 *
 * \brief
 *      Header for SPF error detection framework
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* \brief
*   Initializes one error detection context
*
* Multiple error detection contexts are useful in multi-master DSP scenarios,
*	so that a fatal error on one master does not require the other to restart.
* The error detection context stores some persistent data which is used in
*	error analysis
*
* \param[in] proc_handle: the master proc to initialize context for
* \param[in] client_data: data to return when this master proc needs restart
*
* \return
*   AR_EOK             : on success
*   AR_E<other error>  : on failure
*
* \dependencies
*   None
*/

int32_t ar_err_det_init_ctxt(uint32_t proc_handle, void* client_data);

/**
* \brief
*   Destroys one error detection context
*
* Multiple error detection contexts are useful in multi-master SPF scenarios,
*	so that a fatal error on one master does not require the other to restart
*
* \param[in] proc_handle: the master proc to destroy context for
*
* \return
*   AR_EOK             : on success
*   AR_E<other error>  : on failure
*
* \dependencies
*   None
*/

int32_t ar_err_det_destroy_ctxt(uint32_t proc_handle);

/**
* \brief
*   Reset state variables for an error detection context
*
* After SSR or PDR we must reset state variables in a context, like time since
* last restart or number of timeouts logged. This API will not reset the client
* data stored on context init.
*
* \param[in] proc_handle: the master proc ID to reset the context for
*
* \return
*   AR_EOK             : on success
*   AR_E<other error>  : on failure
*
* \dependencies
*   None
*/

int32_t ar_err_det_reset_ctxt(uint32_t proc_handle);

/**
* \brief
*   Determines whether SPF is in an unrecoverable state
*
* Multiple error detection contexts are useful in multi-master DSP scenarios,
*	so that a fatal error on one master does not require the other to restart
*   We identify them by the proc_id.
*
* \param[in] proc_handle: the master proc to use for error analysis
* \param[in] err_code: the error code returned by SPF
* \param[in] opcode: the opcode for which the error code was returned
* \param[out] do_restart: true when serious error requiring restart is detected.
*                         false otherwise
* \param[out] client_data: data to return when this master proc needs restart.
*
* \return
*   AR_EOK             : on successful error analysis, meaning do_restart is valid
*   AR_E<other error>  : otherwise, meaning do_restart should be ignored
*
* The implication of do_restart being true is that client should restart SPF by
*	doing e.g. PDR on the master proc.
*
* \dependencies
*   None
*/
int32_t ar_err_det_detect_spf_error(uint32_t proc_handle, int32_t err_code,
	uint32_t opcode, bool_t *do_restart, void **client_data);


#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif // #ifndef AR_ERR_DET_H

