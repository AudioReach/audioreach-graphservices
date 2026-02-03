#ifndef GSL_HW_RSC_INTF_H
#define GSL_HW_RSC_INTF_H
/**
 * \file gsl_hw_rsc_intf.h
 *
 * \brief
 *      GSL Hardware Resource API layer
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "ar_osal_types.h"
#include "gsl_intf.h"

enum gsl_hw_rsc_command_rsp {
	GSL_HW_RSC_REQUEST_RSP,
	GSL_HW_RSC_RELEASE_RSP,
};

/**
 * \brief Request for HW resource configuration.
 * Look up into ACDB to retrieve the configuration
 * and send request command to SPF PRM module
 *
 * \param[in] miid: Module instance ID against which HW resource configuration
 *  is stored in ACDB
 * \param[in] key_vect: Key vector used to look up data base for HW resource
 *  configuration
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_request_hw_rsc_config(uint32_t miid,
	const struct gsl_key_vector *key_vect);

/**
 * \brief Release HW resource configuration.
 * Look up into ACDB to retrieve the configuration
 * and send release command to SPF PRM module
 *
 * \param[in] miid: Module instance ID against which HW resource configuration
 *  is stored in ACDB
 * \param[in] key_vect: Key vector used to look up data base for HW resource
 *  configuration
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_release_hw_rsc_config(uint32_t miid,
	const struct gsl_key_vector *key_vect);

/**
 * \brief Request for HW resource configuration.
 * Clients provide the configuration that needs to
 * be sent to SPF PRM module
 *
 * \param[in] payload: Pointer to HW resource configuration
 *  payload should be in the form {MIID, PID, size, error_code} followed by
 *  variable payload. Client is expected to send only one PID at a time
 *  using this API.
 * \param[in] payload_size: Size of the HW resource configuration
 * \param[in,out] buff: OPTIONAL buffer to receive the response payload from
 *  Spf. Will be filled if present.
 * \param[in,out] buff_size: OPTIONAL size of memory allocated for buff.
 *  If buff is written to, contains the number of bytes written.
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_request_hw_rsc_custom_config(const uint8_t *payload,
	size_t payload_size, void *buff, uint32_t *buff_size);

/**
 * \brief Release HW resource configuration.
 * Clients provide the configuration that needs to
 * be sent to SPF PRM module
 *
 * \param[in] payload: Pointer to HW resource configuration
 *  payload should be in the form {MIID, PID, size, error_code} followed by
 *  variable payload. Client is expected to send only one PID at a time
 *  using this API.
 * \param[in] payload_size: Size of the HW resource configuration
 * \param[in,out] buff: OPTIONAL buffer  to receive the response payload from
 *  Spf. Will be filled if present.
 * \param[in,out] buff_size: OPTIONAL size of memory allocated for buff.
 *  If buff is written to, contains the number of bytes written.
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_release_hw_rsc_custom_config(const uint8_t *payload,
	size_t payload_size, void *buff, uint32_t *buff_size);

/**
 * \brief Initialize GSL HW resource manager layer.
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_hw_rsc_init(void);

/**
 * \brief De-Initialize GSL HW resource manager layer.
 *
 *
 * \return AR_EOK on success, error code otherwise
 */
int32_t gsl_hw_rsc_deinit(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif //GSL_HW_RSC_INTF_H
