#ifndef _ASPS_ACD_USECASE_API_H_
#define _ASPS_ACD_USECASE_API_H_
/**
 * \file asps_acd_useacase_api.h
 * \brief
 *    This file contains ACD Usecase ID specific APIs.
 *
 *    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *    SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/


/*------------------------------------------------------------------------------
 *  Usecase ID definition
 *----------------------------------------------------------------------------*/

/*ACD usecase ID */
#define ASPS_USECASE_ID_ACD      0x0B001004

/*------------------------------------------------------------------------------
 * Register request payload specific for ACD usecase. It contains list of context
 * ids that sensors wants to setup.
 *
 * 1. This payload structure is populated in the register request event rasied
 *    by ASPS to Apps client i.e EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST.
 *
 * 2. This same payload structure is used for the ACD usecase register requests
 *    orignating from sensors i.e PARAM_ID_ASPS_SENSOR_USECASE_REGISTER.
 *----------------------------------------------------------------------------*/

/**  ACD usecase(ASPS_USECASE_ID_ACD) specific payload. This contians the list of
 *   context ids necessary to calibrate the ACD module. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_acd_usecase_register_payload_t
{
   uint32_t num_contexts;
   /**< Number of context ids. */

   uint32_t context_ids[0];
   /**< Variable length array of context ids. Length of the array is "num_contexts" */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_acd_usecase_register_payload_t asps_acd_usecase_register_payload_t;

/*------------------------------------------------------------------------------
 * Register ACK payload specific for ACD usecase. It contains the module iid
 * and list of context ids configured for the instance. This can be cascaded
 * payload if there are multiple ACD module instance IDs.
 *
 * 1. This payload structure is used for the register ACK set cfg by
 *    Apps client to ASPS i.e PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 *
 * 2. This payload structure is also used in the Usecase info event payload raised
 *    by ASPS to sensors i.e EVENT_ID_ASPS_SENSOR_USECASE_INFO
 *----------------------------------------------------------------------------*/

/** ACD usecase (ASPS_USECASE_ID_ACD) specific ACK Payload structure. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_acd_usecase_register_ack_payload_t
{
   uint32_t module_instance_id;
   /**< Module instance ID of which is configured with the following contexts ids. */

   uint32_t num_contexts;
   /**< Number of context ids */

   uint32_t context_ids[0];
   /**< Variable length array of context ids. Length of the array is "num_contexts" */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_acd_usecase_register_ack_payload_t asps_acd_usecase_register_ack_payload_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_ACD_USECASE_API_H_ */
