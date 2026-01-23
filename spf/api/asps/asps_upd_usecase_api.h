#ifndef _ASPS_UPD_USECASE_API_H_
#define _ASPS_UPD_USECASE_API_H_
/**
 * \file asps_upd_useacase_api.h
 * \brief
 *    This file contains Ultrasound Usecase ID specific APIs.
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

/* UPD  usecase ID */
#define ASPS_USECASE_ID_UPD      0x0B001005

/*------------------------------------------------------------------------------
 * Register ACK payload specific for UPD usecase. It contains UPD module iid.
 *
 * 1. This payload structure is used for the register ACK set cfg by
 *    Apps client to ASPS i.e PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 *
 * 2. This payload structure is also used in the Usecase info event payload raised
 *    by ASPS to sensors i.e EVENT_ID_ASPS_SENSOR_USECASE_INFO
 *----------------------------------------------------------------------------*/

#include "spf_begin_pack.h"

struct asps_upd_usecase_register_ack_payload_t
{
   uint32_t module_instance_id;
   /**< UPD Module instance ID */
}
#include "spf_end_pack.h"
;
typedef struct asps_upd_usecase_register_ack_payload_t asps_upd_usecase_register_ack_payload_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_UPD_USECASE_API_H_ */
