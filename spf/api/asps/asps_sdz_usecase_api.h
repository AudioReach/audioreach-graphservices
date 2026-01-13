#ifndef _ASPS_SDZ_USECASE_API_H_
#define _ASPS_SDZ_USECASE_API_H_
/**
 * \file asps_sdz_useacase_api.h
 * \brief
 *    This file contains Speaker Diarization Usecase ID specific APIs.
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/


/*------------------------------------------------------------------------------
 *  Usecase ID definition
 *----------------------------------------------------------------------------*/

/* SDZ  usecase ID */
#define ASPS_USECASE_ID_SDZ      0x0B001010

/*------------------------------------------------------------------------------
 * Register ACK payload specific for SDZ usecase. It contains SDZ module iid.
 *
 * 1. This payload structure is used for the register ACK set cfg by
 *    Apps client to ASPS i.e PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 *
 * 2. This payload structure is also used in the Usecase info event payload raised
 *    by ASPS to sensors i.e EVENT_ID_ASPS_SENSOR_USECASE_INFO
 *----------------------------------------------------------------------------*/

#include "spf_begin_pack.h"

struct asps_sdz_usecase_register_ack_payload_t
{
   uint32_t module_instance_id;
   /**< SDZ Module instance ID */
}
#include "spf_end_pack.h"
;
typedef struct asps_sdz_usecase_register_ack_payload_t asps_sdz_usecase_register_ack_payload_t;


#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_SDZ_USECASE_API_H_ */
