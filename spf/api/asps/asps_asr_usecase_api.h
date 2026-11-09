#ifndef _ASPS_ASR_USECASE_API_H_
#define _ASPS_ASR_USECASE_API_H_
/**
 * \file asps_asr_usecase_api.h
 * \brief
 *    This file contains ASR Usecase ID specific APIs.
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

/*ASR usecase ID */
#define ASPS_USECASE_ID_ASR      0x0B001011

/*------------------------------------------------------------------------------
 * Register request payload specific for ASR usecase. It contains ASR
 * configuration parameters that sensors wants to setup.
 *
 * 1. This payload structure is populated in the register request event raised
 *    by ASPS to Apps client i.e EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST.
 *
 * 2. This same payload structure is used for the ASR usecase register requests
 *    originating from sensors i.e PARAM_ID_ASPS_SENSOR_USECASE_REGISTER.
 *----------------------------------------------------------------------------*/

/**  ASR usecase(ASPS_USECASE_ID_ASR) specific payload. This contains the
 *   ASR configuration necessary to calibrate the ASR module. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_asr_usecase_register_payload_t
{
   uint32_t enable_partial_transcription;
   /**< Flag to enable partial transcription for ASR
        Range: 0..1, Default: 0 */

   uint32_t language_code;
   /**< Language code for ASR output
        Range: Language enum values, Default: ASPS_ASR_LANG_EN_US (0) */

   uint32_t enable_sdz;
   /**< Flag to enable Speaker Diarization along with ASR
        Range: 0..1, Default: 0 */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_asr_usecase_register_payload_t asps_asr_usecase_register_payload_t;

/*------------------------------------------------------------------------------
 * Register ACK payload specific for ASR usecase. It contains the module iid
 * and ASR configuration status.
 *
 * 1. This payload structure is used for the register ACK set cfg by
 *    Apps client to ASPS i.e PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 *
 * 2. This payload structure is also used in the Usecase info event payload raised
 *    by ASPS to sensors i.e EVENT_ID_ASPS_SENSOR_USECASE_INFO
 *----------------------------------------------------------------------------*/

/** ASR usecase (ASPS_USECASE_ID_ASR) specific ACK Payload structure. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_asr_usecase_register_ack_payload_t
{
   uint32_t asr_module_instance_id;
   /**< ASR Module instance ID which is configured with the ASR settings. */

   uint32_t sdz_module_instance_id;
   /**< SDZ Module instance ID (valid only if SDZ is enabled)
        Set to 0 if SDZ is not enabled */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_asr_usecase_register_ack_payload_t asps_asr_usecase_register_ack_payload_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_ASR_USECASE_API_H_ */
