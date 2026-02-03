#ifndef _ASPS_ADS_USECASE_API_H_
#define _ASPS_ADS_USECASE_API_H_
/**
 * \file asps_ads_useacase_api.h
 * \brief
 *    This file contains PCM DATA Usecase ID specific APIs.
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

/*ADS usecase ID */
#define ASPS_USECASE_ID_PCM_DATA 0x0B00100A

#ifdef ASPS_USECASE_ID_PCM_DATA /* definitions specific to PCM DATA usecase */

/**
   PCM DATA usecase(ASPS_USECASE_ID_PCM_DATA) specific payload. This payload contains the
   type of the stream required by the sensor.
   This structure is proceeded by param_id_asps_sensor_usecase_register_t structure. */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_pcm_data_usecase_register_payload_t
{
   //stream type for pcm data takes values {0,1,2}
   // 0 : INVALID, 1 : STREAM_TYPE_PCM_RAW, 2 : STREAM_TYPE_PCM_NS
   uint32_t stream_type;
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_pcm_data_usecase_register_payload_t asps_pcm_data_usecase_register_payload_t;

#endif /* ASPS_USECASE_ID_PCM_DATA */

/*ADS usecase ID */
#define ASPS_USECASE_ID_PCM_DATA_V2 0x0B00100C

/**
   PCM DATA usecase(ASPS_USECASE_ID_PCM_DATA_V2) specific payload. This payload contains the
   type of the stream required by the sensor.
   This structure is proceeded by param_id_asps_sensor_usecase_register_t structure. */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_pcm_data_v2_usecase_register_payload_t
{
	 uint32_t stream_type;
	 /* stream type for pcm data takes values {0,1,2}
	  * 0 : INVALID, 1 : STREAM_TYPE_PCM_RAW, 2 : STREAM_TYPE_PCM_NS */

	 uint32_t requires_buffering;
	 /* indicates whether the capture use case requires a buffering module
	  * in the chain */

	uint32_t sample_rate;
	/* sampling rate of pcm data at end point */

	uint32_t bit_width;
	/* bit width of pcm data at end point
	 * currently supports only 16 bit	*/

	uint32_t num_channels;
	/* number of channels takes values from {0..32} */

#if 0
	uint8_t channel_type[0];
	/* channel type for each channel in num_channels
	 * variable array of size num_channels elements
	 * takes values from {0..63} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_pcm_data_v2_usecase_register_payload_t asps_pcm_data_v2_usecase_register_payload_t;

/** PCM DATA usecase (ASPS_USECASE_ID_PCM_DATA/V2) specific Payload structure. This structure is proceeded
    by event_id_asps_sensor_usecase_info_t. */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct asps_audio_data_usecase_register_ack_payload_t
{
   uint32_t sns_rd_ep_miid;
   /**< Module instance ID of SNS read end point module. */

   uint32_t mfc_miid;
   /**< Module instance ID of MFC module. */

   uint32_t pcm_cnv_miid;
   /**< Module instance ID of PCM_CNV module. */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asps_audio_data_usecase_register_ack_payload_t asps_audio_data_usecase_register_ack_payload_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_ADS_USECASE_API_H_ */
