#ifndef _ASPS_US_RENDERER_USECASE_API_H_
#define _ASPS_US_RENDERER_USECASE_API_H_
/**
 * \file asps_us_renderer_useacase_api.h
 * \brief
 *  	 This file contains US Renderer Usecase ID specific APIs.
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
#define ASPS_USECASE_ID_ULTRASOUND_RENDERING 0x0B00100B

/**
   Ultrasound Renderer sepcific payload. This payload contains the
   end point configuration requested by the sensor.
   This structure is preceeded by param_id_asps_sensor_usecase_register_t structure. */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_ultrasound_rendering_usecase_register_payload_t
{
	uint32_t sampling_rate;
	/* sampling rate of pcm data at end point */

	uint32_t bit_width;
	/* bit width of pcm data
	 * currently supports only 16 bit */

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

typedef struct asps_ultrasound_rendering_usecase_register_payload_t asps_ultrasound_rendering_usecase_register_payload_t;

/** Ultrasound Renderer usecase specific information */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asps_ultrasound_rendering_usecase_register_ack_payload_t
{
	uint32_t module_iid_us_tone_renderer;
	/* miid for sending set params to the audio renderer
	 * which will be received as ack for US gen proxy
	 * usecase registration */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct asps_ultrasound_rendering_usecase_register_ack_payload_t asps_ultrasound_rendering_usecase_register_ack_payload_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif /* _ASPS_US_RENDERER_USECASE_API_H_ */
