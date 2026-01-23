/**
 * \file us_tone_renderer_api.h
 * \brief
 *  	 This file contains CAPI us tone renderer params
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
// clang-format off
/*
$Header:
*/
// clang-format on

#ifndef _US_TONE_RENDERER_API_H_
#define _US_TONE_RENDERER_API_H_

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "module_cmn_api.h"

/**
     @h2xml_title1          {US Tone Renderer module}
     @h2xml_title_agile_rev {US Tone Renderer module}
     @h2xml_title_date      {July 19, 2021}
  */

#define US_TONE_RENDERER_STACK_SIZE 1024

#define US_TONE_RENDERER_MAX_INPUT_PORTS 0
#define US_TONE_RENDERER_MAX_OUTPUT_PORTS 1

/*==============================================================================
   Param IDs
==============================================================================*/
/* ID of the parameter used to media format configuration of the module. */
#define PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG 0x08001A79
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG", PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG}
    @h2xmlp_description {- This contains the media format information that changed during the session. \n
						 - Any change in media format be notified to client through the event id \n
						   DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE }
   @h2xmlp_toolPolicy   {CALIBRATION}
   @h2xmlx_expandStructs  {false}
*/

enum us_tone_renderer_ep_media_format_status_t
{
	US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_INVALID = 0,
	/* Invalid Status*/

	US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_CHANGE_START = 1,
	/* Change to given media format will be initiated */

	US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_CHANGE_DONE = 2,
	/* Change to media format recieved during the change
	 * start is now complete. */
};

/* Payload of the PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_ep_media_format_cfg_t
{
	uint32_t status;
   /**< @h2xmle_description {Media format change is to be initiated or complete.
                             Rest of the fields are not applicable if status is either
							 US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_INVALID or
							 US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_CHANGE_DONE. }
        @h2xmle_default     {US_TONE_RENDERER_EP_MEDIA_FORMAT_INFO_INVALID}
		@h2xmle_rangeEnum   {us_tone_renderer_ep_media_format_status_t} */

	uint32_t sampling_rate;
   /**< @h2xmle_description { Sampling rate of the PCM data.}
        @h2xmle_default     {0xBB80}
		@h2xmle_range       {0..96000} */

	uint32_t bit_width;
   /**< @h2xmle_description { Bitwidth of the PCM data}
        @h2xmle_default     {16}
		@h2xmle_range       {0..32} */

	uint32_t num_channels;
   /**< @h2xmle_description { Number of channels at end point .}
        @h2xmle_range       {0..32}
        @h2xmle_default     {2} */

#if defined(__H2XML__)
	uint8_t channel_type[0];
   /**< @h2xmle_description { Defines channel IDs for each of the channel index.
                              Range is defined between 1 to 63.  Value '0' is considered
                              invalid and must not be set. }
        @h2xmle_range       { 0..63}
        @h2xmle_variableArraySize  { "num_channels" } */
#endif

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_ep_media_format_cfg_t param_id_us_tone_renderer_ep_media_format_cfg_t;

#define PARAM_ID_US_TONE_RENDERER_OUTPUT_MEDIA_FORMAT 0x08001A82
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_OUTPUT_MEDIA_FORMAT", PARAM_ID_US_TONE_RENDERER_OUTPUT_MEDIA_FORMAT}
    @h2xmlp_description {- This is a mandatory parameter for this module to work. This specifies the media format of the
						   the module. The output media format can only be set through this parameter. }
   @h2xmlp_toolPolicy   {CALIBRATION}
   @h2xmlx_expandStructs  {false}
*/

/* Payload of the PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_output_media_format_t
{
	uint32_t sampling_rate;
   /**< @h2xmle_description { Sampling rate of the PCM data.}
        @h2xmle_default     {0xBB80}
		@h2xmle_range       {0..96000} */

	uint32_t bit_width;
   /**< @h2xmle_description { Bitwidth of the PCM data - currently only 16 bit is supported}
        @h2xmle_default     {16}
		@h2xmle_range       {00..32} */

	uint32_t num_channels;
   /**< @h2xmle_description { Number of channels at end point .}
        @h2xmle_range       {0..32}
        @h2xmle_default     {2} */

#if defined(__H2XML__)
	uint8_t channel_type[0];
   /**< @h2xmle_description { Defines channel IDs for each of the channel index.
                              Range is defined between 1 to 63.  Value '0' is considered
                              invalid and must not be set. }
        @h2xmle_range       { 0..63}
        @h2xmle_variableArraySize  { "num_channels" } */
#endif

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_output_media_format_t param_id_us_tone_renderer_output_media_format_t;

#define PARAM_ID_US_TONE_RENDERER_TONE_CFG 0x08001A7A
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_TONE_CFG", PARAM_ID_US_TONE_RENDERER_TONE_CFG}
    @h2xmlp_description {- This is a mandatory param for US Tone Renderer module to work.\n
						 - Contains the audio sample which will be rendered at the given \n
						   periodicity at the media format received via PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG\n
						 - If not configured there will be no tone generated }
   @h2xmlp_toolPolicy   {NO_SUPPORT}
   @h2xmlx_expandStructs  {false}
*/

enum us_tone_cfg_buffer_interleaving_t
{
	US_TONE_CFG_BUFFER_INTERLEAVING_INVALID = 0,
	US_TONE_CFG_BUFFER_INTERLEAVING_INTERLEAVED = 1,
	US_TONE_CFG_BUFFER_INTERLEAVING_DEINTERLEAVED = 2

};
/* Payload of the PARAM_ID_US_TONE_RENDERER_TONE_CFG command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_tone_cfg_t
{
	uint32_t period_us;
   /**< @h2xmle_description { Periodicity at which the sample will be repeated }
        @h2xmle_range       {0..100000}
        @h2xmle_default     {0} */

	uint32_t num_repetitions;
	/**< @h2xmle_description { Number of times the tone will be repeated in the
                               given period	}
        @h2xmle_default     {1} */

	uint32_t phase_offset_us;
	/**< @h2xmle_description { Phase offset for every extra channel \n
							   If phase offset is 10us then second channel
							   tone will be at an offset of 10us third
							   will be 20us so on. If 0us then all will be
							   played with zero offset.	}
        @h2xmle_default     {0} */

	uint32_t gain;
	/**< @h2xmle_description { Gain in Q13 format applied to the tone.	}
        @h2xmle_default     {0x2000} */


	uint32_t buffer_data_interleaving;
   /**< @h2xmle_description {Interleaving of the data in the payload }
        @h2xmle_default     {US_TONE_CFG_BUFFER_INTERLEAVING_INVALID}
		@h2xmle_rangeEnum   {us_tone_cfg_buffer_interleaving_t} */

	uint32_t tone_num_channels;
   /**< @h2xmle_description {Number of channels pertaining to the tone buffer }
        @h2xmle_range       {0..32}
        @h2xmle_default     {1} */

	uint32_t payload_len;
   /**< @h2xmle_description { Total length in bytes of the audio samples }
        @h2xmle_range       {0..1024}
        @h2xmle_default     {0} */

#ifdef __H2XML__
	uint8_t payload[payload_len];
   /**< @h2xmle_description { Sample content which will be rendered } */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_tone_cfg_t param_id_us_tone_renderer_tone_cfg_t;

#define PARAM_ID_US_TONE_RENDERER_ENABLE 0x08001A7B
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_ENABLE", PARAM_ID_US_TONE_RENDERER_ENABLE}
    @h2xmlp_description {- This is used to start / stop rendering the tone. \n
						 - By default audio renderer will start generating the tone.}
   @h2xmlp_toolPolicy   {NO_SUPPORT}
   @h2xmlx_expandStructs  {false}
*/

/* Payload of the PARAM_ID_US_TONE_RENDERER_ENABLE command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_enable_t
{
	uint32_t enable;
   /**< @h2xmle_description { 1: Play Audio Sample 0: Halt playing }
        @h2xmle_default     {1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_enable_t param_id_us_tone_renderer_enable_t;

#define PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_ENABLE 0x08001A7C
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_ENABLE", PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_ENABLE}
    @h2xmlp_description {If enabled, then whenever us tone renderer is disabled -> PA_Off }
   @h2xmlp_toolPolicy   {CALIBRATION}
   @h2xmlx_expandStructs  {false}
*/

/* Payload of the PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_ENABLE command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_duty_cycle_enable_t
{
	uint32_t duty_cycle_enable;
   /**< @h2xmle_description { 1: Enable Duty Cycling 0: Disable Duty Cycling }
        @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_duty_cycle_enable_t param_id_us_tone_renderer_duty_cycle_enable_t;

#define PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_THRESHOLD 0x08001A7D
/** @h2xmlp_parameter   {"PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_THRESHOLD", PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_THRESHOLD}
    @h2xmlp_description {Denotes the minimum duration below which duty-cycling cannot be done.}
   @h2xmlx_expandStructs  {false}
*/

/* Payload of the PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_THRESHOLD command. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_us_tone_renderer_duty_cycle_threshold_t
{
	uint32_t duty_cycle_threshold_us;
   /**< @h2xmle_description { minimum duration below which duty-cycling cannot be done }
        @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_us_tone_renderer_duty_cycle_threshold_t param_id_us_tone_renderer_duty_cycle_threshold_t;


/*==============================================================================
   Event IDs
==============================================================================*/

#define DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE 0x06001002
/** @h2xmlp_parameter   {"DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE", DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE}
    @h2xmlp_description {- This is used to notify client of any change in media format - num_channels/channel_type/bit width/SR }
   @h2xmlx_expandStructs  {false}
*/

/* Payload of the DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE command. */
typedef struct param_id_us_tone_renderer_ep_media_format_cfg_t data_event_id_us_tone_renderer_media_format_change_t;

/*==============================================================================
   Constants
==============================================================================*/
/* Global unique Module ID definition
   Module library is independent of this number, it defined here for static
   loading purpose only */

#define MODULE_ID_US_TONE_RENDERER 0x07001175

/*==============================================================================
   Constants
==============================================================================*/
/**
    @h2xml_title1          {US Tone Renderer Module API}
    @h2xml_title_agile_rev {USToneRenderer Module API}
    @h2xml_title_date      {July 13, 2023} */

/**
    @h2xmlm_module            	 { "MODULE_ID_US_TONE_RENDERER", MODULE_ID_US_TONE_RENDERER}
    @h2xmlm_displayName       	 { "US Tone Renderer" }
    @h2xmlm_description       	 { - Repeates given audio sample with configured periodicity and position \n
								   - This is a source module and supports the following params: \n
								   - PARAM_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CFG\n
								   - PARAM_ID_US_TONE_RENDERER_ENABLE\n
								   - PARAM_ID_US_TONE_RENDERER_TONE_CFG\n
								   - PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_ENABLE \n
								   - PARAM_ID_US_TONE_RENDERER_DUTY_CYCLE_THRESHOLD \n
								   - This module also supports the following event:\n
								   - DATA_EVENT_ID_US_TONE_RENDERER_EP_MEDIA_FORMAT_CHANGE \n}
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            { US_TONE_RENDERER_STACK_SIZE }
    @h2xmlm_toolPolicy           { Calibration }
    @h2xmlm_dataMaxInputPorts    { US_TONE_RENDERER_MAX_INPUT_PORTS }
	@h2xmlm_dataMaxOutputPorts   { US_TONE_RENDERER_MAX_OUTPUT_PORTS }
    @{                  		 <-- Start of the Module -->
	@h2xml_Select     			{param_id_us_tone_renderer_ep_media_format_cfg_t}
	@h2xmlm_InsertParameter
	@h2xml_Select     			{param_id_us_tone_renderer_enable_t}
	@h2xmlm_InsertParameter
	@h2xml_Select     			{param_id_us_tone_renderer_duty_cycle_enable_t}
	@h2xmlm_InsertParameter
	@h2xml_Select     			{param_id_us_tone_renderer_duty_cycle_threshold_t}
	@h2xmlm_InsertParameter
	@}                   <-- End of the Module -->*/



#endif /*_US_TONE_RENDERER_API_H_*/
