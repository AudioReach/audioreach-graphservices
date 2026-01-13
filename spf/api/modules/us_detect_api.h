#ifndef _US_DETECT_API_H
#define _US_DETECT_API_H
/*==============================================================================
  @file us_detect_api.h
  @brief This file contains US_DETECT module APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off

/*==============================================================================
   Include Files
==============================================================================*/

#include "media_fmt_api.h"
#include "module_cmn_api.h"
#include "ar_defs.h"
#include "apm_graph_properties.h"
#include "imcl_spm_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of MIC INPUT OF US DETECTOR module */
#define US_DETECTOR_PRIMARY_DATA_INPUT_PORT   0x2

/* Input port ID of REFERENCE INPUT OF US DETECTOR module */
#define US_DETECTOR_REFERENCE_DATA_INPUT_PORT   0x4

/* Output port ID of US DETECTOR module */
#define US_DETECTOR_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of US DETECTOR module */
#define US_DETECTOR_DATA_MAX_INPUT_PORTS 0x2

/* Max number of output ports of US DETECTOR module */
#define US_DETECTOR_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of US DETECTOR module */
#define US_DETECTOR_MODULE_STACK_SIZE 4096

#define US_MAX_DETECTION_EVENT_CLIENTS 4

/*==============================================================================
   Param ID
==============================================================================*/

/** Parameter ID for US generation */
#define PARAM_ID_EXAMPLE_US_DETECT_TONE_FREQUENCY 0x08001352

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_TONE_FREQUENCY", PARAM_ID_EXAMPLE_US_DETECT_TONE_FREQUENCY}
    @h2xmlp_description {Parameter for tuning US Detection Module } */

#include "spf_begin_pack.h"
struct param_id_us_detect_tone_frequency_t
{
   uint32_t frequency;
   /**< @h2xmle_description {US Tone frequency in Hz}
        @h2xmle_default     {100}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */

}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_tone_frequency_t param_id_us_detect_tone_frequency_t;

/** Parameter ID for Detection event raised by the US Detector Module */
#define EVENT_ID_GENERIC_US_DETECTION                      0x08001358

/** @h2xmlp_parameter   {"EVENT_ID_EXAMPLE_US_DETECTION",EVENT_ID_EXAMPLE_US_DETECTION}
    @h2xmlp_description { Detection event raised by the US Detector Module.}
    @h2xmlp_toolPolicy  { NO_SUPPORT}*/

/* Payload returned by us module in response to the EVENT_ID_EXAMPLE_US_DETECTION
 * registered by the client*/
typedef enum
{
    US_DETECT_INVALID = 0,  /** Invalid detection event type */
    US_DETECT_NEAR = 1,     /** Near proximity event */
    US_DETECT_FAR = 2       /** Far proximity event */
}us_detect_event_type;

#include "spf_begin_pack.h"
struct event_id_upd_detection_event_t
{
    uint32_t detection_timestamp_lsw;
    /**< @h2xmle_description {This denotes the buffer timestamp (lsw) in micro-seconds when the proximity is detected}
        @h2xmle_default     {0}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */

    uint32_t detection_timestamp_msw;
    /**< @h2xmle_description {This denotes the buffer timestamp (msw) in micro-seconds when the proximity is detected}
        @h2xmle_default     {0}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */

    uint32_t proximity_event_type;
    /**< @h2xmle_description { proximity_event_type sent by the Detection module to the client}
         @h2xmle_default     {0}
         @h2xmle_rangeList   {"US_DETECT_INVALID"=0;"US_DETECT_NEAR"=1;"US_DETECT_FAR"=2}
         @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct event_id_upd_detection_event_t  event_id_upd_detection_event_t ;

/** Parameter ID for enabling/disabling duty cycling */
#define PARAM_ID_EXAMPLE_US_DETECT_DUTY_CYCLING                      0x08001353

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_DUTY_CYCLING",PARAM_ID_EXAMPLE_US_DETECT_DUTY_CYCLING}
    @h2xmlp_description { Parameter ID for enabling/disabling duty cycling.}
    @h2xmlp_toolPolicy  {RTC}*/

#include "spf_begin_pack.h"
struct param_id_us_detect_duty_cycling_t
{
   uint32_t enable;
   /**< @h2xmle_description {Specifies whether to enable or disable duty cycling}
        @h2xmle_default     {1}
        @h2xmle_rangeList   {"Disable"=0;"Enable"=1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_duty_cycling_t param_id_us_detect_duty_cycling_t;

/** Parameter ID for enabling/disabling codec duty cycling */
#define PARAM_ID_EXAMPLE_US_DETECT_CODEC_DUTY_CYCLING                      0x08001354

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_CODEC_DUTY_CYCLING",PARAM_ID_EXAMPLE_US_DETECT_CODEC_DUTY_CYCLING}
    @h2xmlp_description { Parameter ID for enabling/disabling codec duty cycling.}
    @h2xmlp_toolPolicy  {RTC}*/

#include "spf_begin_pack.h"
struct param_id_us_detect_codec_duty_cycling_t
{
   uint32_t enable;
   /**< @h2xmle_description {Specifies whether to enable or disable codec duty cycling}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {"Disable"=0;"Enable"=1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_codec_duty_cycling_t param_id_us_detect_codec_duty_cycling_t;

/** Parameter ID for enabling/disabling access to sensor APIs */
#define PARAM_ID_EXAMPLE_US_DETECT_SENSOR_ACCESS                      0x08001355

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_SENSOR_ACCESS",PARAM_ID_EXAMPLE_US_DETECT_SENSOR_ACCESS}
    @h2xmlp_description { Parameter ID for enabling/disabling access to sensor APIs}
    @h2xmlp_toolPolicy  {RTC}*/

#include "spf_begin_pack.h"
struct param_id_us_detect_sensor_access_t
{
   uint32_t enable;
   /**< @h2xmle_description {Specifies whether to enable/disable access to sensor APIs}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {"Disable"=0;"Enable"=1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_sensor_access_t param_id_us_detect_sensor_access_t;

/** Parameter ID reserved for future use */
#define PARAM_ID_EXAMPLE_US_DETECT_PARAM_1 0x08001356

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_PARAM_1", PARAM_ID_EXAMPLE_US_DETECT_PARAM_1}
    @h2xmlp_description {Parameter reserved for future use }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct  param_id_us_detect_param_1_t
{
   uint32_t param_1_data;
   /**< @h2xmle_description {param_1_data reserved for future use}
        @h2xmle_default     {0}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_param_1_t param_id_us_detect_param_1_t;

/** Parameter ID reserved for future use */
#define PARAM_ID_EXAMPLE_US_DETECT_PARAM_2 0x08001357

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_DETECT_PARAM_2", PARAM_ID_EXAMPLE_US_DETECT_PARAM_2}
    @h2xmlp_description {Parameter reserved for future use }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct  param_id_us_detect_param_2_t
{
   uint32_t param_2_data;
   /**< @h2xmle_description {param_2_data reserved for future use}
        @h2xmle_default     {0}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_detect_param_2_t param_id_us_detect_param_2_t;

/*==============================================================================
   Module
==============================================================================*/

/** @h2xml_title1           {US DETECTOR Module API}
    @h2xml_title_agile_rev  {US DETECTOR Module API}
    @h2xml_title_date       {Feb 13, 2020} */

/**
 * Module ID for US detector.
 */
#define MODULE_ID_EXAMPLE_US_DETECT0x070010D7

/**
    @h2xmlm_module              {"MODULE_ID_EXAMPLE_US_DETECT", MODULE_ID_EXAMPLE_US_DETECT}

    @h2xmlm_displayName         {"US Detector"}
    @h2xmlm_description         {ID of the US DETECTOR module. This module is used to detect the US tones. \n
    . MFC needs to be configured before US detector module so that it receives the signal with the below supported input media format. \n
    . The module can be used as a single input single output module or as a sink module \n

                                 - Supports the following param:\n
                                 -- PARAM_ID_MODULE_ENABLE\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_TONE_FREQUENCY\n
                                 -- EVENT_ID_EXAMPLE_US_DETECTION\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_DUTY_CYCLING\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_CODEC_DUTY_CYCLING\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_SENSOR_ACCESS\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_PARAM_1\n
                                 -- PARAM_ID_EXAMPLE_US_DETECT_PARAM_2\n
            - Supported Input Media Format:\n
            Data Format          : FIXED_POINT \n
    .       fmt_id               : MEDIA_FMT_ID_PCM \n
    .       Sample Rates         : 96000 \n
    .       Number of channels   : 1  \n
    .       Channel type         : 1 to 63 \n
    .       Bits per sample      : 16 \n
    .       Q format             : 15 \n
    .       Interleaving         : Deinterleaved Unpacked \n
    .       Signed/unsigned      : Signed  \n
    }
    @h2xmlm_dataMaxInputPorts   {US_DETECTOR_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {US_DETECTOR_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {MIC_INPUT = US_DETECTOR_PRIMARY_DATA_INPUT_PORT;REF_INPUT = US_DETECTOR_REFERENCE_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=US_DETECTOR_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC, APM_CONTAINER_TYPE_SC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {US_DETECTOR_MODULE_STACK_SIZE}
@h2xmlm_ctrlDynamicPortIntent {"US detect to us gen for sending param data" = INTENT_ID_EXAMPLE_US_DETECT_PARAM_DATA, maxPorts = 1}
    @h2xmlm_ToolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_us_detect_tone_frequency_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter}
@h2xml_Select               {"event_id_upd_detection_event_t "}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {NO_SUPPORT}
    @h2xml_Select               {"param_id_us_detect_duty_cycling_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_detect_codec_duty_cycling_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_detect_sensor_access_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_detect_param_1_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_detect_param_2_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @}                          <-- End of the Module -->
*/

#endif //US_DETECT_API_H
