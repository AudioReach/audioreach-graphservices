#ifndef _US_GEN_API_H_
#define _US_GEN_API_H_
/*==============================================================================
  @file us_gen_api.h
  @brief This file contains US_GEN module APIs

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
// Commented imcl api, not needed for HLOS
//#include "imcl_upd_api.h"
/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of US_GEN module */
//#define US_GEN_DATA_INPUT_PORT   0x2

/* Output port ID of US_GEN module */
#define US_GEN_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of US_GEN module */
#define US_GEN_DATA_MAX_INPUT_PORTS 0x0

/* Max number of output ports of US_GEN module */
#define US_GEN_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of US_GEN module */
#define US_GEN_MODULE_STACK_SIZE 4096


/*==============================================================================
   Param ID
==============================================================================*/

/** Parameter ID for US generation */
#define PARAM_ID_EXAMPLE_US_GEN_TONE_FREQUENCY                          0x08001347

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_GEN_TONE_FREQUENCY", PARAM_ID_EXAMPLE_US_GEN_TONE_FREQUENCY}
    @h2xmlp_description {Parameter for generating US tone }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct param_id_us_gen_struct_frequency_t
{
   uint32_t frequency;
   /**< @h2xmle_description {US Tone frequency in Hz}
        @h2xmle_default     {192000}
        @h2xmle_range       {0..4294967295}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure */
typedef struct param_id_us_gen_struct_frequency_t param_id_us_gen_struct_frequency_t;


/** Parameter ID for enabling/disabling duty cycling */
#define PARAM_ID_EXAMPLE_US_GEN_DUTY_CYCLING                            0x08001348

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_GEN_DUTY_CYCLING", PARAM_ID_EXAMPLE_US_GEN_DUTY_CYCLING}
    @h2xmlp_description {Parameter for enabling/disabling duty cycling }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct param_id_us_gen_duty_cycling_t
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
typedef struct param_id_us_gen_duty_cycling_t param_id_us_gen_duty_cycling_t;

/** Parameter ID for enabling/disabling codec duty cycling */
#define PARAM_ID_EXAMPLE_US_GEN_CODEC_DUTY_CYCLING                      0x08001349

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_GEN_CODEC_DUTY_CYCLING", PARAM_ID_EXAMPLE_US_GEN_CODEC_DUTY_CYCLING}
    @h2xmlp_description {Parameter for enabling/disabling codec duty cycling }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct  param_id_us_gen_codec_duty_cycling_t
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
typedef struct param_id_us_gen_codec_duty_cycling_t param_id_us_gen_codec_duty_cycling_t;

/** Parameter ID reserved for future use */
#define PARAM_ID_EXAMPLE_US_GEN_PARAM_1                                 0x08001350

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_GEN_PARAM_1", PARAM_ID_EXAMPLE_US_GEN_PARAM_1}
    @h2xmlp_description {Parameter reserved for future use }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct  param_id_us_gen_param_1_t
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
typedef struct param_id_us_gen_param_1_t param_id_us_gen_param_1_t;

/** Parameter ID reserved for future use */
#define PARAM_ID_EXAMPLE_US_GEN_PARAM_2                                 0x08001351

/** @h2xmlp_parameter   {"PARAM_ID_EXAMPLE_US_GEN_PARAM_2", PARAM_ID_EXAMPLE_US_GEN_PARAM_2}
    @h2xmlp_description {Parameter reserved for future use }
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
struct  param_id_us_gen_param_2_t
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
typedef struct param_id_us_gen_param_2_t param_id_us_gen_param_2_t;

/*==============================================================================
   Module
==============================================================================*/

/** @h2xml_title1           {US Gen Module API}
    @h2xml_title_agile_rev  {US Gen Module API}
    @h2xml_title_date       {Feb 13, 2020} */

/**
 * Module ID for US generator.
 */
#define MODULE_ID_EXAMPLE_US_GEN                                        0x070010D6

/**
    @h2xmlm_module              {"MODULE_ID_EXAMPLE_US_GEN", MODULE_ID_EXAMPLE_US_GEN}
    @h2xmlm_displayName         {"Ultrasound Generator"}
    @h2xmlm_description         {This module is used for Example Ultrasound frequency generation.\n
                                 - Supports the following param:\n
                                 -- PARAM_ID_MODULE_ENABLE\n
                                 -- PARAM_ID_EXAMPLE_US_GEN_TONE_FREQUENCY\n
                                 -- PARAM_ID_EXAMPLE_US_GEN_DUTY_CYCLING\n
                                 -- PARAM_ID_EXAMPLE_US_GEN_CODEC_DUTY_CYCLING\n
                                 -- PARAM_ID_EXAMPLE_US_GEN_PARAM_1\n
                                 -- PARAM_ID_EXAMPLE_US_GEN_PARAM_2\n
                                 - Supported Input Media Format:\n
                                 -- Any\n
                                 - Output media format:\n
                                 -- 16 bit, Mono, 96KHz, Fixed, MEDIA_FMT_ID_PCM\n}
    @h2xmlm_dataMaxInputPorts   {US_GEN_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {US_GEN_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataOutputPorts     {OUT=US_GEN_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC, APM_CONTAINER_TYPE_SC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {US_GEN_MODULE_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent  { "US Detect to us gen for sampling frequency control" = INTENT_ID_EXAMPLE_US_DETECT_PARAM_DATA, maxPorts= 1 }
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_gen_struct_frequency_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_gen_duty_cycling_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_gen_codec_duty_cycling_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_gen_param_1_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @h2xml_Select               {"param_id_us_gen_param_2_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy          {Calibration}
    @}                          <-- End of the Module -->
*/

#endif //_US_GEN_API_H_
