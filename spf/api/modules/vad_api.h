/**
 * \file vad_api.h
 * \brief
 *  This file contains CAPI VAD module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */
// clang-format off
/*
$Header: //components/rel/avs.fwk/1.0/api/modules/sh_mem_pull_push_mode_api.h#11 $
*/
// clang-format on

#ifndef __VAD_API_H__
#define __VAD_API_H__

/*============================================================================
EDIT HISTORY FOR MODULE

when       who      what, where, why
--------    ------     -------------------------------------------------
           sboliset     Created File.
============================================================================*/
#include "imcl_fwk_intent_api.h"
#include "contexts_api.h"

/**
   @h2xml_title1           {Module VAD API}
   @h2xml_title_agile_rev  {Module VAD API}
   @h2xml_title_date       {March 23, 2026}
*/
#define VAD_RELEASE_VERSION_MSB AR_NON_GUID(0x01000100)
#define VAD_RELEASE_VERSION_LSB AR_NON_GUID(0x00000000)

/*==============================================================================
   Constants
==============================================================================*/
#define CAPI_VAD_MAX_INPUT_PORTS 1
#define CAPI_VAD_MAX_OUTPUT_PORTS 0
#define CAPI_VAD_STACK_SIZE_REQUIREMENT 8192 // TODO: profile and update


/* Global unique Module ID definition.
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_VAD 0x07001188

/*==============================================================================
   Module definition
==============================================================================*/
/**
    @h2xml_title1          {Voice Activity Detector Module API}
    @h2xml_title_agile_rev {Voice Activity Detector Module API}
    @h2xml_title_date      {March 23, 2026} */

/** @h2xmlm_module       {"MODULE_ID_VAD",MODULE_ID_VAD}
    @h2xmlm_displayName  {"Voice Activity Detector (VAD)"}
    @h2xmlm_description  {Supports the wakeup detection feature. \n
 *      - #PARAM_ID_VAD_STATIC_CFG \n
 *      - #PARAM_ID_VAD_CONTEXT_ML_MODEL_CONFIG \n
 *      - #PARAM_ID_VAD_CONTEXT_THRESHOLD \n
 *      - #PARAM_ID_VAD_SPEECH_DYNAMIC_CONFIG \n
 *      - #PARAM_ID_VAD_ENABLE_SPEECH_RESET \n
 *      - #PARAM_ID_VAD_SPEECH_RESET_PERIOD \n
 *      - #PARAM_ID_VAD_PRE_ROLL_DURATION \n
 *
 * Supported Input Media Format: \n
 *  - Data Format          : FIXED_POINT \n
 *  - fmt_id               : Don't care \n
 *  - Sample Rates         : 16Khz \n
 *  - Number of channels   : 1 to 2 \n
 *  - Channel type         : 1 to 63 \n
 *  - Bits per sample      : 16 \n
 *  - Q format             : 15 \n
 *  - Interleaving         : Deinterleaved Unpacked \n
 *  - Signed/unsigned      : Any }
    @h2xmlm_dataMaxInputPorts    {CAPI_VAD_MAX_INPUT_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {CAPI_VAD_MAX_OUTPUT_PORTS}
    @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {CAPI_VAD_STACK_SIZE_REQUIREMENT}
    @h2xmlm_ctrlDynamicPortIntent { "VAD-DAM Control"  = INTENT_ID_AUDIO_DAM_DETECTION_ENGINE_CTRL,
                                      maxPorts= 1 }

    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
*/

#define PARAM_ID_VAD_STATIC_CFG 0x08001BE2

/** @h2xmlp_parameter   {"PARAM_ID_VAD_STATIC_CFG", PARAM_ID_VAD_STATIC_CFG}
    @h2xmlp_description {Parameter for static configuration for VAD module.}
    @h2xmlp_toolPolicy  {RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_vad_static_cfg_t
{

   int32_t num_channel_processing;
   /**< @h2xmle_description   {Number of channel processing}
        @h2xmle_default       {1}
        @h2xmle_range         {1..2}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced}
        @h2xmle_readOnly      {true} */
   int32_t conf_change;
   /**< @h2xmle_description   {Change in confidence level for sending detection update}
        @h2xmle_default       {1}
        @h2xmle_range         {0..100}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced}
        @h2xmle_visibility    {hide} */
   int16_t mic_gain;
   /**< @h2xmle_description   {Microphone gain to be applied in Q4.11 format}
        @h2xmle_default       {0x0800}
        @h2xmle_range         {0..0x7FFF}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced}
        @h2xmle_readOnly      {true} */

   int16_t reserved;
   /**< @h2xmle_description {Added for alignment}
        @h2xmle_default     {0}
        @h2xmle_range       {0x0000..0x0000}
        @h2xmle_visibility  {hide}
        @h2xmle_readOnly    {true} */

} param_id_vad_static_cfg_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_VAD_CONTEXT_ML_MODEL_CONFIG 0x08001BEA

/** @h2xmlp_parameter           {"PARAM_ID_VAD_CONTEXT_ML_MODEL_CONFIG", PARAM_ID_VAD_CONTEXT_ML_MODEL_CONFIG}
    @h2xmlp_description         {VAD stage1 ML MODEL}
    @h2xmlp_ToolPolicy          {Calibration}
    @h2xmlp_isNeuralNetParam    {TRUE}
    @h2xmlp_isOffloaded         {TRUE}
    @h2xmlp_isHwAccel           {TRUE}
    @h2xmlp_persistType         {SHARED}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

typedef struct param_id_vad_context_ml_model_config_t
{
   uint32_t model_align;
   /**< @h2xmle_description {Data Alignment required for the model_data}
        @h2xmle_default     {256}
        @h2xmle_range       {0..8192}
        @h2xmle_group       {MODEL}
        @h2xmle_visibility  {hide}
        @h2xmle_policy      {Advanced} */

   uint32_t model_offset;
   /**< @h2xmle_description {Data offset (bytes) to align the start address of model by model_align}
        @h2xmle_default     {0}
        @h2xmle_range       {0..8191}
        @h2xmle_group       {MODEL}
        @h2xmle_visibility  {hide}
        @h2xmle_policy      {Basic} */

   uint32_t model_size;
   /**< @h2xmle_description {Size of the model in bytes}
        @h2xmle_default     {0}
        @h2xmle_range       {0x00000000..0xFFFFFFFF}
        @h2xmle_group       {MODEL}
        @h2xmle_visibility  {hide}
        @h2xmle_policy      {Basic} */

   uint8_t model[0];
   /**< @h2xmle_description {Model data: The path to the model file on the platform}
        @h2xmle_elementType {rawData}
        @h2xmle_displayType {stringField}
        @h2xmle_group       {MODEL}
        @h2xmle_policy      {Basic} */

} param_id_vad_context_ml_model_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** @h2xmlp_subStruct */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct capi_vad_context_threshold_struct_t
{
   uint32_t context_id;
   /**< @h2xmle_description   {context ID for which threshold being set. Context_id is indepedent of mode_bit and usecase designer has to tune this based on model which is being set from application}
        @h2xmle_default       {MODULE_CMN_CONTEXT_ID_AMBIENCE_SPEECH}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced}
        @h2xmle_visibility      {hide} */

   uint32_t threshold;
   /**< @h2xmle_description   {Threshold confidence score value}
        @h2xmle_default       {50}
        @h2xmle_range         {0..100}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced} */

} capi_vad_context_threshold_struct_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_VAD_CONTEXT_THRESHOLD 0x08001BE3

/** @h2xmlp_parameter   {"PARAM_ID_VAD_CONTEXT_THRESHOLD", PARAM_ID_VAD_CONTEXT_THRESHOLD}
    @h2xmlp_description {Parameter to set context thresholds for VAD module.
	                     Threshold payload uses capi_vad_context_threshold_struct_t}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

typedef struct param_id_vad_context_threshold_t
{

   uint32_t num_contexts;
   /**< @h2xmle_description   {Number of contexts being set}
        @h2xmle_default       {1}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced}
        @h2xmle_visibility    {hide} */

#if defined(__H2XML__)
   capi_vad_context_threshold_struct_t threshold_array[0];
   /**< @h2xmle_description {pointer to context wise threshold structure}
        @h2xmle_variableArraySize   {num_contexts}
   */
#endif
} param_id_vad_context_threshold_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_VAD_SPEECH_DYNAMIC_CONFIG 0x08001BE4

/** @h2xmlp_parameter   {"PARAM_ID_VAD_SPEECH_DYNAMIC_CONFIG", PARAM_ID_VAD_SPEECH_DYNAMIC_CONFIG}
    @h2xmlp_description {Parameter to set dynamic config for speech/NVD. Applicable if speech_or_nvd bit is set and don't care for other modes}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_vad_speech_dynamic_config_t
{
   uint32_t len_hangover_speech;
   /**< @h2xmle_description   {Number of blocks of no detected speech before vad classification goes to 0}
        @h2xmle_default       {10}
        @h2xmle_range         {0..0xFFFF}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced} */

   uint32_t max_conf_frames_speech;
   /**< @h2xmle_description   {Number of blocks for capping speech confidence frames}
        @h2xmle_default       {300}
        @h2xmle_range         {0..0xFFFFFFFF}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced} */

   uint32_t min_conf_frames_speech;
   /**< @h2xmle_description   {Minimum confidence frames for speech detection}
        @h2xmle_default       {30}
        @h2xmle_range         {0..0xFFFFFFFF}
        @h2xmle_group         {GLOBAL}
        @h2xmle_policy        {Advanced} */

} param_id_vad_speech_dynamic_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_VAD_ENABLE_SPEECH_RESET 0x08001BE5

/** @h2xmlp_parameter   {"PARAM_ID_VAD_ENABLE_SPEECH_RESET", PARAM_ID_VAD_ENABLE_SPEECH_RESET}
    @h2xmlp_description {flag to enable speech reset}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_vad_enable_speech_reset_t
{

   int32_t enable_reset;
   /**< @h2xmle_description {flag to enable speech reset}
   @h2xmle_default     {1}
   @h2xmle_range       {0..1}
   @h2xmle_policy      {Advanced} */

} param_id_vad_enable_speech_reset_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_VAD_SPEECH_RESET_PERIOD 0x08001BE6

/** @h2xmlp_parameter   {"PARAM_ID_VAD_SPEECH_RESET_PERIOD", PARAM_ID_VAD_SPEECH_RESET_PERIOD}
    @h2xmlp_description {reset period in ms  }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_vad_speech_reset_period_t
{

   int32_t speech_reset_period_in_ms;
   /**< @h2xmle_description {reset period in milliseconds}
   @h2xmle_default     {3000}
   @h2xmle_range       {0..9000}
   @h2xmle_policy      {Advanced} */

} param_id_vad_speech_reset_period_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_VAD_PRE_ROLL_DURATION 0x08001BE7

/** @h2xmlp_parameter   {"PARAM_ID_VAD_PRE_ROLL_DURATION", PARAM_ID_VAD_PRE_ROLL_DURATION}
    @h2xmlp_description {Desired duration of pre roll history buffer in milliseconds.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_vad_pre_roll_duration_t
{

   uint32_t pre_roll_history_buffer_size_in_ms;
   /**< @h2xmle_description {Desired duration of pre roll history buffer in milliseconds}
   @h2xmle_default     {500}
   @h2xmle_range       {0..0x7D0}*/

} param_id_vad_pre_roll_duration_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/**    @}                   <-- End of the Module -->*/

#endif // #ifndef __VAD_API_H__
