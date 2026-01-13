#ifndef __MMA_API__
#define __MMA_API__

/*==============================================================================
  @file  mma_api.h
  @brief This file contains Public APIs for MMA module.

\copyright
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
===============================================================================*/

/*============================================================================
EDIT HISTORY FOR MODULE

when       who      what, where, why
--------    ------     -------------------------------------------------
10/5/24     vvenna     Created File.
============================================================================*/
#include "imcl_fwk_intent_api.h"

/**
   @h2xml_title1           {Module MMA API}
   @h2xml_title_agile_rev  {Module MMA API}
   @h2xml_title_date       {May 16, 2024}
*/
#define MMA_RELEASE_VERSION_MSB AR_NON_GUID(0x01000100)
#define MMA_RELEASE_VERSION_LSB AR_NON_GUID(0x00000000)

/*==============================================================================
   Constants
==============================================================================*/
#define CAPI_MMA_MAX_INPUT_PORTS 1
#define CAPI_MMA_MAX_OUTPUT_PORTS 0
#define CAPI_MMA_STACK_SIZE_REQUIREMENT 8192 // TODO: profile and update


/* Global unique Module ID definition.
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_MMA 0x07001177


/*==============================================================================
   Module definition
==============================================================================*/
/**
    @h2xml_title1          {Multi-Modal Activation Module API}
    @h2xml_title_agile_rev {Multi-Modal Activation Module API}
    @h2xml_title_date      {May 10, 2024} */

/** @h2xmlm_module       {"MODULE_ID_MMA",MODULE_ID_MMA}
    @h2xmlm_displayName  {"Multi-Modal Activation (MMA)"}
    @h2xmlm_description  {Supports the wakeup detection feature. \n // TODO: Update
 *      - #PARAM_ID_MMA_STATIC_CFG \n
 *      - #PARAM_ID_MMA_MODE_BIT_CONFIG \n
 *      - #PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG \n
 *      - #PARAM_ID_MMA_CONTEXT_THRESHOLD \n
 *      - #PARAM_ID_MMA_SPEECH_DYNAMIC_CFG \n
 *      - #PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG \n
 *      - #PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG \n
 *      - #PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG \n
 *      - #PARAM_ID_MMA_ENABLE_SPEECH_RESET \n
 *      - #PARAM_ID_MMA_SPEECH_RESET_PERIOD \n
 *      - #PARAM_ID_MMA_ILD_CONFIG \n
 *      - #PARAM_ID_MMA_HISTORY_BUFFER_SIZE \n
 *      - #PARAM_ID_MMA_RESET \n
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
    @h2xmlm_dataMaxInputPorts    {CAPI_MMA_MAX_INPUT_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {CAPI_MMA_MAX_OUTPUT_PORTS}
    @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {CAPI_MMA_STACK_SIZE_REQUIREMENT}
    @h2xmlm_ctrlDynamicPortIntent { "MMA-DAM Control"  = INTENT_ID_AUDIO_DAM_DETECTION_ENGINE_CTRL,
                                      maxPorts= 1 }

    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
*/

#define PARAM_ID_MMA_STATIC_CFG 0x08001AC4

/** @h2xmlp_parameter   {"PARAM_ID_MMA_STATIC_CFG", PARAM_ID_MMA_STATIC_CFG}
    @h2xmlp_description {Parameter for static configuration for MMA module.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_static_cfg_t {

    int32_t num_channel_processing;
    /**< @h2xmle_description   {Number of channel processing}
         @h2xmle_default       {1}
         @h2xmle_range         {1..2}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */
    int32_t conf_change;
    /**< @h2xmle_description   {Change in confidence level for sending detection update}
         @h2xmle_default       {1}
         @h2xmle_range         {0..100}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */
    int16_t mic_gain;
    /**< @h2xmle_description   {Microphone gain to be applied in Q4.11 format}
         @h2xmle_default       {0x0800}
         @h2xmle_range         {0..0x7FFF}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */

    int16_t reserved;
    /**< @h2xmle_description {Added for alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0000..0x0000}
         @h2xmle_visibility  {hide}
         @h2xmle_readOnly    {true} */

}param_id_mma_static_cfg_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_MODE_BIT_CONFIG 0x08001AC5

/** @h2xmlp_parameter   {"PARAM_ID_MMA_MODE_BIT_CONFIG", PARAM_ID_MMA_MODE_BIT_CONFIG}
    @h2xmlp_description {Parameter to get MMA mode bit config}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_mode_bit_config_t {


    uint32_t mode_bit;
    /**< @h2xmle_description {mode bit to enable different modalities}

    @h2xmle_bitfield        {0x00000001}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_0_NVD}
    @h2xmle_description     {Reserved}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000002}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_1_SPEECH_or_NVD}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Speech detection}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000004}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_2_TILT_TO_WAKE}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Tilt to talk}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000008}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_3_INTENT2SPEAK_ACCEL}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Intent to talk}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000010}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_4_CAMERA}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {camera}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000020}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_5_ONOFFBODY_DETECTION}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Onoffbody detection}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0xFFFFFFC0}
    @h2xmle_bitName         {Bit_31_6}
    @h2xmle_description     {Reserved}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    */

}param_id_mma_mode_bit_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG 0x08001AC6

/** @h2xmlp_parameter           {"PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG", PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG}
    @h2xmlp_description         {MMA stage1 ML MODEL}
    @h2xmlp_ToolPolicy          {CALIBRATION}
    @h2xmlp_isNeuralNetParam    {TRUE}
    @h2xmlp_isOffloaded         {TRUE}
    @h2xmlp_isHwAccel           {TRUE}
    @h2xmlp_persistType         {SHARED}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

typedef struct param_id_mma_context_ml_model_config_t
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

}param_id_mma_context_ml_model_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;



 /** @h2xmlp_subStruct */
/* Unique Paramter id */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct capi_mma_context_threshold_struct_t {

    uint32_t context_id;
    /**< @h2xmle_description   {context ID for which threshold being set}
         @h2xmle_default       {1}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */

    uint32_t threshold;
    /**< @h2xmle_description   {Threshold confidence score value}
         @h2xmle_default       {50}
         @h2xmle_range         {0..100}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */

} capi_mma_context_threshold_struct_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_CONTEXT_THRESHOLD 0x08001AC7

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CONTEXT_THRESHOLD", PARAM_ID_MMA_CONTEXT_THRESHOLD}
    @h2xmlp_description {Parameter to set context thresholds for MMA module.}
    @h2xmlp_toolPolicy  {Calibration}*/


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_context_threshold_t {

    uint32_t num_contexts;
    /**< @h2xmle_description   {Number of contexts being set}
         @h2xmle_default       {1}
         @h2xmle_range         {0..18}
         @h2xmle_group         {GLOBAL}
         @h2xmle_policy        {Advanced} */

#if defined (__H2XML__)
    capi_mma_context_threshold_struct_t threshold_array[0];
    /**< @h2xmle_description {pointer to context wise threshold structure}
         @h2xmle_default     {0x00000000}
         @h2xmle_variableArraySize   {num_contexts}
         @h2xmle_policy      {Advanced}
         @h2xmle_rawData */
#endif
}param_id_mma_context_threshold_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG 0x08001AC8

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG", PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG}
    @h2xmlp_description {Parameter to set dynamic config for speech/NVD.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_dynamic_config_t {

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

}param_id_mma_speech_dynamic_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;



#define PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG 0x08001AC9

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG", PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG}
    @h2xmlp_description {Parameter to enable continuous listening mode.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_continuous_listen_enable_config_t {

    int32_t continuous_listen_enable;
    /**< @h2xmle_description {Continuous listening mode enable}
    @h2xmle_default     {0}
    @h2xmle_range       {0..1}
    @h2xmle_policy      {Advanced} */

}param_id_mma_continuous_listen_enable_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG 0x08001ACA

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG", PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG}
    @h2xmlp_description {Timeout for continuous listening mode.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_continuous_listen_timeout_config_t {

    int32_t continuous_listen_timeout_in_ms;
    /**< @h2xmle_description {Continuous listen timeout in ms }
    @h2xmle_default     {2000}
    @h2xmle_range       {1..15000}
    @h2xmle_policy      {Advanced} */

}param_id_mma_continuous_listen_timeout_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG 0x08001ACB

/** @h2xmlp_parameter   {"PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG", PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG}
    @h2xmlp_description {Timeout for detection.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_detection_timeout_config_t {

    int32_t detection_timeout_in_ms;
    /**< @h2xmle_description {detection listen timeout in ms}
    @h2xmle_default     {2000}
    @h2xmle_range       {1..15000}
    @h2xmle_policy      {Advanced} */

}param_id_mma_detection_timeout_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_ENABLE_SPEECH_RESET 0x08001ACC

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ENABLE_SPEECH_RESET", PARAM_ID_MMA_ENABLE_SPEECH_RESET}
    @h2xmlp_description {flag to enable speech reset}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_enable_speech_reset_t {

    int32_t enable_reset;
    /**< @h2xmle_description {flag to enable speech reset}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_policy      {Advanced} */

}param_id_mma_enable_speech_reset_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_SPEECH_RESET_PERIOD 0x08001ACD

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_RESET_PERIOD", PARAM_ID_MMA_SPEECH_RESET_PERIOD}
    @h2xmlp_description {reset period in ms  }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_reset_period_t {

    int32_t speech_reset_period_in_ms;
    /**< @h2xmle_description {reset period in microseconds}
    @h2xmle_default     {3000}
    @h2xmle_range       {0..9000}
    @h2xmle_policy      {Advanced} */

}param_id_mma_speech_reset_period_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_ILD_CONFIG 0x08001ACE

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_CONFIG", PARAM_ID_MMA_ILD_CONFIG}
    @h2xmlp_description {ILD configuration }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_config_param_t {

    int32_t ild_enable;
    /**< @h2xmle_description {Enable or disable ILD mechanism.}
     @h2xmle_default     {0}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_ILD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_threshold_Q16;
    /**< @h2xmle_description {Configure an ILD threshold.}
     @h2xmle_default     {131072}
    @h2xmle_range       {65536..2147483647}
    @h2xmle_group       {MMA_ILD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_buff_duration_in_ms;  //ILD exposed API has it in frames. Do translation in MMA
    /**< @h2xmle_description {HIstory buffer duration.}
     @h2xmle_default     {500}
    @h2xmle_range       {500..3000}
    @h2xmle_group       {MMA_ILD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

}param_id_mma_ild_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


// #define PARAM_ID_MMA_SPEECH_RESET_PERIOD 0x08001AD3

// /** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_RESET_PERIOD", PARAM_ID_MMA_SPEECH_RESET_PERIOD}
    // @h2xmlp_description {reset period in ms  }
    // @h2xmlp_toolPolicy  {Calibration}*/

// #include "spf_begin_pack.h"
// #include "spf_begin_pragma.h"
// typedef struct param_id_mma_speech_reset_period_t {

    // int32_t speech_reset_period_in_ms;
    // /**< @h2xmle_description {reset period in microseconds}
    // @h2xmle_default     {3000}
    // @h2xmle_range       {0..9000}
    // @h2xmle_policy      {Advanced} */

// }param_id_mma_speech_reset_period_t
// #include "spf_end_pragma.h"
// #include "spf_end_pack.h"
// ;


#define PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR 0x08001AD2

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR", PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR}
    @h2xmlp_description {state forget factor for speech model  }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_state_forget_factor_t {

    int16_t state_forget_factor;
    /**< @h2xmle_description {state forget factor in Q14}
    @h2xmle_default     {16384}
    @h2xmle_range       {0..16384}
    @h2xmle_policy      {Advanced} */

    int16_t reserved;
    /**< @h2xmle_description {reserved}
    @h2xmle_default     {0}
    @h2xmle_range       {0..0x7FFF}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

}param_id_mma_speech_state_forget_factor_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_HISTORY_BUFFER_SIZE 0x08001ACF

/** @h2xmlp_parameter   {"PARAM_ID_MMA_HISTORY_BUFFER_SIZE", PARAM_ID_MMA_HISTORY_BUFFER_SIZE}
    @h2xmlp_description {Desired duration of history buffer in milli seconds.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_history_buffer_size_t {

    uint32_t history_buffer_size_in_ms;
    /**< @h2xmle_description {Desired duration of history buffer in milli seconds}
    @h2xmle_default     {2000}
    @h2xmle_range       {0..0xFFFFFFFF}*/

}param_id_mma_history_buffer_size_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_MMA_RESET 0x08001AD0

/**@h2xmlp_emptyParameter {"PARAM_ID_MMA_RESET", PARAM_ID_MMA_RESET}
    @h2xmlp_description   {Resets the MMA module to its initial algorithm stage and begins a new detection.}
    @h2xmlp_toolPolicy    {NO_SUPPORT} */

#define EVENT_ID_MMA_DETECTION_EVENT 0x08001AD1
/** @h2xmlp_parameter   {"EVENT_ID_MMA_DETECTION_EVENT",
                          EVENT_ID_MMA_DETECTION_EVENT}
    @h2xmlp_description { Detection event raised by the MMA module.}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

typedef struct event_id_mma_detection_event_t
{
    uint32_t context_id;
    /**< @h2xmle_description   {context ID for MMA detection?}
     @h2xmle_default       {0}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    uint32_t mode_mask_bits;
    /**< @h2xmle_description   {Mode mask bits?}
     @h2xmle_default       {0}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    uint32_t detection_event_bits;
    /**< @h2xmle_description   {Detection event bits}
     @h2xmle_default       {0}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */
    uint32_t detection_event_bits_after_mask;
    /**< @h2xmle_description   {Detection event bits after mask}
     @h2xmle_default       {0}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t multi_modal_detection_flag;
     /**< @h2xmle_description   {multi modal detection flag}
     @h2xmle_default       {0}
     @h2xmle_range         {0..1}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t curr_detection_timer_enabled_flag;
    /**< @h2xmle_description   {current detection timer enabled flag}
     @h2xmle_default       {0}
     @h2xmle_range         {0..1}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t curr_detection_timer_counter_in_frames;
    /**< @h2xmle_description   {current detection timer counter in frames}
     @h2xmle_default       {0}
     @h2xmle_range         {0..0x7FFFFFFF}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t detection_timeout_in_frames;
    /**< @h2xmle_description   {detection timeout in frames}
     @h2xmle_default       {0}
     @h2xmle_range         {0..0x7FFFFFFF}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t continuous_listen_enabled_flag;
    /**< @h2xmle_description   {continuous listening mode enabled flag}
     @h2xmle_default       {0}
     @h2xmle_range         {0..1}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t continuous_listen_mode_on_flag_after_detection;
    /**< @h2xmle_description   {continuous listening mode on flag after detection}
     @h2xmle_default       {0}
     @h2xmle_range         {0..1}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t continuous_listen_timer_counter_in_frames;
    /**< @h2xmle_description   {continuous listening mode timer counter in frames}
     @h2xmle_default       {0}
     @h2xmle_range         {0..0x7FFFFFFF}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

    int32_t continuous_listen_timeout_in_frames;
    /**< @h2xmle_description   {continuous listening mode timeout in frames}
     @h2xmle_default       {0}
     @h2xmle_range         {0..0x7FFFFFFF}
     @h2xmle_group         {GLOBAL}
     @h2xmle_policy        {Advanced} */

}event_id_mma_detection_event_t;

/**    @}                   <-- End of the Module -->*/

#endif // #ifndef __MMA_API__
