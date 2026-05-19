#ifndef __MMA_API_H__
#define __MMA_API_H__

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
#include "contexts_api.h"

/**
   @h2xml_title1           {Module MMA API}
   @h2xml_title_agile_rev  {Module MMA API}
   @h2xml_title_date       {July 5, 2024}
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
    @h2xml_title_date      {July 5, 2024} */

/** @h2xmlm_module       {"MODULE_ID_MMA",MODULE_ID_MMA}
    @h2xmlm_displayName  {"Multi-Modal Activation (MMA)"}
    @h2xmlm_description  {Supports the wakeup detection feature. \n
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
 *      - #PARAM_ID_MMA_CAMERA_CONFIG \n
 *      - #PARAM_ID_MMA_HISTORY_BUFFER_SIZE \n
 *      - #PARAM_ID_MMA_RESET \n
 *      - #PARAM_ID_MMA_ILD_RMS_CONFIG \n
 *      - #PARAM_ID_MMA_ILD_COH_CONFIG \n
 *      - #PARAM_ID_MMA_ILD_MEDFILT_CONFIG \n
 *      - #PARAM_ID_MMA_ILD_PND_CONFIG \n
 *      - #PARAM_ID_MMA_ILD_LMS_CONFIG \n
 *      - #PARAM_ID_MMA_LVD_CONFIG \n
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
typedef struct param_id_mma_static_cfg_t
{

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

} param_id_mma_static_cfg_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_MODE_BIT_CONFIG 0x08001AC5

/** @h2xmlp_parameter   {"PARAM_ID_MMA_MODE_BIT_CONFIG", PARAM_ID_MMA_MODE_BIT_CONFIG}
    @h2xmlp_description {Parameter to get MMA library version.\n
                                0x00000006  TILT-N_TALK: Tilt2Talk + Speech(or mid-distance speech) Detection \n
*                               0x0000000A  Lift-N-Talk :Intent2Speak + NVD  // CAPI doesnt expose NVD bit. So speech is enabled \n
*                               0x00000026  Lift-Gaze-Talk:Tilt2Talk + Gaze Detection + Speech(or mid-distance speech) Detection \n
*                               0x00000016  Lift-Face-Talk:Tilt2Talk + Face Detection + Speech(or mid-distance speech) Detection \n
*                               0x00000022  Gaze-N-Talk:Gaze Detection + Speech(or mid-distance speech) Detection \n
*                               0x0000002A  Lift-Gaze-Talk_1 :Intent2Speak+ Gaze Detection + Speech(or mid-distance speech) Detection \n
*                               0x0000001A  Lift-Face-Talk_1 :Intent2Speak+ Face Detection + Speech(or mid-distance speech) Detection \n }
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_mode_bit_config_t
{

    uint32_t mode_bit;
    /**< @h2xmle_description {mode bit to enable different modalities}

    @h2xmle_bitfield        {0x00000001}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_0}
    @h2xmle_description     {Reserved}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000002}
    @h2xmle_default         {1}
    @h2xmle_bitName         {Bit_1_SPEECH_or_NVD}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Speech detection}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000004}
    @h2xmle_default         {1}
    @h2xmle_bitName         {Bit_2_TILT_TO_WAKE}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Tilt to talk}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000008}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_3_INTENT2SPEAK_ACCEL}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Intent to talk}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000010}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_4_CAMERA_FACE}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {camera face}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000020}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_5_CAMERA_GAZE}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {camera gaze}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000040}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_6_ONOFFBODY_DETECTION}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Onoffbody detection}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x00000080}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_7_AMD}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Any Motion Detection}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0xFFFFFF00}
    @h2xmle_bitName         {Bit_30_8}
    @h2xmle_description     {Reserved}
    @h2xmle_visibility      {hide}
    @h2xmle_bitfieldEnd

    @h2xmle_bitfield        {0x80000000}
    @h2xmle_default         {0}
    @h2xmle_bitName         {Bit_31_SYNTHETIC_MODALITY_DETECTIONS_FEATURE}
    @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
    @h2xmle_description     {Enable synthetic modality detection feature for testing. When enabled, Module automatically generates detection events for non-audio modalities (sensors/camera) at configured intervals.}
    @h2xmle_bitfieldEnd

    */

} param_id_mma_mode_bit_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG 0x08001AC6

/** @h2xmlp_parameter           {"PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG", PARAM_ID_MMA_CONTEXT_ML_MODEL_CONFIG}
    @h2xmlp_description         {MMA stage1 ML MODEL}
    @h2xmlp_ToolPolicy          {Calibration}
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

} param_id_mma_context_ml_model_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** @h2xmlp_subStruct */
/* Unique Parameter id */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct capi_mma_context_threshold_struct_t
{

    uint32_t context_id;
    /**< @h2xmle_description   {context ID for which threshold being set. Context_id is indepedent of mode_bit and usecase designer has to tune this based on model which is being set from application}
         @h2xmle_default       {MODULE_CMN_CONTEXT_ID_AMBIENCE_SPEECH}
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
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_context_threshold_t
{

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
} param_id_mma_context_threshold_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG 0x08001AC8

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG", PARAM_ID_MMA_SPEECH_DYNAMIC_CONFIG}
    @h2xmlp_description {Parameter to set dynamic config for speech/NVD. Applicable if speech_or_nvd bit is set and don't care for other modes}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_dynamic_config_t
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

} param_id_mma_speech_dynamic_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG 0x08001AC9

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG", PARAM_ID_MMA_CONTINUOUS_LISTEN_ENABLE_CONFIG}
    @h2xmlp_description {Parameter to enable continuous listening mode.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_continuous_listen_enable_config_t
{

    int32_t continuous_listen_enable;
    /**< @h2xmle_description {Continuous listening mode enable}
    @h2xmle_default     {0}
    @h2xmle_range       {0..1}
    @h2xmle_policy      {Advanced} */

} param_id_mma_continuous_listen_enable_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG 0x08001ACA

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG", PARAM_ID_MMA_CONTINUOUS_LISTEN_TIMEOUT_CONFIG}
    @h2xmlp_description {Timeout for continuous listening mode.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_continuous_listen_timeout_config_t
{

    int32_t continuous_listen_timeout_in_ms;
    /**< @h2xmle_description {Continuous listen timeout in ms }
    @h2xmle_default     {2000}
    @h2xmle_range       {1000..15000}
    @h2xmle_policy      {Advanced} */

} param_id_mma_continuous_listen_timeout_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG 0x08001ACB

/** @h2xmlp_parameter   {"PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG", PARAM_ID_MMA_DETECTION_TIMEOUT_CONFIG}
    @h2xmlp_description {Timeout for detection.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_detection_timeout_config_t
{

    int32_t detection_timeout_in_ms;
    /**< @h2xmle_description {detection listen timeout in ms}
    @h2xmle_default     {2000}
    @h2xmle_range       {1000..15000}
    @h2xmle_policy      {Advanced} */

} param_id_mma_detection_timeout_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ENABLE_SPEECH_RESET 0x08001ACC

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ENABLE_SPEECH_RESET", PARAM_ID_MMA_ENABLE_SPEECH_RESET}
    @h2xmlp_description {flag to enable speech reset}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_enable_speech_reset_t
{

    int32_t enable_reset;
    /**< @h2xmle_description {flag to enable speech reset}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_policy      {Advanced} */

} param_id_mma_enable_speech_reset_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_SPEECH_RESET_PERIOD 0x08001ACD

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_RESET_PERIOD", PARAM_ID_MMA_SPEECH_RESET_PERIOD}
    @h2xmlp_description {reset period in ms  }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_reset_period_t
{

    int32_t speech_reset_period_in_ms;
    /**< @h2xmle_description {reset period in microseconds}
    @h2xmle_default     {3000}
    @h2xmle_range       {0..9000}
    @h2xmle_policy      {Advanced} */

} param_id_mma_speech_reset_period_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_CONFIG 0x08001ACE

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_CONFIG", PARAM_ID_MMA_ILD_CONFIG}
    @h2xmlp_description {ILD(interaural level difference) configuration, During multi channel processing checks the signal level difference between input channels for better detection rate }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_config_param_t
{

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

    int32_t ild_buff_duration_in_ms;
    /**< @h2xmle_description {HIstory buffer duration for which rms value evaluation happen for successful detection}
    @h2xmle_default     {300}
    @h2xmle_range       {20..3000}
    @h2xmle_group       {MMA_ILD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_RMS_CONFIG 0x08001BD4

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_RMS_CONFIG", PARAM_ID_MMA_ILD_RMS_CONFIG}
    @h2xmlp_description {ILD RMS configuration for microphone level detection}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_rms_config_param_t
{
    int32_t ild_bot_mic_dBFS;
    /**< @h2xmle_description {Configure bottom microphone absolute RMS level.}
    @h2xmle_default     {-52}
    @h2xmle_range       {-70..-40}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_top_mic_dBFS;
    /**< @h2xmle_description {Configure top microphone absolute RMS level.}
    @h2xmle_default     {-70}
    @h2xmle_range       {-70..-40}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_freq_min_bin;
    /**< @h2xmle_description {Configure an ILD frequency min bin.}
    @h2xmle_default     {2}
    @h2xmle_range       {1..160}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_freq_max_bin;
    /**< @h2xmle_description {Configure an ILD frequency max bin.}
    @h2xmle_default     {120}
    @h2xmle_range       {1..160}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_threshold_upbound_Q16;
    /**< @h2xmle_description {Configure an ILD threshold upper bound.}
    @h2xmle_default     {20724302}
    @h2xmle_range       {1..207243020}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t ild_time_domain_check_enable;
    /**< @h2xmle_description {Configure ild_time_domain_check_enable.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_group       {MMA_RMS}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_rms_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_COH_CONFIG 0x08001BD5

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_COH_CONFIG", PARAM_ID_MMA_ILD_COH_CONFIG}
    @h2xmlp_description {ILD Coherence configuration for signal correlation analysis}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_coh_config_param_t
{
    int16_t coh_1st_enable;
    /**< @h2xmle_description {Enable or disable 1st coherence check.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int16_t coh_2nd_enable;
    /**< @h2xmle_description {Enable or disable 2nd coherence check.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_1st_threshold_Q16;
    /**< @h2xmle_description {Configure a 1st coherence threshold. Default value 19660 corresponds to 0.3 in floating format}
    @h2xmle_default     {19660}
    @h2xmle_range       {1..65535}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_1st_start_bin;
    /**< @h2xmle_description {Configure a 1st coherence start bin.}
    @h2xmle_default     {2}
    @h2xmle_range       {0..160}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_1st_end_bin;
    /**< @h2xmle_description {Configure a 1st coherence end bin.}
    @h2xmle_default     {11}
    @h2xmle_range       {0..160}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_2nd_threshold_Q16;
    /**< @h2xmle_description {Configure a 2nd coherence threshold. Default value 19660 corresponds to 0.3 in floating format}
    @h2xmle_default     {19660}
    @h2xmle_range       {1..65535}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_2nd_start_bin;
    /**< @h2xmle_description {Configure a 2nd coherence start bin.}
    @h2xmle_default     {20}
    @h2xmle_range       {0..160}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t coh_2nd_end_bin;
    /**< @h2xmle_description {Configure a 2nd coherence end bin.}
    @h2xmle_default     {60}
    @h2xmle_range       {0..160}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_group       {MMA_COH}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_coh_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_MEDFILT_CONFIG 0x08001BD6

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_MEDFILT_CONFIG", PARAM_ID_MMA_ILD_MEDFILT_CONFIG}
    @h2xmlp_description {ILD Median Filter configuration for noise reduction}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_medfilt_config_param_t
{
    int16_t medfilt_enable;
    /**< @h2xmle_description {Enable or disable median filter.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_MEDFILT}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int16_t medfilt_kernel_width;
    /**< @h2xmle_description {Configure median filter kernel width.}
    @h2xmle_default     {5}
    @h2xmle_range       {1..9}
    @h2xmle_group       {MMA_MEDFILT}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_range       {0..160}
    @h2xmle_group       {MMA_MEDFILT}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_medfilt_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_PND_CONFIG 0x08001BD7

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_PND_CONFIG", PARAM_ID_MMA_ILD_PND_CONFIG}
    @h2xmlp_description {ILD Pulsive Noise Detection configuration}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_pnd_config_param_t
{
    int32_t pnd_enable;
    /**< @h2xmle_description {Enable or disable pulsive noise detection.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_PND}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t pnd_long_window_in_frame;
    /**< @h2xmle_description {Configure long window's length in the unit of frame.}
    @h2xmle_default     {20}
    @h2xmle_range       {1..50}
    @h2xmle_group       {MMA_PND}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t pnd_short_window_in_frame;
    /**< @h2xmle_description {Configure short window's length in the unit of frame.}
    @h2xmle_default     {2}
    @h2xmle_range       {1..10}
    @h2xmle_group       {MMA_PND}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t pnd_threshold_Q16;
    /**< @h2xmle_description {Configure threshold for pulsive noise detection. Default value 3284580 corresponds to 17dB in floating format}
    @h2xmle_default     {3284580}
    @h2xmle_range       {0..65536000}
    @h2xmle_group       {MMA_PND}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_group       {MMA_PND}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_pnd_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_ILD_LMS_CONFIG 0x08001BD8

/** @h2xmlp_parameter   {"PARAM_ID_MMA_ILD_LMS_CONFIG", PARAM_ID_MMA_ILD_LMS_CONFIG}
    @h2xmlp_description {ILD LMS (Least Mean Squares) adaptive filter configuration}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_ild_lms_config_param_t
{
    int32_t lms_enable;
    /**< @h2xmle_description {Enable or disable LMS.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_tap_num;
    /**< @h2xmle_description {Configure the number of taps in LMS filter.}
    @h2xmle_default     {40}
    @h2xmle_range       {1..50}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_delay;
    /**< @h2xmle_description {Configure the number of samples to be delayed for input signal.}
    @h2xmle_default     {20}
    @h2xmle_range       {1..40}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_mu_Q15;
    /**< @h2xmle_description {Configure the learning rate for LMS filter.}
    @h2xmle_default     {8192}
    @h2xmle_range       {1..32767}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_peak_index_min;
    /**< @h2xmle_description {Configure the minimum peak index.}
    @h2xmle_default     {10}
    @h2xmle_range       {1..20}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_peak_index_max;
    /**< @h2xmle_description {Configure the maximum peak index.}
    @h2xmle_default     {16}
    @h2xmle_range       {1..20}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_peak_value_thres_Q29;
    /**< @h2xmle_description {Configure the peak threshold.}
    @h2xmle_default     {805306368}
    @h2xmle_range       {0..1610612736}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_p2s_ratio_Q16;
    /**< @h2xmle_description {Configure the peak-to-surround ratio threshold.}
    @h2xmle_default     {262144}
    @h2xmle_range       {0..393216}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lms_erle_ratio_Q16;
    /**< @h2xmle_description {Configure the erle ratio threshold.}
    @h2xmle_default     {26214}
    @h2xmle_range       {0..65536}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_group       {MMA_LMS}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_ild_lms_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_LVD_CONFIG 0x08001BD9

/** @h2xmlp_parameter   {"PARAM_ID_MMA_LVD_CONFIG", PARAM_ID_MMA_LVD_CONFIG}
    @h2xmlp_description {LVD (Level Voice Detection) configuration}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_lvd_config_param_t
{
    int32_t lvd_enable;
    /**< @h2xmle_description {Enable or disable LVD mechanism.}
    @h2xmle_default     {1}
    @h2xmle_range       {0..1}
    @h2xmle_group       {MMA_LVD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lvd_threshold_Q20;
    /**< @h2xmle_description {Configure an LVD threshold.}
    @h2xmle_default     {943718}
    @h2xmle_range       {1..1048576}
    @h2xmle_group       {MMA_LVD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lvd_lookback_window_in_ms;
    /**< @h2xmle_description {look back window duration in the unit of milliseconds.}
    @h2xmle_default     {200}
    @h2xmle_range       {10..3000}
    @h2xmle_group       {MMA_LVD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t lvd_lookahead_window_in_ms;
    /**< @h2xmle_description {look ahead window duration in the unit of milliseconds.}
    @h2xmle_default     {200}
    @h2xmle_range       {10..3000}
    @h2xmle_group       {MMA_LVD}
    @h2xmle_subgroup    {General}
    @h2xmle_policy      {Advanced} */

    int32_t reserved;
    /**< @h2xmle_description {Reserved.}
    @h2xmle_default     {0}
    @h2xmle_group       {MMA_LVD}
    @h2xmle_subgroup    {General}
    @h2xmle_visibility  {hide}
    @h2xmle_policy      {Advanced} */

} param_id_mma_lvd_config_param_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR 0x08001AD2

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR", PARAM_ID_MMA_SPEECH_STATE_FORGET_FACTOR}
    @h2xmlp_description {state forget factor for speech model, During reset will change the current state to some intermediate state instead of restting to state 0 }
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_speech_state_forget_factor_t
{

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

} param_id_mma_speech_state_forget_factor_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef enum _camera_fd_delivery_mode
{
   MMA_CAMERA_FD_DELIVERY_MODE_MOTION_BASED = 0,
   MMA_CAMERA_FD_DELIVERY_MODE_TIME_BASED   = 1
} camera_fd_delivery_mode;

#define PARAM_ID_MMA_CAMERA_CONFIG 0x08001B0F

/** @h2xmlp_parameter   {"PARAM_ID_MMA_CAMERA_CONFIG", PARAM_ID_MMA_CAMERA_CONFIG}
    @h2xmlp_description {CAMERA face detection config - this will be set when modality bits of camera_face or camera_gaze are set}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_camera_config_t
{

    uint32_t delivery_mode; // delivery_mode, refer enum camera_fd_delivery_mode
    /**< @h2xmle_description {delivery mode}
    @h2xmle_default     {0}
    @h2xmle_rangeList   {"MMA_CAMERA_FD_DELIVERY_MODE_MOTION_BASED"=0,"MMA_CAMERA_FD_DELIVERY_MODE_TIME_BASED"=1 }
    @h2xmle_policy      {Advanced} */
    uint32_t detections_per_delivery;
    /**< @h2xmle_description {Number of times detections are performed per delivery(applicable for both delivery_mode -
    MOTION_BASED and TIME_BASED).}
    @h2xmle_default     {1}
    @h2xmle_range       {1..100}
    @h2xmle_policy      {Advanced} */
    uint32_t delivery_period_in_ms;
    /**< @h2xmle_description {Delivery period in ms mentions how often events will be delivered. Delivery period in ms is
    applicable only when delivery_mode is set as TIME_BASED.}
    @h2xmle_default     {1000}
    @h2xmle_range       {1..10000}
    @h2xmle_policy      {Advanced} */

} param_id_mma_camera_config_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_HISTORY_BUFFER_SIZE 0x08001ACF

/** @h2xmlp_parameter   {"PARAM_ID_MMA_HISTORY_BUFFER_SIZE", PARAM_ID_MMA_HISTORY_BUFFER_SIZE}
    @h2xmlp_description {Desired duration of history buffer in milli seconds.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_history_buffer_size_t
{

    uint32_t history_buffer_size_in_ms;
    /**< @h2xmle_description {Desired duration of history buffer in milli seconds}
    @h2xmle_default     {2000}
    @h2xmle_range       {0..0x30000}*/

} param_id_mma_history_buffer_size_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define PARAM_ID_MMA_SYNTHETIC_MODALITY_DETECTION_DURATION 0x08001BE8

/** @h2xmlp_parameter   {"PARAM_ID_MMA_SYNTHETIC_MODALITY_DETECTION_DURATION", PARAM_ID_MMA_SYNTHETIC_MODALITY_DETECTION_DURATION}
    @h2xmlp_description {duration of synthetic detection generation}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct param_id_mma_synthetic_modality_detection_duration_t
{

    uint32_t synthetic_modality_detection_duration_in_ms;
    /**< @h2xmle_description {Time interval in milliseconds at which synthetic detection events are automatically generated for enabled non-audio modalities (sensors/camera). Only active when bit 31 of mode_bit is enabled.}
    @h2xmle_default     {10000}
    @h2xmle_range       {5000..15000}
    @h2xmle_policy      {Advanced} */

} param_id_mma_synthetic_modality_detection_duration_t
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

} event_id_mma_detection_event_t;

/**    @}                   <-- End of the Module -->*/

#endif // #ifndef __MMA_API_H__
