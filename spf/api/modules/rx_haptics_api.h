#ifndef __RX_HAPTICS_API_H__
#define __RX_HAPTICS_API_H__

/*==============================================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause

  @file rx_haptics_api.h
  @brief This file contains APIs for Haptics Module
==============================================================================*/

/*==============================================================================
  Edit History

  when          who        what, where, why
  --------      ---        ------------------------------------------------------
  06/21/2022    deepjind   Haptics
  02/28/2025    shyap      Haptics v2.3
==============================================================================*/

/** @h2xml_title1           {Haptics-RX}
    @h2xml_title_date       {June 21, 2022} */
#include "module_cmn_api.h"
#include "ar_defs.h"
#include "imcl_spm_intent_api.h"
#include "rtm_logging_api.h"

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/*==============================================================================
   Constants
==============================================================================*/
#define HAPTICS_MAX_INPUT_PORTS 1
#define HAPTICS_MAX_OUTPUT_PORTS 1
#define HAPTICS_STACK_SIZE 4096

/* Unique Module ID */
#define MODULE_ID_HAPTICS 0x070010E6

/** @h2xmlm_module       {"MODULE_ID_HAPTICS",
                          MODULE_ID_HAPTICS}
    @h2xmlm_displayName  {"HAPTICS-RX"}
    @h2xmlm_toolPolicy   {Calibration;CALIBRATION}
    @h2xmlm_description  {ID of the HAPTICS module.\n
      This module includes Haptics waveform designer block, Excursion control and
      CPS processing.

      This module supports the following parameter IDs:\n
     - #PARAM_ID_MODULE_ENABLE \n
     - #PARAM_ID_RTM_LOGGING_ENABLE\n
     - #PARAM_ID_HAPTICS_STATIC_CFG\n
     - #PARAM_ID_HAPTICS_OP_MODE\n
     - #PARAM_ID_HAPTICS_DYNAMIC_CFG\n
     - #PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG\n
     - #PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG_V2\n
     - #PARAM_ID_HAPTICS_WAVE_DESIGNER_STOP_PARAM\n
     - #PARAM_ID_HAPTICS_WAVE_DESIGNER_UPDATE_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_0_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_1_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_2_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_3_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_4_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_5_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_6_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_7_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_8_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_9_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_10_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_11_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_12_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_13_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EFFECT_14_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_CPS_PARAM\n
     - #PARAM_ID_HAPTICS_CPS_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_EX_CPS_DEMO_PKT_PARAM\n
     - #PARAM_ID_HAPTICS_EX_CPS_DEMO_PARAM\n
     - #PARAM_ID_HAPTICS_EX_DEMO_PKT_PARAM\n
     - #PARAM_ID_HAPTICS_EX_DEMO_PARAM\n
     - #PARAM_ID_HAPTICS_VERSION\n
     - #PARAM_ID_HAPTICS_WAVE_DESIGNER_STATE\n
     - #PARAM_ID_HAPTICS_RX_EFFECTS_CONFIG_PARAM\n
     - #PARAM_ID_HAPTICS_RX_FTM_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_RX_CALIB_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_RX_PERSISTENT_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_RX_PCMV_PLAYBACK\n
     - #PARAM_ID_HAPTICS_RX_FTM_CFG\n
     - #PARAM_ID_HAPTICS_LPASS_SWR_HW_REG_CFG\n
     - #PARAM_ID_HAPTICS_RX_TUNING_DATA_0_PARAM\n
     - #PARAM_ID_HAPTICS_RX_TUNING_DATA_1_PARAM\n
     - #PARAM_ID_HAPTICS_RX_TUNING_DATA_2_PARAM\n
     - #PARAM_ID_HAPTICS_RX_TUNING_DATA_3_PARAM\n
     - #PARAM_ID_HAPTICS_RX_TUNING_DATA_4_PARAM\n
     - #PARAM_ID_HAPTICS_RX_VISENSE_CFG\n

      All parameter IDs are device independent.\n

     Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 48000\n
*  - Number of channels   : 1 and 2\n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 16, 32\n
*  - Q format             : 15 for bps = 16 and 31 for bps = 32\n
supported bps
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

     @h2xmlm_toolPolicy              {Calibration}

     @h2xmlm_dataMaxInputPorts    {HAPTICS_MAX_INPUT_PORTS}
     @h2xmlm_dataInputPorts       {IN=2}
     @h2xmlm_dataMaxOutputPorts   {HAPTICS_MAX_OUTPUT_PORTS}
     @h2xmlm_dataOutputPorts      {OUT=1}
     @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_GC}
     @h2xmlm_isOffloadable        {false}
     @h2xmlm_stackSize            {HAPTICS_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent  { "Haptics VI intent id for communicating Vsens and Isens data" = 0x0800136E, maxPorts=
1 }
     @h2xmlm_ToolPolicy              {Calibration}


    @{                   <-- Start of the Module -->
 @h2xml_Select        {"param_id_module_enable_t"}
 @h2xmlm_InsertParameter

 @h2xml_Select        {"rtm_logging_enable_payload_t"}
 @h2xmlm_InsertParameter
*/
/*------------------------------------------------------------------------------
   Parameters
------------------------------------------------------------------------------*/
/*==============================================================================
   Constants
==============================================================================*/

/* Number of plotting samples in one excursion Rx output packet. */
#define HAPTICS_EX_RX_DEMO_SMPL_PER_PKT 10

/* Max number of vbatt resistance table */
#define NVBATT_DISCRETE (9)

/* Max number of die temp resistance table */
#define NDTEMP_DISCRETE (14)

/* Max number of vbatt fine resistance table */
#define NVBATT_DISCRETE_FINE (13)

/* Max number of resistance table */
#define NRE_DISCRETE (3)

// Maximum output channels
#define HAPTICS_MAX_OUT_CHAN  (2)

/*typedef enum WAVE_DSN_MODE_T {
    MIN_WAVE_DSN_MODE = 0,
    PARAMETRIC = 0, // Parametric waveform designer mode
    PWL = 1,        // Piece-wise linear waveform designer mode
    SINUSOIDAL = 2, // Sinusoidal waveform designer mode
    PCMV_RINGTONE = 3,  // Pre-canned haptics waveform mode for ringtone haptics
    PCMV_EFFECTS = 4,   // Pre-canned haptics waveform mode for pre-defined effects
    PCMV_PLAYBACK = 5, // Pre-canned haptics waveform mode for pcmv playback from HLOS
    MAX_WAVE_DSN_MODE = 0xFFFFFFFF  // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} WAVE_DSN_MODE_T; */

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_STATIC_CFG 0x080014E7

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_static_config_t param_id_haptics_static_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_STATIC_CFG",
                          PARAM_ID_HAPTICS_STATIC_CFG}
    @h2xmlp_description {Parameters used to configure the static configuration of
                         WSA smart haptics Rx processing.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_static_config_t
{
    uint32_t sampling_rate;         // PCM signal sampling rate
    /**< @h2xmle_description {Sampling rate of Rx signal.}
         @h2xmle_rangeList   {"48kHz"=48000}
         @h2xmle_default     {48000} */
    uint32_t bits_per_sample;       // Number of bits for input and output samples, (per channel)
    /**< @h2xmle_description {Bits per sample for Rx signal.}
         @h2xmle_rangeList   {"16"=16;"32"=32}
         @h2xmle_default     {16} */
    uint32_t num_channels;          // Number of LRAs/ number of channels for Rx signal.
    /**< @h2xmle_description {Number of channels for Rx signal.}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    uint32_t frame_size_ms;         // processing frame size in ms
    /**< @h2xmle_description {Frame size for Rx processing in ms.}
         @h2xmle_rangeList   {"1ms"=1}
         @h2xmle_default     {1} */
    uint32_t features;              // what sub-features are on
    /**< @h2xmle_description {Features enabled in the WSA smart haptics
                            algorithm.}
         @h2xmle_range       {0..0x07}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Thermal tracking"}
         @h2xmle_description {Thermal tracking}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Excursion control"}
         @h2xmle_description {Excursion control}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd 
         
         @h2xmle_bitField    {0x00000004}
         @h2xmle_bitName     {"Excursion control static gain support"}
         @h2xmle_description {Excursion control static gain support}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */
    uint32_t pt_lvl_switch_en;      // dynamic pilot tone level switch enable/disable flag
    /**< @h2xmle_description {Flag to enable/disable the dynamic pilot tone level switch.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0} */
    int32_t pt_masking_thr_q27;     // when input level is below this threshold, pilot tone is disabled
    /**< @h2xmle_description {Specifies the input level threshold below which the pilot tone is disabled.}
         @h2xmle_range       {0..0x7FFFFFFF}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {134217728} */
    uint32_t ex_block_size;
    /**< @h2xmle_description {excursion control block size - number of frames used for excursion control}
         @h2xmle_range       {3..3}
         @h2xmle_default     {3} */
    int32_t Mu_gram_q20;
    /**< @h2xmle_description {Mechanical mass of the handset in grams. Default value: 200g, Range: 0 to 2048g}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {209715200} */
    uint32_t fpilot_Hz;      // Pilot tone frequency [40] 40 Hz.
                             // Note: Pilot tone frequency values MUST be the same for the RX/TH/EX modules.
    /**< @h2xmle_description {Pilot tone frequency in Hz. Pilot tone frequency values MUST be the same for the RX/TH/EX modules}
         @h2xmle_rangeList   {"40"=40} Hz
         @h2xmle_default     {40} */
    int32_t fpilot_amplitude_db;    // Pilot tone amplitude [-37] -37dB.
                                    // Note: Pilot tone amplitude values MUST be the same for the RX/TH/EX modules.
    /**< @h2xmle_description {Pilot tone amplitude relative to 0 dbFS (for example, -37 dB from the full scale), in dB. Pilot tone amplitude values MUST be the same for the RX/TH/EX modules}
         @h2xmle_range       {-40..-30} dB
         @h2xmle_default     {-37} */
    int32_t tracked_freq_warmup_time_ms;  // Time delay before enabling resonance frequency tracking (in ms).
    /**< @h2xmle_description {Time delay before enabling resonance frequency tracking, in ms.}
         @h2xmle_range       {0..10000} ms
         @h2xmle_default     {50} */
    int32_t settling_time_ms;  // Maximum time delay for the haptics waveform to settle to zero, after actuation ends (in ms).
    /**< @h2xmle_description {Maximum time delay for the haptics waveform to settle to zero after actuation ends, in ms.}
         @h2xmle_range       {5..100} ms
         @h2xmle_default     {30} */

    // Waveform designer parameters
    int32_t rise_fall_time_max_ms;  // Waveform designer parametric mode parameter. Defines time taken for the LRA to reach specified accelaration at 0% sharpness (in ms).
    /**< @h2xmle_description {Waveform designer parametric mode parameter. Defines time taken for the LRA to reach specified accelaration at 0% sharpness, in ms.}
         @h2xmle_range       {20..100} ms
         @h2xmle_default     {100} */
    int32_t delay_time_ms;          // Waveform designer parametric mode parameter. Time delay at the start and end of the pulse acceleration waveform (in ms).
    /**< @h2xmle_description {Waveform designer parametric mode parameter. Time delay at the start and end of the parametric waveform, in ms}
         @h2xmle_range       {0..100} ms
         @h2xmle_default     {0} */
    int32_t pwl_max_pulse_points; // Maximum no. of pulse points supported in PWL mode, waveform designer
    /**< @h2xmle_description {Maximum no. of pulse points supported in PWL mode by the waveform designer}
         @h2xmle_range       {50..500}
         @h2xmle_default     {100} */
    int32_t wave_dsgn_max_pulse_duration_ms; // Maximum continuous haptics pulse duration supported, to prevent thermal damage (in ms).
    /**< @h2xmle_description {Maximum continuous haptics pulse duration supported to prevent thermal damage, in ms}
         @h2xmle_range       {1000..3000} ms
         @h2xmle_default     {3000} */
    int32_t wave_dsgn_max_duty_cycle; // Maximum duty cycle supported, to prevent thermal damage in %
    /**< @h2xmle_description {Maximum duty cycle supported, to prevent thermal damage in %}
         @h2xmle_range       {40..100}
         @h2xmle_default     {50} */
    int32_t phase_index;    // Initial phase index
    /**< @h2xmle_description {Initial phase index.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_OP_MODE 0x0800136D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_op_mode param_id_haptics_op_mode;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_OP_MODE",
                         PARAM_ID_HAPTICS_OP_MODE}
    @h2xmlp_description {Parameter used to select the operation mode of WSA
                         smart haptics RX processing.}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_op_mode {
    uint32_t operation_mode;        // normal running or thermal calibration
    /**< @h2xmle_description {Operation mode of RX module.}
         @h2xmle_rangeList   {"Normal Running mode"=0;
                              "Calibration mode"=1;
                              "Factory Test Mode"=2}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_PCMV_PLAYBACK 0x08001AE3

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_pcmv_playback param_id_haptics_rx_pcmv_playback;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_PCMV_PLAYBACK",
                         PARAM_ID_HAPTICS_RX_PCMV_PLAYBACK}
    @h2xmlp_description {PCMV Playback mode buffer ptr, size set param}
    @h2xmlp_toolPolicy  {RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_rx_pcmv_playback {
    uint32_t channel_mask;  // Mask to indicate to which channel(s) the buffer is being set, for mono set this to 1
    /**< @h2xmle_description {Mask to indicate which channel(s) have a valid UPDATE command.}
         @h2xmle_range       {0..0x02}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Channel 1"}
         @h2xmle_description {Enabling this bit will indicate a valid PCMV Playback buffer set to Channel 1.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Channel 2"}
         @h2xmle_description {Enabling this bit will indicate a valid PCMV Playback buffer set to Channel 2.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */
    int32_t buffer_size; // Buffer size in bytes
    /**< @h2xmle_description {Length of the effect PCM buffer in bytes, (48kHz, 16-bit mono, Q15 format), Max duration supported is 10 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x000EA600} */
#ifdef __H2XML__
    uint8_t buffer_ptr[0]; // PCMV Playback mode buffer pointer
    /**< @h2xmle_description {Haptics PCMV playback data buffer. PCM data format: 48kHz, 16-bit mono, Q15 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_FTM_CFG 0x08001B1C

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_ftm_cfg_t param_id_haptics_rx_ftm_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_FTM_CFG",
                         PARAM_ID_HAPTICS_RX_FTM_CFG}
    @h2xmlp_description {Parameter to set FTM configuration}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_rx_ftm_cfg_t {
    uint32_t non_linearity_compensation;        // Enable/Disable duffing non linearity compensation
    /**< @h2xmle_description {Enable/Disable duffing non linearity compensation}
         @h2xmle_rangeList   {"Disabled"=0;
                              "Enabled"=1}*/
    int32_t ftm_amplitude_q24[HAPTICS_MAX_OUT_CHAN];     // FTM playback amplitude level in Volts
    /**< @h2xmle_description {FTM playback amplitude level in Volts}
         @h2xmle_range       {0..0x7FFFFFFF}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t f0_tracking_duration_ms[HAPTICS_MAX_OUT_CHAN];     // f0 tracking duration in ms
    /**< @h2xmle_description {FTM f0 tracking duration in ms}
         @h2xmle_range       {0..1000}
         @h2xmle_default     {250} */
    int32_t f0_duffing_duration_ms[HAPTICS_MAX_OUT_CHAN];     // FTM f0 tracking non linearity compensation max duration in ms
    /**< @h2xmle_description {FTM f0 tracking non linearity compensation max duration in ms}
         @h2xmle_range       {0..8000}
         @h2xmle_default     {6000} */
    int32_t rtcl_gain_k_0_q27[HAPTICS_MAX_OUT_CHAN];     // RTCL gain_k[0]
    /**< @h2xmle_description {RTCL gain_k[0]}
         @h2xmle_range       {-7..7}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0} */
    int32_t rtcl_gain_k_1_q27[HAPTICS_MAX_OUT_CHAN];     // RTCL gain_k[1]
    /**< @h2xmle_description {RTCL gain_k[1]}
         @h2xmle_range       {-7..7}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0} */
    int32_t rtcl_gain_l_0_q27[HAPTICS_MAX_OUT_CHAN];     // RTCL gain_l[0]
    /**< @h2xmle_description {RTCL gain_l[0]}
         @h2xmle_range       {-7..7}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0} */
    int32_t rtcl_gain_l_1_q27[HAPTICS_MAX_OUT_CHAN];     // RTCL gain_l[1]
    /**< @h2xmle_description {RTCL gain_l[1]}
         @h2xmle_range       {-7..7}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_DYNAMIC_CFG 0x08001398

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct haptics_ex_ctrl_param_h haptics_ex_ctrl_param_h;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// Structure encapsulating LRA parameters for RX excursion control block
/** @h2xmlp_subStruct */
struct haptics_ex_ctrl_param_h
{
    int32_t amp_gain_q24;   // Amplifier gain that will be used in scaling Tx vsense signal to rx signal
    /**< @h2xmle_description {WSA peak voltage for a digitally full-scale signal. Default = 10, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {167772160} */
    int32_t max_excursion_mm_q27;   // LRA xmax value
    /**< @h2xmle_description {maximum permissible excursoin, in mm. Default = 0.3mm, Range: 0.05 to 16mm}
         @h2xmle_range       {6710886..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {40265318} */
    int32_t max_acceleration_q27;      // LRA maximum acceleration value
    /**< @h2xmle_description {LRA maximum acceleration value in linear scale, in Gs. Default = 1G, Range: 0.1 to 16G}
         @h2xmle_range       {13421773..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {134217728} */
    int32_t trace_resistance_rx_q24;
    /**< @h2xmle_description {trace resistance from amp output to LRA, in Ohms. Default = 0Ohm, Range: 0 to 128Ohms}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t Re_ohm_q24;
    /**< @h2xmle_description {DC resistance of LRA coil at room temperature, in Ohms. Default = 8Ohm, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Le_mH_q24;
    /**< @h2xmle_description {Inductance of LRA coil at room temperature, in mH. Default = 0.04mH, Range: 0.001mH to 128mH}
         @h2xmle_range       {16777..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {671088} */
    int32_t Bl_q24;
    /**< @h2xmle_description {Force factor (Bl product). Default = 1, Range: 0.01 to 128}
         @h2xmle_range       {167772..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Mms_gram_q24;
    /**< @h2xmle_description {Mass of LRA moving mass, in grams. Default = 1g, Range: 0.05 to 128g}
         @h2xmle_range       {838860..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Rms_KgSec_q24;
    /**< @h2xmle_description {Mechanical damping or resistance of LRA, in kg/s. Default = 0.0945kg/s, Range = 0.0001 to 20kg/s}
         @h2xmle_range       {16777..335544320}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1585446} */
    int32_t Kms_Nmm_q24;
    /**< @h2xmle_description {Mechanical stiffness of driver suspension, in N/mm. Default = 1.838N/mm, Range = 0.1 to 50N/mm}
         @h2xmle_range       {1677721..838860800}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {30836523} */
    int32_t Fres_Hz_q20;
    /**< @h2xmle_description {Resonance frequency, in Hz. Default = 160Hz, Range = 50 to 400Hz}
         @h2xmle_range       {52428800..419430400}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {167772160} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_dynamic_cfg param_id_haptics_dynamic_cfg;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_DYNAMIC_CFG",
                          PARAM_ID_HAPTICS_DYNAMIC_CFG}
    @h2xmlp_description {Parameters used to configure the dynamic configuration of
                         WSA smart haptics Rx processing.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_dynamic_cfg
{
   uint32_t num_channels;
   /**< @h2xmle_description {Number of channels for Rx signal.}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
#ifdef __H2XML__
   haptics_ex_ctrl_param_h haptics_ex_ctrl_param[0];
   /**< @h2xmle_description       {Structure encapsulating LRA parameters for RX excursion control block}
        @h2xmle_variableArraySize {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_FTM_DATA_PARAM 0x08001ADE

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_ftm_data_param_t param_id_haptics_rx_ftm_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_FTM_DATA_PARAM", PARAM_ID_HAPTICS_RX_FTM_DATA_PARAM}
    @h2xmlp_description {Parameter for registering haptics ftm data to lib}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_ftm_data_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for FTM data file}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of ftm data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the FTM data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00000064} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics FTM data: The path to the FTM cal file}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_CALIB_DATA_PARAM 0x08001ADF

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_calib_data_param_t param_id_haptics_rx_calib_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_CALIB_DATA_PARAM", PARAM_ID_HAPTICS_RX_CALIB_DATA_PARAM}
    @h2xmlp_description {Parameter for registering haptics calibration data to lib.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_calib_data_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for Calibration data file}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of calibration data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the calibration data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00000064} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics calibration data: The path to the calibration cal file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_PERSISTENT_DATA_PARAM 0x08001B1A

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_persistent_data_param_t param_id_haptics_rx_persistent_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_PERSISTENT_DATA_PARAM",
                    PARAM_ID_HAPTICS_RX_PERSISTENT_DATA_PARAM}
    @h2xmlp_description {Parameter for registering haptics persistent data to lib.}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_persistent_data_param_t {
    int32_t Re_ohm_q24[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {DC resistance of LRA coil at room temperature, in Ohms. Default = 8Ohm, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Le_mH_q24[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Inductance of LRA coil at room temperature, in mH. Default = 0.04mH, Range: 0.001mH to 128mH}
         @h2xmle_range       {16777..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {671088} */
    int32_t Bl_q24[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Force factor (Bl product). Default = 1, Range: 0.01 to 128}
         @h2xmle_range       {167772..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Rms_KgSec_q24[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Mechanical damping or resistance of LRA, in kg/s. Default = 0.0945kg/s, Range = 0.0001 to 20kg/s}
         @h2xmle_range       {16777..335544320}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1585446} */
    int32_t Kms_Nmm_q24[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Mechanical stiffness of driver suspension, in N/mm. Default = 1.838N/mm, Range = 0.1 to 50N/mm}
         @h2xmle_range       {1677721..838860800}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {30836523} */
    int32_t Fres_Hz_q20[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Resonance frequency, in Hz. Default = 160Hz, Range = 50 to 400Hz}
         @h2xmle_range       {52428800..419430400}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {167772160} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG 0x08001399

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct rx_wave_designer_config_h rx_wave_designer_config_h;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_subStruct */
struct rx_wave_designer_config_h {
    // Waveform designer mode parameters
    uint32_t wave_design_mode;    // Waveform designer mode parameter
    /**< @h2xmle_description {Waveform designer mode parameter. Lower 16b represents the wave designer mode.
                              When mode is Pre-canned (Effects), upper 16b represents the effect ID; for all other modes these bits are ignored.}
         @h2xmle_rangeList   {"Parametric"          = 0x00000000;
                              "Piece-wise Linear"   = 0x00000001;
                              "Sinusoidal"             = 0x00000002;
                              "PCMV Ringtone"         = 0x00000003;
                              "Pre-canned Effect 0" = 0x00000004;
                              "Pre-canned Effect 1" = 0x00010004;
                              "Pre-canned Effect 2" = 0x00020004;
                              "Pre-canned Effect 3" = 0x00030004;
                              "Pre-canned Effect 4" = 0x00040004;
                              "Pre-canned Effect 5" = 0x00050004;
                              "Pre-canned Effect 6" = 0x00060004;
                              "Pre-canned Effect 7" = 0x00070004;
                              "Pre-canned Effect 8" = 0x00080004;
                              "Pre-canned Effect 9" = 0x00090004;
                              "Pre-canned Effect10" = 0x000A0004;
                              "Pre-canned Effect11" = 0x000B0004;
                              "Pre-canned Effect12" = 0x000C0004;
                              "Pre-canned Effect13" = 0x000D0004;
                              "Pre-canned Effect 14" = 0x000E0004}
         @h2xmle_default     {0} */

    int32_t auto_overdrive_brake_en;    // Flag to enable/ disable auto overdrive and brake
    /**< @h2xmle_description {Flag to enable/ disable auto overdrive and brake. Considered in Sinusoidal mode only.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1} */
    int32_t f0_tracking_en;    // Flag to enable/ disable resonance frequency tracking
    /**< @h2xmle_description {Flag to enable/ disable resonance frequency tracking. Considered in Sinusoidal mode only.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1} */
    int32_t f0_tracking_param_reset_flag; // If this flag is enabled and f0 tracking is disabled, LRA parameters will be reset to calibration parameters (instead of cached parameters).
    /**<@h2xmle_description  {If this flag is enabled and f0 tracking is disabled, LRA parameters will be reset to calibration parameters (instead of cached parameters). Considered in all modes.}
        @h2xmle_rangeList    {disabled=0;enabled=1}
        @h2xmle_default      {0} */

    uint32_t override_flag; // Mask to indicate the parameters for which default value will be overridden.
    /**< @h2xmle_description {Mask to indicate the parameters for which default value will be overridden. Considered in all modes.}
         @h2xmle_range       {0..0x0f}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Tracked frequency warmup time"}
         @h2xmle_description {If this bit is enabled, tracked_freq_warmup_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Settling time"}
         @h2xmle_description {If this bit is enabled, settling_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000004}
         @h2xmle_bitName     {"Delay time"}
         @h2xmle_description {If this bit is enabled, delay_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000008}
         @h2xmle_bitName     {"Waveform generator fstart"}
         @h2xmle_description {If this bit is enabled, wavegen_fstart_hz_q20 field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */

    int32_t tracked_freq_warmup_time_ms;  // Time delay before enabling resonance frequency tracking (in ms).
    /**< @h2xmle_description {Time delay before enabling resonance frequency tracking, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {0..10000} ms
         @h2xmle_default     {0}*/
    int32_t settling_time_ms;  // Maximum time delay for the haptics waveform to settle to zero, after actuation ends (in ms).
    /**< @h2xmle_description {Maximum time delay for the haptics waveform to settle to zero after actuation ends, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {5..100} ms
         @h2xmle_default     {30}*/
    int32_t delay_time_ms;          // Waveform designer parametric mode parameter. Time delay at the start and end of the pulse acceleration waveform (in ms). Considered only when corresponding bit is enabled in override_flag.
    /**< @h2xmle_description {Waveform designer parametric mode parameter. Time delay at the start and end of the parametric waveform, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {0..100} ms
         @h2xmle_default     {0}*/
    int32_t wavegen_fstart_hz_q20;      // Starting frequency in Hz.
    /**< @h2xmle_description {Starting frequency for the waveform designer, in Hz. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {52428800..419430400} Hz
         @h2xmle_default     {157286400}
         @h2xmle_dataFormat  {Q20} */

    int32_t repetition_count;           // No. of repetitions of the haptics waveform
    /**< @h2xmle_description {No. of repetitions of the haptics waveform. Considered in Parametric, PWL, Sinusoidal modes only.} */
    int32_t repetition_period_ms;       // Time period of one repetition
    /**< @h2xmle_description {Time period of one repetition, in ms. Considered in Parametric, PWL, Sinusoidal modes only.} */
    uint32_t pilot_tone_en;             // Flag to enable/disable pilot tone
    /**< @h2xmle_description {Flag to enable/disable pilot tone. Considered in all modes.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}*/
    int32_t pulse_intensity;            // Pulse intensity as percentage of maximum acceleration
    /**< @h2xmle_description {Pulse intensity as percentage of maximum acceleration, in %. Considered in Parametric, Sinusoidal modes only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {0}*/
    int32_t pulse_width_ms;             // Haptics waveform duration
    /**< @h2xmle_description {Haptics waveform duration, in ms. Considered in Parametric, Sinusoidal modes only.} */
    int32_t pulse_sharpness;            // Pulse sharpness as percentage of maximum rise/fall time
    /**< @h2xmle_description {Pulse sharpness as percentage of maximum rise/fall time, in %. Considered in Parametric mode only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {0}*/
    int32_t num_pwl;                    // No. of waveform points in piece-wise linear waveform
    /**< @h2xmle_description {No. of waveform points in piece-wise linear waveform. Considered in PWL mode only.} */
#ifdef __H2XML__
    int32_t pwl_time[0];                   // Time indices for piece-wise linear waveform
    /**< @h2xmle_description {Time indices for piece-wise linear waveform, in ms. Considered in PWL mode only.}
         @h2xmle_variableArraySize  {num_pwl} */
    int32_t pwl_acc[0];                    // Acceleration values corresponding to piece-wise linear waveform, as percentage of max acceleration
    /**< @h2xmle_description {Acceleration values corresponding to piece-wise linear waveform, as percentage of max acceleration, in %. Considered in PWL mode only.}
         @h2xmle_variableArraySize  {num_pwl} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_wave_designer_config_t param_id_haptics_wave_designer_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG",
                          PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG}
    @h2xmlp_description {Waveform designer configuration.}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_wave_designer_config_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of valid channel configurations that are sent. num_channels= 1 supports channel_mask 1 and 2, num_channels= 2 supports channel_mask 3}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    uint32_t channel_mask;
    /**< @h2xmle_description {Mask to indicate which channel(s) have a valid waveform designer configuration.}
         @h2xmle_range       {0..0x03}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Channel 1"}
         @h2xmle_description {Enabling this bit will indicate a valid configuration for Channel 1.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Channel 2"}
         @h2xmle_description {Enabling this bit will indicate a valid configuration for Channel 2.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */
#ifdef __H2XML__
    rx_wave_designer_config_h rx_wave_designer_config[0]; // Wave designer configuration for each channel
    /**< @h2xmle_description {Wave designer configuration for each channel.}
         @h2xmle_variableArraySize  {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG_V2 0x08001B1B

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct rx_wave_designer_config_v2_h rx_wave_designer_config_v2_h;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_subStruct */
struct rx_wave_designer_config_v2_h {
    // Waveform designer mode parameters
    uint32_t wave_design_mode;    // Waveform designer mode parameter
    /**< @h2xmle_description {Waveform designer mode parameter. Lower 16b represents the wave designer mode.
                              When mode is Pre-canned (Effects), upper 16b represents the effect ID; for all other modes these bits are ignored.}
         @h2xmle_rangeList   {"Parametric"          = 0x00000000;
                              "Piece-wise Linear"   = 0x00000001;
                              "Sinusoidal"             = 0x00000002;
                              "PCMV Ringtone"         = 0x00000003;
                              "Pre-canned Effect 0" = 0x00000004;
                              "Pre-canned Effect 1" = 0x00010004;
                              "Pre-canned Effect 2" = 0x00020004;
                              "Pre-canned Effect 3" = 0x00030004;
                              "Pre-canned Effect 4" = 0x00040004;
                              "Pre-canned Effect 5" = 0x00050004;
                              "Pre-canned Effect 6" = 0x00060004;
                              "Pre-canned Effect 7" = 0x00070004;
                              "Pre-canned Effect 8" = 0x00080004;
                              "Pre-canned Effect 9" = 0x00090004;
                              "Pre-canned Effect10" = 0x000A0004;
                              "Pre-canned Effect11" = 0x000B0004;
                              "Pre-canned Effect12" = 0x000C0004;
                              "Pre-canned Effect13" = 0x000D0004;
                              "Pre-canned Effect 14" = 0x000E0004;
                              "PCMV Playback"        = 0x00000005}
         @h2xmle_default     {0} */

    int32_t auto_overdrive_brake_en;    // Flag to enable/ disable auto overdrive and brake
    /**< @h2xmle_description {Flag to enable/ disable auto overdrive and brake. Considered in Sinusoidal mode only.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1} */
    int32_t f0_tracking_en;    // Flag to enable/ disable resonance frequency tracking
    /**< @h2xmle_description {Flag to enable/ disable resonance frequency tracking. Considered in Sinusoidal mode only.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1} */
    int32_t rtcl_mode;    // Real-time closed loop mode
    /**< @h2xmle_description {Choose real time closed loop mode. Considered in all waveform designer modes.}
         @h2xmle_rangeList   {disabled=0;tracking=1;braking=2;ltf_mode=3}
         @h2xmle_default     {0} */
    int32_t pmic_autobrake_en;    // Flag to enable/disable PMIC autobraking
    /**< @h2xmle_description {Flag to enable/disable PMIC autobraking. Considered in all modes except PCMV Ringtone.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0} */
    int32_t f0_tracking_param_reset_flag; // If this flag is enabled and f0 tracking is disabled, LRA parameters will be reset to calibration parameters (instead of cached parameters).
    /**<@h2xmle_description  {If this flag is enabled and f0 tracking is disabled, LRA parameters will be reset to calibration parameters (instead of cached parameters). Considered in all modes.}
        @h2xmle_rangeList    {disabled=0;enabled=1}
        @h2xmle_default      {0} */

    uint32_t override_flag; // Mask to indicate the parameters for which default value will be overridden.
    /**< @h2xmle_description {Mask to indicate the parameters for which default value will be overridden. Considered in all modes.}
         @h2xmle_range       {0..0x0f}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Tracked frequency warmup time"}
         @h2xmle_description {If this bit is enabled, tracked_freq_warmup_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Settling time"}
         @h2xmle_description {If this bit is enabled, settling_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000004}
         @h2xmle_bitName     {"Delay time"}
         @h2xmle_description {If this bit is enabled, delay_time_ms field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000008}
         @h2xmle_bitName     {"Waveform generator fstart"}
         @h2xmle_description {If this bit is enabled, wavegen_fstart_hz_q20 field will be considered.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */

    int32_t tracked_freq_warmup_time_ms;  // Time delay before enabling resonance frequency tracking (in ms).
    /**< @h2xmle_description {Time delay before enabling resonance frequency tracking, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {0..10000} ms
         @h2xmle_default     {0}*/
    int32_t settling_time_ms;  // Maximum time delay for the haptics waveform to settle to zero, after actuation ends (in ms).
    /**< @h2xmle_description {Maximum time delay for the haptics waveform to settle to zero after actuation ends, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {5..100} ms
         @h2xmle_default     {30}*/
    int32_t delay_time_ms;          // Waveform designer parametric mode parameter. Time delay at the start and end of the pulse acceleration waveform (in ms). Considered only when corresponding bit is enabled in override_flag.
    /**< @h2xmle_description {Waveform designer parametric mode parameter. Time delay at the start and end of the parametric waveform, in ms. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {0..100} ms
         @h2xmle_default     {0}*/
    int32_t wavegen_fstart_hz_q20;      // Starting frequency in Hz.
    /**< @h2xmle_description {Starting frequency for the waveform designer, in Hz. Considered only if corresponding bit is enabled in `override_flag`.}
         @h2xmle_range       {52428800..419430400} Hz
         @h2xmle_default     {157286400}
         @h2xmle_dataFormat  {Q20} */

    int32_t repetition_count;           // No. of repetitions of the haptics waveform
    /**< @h2xmle_description {No. of repetitions of the haptics waveform. Considered in Parametric, PWL, Sinusoidal modes only.} */
    int32_t repetition_period_ms;       // Time period of one repetition
    /**< @h2xmle_description {Time period of one repetition, in ms. Considered in Parametric, PWL, Sinusoidal modes only.} */
    uint32_t pilot_tone_en;             // Flag to enable/disable pilot tone
    /**< @h2xmle_description {Flag to enable/disable pilot tone. Considered in all modes.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}*/
    int32_t pulse_intensity;            // Pulse intensity as percentage of maximum acceleration
    /**< @h2xmle_description {Pulse intensity as percentage of maximum acceleration, in %. Considered in Parametric, Sinusoidal modes only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {0}*/
    int32_t pulse_width_ms;             // Haptics waveform duration
    /**< @h2xmle_description {Haptics waveform duration, in ms. Considered in Parametric, Sinusoidal modes only.} */
    int32_t pulse_sharpness;            // Pulse sharpness as percentage of maximum rise/fall time
    /**< @h2xmle_description {Pulse sharpness as percentage of maximum rise/fall time, in %. Considered in Parametric mode only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {0}*/
    int32_t num_pwl;                    // No. of waveform points in piece-wise linear waveform
    /**< @h2xmle_description {No. of waveform points in piece-wise linear waveform. Considered in PWL mode only.} */
#ifdef __H2XML__
    int32_t pwl_time[0];                   // Time indices for piece-wise linear waveform
    /**< @h2xmle_description {Time indices for piece-wise linear waveform, in ms. Considered in PWL mode only.}
         @h2xmle_variableArraySize  {num_pwl} */
    int32_t pwl_acc[0];                    // Acceleration values corresponding to piece-wise linear waveform, as percentage of max acceleration
    /**< @h2xmle_description {Acceleration values corresponding to piece-wise linear waveform, as percentage of max acceleration, in %. Considered in PWL mode only.}
         @h2xmle_variableArraySize  {num_pwl} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_wave_designer_config_v2_t param_id_haptics_wave_designer_config_v2_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG_V2",
                          PARAM_ID_HAPTICS_WAVE_DESIGNER_CFG_V2}
    @h2xmlp_description {Waveform designer configuration v2.}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_wave_designer_config_v2_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of valid channel configurations that are sent. num_channels= 1 supports channel_mask 1 and 2, num_channels= 2 supports channel_mask 3}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    uint32_t channel_mask;
    /**< @h2xmle_description {Mask to indicate which channel(s) have a valid waveform designer configuration.}
         @h2xmle_range       {0..0x03}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Channel 1"}
         @h2xmle_description {Enabling this bit will indicate a valid configuration for Channel 1.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Channel 2"}
         @h2xmle_description {Enabling this bit will indicate a valid configuration for Channel 2.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */
#ifdef __H2XML__
    rx_wave_designer_config_v2_h rx_wave_designer_config_v2[0]; // Wave designer configuration for each channel
    /**< @h2xmle_description {Wave designer configuration for each channel.}
         @h2xmle_variableArraySize  {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_WAVE_DESIGNER_STOP_PARAM 0x0800139A

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_wave_designer_stop_param_t param_id_haptics_wave_designer_wave_designer_stop_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_WAVE_DESIGNER_STOP_PARAM",
                          PARAM_ID_HAPTICS_WAVE_DESIGNER_STOP_PARAM}
    @h2xmlp_description {Waveform designer stop command.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_wave_designer_stop_param_t {
    uint32_t channel_mask; // Mask to indicate to which channel(s) a valid STOP command was sent.
    /**< @h2xmle_description {Mask to indicate to which channel(s) a valid STOP command was sent.}
         @h2xmle_range       {0..0x03}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Channel 1"}
         @h2xmle_description {Enabling this bit will indicate a valid STOP command for Channel 1.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Channel 2"}
         @h2xmle_description {Enabling this bit will indicate a valid STOP command for Channel 2.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_WAVE_DESIGNER_UPDATE_PARAM 0x0800139B

/*==============================================================================
   Type definitions
==============================================================================*/
/* Structure definition for Parameter */
typedef struct rx_wave_designer_update_config_t rx_wave_designer_update_config_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
// Wave designer parameters - update
struct rx_wave_designer_update_config_t {
    int32_t pulse_intensity;            // Pulse intensity as percentage of maximum acceleration
    /**< @h2xmle_description {Pulse intensity as percentage of maximum acceleration, in %. Valid in Parametric, Sinusoidal modes only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {100} */
    int32_t pulse_sharpness;            // Pulse sharpness as percentage of maximum rise/fall time
    /**< @h2xmle_description {Pulse sharpness as percentage of maximum rise/fall time, in %. Valid in Parametric mode only.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {100} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_wave_designer_update_param_t param_id_haptics_wave_designer_update_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_WAVE_DESIGNER_UPDATE_PARAM",
                          PARAM_ID_HAPTICS_WAVE_DESIGNER_UPDATE_PARAM}
    @h2xmlp_description {This parameter is used to update configuration of haptics Waveform.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_wave_designer_update_param_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of valid channel UPDATE commands that are sent. num_channels = 1 supports channel_mask 1 and 2, num_channels = 2 supports channel_mask 3}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    uint32_t channel_mask;
    /**< @h2xmle_description {Mask to indicate which channel(s) have a valid UPDATE command.}
         @h2xmle_range       {0..0x03}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Channel 1"}
         @h2xmle_description {Enabling this bit will indicate a valid UPDATE command for Channel 1.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Channel 2"}
         @h2xmle_description {Enabling this bit will indicate a valid UPDATE command for Channel 2.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0}
         @h2xmle_bitFieldEnd */

     // Wave designer parameters - update
#ifdef __H2XML__
    rx_wave_designer_update_config_t rx_wave_designer_update_config[0]; // Wave designer update parameters for each channel
    /**< @h2xmle_description {Wave designer update parameters for each channel.}
         @h2xmle_variableArraySize  {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_0_DATA_PARAM 0x08001522

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_0_data_t param_id_haptics_effect_0_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_0_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_0_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 0'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_0_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_1_DATA_PARAM 0x08001523

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_1_data_t param_id_haptics_effect_1_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_1_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_1_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 1'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_1_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_2_DATA_PARAM 0x08001524

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_2_data_t param_id_haptics_effect_2_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_2_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_2_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 2'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_2_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_3_DATA_PARAM 0x08001525

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_3_data_t param_id_haptics_effect_3_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_3_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_3_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 3'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_3_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..7} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_4_DATA_PARAM 0x08001526

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_4_data_t param_id_haptics_effect_4_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_4_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_4_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 4'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_4_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_5_DATA_PARAM 0x08001527

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_5_data_t param_id_haptics_effect_5_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_5_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_5_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 5'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_5_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_6_DATA_PARAM 0x08001528

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_6_data_t param_id_haptics_effect_6_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_6_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_6_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 6'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_6_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_7_DATA_PARAM 0x08001529

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_7_data_t param_id_haptics_effect_7_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_7_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_7_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 7'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_7_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_8_DATA_PARAM 0x0800152A

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_8_data_t param_id_haptics_effect_8_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_8_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_8_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 8'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_8_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_9_DATA_PARAM 0x0800152B

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_9_data_t param_id_haptics_effect_9_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_9_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_9_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 9'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_9_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_10_DATA_PARAM 0x0800152C

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_10_data_t param_id_haptics_effect_10_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_10_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_10_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 10'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_10_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_11_DATA_PARAM 0x0800152D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_11_data_t param_id_haptics_effect_11_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_11_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_11_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 11'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_11_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_12_DATA_PARAM 0x0800152E

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_12_data_t param_id_haptics_effect_12_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_12_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_12_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 12'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_12_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_13_DATA_PARAM 0x0800152F

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_13_data_t param_id_haptics_effect_13_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_13_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_13_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 13'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_13_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EFFECT_14_DATA_PARAM 0x08001530

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_effect_14_data_t param_id_haptics_effect_14_data_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EFFECT_14_DATA_PARAM", PARAM_ID_HAPTICS_EFFECT_14_DATA_PARAM}
    @h2xmlp_description {Parameter for registering the pre-canned effects haptics waveform data for 'Effect 14'.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_effect_14_data_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for the effect data}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of effect data by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the effect PCM data in bytes, (48kHz, 32-bit mono, Q31 format), Max duration supported is 2 sec}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x0005DC00} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {Haptics PCM data for 'Effect 12': The path to the effect file in the file system (PCM data format: 48kHz, 32-bit mono, Q31 format)}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_EFFECTS_CONFIG_PARAM 0x08001ADA

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_effects_config_param_t param_id_haptics_rx_effects_config_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_EFFECTS_CONFIG_PARAM", PARAM_ID_HAPTICS_RX_EFFECTS_CONFIG_PARAM}
    @h2xmlp_description {Parameter for setting f0, R used to generate PCMV Effects waveforms.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_effects_config_param_t {
    int32_t Fres_Hz_q20[HAPTICS_MAX_OUT_CHAN]; // Resonance frequency used to generate PCMV Effects waveforms
    /**< @h2xmle_description {Resonance frequency used to generate PCMV Effects waveforms, in Hz. Default = 0Hz, Range = 0 to 400Hz}
         @h2xmle_range       {0..419430400}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {0} */
    int32_t Re_ohm_q24[HAPTICS_MAX_OUT_CHAN];  // DC resistance of LRA coil used to generate PCMV Effects waveforms
    /**< @h2xmle_description {DC resistance of LRA coil used to generate PCMV Effects waveforms, in Ohms. Default = 0 Ohm, Range: 0 to 128Ohms}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_TUNING_DATA_0_PARAM 0x08001B36

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_tuning_data_0_param_t param_id_haptics_rx_tuning_data_0_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_TUNING_DATA_0_PARAM", PARAM_ID_HAPTICS_RX_TUNING_DATA_0_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 0 to RX module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_tuning_data_0_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for RX module tuning data file for LRA 0}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of RX module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the RX module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {RX module tuning data for LRA 0: path to the RX module tuning binary file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_TUNING_DATA_1_PARAM 0x08001B37

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_tuning_data_1_param_t param_id_haptics_rx_tuning_data_1_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_TUNING_DATA_1_PARAM", PARAM_ID_HAPTICS_RX_TUNING_DATA_1_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 1 to RX module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_tuning_data_1_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for RX module tuning data file for LRA 1}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of RX module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the RX module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {RX module tuning data for LRA 1: path to the RX module tuning binary file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_TUNING_DATA_2_PARAM 0x08001B38

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_tuning_data_2_param_t param_id_haptics_rx_tuning_data_2_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_TUNING_DATA_2_PARAM", PARAM_ID_HAPTICS_RX_TUNING_DATA_2_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 2 to RX module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_tuning_data_2_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for RX module tuning data file for LRA 2}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of RX module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the RX module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {RX module tuning data for LRA 2: path to the RX module tuning binary file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_TUNING_DATA_3_PARAM 0x08001B39

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_tuning_data_3_param_t param_id_haptics_rx_tuning_data_3_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_TUNING_DATA_3_PARAM", PARAM_ID_HAPTICS_RX_TUNING_DATA_3_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 3 to RX module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_tuning_data_3_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for RX module tuning data file for LRA 3}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of RX module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the RX module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {RX module tuning data for LRA 3: path to the RX module tuning binary file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_TUNING_DATA_4_PARAM 0x08001B3A

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_tuning_data_4_param_t param_id_haptics_rx_tuning_data_4_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_TUNING_DATA_4_PARAM", PARAM_ID_HAPTICS_RX_TUNING_DATA_4_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 4 to RX module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_rx_tuning_data_4_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for RX module tuning data file for LRA 4}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of RX module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the RX module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {RX module tuning data for LRA 4: path to the RX module tuning binary file.}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_RX_VISENSE_CFG 0x08001B3B

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_rx_visense_t param_id_haptics_rx_visense_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_RX_VISENSE_CFG",
                          PARAM_ID_HAPTICS_RX_VISENSE_CFG}
    @h2xmlp_description {VI sense scaling factors.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/
struct param_id_haptics_rx_visense_t {
    int32_t vsens_scale_q24[HAPTICS_MAX_OUT_CHAN]; // Vsense scaling constant
    /**< @h2xmle_description {conversion factor from Vsens digital to Volts. Default = 10.48, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {175849472} */
    int32_t isens_scale_q24[HAPTICS_MAX_OUT_CHAN]; // Isense scaling constant
    /**< @h2xmle_description {conversion factor from Isens digital to Amperes. Default = 6.90, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {115859456} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_CPS_FINE_PARAM 0x0800139D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_cps_fine_param_t param_id_haptics_cps_fine_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_CPS_FINE_PARAM",
                          PARAM_ID_HAPTICS_CPS_FINE_PARAM}
    @h2xmlp_description {This parameter is used for getting finer resolution of gain to be applied at Vbatt/DieTemps.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/
struct param_id_haptics_cps_fine_param_t {
   uint16_t cps_fine_tbl_en_flag;
    /**< @h2xmle_description {Flag to enable/disable fine-VBAT resolution CPS gain tables}
         @h2xmle_rangeList   {"disabled"=0; "enabled"=1}
         @h2xmle_default     {0} */

    uint16_t reserved;
    /**< @h2xmle_description {Reserved}
         @h2xmle_default     {0} */

    int32_t FourOhmTable_fine_GaindB_q24[NDTEMP_DISCRETE * NVBATT_DISCRETE_FINE];
    /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp. Range: -9dB to 21dB}
         @h2xmle_range       {-150994944..352321536}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_defaultList {-53285485,  68153209, 140261762,  149830710,  172158254,  179529886,  196730361,  196730361,  201136445,  211417309,  222963712,  224388279,  234465433,
                              -53501694,  71474774, 143619166,  152180893,  172158254,  179529886,  196730361,  196730361,  201004748,  210978319,  218850334,  223483143,  236126715,
                              -61867454,  71578604, 137847344,  148140617,  172158254,  179529886,  196730361,  196730361,  200987512,  210920864,  220936046,  223623129,  235966854,
                              -52962369,  71188477, 137480805,  147884040,  172158254,  179529886,  196730361,  196730361,  199593251,  206273327,  217477288,  220887257,  233383879,
                              -52908655,  70401900, 136689101,  147329847,  172158254,  179529886,  196730361,  196730361,  199611622,  206334564,  216755019,  220142936,  232609941,
                              -49090800,  69633385, 135888699,  146769565,  172158254,  179529886,  196730361,  196730361,  199371583,  205534433,  215815743,  219316788,  232008960,
                              -52801347,  68802805, 135079406,  146203061,  172158254,  179529886,  196730361,  196730361,  199110096,  204662812,  212190708,  218300850,  231207999,
                              -52908655,  67894469, 134206137,  145591772,  172158254,  179529886,  196730361,  196730361,  198845444,  203780637,  211302130,  217362043,  230212812,
                              -52854981,  67057511, 133377831,  145011958,  172158254,  179529886,  196730361,  196730361,  198603204,  202973170,  210496804,  216441856,  229391747,
                              -52747752,  66294546, 132596157,  144464786,  172158254,  179529886,  196730361,  196730361,  195301930,  191968925,  200327519,  202503216,  217012474,
                              -53016122,  65297664, 125651617,  139603608,  172158254,  179529886,  196730361,  196730361,  194781369,  190233721,  199236742,  201411199,  214936993,
                              -53123748,  64815411, 118521597,  134612594,  172158254,  179529886,  196730361,  196730361,  192310557,  181997682,  190067202,  192417852,  204348176,
                              -54922914,  64186542, 102687156,  123528485,  172158254,  179529886,  196730361,  196730361,  188500630,  169297925,  175702957,  177144954,  189897145,
                              -56597988,  34772406, 59808743, 93513596, 172158254,  179529886,  196730361,  196730361,  177321044,  132032639,  143752379,  145289306,  153312524} */

    int32_t SixOhmTable_fine_GaindB_q24[NDTEMP_DISCRETE * NVBATT_DISCRETE_FINE];
    /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp. Range: -9dB to 21dB}
         @h2xmle_range       {-150994944..352321536}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_defaultList {-52640680, 85752586,  147025038, 155761153, 178102761, 190540773, 207818747, 207818747, 216194267, 225950438, 240078195, 253359903, 268795636,
                              -52801347, 84943464,  146287806, 154863101, 176829465, 189412052, 207027370, 207027370, 215376840, 225072228, 239850956, 252790449, 266373698,
                              -52720969, 83409460,  144689660, 153414376, 175729389, 188360566, 206089262, 206089262, 214527575, 224430263, 239476089, 252339879, 265943161,
                              -52640680, 98530836,  156460474, 164467385, 185107520, 197199964, 213671616, 213671616, 222225715, 232398569, 248009020, 258834803, 272751212,
                              -52320404, 97923645,  156115970, 163984123, 184300490, 196365681, 212773743, 212773743, 221345863, 231560765, 247131676, 258218333, 272002190,
                              -52400341, 97618141,  155596140, 163515655, 183951865, 195848921, 211864668, 211864668, 220382051, 230469236, 246049797, 257123593, 271181965,
                              -52400341, 97106104,  155116349, 162986748, 183308354, 195161040, 211073257, 211073257, 219506256, 229396545, 244951610, 256168259, 270459286,
                              -52560479, 90099877,  154677417, 162449121, 182540440, 194500571, 210663492, 210663492, 218973574, 228577056, 244097803, 255252888, 269837167,
                              -52560479, 89531967,  154280104, 161938175, 181764347, 193729031, 209902576, 209902576, 218159648, 227639441, 243280414, 254498926, 269046529,
                              -52720969, 89143244,  153657724, 161121083, 180492929, 192515394, 208823763, 208823763, 217114012, 226671214, 242076305, 253508313, 268247218,
                              -52801347, 88452162,  153029981, 160377231, 179478157, 191184140, 206754050, 206754050, 214815839, 223839972, 237269725, 248183228, 263139965,
                              -52962369, 87964475,  152487578, 158438297, 174280651, 185845259, 201085292, 201085292, 209309272, 218711849, 233820783, 243031842, 257187693,
                              -58139204, 87285590,  129657571, 136098972, 153086249, 165174839, 181637497, 181637497, 189085073, 196676041, 208405479, 216700429, 228434673,
                              -58390588, 7753521,   38934541,  46872245,  67350897,  82467561 , 105995727, 105995727, 116189971, 130189831, 142920003, 151330973, 164524018} */

    int32_t EightOhmTable_fine_GaindB_q24[NDTEMP_DISCRETE * NVBATT_DISCRETE_FINE];
    /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp. Range: -9dB to 21dB}
         @h2xmle_range       {-150994944..352321536}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_defaultList {-37005097,    117034173,    155598710,    164684872,    211051742,    198962287,    217729765,    255946043,    255946043,    255946043,    255946043,    275433571,    276824064,
                              -37005097,    108914168,    152561295,    162855954,    212042649,    199474744,    228869887,    255104773,    255104773,    255104773,    255104773,    273260021,    276824064,
                              -36918818,    112073979,    154961924,    164536395,    212042649,    199312425,    228328826,    254475288,    254475288,    254475288,    254475288,    273615448,    276824064,
                              -41915024,    131132697,    168073936,    202165453,    202165453,    202165453,    202165453,    260392457,    260392457,    260392457,    260392457,    276824064,    276824064,
                              -40271438,    126146996,    164795830,    202165453,    202165453,    202165453,    202165453,    260246586,    260246586,    260246586,    260246586,    276824064,    276824064,
                              -40271438,    122767259,    163494679,    202165453,    202165453,    202165453,    202165453,    259453797,    259453797,    259453797,    259453797,    276824064,    276824064,
                              -40271438,    134614203,    166579267,    202165453,    202165453,    202165453,    202165453,    261978054,    261978054,    261978054,    261978054,    276824064,    276824064,
                              -40181206,    126250128,    164838804,    202165453,    202165453,    202165453,    202165453,    261117463,    261117463,    261117463,    261117463,    276824064,    276824064,
                              -40091086,    124582243,    163187704,    202165453,    202165453,    202165453,    202165453,    260290378,    260290378,    260290378,    260290378,    276824064,    276824064,
                              -40181206,    122875283,    162303439,    171361255,    217661982,    205525916,    235928683,    259365174,    259365174,    259365174,    259365174,    276824064,    276824064,
                              -40181206,    121016723,    161408311,    170459597,    216745088,    203972396,    232889703,    254633170,    254633170,    254633170,    254633170,    276824064,    276824064,
                              -40091086,    119336498,    160502049,    169218616,    214723095,    200145992,    224853007,    247913808,    247913808,    247913808,    247913808,    266049143,    276824064,
                              -40271438,    117616611,    159538184,    165589641,    204875531,    190670985,    216247301,    239818783,    239818783,    239818783,    239818783,    255903548,    269202447,
                              -40361783,    84567719,    104703048,    112262886,    155068332,    142438733,    171689925,    185056341,    185056341,    185056341,    185056341,    206022448,    215241475} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_CPS_DATA_PARAM 0x0800139E

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_cps_data_param_t param_id_haptics_cps_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_CPS_DATA_PARAM",
                          PARAM_ID_HAPTICS_CPS_DATA_PARAM}
   */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_cps_data_param_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of LRAs}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    uint8_t Vbatt_rt[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {battery voltage - register reading}
         @h2xmle_range       {0..255}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q0} */
    uint8_t DieTemp_rt[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {temperature of the die - register reading}
         @h2xmle_range       {0..255}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_CPS_DEMO_PKT_PARAM 0x080013A0

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct haptics_ex_cps_param_t haptics_ex_cps_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_subStruct */
struct haptics_ex_cps_param_t {
    // CPS params
    int32_t Vbatt_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Battery Voltage in volts}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t DieTemp_rt_q20[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {die temperature in degree C}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q20} */
    int32_t dB_cps_Gain_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {cps gain in dB}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_cps_demo_pkt_param_t param_id_haptics_ex_cps_demo_pkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_CPS_DEMO_PKT_PARAM",
                          PARAM_ID_HAPTICS_EX_CPS_DEMO_PKT_PARAM}
   */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_cps_demo_pkt_param_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of LRAs}
    @h2xmle_rangeList   {"1"=1;"2"=2}
    @h2xmle_default     {2} */
#ifdef __H2XML__
    // demo packet for CPS
    haptics_ex_cps_param_t ex_cps_demo_param[0];
    /**< @h2xmle_description        {structure containing LRA params for CPS in Rx Excursion Control block}
         @h2xmle_variableArraySize  {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_CPS_DEMO_PARAM 0x080013A1

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_cps_demo_param_t param_id_haptics_ex_cps_demo_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_CPS_DEMO_PARAM",
                          PARAM_ID_HAPTICS_EX_CPS_DEMO_PARAM}
    @h2xmlp_description {Parameter used for setting the algorithm internal variables related to ex cps demo rtm configuration.}
    @h2xmlp_toolPolicy  {CALIBRATION}*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_cps_demo_param_t
{
    uint16_t dsr;   // downsample ratio from internal values to output
    /**< @h2xmle_description {downsample ratio from internal values to output.}
         @h2xmle_range       {0..65535}
         @h2xmle_default     {10}
         @h2xmle_dataFormat  {Q24} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_DEMO_PKT_PARAM 0x080013A2

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct haptics_ex_param_t haptics_ex_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_subStruct */
struct haptics_ex_param_t
{
    int32_t Re_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Resistance of the LRA, in ohm. Default = 8Ohm, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Bl_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Force factor (Bl product). Default = 1, Range: 0.01 to 128}
         @h2xmle_range       {167772..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Rms_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Mechanical damping or resistance of LRA, in kg/s. Default = 0.0945kg/s, Range = 0.0001 to 20kg/s}
         @h2xmle_range       {16777..335544320}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1585446} */
    int32_t Kms_rt_q24[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Mechanical stiffness of driver suspension, in N/mm. Default = 1.838N/mm, Range = 0.1 to 50N/mm}
         @h2xmle_range       {1677721..838860800}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {30836523} */
    int32_t Fres_rt_q20[HAPTICS_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Resonance frequency, in Hz. Default = 160Hz, Range = 50 to 400Hz}
         @h2xmle_range       {52428800..419430400}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {167772160} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_demo_pkt_param_t param_id_haptics_ex_demo_pkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_DEMO_PKT_PARAM",
                          PARAM_ID_HAPTICS_EX_DEMO_PKT_PARAM}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_demo_pkt_param_t
{
   uint32_t num_channels;
    /**< @h2xmle_description {Number of LRA channels}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    int32_t demo_out_valid;
    /**< @h2xmle_description {flag to indicate signals output contains meaningful data}
         @h2xmle_rangeList   {"Disable"=0; "Enable"=1}
         @h2xmle_default     {0} */
    uint32_t demo_out_pkt_cnt;
    /**< @h2xmle_description {output counter, keep track of repeated or lost output}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */
    int32_t demo_out_samp_dist_ms;
    /**< @h2xmle_description {distance in time between samples (msec)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */

#ifdef __H2XML__
    haptics_ex_param_t ex_demo_param[0];
    /**< @h2xmle_description        {structure containing LRA params for RX excursion control block.}
         @h2xmle_variableArraySize  {num_channels} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_DEMO_PARAM 0x080013A3

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_demo_param_t param_id_haptics_ex_demo_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_DEMO_PARAM",
                          PARAM_ID_HAPTICS_EX_DEMO_PARAM}
    @h2xmlp_description {Parameter used for setting the algorithm internal variables related to demo configuration of excursion.}
    @h2xmlp_toolPolicy  {CALIBRATION}*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_demo_param_t
{
    uint16_t dsr;               // downsample ratio from internal values to output
    /**< @h2xmle_description {downsample ratio from internal values to output.}
         @h2xmle_range       {0..65535}
         @h2xmle_default     {10} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VERSION 0x0800139F

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_version_t param_id_haptics_version_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VERSION",
                         PARAM_ID_HAPTICS_VERSION}
    @h2xmlp_description {parameter used to get the version of the HAPTICS Library.}
    @h2xmlp_toolPolicy  {RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_version_t
{
    uint32_t lib_version_low;
    /**< @h2xmle_description {Lower 32 bits of the 64-bit
                              library version number.} */

    uint32_t lib_version_high;
    /**< @h2xmle_description {Higher 32 bits of the 64-bit
                              library version number.} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */

#define PARAM_ID_HAPTICS_WAVE_DESIGNER_STATE 0x080013D7

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_wave_designer_state param_id_haptics_wave_designer_state;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_WAVE_DESIGNER_STATE",
                          PARAM_ID_HAPTICS_WAVE_DESIGNER_STATE}
    @h2xmlp_description {Parameter used to get waveform state}
    @h2xmlp_toolPolicy  {CALIBRATION}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_wave_designer_state
{
    uint16_t state[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {Wave Designer State}
         @h2xmle_rangeList   {"Ideal"=0;"In_Progress"=1;"Complete"=2}
         @h2xmle_default     {0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/
#define PARAM_ID_HAPTICS_LPASS_SWR_HW_REG_CFG \
  0x08001AE1  // we get hardware register addresses

/* LPASS SWR HW register dependent sub structure payload */

typedef struct pkd_reg_addr_t pkd_reg_addr_t;
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct haptics_pkd_reg_addr_t {
  uint32_t ab_initialize_pkd_reg_addr;
  /**< @h2xmle_description {Per channel write initialized value to register
   * address .} */
  uint32_t ab_trigger_pkd_reg_addr;
  /**< @h2xmle_description {Per channel write values to register to trigger
   * autobraking.} */
  uint32_t ab_stop_pkd_reg_addr;
  /**< @h2xmle_description {Per channel write values to register to stop
   * autobraking} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* LPASS SWR HW register structure payload */
typedef struct param_id_haptics_lpass_swr_hw_reg_cfg_t
    param_id_haptics_lpass_swr_hw_reg_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_LPASS_SWR_HW_REG_CFG",
                          PARAM_ID_HAPTICS_LPASS_SWR_HW_REG_CFG}
    @h2xmlp_description {PMIC autobraking register details.}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct param_id_haptics_lpass_swr_hw_reg_cfg_t {
  uint32_t num_channel;
  /**< @h2xmle_description {Number of channels.}
       @h2xmle_rangeList   {"1"=1;"2"=2}
       @h2xmle_default     {2} */

  uint32_t lpass_wr_cmd_reg_phy_addr;
  /**< @h2xmle_description {LPASS HW write register physical address.} */

  uint32_t lpass_rd_cmd_reg_phy_addr;
  /**< @h2xmle_description {LPASS HW read register physical address} */

  uint32_t lpass_rd_fifo_reg_phy_addr;
  /**< @h2xmle_description {LPASS HW register physical address to read
   * autobreaking soundwire register values.} */

  haptics_pkd_reg_addr_t haptics_pkd_reg_addr[0];
  /**< @h2xmle_description {Per channel packed register address written to LPASS
     RD CMD register.}
     @h2xmle_variableArraySize  {num_channel} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define EVENT_ID_WAVEFORM_STATE 0x080013B2
/*==============================================================================
   Type definitions
==============================================================================*/

/** @h2xmlp_parameter   {"EVENT_ID_WAVEFORM_STATE",
                          EVENT_ID_WAVEFORM_STATE}
    @h2xmlp_description { For Getting update of waveform state as “Complete", event raised by the Haptics Module.}
    @h2xmlp_toolPolicy  { NO_SUPPORT}*/

/** @} <-- End of the Module --> */
#endif /* __HAPTICS_RX_H__ */
