#ifndef __SP_RX_H__
#define __SP_RX_H__

/*==============================================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause

  @file sp_rx.h
  @brief This file contains APIs for Speaker Protection Module
==============================================================================*/

/** @h2xml_title1           {Speaker Protection}
    @h2xml_title_date       {January 7, 2022} */
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
#define SP_MAX_INPUT_PORTS 1
#define SP_MAX_OUTPUT_PORTS 1
#define SP_STACK_SIZE 16384

/* Unique Module ID */
#define MODULE_ID_SPEAKER_PROTECTION_V7 0x0701000F

/** @h2xmlm_module       {"MODULE_ID_SPEAKER_PROTECTION_V5",
                          MODULE_ID_SPEAKER_PROTECTION_V5}
    @h2xmlm_displayName  {"Speaker Protection v5"}
    @h2xmlm_toolPolicy   {Calibration;CALIBRATION}
    @h2xmlm_description  {ID of the Speaker Protection v5 module.\n
      this module implements algorithms to ensure that speakers arent
      damaged when some music is played.

      This module supports the following parameter IDs:\n
     - #PARAM_ID_MODULE_ENABLE \n
     - #PARAM_ID_SP_STATIC_CFG\n
     - #PARAM_ID_SP_OP_MODE\n
     - #PARAM_ID_SP_TRANSITION_ASP_ENABLE\n
     - #PARAM_ID_SP_TRANSITION_ASP_CALIB_PARAM\n
     - #PARAM_ID_SPv5_SP_DYNAMIC_CFG\n \\Todo: rename this and also in VI
     - #PARAM_ID_SP_TH_DEMO_CFG\n
     - #PARAM_ID_SP_EX_DEMO_CFG\n
     - #PARAM_ID_SP_TH_STATS\n
     - #PARAM_ID_SP_EX_STATS\n
     - #PARAM_ID_SP_STATS\n
     - #PARAM_ID_SP_TMAX_XMAX_LOGGING\n
     - #PARAM_ID_SP_VERSION\n
     - #PARAM_ID_RTM_LOGGING_ENABLE\n
     - #PARAM_ID_SP_TH_PI_DERV_CTRL_CFG\n
     - #PARAM_ID_SP_CPS_STATIC_CFG\n
     - #PARAM_ID_SPKR_PROT_EX_CPS_DEMO_CFG\n
     - #PARAM_ID_SPKR_PROT_RX_EX_CPS2_BATTCONFIG_LFATTEN_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS2_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS_BOOSTOPERATION_PARAM\n
     - #PARAM_ID_SPKR_PROT_CPSBASIC_CFG\n
     - #PARAM_ID_CPS_LPASS_HW_INTF_CFG\n
     - #PARAM_ID_CPS_LPASS_SWR_THRESHOLDS_CFG\n
     - #PARAM_ID_RX_CPS_FINE_PARAM\n
     - #PARAM_ID_SP_EX_CPS_STATS\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS2_DEMO_PKT_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS2_DEMO_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PKT_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PARAM\n
     - #PARAM_ID_SPKR_PROT_T0_CALI_PARAM\n
     - #PARAM_ID_SPKR_PROT_EX_RX_BATTTEMP_DATA_PARAM\n
     - #PARAM_ID_SPKR_PROT_DYNAMIC_NOTCH_PARAM\n
     - #PARAM_ID_SPKR_PROT_LIN_RX_DYNAMIC_CFG\n
     - #PARAM_ID_SPKR_PROT_SPEAKERS_LINK_MODE_PARAM\n
     - #PARAM_ID_SP_EX_RX_POWLIM_MODE2_CFG_PARAM\n
     - #PARAM_ID_SPv5_SP_TMAX_XMAX_LOGGING_EXTN\n



      All parameter IDs are device independent.\n

     Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 48000\n
*  - Number of channels   : 1 to 8\n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 16, 24  \n
*  - Q format             : 15 for bps = 16 and 27 for bps = 24\n
supported bps
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

     @h2xmlm_toolPolicy              {Calibration}

    @h2xmlm_dataMaxInputPorts    {SP_MAX_INPUT_PORTS}
     @h2xmlm_dataInputPorts       {IN=2}
     @h2xmlm_dataMaxOutputPorts   {SP_MAX_OUTPUT_PORTS}
     @h2xmlm_dataOutputPorts      {OUT=1}
     @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
     @h2xmlm_isOffloadable        {false}
     @h2xmlm_stackSize            {SP_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent  { "SP VI intent id for communicating Vsens and Isens data" = INTENT_ID_SP,
maxPorts= 1 }
    @h2xmlm_ctrlDynamicPortIntent  { "SP CPS intent id for communicating CPS data" = INTENT_ID_CPS, maxPorts= 1 }
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

/* Maximum number of speakers supported in speaker protection Rx
    processing. */
#define SP_NUM_MAX_SPKRS 8

/* Maximum number of stages in the notch filter. */
#define SP_NCH_FILT_STAGES_MAX 5

/* Number of plotting samples in one thermal Rx output packet. */
#define SP_TH_RX_DEMO_SMPL_PER_PKT 10

/* Number of plotting samples in one excursion Rx output packet. */
#define SP_EX_RX_DEMO_SMPL_PER_PKT 10

/* Maximum number of stages in the IIR filter. */
#define SP_IIR_TDF2_STAGES_MAX 5

/* Number of numerators per stage in the IIR filter. */
#define SP_IIR_TDF2_NUM_NUM_PER_STAGE 3

/* Number of denominators per stage in the IIR filter. */
#define SP_IIR_TDF2_NUM_DEN_PER_STAGE 2

/* Maximum number of samples per packet. */
#define MAX_SAMPLES_IN_PACKET 480

/* Max number of vbatt resistance table */
#define SP_NVBATT_DISCRETE 9

/* Max number of die temp resistance table */
#define SP_NDTEMP_DISCRETE 14

/* Max number of vbatt fine resistance table */
#define SP_NVBATT_DISCRETE_FINE (13)

/* LPASS CPS HW INTF TYPE*/
#define SOUNDWIRE_MODE 1

/* LPASS CPS HW INTF TYPE*/
#define DMA_MODE 2

#define MAX_CPS_BOOST_INDUCTOR_CURRENT_SAMPLES_IN_PACKET_48K (4800)
#define MAX_CPS_BOOST_INDUCTOR_CURRENT_SAMPLES_IN_PACKET_96K (9600)
#define MAX_CPS_BOOST_INDUCTOR_CURRENT_SAMPLES_IN_PACKET_192K (19200)

#define SP_NILIM_DISCRETE (11)

#define FIR_LEN_MAX (385)

#define N_VPH_RANGE (25)

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_STATIC_CFG 0x08001B3C

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_static_cfg_t param_id_sp_static_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_STATIC_CFG",
                         PARAM_ID_SP_STATIC_CFG}
    @h2xmlp_description {parameter used to configure the static configuration of
                         speaker protection processing.}
    @h2xmlp_toolPolicy  {CALIBRATION; RTC_READONLY}*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_static_cfg_t
{
    uint32_t sampling_rate;         // PCM signal sampling rate
  /**< @h2xmle_description {Sampling rate of Rx signal.}
       @h2xmle_rangeList   {"48kHz"=48000}
       @h2xmle_default     {48000} */
    uint32_t bits_per_sample;       // Number of bits for input and output samples, (per channel)
  /**< @h2xmle_description {Bits per sample for Rx signal.}
       @h2xmle_rangeList   {"16"=16;"24"=24}
       @h2xmle_default     {16} */
    uint32_t num_speakers;          // Number of speakers
  /**< @h2xmle_description {Number of channels for Rx signal.}
       @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
       @h2xmle_default     {2} */
    uint32_t frame_size_ms;         // processing frame size in ms
  /**< @h2xmle_description {Frame size for Rx processing.}
       @h2xmle_rangeList   {"1ms"=1}
       @h2xmle_default     {1} */
    uint32_t features;              // what sub-features are on
  /**< @h2xmle_description {Features enabled in the speaker protection
                            algorithm.}
       @h2xmle_range       {0..0x1f}

         @h2xmle_bitField    {0x00000001}
         @h2xmle_bitName     {"Notch high-pass filter"}
         @h2xmle_description {Notch high-pass filter}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_group       {HPF}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000002}
         @h2xmle_bitName     {"Thermal protection"}
         @h2xmle_description {Thermal protection}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000004}
         @h2xmle_bitName     {"Feedback excursion control"}
         @h2xmle_description {Feedback excursion control}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_group       {Excursion_Control}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000008}
         @h2xmle_bitName     {"Account for dc in excursion prediction/control"}
         @h2xmle_description {Feedback voice-coil offset control}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {1}
         @h2xmle_group       {Excursion_Control} //todo: check once on this grouping field.
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000010}
         @h2xmle_bitName     {"Feedback dc control"}
         @h2xmle_description {Feedback voice-coil offset control}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_group       {DC}
         @h2xmle_default     {1}
         @h2xmle_bitFieldEnd

         @h2xmle_bitField    {0x00000020}
         @h2xmle_bitName     {"Reserved bits"}
         @h2xmle_description {any bit field from 0x00000020 to 0xfffffff8 is reserved for future use.}
         @h2xmle_default     {0}
         @h2xmle_visibility  {hide}
         @h2xmle_readOnly    {true}
         @h2xmle_bitFieldEnd*/


    uint32_t tuning_mode_en_flag;   // indicates whether tuning mode is enabled (1) or disabled (0)
    /**< @h2xmle_description {Specifies whether RTM tuning mode is enabled.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0} */
    uint32_t ctrl_rate;             // thermal control rate (Hz)
    /**< @h2xmle_description {Thermal control rate.}
         @h2xmle_rangeList   {"1000Hz"=1000}
         @h2xmle_default     {1000} */
    uint32_t num_nch_filter_stages; // number of NOTCH filter stages
    /**< @h2xmle_description {Number of notch filter stages.}
         @h2xmle_range       {0..SP_NCH_FILT_STAGES_MAX}
         @h2xmle_default     {2} */

    int16_t temp_loop_dly_ms;       // loop delay from predicted temp to temp info coming back
    /**< @h2xmle_description {Loop delay from the predicted temperature to the
                            temperature information coming back.}
         @h2xmle_range       {0..1000}
         @h2xmle_default     {120} */
    int16_t pow_est_smooth_flag;    // indicates whether or not do IIR filtering, to smooth out power estimation
    /**< @h2xmle_description {Specifies whether to use IIR filtering to smooth the
                            power estimation.}
         @h2xmle_rangeList   {"Do not use IIR filtering"=0;
                            "Use IIR filtering"=1}
         @h2xmle_default     {1} */

    uint16_t pt_lvl_switch_en;      // dynamic pilot tone level switch enable/disable flag
    /**< @h2xmle_description {Specifies whether to enable the dynamic pilot tone
                            level switch.}
         @h2xmle_rangeList   {disabled=0;enabled=1}
         @h2xmle_default     {0} */
    uint16_t pt_masking_delay_ms;   // delay in ramping down pilot tone in ms
    /**< @h2xmle_description {Delay in ramping down the pilot tone.}
         @h2xmle_range       {0..1000}
         @h2xmle_default     {13} */
    int32_t pt_masking_thr_q27;     // when input level is below this threshold, pilot tone is disabled
    /**< @h2xmle_description {Specifies the input level threshold below which the
                            pilot tone is disabled.}
         @h2xmle_range       {0..134217727}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {189813} */
    int32_t hist_buf_length;
    /**< @h2xmle_description {history buffer length in msec for excursion and power control}
         @h2xmle_range       {4..12}
         @h2xmle_default     {8} */
    int32_t rx_static_gain_q27;
    /**< @h2xmle_description {Gain to be applied to RX signal before speaker protection in linear scale}
         @h2xmle_range       {33713968..534330399}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {134217728} */
    int32_t dyn_proc_delay_ms;          // dyn_proc delay in millisecond (Q0)
    /**< @h2xmle_description {delay in dynamic processing in msec to compensate analysis filter delay}
         @h2xmle_range       {0..10} ms
         @h2xmle_default     {0} */
    uint32_t log_dump_en_flag;      // indicates whether dumping maximum excursion and temperature data or not; enable(1)/disable(0); enforce to enable tuning_mode_en_flag if this flag is enabled.
    /**< @h2xmle_description {Flag to enable/disable logging maximum excursion and temperature data}
         @h2xmle_rangeList   {"disabled"=0; "enabled"=1}
         @h2xmle_default     {0} */
    uint32_t logging_count_period;  // duration of monitoring Xmax/Tmax to increase counter in msec
    /**< @h2xmle_description {Duration of monitoring Xmax/Tmax to increase counter in msec}
         @h2xmle_range       {0..0xFFFFFFFF}
         @h2xmle_default     {2000} */
    uint32_t fpilot;                // Pilot tone frequencies [16, 40] 16Hz or 40 Hz.
                              // Note: Pilot tone frequency values MUST be the same for the RX/TH/EX modules.
    /**< @h2xmle_description {Pilot tone frequencies. Pilot tone frequency values MUST be the same for the RX/TH/EX modules}
         @h2xmle_rangeList   {"16"=16; "40"=40}
         @h2xmle_default     {40} */

   uint32_t cps_sampling_rate;
   /**< @h2xmle_description {CPS sampling rate for DMA/Pandeiro}
	@h2xmle_rangeList   {"24000"=24000; "48000"=48000}
	@h2xmle_default     {48000} */

   uint32_t chip;
   /**< @h2xmle_description {attached WSA 88xx}
	@h2xmle_rangeList   {"884x"=0; "885x"=1}
	@h2xmle_default     {0} */

   uint32_t cps_mode_flag; //reserved for future
   /**< @h2xmle_description {Flag to enable/disable limiter based on Vbatt/DieTemp}
	@h2xmle_rangeList   {"disabled"=0; "enabled"=1; "LFSN bass shelf"=2; "6dB attenuation at low-die-temperature"=3; "CPSv2.0 with Predictive boost"=4; "CPSv2.0 without Predictive boost"=5; "CPS-bypass"=6; "Phy model single"=7; "Phy model shared"=8; "CPS-basic-single"=9; "CPS-basic-stereo"=10}
    @h2xmle_default     {0}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_CPS_STATIC_CFG 0x08001B3D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_cps_static_cfg_t param_id_sp_cps_static_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_CPS_STATIC_CFG",
                         PARAM_ID_SP_CPS_STATIC_CFG}
    @h2xmlp_description {parameter used to configure the static cps configuration of
                         speaker protection processing.}
    @h2xmlp_toolPolicy  {Calibration;RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_cps_static_cfg_t
{
    uint16_t limiter_cps_en_flag; // flag that activates the limiter based on the Vbatt/Die Temp values. enable (1)/disable(0)/ LFSNshelf (2)/fullband Attenuation at low die temp (3).
    /**< @h2xmle_description {Flag to enable/disable limiter based on Vbatt/DieTemp}
         @h2xmle_rangeList       {"disabled"=0; "enabled"=1; "LFSN bass shelf"=2; "6dB attenuation at low-die-temperature"=3; "CPSv2.0" = 4}
         @h2xmle_default     {0}
         @h2xmle_group       {Limiter}*/

    uint16_t limiter_cps_smooth_VbDT_en_flag; // flag that activates the smoothing operator on the CPS limiter applied to Vbatt/DieTemp. enable (1)/disable(0).
    /**< @h2xmle_description {Flag that activates the smoothing operator on the CPS limiter applied to Vbatt/DieTemp}
         @h2xmle_rangeList       {"disabled"=0; "enabled"=1}
         @h2xmle_default     {0} */


    int32_t limiter_cps_margin_dB_q15; // dB margin about the limiter gain based on the Vbatt/Die Temp values. //{-3dB to 3dB}
    /**< @h2xmle_description {margin in dB about the limiter gain based on Vbatt/DieTemp}
         @h2xmle_range       {-98304..98304}
         @h2xmle_dataFormat  {Q15}
         @h2xmle_default     {0} */

   int32_t FourOhmTable_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE]; //{-9dB to 21dB}
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {sp_fourOhmGain.bin}
        @h2xmle_policy  {Advanced} */

   int32_t SixOhmTable_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE];//{-9dB to 21dB}
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {sp_sixOhmGain.bin}
        @h2xmle_policy  {Advanced} */

   int32_t EightOhmTable_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE];//{-9dB to 21dB}
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {sp_eightOhmGain.bin}
        @h2xmle_policy  {Advanced} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define CPS_NUM_VBATT_THRESHOLD_VALUES 3



/* Unique Parameter id */
#define PARAM_ID_SP_EX_CPS_DEMO_CFG 0x08001B3E

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_cps_demo_cfg_t param_id_sp_ex_cps_demo_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_CPS_DEMO_CFG",
                         PARAM_ID_SP_EX_CPS_DEMO_CFG}
    @h2xmlp_description {parameter used for setting the algorithm internal
                         variables related to ex cps demo rtm configuration.}
    @h2xmlp_toolPolicy  {Calibration} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_ex_cps_demo_cfg_t
{
   uint16_t dsr;
   /**< @h2xmle_description {downsample ratio from internal values to output.}
        @h2xmle_default     {10}  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_EX_CPS_STATS 0x08001B3F  //todo:ms13 update this in ccb as well
/*==============================================================================
   Type definitions
==============================================================================*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_ex_rx_cps_param_t
{
    int32_t Vbatt_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Battery Voltage in volts}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t DieTemp_rt_q20[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {die temperature in degree C}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q20} */
    int32_t dB_cps_Gain_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {cps gain in dB}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct sp_ex_rx_cps_param_t sp_ex_rx_cps_param_t;

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_cps_stats_t param_id_sp_ex_cps_stats_t;
/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_CPS_STATS",
                         PARAM_ID_SP_EX_CPS_STATS}
    @h2xmlp_description {parameter used for RTM of the algorithm internal
                         variables related to ex cps processing.}
    @h2xmlp_toolPolicy  {RTM} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_ex_cps_stats_t
{
    uint32_t frame_duration_in_ms;
    /**< @h2xmle_description {Frame duration in milliseconds for Excursion cps Rx
                                 statistics.} */

    uint32_t frame_num;
    /**< @h2xmle_description {Frame number of the Excursion Rx statistics.} */
    // CPS params

    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */
#ifdef __H2XML__
    // demo packet for CPS
    sp_ex_rx_cps_param_t ex_rx_cps_demo_param[0];
    /**< @h2xmle_description {structure containing speaker params for CPS in Rx Excursion Control block}
         @h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_OP_MODE 0x08001B40
/* unique param id for spv5 */
#define PARAM_ID_SP_OP_MODE_V5 0x080011E9


/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_op_mode_t param_id_sp_op_mode_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_OP_MODE",
                         PARAM_ID_SP_OP_MODE}
    @h2xmlp_description {parameter used to configure the mode of feedback
                         speaker protection processing}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_op_mode_t
{
    uint32_t operation_mode;        // normal running or thermal calibration
    /**< @h2xmle_description {Operation mode of thermal VI module.}
         @h2xmle_rangeList   {"Normal Running mode"=0;
                              "Calibration mode"=1;
                              "Factory Test Mode"=2;
                              "V-Validation Mode"=3} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_TRANSITION_ASP_ENABLE 0x08001B41

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_transition_asp_enable_t param_id_sp_transition_asp_enable_t;
/** @h2xmlp_parameter   {"PARAM_ID_SP_TRANSITION_ASP_ENABLE",
                         PARAM_ID_SP_TRANSITION_ASP_ENABLE}
    @h2xmlp_description {parameter used to enable transition acoustic shock protection
                         feature.}
    @h2xmlp_toolPolicy  {CALIBRATION; RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_transition_asp_enable_t
{
    uint32_t trans_asp_mode;        // transition acoustic shock protection mode (0-disable, 1-enable)
    /**< @h2xmle_description {flag for transition acoustic shock protection mode}
         @h2xmle_rangeList       {"disabled"=0; "enabled"=1}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_TRANSITION_ASP_CALIB_PARAM 0x08001B42

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_transition_asp_calib_param_t param_id_sp_transition_asp_calib_param_t;
/** @h2xmlp_parameter   {"PARAM_ID_SP_TRANSITION_ASP_CALIB_PARAM",
                         PARAM_ID_SP_TRANSITION_ASP_CALIB_PARAM}
    @h2xmlp_description {parameter used for logging the algorithm internal
                         variables.}
    @h2xmlp_toolPolicy  {CALIBRATION; RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_transition_asp_calib_param_t
{
    uint32_t initial_target_gain;                                               // initial linear target gain in Q28
  /**< @h2xmle_description {Initial linear target gain in Q28
                                  default: 7.199 (in decimal)
                                  Range: 0 - 7.999 (in decimal)}
       @h2xmle_range       {0..2147483647}
       @h2xmle_default     {1932735283}
       @h2xmle_dataFormat  {Q28} */
    uint32_t initial_target_gain_period_in_msec;                                // time period in which target gain remain still as initial target gain in milisecond (Q0)
  /**< @h2xmle_description {Time period in which target gain remain still as initial target gain in millisecond (Q0)}
       @h2xmle_range       {0..2147483647}
       @h2xmle_default     {2000}
       @h2xmle_dataFormat  {Q0} */
    uint32_t rampup_transition_time_in_msec;                                    // ramp up transition time from initial linear gain to gain 0dB in milisecond (Q0)
  /**< @h2xmle_description {Ramp up transition time from initial linear gain to gain 0dB in millisecond (Q0)}
       @h2xmle_range       {0..2147483647}
       @h2xmle_default     {1000}
       @h2xmle_dataFormat  {Q0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPv5_SP_DYNAMIC_CFG 0x08001B43

/*==============================================================================
   Type definitions
==============================================================================*/

/* Notch Dyanmic Config structure payload */
typedef struct sp_rx_nch_filt_param_t sp_rx_nch_filt_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_rx_nch_filt_param_t
{
   int32_t num[SP_NCH_FILT_STAGES_MAX * SP_IIR_TDF2_NUM_NUM_PER_STAGE];
   /**< @h2xmle_description {Numerator coefficients for notch filter
                             configuration.}
        @h2xmle_defaultList {1055533754, -2111067576, 1055533762,
                            1073741824, -2147483582, 1073741815,
                      0, 0, 0,
                      0, 0, 0,
                      0, 0, 0} */

   int32_t den[SP_NCH_FILT_STAGES_MAX * SP_IIR_TDF2_NUM_DEN_PER_STAGE];
   /**< @h2xmle_description {Denominator coefficients for notch filter
                             configuration.}
        @h2xmle_defaultList {-2121642205, 1048082161,
                            -2136597088, 1063038326,
                             0, 0,
                      0, 0,
                      0, 0} */

   int16_t num_q[SP_NCH_FILT_STAGES_MAX];
   /**< @h2xmle_description {Q factor of numerator coefficients for notch filter
                             configuration.}
        @h2xmle_defaultList {1, 1, 0, 0, 0} */

   int16_t den_q[SP_NCH_FILT_STAGES_MAX];
   /**< @h2xmle_description {Q factor of denominator coefficients for notch
                             filter configuration.}
        @h2xmle_defaultList {1, 1, 0, 0, 0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* tdf2 configuration structure for RX_EX Dynamic config. */
typedef struct sp_tdf2_cfg_t sp_tdf2_cfg_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_tdf2_cfg_t
{
   int16_t numCh;
  /**< @h2xmle_description {Number of channels for Rx signal.}
       @h2xmle_rangeList   {"1"=1;"2"=2}
       @h2xmle_default     {2} */
   int16_t stages;
  /**< @h2xmle_description {Number of stages.}
       @h2xmle_range       {1..5}
       @h2xmle_default     {1} */
   int32_t num[SP_IIR_TDF2_STAGES_MAX*SP_IIR_TDF2_NUM_NUM_PER_STAGE];    // numerator coefficients
  /**< @h2xmle_description {Numerator coefficients.}
       @h2xmle_defaultList {1073741824,0,0,
                            0,0,0,
                            0,0,0,
                            0,0,0,
                            0,0,0} */
   int32_t den[SP_IIR_TDF2_STAGES_MAX*SP_IIR_TDF2_NUM_DEN_PER_STAGE];    // denominator coefficients
  /**< @h2xmle_description {Denominator coefficients.}
       @h2xmle_defaultList {0,0,0,0,0,
                           0,0,0,0,0} */
   int16_t numQ[SP_IIR_TDF2_STAGES_MAX];                              // numerator coefficients' Q-Factor
  /**< @h2xmle_description {Q factor of numerator coefficients}
       @h2xmle_defaultList {1,0,0,0,0} */
   int16_t denQ[SP_IIR_TDF2_STAGES_MAX];                              // denominator coefficients' Q-Factor
  /**< @h2xmle_description {Q factor of denominator coefficients.}
       @h2xmle_defaultList {1,0,0,0,0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
typedef struct sp_th_ctrl_param_t sp_th_ctrl_param_t;

struct sp_th_ctrl_param_t
{
// Top-level
    uint32_t pi_scale_u16q18;                    // scale down a full-scale 40Hz pilot tone by this much.
    /**< @h2xmle_description {scale down a full scale 40 Hz pilot
         tone by this value.}
         @h2xmle_dataFormat  {Q18}
         @h2xmle_range       {0..65535}
         @h2xmle_default     {3775} */
    uint32_t rx_scale_u16q16;                    // scale outgoing signal down by this much, so that when pilot tone is added, the signal won't exceed full-scale
    /**< @h2xmle_description {scale down the outgoing signal by this
         value so when the pilot tone is added, the signal
         does not exceed full scale.}
         @h2xmle_dataFormat  {Q16}
         @h2xmle_range       {32768..65535}
         @h2xmle_default     {64592} */
    // Th Rx Ch 0 params
    int32_t r_spk_coil_q8;                       // typical resistnace of speaker
    /**< @h2xmle_description {typical resistance.}
         @h2xmle_range       {512..16384}
         @h2xmle_dataFormat  {Q8}
         @h2xmle_default     {2048} */
    int32_t v_full_scale_q10;                    // Speaker voltage for digitially full scale signal
    /**< @h2xmle_description {voltage for a digitally full scale
         signal.}
         @h2xmle_range       {512..16384}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {5477} */
    int32_t thermal_resistance_q6;               // total thermal resistance (voice coil + magnet etc)
    /**< @h2xmle_description {Ch 0: total thermal resistance (such as
         voice coil + magnet).}
         @h2xmle_range       {0..32767}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {3200} */
    int32_t thermal_time_constant_low_q10;       // low estimate of voice coil thermal time constant (sec)
    /**< @h2xmle_description {low estimate of the voice coil thermal
         time constant. (in seconds)}
         @h2xmle_range       {51..32767}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {1024} */
    int32_t thermal_time_constant_high_q10;      // high estimate of voice coil thermal time constant (sec)
    /**< @h2xmle_description {high estimate of voice coil thermal
         time constant. (in seconds)}
         @h2xmle_range       {51..32767}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {3482} */
    int32_t temp_tgt_q6;                         // target temperature (deg C)
    /**< @h2xmle_description {target temperature.(in degrees C)}
         @h2xmle_range       {-1920..12800}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {5120} */
    int32_t pi_ctrl_prop_value_q12;              // value of the P term in the PI controller
    /**< @h2xmle_description {value of the proportional term in the
              PI controller.}
         @h2xmle_range       {0..32767}
         @h2xmle_dataFormat  {Q12}
         @h2xmle_default     {2100} */
    int32_t pi_ctrl_intg_value_q12;              // value of the I term in the PI controller
    /**< @h2xmle_description {value of the integral term in the PI
              controller.}s
         @h2xmle_range       {0..32767}
         @h2xmle_dataFormat  {Q12}
         @h2xmle_default     {75} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct sp_fir_cfg_t sp_fir_cfg_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_fir_cfg_t
{
	int16_t numTaps;
	/**< @h2xmle_description 	{Number of fir filter coefficients}
	@h2xmle_range   	{1...385}
	@h2xmle_default     {49} */
	int16_t Q;                              // Q-Factor
	/**< @h2xmle_description 	{Q factor of numerator coefficients}
	@h2xmle_default 	{0} */
	int32_t taps[FIR_LEN_MAX];    // numerator coefficients
	/**< @h2xmle_description 	{FIR filter coefficients.} 
	@h2xmle_defaultList			{1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}*/
} 
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
typedef struct sp_ex_ctrl_param_t sp_ex_ctrl_param_t;

struct sp_ex_ctrl_param_t
{
    // Ex Rx Ch 0 params
    int32_t amp_gain_q24;                        // Amplifier gain that will be used in scaling Tx vsense signal to rx signal
    /**< @h2xmle_description {speaker peak voltage for a digitally full-scale signal}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t ptone_excursion_mm_q27;                // excursion in mm for pilot tone, will be added to peak excursion computed
    /**< @h2xmle_description {excursion for the pilot tone. This
              excursion is added to the computed peak excursion.}
         @h2xmle_range       {0..134217728}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0}
         @h2xmle_group       {Exc_Control}*/
    int32_t dc_excursion_mm_q27;                // excursion in mm for pilot tone, will be added to peak excursion computed
    /**< @h2xmle_description {DC excursion margin}
         @h2xmle_range       {0..134217728}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0}
         @h2xmle_group       {Exc_Control}*/
    int32_t max_excursion_mm_q27;                            // speaker xmax value
    /**< @h2xmle_description {maximum permissible excursoin}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {40265318}
         @h2xmle_group       {Exc_Control}*/
    int32_t max_amplitude_q27;                            // speaker xmax value
    /**< @h2xmle_description {amplitude limiter threshold in linear scale}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {134217728}
         @h2xmle_group       {Limiter}*/
    int32_t max_power_W_q27;
    /**< @h2xmle_description {maximum power that amplifier can handle}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {536870912}
         @h2xmle_group       {Power_Limiter}*/
    int32_t trace_resistance_rx_q24;
    /**< @h2xmle_description {trace resistance from amp output to speakers in Ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t exc_model_tuning_factor_q27;
    /**< @h2xmle_description {Tuning coefficient to compensation for ex-rx linear model over-prediction}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {134217728} */
    int32_t Re_ohm_q24;
    /**< @h2xmle_description {DC resistance of voice coil at room temperature or small signal level in Ohm}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Bl_q24;
    /**< @h2xmle_description {Force factor (Bl product)}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Mms_gram_q24;
    /**< @h2xmle_description {Ch 0: Mechanical mass of loudspeaker diaphragm in gram}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {2722896} */
    int32_t Rms_KgSec_q24;
    /**< @h2xmle_description {Mechanical damping or resistance of loudspeaker in Kg/sec}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {5056765} */
    int32_t Kms_Nmm_q24;
    /**< @h2xmle_description {Mechanical stiffness of driver suspension in N/mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {68155531} */
    int32_t Qms_q24;
    /**< @h2xmle_description {Mechanical Q-factor}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {50331648} */
    int32_t Fres_Hz_q20;
    /**< @h2xmle_description {Resonance frequency in Hz}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {838860800} */
    int32_t dc_sensitivity_Vmm_q24;
    /**< @h2xmle_description {Speaker DC voltage sensitivity in Volt/mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {838860800} */
    sp_tdf2_cfg_t band_splitting_even_filter_cfg; // band splitting even config
    /**< @h2xmle_description {Band splitting even config}
     */
    sp_tdf2_cfg_t band_splitting_odd_filter_cfg; // band splitting odd config
   sp_fir_cfg_t band_splitting_linear_phase_filter_cfg;// band splitting using linear-phase filters
    /**< @h2xmle_description {Band splitting odd config}
     */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/* Structure definition for Parameter */
typedef struct param_id_sp_dynamic_cfg_t param_id_sp_dynamic_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPv5_SP_DYNAMIC_CFG",
                         PARAM_ID_SPv5_SP_DYNAMIC_CFG}
    @h2xmlp_description {Parameter used to configure dynamic parameters for
                         Feedback Speaker Protection module processing}
   @h2xmlp_toolPolicy  {Calibration;RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_dynamic_cfg_t
{
       /* Common params (common to both speakers) */
       // Top-level
       sp_rx_nch_filt_param_t rx_notch_filter_cfg;   // notch filter configuration (coefficients and coefficient q-factors)
       /**< @h2xmle_description {Payload to configure dynamic
                             notch filter configuration} */

       uint32_t link_all_channels_gain;                    // Specifies whether the gains applied to the two speakers are linked or unlinked.
       /**< @h2xmle_description {Specifies whether the gains applied to the two
                                speakers are linked.}
            @h2xmle_rangeList   {"Unlinked"=0; "Linked"=1}
            @h2xmle_default     {0} */
       // Th Rx
       uint32_t temp_control_mthd;                       // Use feedback temp only (0), feedback with lowpass (1), or use feedforward est temp (2)
       /**< @h2xmle_description {Temperature control method.}
            @h2xmle_rangeList   {"Use feedback temperature only"=0;
                                "Feedback with low pass"=1;
                                "Use feedforward estimated temperature"=2}
            @h2xmle_default     {2} */
       int32_t temp_nominal_q6;                          // assumed voice coil temp, at startup
       /**< @h2xmle_description {Assumed voice coil temperature at startup. (in
                                degree C)}
            @h2xmle_range       {-1920..12800}
            @h2xmle_dataFormat  {Q6}
            @h2xmle_default     {3200} */
       int32_t temp_min_q6;                              // min reasonable meas'd temp, temp lower than this will be ignored
       /**< @h2xmle_description {Minimum reasonable measured temperature. A
                                temperature lower than this value is ignored. (in
                                degree C)}
            @h2xmle_range       {-1920..12800}
            @h2xmle_dataFormat  {Q6}
            @h2xmle_default     {-1920} */
       int32_t temp_max_q6;                              // max reasonable meas'd temp, temp higher than this will be ignored
       /**< @h2xmle_description {Maximum reasonable measured temperature. A
                                temperature higher than this value is ignored.(in
                                degree C)}
            @h2xmle_range       {-1920..12800}
            @h2xmle_dataFormat  {Q6}
            @h2xmle_default     {12800} */
       int32_t temp_max_chg_sec_q6;                      // max temp change (deg C) per sec, new temp will be ignored if outside this range, 0 = disable this feature
       /**< @h2xmle_description {Maximum temperature change per second. A new
                                temperature is ignored if it falls outside this
                                range.(Set 0 to disables this feature)}
            @h2xmle_range       {0..32767}
            @h2xmle_dataFormat  {Q6}
            @h2xmle_default     {4096} */
       int32_t temp_smoothing_factor_q31;                // smoothing of temperature to compute gain
       /**< @h2xmle_description {Smoothing of the temperature to compute the gain.}
            @h2xmle_dataFormat  {Q31}
            @h2xmle_default     {6735944} */
       int32_t max_attenuation_db_q7;                    // minimum temp control gain (dB)
       /**< @h2xmle_description {Minimum temperature control gain.}
            @h2xmle_range       {-7680..0}
            @h2xmle_dataFormat  {Q7}
            @h2xmle_default     {-1536} */
       int32_t attack_gain_smoothing_factor;             // smoothing factor for adjusting gain during attack phase (current gain < previous gain)
       /**< @h2xmle_description {Smoothing factor for adjusting gain during the
                                attack phase (current gain less than previous
                                gain).}
            @h2xmle_range       {328..32767}
            @h2xmle_default     {32767} */
       int32_t release_gain_smoothing_factor;            // smoothing factor for adjusting gain during release phase (current gain > previous gain)
       /**< @h2xmle_description {Smoothing factor for adjusting gain during the
                                release phase (current gain greater than previous
                                gain).}
            @h2xmle_range       {328..32767}
            @h2xmle_default     {32767} */
       int32_t temp_dead_zone_q6;                        // deadZone for reduced P term, (deg C)
       /**< @h2xmle_description {Dead zone (region near the target temperature) for a
                                reduced proportional term.(in degree C)}
            @h2xmle_range       {2..2048}
            @h2xmle_dataFormat  {Q6}
            @h2xmle_default     {64} */
       int32_t dead_zone_scaling_q15;                    // scaling factor to modify P term
       /**< @h2xmle_description {Scaling factor to modify the proportional term.}
            @h2xmle_range       {328..32767}
            @h2xmle_dataFormat  {Q15}
            @h2xmle_default     {32767} */
       int32_t clip_time_out_ms;                         // > 0 means enable clip intr support feature with this time out
      /**< @h2xmle_description {Timeout in milli seconds used for processing a clip
                                interrupt.(value greater than 0 enables the clip
                                interrupt timeout)}
           @h2xmle_range       {0..4000}
           @h2xmle_default     {0} */
       int32_t vbat_time_out_ms;                         // > 0 means enable vbat support feature with this time out
      /**< @h2xmle_description {Timeout in milli seconds used to process a VBAT
                                interrupt. (value greater than 0 enables the VBAT
                                interrupt timeout)}
           @h2xmle_range       {0..1000000}
           @h2xmle_default     {300000} */

       // EX_RX common params
       int32_t link_all_channels_ex_gain;
      /**< @h2xmle_description {Apply common gain to both channels}
           @h2xmle_rangeList       {"Unlinked"=0; "Linked"=1}
           @h2xmle_default     {0} */
       int32_t max_release_time_ms; // 1000ms
      /**< @h2xmle_description {Maximum release time in msec}
           @h2xmle_range       {1000..4000}
           @h2xmle_default     {1000} */

       int32_t dyn_proc_type; // 0 disable, 1 shelving, 2 notch and 3 reserved
      /**< @h2xmle_description {Dynamic processing feature indicator}
           @h2xmle_rangeList       {"Disable"=0; "Notch filter"=1; "Bass boost"=2; "Notch filter with resonance tracking"=3}
           @h2xmle_default     {0}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_fc_q20;
      /**< @h2xmle_description {Dynamic processing -- Parametric EQ filter frequency in Hz}
           @h2xmle_range       {104857600..2097152000}
           @h2xmle_dataFormat  {Q20}
           @h2xmle_default     {262144000}
           @h2xmle_group       {Dyn_Notch} */
       int32_t dyn_proc_Q_q24;
      /**< @h2xmle_description {Dynamic processing -- Parametric EQ filter Q}
           @h2xmle_range       {1677721..1677721600}
           @h2xmle_dataFormat  {Q24}
           @h2xmle_default     {50331648}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_threshold_dBq23;
      /**< @h2xmle_description {Dynamic processing -- compression threshold in dB}
           @h2xmle_range       {-754974720..0}
           @h2xmle_dataFormat  {Q23}
           @h2xmle_default     {0}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_ratio_q24;
      /**< @h2xmle_description {Dynamic processing -- compression ratio}
           @h2xmle_range       {16777216 .. 1677721600}
           @h2xmle_dataFormat  {Q24}
           @h2xmle_default     {16777216}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_makeup_gain_q27;
      /**< @h2xmle_description {Dynamic processing -- makeup gain in linear scale}
           @h2xmle_range       {8468566..2127207634}
           @h2xmle_dataFormat  {Q27}
           @h2xmle_default     {134217728} */
       int32_t dyn_proc_attack_time_ms;
      /**< @h2xmle_description {dynamic processing -- attach time in msec}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {10}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_release_time_ms;
      /**< @h2xmle_description {dynamic processing -- release time in msec}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {100}
           @h2xmle_group       {Dyn_Notch}*/
       int32_t dyn_proc_auto_release_flag;
      /**< @h2xmle_description {flag for automatic release time in dynamic processing}
           @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
           @h2xmle_default     {1} */

       int32_t lfsn_type; // 0 disable, 1 shelving and 2 notch
      /**< @h2xmle_description {optional excursion control using low frequency shelving or notch filter}
           @h2xmle_rangeList       {"Disable"=0; "Low frequency shelving"=1; "notch filter at resonance frequency"=2}
           @h2xmle_default     {0}
           @h2xmle_group       {Low_Freq_Shelf}*/
       int32_t lfsn_fc_q20;
      /**< @h2xmle_description {frequency setting for low frequency shelving}
           @h2xmle_range       {104857600..1048576000}
           @h2xmle_dataFormat  {Q20}
           @h2xmle_default     {314572800}
           @h2xmle_group       {Low_Freq_Shelf}*/
       int32_t lfsn_Q_q24;
      /**< @h2xmle_description {Q setting for time varying notch filter at resonance frequency}
           @h2xmle_range       {1677721..1677721600}
           @h2xmle_dataFormat  {Q24}
           @h2xmle_default     {50331648}
           @h2xmle_group       {Low_Freq_Shelf}*/
       int32_t lfsn_min_gain_q27;
      /**< @h2xmle_description {minimum gain of low frequency shelving or notch filter}
           @h2xmle_range       {8468566..134217728}
           @h2xmle_dataFormat  {Q27}
           @h2xmle_default     {67268211}
           @h2xmle_group       {Low_Freq_Shelf}*/
       int32_t lfsn_attack_time_ms;
      /**< @h2xmle_description {attack time in msec for time varying gain of shelving or notch filter}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {10} */
       int32_t lfsn_release_time_ms;
      /**< @h2xmle_description {release time in msec for time varying gain of shelving or notch filter}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {100} */
       int32_t lfsn_auto_release_flag;
      /**< @h2xmle_description {flag for automatic release time in low frequency shelving or notch filter}
           @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
           @h2xmle_default     {1} */
       int32_t exc_ctrl_attack_time_ms;
      /**< @h2xmle_description {attack time in msec for excursion limiter}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {0}
           @h2xmle_group       {Exc_Control}*/
       int32_t exc_ctrl_release_time_ms;
      /**< @h2xmle_description {release time in msec for excursion limiter}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {100}
           @h2xmle_group       {Exc_Control}*/
       int32_t exc_ctrl_auto_release_flag;
      /**< @h2xmle_description {flag for automatic release time in excursion limiter}
           @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
           @h2xmle_default     {1} */
       int32_t exc_ctrl_min_gain_q27;
      /**< @h2xmle_description {minimum gain for excursion limiter}
           @h2xmle_range       {8468566..134217728}
           @h2xmle_dataFormat  {Q27}
           @h2xmle_default     {33713968} */
       int32_t pow_lim_enable_flag;
      /**< @h2xmle_description {power limiter operating mode}
           @h2xmle_rangeList       {"Disable"=0; "Enable Power Limiter in mode 1"=1; "Temp-based power-limiting"=2, "Power-limiter-during-charging"=3}
           @h2xmle_default     {0}
           @h2xmle_group       {Power_Limiter}*/
       int32_t limiter_attack_time_ms;
      /**< @h2xmle_description {amplitude and power limiter attack time in msec}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {0} */
       int32_t limiter_release_time_ms;
      /**< @h2xmle_description {amplitude and power limiter release time in msec}
           @h2xmle_range       {0..1000}
           @h2xmle_default     {100} */
       int32_t limiter_auto_release_flag;     // limiter gain release constant
      /**< @h2xmle_description {flag for automatic release time in limiter}
           @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
   int32_t filterbank_type; // 0 IIR and 1 FIR
           @h2xmle_default     {1} */

       uint32_t num_ch;
       /**< @h2xmle_description {Number of speaker channels}
       @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
       @h2xmle_default     {2} */
    #ifdef __H2XML__
           /* Speaker-specific parameters */
        sp_th_ctrl_param_t fbsp_th_ctrl_param[0];
        /**< @h2xmle_description {structure containing speaker params for RX thermal control block.}
             @h2xmle_variableArraySize  {num_ch} */
        sp_ex_ctrl_param_t fbsp_ex_ctrl_param[0];
        /**< @h2xmle_description {structure containing speaker params for RX excursion control block.}
             @h2xmle_variableArraySize  {num_ch} */
    #endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Structure definition for Parameter */
#define PARAM_ID_SP_TH_DEMO_CFG 0x08001B44

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_th_demo_cfg_t param_id_sp_th_demo_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_TH_DEMO_CFG",
                         PARAM_ID_SP_TH_DEMO_CFG}
    @h2xmlp_description {parameter used for setting the algorithm internal
                         variables related to demo configuration of thermal processing.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_th_demo_cfg_t
{
   uint16_t dsr;
   /**< @h2xmle_description {downsample ratio from internal values to output.}
        @h2xmle_default     {10}  */

   uint16_t lpass_alph_q16;
   /**< @h2xmle_description {lowpass smoothing factor. Q16 format.}
        @h2xmle_default     {512U}  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Structure definition for Parameter */
#define PARAM_ID_SP_EX_DEMO_CFG 0x08001B45

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_demo_cfg_t param_id_sp_ex_demo_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_DEMO_CFG",
                         PARAM_ID_SP_EX_DEMO_CFG}
    @h2xmlp_description {parameter used for setting the algorithm internal
                         variables related to demo configuration of excursion.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_ex_demo_cfg_t
{
   uint16_t dsr;
   /**< @h2xmle_description {downsample ratio from internal values to output.}
        @h2xmle_default     {10}  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Structure definition for Parameter */
#define PARAM_ID_SP_TH_STATS 0x08001B46  //todo:MS13: Update in CCB as well

/*==============================================================================
   Type definitions
==============================================================================*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */

typedef struct sp_th_rx_param_t sp_th_rx_param_t;

struct sp_th_rx_param_t
{
    int32_t vc_resis_q24[SP_TH_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {voice coil resistance (in ohm)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t vc_temp_q22[SP_TH_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {voice coil temperature.(in degrees C)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {0} */
    int32_t th_gain_lnk_db_q23[SP_TH_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {thermal gain (in dB)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q23}
         @h2xmle_default     {0} */
    int32_t target_temp_q22;
    /**< @h2xmle_description {target temperature.(in degrees C)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/* Structure definition for Parameter */
typedef struct param_id_sp_th_stats_t param_id_sp_th_stats_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_TH_STATS",
                         PARAM_ID_SP_TH_STATS}
    @h2xmlp_description {parameter used for RTM of the algorithm internal
                         variables related to thermal processing.}
    @h2xmlp_toolPolicy  {RTM} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_th_stats_t
{
    //uint16_t spkr_id;
    uint32_t frame_duration_in_ms;
    /**< @h2xmle_description {Frame duration in milliseconds for thermal Rx
                                  statistics.} */
    uint32_t frame_num;
    /**< @h2xmle_description {Frame number of the Excursion Rx statistics.} */

    int32_t demo_out_valid;
    /**< @h2xmle_description {flag to indicate signals output contains meaningful data}
         @h2xmle_rangeList       {"Invalid"=0; "Valid"=1}
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
    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */
#ifdef __H2XML__
    sp_th_rx_param_t th_rx_demo_param[0];
    /**< @h2xmle_description {structure containing speaker params for RX thermal control block.}
         @h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_EX_STATS 0x08001B47

/*==============================================================================
   Type definitions
==============================================================================*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
typedef struct sp_ex_rx_param_t sp_ex_rx_param_t;

struct sp_ex_rx_param_t
{
    int32_t Re_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Resistance of the speaker in ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t Bl_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {force factor (Bl product)}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t Rms_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Mechanical damping or resistance of loudspeaker}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t Kms_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Mechanical stiffness of driver suspension}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t Fres_rt_q20[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Resonance frequency in Hz}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q20} */
    int32_t Qms_rt_q24[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Mechanical Q-factor}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q24} */
    int32_t dc_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {estimated DC from VI}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t dp_in_rms_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {rms_in in ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t dp_out_rms_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {rms_out in ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t dp_notch_gain_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {notch filter gain}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t dp_tgt_rms_q27;
    /**< @h2xmle_description {target rms in ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t lfsn_in_peak_pred_exc_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {lfsn peak predicted excursion}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t lfsn_out_peak_pred_exc_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {lfsn peak predicted excursion}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t lfsn_filter_gain_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {lfsn filter gain}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t exc_ctrl_in_peak_pred_exc_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {peak predicted excursion in mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t exc_ctrl_out_peak_pred_exc_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Peak predicted excursion in mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t exc_ctrl_tot_out_peak_pred_exc_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Total Peak excursion}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t exc_ctrl_gain_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {Excursion gain}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t exc_ctrl_tgt_excursion_q27;
    /**< @h2xmle_description {target excursion in mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t amp_lim_in_peak_pred_amp_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {limiter output amplitude}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t amp_lim_out_peak_pred_amp_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {limiter input amplitude}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t pow_lim_in_peak_pred_pow_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {limiter input peak power}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t pow_lim_out_peak_pred_pow_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {limiter output peak power}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t amp_lim_tgt_amplitude_q27;
    /**< @h2xmle_description {limiter target amplitude}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t pow_lim_tgt_power_q27;
    /**< @h2xmle_description {limiter target power}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
    int32_t tot_lim_gain_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
    /**< @h2xmle_description {limiter gain}
         @h2xmle_range       {0..2147483647}
         @h2xmle_default     {0}
         @h2xmle_dataFormat  {Q27} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_stats_t param_id_sp_ex_stats_t;
/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_STATS",
                         PARAM_ID_SP_EX_STATS}
    @h2xmlp_description {parameter used for RTM of the algorithm internal
                         variables related to exertion processing.}
    @h2xmlp_toolPolicy  {RTM} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_ex_stats_t
{
    uint32_t frame_duration_in_ms;
    /**< @h2xmle_description {Frame duration in milliseconds for Excursion Rx
                              statistics.} */

    uint32_t frame_num;
    /**< @h2xmle_description {Frame number of the Excursion Rx statistics.} */

    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */

    //uint16_t spkr_id;

    int32_t demo_out_valid;
    /**< @h2xmle_description {flag to indicate signals output contains meaningful data}
         @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
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
   sp_ex_rx_param_t ex_rx_demo_param[0];
/**< @h2xmle_description {structure containing speaker params for RX excursion control block.}
@h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_STATS 0x08001B48

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_stats_t param_id_sp_stats_t;
/** @h2xmlp_parameter   {"PARAM_ID_SP_STATS",
                         PARAM_ID_SP_STATS}
    @h2xmlp_description {parameter used for RTM of the algorithm internal
                         variables.}
    @h2xmlp_toolPolicy  {RTM} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_stats_t
{
   uint32_t frame_duration_in_ms;
   /**< @h2xmle_description {Frame duration in milliseconds for Rx statistics.}*/

   uint32_t frame_num;
   /**< @h2xmle_description {Frame number of the Rx statistics.} */

   uint32_t num_speakers;
   /**< @h2xmle_description {Number of speakers.} */

   uint32_t features;
   /**< @h2xmle_description {Features enabled in the speaker protection
                             algorithm.}

        @h2xmle_bitField    {0x00000001}
        @h2xmle_bitName     {"Notch high-pass filter"}
        @h2xmle_description {Notch high-pass filter}
        @h2xmle_rangeList   {"disabled"=0;"enabled"=1}
        @h2xmle_bitFieldEnd

        @h2xmle_bitField    {0x00000002}
        @h2xmle_bitName     {"Thermal protection"}
        @h2xmle_description {Thermal protection}
        @h2xmle_rangeList   {"disabled"=0;"enabled"=1}
        @h2xmle_bitFieldEnd

        @h2xmle_bitField    {0x00000004}
        @h2xmle_bitName     {"Feedback excursion control"}
        @h2xmle_description {Feedback excursion control}
        @h2xmle_rangeList   {"disabled"=0;"enabled"=1}
        @h2xmle_bitFieldEnd */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_TMAX_XMAX_LOGGING 0x08001B49

/*==============================================================================
   Type definitions
==============================================================================*/

/* TMAX XMAX Logging channel dependent params sub structure */
typedef struct sp_tmax_xmax_params_t sp_tmax_xmax_params_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_tmax_xmax_params_t
{
    int32_t max_excursion;
    /**< @h2xmle_description {maximum excursion since the lastest grasp of xmax in mm}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {0} */
    uint32_t count_exceeded_excursion;
    /**< @h2xmle_description {number of periods when the monitored excursion exceeds to and stays at Xmax during logging_count_period}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */
    int32_t max_temperature;
    /**< @h2xmle_description {maximum temperature since the lastest grasp of tmax in C}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {0} */
    uint32_t count_exceeded_temperature;
    /**< @h2xmle_description {number of periods when the monitored temperature exceeds to and stays at Tmax during logging_count_period}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Structure definition for Parameter */
typedef struct param_id_sp_tmax_xmax_logging_t param_id_sp_tmax_xmax_logging_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_TMAX_XMAX_LOGGING",
                         PARAM_ID_SP_TMAX_XMAX_LOGGING}
    @h2xmlp_description {parameter used to log max temp and max excursion logging.}
    @h2xmlp_toolPolicy  {RTM} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_tmax_xmax_logging_t
{
   uint32_t num_ch;
   /**< @h2xmle_description {Number of channels for Rx signal.}
        @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
        @h2xmle_default     {1} */

   sp_tmax_xmax_params_t tmax_xmax_params[0];
   /**< @h2xmle_description {TMAX XMAX logging params sub structure.}
        @h2xmle_variableArraySize  {num_ch} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPv5_SP_TMAX_XMAX_LOGGING_EXTN 0x08001B4A

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_tmax_xmax_logging_extn_params_t param_id_sp_tmax_xmax_logging_extn_params_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPv5_SP_TMAX_XMAX_LOGGING_EXTN",
                         PARAM_ID_SPv5_SP_TMAX_XMAX_LOGGING_EXTN}
    @h2xmlp_description {parameter used to log max temp and max excursion logging.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_tmax_xmax_logging_extn_params_t
{
    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */

    uint32_t Mode;         // determines the big data logging behavior
    // 0: for version 0 (reports max temperature/excursion values since previous call to bigdata)
    // 1: for version 1 (reports max temperature/excursion values over entire playback)
    // one param to control big data logging behavior on both speakers.
    /**< @h2xmle_description {Mode of bigdata logging}
         @h2xmle_rangeList   {"Version_0"=0; "Version_1"=1}
         @h2xmle_default     {1} */
#ifdef __H2XML__
   int32_t Tmax[0]; // rated speaker maximum temperature acts as threshold for over temperature check
   /**< @h2xmle_description {Rated speaker max temperature Tmax (in degrees C)}
        @h2xmle_variableArraySize  {num_ch}
        @h2xmle_range       {-1920..12800}
        @h2xmle_dataFormat  {Q6}
        @h2xmle_default {5120} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_TH_PI_DERV_CTRL_CFG 0x08001B4B

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_th_pi_derv_ctrl_cfg_t param_id_sp_th_pi_derv_ctrl_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_TH_PI_DERV_CTRL_CFG",
                         PARAM_ID_SP_TH_PI_DERV_CTRL_CFG}
    @h2xmlp_description {Proportional Integral derivative control.
                      To detect the rate of change of temperature and bring the gain
                 down more quickly to prevent temperature from overshooting.}
    @h2xmlp_toolPolicy  {Calibration;RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_th_pi_derv_ctrl_cfg_t
{
    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */
#ifdef __H2XML__
    int32_t pi_ctrl_derv_value_q12[0];              // value of the D term in the PI controller
   /**< @h2xmle_description {value of the derivative term in the PI controller.}
        @h2xmle_variableArraySize  {num_ch}
        @h2xmle_range       {0..32767}
        @h2xmle_dataFormat  {Q12}
        @h2xmle_default     {700} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_RX_CPS_FINE_PARAM 0x08001B4C

/*==============================================================================
   Type definitions
==============================================================================*/
/* Structure definition for Parameter */
typedef struct param_id_sp_rx_cps_fine_param_t param_id_sp_rx_cps_fine_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_RX_CPS_FINE_PARAM",
                         PARAM_ID_RX_CPS_FINE_PARAM}
    @h2xmlp_description {This parameter is used for getting finer resolution of gain to be applied at Vbatt/DieTemps.
                         We have extended CPS tables that can be read from using this parameter }
    @h2xmlp_toolPolicy  {Calibration;RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_rx_cps_fine_param_t
{
    uint16_t cps_fine_tbl_en_flag;
    /**< @h2xmle_description {Flag to enable/disable fine-VBAT resolution CPS gain tables}
         @h2xmle_rangeList   {"disabled"=0; "enabled"=1}
         @h2xmle_default     {0} */

    uint16_t reserved;
    /**< @h2xmle_description {Reserved}
         @h2xmle_visibility  {hide}
         @h2xmle_default     {0} */

   int32_t FourOhmTable_fine_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE_FINE];
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.
             Range: -9dB to 21dB}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {cps_fourOhmGain_fine.bin}
        @h2xmle_policy  {Advanced} */

   int32_t SixOhmTable_fine_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE_FINE];
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.
             Range: -9dB to 21dB}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {cps_sixOhmGain_fine.bin}
        @h2xmle_policy  {Advanced} */

   int32_t EightOhmTable_fine_GaindB_q24[SP_NDTEMP_DISCRETE * SP_NVBATT_DISCRETE_FINE];
   /**< @h2xmle_description {dB limiter gain based on Vbatt/DieTemp.
             Range: -9dB to 21dB}
        @h2xmle_range       {-150994944..352321536}
        @h2xmle_dataFormat  {Q24}
        @h2xmlx_expandArray  {true}
        @h2xmle_defaultFile  {cps_eightOhmGain_fine.bin}
        @h2xmle_policy  {Advanced} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_EX_RX_POWLIM_MODE2_CFG_PARAM 0x08001B4D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_rx_power_limiter_mode2_param_t param_id_sp_ex_rx_power_limiter_mode2_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_RX_POWLIM_MODE2_CFG_PARAM",
                         PARAM_ID_SP_EX_RX_POWLIM_MODE2_CFG_PARAM}
    @h2xmlp_description {Temperature based power limiting is applied using this parameter}
    @h2xmlp_toolPolicy  {Calibration;RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// power limiter in mode 2, required additional parameters for operation.
struct param_id_sp_ex_rx_power_limiter_mode2_param_t
{

    int32_t mode2power_limiter_attack_time_ms;
    /**< @h2xmle_description {power limiter in mode 2 attack time in msec}
         @h2xmle_range       {0..20000}
         @h2xmle_default     {0} */
    int32_t mode2power_limiter_release_time_ms;
    /**< @h2xmle_description {power limiter in mode 2 release time in msec}
         @h2xmle_range       {0..20000}
         @h2xmle_default     {100} */
    int32_t temp_nominal_q22;
    /**< @h2xmle_description {nominal temperature.(in degrees C)}
         @h2xmle_range       {-125829120..838860800}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {104857600} */
    int32_t temp_tgt_q22;
    /**< @h2xmle_description {target temperature.(in degrees C)}
         @h2xmle_range       {-125829120..838860800}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {377487360} */
    int32_t temp_delta_q22;
    /**< @h2xmle_description {target temperature.(in degrees C)}
         @h2xmle_range       {0..1048576000}
         @h2xmle_dataFormat  {Q22}
         @h2xmle_default     {125829120} */
    uint32_t num_ch;
    /**< @h2xmle_description {Number of speaker channels}
         @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
         @h2xmle_default     {2} */
#ifdef __H2XML__
    uint32_t PowerW_RolloffEnd_q27[0]; // Power threshold in W that the power limiter will use if the temperature exceeds Ttgt.
    /**< @h2xmle_description {value of the power limiter threshold in mode 2. range 0W to 16W}
         @h2xmle_variableArraySize  {num_ch}
         @h2xmle_range       {0..2147483648}
         @h2xmle_dataFormat  {Q27}
         @h2xmle_default     {536870912} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_VERSION 0x08001B4E

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_version_t param_id_sp_version_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_VERSION",
                         PARAM_ID_SP_VERSION}
    @h2xmlp_description {parameter used to get the version of the SP Library.}
    @h2xmlp_toolPolicy  {RTC} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_version_t
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
#define PARAM_ID_CPS_LPASS_HW_INTF_CFG 0x08001259 // we get hardware register addresses

/*==============================================================================
   Type definitions
==============================================================================*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct cps_reg_wr_values_t
{
   uint32_t value_normal_threshold[CPS_NUM_VBATT_THRESHOLD_VALUES];
   /**< @h2xmle_description {Values to be written to LPASS WR CMD register when vbatt value returns back to
                             normal threshold. vbatt greater than or equal to vbatt_lower_threshold_1} */

   uint32_t value_lower_threshold_1[CPS_NUM_VBATT_THRESHOLD_VALUES];
   /**< @h2xmle_description {Values to be written to LPASS WR CMD register, if vbatt is greater than
                             or equal to vbatt_lower_threshold_2 and if vbatt is less than vbatt_lower_threshold_1} */

   uint32_t value_lower_threshold_2[CPS_NUM_VBATT_THRESHOLD_VALUES];
   /**< @h2xmle_description {Values to be written to LPASS WR CMD register, if vbatt is less than
    *                        vbatt_lower_threshold_2} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_CPS_LPASS_SWR_THRESHOLDS_CFG 0x08001254 // we get hardware register addresses

typedef struct cps_reg_wr_values_t                     cps_reg_wr_values_t;
typedef struct param_id_cps_lpass_swr_thresholds_cfg_t param_id_cps_lpass_swr_thresholds_cfg_t;
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_cps_lpass_swr_thresholds_cfg_t
{
   uint32_t num_spkr;
   /**< @h2xmle_description {Number of Rx speakers.}
        @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
        @h2xmle_default     {2} */

   uint32_t vbatt_lower_threshold_1;
   /**< @h2xmle_description {vbatt lower threshold 1 value. Size = 8bits.
                             if vbatt is greater than or equal to value_lower_threshold_2 and vbatt is less than
                             vbatt_lower_threshold_1, write configured values to LPASS WR CMD register}
        @h2xmle_range       {0..255} */

   uint32_t vbatt_lower_threshold_2;
   /**< @h2xmle_description {vbatt lower threshold 2 value. Size = 8bits.
                             If vbatt is less than vbatt_lower_threshold_2, write configured values to LPASS WR CMD
                             register}
        @h2xmle_range       {0..255} */

   cps_reg_wr_values_t cps_reg_wr_values[0];
   /**< @h2xmle_description {Structures for Vbat values}
   @h2xmle_variableArraySize  {num_spkr}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* LPASS SWR HW register speaker dependent sub structure payload */

typedef struct pkd_reg_addr_t pkd_reg_addr_t;
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct pkd_reg_addr_t
{
   uint32_t vbatt_pkd_reg_addr;
   /**< @h2xmle_description {Per speaker packed register address written to LPASS RD CMD register.
                                To read Voltage value} */

   uint32_t temp_pkd_reg_addr;
   /**< @h2xmle_description {Per speaker packed register address written to LPASS RD CMD register.
                                To read Temp value} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* LPASS SWR HW register structure payload */
typedef struct lpass_swr_hw_reg_cfg_t lpass_swr_hw_reg_cfg_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct lpass_swr_hw_reg_cfg_t
{
   uint32_t num_spkr;
   /**< @h2xmle_description {Number of Rx speakers.}
        @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
        @h2xmle_default     {2} */

   uint32_t lpass_wr_cmd_reg_phy_addr;
   /**< @h2xmle_description {LPASS HW register physical address. Threshold values to be written based on vbatt value
      read. Write only at transitions from either of the following values: lower threshold 1, lower threshold 2 and
      normal} */

   uint32_t lpass_rd_cmd_reg_phy_addr;
   /**< @h2xmle_description {LPASS HW register physical address to write packed soundwire register address
                             values of temp and vbatt} */

   uint32_t lpass_rd_fifo_reg_phy_addr;
   /**< @h2xmle_description {LPASS HW register physical address to read temp and vbatt soundwire register values.} */

   pkd_reg_addr_t pkd_reg_addr[0];
   /**< @h2xmle_description {Per speaker packed register address written to LPASS RD CMD register.
                                To read Voltage/Temp value}
      @h2xmle_variableArraySize  {num_spkr} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_cps_lpass_hw_intf_cfg_t param_id_cps_lpass_hw_intf_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_CPS_LPASS_HW_INTF_CFG",
                         PARAM_ID_CPS_LPASS_HW_INTF_CFG}
    @h2xmlp_description {Parameter used for querying the hardware register details from HLOS. Temp and Voltage}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_cps_lpass_hw_intf_cfg_t
{
   uint32_t lpass_hw_intf_cfg_mode;
   /**< @h2xmle_description {LPASS HW interface configuration mode.
							 1 - SOUNDWIRE MODE
							 2 - DMA MODE}
        @h2xmle_rangeList   {"SOUNDWIRE"=1; "DMA MODE"=2}
        @h2xmle_default     {2}  */

   /* Variable payload depending on lpass_hw_intf_cfg_mode will follow here */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_RX_EX_CPS2_BATTCONFIG_LFATTEN_PARAM  0x08001B4F

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_rx_ex_cps2_battconfig_lfatten_param_t param_id_sp_rx_ex_cps2_battconfig_lfatten_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_RX_EX_CPS2_BATTCONFIG_LFATTEN_PARAM",
                         PARAM_ID_SP_RX_EX_CPS2_BATTCONFIG_LFATTEN_PARAM}
    @h2xmlp_description {1S/2S/3S battery configs induce different levels of attenuation
                         in the low-frequency. Using this param we configure the attenuation expected}
    @h2xmlp_toolPolicy  {CALIBRATION, RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_rx_ex_cps2_battconfig_lfatten_param_t
{
   uint32_t num_ch;
   /**< @h2xmle_description {Number of speaker channels}
   @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
   @h2xmle_default     {2} */

#ifdef __H2XML__
	int32_t battery_config_low_frequency_attenuation_q27[0];   // LF SN attenuation in the low frequency, dependent on the battery config
   /**< @h2xmle_description {low-frequency attenuation observed when using 88xx with different battery configurations,
							  input is in linear format, default for 1S : idb(-2dB), 3S : idb(0dB) in Q27}
	@h2xmle_variableArraySize  {num_ch}
	@h2xmle_range       {0,..134217728}
	@h2xmle_dataFormat  {Q27}
    @h2xmle_default     {134217728} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_EX_RX_CPS2_PARAM 0x08001B50

/*==============================================================================
   Type definitions
==============================================================================*/
typedef struct param_id_sp_cps2_param_t param_id_sp_cps2_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct param_id_sp_cps2_param_t
{
   int32_t battery_configuration; // battery configuration.
   /**< @h2xmle_description {battery configuration : 0/1:1S, 2:2S, 3:3S}
   @h2xmle_range       {0..3}
   @h2xmle_default     {0} */

   int32_t Vph_WSA_min_q24; // VPh min varies for each vendor. For 2S/3S; insert Vph_2S/2; Vph_3S/3 for simplicity. Range from 2.5 to 5V for 1S.
   /**< @h2xmle_description {VPh min varies for each vendor. For 2S/3S; insert Vph_2S/2; Vph_3S/3 for simplicity. Range from 2.5 to 5V for 1S}
   @h2xmle_range       {41943040..83886080}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {50331648} */

   int32_t Ibatt_max_per_channel_q24; // peak battery current per channel, range : 1-7A; default: 4.5A.
   /**< @h2xmle_description {peak battery current per channel.}
   @h2xmle_range       {16777216..117440512}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {50331648} */

   int32_t Iboost_throttled_perchannel_q24; // peak boost current per channel, range : 1-7A; default: 3A.
   /**< @h2xmle_description {peak battery current per channel.}
   @h2xmle_range       {16777216..117440512}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {50331648} */

   int32_t Rph_series_q24; // approx. series resistance between the battery and the Vph tap point on the amp.
   /**< @h2xmle_description {approx. series resistance between the battery and the Vph tap point on the amp.}
   @h2xmle_range       {0..16777216}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {1677722} */

   int32_t PA_eta_q24; // overall PA efficiency that varies as a function of output power and Vbatt; range : 60-99%.
   /**< @h2xmle_description {overall PA efficiency that varies as a function of output power and Vbatt; vary this at a later stage}
   @h2xmle_range       {10066329..16609443}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {15099494} */

   sp_tdf2_cfg_t pbxo_band_splitting_even_filter_cfg; // pbxo band splitting even config
   /**< @h2xmle_description {pbxo band splitting even config}
   */
   sp_tdf2_cfg_t pbxo_band_splitting_odd_filter_cfg; // pbxo band splitting odd config
   /**< @h2xmle_description {pbxo band splitting odd config}
   */

   int32_t clip_detect_hold_time_ms; // clip-release happens after this hold/sustain time-period, in ms.
   /**< @h2xmle_description {clip-release happens after this hold/sustain time-period, in ms..}
   @h2xmle_range       {0..10000}
   @h2xmle_default     {6000} */

   int32_t clip_detect_attenuation_perframe_q27; // max attenuation applied in each frame in q27
   /**< @h2xmle_description {max attenuation applied in each frame in linear format,
   default is idb(-0.5) in q27.}
   @h2xmle_range       {0..134217728}
   @h2xmle_dataFormat  {Q27}
   @h2xmle_default     {126709705}*/

   int32_t clip_detect_max_attenuation_thr_q27; // total max clip detect threshold attenuation available.
   /**< @h2xmle_description {total max clip detect threshold attenuation available in linear format,
   default is idb(-2) in q27 }
   @h2xmle_range       {0..134217728}
   @h2xmle_dataFormat  {Q27}
   @h2xmle_default     {106612930}*/

   int32_t battery_config_low_frequency_attenuation_q27; // low freq attenuation applied as a func of battery stacks. range : -6dB to 0dB
   /**< @h2xmle_description { low freq attenuation in linear format applied as a func of battery stacks.
                  default is idb(-2) in q27}
   @h2xmle_range       {67268211..134217728}
   @h2xmle_dataFormat  {Q27}
   @h2xmle_default     {106612930}*/

   int32_t Vph_WSA_throttlelvl_q24; // q24 throttling threshold to reduce the battery current; applies additional gain regulation
   /**< @h2xmle_description { throttling voltage threshold. apply nominal values for 1/2/3S as is.}
   @h2xmle_range       {50331648..234881024}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {58720256}*/

   int32_t Vph_WSA_max_q24; // q24 approx threshold corresponding to 100% Vph, varies for each vendor
   /**< @h2xmle_description { Vph-max corresponding to a full battery. apply nominal values as is for 1/2/3S.}
   @h2xmle_range       {50331648..301989888}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {70464307}*/

   int32_t CPS2_max_inst_power_limit_W_q24; // maximum power limit permissible as a function of stacked battery; q24
   /**< @h2xmle_description { low freq attenuation applied as a func of battery stacks.  4 to 15W}
   @h2xmle_range       {67108864..251658240}
   @h2xmle_dataFormat  {Q24}
   @h2xmle_default     {184549376}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_rx_cps2_param_t param_id_sp_ex_rx_cps2_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_RX_CPS2_PARAM",
                         PARAM_ID_SP_EX_RX_CPS2_PARAM}
    @h2xmlp_description {Parameter used for setting parameters related to CPS2}
    @h2xmlp_toolPolicy  {CALIBRATION, RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// CPS version 2 param: construction without look-up tables.
struct param_id_sp_ex_rx_cps2_param_t
{
   int32_t clipdetect_limiter_attack_time_ms;
   /**< @h2xmle_description {clip detect limiter threshold attack time in msec}
   @h2xmle_range       {0..1000}
   @h2xmle_default     {0} */
   int32_t clipdetect_limiter_release_time_ms;
   /**< @h2xmle_description {clip detect limiter threshold release time in msec}
   @h2xmle_range       {0..10000}
   @h2xmle_default     {1000} */
   int32_t num_ch;
   /**< @h2xmle_description {Number of speaker channels}
   @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
   @h2xmle_default     {2} */
#ifdef __H2XML__
   param_id_sp_cps2_param_t cps2_param[0];
   /**< @h2xmle_description {structure containing speaker params for CPS2 in Rx Excursion Control block}
   @h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_EX_RX_CPS_BOOSTOPERATION_PARAM 0x08001B51

/*==============================================================================
   Type definitions
==============================================================================*/

typedef struct param_id_sp_cps_batttemp_param_t param_id_sp_cps_batttemp_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct param_id_sp_cps_batttemp_param_t
{
	int16_t attenuateSmallerLoads; //apply a small attenuation if the resistance drops from say 8 to 4.
	/**< @h2xmle_description { //apply a small attenuation if the resistance drops from say 8 to 4.}
	@h2xmle_range       {0..1}
	@h2xmle_default     {0}*/

	uint16_t reserved;
	/**< @h2xmle_description {Reserved Field.}
	@h2xmle_visibility {hide}
	@h2xmle_default {0} */

	int32_t RphDelta_LowTemp; // R_series_Delta with low temperature variation.
	/**< @h2xmle_description {R_series_Delta with low temperature variation.}
	@h2xmle_range       {0..16777216 } // 1 Ohm max
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {1006632} : 0.060 Ohms */

	int32_t BattTempRange[2]; // Battery temperature range where the Series resistance needs to be varied.
	/**< @h2xmle_description {Battery temperature range where the Series resistance needs to be varied.}
	@h2xmle_range       {-335544320..335544320} // -20 to 20 C
	@h2xmle_dataFormat  {Q24}
	@h2xmle_defaultList     {-335544320,335544320} */ // BattTempRange[0] > BattTempRange[1]

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_sp_cps_boostoperation_param_t param_id_sp_cps_boostoperation_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct param_id_sp_cps_boostoperation_param_t
{
	int32_t boost_headroom_voltage;
	/**< @h2xmle_description {Boost headroom}
	@h2xmle_range       {0..50331648}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */ // 1V

	int32_t UVLO_voltage;
	/**< @h2xmle_description {undervoltage-lockout voltage}
	@h2xmle_range       {0..50331648} // auto multiplied by 2 for 2S
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {33554432} */ // 2V

	int32_t switching_freq;
	/**< @h2xmle_description {in MHz.}
	@h2xmle_range       {20132659..80530636}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {40265318} */ // 2.4MHz

	int32_t boost_max_voltage;
	/**< @h2xmle_description {clip detect limiter threshold release time in msec}
	@h2xmle_range       {167772160..335544320} // 8-20V
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {192937984} */ //11.5V

	int32_t boost_inductor_muH;
	/**< @h2xmle_description {clip detect limiter threshold release time in msec}
	@h2xmle_range       {1677721..167772160}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */ //1muH

	int32_t efficiency_classD;
	/**< @h2xmle_description {ClassD efficiency}
	@h2xmle_range       {0..16777216}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {15770583} */ //0.94

	int32_t peak_power_per_channel;
	/**< @h2xmle_description {max amp power limit}
	@h2xmle_range       {16777216..251658240}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {134217728} */ //8W

	int32_t peak_power_per_pair;
	/**< @h2xmle_description {max amp power limit for two shared channels}
	@h2xmle_range       {16777216..251658240}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {201326592} */ //12W

	int32_t inductor_current_limit[SP_NILIM_DISCRETE];
	/**< @h2xmle_description {current limit for a specific Vph-range (x num stacks), 
	Vph_vec[] = { 2, 2.2, 2.5, 2.7, 3, 3.3, 3.7, 4, 4.2, 4.5, 5.0 };}
	@h2xmle_range       {0..117440512}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_defaultList     {16777,167772,1677722,21810381,33554432,41943040,53687091,60397978,67108864,67108864,67108864} */ //4A

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_ex_rx_cps_boostoperation_param_t param_id_spkr_prot_ex_rx_cps_boostoperation_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_EX_RX_CPS_BOOSTOPERATION_PARAM",
                         PARAM_ID_SPKR_PROT_EX_RX_CPS_BOOSTOPERATION_PARAM}
    @h2xmlp_description {Parameter used for setting parameters related to CPS3}
    @h2xmlp_toolPolicy  {CALIBRATION; RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// CPS version 3 param: construction without look-up tables.
struct param_id_spkr_prot_ex_rx_cps_boostoperation_param_t
{
	int32_t boost_limiter_attack_time_ms;
	/**< @h2xmle_description {clip detect limiter threshold attack time in msec}
	@h2xmle_range       {0..10}
	@h2xmle_default     {0} */

	int32_t boost_limiter_release_time_ms;
	/**< @h2xmle_description {clip detect limiter threshold release time in msec}
	@h2xmle_range       {0..20}
	@h2xmle_default     {1} */

	param_id_sp_cps_batttemp_param_t cps_batttemp_param;
	/**< @h2xmle_description {specifics to address low batt temp behavior}*/

	int32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */

#ifdef __H2XML__
	param_id_sp_cps_boostoperation_param_t cps3_param[0];
	/**< @h2xmle_description {structure containing speaker params for CPS3 in Rx-CPS block}
	@h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_SPEAKERS_LINK_MODE_PARAM 0x08001B52

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_speakers_link_mode_param_t param_id_sp_speakers_link_mode_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_SPEAKERS_LINK_MODE_PARAM",
                         PARAM_ID_SP_SPEAKERS_LINK_MODE_PARAM}
    @h2xmlp_description {parameter used to set the mode informing which speakers' gain to be linked.}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_speakers_link_mode_param_t
{
   uint32_t num_ch;
   /**< @h2xmle_description {Number of speaker channels}
   @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
   @h2xmle_default     {2} */


	uint32_t speakers_link_mode[0];
	/**< @h2xmle_description {mode indicating which channels to be gain linked}
	@h2xmle_rangeList   {"Unlink"=0;"Link_1"=1;"Link_2"=2;"Link_3"=3;"Link_4"=4}
	@h2xmle_defaultList {1,1,1,1,1,1,1,1}
	@h2xmle_variableArraySize  {num_ch} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PKT_PARAM 0x08001B53

/*==============================================================================
   Type definitions
==============================================================================*/
typedef struct sp_ex_rx_cps3_param_t sp_ex_rx_cps3_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_ex_rx_cps3_param_t
{
	// demo packet for CPS3: boost operation included.
	uint32_t BoostLimiterThr_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
	/**< @h2xmle_description {Boost limiter threshold in linear format, -\inftydB to 0dB; limit to -12dB or something similar
							  default is idb(0) in Q27 }
	@h2xmle_range       {0..134217728}
	@h2xmle_default     {134217728}
	@h2xmle_dataFormat  {Q27} */

	uint32_t DutyCycle_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
	/**< @h2xmle_description {Duty cycle}
	@h2xmle_range       {0..134217728}
	@h2xmle_default     {67108864}
	@h2xmle_dataFormat  {Q27} */

	// demo packet for CPS3: boost operation included.
	uint32_t inductorcurrent_rt_q27[MAX_CPS_BOOST_INDUCTOR_CURRENT_SAMPLES_IN_PACKET_48K];
	/**< @h2xmle_description {Boost inductor current }//
	@h2xmle_range       {0..2147483648}
	@h2xmle_default     {0}
	@h2xmle_dataFormat  {Q27} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_ex_rx_cps3_demo_pkt_param_t param_id_spkr_prot_ex_rx_cps3_demo_pkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PKT_PARAM",
                         PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PKT_PARAM}
    @h2xmlp_description {Parameter used for getting plots for cps2}
    @h2xmlp_toolPolicy  {RTM} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// CPS version 3 param: construction without look-up tables.
struct param_id_spkr_prot_ex_rx_cps3_demo_pkt_param_t
{
	uint32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */
	int32_t demo_out_valid;
	/**< @h2xmle_description {flag to indicate signals output contains meaningful data}
	@h2xmle_rangeList       {"Disable"=0; "Enable"=1}
	@h2xmle_default     {0} */
#ifdef __H2XML__
	// demo packet for CPS3
	sp_ex_rx_cps3_param_t ex_rx_cps3_demo_param[0];
	/**< @h2xmle_description {structure containing speaker params for CPS3 in Rx Excursion Control block}
	@h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_T0_CALI_PARAM 0x08001B54

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_t0_cali_param_t param_id_spkr_prot_t0_cali_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_T0_CALI_PARAM",
                         PARAM_ID_SPKR_PROT_T0_CALI_PARAM}
    @h2xmlp_description {parameter used to hold intial speaker temperature T0 (in degrees C).}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_t0_cali_param_t
{
   uint32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */

#ifdef __H2XML__
	int32_t t0_cali_q6[0];
	/**< @h2xmle_description {Rated speaker max temperature Tmax (in degrees C)}
	     @h2xmle_range       {-1920..12800}
	     @h2xmle_dataFormat  {Q6}
	     @h2xmle_default {-1920} 
		 @h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_EX_RX_BATTTEMP_DATA_PARAM 0x08001B55

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_ex_rx_batttemp_data_param_t param_id_spkr_prot_ex_rx_batttemp_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_EX_RX_BATTTEMP_DATA_PARAM",
                         PARAM_ID_SPKR_PROT_EX_RX_BATTTEMP_DATA_PARAM}
    @h2xmlp_description {parameter used to set CPS batt temp data in mC that needs to be fed into cps.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_ex_rx_batttemp_data_param_t
{
   int32_t batttemp_data;  // battery tem
	/**< @h2xmle_description {CPS batt temp data in mC that needs to be fed into cps}
	@h2xmle_range       {-20000..70000} //-20 to 70C.
	@h2xmle_default     {20} */ //20C
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PARAM 0x08001B56

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_ex_rx_cps3_demo_param_t param_id_spkr_prot_ex_rx_cps3_demo_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PARAM",
                         PARAM_ID_SPKR_PROT_EX_RX_CPS3_DEMO_PARAM}
    @h2xmlp_description {parameter used to set downsample ratio from internal values to output.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_ex_rx_cps3_demo_param_t
{
   uint16_t dsr; // downsample ratio from internal values to output
   /**< @h2xmle_description {down sampling ratio for cps demo params}
        @h2xmle_default     {10}  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_EX_RX_CPS2_DEMO_PKT_PARAM 0x08001B57

/*==============================================================================
   Type definitions
==============================================================================*/
typedef struct sp_ex_rx_cps2_param_t sp_ex_rx_cps2_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_ex_rx_cps2_param_t
{
   // demo packet for CPS2
   int32_t ClipSmthThr_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
   /**< @h2xmle_description {Clip detect threshold in linear format, -\inftydB to 0dB; limit to -12dB or something similar
                                                                  default is idb(0) in Q27 }
   @h2xmle_range       {0..134217728}
   @h2xmle_default     {134217728}
   @h2xmle_dataFormat  {Q27} */
   int32_t GainLow_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
   /**< @h2xmle_description {limiter threshold in linear format applied to the LF band of the crossover
                                              -\inftydB to 0dB; limit to -12dB or something similar, default is idb(0) in Q27}
   @h2xmle_range       {0..134217728}
   @h2xmle_default     {134217728}
   @h2xmle_dataFormat  {Q27} */
   int32_t GainHigh_rt_q27[SP_EX_RX_DEMO_SMPL_PER_PKT];
   /**< @h2xmle_description {limiter threshold linear applied to the HF band of the crossover
                                              -\inftydB to 0dB; limit to -12dB or something similar, default is idb(0) in Q27 }
   @h2xmle_range       {0..134217728}
   @h2xmle_default     {134217728}
   @h2xmle_dataFormat  {Q27} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_rx_cps2_demo_pkt_param_t param_id_sp_ex_rx_cps2_demo_pkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_RX_CPS2_DEMO_PKT_PARAM",
                         PARAM_ID_SP_EX_RX_CPS2_DEMO_PKT_PARAM}
    @h2xmlp_description {Parameter used for getting plots for cps2}
    @h2xmlp_toolPolicy  {RTM} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
// CPS version 2 param: construction without look-up tables.
struct param_id_sp_ex_rx_cps2_demo_pkt_param_t
{
   uint32_t frame_duration_in_ms;
   /**< @h2xmle_description {Frame duration in milliseconds for Excursion cps Rx
                                statistics.} */

   uint32_t frame_num;
   /**< @h2xmle_description {Frame number of the Excursion Rx statistics.} */

   uint32_t num_ch;
   /**< @h2xmle_description {Number of speaker channels}
   @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4}
   @h2xmle_default     {2} */
   int32_t demo_out_valid;
   /**< @h2xmle_description {flag to indicate signals output contains meaningful data}
   @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
   @h2xmle_default     {0} */
#ifdef __H2XML__
   // demo packet for CPS2
   sp_ex_rx_cps2_param_t ex_rx_cps2_demo_param[0];
   /**< @h2xmle_description {structure containing speaker params for CPS2 in Rx Excursion Control block}
   @h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SP_EX_RX_CPS2_DEMO_PARAM 0x08001B58

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_sp_ex_rx_cps2_demo_param_t param_id_sp_ex_rx_cps2_demo_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SP_EX_RX_CPS2_DEMO_PARAM",
                         PARAM_ID_SP_EX_RX_CPS2_DEMO_PARAM}
    @h2xmlp_description {parameter used to set downsample ratio from internal values to output.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sp_ex_rx_cps2_demo_param_t
{
   uint16_t dsr;               // downsample ratio from internal values to output
   /**< @h2xmle_description {down sampling ratio for cps demo params}
        @h2xmle_default     {10}  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_DYNAMIC_NOTCH_PARAM 0x08001B59

/*==============================================================================
   Type definitions
==============================================================================*/

typedef struct sp_dynamic_notch_param_t sp_dynamic_notch_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_dynamic_notch_param_t
{
	int32_t dyn_proc_type; // 0 disable, 1 shelving, 2 notch and 3 reserved
						   /**< @h2xmle_description {Dynamic processing feature indicator}
						   @h2xmle_rangeList       {"Disable"=0; "Notch filter"=1; "Bass boost"=2; "Notch filter with resonance tracking"=3}
						   @h2xmle_default     {0} */
	int32_t dyn_proc_fc_q20;
	/**< @h2xmle_description {Dynamic processing -- Parametric EQ filter frequency in Hz}
	@h2xmle_range       {104857600..2097152000}
	@h2xmle_dataFormat  {Q20}
	@h2xmle_default     {262144000} */
	int32_t dyn_proc_Q_q24;
	/**< @h2xmle_description {Dynamic processing -- Parametric EQ filter Q}
	@h2xmle_range       {1677721..1677721600}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {50331648} */
	int32_t dyn_proc_threshold_dBq23;
	/**< @h2xmle_description {Dynamic processing -- compression threshold in dB}
	@h2xmle_range       {-754974720..0}
	@h2xmle_dataFormat  {Q23}
	@h2xmle_default     {0} */
	int32_t dyn_proc_ratio_q24;
	/**< @h2xmle_description {Dynamic processing -- compression ratio}
	@h2xmle_range       {16777216 .. 1677721600}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */
	int32_t dyn_proc_makeup_gain_q27;
	/**< @h2xmle_description {Dynamic processing -- makeup gain in linear scale}
	@h2xmle_range       {8468566..2127207634}
	@h2xmle_dataFormat  {Q27}
	@h2xmle_default     {134217728} */
	int32_t dyn_proc_attack_time_ms;
	/**< @h2xmle_description {dynamic processing -- attach time in msec}
	@h2xmle_range       {0..1000}
	@h2xmle_default     {10} */
	int32_t dyn_proc_release_time_ms;
	/**< @h2xmle_description {dynamic processing -- release time in msec}
	@h2xmle_range       {0..1000}
	@h2xmle_default     {100} */
	int32_t dyn_proc_auto_release_flag;
	/**< @h2xmle_description {flag for automatic release time in dynamic processing}
	@h2xmle_rangeList       {"Disable"=0; "Enable"=1}
	@h2xmle_default     {1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_dynamic_notch_param_t param_id_spkr_prot_dynamic_notch_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_DYNAMIC_NOTCH_PARAM",
                         PARAM_ID_SPKR_PROT_DYNAMIC_NOTCH_PARAM}
    @h2xmlp_description {parameter used to configure per channel dynamic notch.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_dynamic_notch_param_t
{
	uint32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */
#ifdef __H2XML__
	sp_dynamic_notch_param_t dynamic_notch_param[0];
	/**< @h2xmle_description {Structure containing dynamic notch params}
	@h2xmle_variableArraySize  {num_ch}*/
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_LIN_RX_DYNAMIC_CFG 0x08001B5A

/*==============================================================================
   Type definitions
==============================================================================*/

typedef struct sp_lin_ex_common_ctrl_param_t sp_lin_ex_common_ctrl_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_lin_ex_common_ctrl_param_t
{
	// Ex Rx Ch 0 params
	int32_t amp_gain_q24;                        // Amplifier gain that will be used in scaling Tx vsense signal to rx signal
	/**< @h2xmle_description {speaker peak voltage for a digitally full-scale signal}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */
	int32_t trace_resistance_rx_q24;
	/**< @h2xmle_description {trace resistance from amp output to speakers in Ohm}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Re_ohm_q24;
	/**< @h2xmle_description {DC resistance of voice coil at room temperature or small signal level in Ohm}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {111394816} */
	int32_t Bl_q24;
	/**< @h2xmle_description {Force factor (Bl product)}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {19316736} */
	int32_t Mms_gram_q24;
	/**< @h2xmle_description {Ch 0: Mechanical mass of loudspeaker diaphragm in gram}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {2260992} */
	int32_t Rms_KgSec_q24;
	/**< @h2xmle_description {Mechanical damping or resistance of loudspeaker in Kg/sec}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {1843200} */
	int32_t Kms_Nmm_q24;
	/**< @h2xmle_description {Mechanical stiffness of driver suspension in N/mm}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {42573824} */
	int32_t Kms1_Nmm2_q24;
	/**< @h2xmle_description {Para-Suspension Stiffness}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Kms2_Nmm3_q24;
	/**< @h2xmle_description {Para-Suspension Stiffness}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Kms3_Nmm4_q24;
	/**< @h2xmle_description {Para-Suspension Stiffness}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Kms4_Nmm5_q24;
	/**< @h2xmle_description {Para-Suspension Stiffness}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Rms1_Kgm_q24;
	/**< @h2xmle_description {Para-Mechanical damping}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Rms2_Kgsm2_q24;
	/**< @h2xmle_description {Para-Mechanical damping}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Bl1_NAmm_q24;
	/**< @h2xmle_description {Force factor (Bl1)}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Bl2_NAmm2_q24;
	/**< @h2xmle_description {Force factor (Bl2)}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Bl3_NAmm3_q24;
	/**< @h2xmle_description {Force factor (Bl3)}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */
	int32_t Bl4_NAmm4_q24;
	/**< @h2xmle_description {Force factor (Bl4)}
	@h2xmle_range       {-2147483648..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct sp_lin_ctrl_param_t sp_lin_ctrl_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_lin_ctrl_param_t
{
	/* Rx lin/Ex common parameters*/
	sp_lin_ex_common_ctrl_param_t lin_ex_common_ctrl_param;

	int32_t input_gain_q24;
	/**< @h2xmle_description {linearization input gain to allow processing head room}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */
	int32_t max_amplitude_q24;
	/**< @h2xmle_description {amplitude limiter threshold in linear scale}
	@h2xmle_range       {0..2147483647}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {16777216} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_lin_rx_dynamic_cfg_t param_id_spkr_prot_lin_rx_dynamic_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_LIN_RX_DYNAMIC_CFG",
                         PARAM_ID_SPKR_PROT_LIN_RX_DYNAMIC_CFG}
    @h2xmlp_description {Linearization}
    @h2xmlp_toolPolicy  {Calibration;RTC} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_lin_rx_dynamic_cfg_t
{
	// LIN_RX common params
	int32_t link_all_channels_gain;
	/**< @h2xmle_description {Apply common gain to both channels}
	@h2xmle_rangeList       {"Unlinked"=0; "Linked"=1}
	@h2xmle_default     {0} */
	int32_t limiter_release_time_ms;
	/**< @h2xmle_description {limiter release time in msec}
	@h2xmle_range       {0..32767}
	@h2xmle_default     {100} */
	uint32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */
#ifdef __H2XML__
	/* Speaker-specific parameters */
	sp_lin_ctrl_param_t fbsp_lin_ctrl_param[0];
	/**< @h2xmle_description {structure containing speaker params for RX linearization block.}
	@h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/*==============================================================================
	 Constants
  ==============================================================================*/

  /* Unique Paramter id */
#define PARAM_ID_SPKR_PROT_CPSBASIC_CFG 0x08001B5B

/*==============================================================================
   Type definitions
==============================================================================*/

typedef struct sp_cps_basic_param_t sp_cps_basic_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_cps_basic_param_t 
{
	int32_t power_W_perchannel[N_VPH_RANGE];
	/**< @h2xmle_description {Power in W per channel in q24, we will use the same variable if SoC is chosen. use the first 20-21 entries here for SoC }
	@h2xmle_range       {0...2147483647} //0-14W
	@h2xmle_dataFormat  {Q24}
	//in W assuming 8 ohm loads: 0.0007176, 0.07176, 0.18025, 0.7176, 2.8568, 4.5277, 5.7001, 5.8328, 5.9687, 6.1077, 6.25, 6.3956, 6.5446, 6.6203, 6.697, 6.697, 6.7745, 6.9323, 7.0126, 7.176, 7.176, 7.176, 7.176, 7.176, 7.176}
	@h2xmle_defaultList {12039,1203933,3024093,12039330,47929151,75962201,95631809,97858145,100138169,102470202,104857600,107300363,109800168,111070203,112357016,112357016,113657250,116304694,117651905,120393302,120393302,120393302,120393302,120393302,120393302}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct sp_cpsbasic_ctrl_param_t sp_cpsbasic_ctrl_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_cpsbasic_ctrl_param_t {
	int32_t useSoC;
	/**< @h2xmle_description {enable/disable SoC as sense input to control CPS-basic.}
	@h2xmle_range       {0...1}
	@h2xmle_default     {0} */

	int32_t SoC_CV_mode;
	/**< @h2xmle_description {SoC that determines cconst voltage charging mode.}
	@h2xmle_range       {0...1677721600}
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {1342177280} */

	int32_t PowerW_CV_mode;
	/**< @h2xmle_description {PowerW for the CV mode; during tuning }
	@h2xmle_range       {0..134217728} //0 to 8W
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {117440512} 7W */

	int32_t low_batt_temperature_threshold;
	/**< @h2xmle_description {batt low temp threshold below which attenuation is applied due to increased series losses.}
	@h2xmle_range       {-671088640..335544320} //-40C to 20C
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */ //0C

	int32_t min_low_batt_temperature;
	/**< @h2xmle_description {batt minimum low temp threshold; below which no increases in attenuation are applied.}
	@h2xmle_range       {-671088640..0} //-40C to 0C
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {-671088640} */ //40C

	int32_t lowbatttemp_limthr_dB_slope;
	/**< @h2xmle_description {Attenuation applied as a function of low batt temp in dB/degrees C.}
	@h2xmle_range       {-671088640..0} //-40C to 0C
	@h2xmle_dataFormat  {Q24}
	@h2xmle_default     {0} */ //0dB/degrees C

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct sp_cps_basic_stereopower_param_t sp_cps_basic_stereopower_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */
struct sp_cps_basic_stereopower_param_t {
	int32_t power_W_perpair[N_VPH_RANGE];
	/**< @h2xmle_description {Power in W per channel in q24, we will use the same variable if SoC is chosen. use the first 20-21 entries here for SoC }
	@h2xmle_range       {0...2147483647} //0-14W
	@h2xmle_dataFormat  {Q24}
	//in W assuming 8 ohm loads: 0.0007    0.0718    0.1802    4.7176    6.8568    8.5277    9.7001    9.8328    9.9687   10.1077   10.2500   10.3956   10.5446   10.6203   10.6970 10.6970   10.7745   10.9323   11.0126   11.1760   11.1760   11.1760   11.1760   11.1760   11.1760}
	@h2xmle_defaultList {12039, 1203933, 3024093, 79148194, 115038015, 143071065, 162740673, 164967009, 167247033, 169579066, 171966464, 174409227, 176909032, 178179067, 179465880, 179465880, 180766114, 183413558, 184760769, 187502166, 187502166, 187502166, 187502166, 187502166, 187502166}*/

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/* Structure definition for Parameter */
typedef struct param_id_spkr_prot_cpsbasic_param_t param_id_spkr_prot_cpsbasic_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_SPKR_PROT_CPSBASIC_CFG",
						 PARAM_ID_SPKR_PROT_CPSBASIC_CFG}
	@h2xmlp_description {CPS}
	@h2xmlp_toolPolicy  {Calibration;RTC} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_spkr_prot_cpsbasic_param_t {
	sp_cpsbasic_ctrl_param_t fbsp_rx_cps_cpsbasic_ctrl_params;
	/**< @h2xmle_description {specifics to address low batt temp behavior and cps-basic operation}*/

	sp_cps_basic_stereopower_param_t fbsp_rx_cps_stereopower_params;
	/**< @h2xmle_description {specifics to address stereo power in connected channels.}*/

	int32_t num_ch;
	/**< @h2xmle_description {Number of speaker channels}
	@h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5;"6"=6;"7"=7;"8"=8}
	@h2xmle_default     {2} */

#ifdef __H2XML__
	sp_cps_basic_param_t cpsbasic_param[0];
	/**< @h2xmle_description {structure containing speaker params for CPS-basic in Rx-CPS block}
	@h2xmle_variableArraySize  {num_ch} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** @} <-- End of the Module --> */
#endif /* __SP_RX_H__ */
