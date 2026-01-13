#ifndef __WSA_HAPTICS_VI_API_H__
#define __WSA_HAPTICS_VI_API_H__

/*==============================================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause

  @file wsa_haptics_vi_api.h
  @brief This file contains APIs for Haptics Module
==============================================================================*/

/** @h2xml_title1           {Haptics}
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
#define HAPTICS_VI_MAX_INPUT_PORTS 1
#define HAPTICS_VI_MAX_OUTPUT_PORTS 1
#define HAPTICS_VI_STACK_SIZE 4096

/* Unique Module ID */
#define MODULE_ID_HAPTICS_VI 0x070010E5

/** @h2xmlm_module       {"MODULE_ID_HAPTICS_VI",
                          MODULE_ID_HAPTICS_VI}
    @h2xmlm_displayName  {"HAPTICS - VI"}
    @h2xmlm_toolPolicy   {Calibration;CALIBRATION}
    @h2xmlm_description  {ID of the HAPTICS VI module.\n
      this module includes VI Sens feedback data processing,
     Thermal tracking, LRA state tracking.

      This module supports the following parameter IDs:\n
     - #PARAM_ID_HAPTICS_VI_STATIC_CONFIG\n
     - #PARAM_ID_HAPTICS_VI_OP_MODE_PARAM\n
     - #PARAM_ID_HAPTICS_VI_EX_FTM_MODE_PARAM\n
     - #PARAM_ID_HAPTICS_TH_VI_R0T0_SET_PARAM\n
     - #PARAM_ID_HAPTICS_TH_VI_R0_GET_PARAM\n
     - #PARAM_ID_HAPTICS_TH_VI_DYNAMIC_PARAM\n
     - #PARAM_ID_HAPTICS_TH_VI_FTM_SET_CFG\n
     - #PARAM_ID_HAPTICS_TH_VI_FTM_GET_PARAM\n
     - #PARAM_ID_HAPTICS_EX_VI_DYNAMIC_PARAM\n
     - #PARAM_ID_HAPTICS_EX_VI_PERSISTENT\n
     - #PARAM_ID_HAPTICS_EX_VI_FTM_SET_CFG\n
     - #PARAM_ID_HAPTICS_EX_VI_FTM_GET\n
     - #PARAM_ID_HAPTICS_LRA_DIAG_GETPKT_PARAM\n
     - #PARAM_ID_HAPTICS_EX_VI_DEMO_PKT_PARAM\n
     - #PARAM_ID_HAPTICS_VI_CHANNEL_MAP_CFG\n
     - #PARAM_ID_HAPTICS_VI_FTM_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_VI_CALIB_DATA_PARAM\n
     - #PARAM_ID_HAPTICS_VI_CALIB_PARAM\n
     - #PARAM_ID_HAPTICS_VI_CALIB_PARAM_V2\n
     - #PARAM_ID_HAPTICS_VI_FTM_CFG\n
     - #PARAM_ID_HAPTICS_VI_TUNING_DATA_0_PARAM\n
     - #PARAM_ID_HAPTICS_VI_TUNING_DATA_1_PARAM\n
     - #PARAM_ID_HAPTICS_VI_TUNING_DATA_2_PARAM\n
     - #PARAM_ID_HAPTICS_VI_TUNING_DATA_3_PARAM\n
     - #PARAM_ID_HAPTICS_VI_TUNING_DATA_4_PARAM\n
     - #PARAM_ID_HAPTICS_LRA_SELECTION_PARAM\n

      All parameter IDs are device independent.\n

     Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 48000\n
*  - Number of channels   : 2, 4\n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 16 , 32 \n
*  - Q format             : 15 for bps = 16 and 27 for bps = 32\n
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

     @h2xmlm_toolPolicy              {Calibration}

    @h2xmlm_dataMaxInputPorts    {HAPTICS_VI_MAX_INPUT_PORTS}
     @h2xmlm_dataInputPorts       {IN=2}
     @h2xmlm_dataMaxOutputPorts   {HAPTICS_VI_MAX_OUTPUT_PORTS}
     @h2xmlm_dataOutputPorts      {OUT=1}
     @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
     @h2xmlm_isOffloadable       {false}
     @h2xmlm_stackSize            {HAPTICS_VI_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent  { "HAPTICS VI intent id for communicating Vsens and Isens data" = 0x0800136E, maxPorts=
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
/* Vsens from the left speaker. */
#define HAPTICS_VI_VSENS_LEFT_CHAN 1

/* Isens from the left speaker. */
#define HAPTICS_VI_ISENS_LEFT_CHAN 2

/* Vsens from the right speaker. */
#define HAPTICS_VI_VSENS_RIGHT_CHAN 3

/* Isens from the right speaker. */
#define HAPTICS_VI_ISENS_RIGHT_CHAN 4

/*==============================================================================
   Constants
==============================================================================*/

// Maximum output channels
#define HAPTICS_MAX_OUT_CHAN  (2)

// Maximum number of output channels
//#define HAPTICS_MAX_OUT_CHAN  (HAPTICS_MAX_OUT_CHAN)

#define MAX_SAMPLES_IN_PACKET 480

/*typedef enum haptics_vi_calib_state_t
{
    HAPTICS_VI_CALIB_STATE_INCORRECT_OP_MODE = 0, // returned if "operation_mode" is not "Thermal Calibration"
    HAPTICS_VI_CALIB_STATE_INACTIVE = 1, // init value
    HAPTICS_VI_CALIB_STATE_WARMUP = 2, // wait state for warmup
    HAPTICS_VI_CALIB_STATE_INPROGRESS = 3, // in calibration state
    HAPTICS_VI_CALIB_STATE_SUCCESS = 4, // calibration successful
    HAPTICS_VI_CALIB_STATE_FAILED = 5, // calibration failed
    HAPTICS_VI_CALIB_STATE_WAIT_FOR_VI = 6, // wait state for vi threshold
    HAPTICS_VI_CALIB_STATE_VI_WAIT_TIMED_OUT = 7, // calibration could not start due to vi signals below threshold
    HAPTICS_VI_CALIB_STATE_LOW_VI = 8, // calibration failed due to vi signals below threshold
    HAPTICS_VI_CALIB_STATE_MAX_VAL = 0xFFFFFFFF // // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} haptics_vi_calib_state_t;

// FTM support
typedef enum haptics_th_vi_ftm_state_t
{
   HAPTICS_TH_VI_FTM_STATE_INCORRECT_OP_MODE = 0, // returned if "operation_mode" is not "Thermal FTM"
   HAPTICS_TH_VI_FTM_STATE_INACTIVE          = 1, // init value
   HAPTICS_TH_VI_FTM_STATE_WARMUP            = 2, // wait state
   HAPTICS_TH_VI_FTM_STATE_INPROGRESS        = 3, // in FTM state
   HAPTICS_TH_VI_FTM_STATE_SUCCESS           = 4, // FTM successful
   HAPTICS_TH_VI_FTM_STATE_FAILED            = 5, // FTM failed
   HAPTICS_TH_VI_FTM_STATE_MAX_VAL = 0xFFFFFFFF // // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} haptics_th_vi_ftm_state_t;

// FTM support
typedef enum haptics_ex_vi_ftm_state_t
{
   HAPTICS_EX_VI_FTM_STATE_INCORRECT_OP_MODE = 0, // returned if "operation_mode" is not "FTM"
   HAPTICS_EX_VI_FTM_STATE_INACTIVE          = 1, // init value
   HAPTICS_EX_VI_FTM_STATE_WARMUP            = 2, // wait state
   HAPTICS_EX_VI_FTM_STATE_INPROGRESS        = 3, // in FTM state
   HAPTICS_EX_VI_FTM_STATE_SUCCESS           = 4, // FTM successful
   HAPTICS_EX_VI_FTM_STATE_FAILED            = 5, // FTM failed
   HAPTICS_EX_VI_FTM_STATE_MAX_VAL = 0xFFFFFFFF // // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} haptics_ex_vi_ftm_state_t;

// LRA diagnostics states in normal operation mode
typedef enum haptics_th_vi_lra_cond_t
{
    HAPTICS_TH_VI_LRA_COND_OK = 0,
    HAPTICS_TH_VI_LRA_COND_SHORT = 1,
    HAPTICS_TH_VI_LRA_COND_OPEN = 2,
    HAPTICS_TH_VI_LRA_COND_DC = 3,
    HAPTICS_TH_VI_LRA_COND_MAX_VAL = 0xFFFFFFFF // // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} haptics_th_vi_lra_cond_t;

// LRA temperature status in normal operation mode
typedef enum haptics_th_vi_lra_temperature_t
{
    HAPTICS_TEMPERATURE_OK = 0,
    HAPTICS_TEMPERATURE_ABOVE_MAX_LIMIT = 1,
    HAPTICS_TEMPERATURE_BELOW_MIN_LIMIT = 2,
    HAPTICS_TEMPERATURE_MAX_VAL = 0xFFFFFFFF // // max 32-bit unsigned value. tells the compiler to use 32-bit data type
} haptics_th_vi_lra_temperature_t;*/

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VI_STATIC_CONFIG 0x080013A4

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_static_config_t param_id_haptics_vi_static_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_STATIC_CONFIG",
                         PARAM_ID_HAPTICS_VI_STATIC_CONFIG}
    @h2xmlp_description {Parameter used to configure static parameters of VI processing.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_static_config_t {
   uint32_t num_channels;
   /**< @h2xmle_description {Number of channels for Rx signal.}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
   uint32_t sampling_rate;
   /**< @h2xmle_description {Sampling rate of VI signal.}
        @h2xmle_rangeList   {"8kHz"=8000;"16kHz"=16000;"48kHz"=48000}
        @h2xmle_default     {48000} */
   uint32_t fpilot_Hz;
   /**< @h2xmle_description {Pilot tone frequency, in Hz. Pilot tone frequency values MUST be the same for the RX/TH/EX modules}
        @h2xmle_rangeList   {"40"=40}
        @h2xmle_default     {40} */
   int32_t fpilot_amplitude_db;    // Pilot tone amplitude [-37] -37dB.
                                  // Note: Pilot tone amplitude values MUST be the same for the RX/TH/EX modules.
   /**< @h2xmle_description {Pilot tone amplitude relative to 0 dbFS (for example, -37 dB from the full scale), in dB. Pilot tone amplitude values MUST be the same for the RX/TH/EX modules}
        @h2xmle_range       {-40..-30} dB
        @h2xmle_default     {-37} */
   int32_t smoothing_time_const_q24;
    /**< @h2xmle_description {Smoothing time constant for f0 tracking parameter update. Default = 1.3, Range: 0 to 9.5}
         @h2xmle_range       {0..159383553}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {21810380} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VI_OP_MODE_PARAM 0x080013A5

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_op_mode_param_t param_id_haptics_vi_op_mode_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_OP_MODE_PARAM",
                    PARAM_ID_HAPTICS_VI_OP_MODE_PARAM}
    @h2xmlp_description {Parameter used to select the operation mode of WSA smart haptics VI processing.}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_op_mode_param_t {
   uint32_t th_operation_mode;   // normal running or calibration
   /**< @h2xmle_description {Operation mode of thermal VI module.}
        @h2xmle_rangeList   {"Normal Running mode"=0;
                             "Calibration mode"=1;
                             "Factory Test Mode"=2} */

   uint32_t th_r0t0_selection_flag[HAPTICS_MAX_OUT_CHAN]; // this flag determines which set of R0, T0 values the algorithm will use
                                                          // (0: use calibrated R0, T0 value, 1: use safe R0, T0 value)
    /**< @h2xmle_description {Specifies which set of R0, T0 values the algorithm will use. This field is valid only in
                              Normal mode (operation_mode = 0).}
         @h2xmle_rangeList   {"Use calibrated R0, T0 value"=0;"Use safe R0, T0 value"=1} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VI_EX_FTM_MODE_PARAM 0x080013A6

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_ex_FTM_mode_param_t param_id_haptics_vi_ex_FTM_mode_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_EX_FTM_MODE_PARAM",
                    PARAM_ID_HAPTICS_VI_EX_FTM_MODE_PARAM}
    */

struct param_id_haptics_vi_ex_FTM_mode_param_t {
  uint32_t ex_FTM_mode_enable_flag;
   /**< @h2xmle_description {Factory Test Mode enablement flag. When enabled, the estimated lra parameters are averaged
                             and pushed out to HAL for parameter display and saving into audio.cal}
        @h2xmle_rangeList        {"disabled"=0; "enabled"=1}
        @h2xmle_default          {0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_TH_VI_R0T0_SET_PARAM 0x080013A7

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_th_vi_r0t0_set_param_t param_id_haptics_th_vi_r0t0_set_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_TH_VI_R0T0_SET_PARAM",
                    PARAM_ID_HAPTICS_TH_VI_R0T0_SET_PARAM}
    @h2xmlp_description {Parameter used to configure static R0T0 parameters of thermal VI processing}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_th_vi_r0t0_set_param_t {
   uint32_t num_channels;
    /**< @h2xmle_description {Number of channels for Rx signal.}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
    int32_t r0_cali_q24[HAPTICS_MAX_OUT_CHAN];           // calibration point resistance (in ohm), per device
    /**< @h2xmle_description {Calibration point resistance per device (in Ohms).  This field is valid only  in Normal mode (operation_mode = 0). Default = 8Ohms, Range: 2 to 64Ohms}
         @h2xmle_range       {33554432..1073741824}
         @h2xmle_default     {134217728}
         @h2xmle_dataFormat  {Q24} */
    int32_t t0_cali_q6[HAPTICS_MAX_OUT_CHAN];            // caliberation point Temp (deg C), per device
    /**< @h2xmle_description {Calibration point temperature per device (in degrees C). This field is valid in both Normal mode and Calibration mode. Default = 25 deg C, Range: -30 to 80 deg C.}
         @h2xmle_range       {-1920..5120}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {1600} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
/* TBD:
 * This param is associated with EVENT_ID_HAPTICS_VI_CALIBRATION
 * If there is no need of GET and SET support for this param from HLOS
 * Then, there is no need to allocate param ID for this structure.
 * Just having structure definition is enough */
#define PARAM_ID_HAPTICS_VI_CALIB_PARAM 0x08001ADD

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_calib_param_t param_id_haptics_vi_calib_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_CALIB_PARAM",
                    PARAM_ID_HAPTICS_VI_CALIB_PARAM}
    */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_calib_param_t {
    uint32_t state; // Calibration/FTM state    
    /**< @h2xmle_description {Calibration/FTM state}
        @h2xmle_range       {0...8}
        @h2xmle_default     {0} */
    uint32_t operation_mode;        // Calibration or FTM
    /**< @h2xmle_description {Operation mode in which parameters were estimated.}
         @h2xmle_rangeList   {"Normal mode"=0;
                              "Calibration mode"=1;
                              "Factory Test Mode"=2} */
    int32_t Re_ohm_q24[HAPTICS_MAX_OUT_CHAN];   // LRA resistance from Calibration/FTM
    /**< @h2xmle_description {DC resistance of LRA coil estimated during calibration/FTM mode, in Ohms. Default = 8Ohm, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Fres_Hz_q20[HAPTICS_MAX_OUT_CHAN];  // Resonance frequency from Calibration/FTM
    /**< @h2xmle_description {Resonance frequency of LRA estimated during calibration/FTM mode, in Hz. Default = 160Hz, Range = 50 to 400Hz}
        @h2xmle_range       {52428800..419430400}
        @h2xmle_dataFormat  {Q20}
        @h2xmle_default     {167772160} */
    int32_t Bl_q24[HAPTICS_MAX_OUT_CHAN]; // Force factor (Bl) from Calibration/FTM
    /**< @h2xmle_description {Force factor (Bl product) estimated during calibration/FTM mode. Default = 1, Range: 0.01 to 128}
         @h2xmle_range       {167772..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Rms_KgSec_q24[HAPTICS_MAX_OUT_CHAN]; // Mechanical damping from Calibration/FTM
    /**< @h2xmle_description {Mechanical damping of LRA, estimated during calibration/FTM mode, in kg/s. Default = 0.0945kg/s, Range = 0.0001 to 20kg/s}
         @h2xmle_range       {16777..335544320}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1585446} */
    int32_t Blq_ftm_q24[HAPTICS_MAX_OUT_CHAN];      // Non-linearity estimate for Bl (normalized value) from FTM
    /**< @h2xmle_description {Non-linearity estimate for Bl (normalized value) estimated during FTM mode. Default = 0, Range: 0 to 1}
         @h2xmle_range       {0..16777216}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t Le_mH_ftm_q24[HAPTICS_MAX_OUT_CHAN];    // LRA inductance from FTM
    /**< @h2xmle_description {Inductance of LRA coil at room temperature estimated during FTM mode, in mH. Default = 0.04mH, Range: 0.001mH to 128mH}
         @h2xmle_range       {16777..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {671088} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
/* TBD:
 * This param is associated with EVENT_ID_HAPTICS_VI_CALIBRATION
 * If there is no need of GET and SET support for this param from HLOS
 * Then, there is no need to allocate param ID for this structure.
 * Just having structure definition is enough */
#define PARAM_ID_HAPTICS_VI_CALIB_PARAM_V2 0x08001B24

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_calib_param_v2_t param_id_haptics_vi_calib_param_v2_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_CALIB_PARAM_V2",
                    PARAM_ID_HAPTICS_VI_CALIB_PARAM_V2}
    */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_calib_param_v2_t {
    uint32_t state; // Calibration/FTM state    
    /**< @h2xmle_description {Calibration/FTM state}
        @h2xmle_range       {0...8}
        @h2xmle_default     {0} */
    uint32_t operation_mode;        // Calibration or FTM
    /**< @h2xmle_description {Operation mode in which parameters were estimated.}
         @h2xmle_rangeList   {"Normal mode"=0;
                              "Calibration mode"=1;
                              "Factory Test Mode"=2} */
    int32_t Re_ohm_q24[HAPTICS_MAX_OUT_CHAN];   // LRA resistance from Calibration/FTM
    /**< @h2xmle_description {DC resistance of LRA coil estimated during calibration/FTM mode, in Ohms. Default = 8Ohm, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t Fres_Hz_q20[HAPTICS_MAX_OUT_CHAN];  // Resonance frequency from Calibration/FTM
    /**< @h2xmle_description {Resonance frequency of LRA estimated during calibration/FTM mode, in Hz. Default = 160Hz, Range = 50 to 400Hz}
        @h2xmle_range       {52428800..419430400}
        @h2xmle_dataFormat  {Q20}
        @h2xmle_default     {167772160} */
    int32_t Bl_q24[HAPTICS_MAX_OUT_CHAN]; // Force factor (Bl) from Calibration/FTM
    /**< @h2xmle_description {Force factor (Bl product) estimated during calibration/FTM mode. Default = 1, Range: 0.01 to 128}
         @h2xmle_range       {167772..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777216} */
    int32_t Rms_KgSec_q24[HAPTICS_MAX_OUT_CHAN]; // Mechanical damping from Calibration/FTM
    /**< @h2xmle_description {Mechanical damping of LRA, estimated during calibration/FTM mode, in kg/s. Default = 0.0945kg/s, Range = 0.0001 to 20kg/s}
         @h2xmle_range       {16777..335544320}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1585446} */
    int32_t Blq_ftm_q24[HAPTICS_MAX_OUT_CHAN];      // Non-linearity estimate for Bl (normalized value) from FTM
    /**< @h2xmle_description {Non-linearity estimate for Bl (normalized value) estimated during FTM mode. Default = 0, Range: 0 to 1}
         @h2xmle_range       {0..16777216}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t Le_mH_ftm_q24[HAPTICS_MAX_OUT_CHAN];    // LRA inductance from FTM
    /**< @h2xmle_description {Inductance of LRA coil at room temperature estimated during FTM mode, in mH. Default = 0.04mH, Range: 0.001mH to 128mH}
         @h2xmle_range       {16777..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {671088} */
    int32_t Fres_offset_Hz_q20[HAPTICS_MAX_OUT_CHAN];      // F0 offset from duffing non linerity
    /**< @h2xmle_description {F0 offset from duffing non linerity (in Hz). Default = 0, Range: 0 to 100}
         @h2xmle_range       {0..0x64}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {0} */
    int32_t Tuned_LRA_ID[HAPTICS_MAX_OUT_CHAN];    // ID of LRA selected during FTM
    /**< @h2xmle_description {ID of LRA selected during FTM. Default = 0, Range: 0 to 4}
         @h2xmle_range       {0..4}
         @h2xmle_default     {0} */
    uint32_t payload_size; // Custom payload size in bytes, returned from FTM.
    /**< @h2xmle_description {Custom payload size in bytes, returned from FTM.}
        @h2xmle_range       {0...10240}
        @h2xmle_default     {0} */
#ifdef __H2XML__
    uint8_t payload_data[0];
    /**< @h2xmle_description      {Custom payload data, returned from FTM.}
         @h2xmle_variableArraySize {payload_size} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
  ==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VI_FTM_CFG 0x08001B1D

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_ftm_cfg_t param_id_haptics_vi_ftm_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_FTM_CFG",
                         PARAM_ID_HAPTICS_VI_FTM_CFG}
    @h2xmlp_description {Parameter to set FTM configuration}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_vi_ftm_cfg_t {
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
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_TH_VI_R0_GET_PARAM 0x080013A8

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_th_vi_r0_get_param_t param_id_haptics_th_vi_r0_get_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_TH_VI_R0_GET_PARAM",
                    PARAM_ID_HAPTICS_TH_VI_R0_GET_PARAM}
    */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_th_vi_r0_get_param_t {
  uint32_t state; // calibration state
   /**< @h2xmle_description {Calibration state}
        @h2xmle_range       {0...8} */
   int32_t r0_cali_q24[HAPTICS_MAX_OUT_CHAN]; // calibration point resistance (in ohm), per device
   /**< @h2xmle_description {Calibration point resistance per device (in Ohms). Default = 8Ohms, Range: 2 to 64Ohms}
         @h2xmle_range       {33554432..1073741824}
         @h2xmle_default     {134217728}
         @h2xmle_dataFormat  {Q24} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_TH_VI_DYNAMIC_PARAM 0x080013A9

/*==============================================================================
   Type definitions
==============================================================================*/

// Structure encapsulating LRA parameters for Thermal VI module
typedef struct wsa_haptics_th_lra_param_t wsa_haptics_th_lra_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */

struct wsa_haptics_th_lra_param_t
{
    int32_t r0_safe_q24;    // backup calibration point resistance (ohm), when per device calibration is not available
    /**< @h2xmle_description {backup calibration point resistance when per-device calibration is not available (in
                              Ohms.) Default = 8Ohms, Range: 2 to 64Ohms}
         @h2xmle_range       {33554432..1073741824}
         @h2xmle_default     {134217728}
         @h2xmle_dataFormat  {Q24} */
    int32_t t0_safe_q6; // backup caliberation point Temp (deg C), when per device calibration is not available
    /**< @h2xmle_description {backup calibration point temperature when per-device calibration is not available (in
                              degrees C). Default = 25 deg C, Range: -30 to 80 deg C.}
         @h2xmle_range       {-1920..5120}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {1600} */
    int16_t amp_gain_q10;   // LRA peak voltage for digitially full scale signal
    /**< @h2xmle_description {voltage for digitally full scale signal. Default = 10, Range: 0 to 32}
         @h2xmle_range       {0..32767}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {10240} */
    uint16_t lra_resistivity_coeff_u16q7;   // resistivity coeff (1/deg C)
    /**< @h2xmle_description {one over temperature coeffcient alpha in 1/deg C. Default = 254.45, Range: 0 to 511.99}
         @h2xmle_range       {0..65535}
         @h2xmle_dataFormat  {Q7}
         @h2xmle_default     {32570} */
    uint16_t vsen_2_v_u16q11;   // conversion factor from Vsen digital to Volt
    /**< @h2xmle_description {conversion factor from Vsens digital to Volts. Default = 10.48, Range: 0 to 31.99}
         @h2xmle_range       {0..65535}
         @h2xmle_dataFormat  {Q11}
         @h2xmle_default     {21466} */
    uint16_t isen_2_a_u16q11;   // conversion factor from Isen digital to Amp
    /**< @h2xmle_description {conversion factor from Isens digital to Amps. Default = 6.90, Range: 0 to 31.99}
         @h2xmle_range       {0..65535}
         @h2xmle_dataFormat  {Q11}
         @h2xmle_default     {14143} */
    int32_t trace_resistance_tx_q24;
    /**< @h2xmle_description {trace resistance from LRA to Vsens tap points in Ohm. Default = 0, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t Re_ohm_q24;
    /**< @h2xmle_description {DC resistance of LRA coil at room temperature, in Ohms. Default = 8Ohms, Range: 2 to 128Ohms}
         @h2xmle_range       {33554432..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {134217728} */
    int32_t r_lra_coil_factor_q10;
    /**< @h2xmle_description {factor used to determine the threshold
                              for LRA coil resistance (max threshold for LRA
                              coil resistance = factor * LRA coil resistance and min threshold = LRA coil resistance/ factor). Default = 2, Range: 1 to 8}
         @h2xmle_range       {1024..8192}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {2048} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure encapsulating LRA parameters for R0T0 calibration*/
typedef struct wsa_haptics_r0t0_cali_param_t wsa_haptics_r0t0_cali_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */

struct wsa_haptics_r0t0_cali_param_t
{
    int32_t wait_time_ms;   // wait time for initial settling before collecting statistic (ms)
    /**< @h2xmle_description {wait time for initial settling before
         collecting statistics (in milli seconds).}
         @h2xmle_range       {100..5000}
         @h2xmle_default     {200} */
    int32_t cali_time_ms;   // calibration time (ms)
    /**< @h2xmle_description {calibration time  (in milli seconds).}
         @h2xmle_range       {500..30000}
         @h2xmle_default     {2000} */
    int32_t vi_wait_time_ms;                 // wait time to check if VI are above threshold levels
    /**< @h2xmle_description {wait time for vi (in milli seconds).}
         @h2xmle_range       {100..30000}
         @h2xmle_default     {2000} */
    int16_t r0_rng_fac_q10;
    /**< @h2xmle_description {If the calibrated R0 is greater than range factor times the typical value, or less than the      typical value divided by the range factor, calibration failed will be called. Default = 1.5, Range: 1 to 8}
         @h2xmle_range       {1024..8192}
         @h2xmle_dataFormat  {Q10}
         @h2xmle_default     {1536} */
    int16_t t0_min_q6;  // min expected temperature from calibration (deg C)
    /**< @h2xmle_description {minimum expected temperature from
                              calibration (in degrees C). Default = 0 deg C, Range: -30 to 80 deg C}
         @h2xmle_range       {-1920..5120}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {0} */
    int16_t t0_max_q6;  // max expected temperature from calibration (deg C)
    /**< @h2xmle_description {maximum expected temperature from
                              calibration (in degrees C). Default = 50 deg C, Range: -30 to 80 deg C}
         @h2xmle_range       {-1920..5120}
         @h2xmle_dataFormat  {Q6}
         @h2xmle_default     {3200} */
    uint16_t reserved;
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_th_vi_dynamic_param_t param_id_haptics_th_vi_dynamic_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_TH_VI_DYNAMIC_PARAM",
                    PARAM_ID_HAPTICS_TH_VI_DYNAMIC_PARAM}
    @h2xmlp_description {Parameter used to configure dynamic thermal parameters for WSA smart haptics VI processing.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_th_vi_dynamic_param_t {
    uint32_t num_channels;
   /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
   int32_t temp_min_q6;
   /**< @h2xmle_description {Minimum reasonable measured temperature (in degree C). Default = -30 deg C, Range: -30 to 200 deg C}
       @h2xmle_range       {-1920..12800}
       @h2xmle_dataFormat  {Q6}
       @h2xmle_default     {-1920} */
   int32_t temp_max_q6;
   /**< @h2xmle_description {Maximum reasonable measured temperature (in degree C). Default = 200 deg C, Range: -30 to 80 deg C}
       @h2xmle_range       {-1920..12800}
       @h2xmle_dataFormat  {Q6}
       @h2xmle_default     {12800} */
#ifdef __H2XML__
   wsa_haptics_th_lra_param_t wsa_haptics_th_lra_param[0];
   /**< @h2xmle_description {Structure encapsulating LRA parameters for Thermal VI module.}
        @h2xmle_variableArraySize  {num_channels} */
   wsa_haptics_r0t0_cali_param_t wsa_haptics_r0t0_cali_param[0];
   /**< @h2xmle_description {Structure encapsulating LRA parameters for R0T0 calibration.}
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
#define PARAM_ID_HAPTICS_TH_VI_FTM_SET_CFG 0x080013AA

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_th_vi_ftm_set_cfg param_id_haptics_th_vi_ftm_set_cfg;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_TH_VI_FTM_SET_CFG",
                   PARAM_ID_HAPTICS_TH_VI_FTM_SET_CFG}
    @h2xmlp_description {Parameter used to set the FTM configuration in the WSA smart haptics thermal VI processing module.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_th_vi_ftm_set_cfg {
  uint32_t num_channels;
   /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
   int32_t wait_time_ms[HAPTICS_MAX_OUT_CHAN]; // wait time before collecting statistics for ftm mode (ms)
   /**< @h2xmle_description {wait time before collecting statistics for ftm mode (ms)}
        @h2xmle_range       {100..5000}
        @h2xmle_dataFormat  {Q0}
        @h2xmle_default     {2000} */
   int32_t ftm_time_ms[HAPTICS_MAX_OUT_CHAN];  // duration that ftm packets will be averaged
   /**< @h2xmle_description {duration that ftm packets will be averaged, in ms}
        @h2xmle_range       {100..5000}
        @h2xmle_dataFormat  {Q0}
        @h2xmle_default     {2000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_TH_VI_FTM_GET_PARAM 0x080013AB

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_th_vi_ftm_get_param_t param_id_haptics_th_vi_ftm_get_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_TH_VI_FTM_GET_PARAM",
                    PARAM_ID_HAPTICS_TH_VI_FTM_GET_PARAM}
    @h2xmlp_description {Thermal VI FTM mode parameters returned from WSA Smart haptics thermal FTM mode}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_th_vi_ftm_get_param_t {
   uint32_t num_channels;
   /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
   int32_t                ftm_rDC_q24[HAPTICS_MAX_OUT_CHAN];  // rDC value in q24
   /**< @h2xmle_description {resistance in ohm}
        @h2xmle_range       {0..2147483647}
        @h2xmle_dataFormat  {Q24}
        @h2xmle_default     {0} */
   int32_t                ftm_temp_q22[HAPTICS_MAX_OUT_CHAN]; // temperature value in q22
   /**< @h2xmle_description {temperature in degree C}
        @h2xmle_range       {0..2147483647}
        @h2xmle_dataFormat  {Q22}
        @h2xmle_default     {0} */
   uint32_t status[HAPTICS_MAX_OUT_CHAN];       // wait, in progress or success
   /**< @h2xmle_description {wait, in progress or success}
        @h2xmle_range       {0..5} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_VI_DYNAMIC_PARAM 0x080013AC

/*==============================================================================
   Type definitions
==============================================================================*/

// Structure encapsulating LRA parameters for VI excursion module
typedef struct wsa_haptics_ex_lra_param_t wsa_haptics_ex_lra_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */

struct wsa_haptics_ex_lra_param_t
{
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
    int32_t amp_gain_q24;
    /**< @h2xmle_description {LRA peak voltage for a digitally full-scale signal. Default = 10, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {167772160} */
    int32_t vsens_scale_q24; // Vsense scaling constant
    /**< @h2xmle_description {conversion factor from Vsens digital to Volts. Default = 10.48, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {175849472} */
    int32_t isens_scale_q24; // Isense scaling constant
    /**< @h2xmle_description {conversion factor from Isens digital to Amperes. Default = 6.90, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {115859456} */
    int32_t trace_resistance_tx_q24;
    /**< @h2xmle_description {trace resistance from LRA to Vsens tap points in Ohm. Default = 0Ohm, Range: 0 to 128Ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t trace_resistance_rx_q24;
    /**< @h2xmle_description {trace resistance from amp output to LRA in Ohm. Default = 0Ohm, Range: 0 to 128Ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t Min_Bl_q24;
    /**< @h2xmle_description {Force factor (Bl product) - Min limit. Default = 0.01, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {167772} */
    int32_t Max_Bl_q24;
    /**< @h2xmle_description {Force factor (Bl product) - Max limit. Default = 10, Range: 0 to 128}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {167772160} */
    int32_t Min_Rms_KgSec_q24;
    /**< @h2xmle_description {Mechanical damping or resistance of LRA in Kg/sec - Min limit. Default = 0.001Kg/sec, Range: 0 to 128Kg/sec}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {16777} */
    int32_t Max_Rms_KgSec_q24;
    /**< @h2xmle_description {Mechanical damping or resistance of LRA in Kg/sec - Max limit. Default = 20Kg/sec, Range: 0 to 128Kg/sec}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {335544320} */
    int32_t Min_Kms_Nmm_q24;
    /**< @h2xmle_description {Mechanical stiffness of driver suspension in N/mm - Min limit. Default = 0.1N/mm, Range: 0 to 128N/mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {1677721} */
    int32_t Max_Kms_Nmm_q24;
    /**< @h2xmle_description {Mechanical stiffness of driver suspension in N/mm - Max limit. Default = 50N/mm, Range: 0 to 128N/mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {838860800} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_vi_dynamic_param_t param_id_haptics_ex_vi_dynamic_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_VI_DYNAMIC_PARAM",
                    PARAM_ID_HAPTICS_EX_VI_DYNAMIC_PARAM}
    @h2xmlp_description {Parameter used to configure the dynamic parameters of excursion VI processing.}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_vi_dynamic_param_t {
   uint32_t num_channels;
   /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
#ifdef __H2XML__
   wsa_haptics_ex_lra_param_t wsa_haptics_ex_lra_param[0];
   /**< @h2xmle_description {Structure encapsulating LRA parameters for VI excursion module}
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
#define PARAM_ID_HAPTICS_EX_VI_PERSISTENT 0x080013AD

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_vi_persistent param_id_haptics_ex_vi_persistent;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_VI_PERSISTENT",
                    PARAM_ID_HAPTICS_EX_VI_PERSISTENT}
    @h2xmlp_description {Excursion VI persistent parameters}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_vi_persistent {
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
#define PARAM_ID_HAPTICS_EX_VI_FTM_SET_CFG 0x080013AE

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_vi_ftm_set_cfg param_id_haptics_ex_vi_ftm_set_cfg;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_VI_FTM_SET_CFG",
                    PARAM_ID_HAPTICS_EX_VI_FTM_SET_CFG}
    @h2xmlp_description {Excursion VI FTM mode parameters}
    @h2xmlp_toolPolicy  {CALIBRATION;RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_vi_ftm_set_cfg {
   uint32_t num_channels;
   /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
   int32_t wait_time_ms[HAPTICS_MAX_OUT_CHAN];
   /**< @h2xmle_description {wait time before collecting statistics for ftm mode, in ms}
        @h2xmle_range       {100..5000}
        @h2xmle_dataFormat  {Q0}
        @h2xmle_default     {2000} */
   int32_t ftm_time_ms[HAPTICS_MAX_OUT_CHAN];
   /**< @h2xmle_description {duration that ftm packets will be averaged, in ms}
        @h2xmle_range       {100..5000}
        @h2xmle_dataFormat  {Q0}
        @h2xmle_default     {1000} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_VI_FTM_GET 0x080013AF

/*==============================================================================
   Type definitions
==============================================================================*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/** @h2xmlp_subStruct */

typedef struct wsa_ex_vi_ftm_get_param_t wsa_ex_vi_ftm_get_param_t;

struct wsa_ex_vi_ftm_get_param_t {
   int32_t                ftm_Re_q24;
    /**< @h2xmle_description {ftm resitance in ohm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t                ftm_Bl_q24;
    /**< @h2xmle_description {force factor (Bl_product)}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t                ftm_Rms_q24;
    /**< @h2xmle_description {resitance due to mechanical damping, Kg/sec}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t                ftm_Kms_q24;
    /**< @h2xmle_description {suspension stiffness, in N/mm}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q24}
         @h2xmle_default     {0} */
    int32_t                ftm_Fres_q20;
    /**< @h2xmle_description {resonant frequency in Hz}
         @h2xmle_range       {0..2147483647}
         @h2xmle_dataFormat  {Q20}
         @h2xmle_default     {0} */
    uint32_t status; // FTM packet status
    /**< @h2xmle_description {FTM packet status}
         @h2xmle_range       {0...5} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_vi_ftm_get param_id_haptics_ex_vi_ftm_get;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_VI_FTM_GET",
                    PARAM_ID_HAPTICS_EX_VI_FTM_GET}
    @h2xmlp_description {Excursion VI FTM mode parameters returned from WSA Smart haptics excursion FTM mode}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_vi_ftm_get {
    uint32_t                 num_channels;
    /**< @h2xmle_description {Number of LRA channels}
         @h2xmle_rangeList   {"1"=1;"2"=2}
         @h2xmle_default     {1} */
#ifdef __H2XML__
    wsa_ex_vi_ftm_get_param_t wsa_ex_vi_ftm_get_param[0];
    /**< @h2xmle_description {structure containing LRA params for FTM }
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
#define PARAM_ID_HAPTICS_LRA_DIAG_GETPKT_PARAM 0x080013B0

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_lra_diag_getpkt_param_t param_id_haptics_lra_diag_getpkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_LRA_DIAG_GETPKT_PARAM",
                    PARAM_ID_HAPTICS_LRA_DIAG_GETPKT_PARAM}
    @h2xmlp_description {Parameter used to get general LRA diagnostics like whether LRA is open, or close or if DC is flowing through it.}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/
// General LRA Diagnostics

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_lra_diag_getpkt_param_t {
    uint32_t num_channels;
    /**< @h2xmle_description {Number of LRA channels}
        @h2xmle_rangeList   {"1"=1;"2"=2}
        @h2xmle_default     {1} */
    uint32_t lra_cond[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {reflects LRA general diagnostics - OK, Short, Open, DC}
         @h2xmle_range       {0...3}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */
    uint32_t temperature_status[HAPTICS_MAX_OUT_CHAN];
    /**< @h2xmle_description {reflects LRA temperature status - OK, above max limit, below min limit}
         @h2xmle_range       {0...2}
         @h2xmle_dataFormat  {Q0}
         @h2xmle_default     {0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_EX_VI_DEMO_PKT_PARAM 0x080013B1

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_ex_vi_demo_pkt_param_t param_id_haptics_ex_vi_demo_pkt_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_EX_VI_DEMO_PKT_PARAM",
                    PARAM_ID_HAPTICS_EX_VI_DEMO_PKT_PARAM}
    @h2xmlp_description {Parameter used to get general LRA diagnostics like whether LRA is open, or close or if DC is flowing through it.}
    @h2xmlp_toolPolicy  {RTC_READONLY}*/
// General LRA Diagnostics

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_ex_vi_demo_pkt_param_t
{
    uint32_t num_channels;
    /**< @h2xmle_description {Number of LRA channels}
    @h2xmle_rangeList   {"1"=1;"2"=2}
    @h2xmle_default     {1} */
#ifdef __H2XML__
    int32_t xpred_from_vsens[0][MAX_SAMPLES_IN_PACKET];
    /**< @h2xmle_description        {structure containing LRA params for excursion prediction }
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
#define PARAM_ID_HAPTICS_VI_FTM_DATA_PARAM 0x08001ADC

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_ftm_data_param_t param_id_haptics_vi_ftm_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_FTM_DATA_PARAM", PARAM_ID_HAPTICS_VI_FTM_DATA_PARAM}
    @h2xmlp_description {Parameter for registering haptics ftm data to lib.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_ftm_data_param_t {
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
#define PARAM_ID_HAPTICS_VI_CALIB_DATA_PARAM 0x08001ADB

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_calib_data_param_t param_id_haptics_vi_calib_data_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_CALIB_DATA_PARAM", PARAM_ID_HAPTICS_VI_CALIB_DATA_PARAM}
    @h2xmlp_description {Parameter for registering haptics calibration data to lib.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_calib_data_param_t {
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
#define PARAM_ID_HAPTICS_VI_CHANNEL_MAP_CFG 0x080013BE

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_channel_map_cfg_t param_id_haptics_vi_channel_map_cfg_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_CHANNEL_MAP_CFG",
                         PARAM_ID_HAPTICS_VI_CHANNEL_MAP_CFG}
    @h2xmlp_description {parameter used to set the input channel mapping for Vsens and Isens
                         for the Haptics VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION, RTC_READONLY} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_haptics_vi_channel_map_cfg_t
{
   uint32_t num_ch;
   /**< @h2xmle_description {Number of channels for Tx signal.}
        @h2xmle_rangeList   {"Two" = 2; "Four" = 4}
        @h2xmle_default     {2} */

   int32_t chan_info[0];
   /**< @h2xmle_description {Channel mapping array that provides information
                             on the order in which the Vsens and Isens of
                             different LRA come into a Tx port.
                             - HAPTICS_VI_VSENS_LEFT_CHAN(1)
                             - HAPTICS_VI_ISENS_LEFT_CHAN(2)
                             - HAPTICS_VI_VSENS_RIGHT_CHAN(3)
                             - HAPTICS_VI_ISENS_RIGHT_CHAN(4)
                      Some possible configurations are (1,2,3,4), (4,2,1,3),
                      (1,2,0,0),(4,3,0,0), and (2,1,0,0).
                      All channels must be unique. The order does not matter
                      as long as the channels are valid.
                      If only two channels are sent (V and I), they must be
                             first two channels: Eg: (4,3), (1,2), etc.}
       @h2xmle_variableArraySize  {num_ch} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
     Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_HAPTICS_VI_TUNING_DATA_0_PARAM 0x08001B1E

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_tuning_data_0_param_t param_id_haptics_vi_tuning_data_0_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_TUNING_DATA_0_PARAM", PARAM_ID_HAPTICS_VI_TUNING_DATA_0_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 0 to VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_tuning_data_0_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for VI module tuning data file for LRA 0}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of VI module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the VI module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {VI module tuning data for LRA 0: path to the VI module tuning binary file.}
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
#define PARAM_ID_HAPTICS_VI_TUNING_DATA_1_PARAM 0x08001B1F

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_tuning_data_1_param_t param_id_haptics_vi_tuning_data_1_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_TUNING_DATA_1_PARAM", PARAM_ID_HAPTICS_VI_TUNING_DATA_1_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 1 to VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_tuning_data_1_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for VI module tuning data file for LRA 1}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of VI module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the VI module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {VI module tuning data for LRA 1: path to the VI module tuning binary file.}
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
#define PARAM_ID_HAPTICS_VI_TUNING_DATA_2_PARAM 0x08001B20

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_tuning_data_2_param_t param_id_haptics_vi_tuning_data_2_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_TUNING_DATA_2_PARAM", PARAM_ID_HAPTICS_VI_TUNING_DATA_2_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 2 to VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_tuning_data_2_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for VI module tuning data file for LRA 2}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of VI module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the VI module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {VI module tuning data for LRA 2: path to the VI module tuning binary file.}
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
#define PARAM_ID_HAPTICS_VI_TUNING_DATA_3_PARAM 0x08001B21

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_tuning_data_3_param_t param_id_haptics_vi_tuning_data_3_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_TUNING_DATA_3_PARAM", PARAM_ID_HAPTICS_VI_TUNING_DATA_3_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 3 to VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_tuning_data_3_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for VI module tuning data file for LRA 3}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of VI module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the VI module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {VI module tuning data for LRA 3: path to the VI module tuning binary file.}
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
#define PARAM_ID_HAPTICS_VI_TUNING_DATA_4_PARAM 0x08001B22

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_haptics_vi_tuning_data_4_param_t param_id_haptics_vi_tuning_data_4_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_VI_TUNING_DATA_4_PARAM", PARAM_ID_HAPTICS_VI_TUNING_DATA_4_PARAM}
    @h2xmlp_description {Parameter for registering tuning data for LRA source 4 to VI module.}
    @h2xmlp_toolPolicy  {CALIBRATION}
    @h2xmlp_isOffloaded {TRUE}
    @h2xmlp_persistType {Shared}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_vi_tuning_data_4_param_t {
    uint32_t alignment;
    /**< @h2xmle_description {Data Alignment required for VI module tuning data file for LRA 4}
         @h2xmle_default     {4}
         @h2xmle_range       {0..4} */
    uint32_t offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of VI module tuning data file by alignment}
         @h2xmle_default     {0}
         @h2xmle_range       {0..3} */
    uint32_t size;
    /**< @h2xmle_description {Length of the VI module tuning data file in bytes.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0x00002710} */
#ifdef __H2XML__
    uint8_t data[0];
    /**< @h2xmle_description {VI module tuning data for LRA 4: path to the VI module tuning binary file.}
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
#define PARAM_ID_HAPTICS_LRA_SELECTION_PARAM 0x08001B23

/*==============================================================================
   Type definitions
==============================================================================*/

// Structure encapsulating min and max range for LRAs from multiple sources
typedef struct haptics_lra_selection_range_param_t haptics_lra_selection_range_param_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** @h2xmlp_subStruct */

struct haptics_lra_selection_range_param_t
{
   int32_t min_value;
   /**< @h2xmle_description {Min valid selection parameter value for selected source (including min_value)}
        @h2xmle_range       {0..2147483647}
        @h2xmle_dataFormat  {Q24}
        @h2xmle_default     {0} */
   int32_t max_value;
   /**< @h2xmle_description {Max valid selection parameter value for selected source (excluding max_value)}
        @h2xmle_range       {0..2147483647}
        @h2xmle_dataFormat  {Q24}
        @h2xmle_default     {2147483647} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure definition for Parameter */
typedef struct param_id_haptics_lra_selection_param_t param_id_haptics_lra_selection_param_t;

/** @h2xmlp_parameter   {"PARAM_ID_HAPTICS_LRA_SELECTION_PARAM",
                    PARAM_ID_HAPTICS_LRA_SELECTION_PARAM}
    @h2xmlp_description {Parameter defining differentiation criteria for LRAs from multiple sources.}
    @h2xmlp_toolPolicy  {CALIBRATION}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_haptics_lra_selection_param_t {
   uint32_t num_lra_sources;
   /**< @h2xmle_description {Number of LRA sources}
        @h2xmle_rangeList   {"1"=1;"2"=2;"3"=3;"4"=4;"5"=5}
        @h2xmle_default     {1} */
   uint32_t lra_selection_criteria;
   /**< @h2xmle_description {Parameter used to differentiate the LRAs from different sources}
        @h2xmle_rangeList   {"LRA DC Resisistance"=0;"LRA Coil Inductance"=1}
        @h2xmle_default     {0} */
#ifdef __H2XML__
   haptics_lra_selection_range_param_t lra_selection_range[0];
   /**< @h2xmle_description       {Selection parameter range for selected source}
        @h2xmle_variableArraySize {num_lra_sources} */   
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#define EVENT_ID_HAPTICS_VI_CALIBRATION 0x080013B4
/*==============================================================================
   Type definitions
==============================================================================*/

/** @h2xmlp_parameter   {"EVENT_ID_HAPTICS_VI_CALIBRATION",
                          EVENT_ID_HAPTICS_VI_CALIBRATION}
    @h2xmlp_description { VI calibration event raised by the Haptics Protection Module.}
    @h2xmlp_toolPolicy  { NO_SUPPORT}*/

#define EVENT_ID_HAPTICS_LRA_DIAGNOSTICS 0x080013B3
/*==============================================================================
   Type definitions
==============================================================================*/

/** @h2xmlp_parameter   {"EVENT_ID_HAPTICS_LRA_DIAGNOSTICS",
                          EVENT_ID_HAPTICS_LRA_DIAGNOSTICS}
    @h2xmlp_description { if change in lra diagnostics state and temperature status,
                    event will be raised by the Haptics Protection Module.}
    @h2xmlp_toolPolicy  { NO_SUPPORT}*/


/** @} <-- End of the Module --> */

#endif /* __WSA_HAPTICS_VI_API_H__ */
