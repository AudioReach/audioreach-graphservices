#ifndef MIQSTER_API_H
#define MIQSTER_API_H

/**
 * \file miqster_api.h
 *
 * \brief
 *
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"

/*==========================================================================
   Macros
========================================================================== */
#define MIQSTER_STACK_SIZE_IN_BYTES 0x8000 //TODO: Profile stack

#define MIQSTER_MIN_NUM_INPUT_PORTS 0x1
#define MIQSTER_MAX_NUM_INPUT_PORTS 0x2

#define MIQSTER_MIN_NUM_OUTPUT_PORTS 0x1
#define MIQSTER_MAX_NUM_OUTPUT_PORTS 0x1

#define MIQSTER_PRIMARY_IN_PORT_ID 0x2
#define MIQSTER_SECONDARY_IN_PORT_ID 0x4

/** @h2xml_title1          {Audio Zoom (Miqster) Module}
    @h2xml_title_agile_rev {Audio Zoom (Miqster) Module}
    @h2xml_title_date      {Feb 14, 2025} */

/*==============================================================================
   Module ID and Module Supported Info
==============================================================================*/
#define MODULE_ID_MIQSTER                      0x0700117F
/**
    @h2xmlm_module       {"MODULE_ID_MIQSTER", MODULE_ID_MIQSTER}
    @h2xmlm_displayName  {MIQSTER_MODULE}
   @h2xmlm_modSearchKeys {Audio zoom}
    @h2xmlm_description  {Audio Zoom usecase. \n

*        Supports the following parameter IDs\n
*            1. PARAM_ID_MODULE_ENABLE \n // TODO: remove PID module_enable
*            2. PARAM_ID_LIB_VERSION \n
*            3. PARAM_ID_MIQSTER_CFG \n
*            4. PARAM_ID_MIQSTER_MIX \n

      //todo: test on both GC and SC containers.
*        Supported Containers: \n
*            1. APM_CONTAINER_TYPE_ID_GC \n

*        Supported Input Media Format     : \n
            - Data Format                : FIXED_POINT \n
            - fmt_id                     : MEDIA_FMT_ID_PCM \n
            - Sample Rates               : 8000, 16000, 32000, 48000, 96000 \n
            - Number of input channels(0x2) : 2 \n
            - Number of input channels(0x4) : 1 \n
            - Number of output channels   : 2 \n
            - Channel type               : 1 to 63 \n
            - Bits per sample            : 16, 32\n
            - Q format                   : 15 for bps 16, 27 or 31 for bps 32 \n
            - Interleaving               : de-interleaved unpacked \n
            - Signed/unsigned            : Signed  }

    @h2xmlm_dataMaxInputPorts    {MIQSTER_MAX_NUM_INPUT_PORTS}
       @h2xmlm_dataInputPorts      {PRIMARY_IN = MIQSTER_PRIMARY_IN_PORT_ID ;
                                 SECONDARY_IN = MIQSTER_SECONDARY_IN_PORT_ID}
    @h2xmlm_dataMaxOutputPorts   {MIQSTER_MAX_NUM_OUTPUT_PORTS}
    @h2xmlm_dataOutputPorts      {OUT=1}
    @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {true}
    @h2xmlm_stackSize            {MIQSTER_STACK_SIZE_IN_BYTES}
    @h2xmlm_ToolPolicy           {Calibration}


    @{                   <-- Start of the Module -->
    @h2xml_Select        {"lib_version_t"}
    @h2xmlm_InsertParameter
    */

/*==============================================================================
   Param miqster CAL
==============================================================================*/
#define PARAM_ID_MIQSTER_CFG              0x08001B31
typedef struct param_id_miqster_cfg_t param_id_miqster_cfg_t;

/**
    @h2xmlp_parameter       {"PARAM_ID_MIQSTER_CFG", PARAM_ID_MIQSTER_CFG}
    @h2xmlp_ToolPolicy      {Calibration}
    @h2xmlp_description     {MIQSTER calibration/tuning parameters\n}
*/
#include "spf_begin_pack.h"
struct param_id_miqster_cfg_t
{
   int32_t Enable;
   /**< @h2xmle_description {Enables lib}
            @h2xmle_dataFormat {Q0}
         @h2xmle_default     {0x1}
            @h2xmle_rangeList {Enable_flag=1}
    */
   int32_t LowerLimit;
   /**< @h2xmle_description {LowerLimit, Minimum amount of enhanced signal to be mixed}
            @h2xmle_dataFormat {Q29}
         @h2xmle_default     {0x0}
         @h2xmle_range {0x0..0x20000000}
         @h2xmle_policy      {Advanced}
    */
   int32_t UpperLimit;
   /**< @h2xmle_description {UpperLimit, Maximum amount of enhanced signal to be mixed}
            @h2xmle_dataFormat {Q29}
         @h2xmle_default     {0x20000000}
         @h2xmle_range {0x0..0x20000000}
         @h2xmle_policy      {Advanced}
    */
   int32_t StereoInputGain;
   /**< @h2xmle_description {StereoInputGain, Ratio of channels 1 and 2 to be mixed with loudness compensation. (Use
      this to reduce the amount of channesl 1 and 2 in the mix without reducing the overall loudness)}
            @h2xmle_dataFormat {Q29}
         @h2xmle_default     {0x20000000}
         @h2xmle_range {0x0..0x20000000}
         @h2xmle_policy      {Advanced}
    */
   int32_t Delay;
   /**< @h2xmle_description {DelayCompensation: number of samples by which the third channel is delayed to align with channels 1 and 2.}
            @h2xmle_dataFormat {Q8}
         @h2xmle_default     {0x100}
         @h2xmle_range {0x0..0x3C000}
         @h2xmle_policy      {Advanced}
    */
   int32_t Mode;
   /**< @h2xmle_description {Mode
      Mode0 = Audio Zoom additive mixing mode with loudness reduction for high SPL scenarios
      Mode1 = Audio Zoom additive mixing mode without loudness reduction
      Mode2 = Audio Zoom subtractive mixing mode where Mix crossfades between channel 1&2 and channel 3. Compared to Modes 0 and 1 which add channel 3 to channel 1&2.}
            @h2xmle_dataFormat {Q8}
         @h2xmle_default     {0x0}
         @h2xmle_range {0x0..0x300}
         @h2xmle_policy      {Advanced}
    */
   int32_t Transition;
   /**< @h2xmle_description {NumTransitionFrames: number of frames that channel 1&2 inputs exceed loudness threshold before applying gain reduction. }
            @h2xmle_dataFormat {Q8}
         @h2xmle_default     {0x300}
         @h2xmle_range {0x0..0x0C800}
         @h2xmle_policy      {Advanced}
    */
}
#include "spf_end_pack.h"
;

#define PARAM_ID_MIQSTER_MIX 0x08001B32
typedef struct param_id_miqster_mix_t param_id_miqster_mix_t;

/**
    @h2xmlp_parameter       {"PARAM_ID_MIQSTER_MIX", PARAM_ID_MIQSTER_MIX}
    @h2xmlp_ToolPolicy      {Calibration, RTC}
    @h2xmlp_description     {MIQSTER Mix param, amount of zoom required\n}
*/
#include "spf_begin_pack.h"
struct param_id_miqster_mix_t
{
   int32_t Mix;
   /**< @h2xmle_description {Mix, Wet/Dry Mix. (Map the Camcorder Zoom level to this param)}
            @h2xmle_dataFormat {Q29}
         @h2xmle_default     {0x0}
         @h2xmle_policy      {Advanced}
    */
}
#include "spf_end_pack.h"
;

/** @}                   <-- End of the Module -->*/
#endif // MIQSTER_API_H
