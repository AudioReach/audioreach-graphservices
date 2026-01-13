/*==============================================================================
  @file aptx_classic_encoder_api.h
  @brief This file contains aptx Classic encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_CLASSIC_ENCODER_API_H_
#define _APTX_CLASSIC_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"


/*==============================================================================
   Parameters
==============================================================================*/
/** ID of the aptx classic encoder output threshold parameter.This parameter should be set at init time.*/
#define PARAM_ID_APTX_CLASSIC_SET_OUTPUT_THRESHOLD  0x08001180
/* Structure payload for: PARAM_ID_APTX_CLASSIC_SET_OUTPUT_THRESHOLD*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_CLASSIC_SET_OUTPUT_THRESHOLD", PARAM_ID_APTX_CLASSIC_SET_OUTPUT_THRESHOLD}
    @h2xmlp_description {- Configures the output threshold of aptX Classic Encoder. \n
                         -  Permissible values are in the range 64 to 1500 bytes.. \n
                         -  .. and must be divisible by 4, since 4 is the smallest possible output 'packet' from Classic Encoder. \n
                         -> Values outside the above range, or not divisible by 4, are rejected with EBADPARAM return code.  \n
                         -> Since aptX compression ratio is fixed at 4:1, the input threshold is also configured from the output threshold.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct param_id_aptx_classic_output_threshold_payload_t
{
    uint32_t output_threshold;
    /**< @h2xmle_description {Threshold in bytes, must be divisible by 4}
         @h2xmle_range       {64..1500}
         @h2xmle_default     {656}
       */
}
#include "spf_end_pack.h"
;

typedef struct param_id_aptx_classic_output_threshold_payload_t param_id_aptx_classic_output_threshold_payload_t;


/** ID of the aptx classic encoder sync mode parameter.This parameter should be set at init time.*/
#define PARAM_ID_APTX_CLASSIC_SET_SYNC_MODE  0x08001181
/* Structure payload for: PARAM_ID_APTX_CLASSIC_SET_SYNC_MODE*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_CLASSIC_SET_SYNC_MODE", PARAM_ID_APTX_CLASSIC_SET_SYNC_MODE}
    @h2xmlp_description {- Configures the autosync mode, startup mode, and CVR fade duration of aptX Classic Encoder}

    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct param_id_aptx_classic_sync_mode_payload_t
{
   int32_t sync_mode;
   /**< @h2xmle_description  { Configures the autosync mode of aptX Classic Encoder}
        @h2xmle_rangeList    {"STEREO SYNC" = 0;
                              "DUAL AUTOSYNC" = 1;
                              "NO AUTOSYNC" = 2}
        @h2xmle_default      {0}   */

   int32_t startup_mode;
   /**< @h2xmle_description  { Configures the startup sync mode of aptX Classic Encoder}
        @h2xmle_rangeList    {"STEREO_SYNC" = 0;
                              "DUAL AUTOSYNC" = 1}
          @h2xmle_default      {0}   */

   int32_t cvr_fade_duration;
   /**< @h2xmle_description {Cosine Volume Ramp duration in mS, for transition between stereo and L+R/2 dual mono (TWS+ Earbuds removal use case)}
        @h2xmle_range       {1..255}
        @h2xmle_default     {255}
      */
}
#include "spf_end_pack.h"
;

typedef struct param_id_aptx_classic_sync_mode_payload_t param_id_aptx_classic_sync_mode_payload_t;


/** ID of the aptx classic encoder switch parameter.This parameter can be set at run time.*/
#define PARAM_ID_APTX_CLASSIC_SWITCH_ENC_PCM_INPUT  0x08001182
/* Structure payload for: PARAM_ID_APTX_CLASSIC_SWITCH_ENC_PCM_INPUT*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_CLASSIC_SWITCH_ENC_PCM_INPUT", PARAM_ID_APTX_CLASSIC_SWITCH_ENC_PCM_INPUT}
    @h2xmlp_description {- Switches the input PCM for aptX Classic Encoder to be either normal stereo, or (L+R/2) mix to both L & R channels. \n
                         -  Permissible values are:  \n
                         -  1 = transition from stereo to L+R/2 mono with CVR fade. \n
                         -  2 = transition from L+R/2 mono to stereo with CVR fade. \n
                         -  payload values outside these valid values are rejected with EBADPARAM return code.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct param_id_aptx_classic_switch_enc_pcm_input_payload_t
{
   int32_t transition_direction;
   /**< @h2xmle_description  {Switches input PCM to be either normal stereo, or (L+R/2) mix to both L & R channels (TWS+ Earbuds removal use case)}
        @h2xmle_rangeList    {"transition from stereo to L+R/2 mono with CVR fade" = 1;
                              "transition from L+R/2 mono to stereo with CVR fade" = 2}
        @h2xmle_default      {1}   */
}
#include "spf_end_pack.h"
;

typedef struct param_id_aptx_classic_switch_enc_pcm_input_payload_t param_id_aptx_classic_switch_enc_pcm_input_payload_t;


/*==============================================================================
   Module
==============================================================================*/


/** @h2xml_title1           {aptX Classic Encoder}
    @h2xml_title_agile_rev  {aptX Classic Encoder}
    @h2xml_title_date       {August 8, 2019}
*/
#define MODULE_ID_APTX_CLASSIC_ENC 0x0700107E
/**
    @h2xmlm_module         {"MODULE_ID_APTX_CLASSIC_ENC", MODULE_ID_APTX_CLASSIC_ENC}
    @h2xmlm_displayName    {"aptX Classic Encoder"}
    @h2xmlm_description    {This module is used as the encoder for aptX Classic use cases.\n
                            - This module has only one input and one output port.\n
                            - Payload for param_id_encoder_output_config_t : xxx_enc_cfg_t\n
                            - Encodes data to format-id = 0x000131FF\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following params:\n
                            --  ------------------------ \n
                            --  --\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 44.1, 48 \n
                            -- Number of channels : 2\n
                            -- Bit Width : 16\n
                            -- Bits Per Sample : 16\n
                            -- Q format : Q15\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- maximum bit rates in bps:\n
                            --- mono : n\a \n
                            --- stereo : 384kbps (48K), 352.8kbps (44K1) \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_reqContcapabilities {APM_CONTAINER_CAP_CD}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_aptx_classic_output_threshold_payload_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_aptx_classic_sync_mode_payload_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_aptx_classic_switch_enc_pcm_input_payload_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif //_APTX_CLASSIC_ENCODER_API_H_
