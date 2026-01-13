/*==============================================================================
  @file lc3_encoder_api.h
  @brief This file contains LC3 1.0 encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _LC3_ENCODER_API_H_
#define _LC3_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "imcl_spm_intent_api.h"
#include "lc3_decoder_api.h"

/* Control port for receiving br info*/
#define COP_ENCODER_FEEDBACK_IN AR_NON_GUID(0xC0000001)


/*==============================================================================
   Parameters
==============================================================================*/

/** ID of the LC3 Enc_Init parameter.This parameter should be set at init time, but not run time.*/
#define PARAM_ID_LC3_ENC_INIT  0x0800118B

/** @h2xmlp_parameter   {"PARAM_ID_LC3_ENC_INIT", PARAM_ID_LC3_ENC_INIT}
    @h2xmlp_description { Configures the parameters of the LC3 Encoder after the module has been instantiated. }
    @h2xmlx_expandStructs  {false}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_lc3_encoder_config_payload_t
{
    lc3_config_t toAirConfig;

    uint32_t stream_map_size;
    /**< @h2xmle_description {The size - in triplets - of the stream map Encoderntity(s) that follows this element. Each stream map entity has 3 elements - audio location, stream-id, and direction}
         @h2xmle_range       {1..2}
         @h2xmle_default     {1}
       */

    stream_map_t streamMapOut[0];
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_lc3_encoder_config_payload_t param_id_lc3_encoder_config_payload_t;


/*==============================================================================
   Parameters
==============================================================================*/

/** ID of the LC3 encoder downmix to mono parameter.This parameter can be set at run time.*/
#define PARAM_ID_LC3_ENC_DOWNMIX_2_MONO 0x0800118C
/* Structure payload for: PARAM_ID_LC3_ENC_DOWNMIX_2_MONO*/
/** @h2xmlp_parameter   {"PARAM_ID_LC3_ENC_DOWNMIX_2_MONO", PARAM_ID_LC3_ENC_DOWNMIX_2_MONO}
    @h2xmlp_description {- Switches the input PCM for LC3 Encoder to be either normal stereo, or (L+R/2) mix to both L and R channels. \n
                         -  Permissible values are:  \n
                         -  1 = transition from stereo to L+R/2 mono with CVR fade. \n
                         -  2 = transition from L+R/2 mono to stereo with CVR fade. \n
                         -  payload values outside these valid values are rejected with EBADPARAM return code.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_lc3_encoder_switch_enc_pcm_input_payload_t
{
   int32_t transition_direction;
   /**< @h2xmle_description  {Switches input PCM to be either normal stereo, or (L+R/2) mix to both L and R channels}
        @h2xmle_rangeList    {"transition from stereo to L+R/2 mono with CVR fade" = 1;
                              "transition from L+R/2 mono to stereo with CVR fade" = 2}
        @h2xmle_default      {1}   */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct  param_id_lc3_encoder_switch_enc_pcm_input_payload_t  param_id_lc3_encoder_switch_enc_pcm_input_payload_t;



/*==============================================================================
   Module
==============================================================================*/


/** @h2xml_title1           {LC3  Encoder}
    @h2xml_title_agile_rev  {LC3  Encoder}
    @h2xml_title_date       {November 4th, 2020}
*/
#define MODULE_ID_LC3_ENC 0x07001085
/**
    @h2xmlm_module         {"MODULE_ID_LC3_ENC", MODULE_ID_LC3_ENC}
    @h2xmlm_displayName    {"LC3 1.0 Encoder"}
    @h2xmlm_description    {This module encodes 24-bit PCM audio into LC3-encoded stream(s)\n
                            - The output media format is Deinterleaved Raw Compressed\n
                            - This module should be used in the same subgraph as the CoPv2 Packetizer\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following mandatory params:\n
                            -- PARAM_ID_LC3_ENC_INIT - configures the LC3 Encoder parameters\n
                            -- Supports following optional params:\n
                            -- PARAM_ID_LC3_ENC_DOWNMIX_2_MONO - downmixes stereo PCM_BIG_ENDIAN input to mono before encoding\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 48, 44.1, 32, 24, 16, 8 \n
                            -- Number of channels : 1, 2\n
                            -- PCM Bits Per Sample : 24\n
                            -- input PCM Q format : Q31\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- mono : depends on selected LC3 frame duration and sample rate  \n
                            -- stereo : depends on selected LC3 frame duration and sample rate \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_IN" = 0xC0000001,
                                 "Bit rate level encoder feedback intent" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {lc3_config_t}
    @h2xmlm_InsertParameter
    @h2xml_Select          {stream_map_t}
    @h2xmlm_InsertParameter
    @h2xml_Select          {param_id_lc3_encoder_config_payload_t}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_lc3_encoder_switch_enc_pcm_input_payload_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->

*/

#endif //_LC3_ENCODER_API_H_

