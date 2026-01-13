/*==============================================================================
  @file aptx-adaptive3-ble-encoder-api.h
  @brief This file contains aptX Adaptive 3.0 LE encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_ADAPTIVE3_BLE_ENCODER_API_H_
#define _APTX_ADAPTIVE3_BLE_ENCODER_API_H_

#define SKIP_LC3_XML                               1
#define MASQERADE_AS_LC3                           0

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "imcl_spm_intent_api.h"
#include "lc3_encoder_api.h"

/*==============================================================================
   Parameters
==============================================================================*/



/*==============================================================================
   Module
==============================================================================*/

#if !MASQERADE_AS_LC3
/** @h2xml_title1           {aptX Adaptive QLEA 3.0 Encoder}
    @h2xml_title_agile_rev  {aptX Adaptive QLEA 3.0  Encoder}
    @h2xml_title_date       {October 8th, 2021}
*/
#define MODULE_ID_APTX_ADAPTIVE_QLEA_ENC 0x070010C3
/**
    @h2xmlm_module         {"MODULE_ID_APTX_ADAPTIVE_QLEA_ENC", MODULE_ID_APTX_ADAPTIVE_QLEA_ENC}
    @h2xmlm_displayName    {"aptX Adaptive QLEA 3.0 Encoder"}
    @h2xmlm_description    {This module encodes 24-bit PCM audio into aptX Adaptive QLEA 3.0 encoded stream(s)\n
                            - The output media format is Deinterleaved Raw Compressed\n
                            - This module should be used in the same subgraph as the CoPv2 Packetizer\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following mandatory params:\n
                            -- PARAM_ID_LC3_ENC_INIT - configures the aptX Adaptive QLEA 3.0 Encoder parameters\n
                            -- Supports following optional params:\n
                            -- PARAM_ID_LC3_ENC_DOWNMIX_2_MONO - downmixes stereo PCM input to mono before encoding\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 96, 48\n
                            -- Number of channels : 2\n
                            -- PCM Bits Per Sample : 24\n
                            -- input PCM Q format : Q31\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- stereo : depends on selected aptX Adaptive QLEA 3.0 frame duration and sample rate \n }
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
#else

// MASQERADE AS LC3

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
                     -- PARAM_ID_LC3_ENC_DOWNMIX_2_MONO - downmixes stereo PCM input to mono before encoding\n
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

#endif

#endif //_APTX_ADAPTIVE3_BLE_ENCODER_API_H_
