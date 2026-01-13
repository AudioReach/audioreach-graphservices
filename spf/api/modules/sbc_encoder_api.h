/*==============================================================================
  @file sbc_encoder_api.h
  @brief This file contains SBC encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _SBC_ENCODER_API_H_
#define _SBC_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/** @h2xml_title1           {SBC Encoder}
    @h2xml_title_agile_rev  {SBC Encoder}
    @h2xml_title_date       {March 13, 2019}
*/
#define MODULE_ID_SBC_ENC 0x0700103A
/**
    @h2xmlm_module         {"MODULE_ID_SBC_ENC", MODULE_ID_SBC_ENC}
    @h2xmlm_displayName    {"SBC Encoder"}
    @h2xmlm_description    {This module is used as the encoder for SBC use cases.\n
                            - This module has only one input and one output port.\n
                            - Payload for param_id_encoder_output_config_t : sbc_enc_cfg_t\n
                            - Encodes data to format-id = MEDIA_FMT_ID_SBC\n
                            - Supports following params:\n
                            -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                            -- PARAM_ID_ENC_BITRATE\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 16, 32, 44.1, 48 \n
                            -- Number of channels : 1, 2\n
                            -- Bit Width : 16\n
                            -- Bits Per Sample : 16\n
                            -- Q format : Q15\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- maximum bit rates in bps:\n
                            --- mono : 320kbps \n
                            --- stereo : 512kbps \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"sbc_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @h2xml_Select          {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif //_SBC_ENCODER_API_H_
