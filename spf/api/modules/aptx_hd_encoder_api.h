/*==============================================================================
  @file aptx_hd_encoder_api.h
  @brief This file contains aptx HD encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_HD_ENCODER_API_H_
#define _APTX_HD_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/** @h2xml_title1           {aptX HD Encoder}
    @h2xml_title_agile_rev  {aptX HD Encoder}
    @h2xml_title_date       {November 15, 2019}
*/
#define MODULE_ID_APTX_HD_ENC 0x07001080
/**
    @h2xmlm_module         {"MODULE_ID_APTX_HD_ENC", MODULE_ID_APTX_HD_ENC}
    @h2xmlm_displayName    {"aptX HD Encoder"}
    @h2xmlm_description    {This module is used as the encoder for aptX HD use cases.\n
                            - This module has only one input and one output port.\n
                            - Payload for param_id_encoder_output_config_t : xxx_enc_cfg_t\n
                            - Encodes data to format-id = 0x00013200\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following params:\n
                            -- TBC \n
                            -- \n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 44.1, 48 \n
                            -- Number of channels : 2\n
                            -- Bit Width : 24\n
                            -- Bits Per Sample : 32\n
                            -- Q format : Q31\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- maximum bit rates in bps:\n
                            --- mono : n\a \n
                            --- stereo : 576kbps \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_reqContcapabilities {APM_CONTAINER_CAP_CD}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @}                     <-- End of the Module -->
*/

#endif //_APTX_HD_ENCODER_API_H_
