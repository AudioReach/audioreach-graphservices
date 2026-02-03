/*==============================================================================
  @file aptx_decoder_api.h
  @brief This file contains aptx Classic decoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_CLASSIC_DECODER_H_
#define _APTX_CLASSIC_DECODER_H_

#include "common_enc_dec_api.h"
#include "ar_defs.h"

/** @h2xml_title1           {aptX Classic Decoder}
    @h2xml_title_agile_rev  {aptX Classic Decoder}
    @h2xml_title_date       {August 8, 2019}
*/

#define MODULE_ID_APTX_CLASSIC_DEC 0x0700107D
/**
    @h2xmlm_module         {"MODULE_ID_APTX_CLASSIC_DEC", MODULE_ID_APTX_CLASSIC_DEC}
    @h2xmlm_displayName    {"aptx Classic Decoder"}
    @h2xmlm_description    {This module is used as the decoder for aptX Classic use cases.\n
                            - This module has only one input and one output port.\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following params:\n
                            -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n
                            - Supported Input Media Format\n
                            -- Data format : RAW_COMPRESSED}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_reqContcapabilities {APM_CONTAINER_CAP_CD}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy     {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
    @h2xmlm_InsertStructure
    @}                     <-- End of the Module -->
*/

#endif //_APTX_CLASSIC_DECODER_H_
