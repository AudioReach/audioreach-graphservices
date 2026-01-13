/*==============================================================================
  @file aptx_hd_decoder_api.h
  @brief This file contains aptx HD decoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_HD_DECODER_H_
#define _APTX_HD_DECODER_H_

#include "common_enc_dec_api.h"
#include "ar_defs.h"

/** @h2xml_title1           {aptX HD Decoder}
    @h2xml_title_agile_rev  {aptX HD Decoder}
    @h2xml_title_date       {December 6, 2019}
*/

#define MODULE_ID_APTX_HD_DEC 0x0700107F
/**
    @h2xmlm_module         {"MODULE_ID_APTX_HD_DEC", MODULE_ID_APTX_HD_DEC}
    @h2xmlm_displayName    {"aptx HD Decoder"}
    @h2xmlm_description    {This module is used as the decoder for aptX HD use cases.\n
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

#endif //_APTX_HD_DECODER_H_
