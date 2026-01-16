/*==============================================================================
  @file sbc_decoder_api.h
  @brief This file contains SBC decoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _SBC_DECODER_H_
#define _SBC_DECODER_H_

#include "common_enc_dec_api.h"
#include "ar_defs.h"

/** @h2xml_title1           {SBC Decoder}
    @h2xml_title_agile_rev  {SBC Decoder}
    @h2xml_title_date       {October 15, 2018}
*/

#define MODULE_ID_SBC_DEC 0x07001039
/**
    @h2xmlm_module         {"MODULE_ID_SBC_DEC", MODULE_ID_SBC_DEC}
    @h2xmlm_displayName    {"SBC Decoder"}
    @h2xmlm_description    {This module is used as the decoder for SBC use cases.\n
                            - This module has only one input and one output port.\n
                            - Supports following params:\n 
                            -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n 
                            - Supported Input Media Format\n 
                            -- Data format : RAW_COMPRESSED}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy     {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
    @h2xmlm_InsertStructure
    @}                     <-- End of the Module -->
*/

#endif //_SBC_DECODER_API_H
