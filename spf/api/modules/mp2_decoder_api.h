#ifndef _MP2_DECODER_API_H_
#define _MP2_DECODER_API_H_
/*==============================================================================
 @file mp2_decoder_api.h
 @brief This file contains MP2 decoder APIs

 Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 SPDX-License-Identifier: BSD-3-Clause
 ==============================================================================*/
// clang-format off

/*==============================================================================
 * Include files
 ==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/** @h2xml_title1           {MP2 Decoder Module API}
    @h2xml_title_agile_rev  {MP2 Decoder Module API}
    @h2xml_title_date       {April 15, 2019} */


/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of MP2 module */
#define MP2_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of MP2 module */
#define MP2_DEC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of MP2 module */
#define MP2_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of MP2 module */
#define MP2_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of MP2 module */
#define MP2_STACK_SIZE 8192


/*==============================================================================
   Module
==============================================================================*/

/**
 * Module ID for MP2 decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_MP2
 */
#define MODULE_ID_MP2_DEC 0x0700104E
/**
    @h2xmlm_module         {"MODULE_ID_MP2_DEC", MODULE_ID_MP2_DEC}
    @h2xmlm_displayName    {"MP2 Decoder"}
    @h2xmlm_description    {This module is used as the decoder for MP2 use cases.\n
                           - This module has only one input and one output port.\n
                           - Media format is not directly set on the decoder, it's set on the EP module which
                             propagates it in the data path.\n
                           - Decodes data of format-id = MEDIA_FMT_ID_MP2\n
                           - Supports following params:\n
                           -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n
						   -- PARAM_ID_REMOVE_INITIAL_SILENCE\n
                           -- PARAM_ID_REMOVE_TRAILING_SILENCE\n
                           - Supported Input Media Format\n
                           -- Data format : RAW_COMPRESSED\n
                           -- fmt_id : MEDIA_FMT_ID_MP2\n

                           * Supported Input Media Format:\n
                           *  - Data Format          : FIXED_POINT\n
                           *  - fmt_id               : Don't care\n
                           *  - Sample Rates         : 16000Hz to 48000Hz \n
                           *  - Number of channels   : 2\n
                           *  - Channel type         : 1 to 63\n
                           *  - Bits per sample      : 16, 24\n


                            }
  @h2xmlm_dataMaxInputPorts   {MP2_DEC_DATA_MAX_INPUT_PORTS}
  @h2xmlm_dataMaxOutputPorts  {MP2_DEC_DATA_MAX_OUTPUT_PORTS}
  @h2xmlm_dataInputPorts      {IN=MP2_DEC_DATA_INPUT_PORT}
  @h2xmlm_dataOutputPorts     {OUT=MP2_DEC_DATA_OUTPUT_PORT}
  @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
  @h2xmlm_stackSize           {MP2_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
 @{                     <-- Start of the Module -->
  @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
  @h2xmlm_InsertParameter
  @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
  @h2xmlm_InsertStructure 
 @}                     <-- End of the Module -->
 */
 #endif // _MP2_DECODER_API_H_

