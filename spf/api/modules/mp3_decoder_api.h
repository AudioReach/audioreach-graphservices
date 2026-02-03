#ifndef _MP3_DECODER_API_H_
#define _MP3_DECODER_API_H_
/*==============================================================================
 @file mp3_decoder_api.h
 @brief This file contains MP3 decoder APIs

 Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 SPDX-License-Identifier: BSD-3-Clause
 ==============================================================================*/
// clang-format off

/*==============================================================================
 * Include files
 ==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/** @h2xml_title1           {MP3 Decoder Module API}
    @h2xml_title_agile_rev  {MP3 Decoder Module API}
    @h2xml_title_date       {April 15, 2019} */


/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of MP3 module */
#define MP3_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of MP3 module */
#define MP3_DEC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of MP3 module */
#define MP3_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of MP3 module */
#define MP3_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of MP3 module */
#define MP3_DEC_MODULE_STACK_SIZE 8192


/*==============================================================================
   Module
==============================================================================*/

/**
 * Module ID for MP3 decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_MP3
 */
#define MODULE_ID_MP3_DEC 0x0700103B
/**
    @h2xmlm_module         {"MODULE_ID_MP3_DEC", MODULE_ID_MP3_DEC}
    @h2xmlm_displayName    {"MP3 Decoder"}
    @h2xmlm_description    {This module is used as the decoder for MP3 use cases.\n
                           - This module has only one input and one output port.\n
                           - Media format is not directly set on the decoder, it's set on the EP module which
                             propagates it in the data path.\n
                           - Decodes data of format-id = MEDIA_FMT_ID_MP3\n
                           - Supports following params:\n
                           -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n
						   -- PARAM_ID_REMOVE_INITIAL_SILENCE\n
                           -- PARAM_ID_REMOVE_TRAILING_SILENCE\n
                           - Supported Input Media Format\n
                           -- Data format : RAW_COMPRESSED\n
                           -- fmt_id : MEDIA_FMT_ID_MP3\n
                            }
  @h2xmlm_dataMaxInputPorts   {MP3_DEC_DATA_MAX_INPUT_PORTS}
  @h2xmlm_dataMaxOutputPorts  {MP3_DEC_DATA_MAX_OUTPUT_PORTS}
  @h2xmlm_dataInputPorts      {IN=MP3_DEC_DATA_INPUT_PORT}
  @h2xmlm_dataOutputPorts     {OUT=MP3_DEC_DATA_OUTPUT_PORT}
  @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
  @h2xmlm_isOffloadable       {true}
  @h2xmlm_stackSize           {MP3_DEC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
 @{                     <-- Start of the Module -->
  @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
  @h2xmlm_InsertParameter
  @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
  @h2xmlm_InsertStructure 
 @}                     <-- End of the Module -->
 */
 #endif // _MP3_DECODER_API_H_

