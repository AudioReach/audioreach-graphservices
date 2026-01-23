#ifndef _OPUS_DECODER_API_H_
#define _OPUS_DECODER_API_H_
/*========================================================================
  @file opus_decoder_api.h
  @brief This file contains OPUS decoder APIs
 ========================================================================*/

/*========================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==========================================================================*/


/** @h2xml_title1          {OPUS Decoder Module}
    @h2xml_title_agile_rev {OPUS Decoder Module}
    @h2xml_title_date      {March, 2023} */

/*========================================================================
 * Include files
 =========================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/*========================================================================
   Constants
=========================================================================*/

/* Input port ID of OPUS module */
#define OPUS_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of OPUS module */
#define OPUS_DEC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of OPUS module */
#define OPUS_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of OPUS module */
#define OPUS_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of OPUS module */
#define OPUS_DEC_MODULE_STACK_SIZE 16384


/*==============================================================================
   Module
==============================================================================*/

/**
 * Module ID for OPUS decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_OPUS
 */
#define MODULE_ID_OPUS_DEC 				    0x07001174

/**
    @h2xmlm_module         {"MODULE_ID_OPUS_DEC", MODULE_ID_OPUS_DEC}
    @h2xmlm_displayName    {"OPUS Decoder"}
    @h2xmlm_description    {This module is used as the decoder for OPUS Youtube offload use cases.\n
                           - This module has only one input and one output port.\n
                           - Payload for media_format_t: payload_media_fmt_opus_t\n
                           - Media format is not directly set on the decoder, it's set
                           on the EP module which propagates it in the data path.\n
                           - Decodes data of format-id = MEDIA_FMT_ID_OPUS\n
                           - Supports following params:\n
                           -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n
                           - Supported Input Media Format\n
                           -- Data format: RAW_COMPRESSED\n
                           -- fmt_id : MEDIA_FMT_ID_OPUS\n
                           -- payload: payload_media_fmt_opus_t\n
                           }
  @h2xmlm_dataMaxInputPorts   {OPUS_DEC_DATA_MAX_INPUT_PORTS}
  @h2xmlm_dataMaxOutputPorts  {OPUS_DEC_DATA_MAX_OUTPUT_PORTS}
  @h2xmlm_dataInputPorts      {IN=OPUS_DEC_DATA_INPUT_PORT}
  @h2xmlm_dataOutputPorts     {OUT=OPUS_DEC_DATA_OUTPUT_PORT}
  @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
  @h2xmlm_isOffloadable       {false}
  @h2xmlm_stackSize           {OPUS_DEC_MODULE_STACK_SIZE}
 @h2xmlm_toolPolicy     {Calibration}
  @{                     <-- Start of the Module -->
  @h2xml_Select               {"param_id_pcm_output_format_cfg_t"}
  @h2xmlm_InsertParameter
  @h2xml_Select               {"payload_pcm_output_format_cfg_t"}
  @h2xmlm_InsertStructure
  @}                     <-- End of the Module -->
*/

#endif //_OPUS_DECODER_API_H_
