#ifndef _CELT_ENCODER_API_H_
#define _CELT_ENCODER_API_H_
/*==============================================================================
  @file celt_encoder_api.h
  @brief This file contains CELT encoder APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
/*==============================================================================
   Include Files
==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of CELT module */
#define CELT_ENC_DATA_INPUT_PORT   0x2

/* Output port ID of CELT module */
#define CELT_ENC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of CELT module */
#define CELT_ENC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of CELT module */
#define CELT_ENC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of CELT module */
#define CELT_ENC_MODULE_STACK_SIZE 8192

/*==============================================================================
   Module
==============================================================================*/
/** @h2xml_title1           {CELT Encoder Module API}
    @h2xml_title_agile_rev  {CELT Encoder Module API}
    @h2xml_title_date       {April 15, 2019} */

/**
 * Module ID for CELT encoder.
 * Encodes to data of format-id = MEDIA_FMT_ID_CELT
 */
#define MODULE_ID_CELT_ENC 0x07001090

/**
    @h2xmlm_module              {"MODULE_ID_CELT_ENC", MODULE_ID_CELT_ENC}
    @h2xmlm_displayName         {"CELT Encoder"}
    @h2xmlm_description    {This module is used as the encoder for CELT use cases.\n
                            - This module has only one input and one output port.\n
                            - Payload for param_id_encoder_output_config_t : CELT_enc_cfg_t\n
                            - Encodes data to format-id = MEDIA_FMT_ID_CELT\n
                            - Supports following params:\n
                            -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                            -- PARAM_ID_ENC_BITRATE\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 32, 44.1, 48, 96 \n
                            -- Number of channels : 1, 2\n
                            -- Bit Width : 16\n
                            -- Bits Per Sample : 16\n
                            -- Q format : Q15\n
                            -- Interleaving : interleaved\n
                            -- Supported bit rates in each configuration :\n
                            -- minimum bit rate in bps:32000 \n
							-- maximum bit rate in bps:1536000 \n
                              \n }
    @h2xmlm_dataMaxInputPorts   {CELT_ENC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {CELT_ENC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=CELT_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=CELT_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {CELT_ENC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_encoder_output_config_t::fmt_id}
    @h2xmle_rangeList           {"Media format ID of CELT"=MEDIA_FMT_ID_CELT}
    @h2xmle_default             {0}
    @h2xml_Select               {"celt_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @h2xml_Select               {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
    @}                          <-- End of the Module -->
*/

#endif //_CELT_ENCODER_API_H_
