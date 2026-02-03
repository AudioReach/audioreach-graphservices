#ifndef _AMRWB_ENCODER_API_H_
#define _AMRWB_ENCODER_API_H_
/*==============================================================================
  @file amrwb_encoder_api.h
  @brief This file contains AMRWB encoder APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
/** @h2xml_title1           {AMRWB Encoder Module API}
    @h2xml_title_agile_rev  {AMRWB Encoder Module API}
    @h2xml_title_date       {May 28, 2019} */

/*==============================================================================
   Include Files
==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "vocoder_cmn_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of AMRWB module */
#define AMRWB_ENC_DATA_INPUT_PORT   0x2

/* Output port ID of AMRWB module */
#define AMRWB_ENC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of AMRWB module */
#define AMRWB_ENC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of AMRWB module */
#define AMRWB_ENC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of AMRWB module */
#define AMRWB_ENC_MODULE_STACK_SIZE 16384

/*==============================================================================
   Module
==============================================================================*/

/**
 * Module ID for AMRWB encoder.
 * Encodes to data of format-id = MEDIA_FMT_ID_AMRWB
 */
#define MODULE_ID_AMRWB_ENC 0x07001079
/**
    @h2xmlm_module         {"MODULE_ID_AMRWB_ENC", MODULE_ID_AMRWB_ENC}
    @h2xmlm_displayName    {"AMRWB Encoder"}
    @h2xmlm_description    {This module is used as the encoder for AMRWB use cases.\n
                                 - This module has only one input and one output port.\n
                                 - Payload for param_id_encoder_output_config_t : amrwb_enc_cfg_t\n
                                 - Encodes data to format-id:\n
                                   - MEDIA_FMT_ID_AMRWB - for voice use cases\n
                                   - MEDIA_FMT_ID_AMRWB_FS - for audio use cases\n
                                 - Supports following params:\n
                                 -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                                 -- PARAM_ID_ENC_BITRATE\n
                                 -- PARAM_ID_VOCODER_ENABLE_DTX_MODE\n
                                 - Supported Input Media Format:\n
                                 -- Data Format : FIXED_POINT\n
                                 -- fmt_id : Don't care\n
                                 -- Sample Rates: 16000 Hz\n
                                 -- Number of channels : 1\n
                                 -- Bit Width : 16\n
                                 -- Bits Per Sample : 16\n
                                 -- Q format : Q15\n
                                 -- Interleaving : de-interleaved unpacked\n
                                 - Supported bit rates in kbps\n
                                  -- 6.60, 8.85, 12.65, 14.25, 15.85, 18.25, 19.85, 23.05, 23.85
                                 }
    @h2xmlm_dataMaxInputPorts   {AMRWB_ENC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {AMRWB_ENC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=AMRWB_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=AMRWB_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {AMRWB_ENC_MODULE_STACK_SIZE}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_encoder_output_config_t::fmt_id}
    @h2xmle_rangeList           {"Media format ID of AMRWB"=MEDIA_FMT_ID_AMRWB}
    @h2xmle_default             {MEDIA_FMT_ID_AMRWB}
    @h2xml_Select               {"amrwb_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @h2xml_Select               {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
	@h2xml_Select               {"param_id_vocoder_enable_dtx_mode_t"}
    @h2xmlm_InsertParameter
    @}                         <-- End of the Module -->
*/

#endif //_AMRWB_ENCODER_API_H_
