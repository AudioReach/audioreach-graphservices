#ifndef _ALAC_DECODER_API_H_
#define _ALAC_DECODER_API_H_

/*==============================================================================
 @file alac_decoder_api.h
 @brief This file contains ALAC decoder APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

/*==============================================================================
   Include Files
==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"

/** @h2xml_title1           {ALAC Decoder Module API}
    @h2xml_title_agile_rev  {ALAC Decoder Module API}
    @h2xml_title_date       {February 22, 2019} */

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of ALAC module */
#define ALAC_DEC_DATA_INPUT_PORT 0x2

/* Output port ID of ALAC module */
#define ALAC_DEC_DATA_OUTPUT_PORT 0x1

/* Max number of input ports of ALAC module */
#define ALAC_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of ALAC module */
#define ALAC_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of ALAC module */
#define ALAC_DEC_MODULE_STACK_SIZE 1024

/*==============================================================================
   Module
==============================================================================*/

/** @ingroup MEDIA_FMT_ID_ALAC
 Media format ID for the Apple Lossless Audio Codec (ALAC).

 @par ALAC format block (payload_media_fmt_alac_t)
 @table{weak__payload__alac__fmt__blk__t} @newpage*

 @par channelLayoutTag constants
 The following constants are extracted when channel layout information is
 present in the bit stream. These constants describe the channel layout
 (for more information, refer to @xhyperref{S4,ISO/IEC 13818-7}).
 @verbatim
 enum
 {
 kALACChannelLayoutTag_Mono         = (100<<16) | 1,   // C
 kALACChannelLayoutTag_Stereo       = (101<<16) | 2,   // L R
 kALACChannelLayoutTag_MPEG_3_0_B   = (113<<16) | 3,   // C L R
 kALACChannelLayoutTag_MPEG_4_0_B   = (116<<16) | 4,   // C L R Cs
 kALACChannelLayoutTag_MPEG_5_0_D   = (120<<16) | 5,   // C L R Ls Rs
 kALACChannelLayoutTag_MPEG_5_1_D   = (124<<16) | 6,   // C L R Ls Rs LFE
 kALACChannelLayoutTag_AAC_6_1      = (142<<16) | 7,   // C L R Ls Rs Cs LFE
 kALACChannelLayoutTag_MPEG_7_1_B   = (127<<16) | 8    // C Lc Rc L R Ls Rs LFE
 };
 @endverbatim
*/

/**
 * Module ID for ALAC decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_ALAC
 */

#define MODULE_ID_ALAC_DEC 0x0700102B
/**
 @h2xmlm_module         {"MODULE_ID_ALAC_DEC", MODULE_ID_ALAC_DEC}
 @h2xmlm_displayName    {"ALAC Decoder"}
 @h2xmlm_description    {This module is used as the decoder for ALAC use cases.\n
                        - This module has only one input and one output port.\n
                        - Payload for media_format_t: payload_media_fmt_alac_t\n
                        - Media format is not directly set on the decoder, it's set on the EP module which
                        propagates it in the data path.\n
                        - Decodes data of format-id = MEDIA_FMT_ID_ALAC\n
                        - Supports following params:\n
						-- PARAM_ID_REMOVE_INITIAL_SILENCE\n
                        -- PARAM_ID_REMOVE_TRAILING_SILENCE\n
                        -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n
                        - Supported Input Media Format\n
                        -- Data format : RAW_COMPRESSED\n
                        -- fmt_id : MEDIA_FMT_ID_ALAC\n
                        -- payload : payload_media_fmt_alac_t\n
                        }
  @h2xmlm_dataMaxInputPorts   {ALAC_DEC_DATA_MAX_INPUT_PORTS}
  @h2xmlm_dataMaxOutputPorts  {ALAC_DEC_DATA_MAX_OUTPUT_PORTS}
  @h2xmlm_dataInputPorts      {IN=ALAC_DEC_DATA_INPUT_PORT}
  @h2xmlm_dataOutputPorts     {OUT=ALAC_DEC_DATA_OUTPUT_PORT}
  @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
  @h2xmlm_isOffloadable       {true}
  @h2xmlm_stackSize           {ALAC_DEC_MODULE_STACK_SIZE}
  @h2xmlm_toolPolicy          {Calibration}
  @{                     <-- Start of the Module -->
  @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
  @h2xmlm_InsertParameter
  @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
  @h2xmlm_InsertStructure
 @}                     <-- End of the Module -->
 */

#endif // _ALAC_DECODER_H_
