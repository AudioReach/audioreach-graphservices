#ifndef PCM_DECODER_API_H_
#define PCM_DECODER_API_H_
/*==============================================================================
  @file pcm_decoder_api.h
  @brief This file contains PCM decoder APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"
#include "common_enc_dec_api.h"

/** 
    @h2xml_title1           {PCM Decoder Module API}
    @h2xml_title_agile_rev  {PCM Decoder Module API}
    @h2xml_title_date       {March 26, 2019} */

/*------------------------------------------------------------------------------
   Defines
------------------------------------------------------------------------------*/
/* Input port ID of MFC module */
#define PCM_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of MFC module */
#define PCM_DEC_DATA_OUTPUT_PORT  0x1

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/**
 * Module ID for PCM decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_PCM
 */
#define MODULE_ID_PCM_DEC              0x07001005

/**
    @h2xmlm_module         {"MODULE_ID_PCM_DEC",
                            MODULE_ID_PCM_DEC}
    @h2xmlm_displayName    {"PCM Decoder"}
    @h2xmlm_description    {
                            This module is used as the decoder for PCM use cases. \n
                            It can be used to convert properties of PCM stream such as \n
                            endianness, interleaving, bit width, number of channels etc. \n
                            It cannot be used to convert sampling rate. \n
                            This module has only one input and one output port. \n
                            Media format for this module is propagated from \n
                            Write Shared Memory End Point (No need to set on this module) \n
                            - This module supports following parameter IDs: \n
                            -#PARAM_ID_PCM_OUTPUT_FORMAT_CFG \n
                            - \n
                            Supported Input Media Format: \n
                            - Data Format          : FIXED_POINT
                            - fmt_id               : MEDIA_FMT_ID_PCM \n
                            - Sample Rates         : 1-384 kHz \n
                            - Number of channels   : 1-32 \n
                            - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                                   : 24 (bits per sample 24 and Q23, \n
                                                     bits per sample 32 and Q23 or Q27 or Q31), \n
                                                   : 32 (bits per sample 32 and Q31) \n
                            - Interleaving         : interleaved, deinterleaved unpacked, \n
                                                    deinterleaved packed. \n
                            - Endianess            : little, big \n
                            }
    @h2xmlm_dataMaxInputPorts           {1}
    @h2xmlm_dataMaxOutputPorts          {1}
    @h2xmlm_dataInputPorts              {IN=PCM_DEC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts             {OUT=PCM_DEC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes         {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable               {true}
    @h2xmlm_stackSize                   { 4096 }
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/


#endif // PCM_DECODER_API_H_
