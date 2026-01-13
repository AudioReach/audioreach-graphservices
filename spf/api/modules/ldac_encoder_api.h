#ifndef _LDAC_ENCODER_API_H_
#define _LDAC_ENCODER_API_H_
/*==============================================================================
  @file aac_encoder_api.h
  @brief This file contains LDAC encoder APIs

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
#include "imcl_fwk_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of LDAC module */
#define LDAC_ENC_DATA_INPUT_PORT   0x2

/* Output port ID of LDAC module */
#define LDAC_ENC_DATA_OUTPUT_PORT  0x1

/* Stack size of LDAC module */
#define LDAC_ENC_MODULE_STACK_SIZE 8192

/* Control port for receiving br info*/
#define COP_ENCODER_FEEDBACK_IN AR_NON_GUID(0xC0000001)
/*==============================================================================
   Parameters
==============================================================================*/
/** ID of the encoder Bit Rate level map parameter.This parameter can be set at run time.*/
#define PARAM_ID_LDAC_BIT_RATE_LEVEL_MAP  0x08001171
/* Structure payload for: PARAM_ID_LDAC_BIT_RATE_LEVEL_MAP*/
/** @h2xmlp_parameter   {"PARAM_ID_LDAC_BIT_RATE_LEVEL_MAP", PARAM_ID_LDAC_BIT_RATE_LEVEL_MAP}
    @h2xmlp_description {- Configures the table which maps each bitrate level received to the actual bitrate value \n
                         -> Quality levels are always in ascending order of bit rate
                         -  (even if we add a new level at the bottom in the future) \n
                         -  i.e. a lower quality level always refers to a lower bit rate \n
                         -> For a given bit rate level, the encoder will never encode at a
                         -  bit rate higher than that defined by the corresponding mapping \n
                         -> The mapping table can be sent multiple times on the fly and each time,
                         -  the new table received will be cached and used to set the bitrate for the next frame.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct bitrate_level_map_t
{
   uint32_t level;
  /**< @h2xmle_description {Index of each quality level, since maximum levels supported is 7 this index ranges from 0 to 7}
       @h2xmle_range     {0..7}
       @h2xmle_default   {0}
   */
   uint32_t bitrate;
  /**< @h2xmle_description {Bit-rate values supported by ldac encoder}
       @h2xmle_rangeList   {"BIT_RATE_909000" = 909000;
                            "BIT_RATE_606000" = 606000;
                            "BIT_RATE_452000" = 452000;
                            "BIT_RATE_363000" = 363000;
                            "BIT_RATE_303000" = 303000;
                            "BIT_RATE_990000" = 990000;
                            "BIT_RATE_660000" = 660000;
                            "BIT_RATE_492000" = 492000;
                            "BIT_RATE_396000" = 396000;
                            "BIT_RATE_330000" = 330000}
       @h2xmle_default     {330000}
   */
}
#include "spf_end_pack.h"
;

typedef struct bitrate_level_map_t bitrate_level_map_t;

#include "spf_begin_pack.h"
struct param_id_ldac_bitrate_level_map_payload_t
{
   uint32_t num_levels;
  /**< @h2xmle_description {Number of bitrate quality levels}
       @h2xmle_range       {0..7}
       @h2xmle_default     {0}
   */
#if 0
   bitrate_level_map_t br_lev_tbl[num_levels];
#endif
}
#include "spf_end_pack.h"
;

typedef struct param_id_ldac_bitrate_level_map_payload_t param_id_ldac_bitrate_level_map_payload_t;

/*==============================================================================
   Module
==============================================================================*/
/** @h2xml_title1           {LDAC Encoder Module API}
    @h2xml_title_agile_rev  {LDAC Encoder Module API}
    @h2xml_title_date       {July 15, 2019} */

/**
 * Module ID for LDAC encoder.
 * Encodes to data of format-id = MEDIA_FMT_ID_LDAC
 */
#define MODULE_ID_LDAC_ENC 0x0700107A

/**
    @h2xmlm_module              {"MODULE_ID_LDAC_ENC", MODULE_ID_LDAC_ENC}
    @h2xmlm_displayName         {"LDAC Encoder"}
    @h2xmlm_description         {This module is used as the encoder for LDAC use cases.\n
                                 - This module has only one input and one output port.\n
                                 - Encodes data to format-id = MEDIA_FMT_ID_LDAC\n
                                 - Supports following params:\n
                                 -- PARAM_ID_ENC_OUTPUT_CONFIG
                                 -- PARAM_ID_ENC_BITRATE\n
                                 -- PARAM_ID_BIT_RATE_LEVEL_MAP\n
                                 - Supported Input Media Format:\n
                                 -- Data Format : FIXED_POINT\n
                                 -- fmt_id : Don't care\n
                                 -- Sample Rates and corresponding bitrates: \n
                                 -- For sampling rates = 44.1KHz, 88.2KHz:
                                 -- bit rates: 909, 606, 452, 363, 303 Kbps
                                 -- For sampling rates = 48KHz, 96KHz:
                                 -- bit rates: 990, 660, 492, 396, 330 Kbps
                                 -- Number of channels : 1, 2\n
                                 -- Bit Width : 16, 24, 32\n
                                 -- Bits Per Sample : 16, 24, 32\n
                                 -- Q format : Q15, Q23, Q31\n
                                 -- Interleaving : interleaved\n}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN=LDAC_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=LDAC_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_IN" = 0xC0000001,
                                 "Bit rate level encoder feedback intent" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {LDAC_ENC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->

    @h2xml_Select               {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_enc_bitrate_param_t::bitrate}
    @h2xmle_rangeList           {"990000"= 990000;
    							 "909000"= 909000;
								 "660000"= 660000;
								 "606000"= 606000;
								 "492000"= 492000;
								 "452000"= 452000;
								 "396000"= 396000;
								 "363000"= 363000;
								 "330000"= 330000;
								 "303000"= 303000}
	@h2xmle_default             {330000}
    @h2xml_Select               {"param_id_ldac_bitrate_level_map_payload_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"ldac_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @}                          <-- End of the Module -->
*/

#endif //_LDAC_ENCODER_API_H_
