#ifndef _AAC_ENCODER_API_H_
#define _AAC_ENCODER_API_H_
/*==============================================================================
  @file aac_encoder_api.h
  @brief This file contains AAC encoder APIs

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

/* Input port ID of AAC module */
#define AAC_ENC_DATA_INPUT_PORT   0x2

/* Output port ID of AAC module */
#define AAC_ENC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of AAC module */
#define AAC_ENC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of AAC module */
#define AAC_ENC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of AAC module */
#define AAC_ENC_MODULE_STACK_SIZE 4096

/* Max size of cutoff table */
#define MAX_NUM_CUTOFF_LEVELS 6

/* Control port for receiving br info*/
#define COP_ENCODER_FEEDBACK_IN AR_NON_GUID(0xC0000001)

/*==============================================================================
   Parameters
==============================================================================*/
/** ID of the encoder Bit Rate level map parameter.This parameter can be set at run time.*/
#define PARAM_ID_AAC_BIT_RATE_LEVEL_MAP  0x08001312
/* Structure payload for: PARAM_ID_AAC_BIT_RATE_LEVEL_MAP*/
/** @h2xmlp_parameter   {"PARAM_ID_AAC_BIT_RATE_LEVEL_MAP", PARAM_ID_AAC_BIT_RATE_LEVEL_MAP}
    @h2xmlp_description {- Configures the table which maps each bitrate level received to the actual bitrate value \n
                         -> Quality levels are always in ascending order of bit rate
                         -  (even if we add a new level at the bottom in the future) \n
                         -  i.e. a lower quality level always refers to a lower bit rate \n
                         -> For a given bit rate level, the encoder will never encode at a
                         -  bit rate higher than that defined by the corresponding mapping \n
                         -> The mapping table can be sent multiple times on the fly and each time,
                         -  the new table received will be cached and used to set the bitrate for the next frame.}
    @h2xmlp_toolPolicy  {Calibration}*/

/** ID of the encoder cutoff configuration parameter.This parameter can be set at run time.*/
#define PARAM_ID_AAC_CUTOFF_FREQ_CONFIG  0x08001A5C
/* Structure payload for: PARAM_ID_AAC_CUTOFF_FREQ_CONFIG*/
/** @h2xmlp_parameter   {"PARAM_ID_AAC_CUTOFF_FREQ_CONFIG", PARAM_ID_AAC_CUTOFF_FREQ_CONFIG}
    @h2xmlp_description {- Configures the cutoff frequency configuration.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct aac_bitrate_level_map_t
{
   uint32_t level;
  /**< @h2xmle_description {Index of each quality level, since maximum levels supported is 5 this index ranges from 0 to 5}
       @h2xmle_range     {0..5}
       @h2xmle_default   {0}
   */
   uint32_t bitrate;
  /**< @h2xmle_description {Bitrate quality levels determined for ABR for 165kbps peak bitrate}
       @h2xmle_rangeList   {"BIT_RATE_33000"  = 33000;
                            "BIT_RATE_66000"  = 66000;
                            "BIT_RATE_99000"  = 99000;
                            "BIT_RATE_132000" = 132000;
                            "BIT_RATE_165000" = 165000}
       @h2xmle_default     {165000}

   */
}
#include "spf_end_pack.h"
;

typedef struct aac_bitrate_level_map_t aac_bitrate_level_map_t;

#include "spf_begin_pack.h"
struct param_id_aac_bitrate_level_map_payload_t
{
   uint32_t num_levels;
  /**< @h2xmle_description {Number of bitrate quality levels}
       @h2xmle_range       {0..5}
       @h2xmle_default     {0}
   */
#if 0
   aac_bitrate_level_map_t br_lev_tbl[num_levels];
#endif
}
#include "spf_end_pack.h"
;

typedef struct param_id_aac_bitrate_level_map_payload_t param_id_aac_bitrate_level_map_payload_t;

/** @h2xmlp_subStruct */
#include "spf_begin_pack.h"
struct cutoff_freq_level_info_t
{
    uint32_t cutoff_bitrate_low;
    /**< @h2xmle_description {low range of bitrate for a cutoff frequency}
         @h2xmle_range       {0x1F40..0x5DC00}
         @h2xmle_default     {0}
     */
    uint32_t cutoff_bitrate_high;
    /**< @h2xmle_description {higher range of bitrate for a cutoff frequency}
         @h2xmle_range       {0x1F40..0x5DC00}
         @h2xmle_default     {0}
     */
    int32_t  cutoff_freq_value;
    /**< @h2xmle_description {Cutoff frequency value for a bitrate of range [cutoff_bitrate_low, cutoff_bitrate_high]
                              NOTE : Any cutoff frequency above max cutoff frequency will be limited to max cutoff frequency(SR/2).}
         @h2xmle_range       {0..0xFFFFFFFF}
         @h2xmle_default     {0}
     */
}
#include "spf_end_pack.h"
;
typedef struct cutoff_freq_level_info_t cutoff_freq_level_info_t;

#include "spf_begin_pack.h"
struct param_id_aac_enc_cutoff_freq_config_t
{
    uint32_t freq_cutoff_mode;
    /**< @h2xmle_description {Frequency cutoff mode.
                              Mode0 – use to retain existing logic in encoder w.r.t cutoff frequency handling.
                              Mode1 – Use to enable a global cutoff frequency.
                                      For example, for usecases with requirement to limit cutoff frequency to a
                                      particular level irrespective of configuration(sampling rate, bit rate etc.,)
                              Mode2 – Use to enable a cutoff frequency table based on bitrate range.
                                      For example, user can choose to configure different cutoff frequencies for different
                                      bitrate ranges, with upto 6 levels.
                              Mode3 – Use to disable cutoff frequency logic in the encoder.
                                      This will pick max cutoff frequency as default, i.e., half the sampling rate.
                              All other values are reserved. }
         @h2xmle_range       {0x0..0x2}
         @h2xmle_default     {0}
     */
    uint32_t global_cutoff_freq;
    /**< @h2xmle_description {Value of the global cutoff frequency in Hz. This value will be picked as global cutoff
                              frequency when 'freq_cutoff_mode' field is set to 'mode1'.
                              NOTE : Any value above maximum cutoff frequency will be discarded and cutoff frequency
                              will be set to max cutoff frequency.}
         @h2xmle_range       {0..0xFFFFFFFF}
         @h2xmle_default     {0}
     */
    uint32_t num_cutoff_levels;
    /**< @h2xmle_description {Number of cutoff frequency levels mapped to bitrate ranges. This value and immediately
                              following variable size array based on num_cutoff_levels will be chosen for cutoff frequency
                              configuration when 'freq_cutoff_mode' field is set to ‘mode2’.}
         @h2xmle_range       {0..MAX_NUM_CUTOFF_LEVELS}
         @h2xmle_default     {0}
     */
#ifdef __H2XML__
    cutoff_freq_level_info_t cutoff_freq_level_table[0];
    /**< @h2xmle_description {Cutoff frequency level table of size num_cutoff_levels}
     */
#endif //__H2XML__
}
#include "spf_end_pack.h"
;

typedef struct param_id_aac_enc_cutoff_freq_config_t param_id_aac_enc_cutoff_freq_config_t;

/*==============================================================================
   Module
==============================================================================*/
/** @h2xml_title1           {AAC Encoder Module API}
    @h2xml_title_agile_rev  {AAC Encoder Module API}
    @h2xml_title_date       {April 15, 2019} */

/**
 * Module ID for AAC encoder.
 * Encodes to data of format-id = MEDIA_FMT_ID_AAC
 */
#define MODULE_ID_AAC_ENC 0x0700101E

/**
    @h2xmlm_module              {"MODULE_ID_AAC_ENC", MODULE_ID_AAC_ENC}
    @h2xmlm_displayName         {"AAC Encoder"}
    @h2xmlm_modSearchKeys       {Audio, Bluetooth}
    @h2xmlm_description         {This module is used as the encoder for AAC use cases.\n
                                 - This module has only one input and one output port.\n
                                 - Payload for param_id_encoder_output_config_t : aac_enc_cfg_t\n
                                 - Encodes data to format-id = MEDIA_FMT_ID_AAC\n
                                 - Supports following params:\n
                                 -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                                 -- PARAM_ID_ENC_BITRATE\n
                                 -- PARAM_ID_ENC_FRAME_SIZE_CONTROL\n
                                 - Supported Input Media Format:\n
                                 -- Data Format : FIXED_POINT\n
                                 -- fmt_id : Don't care\n
                                 -- Sample Rates: \n
                                 -- AAC-LC mono, stereo: 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48 kHz\n
                                 -- AAC+ mono, stereo: 24, 32, 44.1, 48 kHz\n
                                 -- eAAC+ : 24, 32, 44.1, 48 kHz\n
                                 -- Number of channels : 2\n
                                 -- Bit Width : 16\n
                                 -- Bits Per Sample : 16\n
                                 -- Q format : Q15\n
                                 -- Interleaving : interleaved\n
                                 - Supported bit rates in each configuration :\n
                                 -- minimum bit rates in bps:\n
                                 --- AAC-LC mono : 4000\n
                                 --- AAC-LC stereo : 8000\n
                                 --- AAC+ mono : 10000 for 24/32 kHz. 12000 for 44.1/48kHz\n
                                 --- AAC+ stereo : 18000 for 24/32 kHz. 24000 for 44.1/48kHz\n
                                 --- eAAC+ : 10000 for 24/32 kHz. 12000 for 44.1/48kHz\n
                                 -- maximum bit rates in bps:\n
                                 --- AAC-LC mono : min(192000, 6*fs)\n
                                 --- AAC-LC stereo : min(384000, 12*fs)\n
                                 --- AAC+ mono : min(192000, 6*fs)\n
                                 --- AAC+ stereo : min(192000, 12*fs)\n
                                 --- eAAC+ : min(192000, 6*fs)\n}
    @h2xmlm_dataMaxInputPorts   {AAC_ENC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {AAC_ENC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=AAC_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=AAC_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_IN" = 0xC0000001,
                                 "Bit rate level encoder feedback intent" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {AAC_ENC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_encoder_output_config_t::fmt_id}
    @h2xmle_rangeList           {"Media format ID of AAC"=MEDIA_FMT_ID_AAC}
    @h2xmle_default             {0}
    @h2xml_Select               {"aac_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @h2xml_Select               {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_bitrate_level_map_payload_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_enc_cutoff_freq_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_enc_frame_size_control_t"}
    @h2xmlm_InsertParameter
    @}                          <-- End of the Module -->
*/
/*==============================================================================
   Module
==============================================================================*/
/** @h2xml_title1           {AAC_LC Encoder Module API}
    @h2xml_title_agile_rev  {AAC_LC Encoder Module API}
    @h2xml_title_date       {JULY 02 2021} */

/**
 * Module ID for AAC_LC encoder.
 * Encodes to data of format-id = MEDIA_FMT_ID_AAC
 */
#define MODULE_ID_AAC_LC_ENC 0x070010DF

/**
    @h2xmlm_module              {"MODULE_ID_AAC_LC_ENC", MODULE_ID_AAC_LC_ENC}
    @h2xmlm_displayName         {"AAC_LC Encoder"}
    @h2xmlm_modSearchKeys       {Bluetooth}
    @h2xmlm_description         {This module is used as the encoder for AAC_LC use cases.\n
                                 - This module has only one input and one output port.\n
                                 - Payload for param_id_encoder_output_config_t : aac_enc_cfg_t\n
                                 - Encodes data to format-id = MEDIA_FMT_ID_AAC\n
                                 - Supports following params:\n
                                 -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                                 -- PARAM_ID_ENC_BITRATE\n
                                 -- PARAM_ID_ENC_FRAME_SIZE_CONTROL\n
                                 - Supported Input Media Format:\n
                                 -- Data Format : FIXED_POINT\n
                                 -- fmt_id : Don't care\n
                                 -- Sample Rates: \n
                                 -- AAC-LC mono, stereo: 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48 kHz\n
                                 -- Number of channels : 2\n
                                 -- Bit Width : 16\n
                                 -- Bits Per Sample : 16\n
                                 -- Q format : Q15\n
                                 -- Interleaving : interleaved\n
                                 - Supported bit rates in each configuration :\n
                                 -- minimum bit rates in bps:\n
                                 --- AAC-LC mono : 4000\n
                                 --- AAC-LC stereo : 8000\n
                                 -- maximum bit rates in bps:\n
                                 --- AAC-LC mono : min(192000, 6*fs)\n
                                 --- AAC-LC stereo : min(384000, 12*fs)\n}
    @h2xmlm_dataMaxInputPorts   {AAC_ENC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {AAC_ENC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=AAC_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=AAC_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_IN" = 0xC0000001,
                                 "Bit rate level encoder feedback intent" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {AAC_ENC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_encoder_output_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_encoder_output_config_t::fmt_id}
    @h2xmle_rangeList           {"Media format ID of AAC"=MEDIA_FMT_ID_AAC}
    @h2xmle_default             {0}
    @h2xml_Select               {"aac_enc_cfg_t"}
    @h2xmlm_InsertStructure
    @h2xml_Select               {"param_id_enc_bitrate_param_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_bitrate_level_map_payload_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_enc_cutoff_freq_config_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_enc_frame_size_control_t"}
    @h2xmlm_InsertParameter
    @}                          <-- End of the Module -->
*/

#endif //_AAC_ENCODER_API_H_
