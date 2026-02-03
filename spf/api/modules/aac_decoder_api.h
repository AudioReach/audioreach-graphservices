#ifndef AAC_DECODER_API_H_
#define AAC_DECODER_API_H_
/*==============================================================================
  @file aac_decoder_api.h
  @brief This file contains AAC decoder APIs

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

/* Input port ID of AAC module */
#define AAC_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of AAC module */
#define AAC_DEC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of AAC module */
#define AAC_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of AAC module */
#define AAC_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of AAC module */
#define AAC_DEC_MODULE_STACK_SIZE 4096

/** Flag to turn off both SBR and PS processing, if they are present in the
    bit stream */
#define AAC_SBR_OFF_PS_OFF (2)

/** Flag to turn on SBR but turn off PS processing,if they are present in the
    bit stream */
#define AAC_SBR_ON_PS_OFF (1)

/** Flag to turn on both SBR and PS processing, if they are present in the
    bit stream (default behavior) */
#define AAC_SBR_ON_PS_ON (0)

/** First single channel element in a dual mono bit stream */
#define AAC_DUAL_MONO_MAP_SCE_1 (1)

/** Second single channel element in a dual mono bit stream */
#define AAC_DUAL_MONO_MAP_SCE_2 (2)

/** AAC extension audio object type is Low Complexity (LC) */
#define AAC_EXTENSION_AOT_LC 2

/** AAC extension audio object type is SBR */
#define AAC_EXTENSION_AOT_SBR 5

/** AAC extension audio object type is PS */
#define AAC_EXTENSION_AOT_PS 29

/** Use AAC stereo mix coefficients defined in ISO/IEC */
#define AAC_STEREO_MIX_COEFF_ISO (0)

/** Use AAC stereo mix coefficients defined in ARIB */
#define AAC_STEREO_MIX_COEFF_ARIB (1)

/*==============================================================================
   Param ID
==============================================================================*/

/** Parameter ID of the AAC decoder SBR/PS Enable flag */
#define PARAM_ID_AAC_SBR_PS_FLAG 0x08001054

/** @h2xmlp_parameter   {"PARAM_ID_AAC_SBR_PS_FLAG", PARAM_ID_AAC_SBR_PS_FLAG}
    @h2xmlp_description {Parameter for configuring AAC SBR PS processing flag } 
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_aac_sbr_ps_flag_t
{
   uint32_t sbr_ps_flag;
   /**< @h2xmle_description {Control parameter that enables or disables SBR/PS processing in the
                             AAC bit stream. Changes are applied to the next decoded frame}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {"AAC_SBR_OFF_PS_OFF"=2,
                             "AAC_SBR_ON_PS_OFF"=1,
                             "AAC_SBR_ON_PS_ON"=0}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_aac_sbr_ps_flag_t param_id_aac_sbr_ps_flag_t;

/*==============================================================================
   Param ID
==============================================================================*/

/** ID of parameter for configuring AAC decoder dual mono mapping */
#define PARAM_ID_AAC_DUAL_MONO_MAPPING 0x08001055

/** @h2xmlp_parameter   {"PARAM_ID_AAC_DUAL_MONO_MAPPING", PARAM_ID_AAC_DUAL_MONO_MAPPING}
    @h2xmlp_description {Parameter for configuring AAC decoder dual mono channel mapping.
                         This parameter applies only to AAC dual mono bit stream decoding. The
                         command can be sent any time after opening a write or read/write stream,
                         and the changes take effect from the next decoded frame.

                         The same SCE can be routed to both he left and right channels. The
                         following table shows the message payload for AAC dual mono channel
                         mapping, where all the channels are valid.}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_aac_dual_mono_mapping_t
{
   uint16_t left_channel_sce;
   /**< @h2xmle_description {Specifies which SCE is connected to the left channel}
        @h2xmle_default     {1}
        @h2xmle_rangeList   {"AAC_DUAL_MONO_MAP_SCE_1"=1,
                             "AAC_DUAL_MONO_MAP_SCE_2"=2}
        @h2xmle_policy      {Basic} */

   uint16_t right_channel_sce;
   /**< @h2xmle_description {Specifies which SCE is connected to the right channel}
        @h2xmle_default     {1}
        @h2xmle_rangeList   {"AAC_DUAL_MONO_MAP_SCE_1"=1,
                             "AAC_DUAL_MONO_MAP_SCE_2"=2}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct aac_dual_mono_mapping_param_t aac_dual_mono_mapping_param_t;

/*==============================================================================
   Param ID
==============================================================================*/

/** ID of parameter for configuring AAC decoder SBR signalling */
#define PARAM_ID_AAC_SBR_SIGNALLING 0x08001056

/** @h2xmlp_parameter   {"PARAM_ID_AAC_SBR_SIGNALLING", PARAM_ID_AAC_SBR_SIGNALLING}
    @h2xmlp_description {Parameter for configuring AAC decoder SBR signaling.
                         This parameter applies only to AAC bit stream decoding. The command is sent
                         after opening a write or read/write stream and before actual decoding
                         begins. The parameter is used to select the stereo mix coefficients
                         between the ISO/IEC and ARIB standards.
                         Do not send this command during decoding. Such a change can cause
                         glitches in the stereo output.} 
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_aac_sbr_signalling_t
{
   uint32_t extension_aot;
   /**< @h2xmle_description {The extension audio object type in a stream.
                             If this value is set as AAC_EXTENSION_AOT_LC, all remaining fields
                             are ignored and the decoder operates in implicit signaling mode.}
        @h2xmle_default     {2}
        @h2xmle_rangeList   {"AAC_EXTENSION_AOT_LC"=2,
                             "AAC_EXTENSION_AOT_SBR"=5,
                             "AAC_EXTENSION_AOT_PS"=29}
        @h2xmle_policy      {Basic} */

   uint32_t extension_sampling_rate;
   /**< @h2xmle_description {The extension sampling rate}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {INVALID_VALUE=0,8000, 11025, 12000, 16000, 22050, 24000, 32000,
                             44100, 48000, 64000, 88200, 96000}
        @h2xmle_policy      {Basic} */

   uint32_t sbr_present;
   /**< @h2xmle_description {Specifies whether to explicitly assume the presence or absence of the
                             SBR payload in the stream.}
        @h2xmle_rangeList   {"SBR payload is absent"=0;
                             "SBR payload is present"=1}
        @h2xmle_policy      {Basic} */

   uint32_t ps_present;
   /**< @h2xmle_description {Specifies whether to explicitly assume the presence or absence of the
        PS payload in the stream.}
        @h2xmle_rangeList   {"PS payload is absent"=0;
                             "PS payload is present"=1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_aac_sbr_signalling_t param_id_aac_sbr_signalling_t;

/*==============================================================================
   Param ID
==============================================================================*/

/** ID of the AAC decoder Stereo Mixing parameter */
#define PARAM_ID_AAC_STEREO_MIX_COEFF_SELECTION_FLAG 0x08001057

/** @h2xmlp_parameter   {"PARAM_ID_AAC_STEREO_MIX_COEFF_SELECTION_FLAG", PARAM_ID_AAC_STEREO_MIX_COEFF_SELECTION_FLAG}
    @h2xmlp_description {Parameter for configuring AAC decoder Stereo Mixing.
                         This parameter applies only to AAC bit stream decoding. The command is sent
                         after opening a write or read/write stream and before actual decoding
                         begins. The parameter is used to select the stereo mix coefficients
                         between the ISO/IEC and ARIB standards.
                         Do not send this command during decoding. Such a change can cause
                         glitches in the stereo output.}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_aac_stereo_mix_coeff_selection_t
{
   uint32_t aac_stereo_mix_coeff_flag;
   /**< @h2xmle_description {Specifies which standard is used for AAC stereo mix.}
        @h2xmle_rangeList   {"AAC_STEREO_MIX_COEFF_ISO"=0;
                             "AAC_STEREO_MIX_COEFF_ARIB"=1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_aac_stereo_mix_coeff_selection_t param_id_aac_stereo_mix_coeff_selection_t;

/*==============================================================================
   Module
==============================================================================*/

/** @h2xml_title1           {AAC Decoder Module API}
    @h2xml_title_agile_rev  {AAC Decoder Module API}
    @h2xml_title_date       {April 15, 2019} */

/**
 * Module ID for AAC decoder.
 * Decodes data of format-id = MEDIA_FMT_ID_AAC
 */
#define MODULE_ID_AAC_DEC 0x0700101F

/**
    @h2xmlm_module              {"MODULE_ID_AAC_DEC", MODULE_ID_AAC_DEC}
    @h2xmlm_displayName         {"AAC Decoder"}
    @h2xmlm_description         {This module is used as the decoder for AAC use cases.\n
                                 - This module has only one input and one output port.\n
                                 - Payload for media_format_t: payload_media_fmt_aac_t\n
                                 - Media format is not directly set on the decoder, it's set on the EP module which
                                 propagates it in the data path.\n
                                 - Decodes data of format-id = MEDIA_FMT_ID_AAC\n
                                 - Supports following params:\n 
                                 -- PARAM_ID_PCM_OUTPUT_FORMAT_CFG\n 
                                 -- PARAM_ID_AAC_SBR_PS_FLAG\n 
                                 -- PARAM_ID_AAC_DUAL_MONO_MAPPING\n 
                                 -- PARAM_ID_AAC_SBR_SIGNALLING\n 
                                 -- PARAM_ID_AAC_STEREO_MIX_COEFF_SELECTION_FLAG\n
	                             -- PARAM_ID_REMOVE_INITIAL_SILENCE\n
                                 -- PARAM_ID_REMOVE_TRAILING_SILENCE\n
                                 - Supported Input Media Format\n 
                                 -- Data format : RAW_COMPRESSED\n 
                                 -- fmt_id : MEDIA_FMT_ID_AAC\n 
                                 -- payload : payload_media_fmt_aac_t\n
                                 }
    @h2xmlm_dataMaxInputPorts   {AAC_DEC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {AAC_DEC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=AAC_DEC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=AAC_DEC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {AAC_DEC_MODULE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @h2xml_Select               {"media_format_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {media_format_t::data_format}
    @h2xmle_rangeList           {"DATA_FORMAT_RAW_COMPRESSED"=6}
    @h2xmle_default             {0}
    @h2xml_Select               {media_format_t::fmt_id}
    @h2xmle_rangeList           {"Media format ID of AAC"=MEDIA_FMT_ID_AAC}
    @h2xmle_default             {0}
    @h2xml_Select               {"payload_media_fmt_aac_t"}
    @h2xmlm_InsertStructure 
    @h2xml_Select               {"param_id_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"payload_pcm_output_format_cfg_t"}
    @h2xmlm_InsertStructure 
    @h2xml_Select               {"param_id_aac_sbr_ps_flag_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_dual_mono_mapping_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_sbr_signalling_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select               {"param_id_aac_stereo_mix_coeff_selection_t"}
    @h2xmlm_InsertParameter
    @}                          <-- End of the Module -->
*/

#endif // AAC_DECODER_API_H_
