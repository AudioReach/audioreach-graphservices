/*==============================================================================
  @file aptx_adaptive_encoder_api.h
  @brief This file contains aptx Adaptive encoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_ADAPTIVE_ENCODER_API_H_
#define _APTX_ADAPTIVE_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "imcl_spm_intent_api.h"


/* Control port for receiving br info*/
#define COP_ENCODER_FEEDBACK_IN AR_NON_GUID(0xC0000001)

#define SINK_CAPABILITIES_LEN  11 //sink capability bytes

/*==============================================================================
   Parameters
==============================================================================*/

/** ID of the aptx adaptive encoder initialization parameter. This parameter should be set at init time.*/
#define PARAM_ID_APTX_ADAPTIVE_ENC_INIT     0x08001183
/* Structure payload for: PARAM_ID_APTX_ADAPTIVE_ENC_INIT*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_ADAPTIVE_ENC_INIT", PARAM_ID_APTX_ADAPTIVE_ENC_INIT}
    @h2xmlp_description {- Configures the init parameters of the aptX Adaptive R2 Encoder. \n
                         - Configures a number of adaptive encoder parameters after adaptive module is instantiated \n
                         -}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct param_id_aptx_adaptive_enc_init_t
{
    uint32_t  sampleRate;
    /**< @h2xmle_description  { Configures sample rate of incoming PCM audio}
         @h2xmle_rangeList    {"unchanged" = 0;
                               "SRATE_48K" = 1;
                               "SRATE_44K" = 2;
                               "SRATE_96K" = 3}
         @h2xmle_default      {1}   */

    uint32_t  mtulink0;
    /**< @h2xmle_description {Configures MTU size in bytes. A value of 0 means "do not change"}
         @h2xmle_range       {0..1500}
         @h2xmle_default     {675}  */

    int32_t   channelMode0;
    /**< @h2xmle_description  { Configures the channel mode of the aptX Kernel lib}
         @h2xmle_rangeList    {"APTX_CHANNEL_UNCHANGED" = -1;
                               "APTX_CHANNEL_STEREO"    = 0;
                               "APTX_CHANNEL_MONO"      = 1;
                               "APTX_CHANNEL_DUAL_MONO" = 2;
                               "APTX_CHANNEL_STEROO_TWS" = 4;
        "APTX_CHANNEL_EARBUD" = 8}

         @h2xmle_default      {0}   */



    uint32_t  minsinkBufLL;
    uint32_t  maxsinkBufLL;
    uint32_t  minsinkBufHQ;
    uint32_t  maxsinkBufHQ;
    uint32_t  minsinkBufTws;
    uint32_t  maxsinkBufTws;

    /**< @h2xmle_description {Informs the aptX adaptive Encoder of the minimum & maximum buffering,in mS, that \n
                              the A2DP Sink can accept. \n
                              These are the minimum/maximum buffering needed from reception of the packet by the sink to the rendering of the first audio sample of that packet \n
                              For minsinkBufxx, each bit represents 1 mS of audio \n
                              For maxsinkBufxx, each bit represents 4 mS of audio \n
                              minsinkBufxx values default to 20 (20mS) \n
                              maxsinkBufxx values default to 50 (200mS) \n
                              A value of 0 means "unchanged". }

          @h2xmle_range       {0..256}
          @h2xmle_default     {20}  */


    uint32_t  profile;
    /**< @h2xmle_description {Configures aptX Adaptive Primary Profile at initialization time"}
         @h2xmle_rangeList    {"High Quality" = 4096;
                               "Low Latency" = 8192 }
         @h2xmle_default      {4096}   */


    uint32_t  twsplusDualMonoMode;
    /**< @h2xmle_description {Configures startup mode for TWS Plus Adaptive"}
         @h2xmle_rangeList    {"Start in dual mono mode" = 1;
                               "Start in stero mode" = 0 }
         @h2xmle_default      {0}   */


    uint32_t  twsplusFadeDuration;
    /**< @h2xmle_description {Configures fade duration between stereo and dual mono input PCM for TWS Plus Adaptive}

         @h2xmle_range       {1..256}
         @h2xmle_default     {255}  */


    uint8_t   sinkCapability[SINK_CAPABILITIES_LEN];
    /**< @h2xmle_description {Array of SINK_CAPABILITIES_LEN bytes, containing supported decoder configurations, from capability exchange. \n }

         @h2xmle_range       {0..255}
         @h2xmle_default     {0}  */


}

#include "spf_end_pack.h"
;

typedef struct param_id_aptx_adaptive_enc_init_t param_id_aptx_adaptive_enc_init_t;




/** ID of the aptx adaptive encoder profile parameter. This parameter should be set at init time.*/
#define PARAM_ID_APTX_ADAPTIVE_ENC_PROFILE     0x08001184
/* Structure payload for: PARAM_ID_APTX_ADAPTIVE_ENC_PROFILE*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_ADAPTIVE_ENC_PROFILE", PARAM_ID_APTX_ADAPTIVE_ENC_PROFILE}
    @h2xmlp_description {- Configures the Primary & Secondary profiles of aptX Adaptive R2 Encoder. \n
                         - Also configures TTP offsets for LL and HQ profiles. \n
                         -}
    @h2xmlp_toolPolicy  {Calibration}*/


#include "spf_begin_pack.h"

struct param_id_aptx_adaptive_enc_profile_t
{
    uint32_t    primprofile;
    /**< @h2xmle_description {Configures Primary Profile of Adaptive Encoder"}
         @h2xmle_rangeList    {"APTX_PPROFILE_UNCHANGED"      = 0;
                               "APTX_PPROFILE_HIGH_QUALITY_0" = 1;
                               "APTX_PPROFILE_LOW_LATENCY_0"  = 2;
                               "APTX_PPROFILE_LOW_LATENCY_1"  = 4;
                               "APTX_PPROFILE_HIGH_QUALITY_1" = 5 }

         @h2xmle_default      {1}   */

    uint32_t    secprofile;
    /**< @h2xmle_description {Configures Secondary Profile of Adaptive Encoder"}
         @h2xmle_rangeList    {"APTX_SPROFILE_UNCHANGED"    = 0;
                               "APTX_SPROFILE_NONE"         = 1  }

         @h2xmle_default      {1}   */


    uint32_t    LLModeLatTarget0;

    /**< @h2xmle_description {Configures ttp offset for Profile LL-0.\n
                              Each bit represents 1mS of audio. \n
                              A value of 0 means 'do not change'}
         @h2xmle_range       {1..255}
         @h2xmle_default     {60}  */


    uint32_t    LLModeLatTarget1;
    /**< @h2xmle_description {Configures ttp offset for Profile LL-1.\n
                                  Each bit represents 1mS of audio. \n
                                  A value of 0 means 'do not change'}
         @h2xmle_range       {1..255}
         @h2xmle_default     {80}  */


    uint32_t    hQLatTarget0;
    /**< @h2xmle_description {Configures ttp offset for Profile HQ-0.\n
                              Each bit represents 4mS of audio. \n
                              A value of 0 means 'do not change'}
         @h2xmle_range       {1..255}
         @h2xmle_default     {50}  */


    uint32_t    hQLatTarget1;
    /**< @h2xmle_description {Configures ttp offset for Profile HQ-1.\n
                              Each bit represents 4mS of audio. \n
                              A value of 0 means 'do not change'}
         @h2xmle_range       {1..255}
         @h2xmle_default     {50}  */



}

#include "spf_end_pack.h"
;

typedef struct param_id_aptx_adaptive_enc_profile_t param_id_aptx_adaptive_enc_profile_t;



/** ID of the aptx adaptive encoder Source Audio sample rate parameter. This parameter should be set at init time.*/
#define PARAM_ID_APTX_ADAPTIVE_ENC_AUDIOSRC_INFO     0x08001186
/* Structure payload for: PARAM_ID_APTX_ADAPTIVE_ENC_AUDIOSRC_INFO*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_ADAPTIVE_ENC_AUDIOSRC_INFO", PARAM_ID_APTX_ADAPTIVE_ENC_AUDIOSRC_INFO}
    @h2xmlp_description {- Informs R2 Encoder what the sample rate of the original audio being encoded was.\n
                         -
                         -}
    @h2xmlp_toolPolicy  {Calibration}*/


#include "spf_begin_pack.h"

struct param_id_aptx_adaptive_enc_original_samplerate_t
{

    uint16_t original_sample_rate;
    /**< @h2xmle_description  { Informs aptX Adaptive Encoder what sample rate the presented audio originally used.}
         @h2xmle_rangeList    {"No change (same as system setting)" = 0;
                               "44.1KHz" = 1;
                               "48kHz"   = 2;
                               "88.2kHz" = 4;
                               "96kHz"   = 8;
                               "192kHz"  = 16}

         @h2xmle_default      {0}   */

}

#include "spf_end_pack.h"
;

typedef struct param_id_aptx_adaptive_enc_original_samplerate_t param_id_aptx_adaptive_enc_original_samplerate_t;




/** ID of the aptx adaptive encoder Source Audio sample rate parameter. This parameter can be set at run time.*/
#define PARAM_ID_APTX_ADAPTIVE_ENC_SWITCH_TO_MONO     0x08001187
/* Structure payload for: PARAM_ID_APTX_ADAPTIVE_ENC_SWITCH_TO_MONO*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_ADAPTIVE_ENC_SWITCH_TO_MONO", PARAM_ID_APTX_ADAPTIVE_ENC_SWITCH_TO_MONO}
    @h2xmlp_description {- Switches the PCM mix at the input to the R2 Adaptive Encoder.\n
                         -
                         -}
    @h2xmlp_toolPolicy  {Calibration}*/


#include "spf_begin_pack.h"

struct param_id_aptx_adaptive_enc_switch_to_mono_t
{

    uint32_t switch_between_mono_and_stereo;
    /**< @h2xmle_description  { Informs aptX Adaptive Encoder what sample rate the presented audio originally used.}
         @h2xmle_rangeList    {"switch from stereo to double mono" = 1;
                               "switch from double mono to stereo" = 2}

         @h2xmle_default      {2}   */

}

#include "spf_end_pack.h"
;

typedef struct param_id_aptx_adaptive_enc_switch_to_mono_t param_id_aptx_adaptive_enc_switch_to_mono_t;



/*==============================================================================
   Module
==============================================================================*/


/** @h2xml_title1           {aptX Adaptive R2 Encoder}
    @h2xml_title_agile_rev  {aptX Adaptive R2  Encoder}
    @h2xml_title_date       {Oct 31, 2019}
*/
#define MODULE_ID_APTX_ADAPTIVE_ENC 0x07001082
/**
    @h2xmlm_module         {"MODULE_ID_APTX_ADAPTIVE_ENC", MODULE_ID_APTX_ADAPTIVE_ENC}
    @h2xmlm_displayName    {"aptX Adaptive R2 Encoder"}
    @h2xmlm_description    {This module is used as the encoder for aptX Adaptive R2 use cases.\n
                            - This module has only one input and one output port.\n
                            - Payload for param_id_encoder_output_config_t : xxx_enc_cfg_t\n
                            - Encodes data to format-id = 0x00013204\n
                            - Required container capabilities : APM_CONTAINER_CAP_ID_CD\n
                            - Supports following params:\n
                            -- PARAM_ID_ENCODER_OUTPUT_CONFIG\n
                            -- PARAM_ID_ENC_BITRATE\n
                            - Supported Input Media Format:\n
                            -- Data Format : FIXED_POINT\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 44.1, 48 \n
                            -- Number of channels : 2\n
                            -- Bit Width : 32\n
                            -- Bits Per Sample : 24\n
                            -- Q format : Q4.27\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- maximum bit rates in bps:\n
                            --- mono : n\a \n
                            --- stereo : xxxkbps \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_IN" = 0xC0000001,
                                 "Bit rate level encoder feedback intent" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_reqContcapabilities {APM_CONTAINER_CAP_CD}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_aptx_adaptive_enc_init_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_aptx_adaptive_enc_profile_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_aptx_adaptive_enc_original_samplerate_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_aptx_adaptive_enc_switch_to_mono_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif //_APTX_ADAPTIVE_ENCODER_API_H_
