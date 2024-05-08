/*==============================================================================
  @file aptx_adaptive_swb_encoder_api.h
  @brief This file contains aptx Adaptive SWB Encoder APIs

  Copyright (c) Qualcomm Innovation Center, Inc. All rights reserved.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _APTX_ADAPTIVE_SWB_ENCODER_API_H_
#define _APTX_ADAPTIVE_SWB_ENCODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "imcl_spm_intent_api.h"


/* Control port for receiving br info*/
//#define COP_ENCODER_FEEDBACK_IN MM_NON_GUID(0xC0000001)


/*==============================================================================
   Parameters
==============================================================================*/
/** ID of the aptx adaptive SWB Speech encoder initialization parameter. This parameter should be set at init time.*/
#define PARAM_ID_APTX_ADAPTIVE_SPEECH_ENC_INIT        0x0800118D
/* Structure payload for: PARAM_ID_APTX_ADAPTIVE_SPEECH_ENC_INIT*/
/** @h2xmlp_parameter   {"PARAM_ID_APTX_ADAPTIVE_SPEECH_ENC_INIT", PARAM_ID_APTX_ADAPTIVE_SPEECH_ENC_INIT}
    @h2xmlp_description {- Configures the init parameters of the aptX Adaptive SWB Speech Encoder. \n
                         -}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct param_id_aptx_adaptive_speech_enc_init_t
{
    uint32_t  speechMode;
    /**< @h2xmle_description  { Configures the Speech mode used by the aptX Kernel library \n
                                - note that both modes use a frame interval of 7.5mS.}
         @h2xmle_rangeList    {"SWB Speech at 32kHz sample rate and 60 byte payload" = 0;
                               "SSWB Speech at 24kHz sample rate and 60 byte payload" = 4}
         @h2xmle_default      {0}   */

    uint32_t  byteSwap;
    /**< @h2xmle_description {Configures byte-swap of output buffer. \n
                              If enabled, transforms AABBCCDD to DDCCBBAA}
         @h2xmle_rangeList    {"Byte swap disabled" = 0;
                               "Byte swap enabled" = 1}
         @h2xmle_default      {0}   */

}

#include "spf_end_pack.h"
;

typedef struct param_id_aptx_adaptive_speech_enc_init_t param_id_aptx_adaptive_speech_enc_init_t;





/** @h2xml_title1           {aptX Adaptive R2 SWB Encoder}
    @h2xml_title_agile_rev  {aptX Adaptive R2 SWB Encoder}
    @h2xml_title_date       {Nov 21, 2019}
*/
#define MODULE_ID_APTX_ADAPTIVE_SWB_ENC 0x07001084
/**
    @h2xmlm_module         {"MODULE_ID_APTX_ADAPTIVE_SWB_ENC", MODULE_ID_APTX_ADAPTIVE_SWB_ENC}
    @h2xmlm_displayName    {"aptX Adaptive R2 SWB Speech Encoder"}
    @h2xmlm_description    {This module is used as the encoder for aptX Adaptive R2 SWB Speech use cases.\n
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
    @h2xmlm_reqContcapabilities {APM_CONTAINER_CAP_CD}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_aptx_adaptive_speech_enc_init_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif //_APTX_ADAPTIVE_SWB_ENCODER_API_H_
