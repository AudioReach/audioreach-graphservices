/*==============================================================================
  @file lc3_decoder_api.h
  @brief This file contains LC3 1.0 decoder APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

#ifndef _LC3_DECODER_API_H_
#define _LC3_DECODER_API_H_

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "imcl_fwk_intent_api.h"

/*==============================================================================
   Parameters
==============================================================================*/

/** ID of the LC3 Dec_Init parameter.This parameter should be set at init time.*/
#define PARAM_ID_LC3_DEC_INIT  0x080012F8

/** @h2xmlp_subStruct */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct __attribute__((__packed__)) lc3_config_t
{
    uint32_t  api_version;
    /**< @h2xmle_description {informs the LC3 Decoder CAPI of api_version. Currently ignored by the CAPI}
         @h2xmle_range       {0..1}
         @h2xmle_default     {0}
       */
    uint32_t  sampling_Frequency;
    /**< @h2xmle_description {sets the LC3 Decoder input sample rate in Hz.}
         @h2xmle_range       {8000..48000}
         @h2xmle_default     {48000}
       */
    uint32_t  max_octets_per_frame;
    /**< @h2xmle_description {sets the LC3 Decoder max octets per encoded frame}
         @h2xmle_range       {60..600}
         @h2xmle_default     {155}
       */
    uint32_t  frame_duration;
    /**< @h2xmle_description {sets the LC3 Decoder output frame duration}
         @h2xmle_rangeList   {7500, 10000}
         @h2xmle_default     {10000}
       */
    uint32_t  bit_depth;
    /**< @h2xmle_description {sets the LC3 Decoder input PCM bits per sample}
         @h2xmle_rangeList   {16, 24}
         @h2xmle_default     {24}
       */
    uint32_t  num_blocks;
    /**< @h2xmle_description {sets the LC3 Decoder output blocks per SDU}
         @h2xmle_range        {1..2}
         @h2xmle_default     {1}
       */
    uint8_t   default_q_level;
    /**< @h2xmle_description {sets the LC3 Decoder qlevel, which sets the bit error resilience level}
         @h2xmle_rangeList   {0, 1, 2, 3}
         @h2xmle_default     {3}
       */
    uint8_t   vendor_specific[16];
    /**< @h2xmle_description {carries BT host capability exchange bytes to LC3 Decoder}
         @h2xmle_range       {0..255}
         @h2xmle_default     {0}
       */
    uint32_t  mode;
    /**< @h2xmle_description {sets the LC3 Decoder unicast or broadcast mode}
         @h2xmle_range       {0..1}
         @h2xmle_default     {0}
       */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct lc3_config_t lc3_config_t;


/** @h2xmlp_subStruct */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct __attribute__((__packed__)) stream_map_t
{
    uint32_t audio_location;
    /**< @h2xmle_description {sets the input PCM channel mask part of stream map triplet}
         @h2xmle_rangeList   {0, 1, 2, 3}
         @h2xmle_default     {3}
       */
    uint8_t stream_id;
    /**< @h2xmle_description {sets the input or output stream id for a triplet}
         @h2xmle_range       {0..255}
         @h2xmle_default     {0}
       */
    uint8_t direction;
    /**< @h2xmle_description {sets to air or from air for the triplet}
         @h2xmle_range        {0..1}
         @h2xmle_default     {0}
       */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct stream_map_t stream_map_t;


/* Structure payload for: PARAM_ID_LC3_DEC_INIT*/
/** @h2xmlp_parameter   {"PARAM_ID_LC3_DEC_INIT", PARAM_ID_LC3_DEC_INIT}
    @h2xmlp_description { Configures the parameters of the LC3 Decoder after the module has been instantiated. }
    @h2xmlx_expandStructs  {false}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_lc3_decoder_config_payload_t
{
    lc3_config_t fromAirConfig;

    uint32_t decoder_output_channel;
    /**< @h2xmle_description {sets the LC3 decoder output number of channels}
         @h2xmle_range       {1..2}
         @h2xmle_default     {2}
       */

    uint32_t stream_map_size;
    /**< @h2xmle_description {The size - in triplets - of the stream map entity(s) that follows this element. Each stream map entity has 3 elements - audio location, stream-id, and direction}
         @h2xmle_range       {1..2}
         @h2xmle_default     {2}
       */

    stream_map_t streamMapIn[0];

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_lc3_decoder_config_payload_t param_id_lc3_decoder_config_payload_t;



/*==============================================================================
   Module
==============================================================================*/


/** @h2xml_title1           {LC3  Decoder}
    @h2xml_title_agile_rev  {LC3  Decoder}
    @h2xml_title_date       {November 27th, 2020}
*/
#define MODULE_ID_LC3_DEC 0x070010C2
/**
    @h2xmlm_module         {"MODULE_ID_LC3_DEC", MODULE_ID_LC3_DEC}
    @h2xmlm_displayName    {"LC3 1.0 Decoder"}
    @h2xmlm_description    {This module is used as the decoder for LC3 use cases.\n
                            - This module has only one input and one output port.\n
                            - The input media format is Deinterleaved Raw Compressed\n
                            - This module should be used in the same subgraph as the CoPv2 Depacketizer\n
                            - Supports following params:\n
                            --  PARAM_ID_LC3_DEC_INIT \n
                            - Supported Input Media Format:\n
                            -- Data Format : CAPI_V2_DEINTERLEAVED_RAW_COMPRESSED\n
                            -- fmt_id : Don't care\n
                            -- Sample Rates: 0 (native mode), 48,44.1, 32, 24, 16, 8 \n
                            -- Number of channels : 1, 2\n
                            -- Bit Width : 16\n
                            -- Bits Per Sample : 32\n
                            -- Q format : Q31\n
                            -- Interleaving : interleaved\n
                            - Supported bit rates in each configuration :\n
                            -- maximum bit rates in bps:\n
                            -- mono : depends on selected LC3 frame duration and sample rate  \n
                            -- stereo : depends on selected LC3 frame duration and sample rate \n }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN0=2}
    @h2xmlm_dataOutputPorts     {OUT0=1}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {lc3_config_t}
    @h2xmlm_InsertParameter
    @h2xml_Select          {stream_map_t}
    @h2xmlm_InsertParameter
    @h2xml_Select          {param_id_lc3_decoder_config_payload_t}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->

*/

#endif //_LC3_DECODER_API_H_
