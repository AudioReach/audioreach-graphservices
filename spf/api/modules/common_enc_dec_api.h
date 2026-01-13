#ifndef COMMON_ENC_DEC_API_H
#define COMMON_ENC_DEC_API_H
/**
 * \file common_enc_dec_api.h
 * \brief 
 *  	 This file contains media format IDs and definitions
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

/** @h2xml_title1           {Common APIs for Encoders and Decoders}
    @h2xml_title_agile_rev  {Common APIs for Encoders and Decoders}
    @h2xml_title_date       {August 13, 2018} */
/**
   @h2xmlx_xmlNumberFormat {int}
*/

/**
 * Parameter for setting the real module ID for the placeholder modules.
 */
#define PARAM_ID_REAL_MODULE_ID                    0x0800100B

/** @h2xmlp_parameter   {"PARAM_ID_REAL_MODULE_ID", PARAM_ID_REAL_MODULE_ID}
    @h2xmlp_description {Parameter for setting the real module ID for the placeholder modules.
                         }
    @h2xmlp_toolPolicy  {Calibration} */
#include "spf_begin_pack.h"
struct param_id_placeholder_real_module_id_t
{
   uint32_t real_module_id;
    /**< @h2xmle_description {ID of the real module-ID to be used in place of placeholder module.
     *                          E.g. MODULE_ID_AAC_DEC or MODULE_ID_AAC_ENC, etc}
         @h2xmle_default     {0} 
         @h2xmle_range       {0..0xFFFFFFFF}
         @h2xmle_policy      {Basic} 
    */   
}
#include "spf_end_pack.h"
;
typedef struct param_id_placeholder_real_module_id_t param_id_placeholder_real_module_id_t;


/* This parameter is supported by MODULE_ID_PLACEHOLDER_ENCODER, MODULE_ID_PLACEHOLDER_DECODER modules.
*
* After setting the real-module-id to the placeholder using PARAM_ID_REAL_MODULE_ID
* the module is no longer a placeholder. Any set/get API directly goes to the CAPI.
* This API can be used to reset the placeholder module.
* The reset involves destroying the current real-module-id. After resetting, the
* PARAM_ID_REAL_MODULE_ID can be sent again.
* After reset, module regains placeholder-state  
*
* No Payload
*/
#define PARAM_ID_RESET_PLACEHOLDER_MODULE          0x08001173


/**
 * ID of the placeholder encoder
 *
 * Place holder module can be replaced only once.
 * Any set param issued to the real module before PARAM_ID_REAL_MODULE_ID is set is cached.
 */
#define MODULE_ID_PLACEHOLDER_ENCODER              0x07001008
/**
    @h2xmlm_module         {"MODULE_ID_PLACEHOLDER_ENCODER", MODULE_ID_PLACEHOLDER_ENCODER}
    @h2xmlm_displayName    {"Placeholder Encoder"}
    @h2xmlm_description    {To alleviate the need of creating a graph for every encoder a placeholder module is used. 
                            The graph definition contains the placeholder module-id. It is replaced by the real encoder module before graph is started (if enabled). \n
                            PARAM_ID_REAL_MODULE_ID is used to replace with real module. Placeholder module can be replaced only once. 
                            Any set param issued to the real module before PARAM_ID_REAL_MODULE_ID is set is cached. 
                            PARAM_ID_MODULE_ENABLE is used to enable or disable the module. When disabled, modue is bypassed. \n
                          -# Supports PARAM_ID_REAL_MODULE_ID \n
                           *- Supported Input Media Format: See supported media formats of the encoder modules.
                            }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataOutputPorts     {OUT=1}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           { 1024 }
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module --> 
    @h2xml_Select          {"param_id_placeholder_real_module_id_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy     {Calibration}
    @h2xml_Select          {param_id_module_enable_t::enable}
    @h2xmle_default        {1}
    @}                     <-- End of the Module --> 
*/

/**
 * ID of the placeholder decoder
 *
 * Place holder module can be replaced only once.
 * Any set param issued to the real module before PARAM_ID_REAL_MODULE_ID is set is cached.
 */
#define MODULE_ID_PLACEHOLDER_DECODER              0x07001009
/**
    @h2xmlm_module        {"MODULE_ID_PLACEHOLDER_DECODER", MODULE_ID_PLACEHOLDER_DECODER}
    @h2xmlm_displayName   {"Placeholder Decoder"}
    @h2xmlm_description   {To alleviate the need of creating a graph for every decoder a placeholder module is used. 
                           The graph definition contains the placeholder module-id. It is replaced by the real decoder module before graph is started . \n
                           PARAM_ID_REAL_MODULE_ID is used to replace with real module. Place holder module can be replaced only once. 
                           Any set param issued to the real module before PARAM_ID_REAL_MODULE_ID is set is cached. 
                           PARAM_ID_MODULE_ENABLE is used to enable or disable the module. When disabled, modue is bypassed.\n
                          -# Supports PARAM_ID_REAL_MODULE_ID \n
                           *- Supported Input Media Format:  - Data format: DATA_FORMAT_RAW_COMPRESSED . 
                             See supported media formats of the decoder modules.
                            }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataOutputPorts     {OUT=1}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { 1024 }
    @h2xmlm_toolPolicy          {Calibration}
    @{                     <-- Start of the Module -->                                      
    @h2xml_Select          {"param_id_placeholder_real_module_id_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter
    @h2xmlp_toolPolicy     {Calibration}
    @h2xml_Select               {param_id_module_enable_t::enable}
    @h2xmle_default             {1}
    @}                     <-- End of the Module --> 
*/

/**
 * Param-ID to configure the PCM output format of PCM encoder, decoder or converter.
 *
 * Example scenarios that need this parameter are
 * 1. decoder -> converter: This param must be set on both decoder and converter.
 *    The converter will act as back-up for the decoder.
 *    If decoder is not configured for 24 bit output and it outputs 16 bit,
 *       then using converter to get 24b bit doesn't give any benefit.
 * 2. converter -> encoder: This param must be set on converter only.
 * 3. converter use cases in PP/EP containers (E.g. pull mode/push mode).
 */
#define PARAM_ID_PCM_OUTPUT_FORMAT_CFG             0x08001008

/** @h2xmlp_parameter   {"PARAM_ID_PCM_OUTPUT_FORMAT_CFG", PARAM_ID_PCM_OUTPUT_FORMAT_CFG}
    @h2xmlp_description {Param-ID to configure the PCM output format of PCM encoder, decoder or converter.
                         Example scenarios that need this parameter are:\n\n
                         --  decoder -> pcm converter: This param must be set on both decoder and converter.
                            The converter will act as back-up for the decoder. E.g. for 24 bit output, both decoder 
                            and converter are configured to have 24 bit output. In case the decoder can output at 24 bit, then
                            converter is pass-through. Otherwise, converter will do 16 to 24 bit conversion.\n\n
                         -- pcm converter -> encoder: This param must be set on converter only.\n\n
                         -- pcm converter use cases in PP/EP containers (E.g. pull mode/push mode).\n\n
                         
                         - Overall struct contains:\n
                            -- param_id_pcm_output_format_cfg_t pcfg;\n
                            -- uint8_t payload[payload_size]\n
                         -\n
                         }
    @h2xmlp_toolPolicy  {Calibration} */
    
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_pcm_output_format_cfg_t
{
   uint32_t data_format;
    /**< @h2xmle_description {Format of the data} 
         @h2xmle_default     {0} 
         @h2xmle_rangeList   {"INVALID_VALUE"=0,
                              "DATA_FORMAT_FIXED_POINT"=1}
         @h2xmle_policy      {Basic} */

   uint32_t fmt_id;
    /**< @h2xmle_description {Format ID of the data stream} 
         @h2xmle_default     {0} 
         @h2xmle_rangeList   {"INVALID_VALUE"=0,
                              "Media format ID of PCM"=MEDIA_FMT_ID_PCM}
         @h2xmle_policy      {Basic} */  

   uint32_t payload_size;
    /**< @h2xmle_description {Size of the payload immediately following this structure.\n
                              The struct of payload is defined by combination of data_format and fmt_id.
                              E.g. PCM fixed point (payload_pcm_output_format_cfg_t) and floating point may have different payloads.
                              This size does not include bytes added for 32-bit alignment.} 
         @h2xmle_default     {0} 
         @h2xmle_range       {0..0xFFFFFFFF}
         @h2xmle_policy      {Basic} */   
#if defined(__H2XML__)
   uint8_t  payload[0];
    /**< 
         @h2xmle_description {Payload} 
         h2xmle_rangeList   {"For fmt_id = PARAM_ID_PCM_OUTPUT_FORMAT_CFG and data_format=DATA_FORMAT_FIXED_POINT"=payload_pcm_output_format_cfg_t}
         @h2xmle_policy      {Basic} 
         @h2xmle_variableArraySize {payload_size}*/
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct param_id_pcm_output_format_cfg_t param_id_pcm_output_format_cfg_t;

/** @h2xmlp_subStruct
    @h2xmlp_description {Payload for PARAM_ID_PCM_OUTPUT_FORMAT_CFG when fmt_id is MEDIA_FMT_ID_PCM and data_format is fixed point.\n
                         * Overall struct is:\n
                         * [\n
                         *    payload_pcm_output_format_cfg_t cfg;\n
                         *    uint8_t channel_mapping[num_channels];\n
                         *    uint8_t 32bit_padding[if_any];\n
                         * ]\n
                         *\n
                         * Note: inconsistent configuration results in error.\n
                         * E.g. if bit width is 16, then Q format cannot be 27.\n
                         * E.g. bit width, bits per sample, alignment, q format are related. Hence, if one is native, others must also be native,\n
                         * if one is unset, others must be unset.\n
                        }
    @h2xmlp_toolPolicy  {Calibration} */
    
/**
 * Payload for PARAM_ID_PCM_OUTPUT_FORMAT_CFG when fmt_id is MEDIA_FMT_ID_PCM and data_format is fixed point.
 *
 * Overall struct is:
 * {
 *    payload_pcm_output_format_cfg_t cfg;
 *    uint8_t channel_mapping[num_channels];
 *    uint8_t 32bit_padding[if_any];
 * }
 *
 * Note: inconsistent configuration results in error.
 * E.g. if bit width is 16, then Q format cannot be 27.
 * E.g. bit width, bits per sample, alignment, q format are related. Hence, if one is native, others must also be native,
 * if one is unset, others must be unset.
 */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct payload_pcm_output_format_cfg_t
{
   int16_t bit_width;
   /**< @h2xmle_description {bit width of each sample. E.g. 16 bit, 24 bit or 32 bit}
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              ""=16;
                              ""=24;
                              ""=32}
        @h2xmle_policy      {Basic} */  

   int16_t alignment;
   /**< @h2xmle_description {Indicates the alignment of bits_per_sample in sample_word_size. \n
                             Relevant only when bits_per_sample is 24 and word_size is 32
                             For bits_per_sample 24, word_size 32, qfactor 23 -> PCM_LSB_ALIGNED \n
                             For bits_per_sample 24, word_size 32, qfactor 31 -> PCM_MSB_ALIGNED}
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              "PCM_LSB_ALIGNED"=1;
                              "PCM_MSB_ALIGNED"=2}        
        @h2xmle_policy      {Basic} */        

   int16_t bits_per_sample;
   /**< 
        @h2xmle_description {Bits needed to store one sample.
                             - 16-bits per sample always contain 16-bit samples.
                             - 24-bits per sample always contain 24-bit samples.
                             - 32-bits per sample have below cases:
                               - If bit width = 24 and alignment = LSB aligned, then
                                  24-bit samples are placed in the lower 24 bits of a 32-bit word.
                                  Upper bits may or may not be sign-extended.
                               - If bit width = 24 and alignment = MSB aligned, then
                                  24-bit samples are placed in the upper 24 bits of a 32-bit word.
                                  Lower bits may or may not be zeroed.
                               - If bit width = 32, 32-bit samples are placed in the
                                 32-bit words
                            } 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              ""=16;
                              ""=24;
                              ""=32
                            }           
        @h2xmle_policy      {Basic} */  
        
   int16_t q_factor;
   /**< @h2xmle_description {Q factor of the PCM data.
                             15 for 16 bit signed data
                             23 for 24 bit signed packed (24 word size) data
                             27 for LSB aligned 24 bit unpacked (32 word size) signed data used internal to spf.
                             31 for MSB aligned 24 bit unpacked (32 word size) signed data
                             23 for LSB aligned 24 bit unpacked (32 word size) signed data
                             31 for 32 bit signed data} 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              ""=15;
                              ""=23;
                              ""=24;
                              ""=27;
                              ""=31
                            }          
        @h2xmle_policy      {Basic} */  
        

   int16_t endianness;
   /**< @h2xmle_description {Indicates whether PCM samples are stored in little endian or big endian format.} 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              "PCM_LITTLE_ENDIAN"=1;
                              "PCM_BIG_ENDIAN"=2
                            }             
        @h2xmle_policy      {Basic} */  
        
   int16_t interleaved;
   /**< @h2xmle_description {Data is interleaved or not} 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0; 
                              "PCM_INTERLEAVED"=1;
                              "PCM_DEINTERLEAVED_PACKED"=2;        
                              "PCM_DEINTERLEAVED_UNPACKED"=3
                            }
        @h2xmle_policy      {Basic} */  
        
   int16_t reserved;
   /**< @h2xmle_description {Reserved for alignment; must be set to zero} 
        @h2xmle_default     {0} 
        @h2xmle_policy      {Basic} */    

   int16_t num_channels;
   /**< @h2xmle_description {Number of channels} 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { "PARAM_VAL_UNSET"=-2;
                              "PARAM_VAL_NATIVE"=-1; 
                              "PARAM_VAL_INVALID"=0
                            }        
        @h2xmle_rangeEnum   {pcm_channel_map}
        @h2xmle_policy      {Basic} */     
#if defined(__H2XML__)
   uint8_t channel_mapping[0];
   /**< @h2xmle_description {Channel mapping array of variable size. 
                             Size of this array depends upon number of channels. 
                             Channel[i] mapping describes channel i. Each element i of the array
                             describes channel i inside the buffer where i is less than num_channels.
                             An unused channel is set to 0.} 
        @h2xmle_variableArraySize {num_channels}                             
        @h2xmle_default     {0} 
        @h2xmle_policy      {Basic} */
#endif

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct payload_pcm_output_format_cfg_t payload_pcm_output_format_cfg_t;

/** ID of the parameter used to configure the encoder bit rate */
#define PARAM_ID_ENC_BITRATE 0x08001052


/** @h2xmlp_parameter   {"PARAM_ID_ENC_BITRATE", PARAM_ID_ENC_BITRATE}
    @h2xmlp_description {Parameter for setting the bit rate on the encoder module}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_enc_bitrate_param_t
{
   uint32_t bitrate;
   /**< @h2xmle_description {Defines bit rate in bits per second}
    *   @h2xmle_range       {1..1536000}
	@h2xmle_default     {1}*/
}
#include "spf_end_pack.h"
;
typedef struct param_id_enc_bitrate_param_t param_id_enc_bitrate_param_t;

/** ID of the parameter used to configure the AAC encoder frame size */
#define PARAM_ID_ENC_FRAME_SIZE_CONTROL 0x08001053

/** @h2xmlp_parameter   {"PARAM_ID_ENC_FRAME_SIZE_CONTROL", PARAM_ID_ENC_FRAME_SIZE_CONTROL}
    @h2xmlp_description {Parameter for configuring the frame control on the encoder module} 
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
struct param_id_enc_frame_size_control_t
{
   uint32_t frame_size_control_type;
   /**< @h2xmle_description {type of frame size control.}
        @h2xmle_rangeList   {"MTU_SIZE"=0;
                             "PEAK_BIT_RATE"=1;
							 "BIT_RATE_MODE"=2}
        @h2xmle_policy      {Basic} */

   uint32_t frame_size_control_value;
   /**< @h2xmle_description {vaue of frame size control.
                             - MTU_SIZE: MTU size in bytes as per the connected BT sink device.
                               NOTE: Expectation is that mtu_size is >= 'frame size'.
                             - PEAK_BIT_RATE: Peak bit rate in bits/second.
                               Eg : 96000 if 96kbps is the peak bitrate to be set.
                               Assumption is that peak bit rate set is > configured bitrate.
							   BIT_RATE_MODE: Bit rate mode such as Constant
							 - Bit Rate (CBR), Variable Bit Rate (VBR) etc.,
								a)	0: Default(CBR)
								b)	1: VBR}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;
typedef struct param_id_enc_frame_size_control_t param_id_enc_frame_size_control_t;

/** Id of the parameter used to remove initial silence in gapless use cases. */
#define PARAM_ID_REMOVE_INITIAL_SILENCE          0x0800114B

/** @h2xmlp_parameter   {"PARAM_ID_REMOVE_INITIAL_SILENCE",
                          PARAM_ID_REMOVE_INITIAL_SILENCE}
    @h2xmlp_description { This parameter is sent to decoders during gapless use cases to remove initial zeros introduced by the
                          decoder. This parameter must be sent before the first data buffer is received by the decoder. Otherwise,
                          no initial zeros will be removed. If this parameter is sent multiple times before the first data buffer
                          is received by the decoder, only most recent value is considered. }
    @h2xmlp_toolPolicy  { Calibration } */

#include "spf_begin_pack.h"
struct param_id_remove_initial_silence_t
{
   uint32_t samples_per_ch_to_remove;
   /**< @h2xmle_description { The number of samples per channel to remove. } 
        @h2xmle_default     { 0 } 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      { Basic } */    
}
#include "spf_end_pack.h"
;
typedef struct param_id_remove_initial_silence_t param_id_remove_initial_silence_t;

/** Id of the parameter used to remove initial silence in gapless use cases. */
#define PARAM_ID_REMOVE_TRAILING_SILENCE         0x0800115D

/** @h2xmlp_parameter   {"PARAM_ID_REMOVE_TRAILING_SILENCE",
                          PARAM_ID_REMOVE_TRAILING_SILENCE}
    @h2xmlp_description { This parameter is sent to decoders during gapless use cases to remove trailing zeros introduced by the
                          decoder. This parameter must be sent before the last data buffer is received by the decoder. Otherwise,
                          no trailing zeros will be removed. If this parameter is sent multiple times before the last data buffer
                          is received by the decoder, only most recent value is considered. It is expected that the amount of
                          trailing silence is smaller than one frame. If the amount of trailing zeros is larger than one frame,
                          the entire last frame will be dropped, but the rest of the trailing zeros will remain. }
    @h2xmlp_toolPolicy  { Calibration } */

#include "spf_begin_pack.h"
struct param_id_remove_trailing_silence_t
{
   uint32_t samples_per_ch_to_remove;
   /**< @h2xmle_description { The number of samples per channel to remove. } 
        @h2xmle_default     { 0 } 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      { Basic } */    
}
#include "spf_end_pack.h"
;
typedef struct param_id_remove_trailing_silence_t param_id_remove_trailing_silence_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/


#endif /* COMMON_ENC_DEC_API_H */
