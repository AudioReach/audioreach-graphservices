#ifndef PCM_ENCODER_API_H_
#define PCM_ENCODER_API_H_
/*==============================================================================
  @file pcm_encoder_api.h
  @brief This file contains PCM encoder APIs

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
    @h2xml_title1           {PCM Encoder Module API}
    @h2xml_title_agile_rev  {PCM Encoder Module API}
    @h2xml_title_date       {March 26, 2019} */


/*------------------------------------------------------------------------------
   Defines
------------------------------------------------------------------------------*/
/* Input port ID of MFC module */
#define PCM_ENC_DATA_INPUT_PORT   0x2

/* Output port ID of MFC module */
#define PCM_ENC_DATA_OUTPUT_PORT  0x1

/*==============================================================================
   Param ID
==============================================================================*/

/**
  ID of the parameter used to set frame size of the pcm encoder
  In general,the PCM encoder frame size is determined by the perf_mode
  of the container.For Low latency it is 1 ms and for low Power it is 5 ms.
  This PID can be used, if the client has the requirement to specify any
  fixed  frame-size for PCM encoder.
*/

#define PARAM_ID_PCM_ENCODER_FRAME_SIZE                   0x0800136B
/** @h2xmlp_parameter   {"PARAM_ID_PCM_ENCODER_FRAME_SIZE "
                        ,PARAM_ID_PCM_ENCODER_FRAME_SIZE }
    @h2xmlp_description {Structure for PARAM_ID_PCM_ENCODER_FRAME_SIZE
                         used to set the encoded frame size of the pcm encoder
						 module.In general,the PCM encoder frame size is determined
						 by the perf_mode of the container.Currently,for low latency it is
						 1ms and for low power it is 5ms.
						 This PID can be used, if the client has the requirement
						 to specify the frame-size for PCM encoder.
						 }
   @h2xmlp_toolPolicy    {Calibration}                         */


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** Payload of the PARAM_ID_PCM_ENCODER_FRAME_SIZE  parameter.
 */
struct param_id_pcm_encoder_frame_size_t
{
	uint32_t frame_size_type;
	/**< @h2xmle_description  {Specifies whether the frame size of the
	                           pcm encoder module is in samples or microsecond units.}
         @h2xmle_default      {0}
         @h2xmle_rangeList    {"frame_size_not_specified"=0;
			                   "frame_size_in_samples"=1;
		                       "frame_size_in_us"=2  }*/
	uint32_t frame_size_in_samples;
	/**< @h2xmle_description  {Specifies the frame size of pcm encoder
	                           in samples.This parameter value will be used when the
							   frame_size_type is set to 1 and this value is greater than zero.
							   We recommend the frame size in samples to be limited to 100ms(or 384khz*100ms=38400 samples)}
         @h2xmle_default      {0}
         @h2xmle_range        {0..38400}*/
	uint32_t frame_size_in_us;
	/**< @h2xmle_description  {Specifies the frame size of pcm encoder
                               in microsecond units.This parameter value will be used
							   when the frame_size_type is set to 2 and this value
							   is greater than zero.
							  }
         @h2xmle_default      {0}
         @h2xmle_range        {0..100000}*/
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Type definition for the above structures. */
typedef struct param_id_pcm_encoder_frame_size_t param_id_pcm_encoder_frame_size_t;

/**
 * Module ID for PCM encoder.
 * Encodes data to format-id = MEDIA_FMT_ID_PCM
 */
#define MODULE_ID_PCM_ENC              0x07001004
/**
    @h2xmlm_module         {"MODULE_ID_PCM_ENC",
                            MODULE_ID_PCM_ENC}
    @h2xmlm_displayName    {"PCM Encoder"}
    @h2xmlm_description    {
                            This module is used as the encoder for PCM use cases. \n
                            It can be used to convert properties of PCM stream such as \n
                            endianness, interleaving, bit width, number of channels etc. \n
                            It cannot be used to convert sampling rate. \n
                            This module has only one input and one output port. \n
                            - This module supports following parameter IDs: \n
                            -#PARAM_ID_PCM_OUTPUT_FORMAT_CFG \n
                            - \n
                            Doesn't support
                            - #PARAM_ID_ENCODER_OUTPUT_CONFIG \n
                            (as #PARAM_ID_PCM_OUTPUT_FORMAT_CFG covers the supported controls) \n
                            Supported Input Media Format: \n
                            - Data Format          : FIXED_POINT \n
                            - fmt_id               : Don't care \n
                            - Sample Rates         : 1-384 kHz \n
                            - Number of channels   : 1-32 \n
                            - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                                   : 24 (bits per sample 24 and Q23, \n
                                                     bits per sample 32 and Q23 or Q27 or Q31), \n
                                                   : 32 (bits per sample 32 and Q31) \n
                            - Interleaving         : interleaved, deinterleaved unpacked, \n
                                                     deinterleaved packed. \n
                            - Endianess            : little \n
                            }
    @h2xmlm_dataMaxInputPorts           {1}
    @h2xmlm_dataMaxOutputPorts          {1}
    @h2xmlm_dataInputPorts              {IN=PCM_ENC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts             {OUT=PCM_ENC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes         {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable               {false}
    @h2xmlm_stackSize                   { 4096 }
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"param_id_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"payload_pcm_output_format_cfg_t"}
    @h2xmlm_InsertParameter
	@h2xml_Select          {"param_id_pcm_encoder_frame_size_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/


#endif // PCM_ENCODER_API_H_
