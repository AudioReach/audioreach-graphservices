#ifndef COP_PACKETIZER_CMN_API_H
#define COP_PACKETIZER_CMN_API_H

/*==============================================================================
  @file cop_packetizer_cmn_api.h
  @brief This file contains cop pack cmn module APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
// clang-format on


/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"

/*==============================================================================
   Constants
==============================================================================*/
/* ID of the Output Media Format parameters used by MODULE_ID_PACKETIZER V0 and V1 */
#define PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT            0x0800114F

/** @h2xmlp_parameter   {"PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT", PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT}
    @h2xmlp_description {Structure for the output media format parameter used by the Packetizer module.
    It is a mandatory param for pack module to work }
    @h2xmlp_toolPolicy  {Calibration; RTC} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/* Payload of the PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT parameter in the
 Media Format Converter Module. Following this will be the variable payload for channel_map. */
struct param_id_cop_pack_output_media_fmt_t
{
   uint32_t sampling_rate;
   /**< @h2xmle_description  {Sampling rate}
        @h2xmle_rangeList   {"8 kHz"=8000;
                             "11.025 kHz"=11025;
                             "12 kHz"=12000;
                             "16 kHz"=16000;
                             "22.05 kHz"=22050;
                             "24 kHz"=24000;
                             "32 kHz"=32000;
                             "44.1 kHz"=44100;
                             "48 kHz"=48000;
                             "88.2 kHz"=88200;
                             "96 kHz"=96000;
                             "176.4 kHz"=176400;
                             "192 kHz"=192000;
                             "352.8 kHz"=352800;
                             "384 kHz"=384000}
        @h2xmle_default      {48000} */

   uint16_t bits_per_sample;
   /**< @h2xmle_description  {Bits per sample of audio samples \n
                              ->Samples with bit width of 16 (Q15 format) are stored in 16 bit words}
        @h2xmle_rangeList    {"16-bit"= 16}
        @h2xmle_default      {16}
   */

   uint16_t num_channels;
   /**< @h2xmle_description  {Number of channels. \n
                              ->Ranges from 1 to 2 channels}
        @h2xmle_range        {1..2}
        @h2xmle_default      {1}
   */

   uint16_t channel_type[0];
   /**< @h2xmle_description  {Channel mapping array. \n
                              ->Specify a channel mapping for each output channel \n
                              ->If the number of channels is not a multiple of four, zero padding must be added
                              to the channel type array to align the packet to a multiple of 32 bits}
        @h2xmle_variableArraySize {num_channels}
        @h2xmle_rangeEnum   {pcm_channel_map}
        @h2xmle_default      {1}    */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct param_id_cop_pack_output_media_fmt_t param_id_cop_pack_output_media_fmt_t;


#endif //COP_PACKETIZER_CMN_API_H
