#ifndef _RATE_ADAPTED_TIMER_API_H_
#define _RATE_ADAPTED_TIMER_API_H_
/**
 * \file rate_adapted_timer_api.h
 * \brief 
 *  	 This file contains RATE_ADAPTED_TIMER module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/**@h2xml_title1          {RATE_ADAPTED_TIMER Module API}
   @h2xml_title_agile_rev {RATE_ADAPTED_TIMER Module API}
   @h2xml_title_date      {April 8, 2019}  */

/*==============================================================================
   Constants
==============================================================================*/
/* IMCL static port id's to receive drifts*/
#define QT_REFCLK_TIMING_INPUT AR_NON_GUID(0xC0000001)
#define REFCLK_REMOTE_TIMING_INPUT AR_NON_GUID(0xC0000002)
#define QT_REMOTE_TIMING_INPUT AR_NON_GUID(0xC0000003)

/* RAT module stack size*/
#define RATE_ADAPTED_TIMER_STACK_SIZE 4096

/* Input port ID of Rate Adapted Timer module */
#define PORT_ID_RATE_ADAPTED_TIMER_INPUT 0x2

/* Output port ID of Rate Adapted Timer module */
#define PORT_ID_RATE_ADAPTED_TIMER_OUTPUT 0x1

/** ID of the parameter used to configure the RAT media format */
#define PARAM_ID_RAT_MEDIA_FORMAT 0x080010D0

/** @h2xmlp_parameter   {"PARAM_ID_RAT_MEDIA_FORMAT",
                         PARAM_ID_RAT_MEDIA_FORMAT}
    @h2xmlp_description {Configures the media format of the Rate Adapted Timer Module and is mandatory}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_rat_mf_t
{
   uint32_t sample_rate;
   /**< @h2xmle_description {Defines sample rate.}
        @h2xmle_rangelist   {"8 kHz"=8000;
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
        @h2xmle_default     {48000}
   */

   uint16_t bits_per_sample;
   /**< @h2xmle_description {bits per sample.}
        @h2xmle_rangeList   {"16-bit"=16;
                             "32-bit"=32}
        @h2xmle_default     {16}
   */

   uint16_t q_factor;
   /**< @h2xmle_description {q factor \n
                             -> If bits per sample is 16, q_factor should be 15 \n
                             -> If bits per sample is 32, q_factor can be 27 or 31}
        @h2xmle_rangeList   {"q15"=15;
                             "q27"=27;
                             "q31"=31}
        @h2xmle_default     {15}
   */

   uint32_t data_format;
   /**< @h2xmle_description {Format of the data}
        @h2xmle_rangeList   {"DATA_FORMAT_FIXED_POINT"=1}
        @h2xmle_default     {1}
   */

   uint32_t num_channels;
   /**< @h2xmle_description {Number of channels.}
        @h2xmle_range       {1..32}
        @h2xmle_default     {1}
   */

   uint16_t channel_map[0];
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
typedef struct param_id_rat_mf_t param_id_rat_mf_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** Module ID for Rate Adapted Timer module */
#define MODULE_ID_RATE_ADAPTED_TIMER 0x07001041
/** @h2xmlm_module             {"MODULE_ID_RATE_ADAPTED_TIMER",
                                 MODULE_ID_RATE_ADAPTED_TIMER}
   @h2xmlm_displayName         {"Rate Adapted Timer "}
   @h2xmlm_description         {- Rate Adapted Timer \n
                                 - Supports following params: \n
                                 - PARAM_ID_RAT_MEDIA_FORMAT \n
                                 - Supported Input Media Format: \n
                                 - Data Format          : FIXED_POINT, IEC61937_PACKETIZED, IEC60958_PACKETIZED, \n
                                 -                        DSD_OVER_PCM, GENERIC_COMPRESSED, RAW_COMPRESSED \n
                                 - fmt_id               : Don't care \n
                                 - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                                 - Number of channels   : 1 to 16 \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                 -                      : 24 (bits per sample 24 and Q27) \n
                                 -                      : 32 (bits per sample 32 and Q31)	\n
                                 - Q format             : Q15, Q23, Q27, Q31 \n
                                 - Interleaving         : Module needs de-interleaved unpacked }

    @h2xmlm_dataInputPorts      {IN = PORT_ID_RATE_ADAPTED_TIMER_INPUT}
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_RATE_ADAPTED_TIMER_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlStaticPort      {"QT_REFCLK_TIMING_INPUT" = 0xC0000001,
                                 "Qtimer HW-EP drift info" = INTENT_ID_TIMER_DRIFT_INFO}
    @h2xmlm_ctrlStaticPort      {"REFCLK_REMOTE_TIMING_INPUT" = 0xC0000002,
                                 "HWEP BT drift info" = INTENT_ID_TIMER_DRIFT_INFO}
    @h2xmlm_ctrlStaticPort      {"QT_REMOTE_TIMING_INPUT" = 0xC0000003,
                                 "Qtimer Remote drift info" = INTENT_ID_TIMER_DRIFT_INFO}
    @h2xmlm_ctrlDynamicPortIntent  {"Qtimer to Adapted Rate drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { RATE_ADAPTED_TIMER_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select		        {param_id_rat_mf_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

#endif //_RATE_ADAPTED_TIMER_API_H_
