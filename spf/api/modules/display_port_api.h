#ifndef _DISPLAY_PORT_API_H_
#define _DISPLAY_PORT_API_H_
/**
 * \file display_port_api.h
 * \brief 
 *  	 This file contains DISPLAY_PORT module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "hw_intf_cmn_api.h"

/** @h2xml_title1          {Display Port Module API}
    @h2xml_title_agile_rev {Display Port Module API}
    @h2xml_title_date      {May 28, 2019}   */

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of DISPLAY_PORT module */
#define PORT_ID_DISPLAY_PORT_INPUT 0x2

/* Stack size for DISPLAY_PORT Module*/
#define DISPLAY_PORT_STACK_SIZE 1024
/*==============================================================================
   Type definition
==============================================================================*/

/** Parameter used to configure the DISPLAY_PORT interface  */
#define PARAM_ID_DISPLAY_PORT_INTF_CFG 0x08001154
/** @h2xmlp_parameter   {"PARAM_ID_DISPLAY_PORT_INTF_CFG",
                           PARAM_ID_DISPLAY_PORT_INTF_CFG}
    @h2xmlp_description {Configures the DISPLAY_PORT interface.}
    @h2xmlp_toolPolicy   {Calibration}     */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_DISPLAY_PORT_INTF_CFG */
struct param_id_display_port_intf_cfg_t
{
   uint32_t channel_allocation;
   /**< @h2xmle_description {HDMI channel allocation information for programming an HDMI frame. The default is FL_FR_0_0_0_0_0_0
        (Stereo).This information is defined in the HDMI standard, CEA 861-D. The number of
        channels is also inferred from this parameter. 0 in name below indicates blank channel allocation.}
        @h2xmle_rangeList   {"FL_FR_0_0_0_0_0_0"         = 0;
                             "FL_FR_LFE_0_0_0_0_0"       = 1;
                             "FL_FR_0_FC_0_0_0_0"        = 2;
                             "FL_FR_LFE_FC_0_0_0_0"      = 3;
                             "FL_FR_0_0_RC_0_0_0"        = 4;
                             "FL_FR_LFE_0_RC_0_0_0"      = 5;
                             "FL_FR_0_FC_RC_0_0_0"       = 6;
                             "FL_FR_LFE_FC_RC_0_0_0"     = 7;
                             "FL_FR_0_0_RL_RR_0_0"       = 8;
                             "FL_FR_LFE_0_RL_RR_0_0"     = 9;
                             "FL_FR_0_FC_RL_RR_0_0"      = 10;
                             "FL_FR_LFE_FC_RL_RR_0_0"    = 11;
                             "FL_FR_0_0_RL_RR_RC_0"      = 12;
                             "FL_FR_LFE_0_RL_RR_RC_0"    = 13;
                             "FL_FR_0_FC_RL_RR_RC_0"     = 14;
                             "FL_FR_LFE_FC_RL_RR_RC_0"   = 15;
                             "FL_FR_0_0_RL_RR_RLC_RRC"   = 16;
                             "FL_FR_LFE_0_RL_RR_RLC_RRC" = 17;
                             "FL_FR_0_FC_RL_RR_RLC_RRC"  = 18;
                             "FL_FR_LFE_FC_RL_RR_RLC_RRC"= 19;
                             "FL_FR_0_0_0_0_FLC_FRC"     = 20;
                             "FL_FR_LFE_0_0_0_FLC_FRC"   = 21;
                             "FL_FR_0_FC_0_0_FLC_FRC"    = 22;
                             "FL_FR_LFE_FC_0_0_FLC_FRC"  = 23;
                             "FL_FR_0_0_RC_0_FLC_FRC"    = 24;
                             "FL_FR_LFE_0_RC_0_FLC_FRC"  = 25;
                             "FL_FR_0_FC_RC_0_FLC_FRC"   = 26;
                             "FL_FR_LFE_FC_RC_0_FLC_FRC" = 27;
                             "FL_FR_0_0_RL_RR_FLC_FRC"   = 28;
                             "FL_FR_LFE_0_RL_RR_FLC_FRC" = 29;
                             "FL_FR_0_FC_RL_RR_FLC_FRC"  = 30;
                             "FL_FR_LFE_FC_RL_RR_FLC_FRC"= 31}
         @h2xmle_default     {0}
     */

   uint32_t mst_idx;
   /**< @h2xmle_description {Valid Multi-Steam Transport index depending upon the hardware capabilities.
         Suppported values range from 0 to (Max streams supported - 1).}
        @h2xmle_rangeList   {"Video Stream 0"=0;
                             "Video Stream 1"=1}

        @h2xmle_default     {0}
     */

   uint32_t dptx_idx;
   /**< @h2xmle_description {Valid DPTX instance index depending upon the hardware capabilities.
         Suppported values range from 0 to (Max DPTX controllers supported - 1).}
        @h2xmle_rangeList   {"DP Controller Instance 0"=0;
                             "DP Controller Instance 1"=1}
        @h2xmle_default     {0}
     */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_display_port_intf_cfg_t param_id_display_port_intf_cfg_t;
/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/** Module ID for DISPLAY_PORT sink module */
#define MODULE_ID_DISPLAY_PORT_SINK 0x07001069
/** @h2xmlm_module              {"MODULE_ID_DISPLAY_PORT_SINK",
                                 MODULE_ID_DISPLAY_PORT_SINK}
   @h2xmlm_displayName         {"Display Port Sink"}
   @h2xmlm_description         {- Display Port Sink Module\n
                                 - Supports following params: \n
                                 - PARAM_ID_DISPLAY_PORT_INTF_CFG \n
                                 - PARAM_ID_HW_EP_MF_CFG \n
                                 - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                                 - Supported Input Media Format: \n
                                 - Data Format: FIXED_POINT, IEC61937_PACKETIZED \n
                                 - fmt_id               : Don't care \n
                                 - Sample Rates         : 8, 16, 22.05, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192 kHz \n
                                 - Number of channels   : 2-8 \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                 -                      : 24 (bits per sample 24 and Q27) \n
                                 - Q format             : Q15, Q27 \n
                                 - Interleaving         : DISPLAY_PORT sink module needs de-interleaved unpacked }
    @h2xmlm_dataInputPorts      {IN = PORT_ID_DISPLAY_PORT_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { DISPLAY_PORT_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select		 {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_range        { 2..8 }
    @h2xmle_default      {2}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    { "DATA_FORMAT_FIXED_POINT"=1;
                           "DATA_FORMAT_IEC61937_PACKETIZED"=2}
    @h2xmle_default      {1}
    @h2xml_Select        {param_id_hw_ep_mf_t::sample_rate}
    @h2xmle_rangeList    {"8 kHz"=8000;
                          "16 kHz"=16000;
                          "22.05 kHz"=22050;
                          "32 kHz"=32000;
                          "44.1 kHz"=44100;
                          "48 kHz"=48000;
                          "88.2 kHz"=88200;
                          "96 kHz"=96000;
                          "176.4 kHz"=176400;
                          "192 kHz"=192000}
    @h2xmle_default      {48000}
    @h2xml_Select        {param_id_hw_ep_mf_t::bit_width}
    @h2xmle_rangeList    { "16-bit"=16;
                           "24-bit"=24 }
    @h2xmle_default      {16}

    @h2xml_Select		 {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select 		 {param_id_display_port_intf_cfg_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

#endif //_DISPLAY_PORT_API_H_
