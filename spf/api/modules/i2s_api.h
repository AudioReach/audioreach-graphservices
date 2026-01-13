#ifndef _I2S_API_H_
#define _I2S_API_H_
/**
 * \file i2s_api.h
 * \brief
 *  	 This file contains I2S module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "hw_intf_cmn_api.h"

/** @h2xml_title1          {I2S Module API}
    @h2xml_title_agile_rev {I2S Module API}
    @h2xml_title_date      {July 12, 2018}   */

/*==============================================================================
   Constants
==============================================================================*/

/** I2S interface index types  */
#define I2S_INTF_TYPE_PRIMARY                               0
#define I2S_INTF_TYPE_SECONDARY                             1
#define I2S_INTF_TYPE_TERTIARY                              2
#define I2S_INTF_TYPE_QUATERNARY                            3
#define I2S_INTF_TYPE_QUINARY                               4

/* I2S lines and multi-channel operation */

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    serial data wire number 0 (SD0).
 */
#define I2S_SD0                                             0x1

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    serial data wire number 1 (SD1).
 */
#define I2S_SD1                                             0x2

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    serial data wire number 2 (SD2).
 */
#define I2S_SD2                                             0x3

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    serial data wire number 3 (SD3).
 */
#define I2S_SD3                                             0x4

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    SD0 and SD1.
 */
#define I2S_QUAD01                                          0x5

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    SD2 and SD3.
 */
#define I2S_QUAD23                                          0x6

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    six channels.
 */
#define I2S_6CHS                                            0x7

/** Enumeration for setting the I2S configuration sd_line_idx parameter to
    8 channels.
 */
#define I2S_8CHS                                            0x8

/* Master Slave configuration */

/** Enumeration for setting the I2S configuration ws_src parameter to
    external.
 */
#define CONFIG_I2S_WS_SRC_EXTERNAL                          0x0

/** Enumeration for setting the I2S configuration ws_src parameter to
    internal. @newpage
 */
#define CONFIG_I2S_WS_SRC_INTERNAL                          0x1

/* Input port ID of I2S module */
#define PORT_ID_I2S_INPUT                                   0x2

/* Output port ID of I2S module */
#define PORT_ID_I2S_OUTPUT                                  0x1

/* Stack size for I2s Module*/
/** On MDMs, audio runs in root PD. Since MMPM calls on MDMs
    are not optimized, we would need more stack size than MSM.

    I2S stack size would be 4KB for MDM and 2KB for MSM.
*/
#ifdef USES_AUDIO_IN_ROOTPD
#define I2S_STACK_SIZE                                      4096
#else
#define I2S_STACK_SIZE                                      2048
#endif
/*==============================================================================
   Type definition
==============================================================================*/

/** Parameter used to configure the I2S interface  */
#define PARAM_ID_I2S_INTF_CFG                               0x08001019
/** @h2xmlp_parameter   {"PARAM_ID_I2S_INTF_CFG",
                           PARAM_ID_I2S_INTF_CFG}
    @h2xmlp_description {Configures the I2S interface.}
    @h2xmlp_toolPolicy   {Calibration}     */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_I2S_INTF_CFG */
struct param_id_i2s_intf_cfg_t
{
   uint32_t lpaif_type;
   /**< @h2xmle_description {LPAIF types.}
        @h2xmle_rangeList   {"LPAIF"=0;
                             "LPAIF_RXTX"=1;
                             "LPAIF_WSA"=2;
                             "LPAIF_VA"=3;
                             "LPAIF_AXI"=4}
        @h2xmle_default     {0}
   */
   uint32_t intf_idx;
   /**< @h2xmle_description {I2S interface index types.}
        @h2xmle_rangeList   {"I2S_INTF_TYPE_PRIMARY"=0;
                             "I2S_INTF_TYPE_SECONDARY"=1;
                             "I2S_INTF_TYPE_TERTIARY"=2;
                             "I2S_INTF_TYPE_QUATERNARY"=3;
                             "I2S_INTF_TYPE_QUINARY"=4}
        @h2xmle_default     {0}
   */
   uint16_t sd_line_idx;
   /**< @h2xmle_description {I2S serial data line idx}
        @h2xmle_rangeList   {"I2S_SD0"=1;
                             "I2S_SD1"=2;
                             "I2S_SD2"=3;
                             "I2S_SD3"=4;
                             "I2S_QUAD01"=5;
                             "I2S_QUAD23"=6;
                             "I2S_6CHS"=7;
                             "I2S_8CHS"=8}
        @h2xmle_default     {1}
   */
   uint16_t ws_src;
   /**< @h2xmle_description {Specifies Master slave configuration.}
        @h2xmle_rangeList   {"CONFIG_I2S_WS_SRC_EXTERNAL"=0;
                             "CONFIG_I2S_WS_SRC_INTERNAL"=1}
        @h2xmle_default     {1}
   */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_i2s_intf_cfg_t param_id_i2s_intf_cfg_t;
/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/** Module ID for I2S sink module */
#define MODULE_ID_I2S_SINK	   0x0700100A
/** @h2xmlm_module              {"MODULE_ID_I2S_SINK",
                                 MODULE_ID_I2S_SINK}
	@h2xmlm_displayName         {"I2S Sink"}
	@h2xmlm_description         {- I2S Sink Module\n
                                 - Supports following params: \n
                                 - PARAM_ID_I2S_INTF_CFG \n
                                 - PARAM_ID_HW_EP_MF_CFG \n
                                 - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                                 - PARAM_ID_HW_INTF_CLK_CFG \n
                                 - PARAM_ID_HW_EP_POWER_MODE_CFG\n
                                 - Supported Input Media Format: \n
                                 - Data Format          : FIXED_POINT, IEC60958_PACKETIZED,\n
                                                          IEC60958_PACKETIZED_NON_LINEAR, COMPR_OVER_PCM_PACKETIZED,\n
                                                          IEC61937_PACKETIZED, GENERIC_COMPRESSED \n
                                 - fmt_id               : Don't care \n
                                 - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                                 - Number of channels   : 1, 2, 4, 6 or 8 \n
                                        - For DATA_FORMAT_IEC60958_NON_LINEAR: 2 or 8 only \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                 -                      : 24 (bits per sample 24 and Q27) \n
                                 -                      : 32 (bits per sample 32 and Q31)	\n
                                 - Q format             : Q15, Q27, Q31 \n
                                 - Interleaving         : I2S sink module needs de-interleaved unpacked }
    @h2xmlm_dataInputPorts      {IN = PORT_ID_I2S_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { I2S_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select		    {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
	 @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
	 @h2xmle_rangeList    {"ONE"=1;
                          "TWO"=2;
                          "FOUR"=4;
                          "SIX"=6;
						        "EIGHT"=8}
	 @h2xmle_default      {1}
	 @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    {"FIXED POINT"=1;
                          "IEC60958 PACKETIZED"=3;
                          "IEC60958 PACKETIZED NON LINEAR"=8;
                          "COMPR OVER PCM PACKETIZED"=7;
                          "IEC61937 PACKETIZED"=2;
                          "GENERIC COMPRESSED"=5}
    @h2xmle_default      {1}

	 @h2xml_Select		    {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                          "CLOCK_ID_QUI_MI2S_OSR"=CLOCK_ID_QUI_MI2S_OSR}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_attri}
    @h2xmle_rangeList    {"HW_INTF_CLK_ATTRI_DEFAULT"=HW_INTF_CLK_ATTRI_DEFAULT}
    @h2xmle_default      {HW_INTF_CLK_ATTRI_DEFAULT}

	 @h2xml_Select 		 {param_id_i2s_intf_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select      {param_id_hw_ep_power_mode_cfg_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

/** Module ID for I2S source module */
#define MODULE_ID_I2S_SOURCE    0x0700100B
/** @h2xmlm_module              {"MODULE_ID_I2S_SOURCE",
                                  MODULE_ID_I2S_SOURCE}
    @h2xmlm_displayName         {"I2S Source "}
	 @h2xmlm_description         {- I2S Source Module\n
                                 - Supports following params: \n
                                 - PARAM_ID_I2S_INTF_CFG \n
                                 - PARAM_ID_HW_EP_MF_CFG \n
                                 - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                                 - PARAM_ID_HW_INTF_CLK_CFG \n
                                 - PARAM_ID_HW_EP_POWER_MODE_CFG\n
                                 - PARAM_ID_HW_EP_SRC_CHANNEL_MAP\n
                                 - Supported Input Media Format: \n
                                 - I2S source module doesn't take any inputs }
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_I2S_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {0}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { I2S_STACK_SIZE }
    @h2xmlm_toolPolicy          { Calibration }
	 @{                          <-- Start of the Module -->

	 @h2xml_Select		    {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_rangeList    {"ONE"=1;
                          "TWO"=2;
                          "FOUR"=4;
                          "SIX"=6;
                          "EIGHT"=8}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    {"FIXED POINT"=1;
                          "IEC60958 PACKETIZED"=3;
                          "IEC60958 PACKETIZED NON LINEAR"=8;
                          "COMPR OVER PCM PACKETIZED"=7;
                          "IEC61937 PACKETIZED"=2;
                          "GENERIC COMPRESSED"=5}

	 @h2xml_Select		    {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                          "CLOCK_ID_QUI_MI2S_OSR"=CLOCK_ID_QUI_MI2S_OSR}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_attri}
    @h2xmle_rangeList    {"HW_INTF_CLK_ATTRI_DEFAULT"=HW_INTF_CLK_ATTRI_DEFAULT}
    @h2xmle_default      {HW_INTF_CLK_ATTRI_DEFAULT}

	 @h2xml_Select 		 {param_id_i2s_intf_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select      {param_id_hw_ep_power_mode_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_src_channel_map_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_src_channel_map_t::num_channels}
    @h2xmle_range        { 0..15 }
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}
    @}                   <-- End of the Module -->*/

#endif //_I2S_API_H_
