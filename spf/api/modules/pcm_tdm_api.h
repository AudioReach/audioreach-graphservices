#ifndef _PCM_TDM_API_H_
#define _PCM_TDM_API_H_
/**
 * \file pcm_tdm_api.h
 * \brief
 *  	 This file contains PCM TDM module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "hw_intf_cmn_api.h"

/**
    @h2xml_title1           {PCM TDM Module API}
    @h2xml_title_agile_rev  {PCM TDM Module API}
    @h2xml_title_date       {July 12, 2018} */

/*==============================================================================
   Macros
==============================================================================*/
/* Input port ID of HW PCM module */
#define PORT_ID_HW_PCM_INPUT   0x2

/* Output port ID of HW PCM module */
#define PORT_ID_HW_PCM_OUTPUT  0x1

/* Stack size for Hw PCM and TDM Modules*/
#define PCM_TDM_STACK_SIZE     2048

/*==============================================================================
   Constants
==============================================================================*/

/* PCM interface index types */
#define PCM_INTF_TYPE_PRIMARY                              0
#define PCM_INTF_TYPE_SECONDARY                            1
#define PCM_INTF_TYPE_TERTIARY                             2
#define PCM_INTF_TYPE_QUATERNARY                           3
#define PCM_INTF_TYPE_QUINARY                              4

/** Enumeration for the auxiliary PCM synchronization signal provided by an
    external source */
#define PCM_SYNC_SRC_EXTERNAL                              0x0

/** Enumeration for the auxiliary PCM synchronization signal provided by an
    internal source */
#define PCM_SYNC_SRC_INTERNAL                              0x1

/** Enumeration for disabling the PCM/TDM configuration ctrl_data_out_enable
    parameter. The PCM block is the only master */
#define PCM_CTRL_DATA_OE_DISABLE                           0x0

/** Enumeration for enabling the PCM/TDM configuration ctrl_data_out_enable
    parameter. The PCM block shares the signal with other masters. @newpage */
#define PCM_CTRL_DATA_OE_ENABLE                            0x1

/** Enumeration for setting the PCM configuration frame to 16 */
#define PCM_BITS_PER_FRAME_16                              0x0

/** Enumeration for setting the PCM configuration frame to 32 */
#define PCM_BITS_PER_FRAME_32                              0x1

/** Enumeration for setting the PCM configuration frame to 64 */
#define PCM_BITS_PER_FRAME_64                              0x2

/** Enumeration for setting the PCM configuration frame to 128 */
#define PCM_BITS_PER_FRAME_128                             0x3

/** Enumeration for setting the PCM configuration frame to 256 */
#define PCM_BITS_PER_FRAME_256                             0x4

/** Enumeration for the PCM configuration aux_mode parameter, which configures
    the auxiliary PCM interface to use short synchronization */
#define PCM_MODE                                           0x0

/** Enumeration for the PCM configuration aux_mode parameter, which configures
    the auxiliary PCM interface to use long synchronization */
#define AUX_MODE                                           0x1

/*==============================================================================
   Type definition
==============================================================================*/
/** Param ID to configure PCM interface*/
#define PARAM_ID_HW_PCM_INTF_CFG                           0x0800101A

/** @h2xmlp_parameter   {"PARAM_ID_HW_PCM_INTF_CFG",
                           PARAM_ID_HW_PCM_INTF_CFG}
      @h2xmlp_description {Configures the PCM interface.}
      @h2xmlp_toolPolicy   {Calibration}   */

#include "spf_begin_pack.h"

/** Payload for parameter PARAM_ID_HW_PCM_INTF_CFG */
struct param_id_hw_pcm_intf_cfg_t
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
   /**< @h2xmle_description {Defines PCM interface type}
        @h2xmle_rangeList   {"PCM_INTF_TYPE_PRIMARY"=0;
                             "PCM_INTF_TYPE_SECONDARY"=1;
                             "PCM_INTF_TYPE_TERTIARY"=2;
                             "PCM_INTF_TYPE_QUATERNARY"=3;
                             "PCM_INTF_TYPE_QUINARY"=4}
        @h2xmle_default     {0}
   */
   uint16_t sync_src;
   /**< @h2xmle_description {Defines slave or master mode of operation.}
        @h2xmle_rangeList   {"PCM_SYNC_SRC_EXTERNAL"=0;
                             "PCM_SYNC_SRC_INTERNAL"=1}
        @h2xmle_default     {1}
  */
   uint16_t ctrl_data_out_enable;
   /**< @h2xmle_description {Specifies if PCM block shares data-out signal\n
                             to the driver with other masters.}
        @h2xmle_rangeList   {"PCM_CTRL_DATA_OE_DISABLE"=0;
                             "PCM_CTRL_DATA_OE_ENABLE"=1}
        @h2xmle_default     {1}
   */
   uint32_t slot_mask;
   /**< @h2xmle_description {Specifies position of the active slot}
        @h2xmle_range       {1..65535}
        @h2xmle_default     {1}
   */
   uint16_t frame_setting;
   /**< @h2xmle_description {Defines index for number of bits per frame}
        @h2xmle_rangeList   {"PCM_BITS_PER_FRAME_16"=0;
                             "PCM_BITS_PER_FRAME_32"=1;
                             "PCM_BITS_PER_FRAME_64"=2;
                             "PCM_BITS_PER_FRAME_128"=3;
                             "PCM_BITS_PER_FRAME_256"=4}
        @h2xmle_default     {0}
   */
   uint16_t aux_mode;
   /**< @h2xmle_description {PCM interface long and short sync setting.}
        @h2xmle_rangeList   {"PCM_MODE"=0;
                             "AUX_MODE"=1}
        @h2xmle_default     {0}
   */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct param_id_hw_pcm_intf_cfg_t param_id_hw_pcm_intf_cfg_t;



/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** Module ID for PCM sink module */

#define MODULE_ID_HW_PCM_SINK							    0x0700100C
/** @h2xmlm_module       {"MODULE_ID_HW_PCM_SINK",
                           MODULE_ID_HW_PCM_SINK}
    @h2xmlm_displayName  {"HW PCM Sink"}
	@h2xmlm_description  {PCM Sink Module\n
                           - Supports following params: \n
                           - PARAM_ID_HW_PCM_INTF_CFG \n
                           - PARAM_ID_HW_EP_MF_CFG \n
                           - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                           - PARAM_ID_HW_INTF_CLK_CFG \n
                           - Supported Input Media Format: \n
                           - Data Format          : FIXED_POINT \n
                           - fmt_id               : Don't care \n
                           - Sample Rates         : 8, 16, 24, 32, 48 \n
                           - Number of channels   : 1 to 16 \n
                           - Bit Width            : 16 (bits per sample 16 and Q15) \n
                           - Q format             : Q15 \n
                           - Interleaving         : HW PCM sink module needs de-interleaved unpacked}

    @h2xmlm_dataInputPorts      {IN = PORT_ID_HW_PCM_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HWEP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { PCM_TDM_STACK_SIZE }
	@{                   <-- Start of the Module -->

	@h2xml_Select		 {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::sample_rate}
	@h2xmle_rangeList    {"8 kHz"=8000;
                          "16 kHz"=16000;
                          "24 kHz"=24000;
                          "32 kHz"=32000;
                          "48 kHz"=48000}
	@h2xmle_default      {48000}
	@h2xml_Select        {param_id_hw_ep_mf_t::bit_width}
	@h2xmle_rangeList    {"16-bit"=16}
	@h2xmle_default      {16}
	@h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
	@h2xmle_range        {1..16}
	@h2xmle_default      {1}
	@h2xml_Select        {param_id_hw_ep_mf_t::data_format}
	@h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
	@h2xmle_default      {1}

	@h2xml_Select		 {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

  @h2xml_Select    {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
  @h2xml_Select    {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                          "CLOCK_ID_QUI_PCM_OSR"=CLOCK_ID_QUI_PCM_OSR}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}
  @h2xml_Select    {param_id_hw_intf_clk_cfg_t::clock_attri}
    @h2xmle_rangeList    {"HW_INTF_CLK_ATTRI_DEFAULT"=HW_INTF_CLK_ATTRI_DEFAULT}
    @h2xmle_default      {HW_INTF_CLK_ATTRI_DEFAULT}

	@h2xml_Select 		 {param_id_hw_pcm_intf_cfg_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

/** Module ID for PCM source module */

#define MODULE_ID_HW_PCM_SOURCE							   0x0700100D
/** @h2xmlm_module       {"MODULE_ID_HW_PCM_SOURCE",
                           MODULE_ID_HW_PCM_SOURCE}
    @h2xmlm_displayName  {"HW PCM Source"}
	@h2xmlm_description  {PCM Source Module \n
	                       - Supports following params: \n
                           - PARAM_ID_HW_PCM_INTF_CFG \n
                           - PARAM_ID_HW_EP_MF_CFG \n
                           - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                           - PARAM_ID_HW_INTF_CLK_CFG \n
                           - PARAM_ID_HW_EP_SRC_CHANNEL_MAP\n
                           - Supported Input Media Format: \n
                           - HW PCM source module doesn't take any inputs \n }
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_HW_PCM_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {0}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { PCM_TDM_STACK_SIZE }
    @{                   <-- Start of the Module -->

	@h2xml_Select		 {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
	@h2xml_Select        {param_id_hw_ep_mf_t::sample_rate}
	@h2xmle_rangeList    {"8 kHz"=8000;
                          "16 kHz"=16000;
                          "24 kHz"=24000;
                          "32 kHz"=32000;
                          "48 kHz"=48000}
	@h2xmle_default      {48000}
	@h2xml_Select        {param_id_hw_ep_mf_t::bit_width}
	@h2xmle_rangeList    {"16-bit"=16}
	@h2xmle_default      {16}
	@h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
	@h2xmle_range        {1..16}
	@h2xmle_default      {1}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
	@h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
	@h2xmle_default      {1}

	@h2xml_Select		 {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                          "CLOCK_ID_QUI_PCM_OSR"=CLOCK_ID_QUI_PCM_OSR}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}
    @h2xml_Select        {param_id_hw_intf_clk_cfg_t::clock_attri}
    @h2xmle_rangeList    {"HW_INTF_CLK_ATTRI_DEFAULT"=HW_INTF_CLK_ATTRI_DEFAULT}
    @h2xmle_default      {HW_INTF_CLK_ATTRI_DEFAULT}

	  @h2xml_Select 		 {param_id_hw_pcm_intf_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_ep_src_channel_map_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/


/*==============================================================================
   TDM related macros
==============================================================================*/

/* Input port ID of TDM module */
#define PORT_ID_TDM_INPUT   0x2

/* Output port ID of TDM module */
#define PORT_ID_TDM_OUTPUT  0x1

/*==============================================================================
   Constants
==============================================================================*/
/* TDM interface index types */
#define TDM_INTF_TYPE_PRIMARY                              0
#define TDM_INTF_TYPE_SECONDARY                            1
#define TDM_INTF_TYPE_TERTIARY                             2
#define TDM_INTF_TYPE_QUATERNARY                           3
#define TDM_INTF_TYPE_QUINARY                              4

/** Enumeration for the auxiliary TDM synchronization signal provided by an
    external source */
#define TDM_SYNC_SRC_EXTERNAL                              0x0

/** Enumeration for the auxiliary TDM synchronization signal provided by an
    internal source */
#define TDM_SYNC_SRC_INTERNAL                              0x1

/** Enumeration for disabling the TDM configuration ctrl_data_out_enable
    parameter. The PCM block is the only master */
#define TDM_CTRL_DATA_OE_DISABLE                           0x0

/** Enumeration for enabling the TDM configuration ctrl_data_out_enable
    parameter. The PCM block shares the signal with other masters. @newpage */
#define TDM_CTRL_DATA_OE_ENABLE                            0x1

/** Short (one-bit) Synchronization mode. */
#define TDM_SHORT_SYNC_BIT_MODE                             0

/** Long Synchronization mode. */
#define TDM_LONG_SYNC_MODE                                  1

/** Short (one-slot) Synchronization mode. */
#define TDM_SHORT_SYNC_SLOT_MODE                            2

/** Normal synchronization. */
#define TDM_SYNC_NORMAL                                     0

/** Invert the synchronization. */
#define TDM_SYNC_INVERT                                     1

/** Zero-bit clock cycle synchronization data delay. */
#define TDM_DATA_DELAY_0_BCLK_CYCLE                         0

/** One-bit clock cycle synchronization data delay. */
#define TDM_DATA_DELAY_1_BCLK_CYCLE                         1

/** Two-bit clock cycle synchronization data delay */
#define TDM_DATA_DELAY_2_BCLK_CYCLE                         2

/** Max number of slots per frame supported by TDM interface */
#define TDM_MAX_SLOTS_PER_FRAME                             32

/** max number of channels for tdm interface */
#define TDM_MAX_CHANNEL_CNT                                 32

/*==============================================================================
  Type definition
==============================================================================*/
/** Param ID to configure TDM interface */
#define PARAM_ID_TDM_INTF_CFG                              0x0800101B

/**   @h2xmlp_parameter   {"PARAM_ID_TDM_INTF_CFG",
                           PARAM_ID_TDM_INTF_CFG}
      @h2xmlp_description {Configures the TDM interface.}
      @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_TDM_INTF_CFG */
struct param_id_tdm_intf_cfg_t
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
   /**< @h2xmle_description {Defines TDM interface type}
        @h2xmle_rangeList   {"TDM_INTF_TYPE_PRIMARY"=0;
                            "TDM_INTF_TYPE_SECONDARY"=1;
                            "TDM_INTF_TYPE_TERTIARY"=2;
                            "TDM_INTF_TYPE_QUATERNARY"=3;
                            "TDM_INTF_TYPE_QUINARY"=4}
        @h2xmle_default     {0}
   */
   uint16_t sync_src;
   /**< @h2xmle_description {Defines slave or master mode of operation.}
        @h2xmle_rangeList   {"TDM_SYNC_SRC_EXTERNAL"=0;
                             "TDM_SYNC_SRC_INTERNAL"=1}
        @h2xmle_default     {1}
   */
   uint16_t ctrl_data_out_enable;
   /**< @h2xmle_description {Specifies if TDM block shares data-out signal\n
                             to the driver with other masters.}
        @h2xmle_rangeList   {"TDM_CTRL_DATA_OE_DISABLE"=0;
                             "TDM_CTRL_DATA_OE_ENABLE"=1}
        @h2xmle_default     {1}
   */
   uint32_t slot_mask;
   /**< @h2xmle_description {Specifies position of the active slot}
        @h2xmle_range       {1..65535}
     	@h2xmle_default     {1}
   */
   uint16_t nslots_per_frame;
   /**< @h2xmle_description {Number of slots per frame}
        @h2xmle_range       {1..32}
        @h2xmle_default     {1}
   */
   uint16_t slot_width;
   /**< @h2xmle_description {Width of the slot in a TDM frame}
        @h2xmle_rangeList   {"16-bit"=16;
                             "24-bit"=24;
                             "32-bit"=32}
        @h2xmle_default     {16}
   */
   uint16_t sync_mode;
   /**< @h2xmle_description {TDM Synchronization mode setting}
        @h2xmle_rangeList   {"TDM_SHORT_SYNC_BIT_MODE"=0;
                             "TDM_LONG_SYNC_MODE"=1;
                             "TDM_SHORT_SYNC_SLOT_MODE"=2}
        @h2xmle_default     {0}
   */
   uint16_t ctrl_invert_sync_pulse;
   /**< @h2xmle_description {Specifies whether to invert Synchronization}
        @h2xmle_rangeList   {"TDM_SYNC_NORMAL"=0;
                             "TDM__SYNC_INVERT"=1}
        @h2xmle_default     {0}
   */
   uint16_t ctrl_sync_data_delay;
   /**< @h2xmle_description {Specifies number of bit-clock cycles for delaying\n
                             data for synchronization.}
        @h2xmle_rangeList   {"TDM_DATA_DELAY_0_BCLK_CYCLE"=0;
                             "TDM_DATA_DELAY_1_BCLK_CYCLE"=1;
                             "TDM_DATA_DELAY_2_BCLK_CYCLE"=2}
        @h2xmle_default     {0}
   */
   uint16_t reserved;
   /**< @h2xmle_description {Client should set this field to zero.}
        @h2xmle_default     {0}
        @h2xmle_readOnly    {true}
   */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct param_id_tdm_intf_cfg_t param_id_tdm_intf_cfg_t;

/** Param ID to configure TDM lanes */
#define PARAM_ID_TDM_LANE_CFG                              0x0800106A

/**   @h2xmlp_parameter   {"PARAM_ID_TDM_LANE_CFG",
                           PARAM_ID_TDM_LANE_CFG}
      @h2xmlp_description {Configures TDM lanes. Optional for single lane usage, should be configured \n
                           if more than 1 lane is required}
      @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_TDM_LANE_CFG */
struct param_id_tdm_lane_cfg_t
{
   uint16_t lane_mask;
   /**< @h2xmle_description { Position of the active lanes. 1 to ((2^N)-1),\n
                              where N is the number of physical lanes supported\n
                              by the hardware interface.\n
                              Bits 0 to N-1 correspond to lanes 0 to N-1.\n
                              When a bit is set, the corresponding lane is active.\n
                              The number of active lanes can be inferred from \n
                              the number of bits set in the mask.}
        @h2xmle_range       {1..65535}
        @h2xmle_default     {1}
   */
   uint16_t reserved;
   /**< @h2xmle_description {Client should set this field to zero.}
        @h2xmle_default     {0}
        @h2xmle_readOnly    {true}
   */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct param_id_tdm_lane_cfg_t param_id_tdm_lane_cfg_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** Module ID for TDM sink module */
#define MODULE_ID_TDM_SINK							       0x0700100E
/** @h2xmlm_module       {"MODULE_ID_TDM_SINK",
                           MODULE_ID_TDM_SINK}
    @h2xmlm_displayName  {"TDM Sink"}
	 @h2xmlm_description  {- TDM Sink Module \n
                          - Supports following params: \n
                          - PARAM_ID_TDM_INTF_CFG \n
                          - PARAM_ID_TDM_LANE_CFG \n
                          - PARAM_ID_HW_EP_MF_CFG \n
                          - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                          - PARAM_ID_HW_INTF_CLK_CFG \n
                          - Supported Input Media Format: \n
                          - Data Format          : FIXED_POINT, IEC61937_PACKETIZED, IEC60958_PACKETIZED, \n
                                                   DSD_OVER_PCM, GENERIC_COMPRESSED, RAW_COMPRESSED \n
                          - fmt_id               : Don't care \n
                          - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                          -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                          - Number of channels   : 1 to 32 \n
                          - Channel type         : Don't care \n
                          - Bit Width            : 16 (bits per sample 16 and Q15) \n
                          - \n                   : 24 (bits per sample 24 and Q27) \n
                          - \n                   : 32 (bits per sample 32 and Q31) \n
                          - Q format             : Q15, Q27, Q31 \n
                          - Interleaving         : TDM sink module needs de-interleaved unpacked}
    @h2xmlm_dataInputPorts      {IN = PORT_ID_TDM_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HWEP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { PCM_TDM_STACK_SIZE }
	 @{                   <-- Start of the Module -->

	 @h2xml_Select		 {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
	 @h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
	 @h2xmle_default      {1}

	 @h2xml_Select		 {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select    {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select    {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                        "CLOCK_ID_PRI_TDM_IBIT"=CLOCK_ID_PRI_TDM_IBIT;
                        "CLOCK_ID_SEC_TDM_IBIT"=CLOCK_ID_SEC_TDM_IBIT;
                        "CLOCK_ID_TER_TDM_IBIT"=CLOCK_ID_TER_TDM_IBIT;
                        "CLOCK_ID_QUAD_TDM_IBIT"=CLOCK_ID_QUAD_TDM_IBIT;
                        "CLOCK_ID_QUI_TDM_IBIT"=CLOCK_ID_QUI_TDM_IBIT;
                        "CLOCK_ID_QUI_TDM_OSR"=CLOCK_ID_QUI_TDM_OSR;
                        "CLOCK_ID_SEN_TDM_IBIT"=CLOCK_ID_SEN_TDM_IBIT}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}

	 @h2xml_Select 		 {param_id_tdm_intf_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select      {param_id_tdm_lane_cfg_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/



/** Module ID for TDM source module */
#define MODULE_ID_TDM_SOURCE        				   0x0700100F
/** @h2xmlm_module       {"MODULE_ID_TDM_SOURCE",
                           MODULE_ID_TDM_SOURCE}
    @h2xmlm_displayName  {"TDM Source"}
	 @h2xmlm_description  {TDM Source Module \n
	                      - Supports following params: \n
                          - PARAM_ID_TDM_INTF_CFG \n
                          - PARAM_ID_TDM_LANE_CFG \n
                          - PARAM_ID_HW_EP_MF_CFG \n
                          - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                          - PARAM_ID_HW_INTF_CLK_CFG \n
                          - PARAM_ID_HW_EP_SRC_CHANNEL_MAP\n
                          - Supported Input Media Format: \n
                          - TDM source module doesn't take any inputs}
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_TDM_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {0}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HWEP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { PCM_TDM_STACK_SIZE }
	 @{                   <-- Start of the Module -->

	 @h2xml_Select		 {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
	 @h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
	 @h2xmle_default      {1}

	 @h2xml_Select		 {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select    {param_id_hw_intf_clk_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select    {param_id_hw_intf_clk_cfg_t::clock_id}
    @h2xmle_rangeList    {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT;
                        "CLOCK_ID_PRI_TDM_IBIT"=CLOCK_ID_PRI_TDM_IBIT;
                        "CLOCK_ID_SEC_TDM_IBIT"=CLOCK_ID_SEC_TDM_IBIT;
                        "CLOCK_ID_TER_TDM_IBIT"=CLOCK_ID_TER_TDM_IBIT;
                        "CLOCK_ID_QUAD_TDM_IBIT"=CLOCK_ID_QUAD_TDM_IBIT;
                        "CLOCK_ID_QUI_TDM_IBIT"=CLOCK_ID_QUI_TDM_IBIT;
                        "CLOCK_ID_QUI_TDM_OSR"=CLOCK_ID_QUI_TDM_OSR;
                        "CLOCK_ID_SEN_TDM_IBIT"=CLOCK_ID_SEN_TDM_IBIT}
    @h2xmle_default      {HW_INTF_CLK_ID_DEFAULT}

	 @h2xml_Select 		 {param_id_tdm_intf_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select      {param_id_tdm_lane_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_ep_src_channel_map_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/

#endif // _PCM_TDM_API_H_
