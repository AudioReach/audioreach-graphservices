#ifndef _CODEC_DMA_API_H_
#define _CODEC_DMA_API_H_
/**
 * \file codec_dma_api.h
 * \brief
 *  	 This file contains CODEC_DMA module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "hw_intf_cmn_api.h"
//#include "prbdma_hw_api.h"

 /** @h2xml_title1           {Codec Dma Module API}
     @h2xml_title_agile_rev  {Codec Dma Module API}
     @h2xml_title_date       {Oct 11, 2018} */

/*==============================================================================
   Constants
==============================================================================*/

/** @ingroup ar_spf_codec_dma_macros
    Input port ID of Codec DMA module */
#define PORT_ID_GEN_CNTR_DMA_INPUT   0x2

/** @ingroup ar_spf_codec_dma_macros
    Output port ID of Codec DMA module */
#define PORT_ID_GEN_CNTR_DMA_OUTPUT  0x1

/** @ingroup ar_spf_codec_dma_macros
    Stack size for Codec DMA Module*/
#define GEN_CNTR_DMA_STACK_SIZE          2048

/*==============================================================================
   Type definition
==============================================================================*/

/** @ingroup ar_spf_codec_dma_macros
    Parameter used to configure the CODEC DMA interface  */
#define PARAM_ID_CODEC_DMA_INTF_CFG                            0x08001063

/** @ingroup ar_spf_codec_dma_macros

    Configures the CODEC DMA interface
*/

/** @h2xmlp_parameter   {"PARAM_ID_CODEC_DMA_INTF_CFG",
                         PARAM_ID_CODEC_DMA_INTF_CFG}
    @h2xmlp_description {Configures the CODEC DMA interface.}
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
/* Payload for parameter PARAM_ID_CODEC_DMA_INTF_CFG */
struct param_id_codec_dma_intf_cfg_t
{
       uint32_t                lpaif_type;
       /**< LPAIF types. */

       /**< @h2xmle_description {LPAIF types.}
            @h2xmle_rangeList   {"LPAIF"=0;
                                 "LPAIF_RXTX"=1;
                                 "LPAIF_WSA"=2;
                                 "LPAIF_VA"=3;
                                 "LPAIF_AXI"=4;
                                 "LPAIF_AUD"=5;
                                 "LPAIF_WSA2"=7;
                                 "LPAIF_RXTX_SDCA"=8;
                                 "LPAIF_WSA_SDCA"=9;
                                 "LPAIF_QAIF"=10;
                                 "LPAIF_QAIF_VA"=11}
          @h2xmle_default     {2}
     */
     uint32_t                  intf_indx;
     /**< CODEC DMA interface index which picks an instance of codec DMA.
          Each interface supports different num of channels. */

     /**< @h2xmle_description {CODEC DMA interface index which picks an instance of codec dma.
	                           Each interface supports different num of channels}
     */
     uint32_t                  active_channels_mask;
     /**< Active channels mask to denote the bit mask for active channels.
          Bits 0 to 15 denote channels 0 to 15. A set bit in the mask denotes
          the channel is active while a 0 denotes a channel is inactive.
          Mask should match the channel indices being set from codec side. */

     /**< @h2xmle_description {Active channels mask to denote the bit mask for active channels.
          Bits 0 to 15 denote channels 0 to 15. A set bit in the mask denotes
          the channel is active while a 0 denotes a channel is inactive.
		  Mask should match the channel indices being set from codec side}
          @h2xmle_range       {1..65535}
          @h2xmle_default     {1}
     */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_codec_dma_intf_cfg_t param_id_codec_dma_intf_cfg_t;

/** @ingroup ar_spf_codec_dma_macros
    Parameter used to configure the CODEC DMA interface Frame select */
#define PARAM_ID_CODEC_DMA_CODEC_FS_SEL_CFG                            0x08001B8B

/** @ingroup ar_spf_codec_dma_macros

    Configures the CODEC DMA Frame select
*/

/** @h2xmlp_parameter   {"PARAM_ID_CODEC_DMA_CODEC_FS_SEL_CFG",
                         PARAM_ID_CODEC_DMA_CODEC_FS_SEL_CFG}
    @h2xmlp_description {Configures the CODEC DMA interface.}
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
/* Payload for parameter PARAM_ID_CODEC_DMA_CODEC_FS_SEL_CFG */
struct param_id_codec_dma_codec_fs_sel_cfg_t
{
    uint16_t    enable_codec_fs_config;
     /**< @h2xmle_description { Enable. - allowed only when HLOS audio driver wants to program frame select value explictly.
                                Disable - (legacy approach) }
          @h2xmle_rangeList    {"Disable"=0;
                                "Enable"=1}
          @h2xmle_default     {0}
      */
    uint16_t codec_fs_sel_value;
    /**< @h2xmle_description {desired channel index to be set for frame strobe selection}
           @h2xmle_range       {0x0..0xf}
           @h2xmle_default     {0x0} */
    
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_codec_dma_codec_fs_sel_cfg_t param_id_codec_dma_codec_fs_sel_cfg_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/


/** @ingroup ar_spf_codec_dma_macros
    CODEC DMA Sink module.

    @subhead4{Supported parameter IDs}
    - #PARAM_ID_CODEC_DMA_INTF_CFG @lstsp1
    - #PARAM_ID_HW_EP_MF_CFG @lstsp1
    - #PARAM_ID_HW_EP_FRAME_DURATION @lstsp1
    - #PARAM_ID_HW_EP_POWER_MODE_CFG @lstsp1
    - #PARAM_ID_HW_EP_DMA_DATA_ALIGN @lstsp1
    - PARAM_ID_HW_DELAY

    @subhead4{Supported input media format ID}
    - Data Format          : FIXED_POINT @lstsp1
    - fmt_id               : Don't care @lstsp1
    - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48,
                             88.2, 96, 176.4, 192, 352.8, 384 kHz  @lstsp1
    - Number of channels   : 1 to 16 @lstsp1
    - Channel type         : Don't care @lstsp1
    - Bit Width            : 16 (bits per sample 16 and Q15),
                           : 24 (bits per sample 24 and Q27)
                           : 32 (bits per sample 32 and Q31) @lstsp1
    - Q format             : Q15, Q27, Q31 @lstsp1
    - Interleaving         : I2S sink module needs de-interleaved unpacked  or Interleaved */

#define MODULE_ID_CODEC_DMA_SINK                                      0x07001023

/** @h2xmlm_module       {"MODULE_ID_CODEC_DMA_SINK",
                           MODULE_ID_CODEC_DMA_SINK}
    @h2xmlm_displayName  {"Codec DMA Sink"}
    @h2xmlm_modSearchKeys{hardware}
    @h2xmlm_description  {CODEC_DMA Sink Module\n
                        - Supports following params:
                        - PARAM_ID_CODEC_DMA_INTF_CFG \n
                          - PARAM_ID_HW_EP_MF_CFG \n
                          - PARAM_ID_HW_EP_FRAME_DURATION \n
                          - PARAM_ID_HW_EP_POWER_MODE_CFG\n
                          - PARAM_ID_HW_EP_DMA_DATA_ALIGN\n
                          - PARAM_ID_HW_DELAY\n
                          - \n
                          - Supported Input Media Format: \n
                          - Data Format          : FIXED_POINT \n
                          - fmt_id               : Don't care \n
                          - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                          -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                          - Number of channels   : 1 to 16 \n
                          - Channel type         : Don't care \n
                          - Bit Width            : 16 (bits per sample 16 and Q15), \n
                          -                      : 24 (bits per sample 24 and Q27) \n
                          -                      : 32 (bits per sample 32 and Q31)  \n
                          - Q format             : Q15, Q27, Q31 \n
                          - Interleaving         : Codec DMA sink module needs de-interleaved unpacked or interleaved }
    @h2xmlm_dataInputPorts      {IN = PORT_ID_GEN_CNTR_DMA_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { GEN_CNTR_DMA_STACK_SIZE }
    @{                   <-- Start of the Module -->

    @h2xml_Select     {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_rangeList    {"ONE"=1;
                         "TWO"=2;
                         "THREE"=3;
                         "FOUR"=4;
                         "FIVE"=5;
                         "SIX"=6;
                         "SEVEN"=7;
                         "EIGHT"=8;
                         "NINE"=9;
                         "TEN"=10;
                         "ELEVEN"=11;
                         "TWELVE"=12;
                         "THIRTEEN"=13;
                         "FOURTEEN"=14;
                         "FIFTEEN"=15;
                         "SIXTEEN"=16}
    @h2xmle_default      {1}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
    @h2xmle_default      {1}

    @h2xml_Select     {param_id_hw_ep_frame_duration_t}
    @h2xmle_range       {1..40000}
    @h2xmlm_InsertParameter
    @h2xml_Select      {param_id_hw_ep_power_mode_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select     {param_id_codec_dma_intf_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_codec_dma_intf_cfg_t::intf_indx}
    @h2xmle_rangeList    {"CODEC_RX0"=1;
                         "CODEC_RX1"=2;
                         "CODEC_RX2"=3;
                         "CODEC_RX3"=4;
                         "CODEC_RX4"=5;
                         "CODEC_RX5"=6;
                         "CODEC_RX6"=7;
                         "CODEC_RX7"=8;
                         "CODEC_RX8"=9;
                         "CODEC_RX9"=10;
                         "CODEC_RX10"=11;
                         "CODEC_RX11"=12;
                         "CODEC_RX12"=13;
                         "CODEC_RX13"=14;
                         "CODEC_RX14"=15;
                         "CODEC_RX15"=16;
                         "CODEC_RX16"=17;
                         "CODEC_RX17"=18}
    @h2xmle_default      {1}

    @h2xml_Select     {param_id_hw_ep_dma_data_align_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_dma_data_align_t::dma_data_align}
    @h2xmle_rangeList    {"DMA_DATA_ALIGN_MSB"=0;
                         "DMA_DATA_ALIGN_LSB"=1}
    @h2xmle_default      {0}
    @h2xml_Select     {param_id_hw_delay_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

/** @ingroup ar_spf_codec_dma_macros
    CODEC DMA Source module

    @subhead4{Supported parameter IDs}
    - #PARAM_ID_CODEC_DMA_INTF_CFG @lstsp1
    - #PARAM_ID_HW_EP_MF_CFG @lstsp1
    - #PARAM_ID_HW_EP_FRAME_DURATION @lstsp1
    - #PARAM_ID_HW_EP_POWER_MODE_CFG @lstsp1
    - PARAM_ID_HW_DELAY
    - PARAM_ID_PRBDMA_ENABLE
    - PARAM_ID_PRBDMA_DEBUG_CONFIG

    @subhead4{Supported input media format ID}
    - Codec DMA source module does not take any inputs  */

#define MODULE_ID_CODEC_DMA_SOURCE                                  0x07001024

/** @h2xmlm_module       {"MODULE_ID_CODEC_DMA_SOURCE",
                           MODULE_ID_CODEC_DMA_SOURCE}
    @h2xmlm_displayName  {"Codec DMA Source"}
    @h2xmlm_modSearchKeys{hardware}
    @h2xmlm_description  {CODEC_DMA Source Module \n
                          - Supports following params:
                        - PARAM_ID_CODEC_DMA_INTF_CFG \n
                          - PARAM_ID_HW_EP_MF_CFG \n
                          - PARAM_ID_HW_EP_FRAME_DURATION\n
                          - PARAM_ID_HW_EP_POWER_MODE_CFG\n
						  - PARAM_ID_HW_EP_DMA_DATA_ALIGN\n
                          - PARAM_ID_HW_DELAY\n
                          - PARAM_ID_PRBDMA_ENABLE\n
                          - PARAM_ID_PRBDMA_DEBUG_CONFIG\n
                          - PARAM_ID_SILENCE_DETECTION\n
                          - PARAM_ID_CODEC_DMA_CODEC_FS_SEL_CFG\n
                          - \n
                          - Supported Input Media Format: \n
                          - Codec dma source module doesn't take any inputs }
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_GEN_CNTR_DMA_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {0}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "AAD-Codec DMA Control" = INTENT_ID_PRBDMA_CONTROL,
                                      maxPorts= 1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { GEN_CNTR_DMA_STACK_SIZE }
    @{                   <-- Start of the Module -->

    @h2xml_Select     {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_rangeList    {"ONE"=1;
                         "TWO"=2;
                         "THREE"=3;
                         "FOUR"=4;
                         "FIVE"=5;
                         "SIX"=6;
                         "SEVEN"=7;
                         "EIGHT"=8;
                         "NINE"=9;
                         "TEN"=10;
                         "ELEVEN"=11;
                         "TWELVE"=12;
                         "THIRTEEN"=13;
                         "FOURTEEN"=14;
                         "FIFTEEN"=15;
                         "SIXTEEN"=16}
    @h2xmle_default      {1}
	@h2xml_Select        {param_id_hw_ep_mf_t::data_format}
	@h2xmle_rangeList    {"DATA_FORMAT_FIXED_POINT"=1}
	@h2xmle_default      {1}
    @h2xml_Select     {param_id_hw_ep_frame_duration_t}
    @h2xmle_range       {1..40000}
    @h2xmlm_InsertParameter
    @h2xml_Select      {param_id_hw_ep_power_mode_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_codec_dma_intf_cfg_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_codec_dma_intf_cfg_t::intf_indx}
    @h2xmle_rangeList    {"CODEC_TX0"=1;
                         "CODEC_TX1"=2;
                         "CODEC_TX2"=3;
                         "CODEC_TX3"=4;
                         "CODEC_TX4"=5;
                         "CODEC_TX5"=6;
                         "CODEC_TX6"=7;
                         "CODEC_TX7"=8;
                         "CODEC_TX8"=9;
                         "CODEC_TX9"=10;
                         "CODEC_TX10"=11;
                         "CODEC_TX11"=12;
                         "CODEC_TX12"=13;
                         "CODEC_TX13"=14;
                         "CODEC_TX14"=15;
                         "CODEC_TX15"=16;
                         "CODEC_TX16"=17;
                         "CODEC_TX17"=18;
						 "CODEC_TX18"=19;
                         "CODEC_TX19"=20;
                         "CODEC_TX20"=21;
                         "CODEC_TX21"=22;
                         "CODEC_TX22"=23}
    @h2xmle_default      {1}
    @h2xml_Select     {param_id_hw_delay_t}
    @h2xmlm_InsertParameter
    @h2xml_Select             {param_id_prbdma_enable_t}
    @h2xmlm_InsertParameter
    @h2xml_Select             {param_id_prbdma_debug_config_t}
    @h2xmlm_InsertParameter
    @h2xml_Select             {param_id_hw_ep_data_interleaving_t}
    @h2xmlm_InsertParameter
    @h2xml_Select             {param_id_hw_ep_timestamp_propagation_t}
    @h2xmlm_InsertParameter
	@h2xml_Select             {param_id_silence_detection_t}
    @h2xmlm_InsertParameter
    @h2xml_Select             {event_cfg_silence_detection_t}
    @h2xmlm_InsertParameter
    @h2xml_Select     {param_id_hw_ep_dma_data_align_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_dma_data_align_t::dma_data_align}
    @h2xmle_rangeList    {"DMA_DATA_ALIGN_MSB"=0;
                         "DMA_DATA_ALIGN_LSB"=1}
    @h2xmle_default      {0}
    @h2xml_Select     {param_id_hw_delay_t}
    @h2xmlm_InsertParameter
    @h2xml_Select     {param_id_codec_dma_codec_fs_sel_cfg_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/
#endif //_CODEC_DMA_API_H_
