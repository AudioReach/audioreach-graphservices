/**
 * \file slimbus_api.h
 * \brief
 *  	 This file contains slimbus module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SLIMBUS_API_H_
#define _SLIMBUS_API_H_

 /*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "hw_intf_cmn_api.h"

/** @h2xml_title1          {SLIMBUS Module API}
    @h2xml_title_agile_rev  {SLIMBUS Module API}
     @h2xml_title_date      {29 Jan, 2019} */

/*==============================================================================
   Constants
==============================================================================*/
/** Sets SLIMbus device ID 1. */
#define SLIMBUS_DEVICE_1                                  0x0

/** Sets SLIMbus device ID 2. */
#define SLIMBUS_DEVICE_2                                  0x1

/** Enumeration for setting the maximum number of channels per device @newpage */
#define SB_MAX_CHAN_CNT                                   8

#define CAPI_SLIMBUS_STACK_SIZE                        4096

#define PARAM_ID_SLIMBUS_CONFIG                           0x08001068

  /** @h2xmlp_parameter   {"PARAM_ID_SLIMBUS_CONFIG",
                           PARAM_ID_SLIMBUS_CONFIG}
      @h2xmlp_description {Configures the SLIMBUS interface.} 
      @h2xmlp_toolPolicy   {Calibration}
      */
/* Payload of the PARAM_ID_SLIMBUS_CONFIG parameter
 */
#include "spf_begin_pack.h"
struct param_id_slimbus_cfg_t
{
    uint32_t                  slimbus_dev_id;
    /**< @h2xmle_description {ID of the SLIMbus hardware device. This ID is required to handle
                              multiple SLIMbus hardware blocks.}
       @h2xmle_rangeList   {"SLIMBUS_DEVICE_1"=0;
                            "SLIMBUS_DEVICE_2"=1}
       @h2xmle_default     {0}
  */
    uint8_t                  shared_channel_mapping[SB_MAX_CHAN_CNT];
    /**< @h2xmle_description {Shared_channel_mapping[i] represents the shared channel assigned for
                              audio channel i in multichannel audio data.
                              Array of shared channel IDs (128 to 255) to which the master port
                              is connected.}
       @h2xmle_range        {128..255}
       @h2xmle_default      {128}
  */

}
#include "spf_end_pack.h"
; 
typedef struct param_id_slimbus_cfg_t param_id_slimbus_cfg_t;


/*------------------------------------------------------------------------------
  Module
------------------------------------------------------------------------------*/
/** Module ID for SLIMBUS sink module */
/* 

*/
#define MODULE_ID_SLIMBUS_SINK                            0x07001029
/** @h2xmlm_module       {"MODULE_ID_SLIMBUS_SINK",
                           MODULE_ID_SLIMBUS_SINK}
    @h2xmlm_displayName    {"SLIMBus Sink"}
    @h2xmlm_description  {SLIMBUS Sink Module \n
*  - Supports following params: \n
*  - PARAM_ID_SLIMBUS_CONFIG \n
*  - PARAM_ID_HW_EP_MF_CFG \n
*  - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
*
* Supported Input Media Format:\n
*  - Data Format          : SB_DATA_FORMAT_NOT_INDICATED, FIXED_POINT,\n
*  -                        COMPR_OVER_PCM_PACKETIZED, GENERIC_COMPRESSED \n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
*                           88.2, 96, 176.4, 192, 352.8, 384 kHz\n
*  - Number of channels   : 1 to 8\n
*  - Channel type         : Don't care\n
*  - Bit Width            : 16 (bits per sample 16 and Q15),\n
*                         : 24 (bits per sample 24 and Q27)\n
*                         : 32 (bits per sample 32 and Q31) \n
*  - Q format             : Q15, Q27, Q31\n
*  - Interleaving         : Deinterleaved unpacked \n
    }
    @h2xmlm_dataMaxInputPorts    {1}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {CAPI_SLIMBUS_STACK_SIZE}
    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
    @h2xml_Select        {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_range        {1..SB_MAX_CHAN_CNT}
    @h2xmle_default      {1}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    {"FIXED POINT"=1;
                          "COMPR OVER PCM PACKETIZED"=7;
                          "GENERIC COMPRESSED"=5}
    @h2xmle_default      {1}

    @h2xml_Select        {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter
        
    @h2xml_Select        {param_id_slimbus_cfg_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/ 
/** Module ID for SLIMBUS source module  */
#define MODULE_ID_SLIMBUS_SOURCE                          0x0700102A
/** @h2xmlm_module       {"MODULE_ID_SLIMBUS_SOURCE",
                           MODULE_ID_SLIMBUS_SOURCE}
    @h2xmlm_displayName    {"SLIMBus Source"}
    @h2xmlm_description  {SLIMBUS Source Module\n
*  - Supports following params: \n
*  - PARAM_ID_SLIMBUS_CONFIG \n
*  - PARAM_ID_HW_EP_MF_CFG \n
*  - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
*  - PARAM_ID_HW_EP_SRC_CHANNEL_MAP\n
- # Slimbus source doesn't take any inputs} 
    @h2xmlm_dataMaxInputPorts    {0}
    @h2xmlm_dataMaxOutputPorts   {1}
    @h2xmlm_dataOutputPorts      {OUT=1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize            {CAPI_SLIMBUS_STACK_SIZE}
    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
    
    @h2xml_Select        {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_range        {1..8}
    @h2xmle_default      {1}
    @h2xml_Select        {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList    {"FIXED POINT"=1;
    					        "COMPR OVER PCM PACKETIZED" = 7;
                          "GENERIC COMPRESSED"=5}
    @h2xmle_default      {1}

    @h2xml_Select        {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter
    
    @h2xml_Select        {param_id_slimbus_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_ep_src_channel_map_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_src_channel_map_t::num_channels}
    @h2xmle_range        {0..8}
    @}                   <-- End of the Module -->*/


#endif // _SLIMBUS_API_H_
