#ifndef _USB_API_H_
#define _USB_API_H_

/**
 * \file usb_api.h
 * \brief 
 *  	 This file contains USB module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/** @h2xml_title1          {USB Module API}
    @h2xml_title_agile_rev {USB Module API}
    @h2xml_title_date      {April 24, 2019}  */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "hw_intf_cmn_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Stack size for USB Module*/
#define USB_STACK_SIZE                                      4096
/* Input port ID of USB module */
#define PORT_ID_USB_INPUT                                   0x2

/* Output port ID of USB module */
#define PORT_ID_USB_OUTPUT                                  0x1
/*==============================================================================
   Type definition
==============================================================================*/

/** Parameter used to configure the USB interface  */
#define PARAM_ID_USB_AUDIO_INTF_CFG                               0x080010D6
/** @h2xmlp_parameter   {"PARAM_ID_USB_AUDIO_INTF_CFG",
                           PARAM_ID_USB_AUDIO_INTF_CFG}
    @h2xmlp_description {Configures the USB interface.}
    @h2xmlp_toolPolicy   {Calibration}     */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_USB_AUDIO_INTF_CFG */
struct param_id_usb_audio_intf_cfg_t
{
   uint32_t usb_token;
   /**< @h2xmle_description {Valid token for the USB audio device} */
   uint32_t svc_interval;
   /**< @h2xmle_description {USB device service interval in microseconds. Though the acceptable
         values are between 125- 3276800, the actual supported values are
         determined by the equation specified in USB 3.0 documentation.}
         @h2xmle_range      {125..3276800}
         @h2xmle_default {125}
   */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_usb_audio_intf_cfg_t param_id_usb_audio_intf_cfg_t;
/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/** Module ID for USB sink module */
#define MODULE_ID_USB_AUDIO_SINK     0x0700104F
/** @h2xmlm_module              {"MODULE_ID_USB_AUDIO_SINK",
                                 MODULE_ID_USB_AUDIO_SINK}
  @h2xmlm_displayName         {"USB Sink"}
  @h2xmlm_description         {- USB Sink Module\n
                                 - Supports following params: \n
                                 - PARAM_ID_USB_AUDIO_INTF_CFG \n
                                 - PARAM_ID_HW_EP_MF_CFG \n
                                 - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                                 - Supported Input Media Format: \n
                                 - Data Format          : FIXED_POINT \n
                                 - fmt_id               : Don't care \n
                                 - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                                 - Number of channels   : 1, 2, 3, 4, 5, 6, 7, 8 \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                 -                      : 24 (bits per sample 24 and Q27), \n
                                 -                      : 32 (bits per sample 32 and Q31) \n
                                 - Q format             : Q15, Q27, Q31 \n
                                 - Interleaving         : USB sink module needs de-interleaved unpacked }
    @h2xmlm_dataInputPorts      {IN = PORT_ID_USB_INPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {0}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HW-EP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize           { USB_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select    {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_rangeList    {"ONE"=1;
                         "TWO"=2;
                         "THREE"=3;
                         "FOUR"=4;
                         "FIVE"=5;
                         "SIX"=6;
                         "SEVEN"=7;
                         "EIGHT"=8}
   @h2xmle_default      {1}
   @h2xml_Select       {param_id_hw_ep_mf_t::data_format}
   @h2xmle_rangeList   {"FIXED_POINT"=1}
   @h2xmle_default      {1}
  
   @h2xml_Select    {param_id_frame_size_factor_t}
   @h2xmlm_InsertParameter
    
   @h2xml_Select      {param_id_usb_audio_intf_cfg_t}
   @h2xmlm_InsertParameter
   @}                   <-- End of the Module -->*/

/** Module ID for USB source module  */
#define MODULE_ID_USB_AUDIO_SOURCE 0x07001050
/** @h2xmlm_module              {"MODULE_ID_USB_AUDIO_SOURCE",
                                  MODULE_ID_USB_AUDIO_SOURCE}
    @h2xmlm_displayName         {"USB Source"}
    @h2xmlm_description         {- USB Source Module\n
                                 - Supports following params: \n
                                 - PARAM_ID_USB_AUDIO_INTF_CFG \n
                                 - PARAM_ID_HW_EP_MF_CFG \n
                                 - PARAM_ID_HW_EP_FRAME_SIZE_FACTOR \n
                                 - PARAM_ID_HW_EP_SRC_CHANNEL_MAP\n
                                 - Supported Input Media Format: \n
                                 - USB source module doesn't take any inputs }
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_USB_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {0}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlDynamicPortIntent  { "Qtimer HWEP drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= -1 }
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize           { USB_STACK_SIZE }
    @h2xmlm_toolPolicy          { Calibration }
    @{                          <-- Start of the Module -->

    @h2xml_Select    {param_id_hw_ep_mf_t}
    @h2xmlm_InsertParameter
    @h2xml_Select        {param_id_hw_ep_mf_t::num_channels}
    @h2xmle_rangeList    {"ONE"=1;
                         "TWO"=2;
                         "THREE"=3;
                         "FOUR"=4;
                         "FIVE"=5;
                         "SIX"=6;
                         "SEVEN"=7;
                         "EIGHT"=8}
    @h2xmle_default      {1}
    @h2xml_Select       {param_id_hw_ep_mf_t::data_format}
    @h2xmle_rangeList   {"FIXED_POINT"=1}
    @h2xmle_default      {1}

    @h2xml_Select     {param_id_frame_size_factor_t}
    @h2xmlm_InsertParameter

    @h2xml_Select     {param_id_usb_audio_intf_cfg_t}
    @h2xmlm_InsertParameter

    @h2xml_Select        {param_id_hw_ep_src_channel_map_t}
    @h2xmlm_InsertParameter
    @h2xml_Select       {param_id_hw_ep_src_channel_map_t::num_channels}
    @h2xmle_range       { 0..8 }
    @}                   <-- End of the Module -->*/

#endif //_USB_API_H_
