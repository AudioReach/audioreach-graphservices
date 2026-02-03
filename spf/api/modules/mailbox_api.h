/**
 * \file mailbox_api.h
 * \brief 
 *  	 This file contains CAPI Mailbox rx and tx module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MAILBOX_API_H_
#define _MAILBOX_API_H_

 /**
     @h2xml_title1          {Module Mailbox rx and tx}
     @h2xml_title_agile_rev {Module Mailbox rx and tx}
     @h2xml_title_date      {June 9, 2019}
  */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "apm_graph_properties.h"
#include "imcl_fwk_intent_api.h"
#include "imcl_spm_intent_api.h"

#define MAILBOX_TX_MAX_INPUT_PORTS                  0x1

#define MAILBOX_TX_MAX_OUTPUT_PORTS                 0x0

#define MAILBOX_TX_STACK_SIZE_REQUIREMENT           4096

#define MAILBOX_RX_MAX_INPUT_PORTS                  0x0

#define MAILBOX_RX_MAX_OUTPUT_PORTS                 0x1

#define MAILBOX_RX_STACK_SIZE_REQUIREMENT           4096

/**
   @h2xmlx_xmlNumberFormat {int}
*/

/*==============================================================================
   Static Control port ID
==============================================================================*/

/* static control port id connected to DTMF generator module */
#define MAILBOX_RX_DTMF_GEN_STATIC_CONTROL_PORT_ID    AR_NON_GUID(0xC0000001)

/*************************************************** DTMF media format *************************************************/
/**
 * Media format ID for DTMF tone and the payload.
 */
#define MEDIA_FMT_ID_DTMF                             0x09001038

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/**
 * Payload of fmt-id = MEDIA_FMT_ID_DTMF 
 */
struct payload_media_fmt_dtmf_tone_t
{   
   uint16_t low_freq;
   /**< @h2xmle_description {DTMF Tone low frequency in Hz}
        @h2xmle_default     {697}
        @h2xmle_rangeList   {0=697, 1=770, 2=852, 3=941}
        @h2xmle_policy      {Basic} */

   uint16_t high_freq;
   /**< @h2xmle_description {DTMF Tone high frequency in Hz}
        @h2xmle_default     {1209}
        @h2xmle_rangeList   {0=1209, 1=1336, 2=1477, 3=1633}
        @h2xmle_policy      {Basic} */

   uint32_t duration_ms;
   /**< @h2xmle_description {Duration of the tone in milliseconds. The duration includes
                             ramp-up and ramp-down periods of 1 ms and 2 ms, respectively.
                              -1 - Infinite or Continuous tone mode, tone is played until stop is received.
                               0 - Stops the current tone,
                              >0 - tone is generated for the given duration (milli secs) }
        @h2xmle_default     {0}
        @h2xmle_range       {0...0xFFFFFFFF}
        @h2xmle_policy      {Basic} */

   uint16_t gain;
   /**< @h2xmle_description {DTMF tone linear gain. Because the level of tone generation is fixed
                             at 0 dBFS, this parameter must be set to a value in Q13 format.}
        @h2xmle_default     {8192}
        @h2xmle_dataFormat  {Q13}  
        @h2xmle_policy      {Basic} */

   uint16_t generate_unmixed_output;
   /**< @h2xmle_description { Flag to inidicate if the generated DTMF tone needs to be mixed or not.
                               >0 -  Indicates only tone must be played
                                0 -  Indicates tone needs to be mixed with primary path. }
        @h2xmle_default     {0}
        @h2xmle_range       {0,1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct payload_media_fmt_dtmf_tone_t payload_media_fmt_dtmf_tone_t;


/*==============================================================================
   Events
==============================================================================*/

/*Event sent from Mailbox(ADSP) to VS(Modem) indicating that
  packet is having a NO_DATA frame.
*/
#define MAILBOX_PKTEXG_EVT_NO_DATA_PACKET  0x08001257 

/*==============================================================================
   Param ID
==============================================================================*/

/* Parameter id to be used to configuration info for mailbox module.

   Before issuing this set-param, APM_CMD_SHARED_MEM_MAP_REGIONS must be
   issued and memory corresponding to mailbox circular buffer must be mapped.
   
 */
#define PARAM_ID_MAILBOX_CFG 0x080010DF

/*==============================================================================
   Param structure defintions
==============================================================================*/

#include "spf_begin_pack.h"
typedef struct mailbox_config_t mailbox_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_MAILBOX_CFG", PARAM_ID_MAILBOX_CFG}
    @h2xmlp_description {Parameter id to be used to configure
                         shared mem info for mailbox
                         configuration.
                         Before issuing this set-param,
                         APM_CMD_SHARED_MEM_MAP_REGIONS must be
                         issued and memory for the circular
                         buffer must be mapped. }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */
struct mailbox_config_t
{
  uint32_t mem_handle;
  /**< @h2xmle_description {Unique identifier for the shared memory address of the mailbox vocoder
                             packet exchange data.                                                                          
                             The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */             

  uint32_t circ_buf_mem_address_lsw;
  /**< @h2xmle_description {Lower 32 bits of the address of the circular buffer used to hold vocoding
                            requests. }
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */       

  uint32_t circ_buf_mem_address_msw;
  /**< @h2xmle_description {Upper 32 bits of the address of the circular buffer used to hold vocoding
                            requests. }
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */       
       
  uint32_t circ_buf_mem_size;
  /**< @h2xmle_description {Size of the memory(in bytes) allocated for the circular buffer. 
                             The amount of memory available to hold vocoding requests must be an
                            integer multiple of the size of a single vocoding request data structure.}
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */       

}
#include "spf_end_pack.h"
;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct mailbox_voc_packet_t mailbox_voc_packet_t;

struct mailbox_voc_packet_t
{
  uint32_t minor_version;
  /**< @h2xmle_description {Minor version of the vocoder packet.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFF }
       @h2xmle_policy      {Basic} */
  
  uint64_t timestamp_us;
  /**< @h2xmle_description {Capture timestamp at microphone in microseconds.
                            The clock source used for interpreting the timestamp is specific
                            per product requirements.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */

  uint32_t status_mask;
  /**< @h2xmle_description {Bitmask that indicates the vocoder packet status.
                            - if bit 0 is set -- Indicates a general vocoding error, informing 
                              that the packet has been dropped. The data_size set to 0.
                            - bits 1 to 31 are Reserved.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
  
  uint32_t media_fmt_id;
  /**< @h2xmle_description {Media format ID of the vocoder packet.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
  
  uint32_t data_size;
  /**< @h2xmle_description {Actual size of the vocoder media data, in bytes.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
#if defined(__H2XML__)
  uint8_t data[0]; 
  /**< Vocoder media data of size data_size. */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#include "spf_begin_pack.h"
typedef struct mailbox_voc_request_t mailbox_voc_request_t;

/** 
    @h2xmlp_description {Structure for specifying an vocoding request.
                         An encoding request allows the client to specify the
                         timestamp of when an encoder packet is to be delivered
                         into shared memory. The client ensures
                         that the vocoding request is available
                         in shared memory at least 5
                         milliseconds before the requested
                         timestamp. The client is to provide the
                         next vocoding request immediately after
                         picking up an vocoder packet.
                         If the difference in timestamp values between two adjacent vocoding requests
                         is not exactly an vocoder packet duration in microseconds, a skew occurs
                         between the client timeline and stream timeline.}
*/
struct mailbox_voc_request_t 
{
  uint32_t mem_address_lsw;
  /**< @h2xmle_description {Lower 32 bits shared memory address of the vocoder packet.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */

  uint32_t mem_address_msw;
  /**< @h2xmle_description {Upper 32 bits of shared memory address of the vocoder packet.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
       
  uint32_t mem_size;
  /**< @h2xmle_description {Size of the memory allocated for the vocoder packet. 
                            The amount of memory allocated must be sufficient to hold the
                            largest possible vocoder packet for the media ID currently configured on the stream.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/* Type definition for mailbox_voc_req_circ_buffer_t. */
typedef struct mailbox_voc_req_circ_buffer_t mailbox_voc_req_circ_buffer_t;

/**< @h2xmle_description{Structure for specifying the format of a circular buffer that holds
                          vocoding requests.
                       
                         Each time a vocoding request is written into data[], the write offset is
                         advanced by the size of the request. After each vocoding request is read from
                         data[], the read offset is advanced by the size of the request. Any request
                         written into data[] is not modified before it is read.
                        
                         The read offset and write offset reset to 0 when they reach the end of
                         data[].

                         The data[] array is empty when the read offset and write offset are equal.
                         It is full when space is available to hold only one vocoding request. The
                         client does not write a new vocoding request when data[] is full.

                         The client shall provide a separate circular buffer
                         (mailbox_voc_req_circ_buffer_t) for each direction of the
                         stream subgraph. The circular buffer is used to hold the client's vocoding requests.
                        
                         Mailbox circular buffer can be reclaimed by the client only after the
                         following:
                            - The client has successfully destroyed the Voice stream subgraph.
                       
                         Making a mailbox vocoding request:
                            - The client places the request inside the corresponding circular buffer.
                            - The client advances the circular buffer's write offset by the size of
                              the request.
                            - When the mailbox module honors a vocoding request, it advances the circular
                              buffer's read offset by the size of the request.
                            - When mailbox module is running, the client can reclaim the vocoder packet
                              associated with the vocoding request only after the request is
                              completed.} */
struct mailbox_voc_req_circ_buffer_t
{
  uint32_t read_offset;
  /**< @h2xmle_description {Offset in bytes from the beginning of data[] where the next vocoding
                            request is read.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */

  uint8_t padding_1[ 252 ]; 
  /**< @h2xmle_description {Padding for cache line alignment. The content in the padding is
                            ignored.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */

  uint32_t write_offset;
  /**< @h2xmle_description {Offset in bytes from the beginning of data[] where the next vocoding
                            request is written.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */

  uint8_t padding_2[ 252 ];
  /**< @h2xmle_description {Padding for cache line alignment. The content in the padding is
                            ignored.} 
       @h2xmle_default     {0} 
       @h2xmle_range       { 0..0xFFFFFFFF }
       @h2xmle_policy      {Basic} */
#if defined(__H2XML__)
  uint8_t data[0];       /**< Circular buffer data. */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*==============================================================================
   Module defintions
==============================================================================*/

/*
 * ID of the Mailbox Rx Module
 * 
 *  Supported Input Media Format:
 *  - Data Format          : RAW_COMPRESSED.
 *  - fmt_id               : Don't care.
 *  - Sample Rates         : 8kHz, 16kHz, 32kHz, 48kHz.
 *  - Number of channels   : 1
 *  - Bit Width            : 16 (bits per sample 16 and Q15),
 *                         : 24 (bits per sample 24 and Q23, bits per sample 32 and Q23 or Q27 or Q31),
 *                         : 32 (bits per sample 32 and Q31)
 *  - Interleaving         : interleaved, deinterleaved unpacked, deinterleaved packed.
 *  - Endianess            : little, big
 */
#define MODULE_ID_MAILBOX_RX 0x07001057
/**
    @h2xmlm_module         {"MODULE_ID_MAILBOX_RX",
                            MODULE_ID_MAILBOX_RX}
    @h2xmlm_displayName    {"Mailbox EndPoint - Downlink"}
    @h2xmlm_description    {
                            This module is used to write data to
                            spf from the client through
                            mailbox circular buffer mechanism.
                           }
    @h2xmlm_dataMaxInputPorts    {MAILBOX_RX_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts   {MAILBOX_RX_MAX_OUTPUT_PORTS}
    @h2xmlm_ctrlStaticPort      {"DTMF_GEN_CTRL" = 0xC0000001,
                                 "DTMF generator ctrl" = INTENT_ID_DTMF_GENERATOR_CTRL}
    @h2xmlm_ctrlDynamicPortIntent  { "VFR drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= 1 }
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {
                                 MAILBOX_RX_STACK_SIZE_REQUIREMENT
                                 }
    @h2xmlm_toolPolicy     {Calibration}

    @{                     <-- Start of the Module -->
    @h2xml_Select          {"mailbox_config_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

/*
 * ID of the Mailbox Tx Module
 * 
 * Supported Input Media Format:
 *  - Data Format          : RAW_COMPRESSED.
 *  - fmt_id               : Don't care.
 *  - Sample Rates         : 8kHz, 16kHz, 32kHz, 48kHz.
 *  - Number of channels   : 1
 *  - Bit Width            : 16 (bits per sample 16 and Q15),
 *                         : 24 (bits per sample 24 and Q23, bits per sample 32 and Q23 or Q27 or Q31),
 *                         : 32 (bits per sample 32 and Q31)
 *  - Interleaving         : interleaved, deinterleaved unpacked, deinterleaved packed.
 *  - Endianess            : little, big
 */
#define MODULE_ID_MAILBOX_TX 0x07001056
/**
    @h2xmlm_module         {"MODULE_ID_MAILBOX_TX",
                             MODULE_ID_MAILBOX_TX}
    @h2xmlm_displayName    {"Mailbox EndPoint - Uplink"}
    @h2xmlm_description    {
                            This module is used to read data
                            from spf to the Client through
                            shared circular buffer mechanism.
                            }
    @h2xmlm_dataMaxInputPorts   {MAILBOX_TX_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts   {MAILBOX_TX_MAX_OUTPUT_PORTS}
    @h2xmlm_ctrlDynamicPortIntent  { "VFR drift info"=INTENT_ID_TIMER_DRIFT_INFO, maxPorts= -1 }
    @h2xmlm_ctrlDynamicPortIntent  { "HW EP Module Instance info"=INTENT_ID_MODULE_INSTANCE_INFO, maxPorts= 1 }
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize       {MAILBOX_TX_STACK_SIZE_REQUIREMENT}
    @h2xmlm_toolPolicy     {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"mailbox_config_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif // _MAILBOX_API_H_
