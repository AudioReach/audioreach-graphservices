/**
 * \file sh_mem_pull_push_mode_api.h
 * \brief 
 *  This file contains CAPI pull mode and push mode module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _PULL_PUSH_MODE_API_H_
#define _PULL_PUSH_MODE_API_H_

 /*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "apm_container_api.h"
#include "media_fmt_api.h"

/**
     @h2xml_title1          {Shared memory pull and push module}
     @h2xml_title_agile_rev {Shared memory pull and push module}
     @h2xml_title_date      {March 29, 2019}
  */

#define SH_MEM_PULL_MODE_MAX_INPUT_PORTS                  0x0

#define SH_MEM_PULL_MODE_MAX_OUTPUT_PORTS                 0x1

#define SH_MEM_PULL_MODE_STACK_SIZE_REQUIREMENT           4096

#define SH_MEM_PUSH_MODE_MAX_INPUT_PORTS                  0x1

#define SH_MEM_PUSH_MODE_MAX_OUTPUT_PORTS                 0x0

#define SH_MEM_PUSH_MODE_STACK_SIZE_REQUIREMENT           4096

/**
   @h2xmlx_xmlNumberFormat {int}
*/

/*==============================================================================
   Event ID
==============================================================================*/

/**
 * Watermark event ID from pull/push module to the client.
 *
 * Payload of the configuration in APM_CMD_REGISTER_MODULE_EVENTS: event_cfg_sh_mem_pull_push_mode_watermark_level_t
 * Payload of the event APM_EVENT_MODULE_TO_CLIENT: event_sh_mem_pull_push_mode_watermark_level_t
 */
#define EVENT_ID_SH_MEM_PULL_PUSH_MODE_WATERMARK 0x0800101C

#include "spf_begin_pack.h"

struct event_cfg_sh_mem_pull_push_mode_watermark_level_t
{
   uint32_t watermark_level_bytes;
   /**< @h2xmle_description {Watermark level in bytes} 
        @h2xmle_policy      {Basic} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */         
}

#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct event_cfg_sh_mem_pull_push_mode_watermark_level_t event_cfg_sh_mem_pull_push_mode_watermark_level_t;

/**< Number of watermark-level structures of type
        sh_mem_pull_push_mode_watermark_level_t following this structure.
        Overall structure is
        {
            event_cfg_sh_mem_pull_push_mode_watermark_t a;
            event_cfg_sh_mem_pull_push_mode_watermark_level_t[num_water_mark_levels];
        }
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_cfg_sh_mem_pull_push_mode_watermark_t
{
   uint32_t num_water_mark_levels;
   /**< @h2xmle_description {Number of watermark-level structures of type. 
                             sh_mem_pull_push_mode_watermark_level_t following this structure. 
                             If set to zero, no watermark levels are specified, and hence no watermark events are supported.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */ 
#if defined(__H2XML__)
   event_cfg_sh_mem_pull_push_mode_watermark_level_t levels[0];     
   /**< @h2xmle_description {Watermark levels} 
        @h2xmle_variableArraySize {num_water_mark_levels}
        @h2xmle_policy      {Basic} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct event_cfg_sh_mem_pull_push_mode_watermark_t event_cfg_sh_mem_pull_push_mode_watermark_t;


#include "spf_begin_pack.h"
struct event_sh_mem_pull_push_mode_watermark_level_t
{
   uint32_t    watermark_level_bytes;
   /**< h2xmle_description {Watermark level in bytes} 
        h2xmle_policy      {Basic} 
        h2xmle_default     {0} 
        h2xmle_range       { 0..0xFFFFFFFF }
        h2xmle_policy      {Basic} */  
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct event_sh_mem_pull_push_mode_watermark_level_t event_sh_mem_pull_push_mode_watermark_level_t;

/** @ingroup ar_spf_mod_ep_shmempp_mods
    Identifier of the EOS marker event from the #MODULE_ID_SH_MEM_PUSH_MODE modules to the client.
    EOS marker payload has the timestamp info when the Push mode module receives end of the stream, which
    inturn indicates the TS till which client can read the current stream from circular buffer.

    The client must exercise this event with caution and cannot assume has absolutely ended here.
    Event only indicates that the stream momentarily ended at this timestamp. The data flow can always resume
    if the upstream graph of the push mode graph remains started. So there is no synchronization promised with
    respect to the data flow and EOS event.

    @msgpayload
    Client needs to register with the module through APM_CMD_REGISTER_MODULE_EVENTS. No
    payload required for this event's registration.\n

    @par
    @indent{12pt} Payload of the event raised by the module to the client
                  through \n
    @indent{12pt} APM_CMD_REGISTER_MODULE_EVENTS. \n
    @indent{12pt} event_sh_mem_push_mode_eos_marker_t
    @par
    @note1hang For information about the APM events, see the AudioReach SPF
    API Reference (80-VN500-5).
 */
#define EVENT_ID_SH_MEM_PUSH_MODE_EOS_MARKER    0x080013DD

/** @ingroup ar_spf_mod_ep_shmempp_mods
    Payload of the event EVENT_ID_SH_MEM_PUSH_MODE_EOS_MARKER, contains the timestamp of the EOS marker. */
#include "spf_begin_pack.h"
struct event_sh_mem_push_mode_eos_marker_t
{
    uint32_t index;
   /**< Index of the sample in the circular buffer at which EOS marker is set.

        Range for the index:
        0 @ge index \> shared_circ_buf_size - 1 */

   /*#< @h2xmle_description {Index of the sample in the circular buffer at which EOS marker is set. \n
                             Range for the index: 0 &ge; index &gt; shared_circ_buf_size - 1}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {0..0xFFFFFFFF}
        @h2xmle_policy      {Basic} */

   uint32_t timestamp_us_lsw;
   /**< Lower 32 bits of Timestamp at which push mode module received EOS. */

   /*#< @h2xmle_description {Lower 32 bits of Timestamp at which push mode module gets EOS. }
        @h2xmle_default     {0}
        @h2xmle_range       {0..0xFFFFFFFF}
        @h2xmle_policy      {Basic} */

   uint32_t timestamp_us_msw;
   /**< Higher 32 bits of Timestamp at which push mode module received EOS. */

   /*#< @h2xmle_description {Higher 32 bits of Timestamp at which push mode module gets EOS. }
        @h2xmle_default     {0}
        @h2xmle_range       {0..0xFFFFFFFF}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;
typedef struct event_sh_mem_push_mode_eos_marker_t event_sh_mem_push_mode_eos_marker_t;
/** Position buffer for pull mode writes and push mode reads. */
#include "spf_begin_pack.h"
struct sh_mem_pull_push_mode_position_buffer_t
{
   volatile uint32_t frame_counter;
   /**< @h2xmle_description {Counter used to handle interprocessor synchronization issues associated
                             with reading write_index, wall_clock_us_lsw, and wall_clock_us_msw.
                             These are invalid when frame_counter = 0.
                             
                             Read the frame_counter value both before and after reading these values
                             to make sure the spf did not update them while the client was reading
                             them.
                            } 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */  
        
   volatile uint32_t index;
   /**< @h2xmle_description {Index in bytes to where the spf is writing (push mode) or reading (pull mode).
                             "0 &ge; index &gt; sh_mem_pull_push_mode_cfg_t::shared_circ_buf_size - 1"} 
        @h2xmle_default     {0} 
        @h2xmle_rangeList   { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */  
        
   volatile uint32_t timestamp_us_lsw;
   /**< @h2xmle_description {Upper 32 bits of the 64-bit timestamp in microseconds.
                              For pull mode, the timestamp is the timestamp at which index was updated.
                              For push mode, the timestamp is the buffer or the capture timestamp of the sample at index.
                            }
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */          

   volatile uint32_t timestamp_us_msw;
   /**< @h2xmle_description {Upper 32 bits of the 64-bit timestamp in microseconds.
                              For pull mode, the timestamp is the timestamp at which index was updated.
                              For push mode, the timestamp is the buffer or the capture timestamp of the sample at index.
                            }
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */              
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct sh_mem_pull_push_mode_position_buffer_t sh_mem_pull_push_mode_position_buffer_t;

/*==============================================================================
   Param ID
==============================================================================*/

/* Parameter id to be used to configure shared mem info for pull mode and push mode.

   Before issuing this set-param, APM_CMD_SHARED_MEM_MAP_REGIONS must be
   issued and memories for position buffer and shared circular buffer must be mapped.

   Position buffer must be always mapped as uncached.
   Shared circular buffer must be mapped as uncached for push mode and cached for pull mode.

   Payload struct sh_mem_pull_push_mode_cfg_t
 */
#define PARAM_ID_SH_MEM_PULL_PUSH_MODE_CFG 0x0800100A

/*==============================================================================
   Param structure defintions
==============================================================================*/

#include "spf_begin_pack.h"
struct sh_mem_pull_push_mode_cfg_t
{
   uint32_t shared_circ_buf_addr_lsw;
   /**< @h2xmle_description {Lower 32 bits of the address of the shared circular buffer.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */       

   uint32_t shared_circ_buf_addr_msw;
   /**< @h2xmle_description {Upper 32 bits of the address of the shared circular buffer.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */          

   uint32_t shared_circ_buf_size;
   /**< @h2xmle_description {Number of bytes in the shared circular buffer. 
                             The value must be an integral multiple of the number of (bits per sample * number of channels)}
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */           

   uint32_t circ_buf_mem_map_handle;
   /**< @h2xmle_description {Unique identifier for the shared memory address of shared circular buffer.
                             The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */             

   uint32_t shared_pos_buf_addr_lsw;
   /**< @h2xmle_description {Lower 32 bits of the address of the shared Position buffer.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */                

   uint32_t shared_pos_buf_addr_msw;
   /**< @h2xmle_description {Upper 32 bits of the address of the shared Position buffer.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */                   

   uint32_t pos_buf_mem_map_handle;
   /**< @h2xmle_description {Unique identifier for the shared memory address of position buffer.
                             The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS.} 
        @h2xmle_default     {0} 
        @h2xmle_range       { 0..0xFFFFFFFF }
        @h2xmle_policy      {Basic} */                           
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct sh_mem_pull_push_mode_cfg_t sh_mem_pull_push_mode_cfg_t;

/*
 * ID of the Shared Memory Pull mode Module
 * 
 *  Supported Input Media Format:
 *  - Data Format          : FIXED_POINT
 *  - fmt_id               : MEDIA_FMT_ID_PCM
 *  - Sample Rates         : 1-384 kHz
 *  - Number of channels   : 1-32
 *  - Bit Width            : 16 (bits per sample 16 and Q15),
 *                         : 24 (bits per sample 24 and Q23, bits per sample 32 and Q23 or Q27 or Q31),
 *                         : 32 (bits per sample 32 and Q31)
 *  - Interleaving         : interleaved, deinterleaved unpacked, deinterleaved packed.
 *  - Endianess            : little, big
 */
#define MODULE_ID_SH_MEM_PULL_MODE 0x07001006
/**
    @h2xmlm_module         {"MODULE_ID_SH_MEM_PULL_MODE", MODULE_ID_SH_MEM_PULL_MODE}
    @h2xmlm_displayName    {"Shared Memory Pull-Mode EndPoint"}
    @h2xmlm_description    {
                            This module is used to write data to spf from the host through shared circular buffer mechanism.
                            This module has only one static output port with ID 1.
                            Pull mode module doesn't work without receiving PARAM_ID_MEDIA_FORMAT.
                           }
    @h2xmlm_dataMaxInputPorts    {SH_MEM_PULL_MODE_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts   {SH_MEM_PULL_MODE_MAX_OUTPUT_PORTS}
    @h2xmlm_dataOutputPorts      {OUT = 1}
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            { SH_MEM_PULL_MODE_STACK_SIZE_REQUIREMENT }
    @h2xmlm_toolPolicy     {Calibration}

    @{                     <-- Start of the Module -->
    @h2xml_Select          {"sh_mem_pull_push_mode_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"event_cfg_sh_mem_pull_push_mode_watermark_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"media_format_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

/*
 * ID of the Shared Memory Push mode Module
 * 
 * Supported Input Media Format:
 *  - Data Format          : FIXED_POINT
 *  - fmt_id               : Don't care
 *  - Sample Rates         : 1-384 kHz
 *  - Number of channels   : 1-32
 *  - Bit Width            : 16 (bits per sample 16 and Q15),
 *                         : 24 (bits per sample 24 and Q23, bits per sample 32 and Q23 or Q27 or Q31),
 *                         : 32 (bits per sample 32 and Q31)
 *  - Interleaving         : interleaved, deinterleaved unpacked, deinterleaved packed.
 *  - Endianess            : little, big
 */
#define MODULE_ID_SH_MEM_PUSH_MODE 0x07001007
/**
    @h2xmlm_module         {"MODULE_ID_SH_MEM_PUSH_MODE", MODULE_ID_SH_MEM_PUSH_MODE}
    @h2xmlm_displayName    {"Shared Memory Push-Mode EndPoint"}
    @h2xmlm_description    {
                            This module is used to read data from spf to the host through shared circular buffer mechanism.
                            This module has only one static input port with ID 2.
                            }
    @h2xmlm_dataMaxInputPorts    {SH_MEM_PUSH_MODE_MAX_INPUT_PORTS}
    @h2xmlm_dataInputPorts       {IN = 2}
    @h2xmlm_dataMaxOutputPorts   {SH_MEM_PUSH_MODE_MAX_OUTPUT_PORTS}
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize            { SH_MEM_PUSH_MODE_STACK_SIZE_REQUIREMENT }
    @h2xmlm_toolPolicy     {Calibration}
    @h2xmlm_toolPolicy     {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"sh_mem_pull_push_mode_cfg_t"}
    @h2xmlm_InsertParameter
    @h2xml_Select          {"event_cfg_sh_mem_pull_push_mode_watermark_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif // _PULL_PUSH_MODE_API_H_
