#ifndef COP_V2_PACKETIZER_API_H
#define COP_V2_PACKETIZER_API_H

/*==============================================================================
  @file cop_v2_packetizer_api.h
  @brief This file contains cop pack v2 module APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
// clang-format on

/**@h2xml_title1          {COP Packetizer V2}
   @h2xml_title_agile_rev {COP Packetizer V2}
   @h2xml_title_date      {June 30 2020}  */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "cop_packetizer_cmn_api.h"
#include "imcl_spm_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/
/* CoP Packetizer module stack size*/
#define COP_V2_PACK_STACK_SIZE 6144

/* Input port ID of CoP Packetizer module */
#define PORT_ID_COP_V2_PACK_INPUT 0x2

/* Output port ID of CoP Packetizer module */
#define PORT_ID_COP_V2_PACK_OUTPUT 0x1

/* Max number of intent per control port of CoP Packetizer module */
#define COP_PACK_MAX_INTENTS_PER_CTRL_PORT 1

/* Static input control port ID's of CoP Packetizer module */
#define COP_PACKETIZER_FEEDBACK_IN AR_NON_GUID(0xC0000001)

/* Direction of Stream Information for CoP Packetizer module */
#define COP_V2_FROM_AIR    1
#define COP_V2_TO_AIR      0

/*==============================================================================
   Param ID
==============================================================================*/

/** Parameter ID of CoP V2 Stream Info */
#define PARAM_ID_COP_V2_STREAM_INFO            0x08001255

/** @h2xmlp_parameter   {"PARAM_ID_COP_V2_STREAM_INFO", PARAM_ID_COP_V2_STREAM_INFO}
    @h2xmlp_description {Structure for the param_id_cop_v2_stream_info_t parameter used by the COP v2 modules.
                         It is a mandatory param for pack v2 module to work }
    @h2xmle_policy      {Basic} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct cop_v2_stream_info_map_t
{
   uint32_t stream_id;
   uint32_t direction;
   uint32_t channel_mask_lsw;
   uint32_t channel_mask_msw;
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_cop_v2_stream_info_t
{
   uint32_t num_streams;
   /**
     @h2xmle_description {Number of Packetizer Output Streams}
     @h2xmle_default     {0}
     @h2xmle_rangeList   {"INVALID_VALUE"=0}
     @h2xmle_policy      {Basic}
    */

#if defined (__H2XML__)
   cop_v2_stream_info_map_t stream_map[0];
   /**< @h2xmle_description  {Channel mapping from Stream ID to Bluetooth Channel ID. \n
                              ->Specify a mapping for each output stream}
        @h2xmle_variableArraySize {num_streams}
        @h2xmle_default      {0}    */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_cop_v2_stream_info_t param_id_cop_v2_stream_info_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** @h2xml_title1           {CoP V2 Packetizer Module API} */

/**
 * Module ID for CoP V2 Packetizer
 */

#define MODULE_ID_COP_V2_PACKETIZER 0x070010B0
/**
   @h2xmlm_module              {"MODULE_ID_COP_V2_PACKETIZER",
                                 MODULE_ID_COP_V2_PACKETIZER}
   @h2xmlm_displayName         {"CoP V2 Packetizer"}
   @h2xmlm_description         {- CoP V2 Packetizer\n
                                - This module packetizes deinterleaved raw bitstream into Compressed Over PCM packetized bitstream\n
                                - This module should be in the same subgraph as the encoder\n
                                - Supports following params: mandatory param: \n
                                - PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT
                                - PARAM_ID_COP_V2_STREAM_INFO
                                - Supported Input Media Format: \n
                                - Data Format          : CAPI_DEINTERLEAVED_RAW_COMPRESSED, RAW_COMPRESSED
                                - fmt_id               : Don't care \n}
    @h2xmlm_dataInputPorts      {IN = PORT_ID_COP_V2_PACK_INPUT}
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_COP_V2_PACK_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlStaticPort      {"COP_PACKETIZER_FEEDBACK_IN" = 0xC0000001,
                                 "BT Packetizer feedback intent" = INTENT_ID_V2_PACKETIZER_FEEDBACK}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {COP_V2_PACK_STACK_SIZE}
    @{                          <-- Start of the Module -->

    @h2xml_Select               {param_id_cop_pack_output_media_fmt_t}
    @h2xmlm_InsertParameter
    @h2xml_Select               {param_id_cop_v2_stream_info_t}
    @h2xmlm_InsertParameter
    @}                        <-- End of the Module -->
*/
#endif // COP_V2_PACKETIZER_API_H
