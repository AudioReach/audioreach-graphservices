#ifndef COP_V2_DEPACKETIZER_API_H
#define COP_V2_DEPACKETIZER_API_H

/*==============================================================================
  @file cop_v2_depacketizer_api.h
  @brief This file contains cop depack module v2 APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
// clang-format on

/** @h2xml_title1          {COP V2 Depacketizer }
    @h2xml_title_agile_rev {COP V2 Depacketizer }
    @h2xml_title_date      {Oct 23, 2020}  */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"
#include "imcl_spm_intent_api.h"
#include "cop_v2_packetizer_api.h"
/*==============================================================================
   Constants
==============================================================================*/
/* CoP Depacketizer module stack size*/
#define COP_V2_DEPACK_STACK_SIZE 6144

/* Input port ID of CoP Depacketizer module */
#define PORT_ID_COP_V2_DEPACK_INPUT 0x2

/* Output port ID of CoP Depacketizer module */
#define PORT_ID_COP_V2_DEPACK_OUTPUT 0x1       //TODO: multiple stream ids

/* Max number of intent per control port of CoP Depacketizer module */
#define COP_V2_DEPACK_MAX_INTENTS_PER_CTRL_PORT 1

/* Static output control port ID's of CoP Depacketizer module */
#define REFCLK_REMOTE_TIMING_OUT_FOR_RAT_RENDER AR_NON_GUID(0xC0000001) //rx
#define REFCLK_REMOTE_TIMING_OUT_FOR_RAT_CAPTURE AR_NON_GUID(0xC0000002) //tx
#define COP_ENCODER_FEEDBACK_OUT AR_NON_GUID(0xC0000003)
#define COP_PACKETIZER_FEEDBACK_OUT AR_NON_GUID(0xC0000004)
#define DEADLINE_TIME_OUT AR_NON_GUID(0xC0000005)

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** @h2xml_title1           {CoP V2 Depacketizer Module API} */

/**
 * Module ID for CoP V2 Depacketizer.
 */
#define MODULE_ID_COP_V2_DEPACKETIZER 0x070010C1
/**
   @h2xmlm_module              {"MODULE_ID_COP_V2_DEPACKETIZER",
                                 MODULE_ID_COP_V2_DEPACKETIZER}
   @h2xmlm_displayName         {"CoP V2 Depacketizer "}
   @h2xmlm_description         { - CoP V2 Depacketizer\n
                                 - This module has only one input and one output port
                                 - Supports following params: mandatory param: \n
                                 - PARAM_ID_COP_V2_STREAM_INFO
                                 - Supported Input Media Format: \n
                                 - Data Format          : CAPI_COMPR_OVER_PCM_PACKETIZED
                                 - fmt_id               : Don't care \n
                                 - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                                 - Number of channels   : 1, 2 \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : 16 (bits per sample 16 and Q15), \n
                                 -                      : 24 (bits per sample 24 and Q27) \n
                                 -                      : 32 (bits per sample 32 and Q31) \n
                                 - Q format             : Q15, Q27, Q31 \n
                                 - Interleaving         : Interleaved }
    @h2xmlm_dataInputPorts      {IN = PORT_ID_COP_V2_DEPACK_INPUT}
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_COP_V2_DEPACK_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlStaticPort      {"REFCLK_REMOTE_TIMING_OUT_FOR_RAT_RENDER" = 0xC0000001,
                                 "HWEP BT drift info" = INTENT_ID_TIMER_DRIFT_INFO}
    @h2xmlm_ctrlStaticPort      {"REFCLK_REMOTE_TIMING_OUT_FOR_RAT_CAPTURE" = 0xC0000002,
                                 "HWEP BT drift info" = INTENT_ID_TIMER_DRIFT_INFO}
    @h2xmlm_ctrlStaticPort      {"COP_ENCODER_FEEDBACK_OUT" = 0xC0000003,
                                 "BT encoder feedback" = INTENT_ID_BT_ENCODER_FEEDBACK}
    @h2xmlm_ctrlStaticPort      {"COP_PACKETIZER_FEEDBACK_OUT" = 0xC0000004,
                                 "BT Packetizer feedback" = INTENT_ID_V2_PACKETIZER_FEEDBACK}
    @h2xmlm_ctrlStaticPort      {"DEADLINE_TIME_OUT" = 0xC0000005,
                                 "BT Deadline Time" = INTENT_ID_BT_DEADLINE_TIME}
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { COP_V2_DEPACK_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select               {param_id_cop_v2_stream_info_t}
    @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

#endif // COP_V2_DEPACKETIZER_API_H
