#ifndef COP_PACKETIZER_V0_API_H
#define COP_PACKETIZER_V0_API_H

/*==============================================================================
  @file cop_packetizer_v0_api.h
  @brief This file contains cop pack v0 module APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
// clang-format on

/** @h2xml_title1          {CoP Packetizer V0}
	@h2xml_title_agile_rev {COP Packetizer V0}
	@h2xml_title_date      {June 30, 2019}	 */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "cop_packetizer_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/
/* CoP Packetizer module stack size*/
#define COP_PACK_V0_STACK_SIZE 6144

/* Input port ID of CoP Packetizer module */
#define PORT_ID_COP_PACK_V0_INPUT 0x2

/* Output port ID of CoP Packetizer module */
#define PORT_ID_COP_PACK_V0_OUTPUT 0x1

/* Static input control port ID's of CoP Packetizer module */
/* Receives drift from cop depack on this port*/
#define COP_PACKETIZER_FEEDBACK_IN AR_NON_GUID(0xC0000001)


  /*==============================================================================
     Param ID
  ==============================================================================*/

/* Param ID of the Scrambling parameter used by MODULE_ID_PACKETIZER V0  */
  #define PARAM_ID_COP_PACKETIZER_ENABLE_SCRAMBLING     0x0800134D


/** @h2xmlp_parameter   {"PARAM_ID_COP_PACKETIZER_ENABLE_SCRAMBLING", PARAM_ID_COP_PACKETIZER_ENABLE_SCRAMBLING}
    @h2xmlp_description {Structure for the enable scrambling parameter used by the Packetizer module.    }
    @h2xmlp_toolPolicy  {Calibration; RTC} */


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/* Payload of the PARAM_ID_COP_PACKETIZER_ENABLE_SCRAMBLING parameter in the
packetizer Module. Following this will be the variable payload for scrambler . */

  struct param_id_cop_pack_enable_scrambling_t
  {
      uint32_t                  enable_scrambler;
      /**< @h2xmle_description  {flag for enabling scrambler. \n
                                    ->1 = enable scrambler , 0 = disable scrambler}
              @h2xmle_range        {0,1}
              @h2xmle_default      {0}
         */
  }
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
  ;
typedef struct  param_id_cop_pack_enable_scrambling_t  param_id_cop_pack_enable_scrambling_t;


/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/** Module ID for CoP Packetizer module */
#define MODULE_ID_COP_PACKETIZER_V0	   0x0700106D
/** @h2xmlm_module              {"MODULE_ID_COP_PACKETIZER_V0",
                                 MODULE_ID_COP_PACKETIZER_V0}
	@h2xmlm_displayName         {"CoP V0 Packetizer"}
	@h2xmlm_description         {- CoP V0 Packetizer\n
	                             - This module packetizes raw bitstream into Compressed Over PCM packetized bitstream\n
	                             - This module should be in the same subgraph as the encoder\n
	                             - This module has only one input and one output port\n
                                 - Supports following mandatory param: \n
                                 - PARAM_ID_COP_PACKETIZER_OUTPUT_MEDIA_FORMAT
                                 - Supported Input Media Format: \n
                                 - Data Format          : CAPI_RAW_COMPRESSED
                                 - fmt_id               : Don't care \n}
    @h2xmlm_dataInputPorts      {IN = PORT_ID_COP_PACK_V0_INPUT}
    @h2xmlm_dataOutputPorts     {OUT = PORT_ID_COP_PACK_V0_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_ctrlStaticPort      {"COP_PACKETIZER_FEEDBACK_IN" = 0xC0000001,
                                 "HWEP BT drift info" = INTENT_ID_TIMER_DRIFT_INFO}

    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { COP_PACK_V0_STACK_SIZE }
    @{                          <-- Start of the Module -->

    @h2xml_Select		        {param_id_cop_pack_output_media_fmt_t}
    @h2xmlm_InsertParameter
    @h2xml_Select		        {param_id_cop_pack_enable_scrambling_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/

#endif //COP_PACKETIZER_V0_API_H
