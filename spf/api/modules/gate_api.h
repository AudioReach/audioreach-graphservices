#ifndef GATE_API_H_
#define GATE_API_H_
/**
 * \file gate_api.h
 * \brief 
 *  	 API file for Gate Module
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of GATE */
#define GATE_DATA_INPUT_PORT   0x2

/* Output port ID of GATE */
#define GATE_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of GATE */
#define GATE_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of GATE */
#define GATE_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of GATE */
#define GATE_STACK_SIZE 1024

/* Control port for receiving deadline time*/
#define DEADLINE_TIME_INFO_IN AR_NON_GUID(0xC0000001)

/*==============================================================================
   Module
==============================================================================*/

/** @h2xml_title1           {GATE API}
    @h2xml_title_agile_rev  {GATE API}
    @h2xml_title_date       {July 7, 2019} */

/**
 * Module ID for Gate Module
 */
#define MODULE_ID_GATE			0x07001042

/**
    @h2xmlm_module              {"Gate", MODULE_ID_GATE}
    @h2xmlm_displayName         {"Gate"}
    @h2xmlm_description         {- This module gates data flow based on calculated deadline time\n
                                 - It doesn't modify data in any way.
                                 - Supports following params:\n
                                 -- PARAM_ID_GATE_EP_TRANSMISSION_DELAY\n
                                 - Supported Input Media Format:\n
                                 -- Data Format         : FIXED_POINT\n
                                 -- fmt_id              : Don't care\n
                                 - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                                 -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                                 - Number of channels   : 1 to 32 \n
                                 - Channel type         : Don't care \n
                                 - Bit Width            : Don't care \n
                                 - Q format             : Don't care \n
                                 - Interleaving         : Dont care}

    @h2xmlm_dataMaxInputPorts   {GATE_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {GATE_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=GATE_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=GATE_DATA_OUTPUT_PORT}
    @h2xmlm_ctrlStaticPort      {"DEADLINE_TIME_INFO_IN" = 0xC0000001,
                                 "Deadline time intent" = INTENT_ID_BT_DEADLINE_TIME}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize           {GATE_STACK_SIZE}
    @h2xmlm_toolPolicy          {Calibration}
    @{                          <-- Start of the Module -->
    @}                          <-- End of the Module -->
*/

#endif //GATE_API_H_
