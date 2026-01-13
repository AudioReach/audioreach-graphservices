#ifndef _SYNC_API_H_
#define _SYNC_API_H_
/**
 * \file sync_api.h
 * \brief 
 *  	 This file contains the Sync module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "apm_graph_properties.h"

/**
    @h2xml_title1          {Sync Module API}
    @h2xml_title_agile_rev {Sync Module API}
    @h2xml_title_date      {July 12, 2018}   */

/*==============================================================================
   Defines
==============================================================================*/

/*==============================================================================
   API definitions
==============================================================================*/

#define SYNC_STACK_SIZE 4096
#define SYNC_MAX_IN_PORTS  32
#define SYNC_MAX_OUT_PORTS 32

#define MODULE_ID_SYNC      0x07001038
/** @h2xmlm_module            {"MODULE_ID_SYNC", MODULE_ID_SYNC}
  @h2xmlm_displayName         {"Sync Module"}
  @h2xmlm_description         {- Generic Synchronziation Module\n
                               - Supported Input Media Format: \n
                               - Data Format          : FIXED_POINT, \n
                               - fmt_id               : MEDIA_FMT_ID_PCM \n
                               - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                               -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                               - Number of channels   : 1 to 8 \n
                               - Channel type         : Don't care \n
                               - Bit Width            : 16 (bits per sample 16 and Q15), \n
                               -                      : 32 (bits per sample 32 and Q31)  \n
                               - Q format             : Q15, Q31 \n
                               - Interleaving         : Deinterleaved unpacked, deinterleaved packed. \n
                               - Endianess            : little, big \n
                               - Ports are allowed to have different media formats. The only \n
                               - restriction is that if one port runs at a fractional rate, the other ports must also \n
                               - run at a fractional rate (use cases where ports have variable input frame sizes are \n
                               - not supported).}

    @h2xmlm_dataMaxInputPorts   {SYNC_MAX_IN_PORTS}
    @h2xmlm_dataInputPorts      {IN0 = 6;
                                 IN1 = 8;
                                 IN2 = 10;
                                 IN3 = 12;
                                 IN4 = 14;
                                 IN5 = 16;
                                 IN6 = 18;
                                 IN7 = 20}
    @h2xmlm_dataMaxOutputPorts  {SYNC_MAX_OUT_PORTS}
    @h2xmlm_dataOutputPorts     {OUT0 = 5;
                                 OUT1 = 7;
                                 OUT2 = 9;
                                 OUT3 = 11;
                                 OUT4 = 13;
                                 OUT5 = 15;
                                 OUT6 = 17;
                                 OUT7 = 19}

    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_SC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize           { SYNC_STACK_SIZE }
    @{                     <-- Start of the Module -->
    @}                     <-- End of the Module -->
*/

#endif //_SYNC_API_H_
