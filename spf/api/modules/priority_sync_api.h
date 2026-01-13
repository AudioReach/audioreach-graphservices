#ifndef _PRIORITY_SYNC_API_H_
#define _PRIORITY_SYNC_API_H_
/**
 * \file priority_sync_api.h
 * \brief 
 *  	 This file contains Priority Sync module APIs
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "apm_graph_properties.h"

/** @h2xml_title1          {Priority Sync Module API}
    @h2xml_title_agile_rev {Priority Sync Module API}
    @h2xml_title_date      {July 12, 2018}   */

/*==============================================================================
   Defines
==============================================================================*/

#define PRIORITY_SYNC_MAX_IN_PORTS 2
#define PRIORITY_SYNC_MAX_OUT_PORTS 2

#define PRIORITY_SYNC_PRIMARY_IN_PORT_ID 0x2
#define PRIORITY_SYNC_PRIMARY_OUT_PORT_ID 0x1

#define PRIORITY_SYNC_SECONDARY_IN_PORT_ID 0x4
#define PRIORITY_SYNC_SECONDARY_OUT_PORT_ID 0x3

#define PRIORITY_SYNC_MAX_CHANNELS 32
#define PRIORITY_SYNC_STACK_SIZE 4096

/*==============================================================================
   API definitions
==============================================================================*/

#define MODULE_ID_EC_SYNC 0x07001028
#define MODULE_ID_PRIORITY_SYNC MODULE_ID_EC_SYNC

/** @h2xmlm_module            {"MODULE_ID_PRIORITY_SYNC", MODULE_ID_PRIORITY_SYNC}
  @h2xmlm_displayName         {"Priority Sync"}
  @h2xmlm_description         {- This module is used to synchronize the secondary input signal with respect to primary(priority) input signal.
                               - Use cases are :-
                               - To synchronize Echo reference signal with Mic data. ECNS and other similar use cases.
                               - To synchronize music Rx signal with voice Tx signal for ICMD use case.
                               - Supported Input Media Format: \n
                               - Data Format          : FIXED_POINT, \n
                               - fmt_id               : MEDIA_FMT_ID_PCM \n
                               - Sample Rates         : 8, 11.025, 12, 16, 22.05, 24, 32, 44.1, 48, \n
                               -                        88.2, 96, 176.4, 192, 352.8, 384 kHz \n
                               - Number of channels   : 1 to 32 \n
                               - Channel type         : Don't care \n
                               - Bit Width            : 16, 24, 32
                               - Q format             : Don't care \n
                               - Interleaving         : Deinterleaved unpacked. \n
                               - Endianess            : little, big \n
                               - Primary and secondary ports are allowed to have different media formats. The only \n
                               - restriction is that if one port runs at a fractional rate, the other port must also \n
                               - run at a fractional rate (use cases where ports have variable input frame sizes are \n
                               - not supported).}

    @h2xmlm_dataMaxInputPorts   {PRIORITY_SYNC_MAX_IN_PORTS}
    @h2xmlm_dataInputPorts      {PRIMARY_IN = PRIORITY_SYNC_PRIMARY_IN_PORT_ID;
                                 SECONDARY_IN = PRIORITY_SYNC_SECONDARY_IN_PORT_ID}
    @h2xmlm_dataMaxOutputPorts  {PRIORITY_SYNC_MAX_OUT_PORTS}
    @h2xmlm_dataOutputPorts     {PRIMARY_OUT = PRIORITY_SYNC_PRIMARY_OUT_PORT_ID;
                                 SECONDARY_OUT = PRIORITY_SYNC_SECONDARY_OUT_PORT_ID}

    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_SC}
    @h2xmlm_isOffloadable        {true}
    @h2xmlm_stackSize           { PRIORITY_SYNC_STACK_SIZE }
    @{                     <-- Start of the Module -->
    @}                     <-- End of the Module -->
*/

#endif //_PRIORITY_SYNC_API_H_
