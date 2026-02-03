/**
 * \file tty_cmn_api.h
 * \brief 
 *  	 This file contains api exposed to voice service in modem for tty modules.
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TTY_CMN_API_H
#define TTY_CMN_API_H

#include "ar_defs.h"
#include "apm_graph_properties.h"

/*==============================================================================
   Param ID
==============================================================================*/

#define PARAM_ID_LTETTY_CHAR  0x080011A8
/** @h2xmlp_parameter   {"PARAM_ID_LTETTY_CHAR", PARAM_ID_LTETTY_CHAR}
    @h2xmlp_description {Parameter for sending the TTY character to Module. Voice Service should send this parameter.}
    @h2xmlp_toolPolicy  {Calibration} */


typedef struct param_id_ltetty_char_t param_id_ltetty_char_t;

#include "spf_begin_pack.h"
struct param_id_ltetty_char_t
{
    uint32_t tty_char;
    /**< @h2xmle_description {TTY character. In UTF-8 format.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0xFF}
         @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;


/*==============================================================================
   Event ID
==============================================================================*/

#define EVENT_ID_LTETTY_CHAR 	0x080011A9
/** @h2xmlp_parameter   {"EVENT_ID_LTETTY_CHAR", EVENT_ID_LTETTY_CHAR}
    @h2xmlp_description {Event for sending the detected TTY character to Voice Service. Voice Service must register this event with LTETTY-Tx Module.}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */


typedef struct event_id_ltetty_char_t event_id_ltetty_char_t;

#include "spf_begin_pack.h"
struct event_id_ltetty_char_t
{
    uint32_t tty_char;
    /**< @h2xmle_description {TTY character. In UTF-8 format.}
         @h2xmle_default     {0}
         @h2xmle_range       {0x0..0xFF}
         @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;

/*------------------------------------------------------------------------------
   Param ID
------------------------------------------------------------------------------*/
#define PARAM_ID_CTM_RESYNC 0x08001190
/** @h2xmlp_emptyParameter {"PARAM_ID_CTM_RESYNC", PARAM_ID_CTM_RESYNC}
    @h2xmlp_description {Parameter to re-synchronize the CTM blocks.}
    @h2xmlp_toolPolicy  {Calibration} */


#endif // TTY_CMN_API_H
