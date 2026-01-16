#ifndef __JITTER_BUF_H
#define __JITTER_BUF_H
/**
 * \file jitter_buf_api.h
 * \brief
 *     This file contains module published by Jitter Buf CAPI intialization.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/**
  @h2xml_title1          {Jitter Buffer Module}
  @h2xml_title_agile_rev {Jitter Buffer Modulee}
  @h2xml_title_date      {July 17, 2024}
*/

// Max number of ports supported by Jitter Buf module.
#define CAPI_JITTER_BUF_MAX_INPUT_PORTS         (1)
#define CAPI_JITTER_BUF_MAX_OUTPUT_PORTS        (1)
#define CAPI_JITTER_BUF_MAX_CTRL_PORTS          (1)

/*==============================================================================
   Constants
==============================================================================*/

/* Parameter description */
#define PARAM_ID_JITTER_BUF_CONFIG              0x080014E3
#define PARAM_ID_JITTER_BUF_SETTLING_TIME       0x080014E4
#define PARAM_ID_JITTER_BUF_SIZE_CONFIG         0x080014E6

/*==============================================================================
   Type Definitions
==============================================================================*/


/** @h2xmlp_parameter   {"PARAM_ID_JITTER_BUF_CONFIG",
                          PARAM_ID_JITTER_BUF_CONFIG}
    @h2xmlp_description { This param ID is used to configure Jitter Buf module. }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_jitter_buf_config_t
{
   uint32_t jitter_allowance_in_ms;
   /**< @h2xmle_description { It defines the range of jitter for client buffers.
                              If 0 then used to disable module. }
        @h2xmle_default     { 200 }
        @h2xmle_range       {0..300}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure to define the Jitter Buf configuration.*/
typedef struct param_id_jitter_buf_config_t param_id_jitter_buf_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_JITTER_BUF_SETTLING_TIME",
                          PARAM_ID_JITTER_BUF_SETTLING_TIME}
    @h2xmlp_description { This param ID is used to configure settling time before accurate drift can be reported. }
    @h2xmlp_toolPolicy  {CALIBRATION} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_jitter_buf_settling_time_t
{
   uint32_t drift_settlement_in_ms;
   /**< @h2xmle_description { It defines the max time usually taken to settle.
                              in steady state to start reporting drift. }
        @h2xmle_default     { 0 }
        @h2xmle_range       {0..10000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure to define the Jitter Buf configuration.*/
typedef struct param_id_jitter_buf_settling_time_t param_id_jitter_buf_settling_time_t;

/** @h2xmlp_parameter   {"PARAM_ID_JITTER_BUF_SIZE_CONFIG",
                          PARAM_ID_JITTER_BUF_SIZE_CONFIG}
    @h2xmlp_description { This param ID is used to configure Jitter Buf module size from QACT for debug purposes. }
    @h2xmlp_toolPolicy  {CALIBRATION} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_jitter_buf_size_config_t
{
   uint32_t jitter_allowance_in_ms;
   /**< @h2xmle_description { It defines the range of jitter for client buffers.
                              If 0 then used to disable module. }
        @h2xmle_default     { 200 }
        @h2xmle_range       {0..300}*/

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_jitter_buf_size_config_t param_id_jitter_buf_size_config_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/**  Module ID of the Jitter Buffer Module. */
#define MODULE_ID_JITTER_BUFFER                     0x07010005

/**
    @h2xmlm_module         {"MODULE_ID_JITTER_BUFFER", MODULE_ID_JITTER_BUFFER}
    @h2xmlm_displayName    {"Jitter Buffer Module"}

    @h2xmlm_description    { This module acts a delay buffer between BT decoder and sink.\n

    \n This module supports the following parameter IDs:\n
     - PARAM_ID_JITTER_BUF_CONFIG\n
     - PARAM_ID_JITTER_BUF_SETTLING_TIME\n
     - PARAM_ID_JITTER_BUF_SIZE_CONFIG\n

   \n Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 44100, 48000\n
*  - Number of channels   : 1 and 2\n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 16, 24  \n
*  - Q format             : 15 for bps = 16 and 27 for bps = 24\n
supported bps
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

    @h2xmlm_dataMaxInputPorts    { 1 }
    @h2xmlm_dataMaxOutputPorts   { 1 }
    @h2xmlm_ctrlDynamicPortIntent  { "Jitter Buf - SS" = INTENT_ID_TIMER_DRIFT_INFO,
                                 maxPorts= 1 }
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_GC }
    @h2xmlm_stackSize            { 1024 }
    @{                     <-- Start of the Module -->

    @h2xml_Select      {param_id_jitter_buf_config_t}
    @h2xmlm_InsertParameter

    @h2xml_Select      {param_id_jitter_buf_settling_time_t}
    @h2xmlm_InsertParameter

    @h2xml_Select      {param_id_jitter_buf_size_config_t}
    @h2xmlm_InsertParameter

 @}                     <-- End of the Module --> */

#endif /*__JITTER_BUF_H*/
