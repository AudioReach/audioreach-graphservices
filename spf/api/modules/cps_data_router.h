#ifndef __SP_CPS_DATA_ROUTER_H__
#define __SP_CPS_DATA_ROUTER_H__

/*==============================================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause

  @file cps_data_router.h
  @brief This file contains APIs for Speaker Protection Module
==============================================================================*/

/** @h2xml_title1           {Speaker Protection v5 CPS Data Router}
    @h2xml_title_date       {January 30, 2022} */
#include "module_cmn_api.h"
#include "ar_defs.h"
#include "imcl_spm_intent_api.h"
#include "rtm_logging_api.h"

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/*==============================================================================
   Constants
==============================================================================*/
#define CPS_STACK_SIZE 1024
#define CPS_NUM_MAX_SPKRS 8
#define CPS_MAX_INPUT_PORTS 1
#define CPS_MAX_OUTPUT_PORTS 0

/* Unique Module ID */
#define MODULE_ID_CPS_DATA_ROUTER_V7 0x07001180

/** @h2xmlm_module       {"MODULE_ID_CPS_DATA_ROUTER",
                          MODULE_ID_CPS_DATA_ROUTER}
    @h2xmlm_displayName  {"CPS DATA ROUTER"}
    @h2xmlm_toolPolicy   {Calibration;CALIBRATION}
    @h2xmlm_description  {ID of the CPS Data Router module.\n

      This module supports the following parameter IDs:\n
     - #PARAM_ID_MODULE_ENABLE \n

      All parameter IDs are device independent.\n

     Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 24000\n
*  - Number of channels   : 1, 2, 3, 4\n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 32 \n
*  - Q format             : 27 \n
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

    @h2xmlm_toolPolicy              {Calibration}

    @h2xmlm_dataMaxInputPorts    {CPS_MAX_INPUT_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
     @h2xmlm_dataMaxOutputPorts   {CPS_MAX_OUTPUT_PORTS}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize            {CPS_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent  { "Intent ID for communicating CPS related data to SP module" = INTENT_ID_CPS, maxPorts=
1 }
     @h2xmlm_ToolPolicy              {Calibration}

    @{                   <-- Start of the Module -->

 @h2xml_Select        {"param_id_module_enable_t"}
 @h2xmlm_InsertParameter
   */
/*==============================================================================
   Constants
==============================================================================*/

/* Unique Paramter id */
#define PARAM_ID_CPS_CHANNEL_MAP 0x08001B5F //todo: Mention explicitly in CCB as well that this is for channel ordering and not for left, right or center etc channels
/* Unique Param ID for spv5 */
#define PARAM_ID_CPS_CHANNEL_MAP_V5 0x080013CB

/*==============================================================================
   Type definitions
==============================================================================*/

/* Structure definition for Parameter */
typedef struct param_id_cps_ch_map_t param_id_cps_ch_map_t;

/** @h2xmlp_parameter   {"PARAM_ID_CPS_CHANNEL_MAP",
                         PARAM_ID_CPS_CHANNEL_MAP}
    @h2xmlp_description {parameter used to configure the channel map for CPS processing.}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_cps_ch_map_t
{
    uint32_t num_ch;         // PCM signal sampling rate
    /**< @h2xmle_description {Number of channels}
    @h2xmle_rangeList   {"mono"=1;"stereo"=2; "three" = 3; "quad"= 4}
    @h2xmle_default     {2} */

    uint32_t ch_info[CPS_NUM_MAX_SPKRS];
    /**< @h2xmle_description {channel mapping for cps data}
    @h2xmle_defaultList     {1, 2, 3, 4} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** @} <-- End of the Module --> */

#endif /* __SP_CPS_DATA_ROUTER_H__ */
