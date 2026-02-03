#ifndef DATA_MARKER_API_H
#define DATA_MARKER_API_H

/**
 * \file data_marker_api.h
 *  
 * \brief data_marker_api.h: This file contains the Module Id, Param IDs and configuration structures exposed by the
 *  DATA_MARKER Module.
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"
#include "metadata_api.h"

/**
     @h2xml_title1           {Data Marker API}
     @h2xml_title_agile_rev  {Data Marker API}
     @h2xml_title_date       {June 18, 2019}
  */

/*==============================================================================
   Constants
==============================================================================*/

#define CAPI_DATA_MARKER_STACK_SIZE 2048

#define CAPI_DATA_MARKER_MAX_PORTS 1

/** ID of the DATA_MARKER module, which is used to insert and intercept metadata.

    @gpr_hdr_fields
    Opcode -- MODULE_ID_DATA_MARKER
 */
#define MODULE_ID_DATA_MARKER 0x0700106A
/**
    @h2xmlm_module       {"MODULE_ID_DATA_MARKER",
                          MODULE_ID_DATA_MARKER}
    @h2xmlm_displayName  {"DATA MARKER"}
    @h2xmlm_description  {ID of the DATA MARKER module. This module is used to insert metadata
    at one point and intercept at another point in a graph. \n

   * Supported Input Media Format:      \n
   *  - Data Format          : FIXED_POINT \n
   *  - fmt_id               : Don't care \n
   *  - Sample Rates         : Any (>0) \n
   *  - Number of channels   : 1 to 32 \n
   *  - Channel type         : 1 to 63 \n
   *  - Bits per sample      : 16, 24, 32 \n
   *  - Q format             : 15, 27, 31 \n
   *  - Interleaving         : Any \n
   *  - Signed/unsigned      : Any  \n
   *}
    @h2xmlm_dataMaxInputPorts    {CAPI_DATA_MARKER_MAX_PORTS}
    @h2xmlm_dataMaxOutputPorts   {CAPI_DATA_MARKER_MAX_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataOutputPorts      {OUT=1}
    @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize            {CAPI_DATA_MARKER_STACK_SIZE}
    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
*/

/**
    ID of the MD Insert parameter, used by the Data Marker Module
 */

#define PARAM_ID_DATA_MARKER_INSERT_MD 0x08001155
/** @h2xmlp_parameter   {"PARAM_ID_DATA_MARKER_INSERT_MD", PARAM_ID_DATA_MARKER_INSERT_MD}
    @h2xmlp_description {Structure for PARAM_ID_DATA_MARKER_INSERT_MD parameter.
                         This tells the module to create a metadatum of said ID and insert to the propagated list.
                         It also provides a token to uniquely identify the inserted MD.}
   @h2xmlp_toolPolicy              {Calibration}                         */
#include "spf_begin_pack.h"
/** Payload of the PARAM_ID_DATA_MARKER_INSERT_MD parameter.
 */
struct param_id_data_marker_insert_md_t
{
   uint32_t metadata_id;
   /**< @h2xmle_description   {Specifies the metadata_id to create and propagate.}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF}*/

   uint32_t token;
   /**< @h2xmle_description  {Token to uniquely track the inserted md}
         @h2xmle_default     {0}
         @h2xmle_range       {0..0xFFFFFFFF}*/
}
#include "spf_end_pack.h"
;
/* Structure for PARAM_ID_DATA_MARKER_INSERT_MD parameter. */
typedef struct param_id_data_marker_insert_md_t param_id_data_marker_insert_md_t;

/* Unique Parameter id */
#define EVENT_ID_DELAY_MARKER_INFO 0x08001156

/*==============================================================================
   Type definitions
==============================================================================*/

/** @h2xmlp_parameter   {"EVENT_ID_DELAY_MARKER_INFO",
                          EVENT_ID_DELAY_MARKER_INFO}
    @h2xmlp_description { Event raised by the module to convey the path delay.}
    @h2xmlp_toolPolicy  { Calibration}*/

#include "spf_begin_pack.h"
struct event_id_delay_marker_info_t
{
   uint32_t delay;
   /**< @h2xmle_description   {Delay as seen by the module that raises the event (us)}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF}*/

   uint32_t token;
   /**< @h2xmle_description   {Token provided by the Delay marker insertion module}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF}*/
}
#include "spf_end_pack.h"
;

/* Structure for EVENT_ID_DELAY_MARKER_INFO parameter. */
typedef struct event_id_delay_marker_info_t event_id_delay_marker_info_t;

/** @}                   <-- End of the Module -->*/

#endif /* DATA_MARKER_API_H */
