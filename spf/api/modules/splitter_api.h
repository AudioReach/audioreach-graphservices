#ifndef SPLITTER_API_H
#define SPLITTER_API_H
/**
 * \file splitter_api.h
 * \brief 
 *  	 splitter_api.h: This file contains the Module Id, Param IDs and configuration
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"
#include "metadata_api.h"


/**
     @h2xml_title1          {Simple Splitter API}
     @h2xml_title_agile_rev  {Simple Splitter API}
     @h2xml_title_date      {July 9, 2018}
  */
  
/*==============================================================================
   Constants
==============================================================================*/

#define CAPI_SPLITTER_STACK_SIZE 512

#define SPLITTER_MAX_INPUT_PORTS    1

/** ID of the SPLITTER module, which is used for splitting the data on the input port
    on all the output ports.

    @gpr_hdr_fields
    Opcode -- MODULE_ID_SPLITTER
 */
#define MODULE_ID_SPLITTER 0x07001011
/**
    @h2xmlm_module       {"MODULE_ID_SPLITTER",
                          MODULE_ID_SPLITTER}
    @h2xmlm_displayName  {"Splitter"}
    @h2xmlm_description  {ID of the SPLITTER module. This module is used to split the
    streams on the input to all the output ports. \n

   * \n
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
    @h2xmlm_dataMaxInputPorts    {SPLITTER_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts   {INFINITE}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {true}
    @h2xmlm_stackSize            {CAPI_SPLITTER_STACK_SIZE}
    @h2xmlm_ToolPolicy           {Calibration}    
    @{                   <-- Start of the Module -->
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
 /** @h2xmlp_subStruct */
struct per_port_md_cfg_t
{
   uint32_t port_id;
   /**< @h2xmle_description  {output port_id on which metadata propagation
        will be configured.} */
   uint32_t num_white_listed_md;
    /**< @h2xmle_description  {number of metadata IDs that should be propagated on the splitter's 
    output that maps to this port_id} */
#if defined(__H2XML__)
   uint32_t md_whitelist[0];
    /**< @h2xmle_description  {array of Metadata IDs corresponding to the metadata that need to be propagated.
    By default - Splitter will NOT propagate any.}
    @h2xmle_variableArraySize {num_white_listed_md}*/
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Sub-Structure for per_port_md_cfg_t parameter. */
typedef struct  per_port_md_cfg_t per_port_md_cfg_t;

/**
    ID of the Port EoS parameter, used by the Splitter Module
    Used to disable the EoS metadata propagation on
    certain output ports.
 */
#define PARAM_ID_SPLITTER_METADATA_PROP_CFG 0x0800103C
/** @h2xmlp_parameter   {"PARAM_ID_SPLITTER_METADATA_PROP_CFG", PARAM_ID_SPLITTER_METADATA_PROP_CFG}
    @h2xmlp_description {Structure for PARAM_ID_SPLITTER_METADATA_PROP_CFG parameter for Multiport modules.
                         Module should have received CAPI_PORT_NUM_INFO before this.
                         If this parameter is not issued to the module - The default behavior is to propagate the 
                         metadata on the output ports. BUT, if this parameter is issued, only the whitelisted
                         metadata will be propagated.}
   @h2xmlp_toolPolicy              {Calibration}                         */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/** Payload of the PARAM_ID_SPLITTER_METADATA_PROP_CFG parameter.
 */
struct param_id_splitter_metadata_prop_cfg_t
{
   uint32_t num_ports;
   /**< @h2xmle_description  {Specifies the number of ports for which the metadata propagation is configured.}
         @h2xmle_default      {0}
         @h2xmle_range       {0..32767}*/
#if defined(__H2XML__)
   per_port_md_cfg_t port_md_prop_cfg_arr[0];
   /**< @h2xmle_description  {port_id_arr payload is of variable length and depends on the number
        of port_ids. This payload has port ids on which eos metadata propagation
        will be disabled.} 
        @h2xmle_variableArraySize {num_ports}*/
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Structure for PARAM_ID_SPLITTER_METADATA_PROP_CFG parameter. */
typedef struct param_id_splitter_metadata_prop_cfg_t param_id_splitter_metadata_prop_cfg_t;

/** @}                   <-- End of the Module -->*/

#endif /* SPLITTER_API_H */
