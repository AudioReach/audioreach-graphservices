#ifndef _POP_SUPPRESSOR_API_H_
#define _POP_SUPPRESSOR_API_H_

/*==============================================================================
  @file pop_suppressor_api.h
  @brief This file contains pop suppressor parameters
==============================================================================*/

/*=======================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
=========================================================================*/
/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"

/** @h2xml_title1           {Pop Suppressor Module}
    @h2xml_title_agile_rev  {Pop Suppressor}
    @h2xml_title_date       {Jul 5, 2019}
 */
/**
   @h2xmlx_xmlNumberFormat {int}
 */

/*==============================================================================
   Constants
==============================================================================*/
#define CAPI_POP_SUPPRESSOR_STACK_SIZE 1024
#define CAPI_POP_SUPPRESSOR_MAX_IN_PORTS 1
#define CAPI_POP_SUPPRESSOR_MAX_OUT_PORTS 1

/* Global unique Module ID definition
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_POP_SUPPRESSOR 0x07001072
/**
    @h2xmlm_module       {"MODULE_ID_POP_SUPPRESSOR",
                          MODULE_ID_POP_SUPPRESSOR}
    @h2xmlm_displayName  {"Pop Suppressor"}
    @h2xmlm_toolPolicy   {Calibration}
    @h2xmlm_description  {This module takes care of the unwanted  
     and annoying pops happening due to data discontinuity arising 
	  because of the handovers and device switches during a voice call. 
     Pop suppressor module smoothens out the sudden discontinuity 
     and sudden rise of the speech in scenarios like when handover
     occurs or just after handover is completed.  For smoothing   
     the algorithm uses a sigmoid curve. The module supports both mono 
     and stereo channel input. \n

  -  This module supports the following parameter IDs: \n
    - #PARAM_ID_POP_SUPPRESSOR_CONFIG \n
	- #PARAM_ID_POP_SUPPRESSOR_MUTE_CONFIG \n
	- #PARAM_ID_MODULE_ENABLE \n

    - Supported Input Media Format:\n
    - Data Format             : FIXED_POINT\n
    - fmt_id                  : PCM\n
    - Sample Rates            : 8000, 16000, 32000, 48000, 96000 Hz \n
    - Number of channels(Max) : 2  \n
    - Channel type            : Don't care\n
    - Bits per sample         : 16 \n
    - Q format                : Q15\n
    - Interleaving            : de-interleaved unpacked\n
    - Signed/unsigned         : Signed }

    @h2xmlm_dataMaxInputPorts    {CAPI_POP_SUPPRESSOR_MAX_IN_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {CAPI_POP_SUPPRESSOR_MAX_OUT_PORTS}
    @h2xmlm_dataOutputPorts      {OUT=1}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {CAPI_POP_SUPPRESSOR_STACK_SIZE}
    @{                   <-- Start of the Module --> */


/*  ID of the POP_SUPPRESSOR Configuration parameter used by MODULE_ID_POP_SUPPRESSOR.*/
#define PARAM_ID_POP_SUPPRESSOR_CONFIG 0x0800117F

/* ID of the POP_SUPPRESSOR Configuration parameter to MUTE the Output of POP_SUPPRESSOR MODULE */
#define PARAM_ID_POP_SUPPRESSOR_MUTE_CONFIG   0x0800134F

/*==============================================================================
   Type Definitions
==============================================================================*/

/* Structure for pop suppressor configuration parameters */
typedef struct param_id_pop_suppressor_params_t param_id_pop_suppressor_params_t;
/** @h2xmlp_parameter   {"PARAM_ID_POP_SUPPRESSOR_CONFIG", PARAM_ID_POP_SUPPRESSOR_CONFIG}
    @h2xmlp_description {This is used to configure pop suppressor module} */

#include "spf_begin_pack.h"

/* Payload of the PARAM_ID_POP_SUPPRESSOR_CONFIG parameters in the POP Suppressor module.
 */
struct param_id_pop_suppressor_params_t
{
   uint16_t ramp_duration_in_ms;
   /**< @h2xmle_description  {Input ramp duration in ms}
        @h2xmle_default      {0x1}
        @h2mle_dataFormat    {Q0}
    */

   int16_t reserved;
   /**< @h2xmle_description {Client must set this field to zero.}
    @h2xmle_default     {0}
    @h2xmle_policy      {Advanced}
    */
}
#include "spf_end_pack.h"
;
/* Structure for pop suppressor configuration parameters */
typedef struct param_id_pop_suppressor_mute_config_t  param_id_pop_suppressor_mute_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_POP_SUPPRESSOR_MUTE_CONFIG ", PARAM_ID_POP_SUPPRESSOR_MUTE_CONFIG}
    @h2xmlp_description {This parameter is used to mute the output of pop suppressor module during a device switch usecase.
	                     The mute would happen with a duration set in PID PARAM_ID_POP_SUPPRESSOR_CONFIG.
	                     This parameter can be set to enable/disable by
						 the client.
						 POP_SUPPRESSOR module will reset to unmute (disable) when GRAPH_STOP(or algo reset) command is issued}
    @h2xmlp_toolPolicy   {Calibration; RTC}						 */
	
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_pop_suppressor_mute_config_t
{
	uint32_t mute_enable;
   /**< Specifies whether the Pop_suppressor mute parameter is to be enabled(1) or disabled(0)

       @valuesbul
        - 0 --  Disabled (Default)
        - 1 --  Enabled @tablebulletend */
	 /*#< @h2xmle_description {Specifies whether the Pop_suppressor mute parameter is to be enabled or
                              disabled.}
        @h2xmle_rangeList   {"Disable"=0;
                             "Enable"=1}
        @h2xmle_default     {0}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/**
   @h2xml_Select		 {param_id_module_enable_t}
    @h2xmlm_InsertParameter
    @h2xml_Select		 {param_id_pop_suppressor_params_t}
   @h2xmlm_InsertParameter
   @h2xml_Select           {param_id_pop_suppressor_mute_config_t}
   @h2xmlm_InsertParameter
    @}                   <-- End of the Module -->*/

#endif /* _POP_SUPPRESSOR_API_H_ */
