/**
 * \file data_logging_api.h
 * \brief
 *  	 This file contains Public APIs for Data logging Module
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _DATA_LOGGING_API_H_
#define _DATA_LOGGING_API_H_

 /*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"
#include "apm_container_api.h"

#define DATA_LOGGING_MAX_INPUT_PORTS                  0x1

#define DATA_LOGGING_MAX_OUTPUT_PORTS                 0x1

#define DATA_LOGGING_STACK_SIZE_REQUIREMENT           2048

/**
   @h2xmlx_xmlNumberFormat {int}
*/

/*==============================================================================
   Param ID
==============================================================================*/

/* ID of the parameter used to set configuration for Data logging module. */
#define PARAM_ID_DATA_LOGGING_CONFIG             0x08001031

/*==============================================================================
   Param structure defintions
==============================================================================*/

/** @h2xmlp_parameter   {"PARAM_ID_DATA_LOGGING_CONFIG", PARAM_ID_DATA_LOGGING_CONFIG}
   @h2xmlp_description  {Configures the data logging module.\n}
   @h2xmlp_toolPolicy   {Calibration; RTC} */

#include "spf_begin_pack.h"
struct data_logging_config_t
{
   uint32_t log_code;
   /**< logging code for this module instance

        @values 0 to 0x19B1 */
   /**< @h2xmle_description {logging code}
        @h2xmle_default     {0}
        @h2xmle_range       { 0..6577}
        @h2xmle_policy      {Basic} */

   uint32_t log_tap_point_id;
   /**< logging tap point of this module instance

        @values 0 to 0x10FC5 */
   /**< @h2xmle_description {logging tap point}
        @h2xmle_default     {0}
        @h2xmle_range       { 0..69573}
        @h2xmle_policy      {Basic} */

   uint32_t mode;
   /**< Mode to indicate whether to log immediately (1) or wait until
    *   log buffer is completely filled (0)

        @values 0, 1 */
   /**< @h2xmle_description {Buffering mode}
        @h2xmle_default     {0}
        @h2xmle_range       { 0..1}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct data_logging_config_t data_logging_config_t;

/* ID of the parameter used to configure Island logging for Data logging module. */
#define PARAM_ID_DATA_LOGGING_ISLAND_CFG         0x08001313

/** @h2xmlp_parameter   {"PARAM_ID_DATA_LOGGING_ISLAND_CFG", PARAM_ID_DATA_LOGGING_ISLAND_CFG}
   @h2xmlp_description  {Force logging for a logging module in an Island Container. Enabling this causes island exit\n}
   @h2xmlp_toolPolicy   {Calibration; RTC} */

#include "spf_begin_pack.h"
struct data_logging_island_t
{
   uint32_t forced_logging;
   /**< @h2xmle_description  {Specifies whether the data logging module needs to log in island by exiting island.}
        @h2xmle_rangeList    {"disallowed"=0;
                              "allowed"=1}
        @h2xmle_default      {0}
        @h2xmle_range        { 0..1}
        @h2xmle_policy       {Basic} */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct data_logging_island_t data_logging_island_t;

/*
 * ID of the Logging module
 *
 * Supported Input Media Format:
 *  - Data Format          : any
 *  - fmt_id               : Don't care
 *  - Sample Rates         : 1-384 kHz
 *  - Number of channels   : 1-32
 *  - Bit Width            : 16 (bits per sample 16 and Q15),
 *                         : 24 (bits per sample 24 and Q23, bits per sample 32 and Q23 or Q27 or Q31),
 *                         : 32 (bits per sample 32 and Q31)
 *  - Interleaving         : interleaved, deinterleaved unpacked, deinterleaved packed.
 *  - Endianess            : little, big
 *
 */
#define MODULE_ID_DATA_LOGGING                   0x0700101A

/** @h2xml_title1          {Module Data Logging}
    @h2xml_title_agile_rev {Module Data Logging}
     @h2xml_title_date     {March 29, 2019}
  */

/**
    @h2xmlm_module         {"MODULE_ID_DATA_LOGGING", MODULE_ID_DATA_LOGGING}
    @h2xmlm_displayName    {"Data Logging"}
    @h2xmlm_description    {
                            This module is used to log PCM data and bit stream data
                            This module has only one input and one output port.
                            This module is an in place module.
                            This module supports the following parameter IDs, \n
                            - PARAM_ID_DATA_LOGGING_CONFIG\n
                            - PARAM_ID_DATA_LOGGING_ISLAND_CFG\n
                            }

    @h2xmlm_dataMaxInputPorts    {DATA_LOGGING_MAX_INPUT_PORTS}
    @h2xmlm_dataInputPorts       {IN = 2}
    @h2xmlm_dataMaxOutputPorts   {DATA_LOGGING_MAX_OUTPUT_PORTS}
    @h2xmlm_dataOutputPorts      {OUT = 1}
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_SC,APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {true}
    @h2xmlm_stackSize            { DATA_LOGGING_STACK_SIZE_REQUIREMENT }
    @h2xmlm_toolPolicy           {Calibration}
    @{                     <-- Start of the Module -->
    @h2xml_Select          {"data_logging_config_t"}
    @h2xmlm_InsertParameter

    @h2xml_Select              {param_id_module_enable_t}
    @h2xmlm_InsertParameter
    @h2xml_Select              {param_id_module_enable_t::enable}
    @h2xmle_default            {1}

    @h2xml_Select          {"data_logging_island_t"}
    @h2xmlm_InsertParameter

    @}                     <-- End of the Module -->
*/

#endif /* _DATA_LOGGING_API_H_ */
