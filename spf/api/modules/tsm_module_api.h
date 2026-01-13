/*==============================================================================
  @file tsm_api.h
  @brief This file contains TSM module apis
==============================================================================*/
/*-----------------------------------------------------------------------
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
-----------------------------------------------------------------------*/
/** @h2xml_title1          {TSM Module}
    @h2xml_title_agile_rev {TSM Module}
    @h2xml_title_date      {March, 2023} */

/*==============================================================================
   Constants
==============================================================================*/

#ifndef TSM_MODULE_API_H
#define TSM_MODULE_API_H

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "module_cmn_api.h"
#include "apm_graph_properties.h"


/*==============================================================================
   Constants
==============================================================================*/
/*Stack size of TSM module*/
#define TSM_STACK_SIZE              100 * 1024

/* Max number of input/output ports of TSM module */
#define TSM_MAX_PORTS               1

/*Min TSM Channels supported*/
#define TSM_MIN_CHANNELS 1

/*Max TSM Channels supported*/
#define TSM_MAX_CHANNELS 2

#define CAPI_TSM_DEFAULT_PORT 0
/*==============================================================================
   Param ID
==============================================================================*/

#define PARAM_ID_TSM_MAX_MIN_SPEED 0x08001A62
/** @h2xmlp_parameter   {"PARAM_ID_TSM_MAX_MIN_SPEED", PARAM_ID_TSM_MAX_MIN_SPEED}
    @h2xmlp_description {Parameter to change the speed and this should be in the range (max,min) provided in static config}
    @h2xmlp_toolPolicy  {Calibration} */

typedef struct param_id_tsm_max_min_speed_t param_id_tsm_max_min_speed_t;

#include "spf_begin_pack.h"

struct param_id_tsm_max_min_speed_t {
    uint32_t min_speed_factor;
    /**< @h2xmle_description   {Speed factor in Q24 format}
         @h2xmle_default       {4194304}
         @h2xmle_range         {1677721..67108864} */
    uint32_t max_speed_factor;
    /**< @h2xmle_description   {Speed factor in Q24 format}
         @h2xmle_default       {33554432}
         @h2xmle_range         {1677721..67108864} */
}
#include "spf_end_pack.h"
;

#define PARAM_ID_TSM_SPEED_FACTOR 0x08001A63
/** @h2xmlp_parameter   {"PARAM_ID_TSM_SPEED_FACTOR", PARAM_ID_TSM_SPEED_FACTOR}
    @h2xmlp_description {Parameter for configuring/viewing TSM module Speed Factor}
    @h2xmlp_toolPolicy  {Calibration} */

typedef struct param_id_tsm_speed_t param_id_tsm_speed_t;

#include "spf_begin_pack.h"
struct param_id_tsm_speed_t {
    uint32_t speed_factor;
    /**< @h2xmle_description        {Speed factor in Q24 format}
             @h2xmle_default     {16777216}
             @h2xmle_range       {1677721..67108864}
              @h2xmle_readOnly    {true} */

    uint32_t reserved;
    /**< @h2xmle_description     {reserved}
              @h2xmle_default     {0}
              @h2xmle_range       {0..0}
              @h2xmle_visibility  {hide}
              @h2xmle_readOnly    {true} */
}
#include "spf_end_pack.h"
;


#define PARAM_ID_TSM_VERSION 0x08001A65
/** @h2xmlp_parameter   {"PARAM_ID_TSM_VERSION", PARAM_ID_TSM_VERSION}
    @h2xmlp_description {Parameter for viewing TSM module version}
    @h2xmlp_toolPolicy  {RTC_READONLY} */

typedef struct param_id_tsm_ver_t param_id_tsm_ver_t;

#include "spf_begin_pack.h"
struct param_id_tsm_ver_t {

    uint32_t ver_high;
    /**< @h2xmle_description       {Higher 32 bits of 64 bit version number}
             @h2xmle_default       {0x02000100}
             @h2xmle_range         {0..0xFFFFFFFF} */

    uint32_t ver_low;
    /**< @h2xmle_description       {Lower 32 bits of 64 bit version number}
         @h2xmle_default           {0x00000000}
         @h2xmle_range             {0..0xFFFFFFFF} */

    uint32_t reserved1;
    /**< @h2xmle_description       {reserved}
              @h2xmle_default       {0}
              @h2xmle_range      {0..0}
              @h2xmle_visibility {hide}
              @h2xmle_readOnly   {true} */

    uint32_t reserved2;
    /**< @h2xmle_description       {reserved}
              @h2xmle_default    {0}
              @h2xmle_range      {0..0}
              @h2xmle_visibility {hide}
              @h2xmle_readOnly   {true} */
}
#include "spf_end_pack.h"
;

#define PARAM_ID_TSM_SESSION_TIME_SCALING   0x08001A58
/** @h2xmlp_parameter   {"PARAM_ID_TSM_SESSION_TIME_SCALING", PARAM_ID_TSM_SESSION_TIME_SCALING}
    @h2xmlp_description {Param to indicate SPR from TSM through metadata if to propagate Session time.}
    @h2xmlp_toolPolicy  {Calibration} */

typedef struct param_id_tsm_session_time_scaling_t param_id_tsm_session_time_scaling_t;

#include "spf_begin_pack.h"
struct param_id_tsm_session_time_scaling_t
{
    uint32_t is_session_time_scaling_enabled;
    /**< @h2xmle_description {To specify if the TSM module needs to send the metadata for SPR to scale the
                                 session time based on the current speed factor.}
        @h2xmle_rangeList       {"Disable"=0;
                                  "Enable"=1}
        @h2xmle_default         {1}
        @h2xmle_policy          {Basic} */

    uint32_t reserved;
    /**< @h2xmle_description    {reserved}
         @h2xmle_default         {0}
         @h2xmle_range           {0..0}
          @h2xmle_visibility      {hide}
         @h2xmle_readOnly        {true} */
}
#include "spf_end_pack.h"
;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

#define MODULE_ID_TSM  0x07001172
/**
    @h2xmlm_module       {"MODULE_ID_TSM", MODULE_ID_TSM}
    @h2xmlm_displayName  {"Time Scale Modification"}
    @h2xmlm_description  { Time scaling with varying speed factors\n
                           - This module supports the following parameter IDs:\n
                           - #PARAM_ID_MAX_MIN_SPEED\n
                           - #PARAM_ID_TSM_SPEED_FACTOR\n
                           - #PARAM_ID_TSM_VERSION\n
                           - #PARAM_ID_TSM_SESSION_TIME_SCALING\n
                           - Supported Input Media Format: \n
                           - Data Format          : FIXED \n
                           - fmt_id               : Don't care \n
                           - Sample Rates         : 8000,11025, 12000, 16000, 22500, 24000, 32000, 44100, 48000\n
                           - Number of channels   : 1, 2 \n
                           - Channel type         : Don't care \n
                           - Bits per sample      : 16 \n
                           - Q format             : Q15 \n
                           - Interleaving         : de-interleaved unpacked \n
                           - Signed/unsigned      : Signed \n
  \n}
    @h2xmlm_dataMaxInputPorts   {TSM_MAX_PORTS}
    @h2xmlm_dataMaxOutputPorts  {TSM_MAX_PORTS}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {8192}
    @h2xmlm_toolPolicy          {Calibration}

    @{                   <-- Start of the Module -->

    @h2xml_Select                    {param_id_tsm_max_min_speed_t}
    @h2xmlm_InsertParameter

    @h2xml_Select                    {param_id_tsm_speed_t}
    @h2xmlm_InsertParameter

    @h2xml_Select                    {param_id_tsm_ver_t}
    @h2xmlm_InsertParameter

    @h2xml_Select                    {param_id_tsm_session_time_scaling_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/
#endif
