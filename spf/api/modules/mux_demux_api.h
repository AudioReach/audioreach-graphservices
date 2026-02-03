#ifndef MUX_DEMUX_H_
#define MUX_DEMUX_H_
/**
 * \file mux_demux_api.h
 * \brief 
 *  	 This file contains APIs for mux_demux module.
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/** @h2xml_title1          {Muxing and Demuxing Module}
    @h2xml_title_agile_rev {Muxing and Demuxing Module}
    @h2xml_title_date      {October, 2019} */

/*==============================================================================
   Include Files
==============================================================================*/
#include "module_cmn_api.h"

/*==============================================================================
   Constants
==============================================================================*/

/* Stack size of module */
#define MUX_DEMUX_STACK_SIZE 		2048

/*==============================================================================
   Param ID
==============================================================================*/

#define PARAM_ID_MUX_DEMUX_CONFIG 	0x080011BD

/*==============================================================================
   Param structure defintions
==============================================================================*/
/** @h2xmlp_subStruct
    @h2xmlp_description  { This structure defines a connection from an input
                           port to an output port. }
    */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct mux_demux_connection_config_t
{
   uint32_t input_port_id;
   /**< @h2xmle_description {input port id.}
    */
   uint32_t input_channel_index;
   /**< @h2xmle_description {input channel id.}
        @h2xmle_range       {0..31}
    */

   uint32_t output_port_id;
   /**< @h2xmle_description {output port id.}
    */
   uint32_t output_channel_index;
   /**< @h2xmle_description {output channel id.}
        @h2xmle_range       {0..31}
    */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct mux_demux_connection_config_t mux_demux_connection_config_t;


/** @h2xmlp_parameter   {"PARAM_ID_MUX_DEMUX_CONFIG", PARAM_ID_MUX_DEMUX_CONFIG}
    @h2xmlp_description {This parameter is used for mux and demux configuration
                                     at channel level across input-output streams.}
    @h2xmlp_toolPolicy  {Calibration; RTC} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_mux_demux_config_t
{
   uint32_t num_of_connections;
   /**< @h2xmle_description {Number of connections from input to output across
                         all streams.}
    */
#ifdef __H2XML__
   mux_demux_connection_config_t connection_arr[0];
   /**< @h2xmle_description  		{An array of connections}
        @h2xmlx_expandStructs 		{true}
        @h2xmle_variableArraySize	{ num_of_connections }
    */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_mux_demux_config_t param_id_mux_demux_config_t;

/*==============================================================================
   Param ID
==============================================================================*/

#define PARAM_ID_MUX_DEMUX_OUT_FORMAT 	0x080011BE

/*==============================================================================
   Param structure defintions
==============================================================================*/
/** @h2xmlp_subStruct
    @h2xmlp_description  { This structure sets the media format of an output port. }
    */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct mux_demux_out_format_t
{
   uint32_t output_port_id;
   /**< @h2xmle_description {output port id.}
    */

   uint16_t bits_per_sample;
   /**< @h2xmle_description {bits per sample.}
        @h2xmle_default     {16}
        @h2xmle_rangelist   {BPS16;16,BPS32;32}
    */

   uint16_t q_factor;
   /**< @h2xmle_description {q factor.}
        @h2xmle_default     {15}
        @h2xmle_rangelist   {BPS16_Q15;15,BPS32_Q27;27,BPS32_Q31;31}
    */

   uint32_t num_channels;
   /**< @h2xmle_description {number of channels.}
        @h2xmle_default     {2}
        @h2xmle_range       {1..32}
    */
#ifdef __H2XML__
   uint16_t channel_type[0];
   /**< @h2xmle_description   {channel type, array size is even for alignment purpose.}
        @h2xmlx_expandStructs {true}
        @h2xmle_variableArraySize  { num_channels}
		@h2xmle_rangeEnum   {pcm_channel_map}
		@h2xmle_default     {1}
    */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct mux_demux_out_format_t mux_demux_out_format_t;


/** @h2xmlp_parameter   {"PARAM_ID_MUX_DEMUX_OUT_FORMAT", PARAM_ID_MUX_DEMUX_OUT_FORMAT}
    @h2xmlp_description {This parameter is used to configure the output port
   	   	   	   	   	   	 media format.}
    @h2xmlp_toolPolicy  {Calibration; RTC} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_mux_demux_out_format_t
{
   uint32_t num_config;
   /**< @h2xmle_description {Number of output port media format configuration.}
    */
#ifdef __H2XML__
   mux_demux_out_format_t out_fmt_arr[0];
   /**< @h2xmle_description  		{An array of output port format}
        @h2xmlx_expandStructs 		{false}
        @h2xmle_variableArraySize  	{num_config}
    */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_mux_demux_out_format_t param_id_mux_demux_out_format_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

#define MODULE_ID_MUX_DEMUX 	0x07001098
/**
    @h2xmlm_module       {"MODULE_ID_MUX_DEMUX", MODULE_ID_MUX_DEMUX}
    @h2xmlm_displayName  {"Muxing &amp; Demuxing"}
    @h2xmlm_description  { This module provides channel routing
   	   	   	   	   	   	   functionality from multiple input stream
   	   	   	   	   	   	   to multiple output streams.\n
   	   	   	   	   	   	   Sync module is required to synchronize the inputs
   	   	   	   	   	   	   if placed in CD or PP container(non timer triggered).\n
                           -#PARAM_ID_MUX_DEMUX_CONFIG\n
                           -#PARAM_ID_MUX_DEMUX_OUT_FORMAT\n
                           - Supported Input Media Format:\n
                           - Data Format          : FIXED \n
                           - fmt_id               : PCM \n
                           - Sample Rates         : 8000...384000 \n
                           - Number of channels   : 1...32 \n
                           - Channel type         : Don't care \n
                           - Bits per sample      : 16,32 \n
                           - Q format             : Q15,Q27,Q31 \n
                           - Interleaving         : De-interleaved unpacked \n
                           - Signed/unsigned      : Signed \n}
    @h2xmlm_dataMaxInputPorts    {INFINITE}
    @h2xmlm_dataMaxOutputPorts   {INFINITE}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_stackSize           {MUX_DEMUX_STACK_SIZE}
    @h2xmlm_toolPolicy          { Calibration }

    @{                   <-- Start of the Module -->

    @h2xml_Select					{mux_demux_out_format_t}
    @h2xmlm_InsertParameter

    @h2xml_Select					{mux_demux_connection_config_t}
    @h2xmlm_InsertParameter

    @h2xml_Select					{param_id_mux_demux_config_t}
    @h2xmlm_InsertParameter

    @h2xml_Select					{param_id_mux_demux_out_format_t}
    @h2xmlm_InsertParameter

    @}                   <-- End of the Module -->*/

#endif
