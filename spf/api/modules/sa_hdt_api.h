#ifndef SA_HDT_API_H
#define SA_HDT_API_H

/*==============================================================================
  @file sa_hdt_api.h
  @brief This file contains spatial audio head tracking module APIs

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
/* =========================================================================
   Edit History


   when       who       what, where, why
   --------   -------   ----------------------------------------------------

   ======================================================================== */
// clang-format on

/** @h2xml_title1          {SA Head Tracking}
    @h2xml_title_agile_rev {SA Head Tracking}
    @h2xml_title_date      {Sep 16 2025}  */

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "imcl_spm_intent_api.h"
#include "imcl_fwk_intent_api.h"

/*==============================================================================
   Constants
==============================================================================*/
/* SA HDT module stack size*/
#define SA_HDT_STACK_SIZE 4096

/* Input ports of SA HDT module */
#define SA_HDT_MAX_IN_PORTS 0x1

/* Ouput ports of SA HDT module */
#define SA_HDT_MAX_OUT_PORTS 0x0

/* Input port ID of SA HDT module */
#define PORT_ID_SA_HDT_INPUT 0x2

/* Output port ID of SA HDT module */
#define PORT_ID_SA_HDT_OUTPUT 0x1

/* Max number of intent per control port of SA HDT module */
#define SA_HDT_MAX_INTENTS_PER_CTRL_PORT 2

/* Static output control port ID's of SA HDT module */
#define SA_HDT_OUT_RAW_DATA AR_NON_GUID(0xC0000001)

/* Static output control port for orientation data */
#define SA_HDT_OUT_ORIENTATION_DATA AR_NON_GUID(0xC0000002)

/* Direction of Stream Information for SA HDT module */
#define SA_HDT_FROM_AIR 1
#define SA_HDT_TO_AIR 0

/*==============================================================================
   Param ID
==============================================================================*/
/** Parameter ID of SA HDT Stream Info */
#define PARAM_ID_SA_HDT_STREAM_INFO 0x08001B95

/** @h2xmlp_subStruct */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
typedef struct sa_hdt_stream_info_map_t
{
   uint32_t stream_id;
   /**<
     @h2xmle_description {Stream ID}
     @h2xmle_default     {0}     */
   uint32_t direction;
   /**<
     @h2xmle_description {1 -> from air || 0 -> to air }
     @h2xmle_default     {0}
     @h2xmle_rangeList   {"FROMAIR"=1;
                          "TOAIR"=0}    */
   uint32_t channel_mask_lsw;
   /**<
     @h2xmle_description {Channel Mask LSW}
     @h2xmle_default     {0x00000008}    */
   uint32_t channel_mask_msw;
   /**<
     @h2xmle_description {Channel Mask MSW}
     @h2xmle_default     {0x00000000}    */
} sa_hdt_stream_info_map_t
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
   ;

/** @h2xmlp_parameter   {"PARAM_ID_SA_HDT_STREAM_INFO", PARAM_ID_SA_HDT_STREAM_INFO}
    @h2xmlp_description {Structure for the param_id_sa_hdt_stream_info_t parameter used by the SA HDT module.
                         It is a mandatory param for SA HDT module to work }
   @h2xmlp_toolPolicy   {NO_SUPPORT}
   @h2xmlx_expandStructs  {false}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sa_hdt_stream_info_t
{
   uint32_t num_streams;
   /**<
     @h2xmle_description {Number of Streams of HDT data}
     @h2xmle_default     {1}
     @h2xmle_policy      {Basic}
    */

#if defined(__H2XML__)
   sa_hdt_stream_info_map_t stream_map[0];
   /**< @h2xmle_description  {Channel mapping -> sa_hdt_stream_info_map_t structures}
        @h2xmle_variableArraySize {num_streams} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_sa_hdt_stream_info_t param_id_sa_hdt_stream_info_t;

/** Parameter ID of SA HDT OP Mode */
#define PARAM_ID_SA_HDT_OP_MODE 0x08001B96

/** @h2xmlp_parameter   {"PARAM_ID_SA_HDT_OP_MODE", PARAM_ID_SA_HDT_OP_MODE}
    @h2xmlp_description {Structure for the param_id_sa_hdt_op_mode_t parameter used by the SA HDT module.
                         It is an optional param for SA HDT module }
   @h2xmlp_toolPolicy   {CALIBRATION}
   @h2xmlx_expandStructs  {false}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sa_hdt_op_mode_t
{
   uint32_t hdt_op_mode;
   /**<
     @h2xmle_description {Operation mode of HDT Module}
     @h2xmle_rangeList   {"Default RAW Mode"=0;
                          "Processed HDT Data"=1}
     @h2xmle_default     {0}
     @h2xmle_policy      {Basic}
    */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_sa_hdt_op_mode_t param_id_sa_hdt_op_mode_t;

/** Parameter ID for SA HDT Tracking Configuration */
#define PARAM_ID_SA_HDT_TRACKING_CONFIG 0x08010007

/** @h2xmlp_parameter   {"PARAM_ID_SA_HDT_TRACKING_CONFIG", PARAM_ID_SA_HDT_TRACKING_CONFIG}
    @h2xmlp_description {Structure for tracking configuration parameters}
    @h2xmlp_toolPolicy  {CALIBRATION}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sa_hdt_tracking_config_t
{
   uint32_t target_tracking_mode;
   /**<
     @h2xmle_description {Target tracking mode}
     @h2xmle_rangeList   {"Static (No tracking)"=0;
                          "World-locked (Head tracking)"=1;
                          "Screen-locked"=2}
     @h2xmle_default     {1}
     @h2xmle_policy      {Basic}
    */

   uint32_t stillness_detect;
   /**<
     @h2xmle_description {Enable stillness detection for auto-recenter}
     @h2xmle_rangeList   {"Disabled"=0;
                          "Enabled"=1}
     @h2xmle_default     {1}
     @h2xmle_policy      {Basic}
    */

   uint32_t stillness_timer;
   /**<
     @h2xmle_description {Stillness timer in milliseconds}
     @h2xmle_range       {500..15000}
     @h2xmle_default     {7000}
     @h2xmle_policy      {Basic}
    */

   float stillness_threshold;
   /**<
     @h2xmle_description {Stillness threshold (quaternion dot product)}
     @h2xmle_range       {0.001..0.1}
     @h2xmle_default     {0.0175}
     @h2xmle_policy      {Basic}
    */

   float max_rotational_velocity;
   /**<
     @h2xmle_description {Maximum rotational velocity in rad/s}
     @h2xmle_range       {0.0..20}
     @h2xmle_default     {10}
     @h2xmle_policy      {Basic}
    */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_sa_hdt_tracking_config_t param_id_sa_hdt_tracking_config_t;

/** Parameter ID for SA HDT Tracking Recenter */
#define PARAM_ID_SA_HDT_TRACKING_RECENTER 0x08F013DB

/** @h2xmlp_parameter   {"PARAM_ID_SA_HDT_TRACKING_RECENTER", PARAM_ID_SA_HDT_TRACKING_RECENTER}
    @h2xmlp_description {Command to recenter head tracking}
    @h2xmlp_toolPolicy  {RTC}
    @h2xmlx_expandStructs {false}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sa_hdt_tracking_recenter_t
{
    uint32_t force_update;
    /**<
     @h2xmle_description {Force immediate update bypassing velocity limiting}
     @h2xmle_rangeList   {"Normal recenter"=0;
                          "Force immediate"=1}
     @h2xmle_default     {0}
     @h2xmle_policy      {Basic}
    */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_sa_hdt_tracking_recenter_t param_id_sa_hdt_tracking_recenter_t;

/** Parameter ID for SA HDT Tracking Status (Read-only) */
#define PARAM_ID_SA_HDT_TRACKING_STATUS 0x08F013E0

/** @h2xmlp_parameter   {"PARAM_ID_SA_HDT_TRACKING_STATUS", PARAM_ID_SA_HDT_TRACKING_STATUS}
    @h2xmlp_description {Read-only tracking status information}
    @h2xmlp_toolPolicy  {RTC_READONLY}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_sa_hdt_tracking_status_t
{
  uint32_t current_tracking_mode;
  /**<
    @h2xmle_description {Current active tracking mode}
    @h2xmle_rangeList   {"Static"=0;
                        "World-locked"=1;
                        "Screen-locked"=2}
    @h2xmle_default     {1}
    @h2xmle_policy      {Basic}
  */

  uint32_t head_to_stage_rotation_mode;
  /**<
    @h2xmle_description {Rotation mode of head-to-stage output}
    @h2xmle_rangeList   {"YPR"=0;
                        "RPY"=1;
                        "Axis-Angle"=2}
    @h2xmle_default     {2}
    @h2xmle_policy      {Basic}
  */

  float head_to_stage_x;
  /**<
    @h2xmle_description {Head-to-stage rotation X component}
    @h2xmle_default     {0.0}
    @h2xmle_policy      {Basic}
  */

  float head_to_stage_y;
  /**<
    @h2xmle_description {Head-to-stage rotation Y component}
    @h2xmle_default     {0.0}
    @h2xmle_policy      {Basic}
  */

  float head_to_stage_z;
  /**<
    @h2xmle_description {Head-to-stage rotation Z component}
    @h2xmle_default     {0.0}
    @h2xmle_policy      {Basic}
  */

  uint32_t head_is_still;
  /** < @h2xmle_default       {0}
        @h2xmle_description   {Current head stillness status}
        @h2xmle_dataFormat    {Q0}
        @h2xmle_rangeList     {moving=0;still=1} */
  
  int64_t stillness_countdown;
  /** < @h2xmle_default       {7000}
        @h2xmle_description   {Stillness time until recenter in ms}
        @h2xmle_dataFormat    {Q0}
        @h2xmle_range         {500,15000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_sa_hdt_tracking_status_t param_id_sa_hdt_tracking_status_t;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/** @h2xml_title1           {SA HDT Module API} */

/**
 * Module ID for SA HDT Module
 */

#define MODULE_ID_SA_HDT     0x0702C005
/**
   @h2xmlm_module              {"MODULE_ID_SA_HDT",
                                 MODULE_ID_SA_HDT}
   @h2xmlm_displayName         {"Spatial Audio HDT"}
   @h2xmlm_modSearchKeys       {Spatial Audio, HDT}
   @h2xmlm_description         {- SA HDT\n
                                - This module handles headtracking data from BT controller as deinterleaved raw
   bitstream\n
                                - Supports following params: \n
                                - PARAM_ID_SA_HDT_STREAM_INFO
                                - PARAM_ID_SA_HDT_OP_MODE
                                - PARAM_ID_SA_HDT_TRACKING_CONFIG
                                - PARAM_ID_SA_HDT_TRACKING_RECENTER
                                - PARAM_ID_SA_HDT_TRACKING_STATUS
                                - Supported Input Media Format: \n
                                - Data Format          : CAPI_DEINTERLEAVED_RAW_COMPRESSED
                                - fmt_id               : Don't care \n}
   @h2xmlm_dataInputPorts      {IN = PORT_ID_SA_HDT_INPUT}
   @h2xmlm_dataMaxInputPorts   {1}
   @h2xmlm_dataMaxOutputPorts  {0}
   @h2xmlm_ctrlStaticPort      {"SA_HDT_OUT_RAW_DATA" = 0xC0000001,
                              "HDT Raw Data Out" = INTENT_ID_SA_HDT_RAW_DATA}
   @h2xmlm_ctrlStaticPort      {"SA_HDT_OUT_ORIENTATION_DATA" = 0xC0000002,
                              "HDT Orientation Data Out" = INTENT_ID_SA_HDT_ORIENTATION_DATA}
   @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
   @h2xmlm_isOffloadable       {false}
   @h2xmlm_stackSize           {SA_HDT_STACK_SIZE}
   @{                          <-- Start of the Module -->

   @h2xml_Select               {param_id_sa_hdt_op_mode_t}
   @h2xmlm_InsertParameter
   @h2xml_Select               {sa_hdt_stream_info_map_t}
   @h2xmlm_InsertParameter
   @h2xml_Select               {param_id_sa_hdt_stream_info_t}
   @h2xmlm_InsertParameter
   @h2xml_Select               {param_id_sa_hdt_tracking_config_t}
   @h2xmlm_InsertParameter
   @h2xml_Select               {param_id_sa_hdt_tracking_recenter_t}
   @h2xmlm_InsertParameter
   @h2xml_Select               {param_id_sa_hdt_tracking_status_t}
   @h2xmlm_InsertParameter
   @}                        <-- End of the Module -->
*/
#endif // SA_HDT_API_H
