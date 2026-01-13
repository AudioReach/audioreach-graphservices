#ifndef _ACD_API_H_
#define _ACD_API_H_

/*==============================================================================
  @file acd_api.h
  @brief This file contains Public APIs for Audio Context Detection Engine Module

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "detection_cmn_api.h"
#include "contexts_api.h"
/**
    @h2xml_title1          {ACD API}
    @h2xml_title_agile_rev {ACD API}
    @h2xml_title_date      {Dec 12, 2020}
 */

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/
/*==============================================================================
   Constants
==============================================================================*/
/* maximum number of ports on either side, supported by algorithm */
#define CAPI_ACD_MAX_PORTS 1
/* maximum number of Detection Clients, supported by algorithm */
#define CAPI_ACD_MAX_DETECTION_EVENT_CLIENTS 4
/* Stack Size requirement of this Algo*/
#define CAPI_ACD_STACK_SIZE 8192
/* Global unique Module ID definition.
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_ACD 0x070010CC

/* Unique Paramter id */
#define PARAM_ID_ACD_STATIC_CFG                     0x0800133B

/* Structure definition for Parameter */
/** @h2xmlp_parameter   {"PARAM_ID_ACD_STATIC_CFG",PARAM_ID_ACD_STATIC_CFG}
    @h2xmlp_description {Defines the static configuration needed by the ACD module \n
                        -# This helps configure required processing blocks in the algorithm}
    @h2xmlp_toolPolicy  {Calibration}*/
#include "spf_begin_pack.h"
struct param_id_acd_static_cfg_t
{
    uint32_t env_process_required;
    /**< @h2xmle_description   {flag to control if ACD should process environment contexts}
          @h2xmle_default       {1}
         @h2xmle_range         {0..1} */

    uint32_t event_process_required;
    /**< @h2xmle_description   {flag to control if ACD should process event contexts}
         @h2xmle_default       {1}
         @h2xmle_range         {0..1}*/

    uint32_t ambience_process_required;
    /**< @h2xmle_description   {flag to control if ACD should process ambience contexts}
         @h2xmle_default       {1}
         @h2xmle_range         {0..1}*/

    uint32_t ambience_class_bitmask;
    /**< @h2xmle_description   {Bitmask to Enable or disable individual ambience classes}

        @h2xmle_bitField    {0x00000001}
        @h2xmle_bitName     {Speech}
        @h2xmle_description {Enable/Disable Speech Ambience}
        @h2xmle_rangeList   {Disabled=0;Enabled=1}
        @h2xmle_bitFieldEnd

        @h2xmle_bitField    {0x00000002}
        @h2xmle_bitName     {Music}
        @h2xmle_description {Enable/Disable Music Ambience}
        @h2xmle_rangeList   {Disabled=0;Enabled=1}
        @h2xmle_bitFieldEnd

        @h2xmle_bitField    {0x00000004}
        @h2xmle_bitName     {Noise}
        @h2xmle_description {Enable/Disable Noise Ambience}
        @h2xmle_rangeList   {Disabled=0;Enabled=1}
        @h2xmle_bitFieldEnd

        @h2xmle_bitField    {0x00000008}
        @h2xmle_bitName     {Silence}
        @h2xmle_description {Enable/Disable Silence Ambience}
        @h2xmle_rangeList   {Disabled=0;Enabled=1}
        @h2xmle_bitFieldEnd

        @h2xmle_default       {0xF}
        @h2xmle_range         {0..0xF}*/


  uint32_t num_noise_smoothing_frames;
    /**< @h2xmle_description   {Number of frames to take into account for averaging Noise Levels}
         @h2xmle_default       {1}
         @h2xmle_range         {0..100}*/

}
#include "spf_end_pack.h"
;
typedef struct param_id_acd_static_cfg_t param_id_acd_static_cfg_t;

#define PARAM_ID_ACD_AMBIENCE_DYNAMIC_CFG           0x0800133C

/* Structure definition for Parameter */
/** @h2xmlp_parameter   {"PARAM_ID_ACD_AMBIENCE_DYNAMIC_CFG",PARAM_ID_ACD_AMBIENCE_DYNAMIC_CFG}
    @h2xmlp_description {Defines the dynamic configuration needed by the ACD's Ambience sub-module}
    @h2xmlp_toolPolicy  {Calibration}*/
#include "spf_begin_pack.h"
struct param_id_acd_ambience_dynamic_cfg_t
{
   uint16_t speech_hangover_num_frames;
    /**< @h2xmle_description   {Number of frames of no detected speech before vad classification goes to 0}
         @h2xmle_default       {10}
         @h2xmle_range         {0..0xFFFF}*/

   uint16_t music_hangover_num_frames;
    /**< @h2xmle_description   {Number of frames of no detected music before mad classification goes to 0}
         @h2xmle_default       {10}
         @h2xmle_range         {0..0xFFFF}*/

    uint32_t max_conf_frames_speech;
    /**< @h2xmle_description   {Number of frames for capping speech confidence frames}
         @h2xmle_default       {300}
         @h2xmle_range         {0..0xFFFFFFFF}*/

    uint32_t min_conf_frames_speech;
    /**< @h2xmle_description   {Minimum confidence frames for speech detection}
         @h2xmle_default       {30}
         @h2xmle_range         {0..0xFFFFFFFF}*/

   uint32_t max_conf_frames_music;
    /**< @h2xmle_description   {Number of frames for capping music confidence frames}
         @h2xmle_default       {300}
         @h2xmle_range         {0..0xFFFFFFFF}*/

   uint32_t min_conf_frames_music;
    /**< @h2xmle_description   {Minimum confidence frames for music detection}
         @h2xmle_default       {30}
         @h2xmle_range         {0..0xFFFFFFFF}*/
}
#include "spf_end_pack.h"
;
typedef struct param_id_acd_ambience_dynamic_cfg_t param_id_acd_ambience_dynamic_cfg_t;



#define EVENT_ID_ACD_DETECTION_EVENT        0x0800133D
/* Structure definition for Parameter */
/** @parameter   {"EVENT_ID_ACD_DETECTION_EVENT",EVENT_ID_ACD_DETECTION_EVENT}
    @description {Event raised by ACD to the clients; registration and event have differnt payload types}
    @toolPolicy  {NO_SUPPORT}*/

/** IDs that determine the type of context_specific_payload use to configure
    the acd during event register payload.
 */
enum acd_event_cfg_key_id_t
{
  ACD_KEY_ID_GENERIC_INFO = 0,   /**< reg: acd_generic_key_id_reg_cfg_t; event: acd_generic_key_id_event_t */
  ACD_MAX_KEYS_SUPPORTED /**<  Maxium supported value for acd_event_cfg_key_id_t */
};

typedef enum acd_event_cfg_key_id_t acd_event_cfg_key_id_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct acd_key_info_t
{
   uint32_t key_id;
   /**< @description {ID that Indicates the information/payload type that will follow}
        @rangeEnum    {acd_event_cfg_key_id_t}
        @default      {ACD_KEY_ID_GENERIC_INFO} */

   uint32_t key_payload_size;
   /**< @description {Size of the key specific payload that follows -has to be 4 byte multiple
        This is followed by the key specific payload based on the key ID}*/
#if defined(__H2XML__)
   uint8_t key_specific_payload[0];
   /*@variableArraySize {key_payload_size} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct acd_key_info_t acd_key_info_t;
/** ################################ Struct definitions for event registration################### */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_id_acd_detection_cfg_t
{
   uint32_t num_keys;
   /**< @description {number of keys and related structures in the payload that follows}*/
#if defined(__H2XML__)
   acd_key_info_t key_payload_arr[0];
   /**< @description  {event config array of size num_keys.}
        @variableArraySize {num_keys} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct event_id_acd_detection_cfg_t event_id_acd_detection_cfg_t;

/** @description {This is the context specific payload to configure the
                  detection events for contexts with the generic event key id} */
#include "spf_begin_pack.h"
struct acd_context_specific_generic_reg_info_t
{
   uint32_t context_id;
   /**< @description  {context ID}
        @rangeList    {"ENV_HOME"=MODULE_CMN_CONTEXT_ID_ENV_HOME;
                              "ENV_OFFICE"=MODULE_CMN_CONTEXT_ID_ENV_OFFICE;
                              "ENV_RESTAURANT"=MODULE_CMN_CONTEXT_ID_ENV_RESTAURANT;
                              "ENV_INDOOR"=MODULE_CMN_CONTEXT_ID_ENV_INDOOR;
                              "ENV_INSTREET"=MODULE_CMN_CONTEXT_ID_ENV_INSTREET;
                              "ENV_OUTDOOR"=MODULE_CMN_CONTEXT_ID_ENV_OUTDOOR;
                              "ENV_INCAR"=MODULE_CMN_CONTEXT_ID_ENV_INCAR;
                              "ENV_INTRAIN"=MODULE_CMN_CONTEXT_ID_ENV_INTRAIN;
                              "ENV_UNKNOWN"=MODULE_CMN_CONTEXT_ID_ENV_UNKNOWN;
                              "EVENT_ALARM"=MODULE_CMN_CONTEXT_ID_EVENT_ALARM;
                              "EVENT_BABYCRYING"=MODULE_CMN_CONTEXT_ID_EVENT_BABYCRYING;
                              "EVENT_DOGBARKING"=MODULE_CMN_CONTEXT_ID_EVENT_DOGBARKING;
                              "EVENT_DOORBELL"=MODULE_CMN_CONTEXT_ID_EVENT_DOORBELL;
                              "EVENT_DOORCLOSE"=MODULE_CMN_CONTEXT_ID_EVENT_DOORCLOSE;
                              "EVENT_DOOROPEN"=MODULE_CMN_CONTEXT_ID_EVENT_DOOROPEN;
                              "EVENT_GLASSBREAKING"=MODULE_CMN_CONTEXT_ID_EVENT_GLASSBREAKING;
                              "EVENT_SIREN"=MODULE_CMN_CONTEXT_ID_EVENT_SIREN;
                              "AMBIENCE_SPEECH"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SPEECH;
                              "AMBIENCE_MUSIC"=MODULE_CMN_CONTEXT_ID_AMBIENCE_MUSIC;
                              "AMBIENCE_NOISY_SPL"=MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SPL;
                              "AMBIENCE_SILENT_SPL"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SPL;
                              "AMBIENCE_NOISY_SFLUX"=MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SFLUX;
                              "AMBIENCE_SILENT_SFLUX"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SFLUX}
        @default      {MODULE_CMN_CONTEXT_ID_ENV_HOME} */

   uint32_t confidence_threshold;
   /**< @description {Threshold for context detection}
        @range        {0..100}
        @default      {50} */

   uint32_t step_size;
   /**< @description {This denotes the step size in confidence i.e, event
                      should only be raised if the confidence score changes by this much}
        @range        {0..100}
        @default      {10}                            */
}
#include "spf_end_pack.h"
;

typedef struct acd_context_specific_generic_reg_info_t acd_context_specific_generic_reg_info_t;

/* Event register/config payload associated with the generic context IDs
   Corresponding to ACD_KEY_ID_GENERIC_INFO
*/

#include "spf_begin_pack.h"
struct acd_generic_key_id_reg_cfg_t
{
   uint32_t num_contexts;
   /**< @description  {number of contexts required by the client} */
#if defined (__H2XML__)
   acd_context_specific_generic_reg_info_t context_cfg_arr[0];
   /**< @description  {context config payloads specific to generic key}
        @variableArraySize {num_contexts} */
#endif
}
#include "spf_end_pack.h"
;

typedef struct acd_generic_key_id_reg_cfg_t acd_generic_key_id_reg_cfg_t;
/** ################################ Struct definitions for raised event################### */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_id_acd_detection_event_t
{
   uint32_t event_timestamp_lsw;
   /**< @description {This denotes the buffer timestamp (lsw) in us when the event is raised}
        @range        {0..0xFFFFFFFF}  */

   uint32_t event_timestamp_msw;
   /**< @description {This denotes the buffer timestamp (msw) in us when the event is raised}
        @range        {0..0xFFFFFFFF}  */

   uint32_t num_keys;
   /**< @description {number of keys and related structures in the payload that follows}
        @rangeEnum    {acd_event_cfg_key_id_t}
        @default      {ACD_KEY_ID_GENERIC_INFO} */

#if defined(__H2XML__)
   acd_key_info_t key_payload_arr[0];
   /**< @description  {key array}
        @variableArraySize {num_keys} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_acd_detection_event_t event_id_acd_detection_event_t;

#include "spf_begin_pack.h"
struct acd_context_specific_generic_event_t
{
   uint32_t context_id;
   /**< @description  {context ID}
        @rangeList    {"ENV_HOME"=MODULE_CMN_CONTEXT_ID_ENV_HOME;
                       "ENV_OFFICE"=MODULE_CMN_CONTEXT_ID_ENV_OFFICE;
                       "ENV_RESTAURANT"=MODULE_CMN_CONTEXT_ID_ENV_RESTAURANT;
                       "ENV_INDOOR"=MODULE_CMN_CONTEXT_ID_ENV_INDOOR;
                       "ENV_INSTREET"=MODULE_CMN_CONTEXT_ID_ENV_INSTREET;
                       "ENV_OUTDOOR"=MODULE_CMN_CONTEXT_ID_ENV_OUTDOOR;
                       "ENV_INCAR"=MODULE_CMN_CONTEXT_ID_ENV_INCAR;
                       "ENV_INTRAIN"=MODULE_CMN_CONTEXT_ID_ENV_INTRAIN;
                       "ENV_UNKNOWN"=MODULE_CMN_CONTEXT_ID_ENV_UNKNOWN;
                       "EVENT_ALARM"=MODULE_CMN_CONTEXT_ID_EVENT_ALARM;
                       "EVENT_BABYCRYING"=MODULE_CMN_CONTEXT_ID_EVENT_BABYCRYING;
                       "EVENT_DOGBARKING"=MODULE_CMN_CONTEXT_ID_EVENT_DOGBARKING;
                       "EVENT_DOORBELL"=MODULE_CMN_CONTEXT_ID_EVENT_DOORBELL;
                       "EVENT_DOORCLOSE"=MODULE_CMN_CONTEXT_ID_EVENT_DOORCLOSE;
                       "EVENT_DOOROPEN"=MODULE_CMN_CONTEXT_ID_EVENT_DOOROPEN;
                       "EVENT_GLASSBREAKING"=MODULE_CMN_CONTEXT_ID_EVENT_GLASSBREAKING;
                       "EVENT_SIREN"=MODULE_CMN_CONTEXT_ID_EVENT_SIREN;
                       "AMBIENCE_SPEECH"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SPEECH;
                       "AMBIENCE_MUSIC"=MODULE_CMN_CONTEXT_ID_AMBIENCE_MUSIC;
                       "AMBIENCE_NOISY_SPL"=MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SPL;
                       "AMBIENCE_SILENT_SPL"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SPL;
                       "AMBIENCE_NOISY_SFLUX"=MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SFLUX;
                       "AMBIENCE_SILENT_SFLUX"=MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SFLUX}
        @default      {MODULE_CMN_CONTEXT_ID_ENV_HOME} */

   uint32_t event_type;
   /**< @description   {Defines whether the Context Detected is Started, Stopped or Ongoing}
         @rangeList     {"ACD_TYPE_STOPPED" = 0;
                         "ACD_TYPE_STARTED" = 1;
                         "ACD_TYPE_DETECTED" = 2}*/
   uint32_t confidence_score;
   /**< @description {Confidence Score for the detection}
        @range        {0..100} */

   uint32_t detection_timestamp_lsw;
   /**< @description {This denotes the timestamp (lsw) in us when the context was first detected (event type started)}
        @range        {0..0xFFFFFFFF}  */

   uint32_t detection_timestamp_msw;
   /**< @description {This denotes the timestamp (msw) in us when the context was first detected (event type started)}
        @range        {0..0xFFFFFFFF}  */
}
#include "spf_end_pack.h"
;
typedef struct acd_context_specific_generic_event_t acd_context_specific_generic_event_t;

/* Event Payload associated with the generic context IDs
   Corresponding to ACD_KEY_ID_GENERIC_INFO*/

#include "spf_begin_pack.h"
struct acd_generic_key_id_event_t
{
   uint32_t num_contexts;
   /**< @description  {number of client's contexts detected by the algo} */
#if defined (__H2XML__)
   acd_context_specific_generic_event_t context_event_arr[0];
   /**< @description  {context config for the required events array}
        @variableArraySize {num_contexts} */
#endif
}
#include "spf_end_pack.h"
;

typedef struct acd_generic_key_id_event_t acd_generic_key_id_event_t;
/*==============================================================================
   Module definition
==============================================================================*/

/** @h2xmlm_module       {"MODULE_ID_ACD",MODULE_ID_ACD}
    @h2xmlm_displayName  {"Audio Context Detection"}
    @h2xmlm_description  {Supports the Audio Context Detection (environments, events, ambiences) \n
    This module supports the following parameter IDs:  \n
   * PARAM_ID_ACD_STATIC_CFG \n
   * PARAM_ID_ACD_AMBIENCE_DYNAMIC_CFG \n
   * PARAM_ID_DETECTION_ENGINE_REGISTER_MULTI_SOUND_MODEL \n
   * PARAM_ID_MLA_ENABLE \n
 * Supported Input Media Format: \n
 *  - Data Format          : FIXED_POINT \n
 *  - fmt_id               : Don't care \n
 *  - Sample Rates         : 16Khz \n
 *  - Number of channels   : any, but algo uses only the first channel \n
 *  - Channel type         : 1 to 63 \n
 *  - Bits per sample      : 16 \n
 *  - Q format             : 15 \n
 *  - Interleaving         : Deinterleaved Unpacked \n
 *  - Signed/unsigned      : Any }
    @h2xmlm_dataMaxInputPorts    {CAPI_ACD_MAX_PORTS}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {CAPI_ACD_MAX_PORTS}
    @h2xmlm_dataOutputPorts      {OUT=1}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {true}
    @h2xmlm_stackSize            {CAPI_ACD_STACK_SIZE}

    @h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->
   @h2xml_Select        {param_id_acd_static_cfg_t}
   @h2xmlm_InsertParameter
   @h2xml_Select        {param_id_acd_ambience_dynamic_cfg_t}
   @h2xmlm_InsertParameter
   @h2xml_Select        {param_id_detection_engine_register_multi_sound_model_t}
   @h2xmlm_InsertParameter
   @h2xml_Select        {"mla_enable_t"}
   @h2xmlm_InsertParameter

@}                   <-- End of the Module -->
*/
#endif //_ACD_API_H