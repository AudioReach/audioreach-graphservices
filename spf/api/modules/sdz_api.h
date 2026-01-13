/* =========================================================================
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
   ========================================================================= */

#ifndef SDZ_API_H
#define SDZ_API_H

/** @h2xml_title1           {Speaker Diarization (SDZ)}
    @h2xml_title_agile_rev  {Speaker Diarization (SDZ)}
    @h2xml_title_date       {Feb 18, 2025} */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

#define CAPI_SDZ_MAX_INPUT_PORTS  1
#define CAPI_SDZ_MAX_OUTPUT_PORTS 0

/* Stack memory size used by SDZ module library */
#define CAPI_SDZ_STACK_SIZE                 65536

/* Global unique Module ID definition
   Module library is independent of this number, it is defined here for static
   loading purpose only */
#define MODULE_ID_SDZ    0x0702C000

/**
    @h2xmlm_module       {"MODULE_ID_SDZ",
                          MODULE_ID_SDZ}
    @h2xmlm_displayName  {"Speaker Diarization"}
    @h2xmlm_description  {SDZ (Speaker Diarization) module identifies a speaker ID and spits out a unique
                          identification number for further consumption and processing by applications which
                          require the speaker identification from single MIC stream\n

    . This module supports the following parameter IDs:\n
        . #PARAM_ID_SDZ_VERSION\n
        . #PARAM_ID_SDZ_INPUT_THRESHOLD\n
        . #PARAM_ID_SDZ_OUTPUT_CONFIG\n
        . #PARAM_ID_SDZ_FORCE_OUTPUT\n
        . #PARAM_ID_SDZ_MODEL\n
        . #PARAM_ID_SDZ_OUTPUT\n
    \n
    . Supported Input Media Format:      \n
    .           Data Format          : FIXED_POINT \n
    .           fmt_id               : MEDIA_FMT_ID_PCM \n
    .           Sample Rates         : 16000 \n
    .           Number of channels   : 1  \n
    .           Channel type         : C  \n
    .           Bits per sample      : 16 \n
    .           Q format             : Q15 for bps = 16 \n
    .           Interleaving         : Deinterleaved Unpacked \n
    .           Signed/unsigned      : Signed  \n
    }
    @h2xmlm_dataMaxInputPorts   {CAPI_SDZ_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {CAPI_SDZ_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {FALSE}
    @h2xmlm_stackSize           {CAPI_SDZ_STACK_SIZE}
    @h2xmlm_ctrlDynamicPortIntent   { "DAM-SDZ Control" = INTENT_ID_AUDIO_DAM_DETECTION_ENGINE_CTRL,
                                      maxPorts= 1 }
    @h2xmlm_toolPolicy          {Calibration}
    @{                   <-- Start of the Module -->
    @h2xml_Select        {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter

*/

/*  ID of the SDZ version parameter used by MODULE_ID_SDZ.*/
#define PARAM_ID_SDZ_VERSION                            0x08001B08

/*  Structure for the SDZ version parameter of SDZ module. */
typedef struct sdz_version_t sdz_version_t;
/** @h2xmlp_parameter {"PARAM_ID_SDZ_VERSION", PARAM_ID_SDZ_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy {RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_VERSION parameter used by the
    SDZ module.
 */

struct sdz_version_t
{
  uint32_t lib_version_low;
   /**< @h2xmle_description {Lower 32 bits of the 64-bit library version number} */
  uint32_t lib_version_high;
  /**< @h2xmle_description {Higher 32 bits of the 64-bit library version number} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {sdz_version_t}
     @h2xmlm_InsertParameter */

/*  ID of the SDZ input threshold parameter used by MODULE_ID_SDZ.*/
#define PARAM_ID_SDZ_INPUT_THRESHOLD                    0x08001B09

/*  Structure for the input threshold parameter of SDZ module. */
typedef struct param_id_sdz_input_threshold_t param_id_sdz_input_threshold_t;
/** @h2xmlp_parameter   {"PARAM_ID_SDZ_INPUT_THRESHOLD", PARAM_ID_SDZ_INPUT_THRESHOLD}
    @h2xmlp_description {Param to control wakeup threshold for SDZ engine based on input buffering i.e.,
                         to control the frequency at which SDZ engine should be woken up periodically }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_INPUT_THRESHOLD parameter used by the
    SDZ module.
 */
struct param_id_sdz_input_threshold_t
{
    uint32_t buf_duration_ms;
    /**< @h2xmle_description {Duration of input threshold in milli seconds, used to create input buffering and wakeup control.}
         @h2xmle_range       {200..30000} ms
         @h2xmle_default     {200} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {param_id_sdz_input_threshold_t}
     @h2xmlm_InsertParameter */

/*  ID of the SDZ output configuration parameter used by MODULE_ID_SDZ.*/
#define PARAM_ID_SDZ_OUTPUT_CONFIG                      0x08001B0D

/*  Enums defining the mode of output used by param_id_sdz_output_config_t */
typedef enum sdz_output_mode_t
{
    NON_BUFFERED_MODE = 0,                /* Send SDZ engine output immediately. Each buffer shall have one payload
                                             corresponding to a partial/complete segment of speech.
                                             Typical usage : live display of output. */

    BUFFERED_MODE,                        /* Buffer up SDZ engine output based on configured buffer size from client.
                                             Send the event to clients once buffer is full.
                                             Typical usage : save transcription output in background. */
}sdz_output_mode_t;

/*  Structure for the output configuration parameter of SDZ module. */
typedef struct param_id_sdz_output_config_t param_id_sdz_output_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_SDZ_OUTPUT_CONFIG", PARAM_ID_SDZ_OUTPUT_CONFIG}
    @h2xmlp_description {Param to configure required output mode and buffering mode for SDZ engine  }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_OUTPUT_CONFIG parameter used by the
    SDZ module.
 */

struct param_id_sdz_output_config_t
{
    uint32_t output_mode;
    /**< @h2xmle_description {Configuration to specify transcription output mode depending on usecase requirement.
                              NON_BUFFERED_MODE - Output of each SDZ algo process is immediately sent to client.
                              BUFFERED_MODE     - Output of each SDZ algo process is buffered and sent to client intermittently.}
         @h2xmle_default     {NON_BUFFERED_MODE}
         @h2xmle_rangeList   {"NON_BUFFERED_MODE"=0, "BUFFERED_MODE"=1} */
   uint32_t out_buf_size;
    /**< @h2xmle_description {Configuration to specify transcription output buffer size, 0 for NON_BUFFERED output mode.}
         @h2xmle_default     {0}
         @h2xmle_range       {0.. 262144} */
   uint32_t num_bufs;
    /**< @h2xmle_description {Configuration to specify number of output buffers, 0 for NON_BUFFERED_MODE output mode.}
         @h2xmle_default     {1}
         @h2xmle_range       {1.. 16} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {param_id_sdz_output_config_t}
     @h2xmlm_InsertParameter */


/*  ID of the SDZ force output parameter used by MODULE_ID_SDZ.*/
#define PARAM_ID_SDZ_FORCE_OUTPUT                       0x08001B0E

/*  Structure for the force output parameter of SDZ module. */
typedef struct param_id_sdz_force_output_t param_id_sdz_force_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_SDZ_FORCE_OUTPUT", PARAM_ID_SDZ_FORCE_OUTPUT}
    @h2xmlp_description {Forces the SDZ module to produce output event irrespective of configured input threshold and current buffering state}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_FORCE_OUTPUT parameter used by the
    SDZ module.
 */
struct param_id_sdz_force_output_t
{
    uint32_t force_output;
    /**< @h2xmle_description {forces SDZ module to produce output with current data without waiting for further data accumulation.}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {param_id_sdz_force_output_t}
     @h2xmlm_InsertParameter */

/*  ID of the SDZ output event configuration used by MODULE_ID_SDZ.*/
#define EVENT_ID_SDZ_OUTPUT                             0x08001B0A

/* Structure definition for Parameter */
typedef struct event_id_sdz_output_reg_cfg_t event_id_sdz_output_reg_cfg_t;
/** @parameter   {"EVENT_ID_SDZ_OUTPUT",EVENT_ID_SDZ_OUTPUT}
    @description {Event raised by SDZ to the clients; registration and event have differnt payload types}
    @toolPolicy  {NO_SUPPORT}*/

/** ################################ Struct definitions for event registration################### */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the EVENT_ID_SDZ_OUTPUT parameter used by the
    SDZ module.
 */

struct event_id_sdz_output_reg_cfg_t
{
   uint32_t event_payload_type;
   /**< @h2xmle_description {Field to configure event payload type}
                             QUERY     - Client queries the output via getparam upon receiving SDZ output event.
                             INBAND    - SDZ output event has the output payload inband in the event.}
                             DONT_CARE - SDZ output event can be INBAND or QUERY based, flag in event
                                         payload indicates the mode.}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {"QUERY"=0, "INBAND"=1, "DONT_CARE"=2} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** ################################ Struct definitions for raised event ################### */

/*  Structure for the payload of EVENT_ID_SDZ_OUTPUT parameter of SDZ module. */
typedef struct sdz_output_status_t sdz_output_status_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the EVENT_ID_SDZ_OUTPUT parameter used by the
    SDZ module for raising event.
 */

struct sdz_speaker_info_t
{
    uint32_t speaker_id;
   /**< @h2xmle_description  {speaker ID detected by the algorithm}
        @h2xmle_default      {0}
        @h2xmle_range        {0..0xFFFFFFFF} */

   uint32_t start_ts_lsw;
   /**< @h2xmle_description  {Field indicating the least-significant 32 bits of the start timestamp for
                              above speaker id.}
        @h2xmle_default      {0}
        @h2xmle_range        {0..0xFFFFFFFF} */

   uint32_t start_ts_msw;
   /**< @h2xmle_description  {Field indicating the most-significant 32 bits of the start timestamp for
                              above speaker id.}
        @h2xmle_default      {0}
        @h2xmle_range        {0..0xFFFFFFFF} */

   uint32_t end_ts_lsw;
   /**< @h2xmle_description  {Field indicating the least-significant 32 bits of the end timestamp for
                              above speaker id.}
        @h2xmle_default      {0}
        @h2xmle_range        {0..0xFFFFFFFF} */

   uint32_t end_ts_msw;
   /**< @h2xmle_description  {Field indicating the most-significant 32 bits of the end timestamp for
                              above speaker id.}
        @h2xmle_default      {0}
        @h2xmle_range        {0..0xFFFFFFFF} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

struct sdz_output_status_t
{
    uint32_t num_speakers;
    /**< @h2xmle_description  {Field indicating the number of sdz_speaker_info_t present in
                               the speakers_info_list buf}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */

    uint32_t overlap_detected;
    /**< @h2xmle_description  {Field indicating if the overlapping detected in the given inference
                               result.}
         @h2xmle_default      {0}
         @h2xmle_rangeList    {"FALSE"=0, "TRUE"=1} */
#if defined(__H2XML__)
    sdz_speaker_info_t speakers_info_list[0];
    /*@variableArraySize      {num_speakers} */
#endif
};

/*  Structure for the EVENT_ID_SDZ_OUTPUT parameter of SDZ module for raising event */
typedef struct param_id_sdz_output_t event_id_sdz_output_event_t;


/*  ID of the SDZ output get parameter used by MODULE_ID_SDZ.*/
#define PARAM_ID_SDZ_OUTPUT                             0x08001B0C

/*  Structure for the output get parameter of SDZ module. */
typedef struct param_id_sdz_output_t param_id_sdz_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_SDZ_OUTPUT", PARAM_ID_SDZ_OUTPUT}
    @h2xmlp_description {Get Param to query output from the module based on sdz_out_mode in event_id_sdz_output_event_t }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_OUTPUT parameter used by the
    SDZ module.
 */

struct param_id_sdz_output_t
{
    uint32_t event_payload_type;
    /**< @h2xmle_description   {event type of SDZ event.
                                Query = Client will query via getparam upon receiving this event, using the
                                        output_token provided as part of this payload.
                                Inband = SDZ output payload follows inband after the payload_size field }
          @h2xmle_default      {0}
          @h2xmle_rangeList    {"Query"=0, "Inband"=1} */
   uint32_t output_token;
   /**< @h2xmle_description   {Token provided by the SDZ engine corresponding to an output.
                               This is used to query the corresponding output payload.
                               If not configured or invalid, Payload corresponds to next output buffer
                               is sent.}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t num_outputs;
   /**< @h2xmle_description   {Number of outputs of type sdz_output_status_t in the payload }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t payload_size;
   /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                              this size. Payload is variable array of type sdz_output_status_t}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
#if defined(__H2XML__)
   sdz_output_status_t buf[0];
   /*@variableArraySize       {payload_size} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {param_id_sdz_output_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_SDZ_MODEL                              0x08001B0B

/*  Structure for the model parameter of SDZ module. */
typedef struct param_id_sdz_model_t param_id_sdz_model_t;
/** @h2xmlp_parameter           {"PARAM_ID_SDZ_MODEL", PARAM_ID_SDZ_MODEL}
    @h2xmlp_description         {NN Model related parameters}
    @h2xmlp_ToolPolicy          {NO_SUPPORT}
    @h2xmlp_isHwAccel           {FALSE}
    @h2xmlp_isNeuralNetParam    {TRUE}
    @h2xmlp_isOffloaded         {TRUE}
    @h2xmlp_persistType         {Shared}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_SDZ_MODEL parameter used by the
    SDZ module.
 */

struct param_id_sdz_model_t
{
    uint32_t model_align;
    /**< @h2xmle_description {Data Alignment required for the model_data}
         @h2xmle_default     {256}
         @h2xmle_range       {0..8192}
         @h2xmle_group       {SPF}
         @h2xmle_subgroup    {NNVAD}
         @h2xmle_policy      {Advanced} */

    uint32_t model_offset;
    /**< @h2xmle_description {Data offset (bytes) to align the start address of model by model_align}
         @h2xmle_default     {0}
         @h2xmle_range       {0..8191}
         @h2xmle_visibility  {hide}
         @h2xmle_policy      {Basic} */

    uint32_t model_size;
    /**< @h2xmle_description {Size of the model in bytes}
         @h2xmle_default     {0}
         @h2xmle_range       {0x00000000..0xFFFFFFFF}
         @h2xmle_visibility  {hide}
         @h2xmle_policy      {Basic} */
#if defined(__H2XML__)
    uint8_t model[0];
    /**< @h2xmle_description {Model data: The path to the model file on the platform}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField}
         @h2xmle_policy      {Basic} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                  {param_id_sdz_model_t}
     @h2xmlm_InsertParameter */

/** @}                   <-- End of the Module -->*/
#endif /* SDZ_API_H */
