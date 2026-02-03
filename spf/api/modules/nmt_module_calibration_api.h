/* =========================================================================
   Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
   SPDX-License-Identifier: BSD-3-Clause
   ========================================================================= */

#ifndef NMT_MODULE_CALIBRATION_API_H
#define NMT_MODULE_CALIBRATION_API_H

/** @h2xml_title1           {Neural Machine Translation (NMT)}
    @h2xml_title_agile_rev  {Neural Machine Translation (NMT)}
    @h2xml_title_date       {Dec 20, 2024} */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/* Global unique Module ID definition
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_NMT    0x0702C002

/**
    @h2xmlm_module       {"MODULE_ID_NMT",
                          MODULE_ID_NMT}
    @h2xmlm_displayName  {"Neural Machine Translation"}
    @h2xmlm_description  {ID of the NMT module.\n

    . This module supports the following parameter IDs:\n
        . #PARAM_ID_NMT_CONFIG\n
        . #PARAM_ID_NMT_VERSION\n
        . #PARAM_ID_NMT_MODEL\n
        . #PARAM_ID_NMT_FORCE_OUTPUT\n
        . #PARAM_ID_NMT_OUTPUT_CONFIG\n
        . #PARAM_ID_NMT_OUTPUT\n
    \n
    . Supported Input Media Format:      \n
    .           Data Format          : CAPI_RAW_COMPRESSED \n
    .           fmt_id               : MEDIA_FMT_ID_ASR \n
    \n
   }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataOutputPorts     {OUT=1}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}

    @{                   <-- Start of the Module -->


*/

#define NMT_NPU_RELEASE_VERSION_MAJOR 0x00000001
#define NMT_NPU_RELEASE_VERSION_MINOR 0x00000000

#define PARAM_ID_NMT_VERSION                      0x08001B2C
/** @h2xmlp_parameter {"PARAM_ID_NMT_VERSION", PARAM_ID_NMT_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy {RTC_READONLY} */

typedef struct nmt_version_t nmt_version_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct nmt_version_t
{
  uint32_t lib_version_low;
   /**< @h2xmle_description {Lower 32 bits of the 64-bit library version number}
     @h2xmle_default    {NMT_NPU_RELEASE_VERSION_MAJOR} */
  uint32_t lib_version_high;
  /**< @h2xmle_description {Higher 32 bits of the 64-bit library version number}
     @h2xmle_default    {NMT_NPU_RELEASE_VERSION_MINOR} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select               {nmt_version_t}
     @h2xmlm_InsertParameter */

/*
 * Supported language codes
 */
namespace NMT {
    typedef enum NMT_LANGUAGE_CODE_t {
        en_US = 0,
        zh_CN,
        hi_IN,
        es_US,
        ko_KR,
        ja_JP,
        language_code_end_1 = 0xFFFFFFFF
    } NMT_LANGUAGE_CODE_t;
}
/*  ID of the NMT configuration parameter used by MODULE_ID_NMT.*/
#define PARAM_ID_NMT_CONFIG                       0x08001B2B

/*  Structure for the configuration parameters of NMT module. */
typedef struct param_id_nmt_config_t param_id_nmt_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_NMT_CONFIG", PARAM_ID_NMT_CONFIG}
    @h2xmlp_description {Configures the NMT module}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct param_id_nmt_config_t
{
    uint32_t input_language_code;  // specify language of input text segment.
    /**< @h2xmle_description {Code to specify NMT input language.}
         @h2xmle_rangeList   {"en_US"=en_US;"zh_CN"=zh_CN;"hi_IN"=hi_IN;"es_US"=es_US;"ko_KR"=ko_KR;"ja_JP"=ja_JP;"language_code_end"=language_code_end_1}
         @h2xmle_default     {en_US} */
    uint32_t output_language_code; // Specify language of output text segment.
    /**< @h2xmle_description {Code to specify NMT output language.}
         @h2xmle_rangeList   {"en_US"=en_US;"zh_CN"=zh_CN;"hi_IN"=hi_IN;"es_US"=es_US;"ko_KR"=ko_KR;"ja_JP"=ja_JP;"language_code_end"=language_code_end_1}
         @h2xmle_default     {en_US} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select           {param_id_nmt_config_t}
     @h2xmlm_InsertParameter */

namespace NMT{
    typedef enum nmt_output_mode_t
    {
        NON_BUFFERED = 0,     /* Send NMT engine output immediately. Each buffer shall have one payload
                                 corresponding to a partial/complete segment of speech.
                                 Typical usage : live display of output. */
        BUFFERED,             /* Buffer up NMT engine output based on configured buffer size from client.
                                 Send the event to clients once buffer is full.
                                 Typical usage : save transcription output in background. */
    } nmt_output_mode_t;
}
/*  ID of the NMT output configuration parameter used by MODULE_ID_NMT.*/
#define PARAM_ID_NMT_OUTPUT_CONFIG                          0x08001B80

/*  Structure for the output configuration parameter of NMT module. */
typedef struct param_id_nmt_output_config_t param_id_nmt_output_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_NMT_OUTPUT_CONFIG", PARAM_ID_NMT_OUTPUT_CONFIG}
    @h2xmlp_description {Param to configure required output mode and buffering for NMT engine  }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_NMT_OUTPUT_CONFIG parameter used by the NMT module.
 */
struct param_id_nmt_output_config_t
{
    uint32_t output_mode;    // mode of NMT output data requested by application
    /**< @h2xmle_description {Configuration to specify transcription output mode depending on usecase requirement.
                              NON_BUFFERED - Output of each NMT algo process is immediately sent to client.
                              BUFFERED     - Output of each NMT algo process is buffered and sent to client intermittently.}
         @h2xmle_default     {NON_BUFFERED}
         @h2xmle_rangeList   {"NON_BUFFERED"=0, "BUFFERED"=1} */

    uint32_t out_buf_size;   // size in bytes of buffer to use in different output modes, primarily in buffered mode
    /**< @h2xmle_description {Configuration to specify transcription output buffer size depending on usecase requirement.}
         @h2xmle_default     {3072} // NMT engine controlled default if not configured
         @h2xmle_range       {3072.. 262144} */

    uint32_t num_bufs;       // Number of buffers
    /**< @h2xmle_description {Configuration to specify number of output buffers.}
         @h2xmle_default     {1} // NMT engine controlled default if not configured
         @h2xmle_range       {1.. 16} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Maximum transcription text size of NMT output in one process call */
#define MAX_TRANSCRIPTION_CHAR_SIZE 1024

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct nmt_output_status_t
{
    uint32_t status;
    /**<@h2xmle_description  {Status of NMT output in this payload}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"NMT_SUCCESS"=0,"NMT_FAIL"=1} */

    uint32_t is_final;
    /**<@h2xmle_description  {Field indicating payload is partial output of NMT or complete}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"TRUE"=1, "FALSE"=0} */

    uint32_t segment_start_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us least significant 32 bits.} */

    uint32_t segment_start_time_us_msw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us most significant 32 bits.} */

    uint32_t segment_end_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us least significant 32 bits.} */

    uint32_t segment_end_time_us_msw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us most significant 32 bits.} */

    uint32_t output_text_size;
    /**< @h2xmle_description  {Field indicating size of valid output text including NULL Char } */

    uint8_t output_text[MAX_TRANSCRIPTION_CHAR_SIZE];
    /**< @h2xmle_description  {NMT output text } */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct nmt_output_status_t nmt_output_status_t;

/*   @h2xml_Select      {nmt_output_status_t}
     @h2xmlm_InsertParameter */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct nmt_input_status_t
{
    uint32_t status;
    /**<@h2xmle_description  {Status of NMT output in this payload}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"NMT_SUCCESS"=0,"NMT_FAIL"=1} */

    uint32_t is_final;
    /**<@h2xmle_description  {Field indicating payload is partial output of NMT or complete}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"TRUE"=1, "FALSE"=0} */

    uint32_t segment_start_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us least significant 32 bits.} */

    uint32_t segment_start_time_us_msw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us most significant 32 bits.} */

    uint32_t segment_end_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us least significant 32 bits.} */

    uint32_t segment_end_time_us_msw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us most significant 32 bits.} */

    uint32_t input_text_size;
    /**< @h2xmle_description  {Field indicating size of valid input text including NULL Char } */

    uint8_t input_text[MAX_TRANSCRIPTION_CHAR_SIZE];
    /**< @h2xmle_description  {NMT input text } */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct nmt_input_status_t nmt_input_status_t;

/*   @h2xml_Select      {nmt_input_status_t}
     @h2xmlm_InsertParameter */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

struct nmt_io_status_t
{
    uint32_t status;
    /**< @h2xmle_description {Status of NMT output in this payload}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"NMT_SUCCESS"=0,"NMT_FAIL"=1} */

    uint32_t is_final;
    /**<@h2xmle_description  {Field indicating payload is partial output of NMT or complete}
        @h2xmle_default      {0}
        @h2xmle_rangeList    {"TRUE"=1, "FALSE"=0} */

    uint32_t segment_start_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us least significant 32 bits.} */

    uint32_t segment_start_time_us_msw;
    /**< @h2xmle_description  {Field indicating word start timestamp in us most significant 32 bits.} */

    uint32_t segment_end_time_us_lsw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us least significant 32 bits.} */

    uint32_t segment_end_time_us_msw;
    /**< @h2xmle_description  {Field indicating word end timestamp in us most significant 32 bits.} */

    uint32_t output_text_size;
    /**< @h2xmle_description  {Field indicating size of valid output text including NULL Char } */

    uint8_t output_text[MAX_TRANSCRIPTION_CHAR_SIZE];
    /**< @h2xmle_description  {NMT output text } */

    uint32_t input_text_size;
    /**< @h2xmle_description  {Field indicating size of valid input text including NULL Char } */

    uint8_t input_text[MAX_TRANSCRIPTION_CHAR_SIZE];
    /**< @h2xmle_description  {NMT input text } */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct nmt_io_status_t nmt_io_status_t;

/*   @h2xml_Select      {nmt_io_status_t}
     @h2xmlm_InsertParameter */


/*  ID of the NMT output get parameter used by MODULE_ID_NMT.*/
#define PARAM_ID_NMT_OUTPUT 0x08001B81

/*  Structure for the output get parameter of NMT module. */
typedef struct param_id_nmt_output_t param_id_nmt_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_NMT_OUTPUT", PARAM_ID_NMT_OUTPUT}
    @h2xmlp_description {Get Param to query input/output from the module based on event_payload_type in event_id_nmt_event_t}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_NMT_OUTPUT parameter used by the NMT module.
 */
struct param_id_nmt_output_t
{
    uint32_t token;
    /**< @h2xmle_description   {Token provided by the NMT engine corresponding to an output.
                                This can be used by clients to query the corresponding payload.
                                If not configured or invalid, Payload corresponds to output buffers
                                in sequential order as produced by NMT engine.Dummy token (0x7F7F7F7F)
                                is reserved for FORCE_OUTPUT scenario where output buffer doesn’t
                                have valid content but must raise event to client.}
         @h2xmle_default       {1}
         @h2xmle_range         {1..0xFFFFFFFF} */
    uint32_t num_outputs;
    /**< @h2xmle_description   {Number of buffers of type nmt_output_status_t, nmt_input_status_t or nmt_io_status_t in the payload }
         @h2xmle_default       {0}
         @h2xmle_range         {0..0xFFFFFFFF} */
    uint32_t payload_size;
    /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                                this size. Payload is variable array of type nmt_io_status_t .
                                Size '0' indicates this is an event generated without any valid input/output,
                                for example : in response to a force output param set by client. }
         @h2xmle_default       {0}
         @h2xmle_range         {0..0xFFFFFFFF} */
#if defined(__H2XML__)
    nmt_io_status_t transcription_payload[0];
   /*@variableArraySize {payload_size} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select             {param_id_nmt_output_t}
     @h2xmlm_InsertParameter */


/*  ID of the NMT force output parameter used by MODULE_ID_NMT.*/
#define PARAM_ID_NMT_FORCE_OUTPUT                      0x08001B2E

/*  Structure for the force output parameter of NMT module. */
typedef struct param_id_nmt_force_output_t param_id_nmt_force_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_NMT_FORCE_OUTPUT", PARAM_ID_NMT_FORCE_OUTPUT}
    @h2xmlp_description {Forces the NMT module to produce output event irrespective of configured input threshold}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_NMT_FORCE_OUTPUT parameter used by the NMT module.
 */
struct param_id_nmt_force_output_t
{
    uint32_t force_output;     // Force NMT to process and produce output
    /**< @h2xmle_description   {force NMT module to produce output with current data without waiting for further data accumulation.}
         @h2xmle_default       {1}
         @h2xmle_range         {0..1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select             {param_id_nmt_force_output_t}
     @h2xmlm_InsertParameter */


#define EVENT_ID_NMT_STATUS                  0x08001B82

/* Structure definition for Parameter */
/** @parameter   {"EVENT_ID_NMT_STATUS", EVENT_ID_NMT_STATUS}
    @description {Event raised by NMT to the clients; registration and event have different payload types}
    @toolPolicy  {NO_SUPPORT}*/

/** ################################ Struct definitions for event registration################### */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_id_nmt_reg_cfg_t
{
    uint32_t event_payload_type;
    /**< @h2xmle_description {Field to configure event payload type
                              QUERY   - Client queries the input/output via getparam upon receiving NMT event.
                              INBAND  - NMT event has the payload inband in the event.
                              OPTIMAL - NMT event can be INBAND or QUERY based, flag in event
                                        payload indicates the mode.}
         @h2xmle_default     {0}
         @h2xmle_rangeList   {"QUERY"=0, "INBAND"=1, "OPTIMAL"=2} */

    uint32_t event_text_type;
    /**< @h2xmle_description {Field to configure event text type
                              OUT   - event payload contains output text only.
                              IN    - event payload contains input text only.
                              INOUT - event payload contains combined input and output text.}
         @h2xmle_default     {2}
         @h2xmle_rangeList   {"OUT"=0, "IN"=1, "INOUT"=2} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_nmt_reg_cfg_t event_id_nmt_reg_cfg_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/* Event config to provide the info of getparam vs inband vs both */
struct event_id_nmt_event_t
{
    uint32_t event_payload_type;
    /**< @h2xmle_description   {Event payload type. Default mode is Query.
                                QUERY  = Client will query via getparam upon receiving this event, using the
                                         output_token provided as part of this payload.
                                Inband = NMT output payload follows inband after the payload_size field }
         @h2xmle_default       {0}
         @h2xmle_rangeList     {"QUERY"=0, "INBAND"=1} */
    uint32_t event_text_type;
    /**< @h2xmle_description   {Event text type. Default type is OUT.
                                OUT   - event payload contains output text only.
                                IN    - event payload contains input text only.
                                INOUT - event payload contains combined input and output text.}
         @h2xmle_default       {2}
         @h2xmle_rangeList     {"OUT"=0, "IN"=1, "INOUT"=2} */
    uint32_t token;
    /**< @h2xmle_description   {Token provided by the NMT engine corresponding to an output.
                                This can be used by clients to query the payload param in 'QUERY' mode.
                                Dummy token (0x7F7F7F7F) is reserved for FORCE_OUTPUT scenario where
                                output buffer doesn’t have valid content but must raise event to client.}
         @h2xmle_default       {1}
         @h2xmle_range         {1..0xFFFFFFFF} */
    uint32_t num_outputs;
    /**< @h2xmle_description   {Number of buffers of type nmt_ouput_status_t, nmt_input_status_t or nmt_io_status_t in the payload }
         @h2xmle_default       {0}
         @h2xmle_range         {0..0xFFFFFFFF} */
    uint32_t payload_size;
    /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                                this size. Payload is variable array of type nmt_io_status_t .
                                Size '0' indicates this is an event generated without any valid output,
                                for example : in response to a force output param set by client. }
         @h2xmle_default       {0}
         @h2xmle_range         {0..0xFFFFFFFF} */
#if defined(__H2XML__)
    nmt_io_status_t transcription_payload[0];
    /*@variableArraySize {payload_size} */
#endif

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_nmt_event_t event_id_nmt_event_t;

/*   @h2xml_Select             {nmt_model_param_t}
     @h2xmlm_InsertParameter */
#define PARAM_ID_NMT_MODEL                  0x08001B2D

typedef struct nmt_model_param_t nmt_model_param_t;

/** @h2xmlp_parameter        {"PARAM_ID_NMT_MODEL", PARAM_ID_NMT_MODEL}
    @h2xmlp_description      {NN Model related parameters}
    @h2xmlp_ToolPolicy       {CALIBRATION}
    @h2xmlp_isHwAccel        {FALSE}
    @h2xmlp_isNeuralNetParam {TRUE}
    @h2xmlp_isOffloaded      {TRUE}
    @h2xmlp_persistType      {Shared}
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct nmt_model_param_t
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

    uint8_t model[0];
    /**< @h2xmle_description {Model data: The path to the model file on the platform}
         @h2xmle_elementType {rawData}
         @h2xmle_displayType {stringField}
         @h2xmle_policy      {Basic} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/** @}                   <-- End of the Module -->*/
#endif /* NMT_MODULE_CALIBRATION_API_H */
