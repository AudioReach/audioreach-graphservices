/*==================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 ==================================================*/

#ifndef ASR_MODULE_CALIBRATION_API_H
#define ASR_MODULE_CALIBRATION_API_H

/** @h2xml_title1           {Adaptive Speech Recognition (ASR)}
    @h2xml_title_agile_rev  {Adaptive Speech Recognition (ASR)}
    @h2xml_title_date       {Feb 26, 2024} */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/* Global unique Module ID definition
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_ASR    0x7001176

/**
    @h2xmlm_module       {"MODULE_ID_ASR",
                          MODULE_ID_ASR}
    @h2xmlm_displayName  {"Adaptive Speech Recognition"}
    @h2xmlm_description  {ID of the ASR module.\n

    . This module supports the following parameter IDs:\n
        . #PARAM_ID_ASR_CONFIG\n
        . #PARAM_ID_ASR_FORCE_OUTPUT\n
        . #PARAM_ID_ASR_INPUT_THRESHOLD\n
        . #PARAM_ID_ASR_OUTPUT_CONFIG\n
        . #PARAM_ID_ASR_OUTPUT\n
    \n
    . Supported Input Media Format:      \n
    .           Data Format          : FIXED_POINT \n
    .           fmt_id               : MEDIA_FMT_ID_PCM \n
    .           Sample Rates         : 16000 \n
    .           Number of channels   : 1  \n
    .           Channel type         : Supported channel mapping based on number of channels is given below.  \n
    .           Bits per sample      : 16 \n
    .           Q format             : Q15 for bps = 16 \n
    .           Interleaving         : Deinterleaved Unpacked \n
    .           Signed/unsigned      : Signed  \n
    \n
    . Supported Channel Mapping based on number of input channels: \n
    .           1:  mono    [C] \n
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
    @h2xmlm_ctrlDynamicPortIntent   { "DAM-ASR Control" = INTENT_ID_AUDIO_DAM_DETECTION_ENGINE_CTRL,
                                      maxPorts= 1 }

    @{                   <-- Start of the Module -->
    @h2xml_Select        {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter

*/


#define ASR_ENPU_RELEASE_VERSION_MAJOR 0x00000001
#define ASR_ENPU_RELEASE_VERSION_MINOR 0x00000000

#define PARAM_ID_ASR_VERSION                      0x08001AA3
/** @h2xmlp_parameter {"PARAM_ID_ASR_VERSION", PARAM_ID_ASR_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy {RTC_READONLY} */

typedef struct asr_version_t asr_version_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asr_version_t
{
  uint32_t lib_version_low;
   /**< @h2xmle_description {Lower 32 bits of the 64-bit library version number}
     @h2xmle_default    {ASR_ENPU_RELEASE_VERSION_MAJOR} */
  uint32_t lib_version_high;
  /**< @h2xmle_description {Higher 32 bits of the 64-bit library version number}
     @h2xmle_default    {ASR_ENPU_RELEASE_VERSION_MINOR} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*
Supported language codes
*/
typedef enum ASR_LANGUAGE_CODE_t{
    en_US=0,
    zh_CN,
    hi_IN,
    es_US,
    ko_KR,
    ja_JP,
    language_code_end_1
}ASR_LANGUAGE_CODE_t;

/*   @h2xml_Select                     {asr_version_t}
     @h2xmlm_InsertParameter */

/*  ID of the ASR configuration parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_CONFIG                       0x08001AA4

/*  Structure for the configuration parameters of ASR module. */
typedef struct param_id_asr_config_t param_id_asr_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_CONFIG", PARAM_ID_ASR_CONFIG}
    @h2xmlp_description {Configures the ASR module}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_CONFIG parameter used by the
 ASR module.
 */
struct param_id_asr_config_t
{
    uint32_t input_language_code;               // input language code, refer enum ASR_LANGUAGE_CODE_t
    /**< @h2xmle_description {Code to specify ASR input language.}
         @h2xmle_rangeList   {"en_US"=en_US;"zh_CN"=zh_CN;"hi_IN"=hi_IN;"es_US"=es_US;"ko_KR"=ko_KR;"ja_JP"=ja_JP;"language_code_end"=language_code_end_1}
         @h2xmle_default     {en_US} */
    uint32_t output_language_code;              // output language code, refer enum ASR_LANGUAGE_CODE_t
    /**< @h2xmle_description {Code to specify ASR output language.}
         @h2xmle_rangeList   {"en_US"=en_US;"zh_CN"=zh_CN;"hi_IN"=hi_IN;"es_US"=es_US;"ko_KR"=ko_KR;"ja_JP"=ja_JP;"language_code_end"=language_code_end_1}
         @h2xmle_default     {en_US} */
    uint32_t enable_language_detection;         // language detection switch enable or disable flag
    /**< @h2xmle_description {Flag to enable or disable the language detection switch.}
         @h2xmle_rangeList   {enabled=1;disabled=0}
         @h2xmle_default     {0} */
    uint32_t enable_translation;                // translation switch enable or disable flag
    /**< @h2xmle_description {Flag to enable or disable the translation switch.}
         @h2xmle_rangeList   {enabled=1;disabled=0}
         @h2xmle_default     {0} */
    uint32_t enable_continuous_mode;            // continuous mode enable or disable flag
    /**< @h2xmle_description {Flag to enable or disable the continuous mode.}
         @h2xmle_rangeList   {enabled=1;disabled=0}
         @h2xmle_default     {0} */
    uint32_t enable_partial_transcription;      // partial transcription switch enable or disable flag
    /**< @h2xmle_description {Flag to enable or disable the partial transcription switch.}
         @h2xmle_rangeList   {enabled=1;disabled=0}
         @h2xmle_default     {0} */
    uint32_t threshold;
    /**< @h2xmle_description {Minimum confidence value (threshold) needed by the ASR to generate transcription.}
         @h2xmle_range       {0..100}
         @h2xmle_default     {50} */
    uint32_t timeout_duration;                  // ASR processing timeout (in ms)
    /**< @h2xmle_description {ASR processing timeout (ASR will stop if cumulative buffer duration exceeds this value, even if speech continues), in ms.}
         @h2xmle_range       {0..30000} ms
         @h2xmle_default     {10000} */
    uint32_t vad_hangover_duration;             // "No speech" duration needed before determining speech has ended (in ms)
    /**< @h2xmle_description {'No speech' duration needed before determining speech has ended, in ms.}
         @h2xmle_range       {0..5000} ms
         @h2xmle_default     {1000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/*   @h2xml_Select                    {param_id_asr_config_t}
     @h2xmlm_InsertParameter */


/*  ID of the ASR input threshold parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_INPUT_THRESHOLD                   0x08001AA5

/*  Structure for the input threshold parameter of ASR module. */
typedef struct param_id_asr_input_threshold_t param_id_asr_input_threshold_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_INPUT_THRESHOLD", PARAM_ID_ASR_INPUT_THRESHOLD}
    @h2xmlp_description {Param to control wakeup threshold for ASR engine based on input buffering i.e., to control the frequency or resolution at which ASR engine should be woken up periodically }
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_INPUT_THRESHOLD parameter used by the
 ASR module.
 */
struct param_id_asr_input_threshold_t
{
    uint32_t buf_duration_ms;             // input threshold in milli seconds
    /**< @h2xmle_description {Duration of input threshold in milli seconds, used to create input buffering and wakeup control.}
         @h2xmle_range       {100..20000} ms
         @h2xmle_default     {3000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                 {param_id_asr_input_threshold_t}
     @h2xmlm_InsertParameter */


/*  ID of the ASR force output parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_FORCE_OUTPUT                      0x08001AA6

/*  Structure for the force output parameter of ASR module. */
typedef struct param_id_asr_force_output_t param_id_asr_force_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_FORCE_OUTPUT", PARAM_ID_ASR_FORCE_OUTPUT}
    @h2xmlp_description {Forces the ASR module to produce output event irrespective of configured input threshold}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_FORCE_OUTPUT parameter used by the
 ASR module.
 */
struct param_id_asr_force_output_t
{
    uint32_t force_output;             // forces ASR to process and produce output
    /**< @h2xmle_description {forces ASR module to produce output with current data without waiting for further data accumulation.}
         @h2xmle_default     {1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*  Payload of the PARAM_ID_ASR_OUTPUT_CONFIG parameter used by the
 ASR module.
 */

typedef enum asr_output_mode_t
{
     NON_BUFFERED = 0,   /* Send ASR engine output immediately. Each buffer shall have one payload
                          corresponding to a partial/complete segment of speech.
                          Typical usage : live display of output. */

     BUFFERED,           /* Buffer up ASR engine output based on configured buffer size from client.
                         Send the event to clients once buffer is full.
                         Typical usage : save transcription output in background. */

     LOGGER,             /* Buffer up ASR engine output based on configured buffer size from client.
                         Send the output when the client queries it.
                         Typical usage : save transcription output in a circular buffer. */

     TS_NON_BUFFERED,    /* Send ASR engine output with timestamps immediately. Each buffer shall have one payload
                          corresponding to a partial/complete segment of speech.
                          Typical usage : live display of output. */

     TS_BUFFERED,        /* Buffer up ASR engine output with timestamps based on configured buffer size from client.
                         Send the event to clients once buffer is full.
                         Typical usage : save transcription output in background. */

     TS_LOGGER           /* Buffer up ASR engine output with timestamps based on configured buffer size from client.
                         Send the output when the client queries it.
                         Typical usage : save transcription output in a circular buffer. */
}asr_output_mode_t;

/*   @h2xml_Select                 {param_id_asr_force_output_t}
     @h2xmlm_InsertParameter */

/*  ID of the ASR output configuration parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_OUTPUT_CONFIG                          0x08001AA7

/*  Structure for the output configuration parameter of ASR module. */
typedef struct param_id_asr_output_config_t param_id_asr_output_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_OUTPUT_CONFIG", PARAM_ID_ASR_OUTPUT_CONFIG}
    @h2xmlp_description {Param to configure required output mode and buffering for ASR engine  }
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"



struct param_id_asr_output_config_t
{
    uint32_t output_mode;               // mode of ASR output data requested by application
    /**< @h2xmle_description {Configuration to specify transcription output mode depending on usecase requirement.
                              NON_BUFFERED    - Output of each ASR algo process is immediately sent to client.
                              BUFFERED        - Output of each ASR algo process is buffered and sent to client intermittently.
                              LOGGER          - Output of each ASR algo process is stored and sent to client on demand.
                              TS_NON_BUFFERED - Output of each ASR algo process is immediately sent to client with timestamps.
                              TS_BUFFERED     - Output of each ASR algo process is buffered and sent to client intermittently with timestamps.
                              TS_LOGGER       - Output of each ASR algo process is stored and sent to client on demand with timestamps.}
         @h2xmle_default     {NON_BUFFERED}
         @h2xmle_rangeList   {"NON_BUFFERED"=0, "BUFFERED"=1, "LOGGER"=2, "TS_NON_BUFFERED"=3, "TS_BUFFERED"=4, "TS_LOGGER"=5} */
   uint32_t out_buf_size;      // size in bytes of buffer to use in different output modes, primarily in buffered mode
    /**< @h2xmle_description {Configuration to specify transcription output buffer size depending on usecase requirement. }
         @h2xmle_default     {} // ASR engine controlled default if not configured
         @h2xmle_range       {0.. 262144} */
 uint32_t num_bufs;               // Number of buffers
    /**< @h2xmle_description {Configuration to specify number of output buffers . }
         @h2xmle_default     {1} // ASR engine controlled default if not configured
         @h2xmle_range       {1.. 16} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                 {param_id_asr_input_threshold_t}
     @h2xmlm_InsertParameter */


#define EVENT_ID_ASR_OUTPUT                  0x08001AA8

/* Structure definition for Parameter */
/** @parameter   {"EVENT_ID_ASR_OUTPUT",EVENT_ID_ASR_OUTPUT}
    @description {Event raised by ASR to the clients; registration and event have differnt payload types}
    @toolPolicy  {NO_SUPPORT}*/

/** ################################ Struct definitions for event registration################### */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_id_asr_output_reg_cfg_t
{
   uint32_t event_payload_type;
   /**< @h2xmle_description {Field to configure event payload type}
                             QUERY   - Client queries the output via getparam upon receiving ASR output event.
                             INBAND  - ASR output event has the output payload inband in the event.}
                             OPTIMAL - ASR output event can be INBAND or QUERY based, flag in event
                                       payload indicates the mode.}
        @h2xmle_default     {0}
        @h2xmle_rangeList   {"QUERY"=0, "INBAND"=1, "OPTIMAL"=2} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_asr_output_reg_cfg_t event_id_asr_output_reg_cfg_t;

/** ################################ Struct definitions for raised event ################### */


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/* Maximum transcription text size of ASR output in one process call */
#define MAX_TRANSCRIPTION_CHAR_SIZE 1024

enum asr_output_status_value
{
    ASR_SUCCESS = 0,
    ASR_FAIL    = 1,
    ASR_TIMEOUT = 12,
};

struct asr_output_status_t
{
    uint32_t status;
   /**< @h2xmle_description  {Status of ASR output in this payload}
         @h2xmle_default      {0}
         @h2xmle_rangeList    {"ASR_SUCCESS"=0,"ASR_FAIL"=1,"ASR_TIMEOUT"=12} */

   uint32_t is_final;
   /**< @h2xmle_description  {Field indicating payload is partial output of ASR or complete}
         @h2xmle_default      {TRUE}
         @h2xmle_rangeList    {"TRUE"=1, "FALSE"=0} */

   uint32_t confidence;
   /**< @h2xmle_description  {Field indicating confidence level of output} */

   uint32_t text_size;
   /**< @h2xmle_description  {Field indicating size of valid text including NULL Char } */

   uint8_t text[MAX_TRANSCRIPTION_CHAR_SIZE];
   /**< @h2xmle_description  {ASR output text } */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct asr_output_status_t asr_output_status_t;

#define PARAM_ID_ASR_LLM                  0x08001AA9

typedef struct asr_model_param_t asr_model_param_t;
/** @h2xmlp_parameter       {"PARAM_ID_ASR_LLM", PARAM_ID_ASR_LLM}
	@h2xmlp_description  {NN Model related parameters}
    @h2xmlp_ToolPolicy 	 {CALIBRATION}
    @h2xmlp_isHwAccel {FALSE}
	@h2xmlp_isNeuralNetParam	{TRUE}
	@h2xmlp_isOffloaded		{TRUE}
	@h2xmlp_persistType  { Shared }
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct asr_model_param_t
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


#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*TODO: move it to */
/* Event config to provide the info of getparam vs inband vs both */
struct event_id_asr_output_event_t
{
   uint32_t event_payload_type;
   /**< @h2xmle_description   {Event payload type. Default mode is Query.
                               QUERY = Client will query via getparam upon receiving this event, using the
                                         output_token provided as part of this payload.
                               Inband = ASR output payload follows inband after the payload_size field }
         @h2xmle_default      {0}
         @h2xmle_rangeList    {"Query"=0, "Inband"=1} */
   uint32_t output_token;
   /**< @h2xmle_description   {Token provided by the AsR engine corresponding to an output.
                               This can be used by clients to query the payload param in 'Getparam' mode}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t num_outputs;
   /**< @h2xmle_description   {Number of outputs of type asr_output_status_t in the payload }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t payload_size;
   /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                              this size. Payload is variable array of type asr_output_status_t .
                              Size '0' indicates this is an event generated without any valid output,
                              for example : in response to a force output param set by client. }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
#if defined(__H2XML__)
   asr_output_status_t transcription_payload[0];
   /*@variableArraySize {payload_size} */
#endif

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_asr_output_event_t event_id_asr_output_event_t;


/*  ID of the ASR output get parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_OUTPUT 0x08001AAA

/*  Structure for the output get parameter of ASR module. */
typedef struct param_id_asr_output_t param_id_asr_output_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_OUTPUT", PARAM_ID_ASR_OUTPUT}
    @h2xmlp_description {Get Param to query output from the module based on asr_out_mode in event_id_asr_output_event_t }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_OUTPUT parameter used by the
 ASR module.
 */

struct param_id_asr_output_t
{
   uint32_t output_token;
   /**< @h2xmle_description   {Token provided by the ASR engine corresponding to an output.
                               This can be used by clients to query the corresponding payload.
                               If not configured or invalid, Payload corresponds to output buffers
                               in sequential order as produced by ASR engine.}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t num_outputs;
   /**< @h2xmle_description   {Number of outputs of type asr_output_status_t in the payload }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t payload_size;
   /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                              this size. Payload is variable array of type asr_output_status_t .
                              Size '0' indicates this is an event generated without any valid output,
                              for example : in response to a force output param set by client. }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
#if defined(__H2XML__)
   asr_output_status_t transcription_payload[0];
   /*@variableArraySize {payload_size} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                 {param_id_asr_output_t}
     @h2xmlm_InsertParameter */

/*  ID of the ASR input threshold parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_ALGO_MAX_INFERENCE_TIME                  0x08001B06

/*  Structure for the input threshold parameter of ASR module. */
typedef struct param_id_asr_algo_max_inference_time_t param_id_asr_algo_max_inference_time_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_ALGO_MAX_INFERENCE_TIME", PARAM_ID_ASR_ALGO_MAX_INFERENCE_TIME}
    @h2xmlp_description {Param to control input input buffers  size in partial output mode, to prevent the PCM data overflow. It should be set based on the worst enpu inference time.}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_ALGO_MAX_INFERENCE_TIME parameter used by the
 ASR module.
 */
struct param_id_asr_algo_max_inference_time_t
{
    uint32_t worstcase_time_ms;    // Max inference time taken by algo to process the input threshold amount worth of data.
    /**< @h2xmle_description {Maximum duration to process the input data by the algorithm for one inference in ms.
          This is taken as input as this can vary based on model and enpu capability etc., hence tuning this for memory requirements based on usecase needs external input.}
         @h2xmle_range       {80..30000} ms
         @h2xmle_default     {5000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                   {param_id_asr_algo_max_inference_time_t}
     @h2xmlm_InsertParameter */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
#define MAX_WORD_SIZE 28

struct asr_word_status_t
{
   uint32_t word_confidence;
   /**< @h2xmle_description  {Field indicating the confidence level of word detected by the algorithm between 0 to 100} */

   uint32_t word_size;
   /**< @h2xmle_description  {Field indicating the number of characters present in the word. (Not including the NULL character)} */

   uint8_t word[MAX_WORD_SIZE];
   /**< @h2xmle_description  {Field indicating the array of characters (in a word) detected by the algorithm. MAX_WORD_SIZE to be a multiple of 4. Client should read only word_size from this array for the actual word which does not include any null term char} */

   uint32_t word_start_time_ms_lsw;
   /**< @h2xmle_description  {Field indicating word start timestamp in ms least significant 32 bits.} */

   uint32_t word_start_time_ms_msw;
   /**< @h2xmle_description  {Field indicating word start timestamp in ms most significant 32 bits.} */

   uint32_t word_end_time_ms_lsw;
   /**< @h2xmle_description  {Field indicating word end timestamp in ms least significant 32 bits.} */

   uint32_t word_end_time_ms_msw;
   /**< @h2xmle_description  {Field indicating word end timestamp in ms most significant 32 bits.} */
};

struct asr_output_status_v2_t
{
    uint32_t status;
   /**< @h2xmle_description  {Status of ASR output in this payload}
         @h2xmle_default      {0}
         @h2xmle_rangeList    {"ASR_SUCCESS"=0,"ASR_FAIL"=1} */

   uint32_t is_final;
   /**< @h2xmle_description  {Field indicating payload is partial output of ASR or complete}
         @h2xmle_default      {TRUE}
         @h2xmle_rangeList    {"TRUE"=1, "FALSE"=0} */

   uint32_t confidence;
   /**< @h2xmle_description  {Field indicating confidence level of output} */

   uint32_t text_size;
   /**< @h2xmle_description  {Field indicating size of valid text including NULL Char } */

   uint8_t text[MAX_TRANSCRIPTION_CHAR_SIZE];
   /**< @h2xmle_description  {ASR output text } */

   uint32_t segment_start_time_ms_lsw;
   /**< @h2xmle_description  {Field indicating transcription start timestamp in ms least significant 32 bits.} */

   uint32_t segment_start_time_ms_msw;
   /**< @h2xmle_description  {Field indicating transcription start timestamp in ms most significant 32 bits.} */

   uint32_t segment_end_time_ms_lsw;
   /**< @h2xmle_description  {Field indicating transcription end timestamp in ms least significant 32 bits.} */

   uint32_t segment_end_time_ms_msw;
   /**< @h2xmle_description  {Field indicating transcription end timestamp in ms most significant 32 bits.} */

   uint32_t num_words;
   /**< @h2xmle_description  {Field indicating num of words produced by ASR engine. this is variable payload based on num_words field above.} */

 #if defined(__H2XML__)
   asr_word_status_t words[0];
   /**< @h2xmle_description  {Field indicating the ptr to the words list of words produced by ASR engine.} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct asr_output_status_v2_t asr_output_status_v2_t;


/*  ID of the ASR output get parameter used by MODULE_ID_ASR.*/
#define PARAM_ID_ASR_OUTPUT_V2 0x08001B04

/*  Structure for the output get parameter of ASR module. */
typedef struct param_id_asr_output_v2_t param_id_asr_output_v2_t;
/** @h2xmlp_parameter   {"PARAM_ID_ASR_OUTPUT_V2", PARAM_ID_ASR_OUTPUT_V2}
    @h2xmlp_description {Get Param to query output from the module based on asr_out_mode in event_id_asr_output_event_t }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_ASR_OUTPUT_V2 parameter used by the
 ASR module.
 */

struct param_id_asr_output_v2_t
{
   uint32_t output_token;
   /**< @h2xmle_description   {Token provided by the ASR engine corresponding to an output.
                               This can be used by clients to query the corresponding payload.
                               If not configured or invalid, Payload corresponds to output buffers
                               in sequential order as produced by ASR engine.}
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t num_outputs;
   /**< @h2xmle_description   {Number of outputs of type asr_output_status_v2_t in the payload }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
   uint32_t payload_size;
   /**< @h2xmle_description   {Payload size in bytes. Following this field is the payload of
                              this size. Payload is variable array of type asr_output_status_v2_t .
                              Size '0' indicates this is an event generated without any valid output,
                              for example : in response to a force output param set by client. }
         @h2xmle_default      {0}
         @h2xmle_range        {0..0xFFFFFFFF} */
#if defined(__H2XML__)
   asr_output_status_v2_t transcription_payload[0];
   /*@variableArraySize {payload_size} */
#endif
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                    {param_id_asr_output_v2_t}
     @h2xmlm_InsertParameter */

/** @}                   <-- End of the Module -->*/
#endif /* ASR_MODULE_CALIBRATION_API_H */
