/*
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TTS_MODULE_CALIBRATION_API_H
#define TTS_MODULE_CALIBRATION_API_H

/** @h2xml_title1           {Text To Speech (TTS)}
    @h2xml_title_agile_rev  {Text To Speech (TTS)}
    @h2xml_title_date       {Feb 26, 2024} */

#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/* Global unique Module ID definition
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_TTS    0x0702C001

/**
    @h2xmlm_module       {"MODULE_ID_TTS",
                          MODULE_ID_TTS}
    @h2xmlm_displayName  {"Text To Speech"}
    @h2xmlm_description  {ID of the TTS module.\n

    . This module supports the following parameter IDs:\n
        . #PARAM_ID_TTS_CONFIG\n
        . #PARAM_ID_TTS_SPEECH_CONFIG\n
        . #PARAM_ID_TTS_GAIN_CONFIG\n
        . #PARAM_ID_TTS_VERSION\n
        . #PARAM_ID_TTS_MODEL\n
        . #PARAM_ID_TTS_FORCE_STOP\n
    \n
    . Supported Input Media Format:      \n
    .           Data Format          : RAW_COMPRESSED \n
    .           fmt_id               : MEDIA_FMT_ID_ASR \n
    .           payload              : payload_media_fmt_asr_t \n
    \n
   }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_dataOutputPorts     {IN=1}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}
    @{                   <-- Start of the Module -->
    @h2xml_Select        {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter

*/

#define TTS_RELEASE_VERSION_MAJOR 0x00000001
#define TTS_RELEASE_VERSION_MINOR 0x00000000

#define PARAM_ID_TTS_VERSION                      0x08001B28
/** @h2xmlp_parameter {"PARAM_ID_TTS_VERSION", PARAM_ID_TTS_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy {RTC_READONLY} */

typedef struct tts_version_t tts_version_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct tts_version_t
{
  uint32_t lib_version_low;
   /**< @h2xmle_description {Lower 32 bits of the 64-bit library version number}
     @h2xmle_default    {TTS_RELEASE_VERSION_MAJOR} */
  uint32_t lib_version_high;
  /**< @h2xmle_description {Higher 32 bits of the 64-bit library version number}
     @h2xmle_default    {TTS_RELEASE_VERSION_MINOR} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                    {tts_version_t}
     @h2xmlm_InsertParameter */

/*
Supported language codes
*/
namespace TTS {
    typedef enum TTS_LANGUAGE_CODE_t{
        en_US=0,
        zh_CN,
        hi_IN,
        es_US,
        ko_KR,
        ja_JP,
        language_code_end_1
    }TTS_LANGUAGE_CODE_t;
}

/*
Supported language codes
*/
typedef enum TTS_SPEECH_FORMAT_t{
    SPEECH_FORMAT_PCM=0,
    SPEECH_FORMAT_END
}TTS_SPEECH_FORMAT_t;


/*  ID of the TTS configuration parameter used by MODULE_ID_TTS.*/
#define PARAM_ID_TTS_CONFIG                       0x08001B25

/*  Structure for the configuration parameters of TTS module. */
typedef struct param_id_tts_config_t param_id_tts_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_TTS_CONFIG", PARAM_ID_TTS_CONFIG}
    @h2xmlp_description {Configures the TTS module}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_TTS_CONFIG parameter used by the
 TTS module.
 */
struct param_id_tts_config_t
{
    uint32_t language_code;               // language code, refer enum TTS_LANGUAGE_CODE_t
    /**< @h2xmle_description {Code to specify TTS input-output language.}
         @h2xmle_rangeList   {"en_US"=en_US;"zh_CN"=zh_CN;"hi_IN"=hi_IN;"es_US"=es_US;"ko_KR"=ko_KR;"ja_JP"=ja_JP;"language_code_end"=language_code_end_1}
         @h2xmle_default     {en_US} */
    uint32_t speech_format;              // output speech format, refer enum TTS_SPEECH_FORMAT_t
    /**< @h2xmle_description {Code to specify TTS output speech format.}
         @h2xmle_rangeList   {"PCM"=SPEECH_FORMAT_PCM;"SPEECH_FORMAT_END"=SPEECH_FORMAT_END}
         @h2xmle_default     {SPEECH_FORMAT_PCM} */
    uint32_t reserved;             // Reserved field
    /**< @h2xmle_description {Reserved field}
         @h2xmle_visibility  {hide}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


/*   @h2xml_Select                    {param_id_tts_config_t}
     @h2xmlm_InsertParameter */

/*  ID of the TTS speech configuration parameter used by MODULE_ID_TTS.*/
#define PARAM_ID_TTS_SPEECH_CONFIG                       0x08001B26

/*  Structure for the speech specific configuration TTS module. */
typedef struct param_id_tts_speech_config_t param_id_tts_speech_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_TTS_SPEECH_CONFIG", PARAM_ID_TTS_SPEECH_CONFIG}
    @h2xmlp_description {Speech specific configuration of the TTS module}
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_TTS_SPEECH_CONFIG parameter used by the
 TTS module.
 */
struct param_id_tts_speech_config_t
{
    uint32_t speaker_rate_q4;               // speaker rate of output speech
    /**< @h2xmle_description {Rate of speech output to control slow or faster rate of output speech.}
         @h2xmle_rangeList   {"0.25x"=4,
                                   "0.50x"=8,
                                   "0.75x"=12,
                                   "1.00x"=16,
                                   "1.25x"=20,
                                   "1.50x"=24,
                                   "1.75x"=28,
                                   "2.00x"=32,
                                   "4.00x"=64}
         @h2xmle_default     {16}
         @h2xmle_range       {4..64} */
    int32_t pitch;              // speaker pitch
    /**< @h2xmle_description {Pitch of the speech output}
         @h2xmle_visibility  {hide}
         @h2xmle_default     {0}
         @h2xmle_range       {-20..20} */
    uint32_t reserved;             // Reserved field
    /**< @h2xmle_description {Reserved field}
         @h2xmle_visibility  {hide}
         @h2xmle_default     {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                    {param_id_tts_speech_config_t}
     @h2xmlm_InsertParameter */


/*  ID of the TTS force stop parameter used by MODULE_ID_TTS.*/
#define PARAM_ID_TTS_FORCE_STOP                      0x08001B2A

/*  Structure for the force stop parameter of TTS module. */
typedef struct param_id_tts_force_stop_t param_id_tts_force_stop_t;
/** @h2xmlp_parameter   {"PARAM_ID_TTS_FORCE_STOP", PARAM_ID_TTS_FORCE_STOP}
    @h2xmlp_description {Forces the TTS module to stop data processing irrespective of buffered input or output}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_TTS_FORCE_STOP parameter used by the
 TTS module.
 */
struct param_id_tts_force_stop_t
{
    uint32_t force_stop;             // forces TTS to stop data process
    /**< @h2xmle_description {forces TTS module to stop processing irrespective of presence of buffered input and\or output data }
         @h2xmle_default     {0}
         @h2xmle_rangeList   {"CONTINUE"=0;"STOP"=1}*/
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                    {param_id_tts_force_stop_t}
     @h2xmlm_InsertParameter */

/*  ID of the TTS gain configuration parameter used by MODULE_ID_TTS.*/
#define PARAM_ID_TTS_GAIN_CONFIG                          0x08001B27

/*  Structure for the output configuration parameter of TTS module. */
typedef struct param_id_tts_gain_config_t param_id_tts_gain_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_TTS_GAIN_CONFIG", PARAM_ID_TTS_GAIN_CONFIG}
    @h2xmlp_description {Param to configure required gain parameters of speech output }
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_TTS_GAIN_CONFIG parameter used by the
 TTS module.
 */

struct param_id_tts_gain_config_t
{
    int32_t gain;               // TTS output speech gain
    /**< @h2xmle_description {Gain of the speech output in dB}
         @h2xmle_default     {0}
         @h2xmle_range       {-96..16} */
    uint32_t reserved;             // Reserved field
    /**< @h2xmle_description {Reserved field}
         @h2xmle_visibility  {hide}
         @h2xmle_default     {0} */
}

#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select                    {param_id_tts_gain_config_t}
     @h2xmlm_InsertParameter */

/*  ID of the TTS model parameter used by MODULE_ID_TTS.*/
#define PARAM_ID_TTS_MODEL                  0x08001B29

typedef struct tts_model_param_t tts_model_param_t;
/** @h2xmlp_parameter       {"PARAM_ID_TTS_MODEL", PARAM_ID_TTS_MODEL}
    @h2xmlp_description  {NN Model related parameters}
    @h2xmlp_ToolPolicy      {CALIBRATION}
    @h2xmlp_isHwAccel {FALSE}
    @h2xmlp_isNeuralNetParam    {TRUE}
    @h2xmlp_isOffloaded        {TRUE}
    @h2xmlp_persistType  { Shared }
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct tts_model_param_t
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
#endif /* TTS_MODULE_CALIBRATION_API_H */
