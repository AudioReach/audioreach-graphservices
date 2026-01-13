/*==================================================
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 ==================================================*/

#ifndef MSPP_MODULE_CALIBRATION_API_H
#define MSPP_MODULE_CALIBRATION_API_H

/** @h2xml_title1           {MicroSpeaker Post Processing (MSPP)}
    @h2xml_title_agile_rev  {MicroSpeaker Post Processing (MSPP)}
    @h2xml_title_date       {March 15, 2021} */

#include "module_cmn_api.h"

/* Global unique Module ID definition 0x070010DE
   Module library is independent of this number, it defined here for static
   loading purpose only */
#define MODULE_ID_MICROSPEAKER_POST_PROCESSING    0x070010DE

/**
    @h2xmlm_module       {"MODULE_ID_MICROSPEAKER_POST_PROCESSING",
                          MODULE_ID_MICROSPEAKER_POST_PROCESSING}
    @h2xmlm_displayName  {"MicroSpeaker Post Processing"}
    @h2xmlm_description  {ID of the MSPP module.\n

    . This module supports the following parameter IDs:\n
        . #PARAM_ID_MODULE_ENABLE\n
        . #PARAM_ID_MSPP_CFG\n
        . #PARAM_ID_MSPP_VOLUME\n
        . #PARAM_ID_MSPP_DEV_ORIENTATION\n
        . #PARAM_ID_MSPP_VERSION\n
    \n
    . Supported Input Media Format:      \n
    .           Data Format          : FIXED_POINT \n
    .           fmt_id               : MEDIA_FMT_ID_PCM \n
    .           Sample Rates         : 48000 \n
    .           Number of channels   : 2  \n
    .           Channel type         : Supported channel mapping based on number of channels is given below.  \n
    .           Bits per sample      : 16,32 \n
    .           Q format             : Q15 for bps = 16, Q27 for bps = 32 \n
    .           Interleaving         : Deinterleaved Unpacked \n
    .           Signed/unsigned      : Signed  \n
    \n
    . Supported Input Channel Mapping based on number of input channels: \n
    .           1:  stereo  [L, R] \n
    .           2:  mono    [C] \n
    \n
    . Supported Output Channel Mapping based on number of output channels: \n
    .           1:  stereo  [L, R] \n
    .           2:  mono    [C] \n
    \n
   }
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_dataInputPorts      {IN=2}
    @h2xmlm_dataOutputPorts     {OUT=1}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {4096}
    @h2xmlm_toolPolicy          {Calibration}


    @{                   <-- Start of the Module -->
    @h2xml_Select        {"param_id_module_enable_t"}
    @h2xmlm_InsertParameter
*/

/*  ID of the MSPP configuration parameter used by MODULE_ID_MICROSPEAKER_POST_PROCESSING.*/
#define PARAM_ID_MSPP_CFG 0x0800137B

/*  Structure for the configuration parameters of MSPP module. */
typedef struct mspp_param_id_config_t mspp_param_id_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_MSPP_CFG", PARAM_ID_MSPP_CFG}
    @h2xmlp_description {Configures the MSPP module}
    @h2xmlp_toolPolicy  {Calibration; RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/*  Payload of the PARAM_ID_MSPP_CONFIG parameter used by the
 MSPP module.
 */
struct mspp_param_id_config_t
{

   uint32_t cfg_size;
   /**< @h2xmle_description {Specifies the length of config}
        @h2xmle_range       {10000..60000}
        @h2xmle_default     {48124} */

   uint8_t cfg_buf[0];
   /**< @h2xmle_description  {Buffer containing MSPP config}
        @h2xmle_range       {0x00..0xFF}
        @h2xmle_variableArraySize {"cfg_size"}
        @h2xmle_elementType {rawData}
        @h2xmle_displayType {file}
        @h2xmle_defaultFile {mspp_cfg_default.bin} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select        {mspp_param_id_config_t}
     @h2xmlm_InsertParameter */


#define MICROSPEAKER_LIN_VOLUME_QFACTOR_28 28

/* ID of the Multi-channel Volume Control parameters used by #MODULE_ID_MICROSPEAKER_POST_PROCESSING. */
#define PARAM_ID_MSPP_VOLUME 0x0800137C
/** @h2xmlp_parameter   {"PARAM_ID_MSPP_VOLUME", PARAM_ID_MSPP_VOLUME}
    @h2xmlp_description { Payload of the volume used by the MSPP module}
    @h2xmlp_toolPolicy  {Calibration; RTC}
    @h2xmlp_maxSize     {760} */

/* Structure for the volume command */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct mspp_volume_ctrl_gain_t
{
   int32_t vol_lin_gain;
   /**< @h2xmle_description  {Device volume (linear gain) Q28 format}
        @h2xmle_dataFormat   {Q28}
        @h2xmle_default      {0x10000000} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct mspp_volume_ctrl_gain_t mspp_volume_ctrl_gain_t;

/*   @h2xml_Select        {mspp_volume_ctrl_gain_t}
     @h2xmlm_InsertParameter */


#define PARAM_ID_MSPP_DEV_ORIENTATION 0x08001394
/** @h2xmlp_parameter {"PARAM_ID_MSPP_DEV_ORIENTATION", PARAM_ID_MSPP_DEV_ORIENTATION}
    @h2xmlp_description {Structure to set the current device orientation.}
    @h2xmlp_toolPolicy {Calibration; RTC} */

typedef struct microspeaker_dev_orientation_t microspeaker_dev_orientation_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct microspeaker_dev_orientation_t {
  uint32_t dev_orientation;
   /**< @h2xmle_description {device orientation as 0, 1, 2 or 3 for portrait, inverted portrait, landscape, inverted landscape respectively} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select        {microspeaker_dev_orientation_t}
     @h2xmlm_InsertParameter */


#define MICROSPEAKER_RELEASE_VERSION_MAJOR 0x00000003
#define MICROSPEAKER_RELEASE_VERSION_MINOR 0x00000000

#define PARAM_ID_MSPP_VERSION 0x0800137D
/** @h2xmlp_parameter {"PARAM_ID_MSPP_VERSION", PARAM_ID_MSPP_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy {RTC_READONLY} */

typedef struct microspeaker_version_t microspeaker_version_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct microspeaker_version_t
{
  uint32_t lib_version_low;
   /**< @h2xmle_description {Lower 32 bits of the 64-bit library version number}
     @h2xmle_default    {MICROSPEAKER_RELEASE_VERSION_MAJOR} */
  uint32_t lib_version_high;
  /**< @h2xmle_description {Higher 32 bits of the 64-bit library version number}
     @h2xmle_default    {MICROSPEAKER_RELEASE_VERSION_MINOR} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select        {microspeaker_version_t}
     @h2xmlm_InsertParameter */


/** @}                   <-- End of the Module -->*/
#endif /* MSPP_MODULE_CALIBRATION_API_H */
