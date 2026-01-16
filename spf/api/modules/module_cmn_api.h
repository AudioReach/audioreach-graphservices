#ifndef _MOD_CMN_API_H_
#define _MOD_CMN_API_H_
/**
 * \file module_cmn_api.h
 * \brief
 *       this file contains common module definitions
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "apm_graph_properties.h"
#include "media_fmt_api.h"


/** @ingroup ar_spf_mod_encdec_mods
    Identifier for the Enable parameter used by any audio processing module.

    This generic/common parameter is used to configure or determine the
    state of any audio processing module.

    @msgpayload
    param_id_module_enable_t @newpage
 */
#define PARAM_ID_MODULE_ENABLE                                   0x08001026

/*# @h2xmlp_parameter   {"PARAM_ID_MODULE_ENABLE", PARAM_ID_MODULE_ENABLE}
    @h2xmlp_description {ID for the Enable parameter used by any audio
                         processing module. This generic/common parameter is
                         used to configure or determine the state of any audio
                         processing module.}
    @h2xmlp_toolPolicy  {Calibration; RTC} */

/** @ingroup ar_spf_mod_encdec_mods
    Payload of the #PARAM_ID_MODULE_ENABLE parameter, which is used for any
    audio processing module.
*/
#include "spf_begin_pack.h"
struct param_id_module_enable_t
{
   uint32_t enable;
   /**< Specifies whether the module is to be enabled or disabled.

        @valuesbul
        - 0 -- Disable (Default)
        - 1 -- Enable @tablebulletend */

   /*#< @h2xmle_description {Specifies whether the module is to be enabled or
                             disabled.}
        @h2xmle_rangeList   {"Disable"=0;
                             "Enable"=1}
        @h2xmle_default     {0}
        @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;
typedef struct param_id_module_enable_t param_id_module_enable_t;


#ifndef DOXYGEN_SHOULD_SKIP_THIS // to end of file

#define PARAM_ID_LIB_VERSION                                   0x00010937

/*# @h2xmlp_parameter   {"PARAM_ID_LIB_VERSION", PARAM_ID_LIB_VERSION}
    @h2xmlp_description {To query the lib version of any audio processing
                         module.}
    @h2xmlp_toolPolicy  {RTC_READONLY}
    @h2xmlp_readOnly    {true} */

/* Payload of the PARAM_ID_LIB_VERSION parameter used by
 any Audio Processing module
 */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct lib_version_t
{
   uint32_t lib_version_low;
   /*#< @h2xmle_description {Version of the module LSB.} */

   uint32_t lib_version_high;
   /*#< @h2xmle_description {Version of the module MSB} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Structure for Querying module lib version of any Audio processing modules. */
typedef struct lib_version_t lib_version_t;


#define FRAME_SIZE_TYPE_NATIVE 0
#define FRAME_SIZE_TYPE_US 1
#define FRAME_SIZE_TYPE_SAMPLES_PER_CHANNEL 2

#define PARAM_ID_MODULE_FRAME_SIZE_CFG                               0x08001252

/*# @h2xmlp_parameter   {"PARAM_ID_MODULE_FRAME_SIZE_CFG",
                          PARAM_ID_MODULE_FRAME_SIZE_CFG}
    @h2xmlp_description {Parameter for setting the module frame size.}
    @h2xmlp_toolPolicy  {Calibration} */

/* Payload of the PARAM_ID_MODULE_FRAME_SIZE_CFG parameter used by any Audio Processing module.
 */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_module_frame_size_cfg_t
{
    uint32_t frame_size_type;
   /*#< @h2xmle_description {If set to FRAME_SIZE_TYPE_NATIVE, the CAPI frame
                             size will be <em>don't care</em> and can
                             be selected according to the internal CAPI
                             implementation. (NATIVE does NOT mean the frame
                             size automatically follows the container frame
                             size. So, NATIVE mode will not work in all use
                             cases.) \n
                             Otherwise, this field specifies the units of the
                             frame_size_value.}
        @h2xmle_rangeList    {"Library Frame Size"=0;
                              "Microseconds"=1;
                              "Samples per Channel"=2}
        @h2xmle_default      {0}
        @h2xmle_policy       {Basic} */

   uint32_t frame_size_value;
   /*#< @h2xmle_description {CAPI frame size. For FRAME_SIZE_TYPE_NATIVE, this
                             value is <em>don't care</em>. \n
                             FOR FRAME_SIZE_TYPE_US, this value is in
                             microseconds. \n
                             For FRAME_SIZE_TYPE_SAMPLES_PER_CHANNEL, this
                             value is in samples per channel.}
        @h2xmle_default     {0}
        @h2xmle_policy      {Basic} */

   uint32_t sample_rate;
   /*#< @h2xmle_description {If frame_size_type is NOT
                             FRAME_SIZE_TYPE_SAMPLES_PER_CHANNEL, this value is
                             <em>don't care</em>. \n
                             If this value is 0, the frame size is specified in
                             samples that are independent of the sample rate.
                             Otherwise, the frame size is fixed in time based
                             on the specified samples (frame_size_value) at
                             this sample rate. \n
                             For FFNS, because frame_size_type is expected to
                             be FRAME_SIZE_TYPE_NATIVE or FRAME_SIZE_TYPE_US,
                             this value is <em>don't care</em>.}
        @h2xmle_default     {0}
        @h2xmle_policy      {Basic} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/* Structure for setting the module frame size. */
typedef struct param_id_module_frame_size_cfg_t param_id_module_frame_size_cfg_t;


/* Param id to Enable/Disable MLA/eNPU offloading */
#define PARAM_ID_MLA_ENABLE 0x080011DF

/*# @h2xmlp_parameter       {"PARAM_ID_MLA_ENABLE", PARAM_ID_MLA_ENABLE}
    @h2xmlp_description     {ID for the parameter that enables MLA/eNPU
                             offloading.}
    @h2xmlp_isHwAccelEnable {true}
    @h2xmlp_toolPolicy      {Calibration} */

/* Payload of the PARAM_ID_MLA_ENABLE parameter */
#include "spf_begin_pack.h"
struct mla_enable_t
{
    uint32_t mla_enable;
    /*#< @h2xmle_description {Flag that indicates whether MLA (aka NPU) is to
                              be invoked.}
         @h2xmle_rangeList   {"Disable"= 0;
                              "Enable"=1}
         @h2xmle_default     {0}
         @h2xmle_policy      {Basic} */
}
#include "spf_end_pack.h"
;
typedef struct mla_enable_t mla_enable_t;

#endif /* DOXYGEN_SHOULD_SKIP_THIS */


#endif /* _MOD_CMN_API_H_ */
