#ifndef __CONGESTION_BUF_H
#define __CONGESTION_BUF_H
/**
 * \file congestion_buf_api.h
 * \brief
 *     This file contains module published by Congestion Buf CAPI intialization.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "module_cmn_api.h"
#include "imcl_fwk_intent_api.h"

/**
  @h2xml_title1          {Congestion Audio Buffer Module}
  @h2xml_title_agile_rev {Congestion Audio Buffer Module}
  @h2xml_title_date      {July 17, 2024}
*/

// Max number of ports supported by Congestion Buf module.
#define CAPI_CONGESTION_BUF_MAX_INPUT_PORTS         (1)
#define CAPI_CONGESTION_BUF_MAX_OUTPUT_PORTS        (1)

/*==============================================================================
   Constants
==============================================================================*/

/* Parameter description */
#define PARAM_ID_CONGESTION_BUF_CONFIG         0x080014E2
#define PARAM_ID_CONGESTION_BUF_SIZE_CONFIG    0x080014E5

/*==============================================================================
   Type Definitions
==============================================================================*/

typedef struct param_id_congestion_buf_config_t param_id_congestion_buf_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_CONGESTION_BUF_CONFIG",
                          PARAM_ID_CONGESTION_BUF_CONFIG}
    @h2xmlp_description { This param ID is used to configure Congestion Buffer module. }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_congestion_buf_config_t
{
      uint32_t bit_rate_mode;
      /**< @h2xmle_description { Defines the bit rate mode of module }
           @h2xmle_rangeList   {"UNSET" = 0; "AVG" = 1; "MAX" = 2} */

      uint32_t bit_rate;
      /**< @h2xmle_description { Defines the bit rate of decoder. A value of '0' indicates unknown\unset bitrate}
           @h2xmle_default     { 0 } */

      uint32_t congestion_buffer_duration_ms;
      /**< @h2xmle_description { Defines the congestion buffer size (not latency) in milli seconds}
           @h2xmle_default     { 0 }
           @h2xmle_range       {0..300} */

      uint32_t delay_buffer_duration_ms;
      /**< @h2xmle_description { Reserved, set to 0 }
           @h2xmle_default     { 0 } */

      uint32_t frame_size_mode;
      /**< @h2xmle_description { Defines the mode of frame size which can be duration or samples }
           @h2xmle_rangeList   {"UNSET" = 0; "DURATION IN US" = 1; "SAMPLES" = 2} */

      uint32_t frame_size_value;
      /**< @h2xmle_description { Decoder frame size in us or samples - 0 : unset\variable}
           @h2xmle_default     { 0 } */

      uint32_t sampling_rate;
      /**< @h2xmle_description { Decoder sampling rate, used to derive frame duration when frame size mode is samples } */

      uint32_t mtu_size;
      /**< @h2xmle_description { Maximum Transfer Unit in bytes }
           @h2xmle_default     { 1024 }
           @h2xmle_range       {0..1200} */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_congestion_buf_size_config_t param_id_congestion_buf_size_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_CONGESTION_BUF_SIZE_CONFIG",
                          PARAM_ID_CONGESTION_BUF_SIZE_CONFIG}
    @h2xmlp_description { This param ID is used to configure Congestion Buffer size from QACT for debug purpose. }
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_congestion_buf_size_config_t
{
      uint32_t congestion_buffer_duration_ms;
      /**< @h2xmle_description { Defines the congestion buffer size (not latency) in milli seconds}
           @h2xmle_default     { 0 }
           @h2xmle_range       {0..300} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*------------------------------------------------------------------------------
   Module
------------------------------------------------------------------------------*/

/**  Module ID of the Congestion Buf Module. */
#define MODULE_ID_CONGESTION_AUDIO_BUFFER                     0x07010004

/**
    @h2xmlm_module         {"MODULE_ID_CONGESTION_AUDIO_BUFFER", MODULE_ID_CONGESTION_AUDIO_BUFFER}
    @h2xmlm_displayName    {"Congestion Audio Buffer"}

    @h2xmlm_description    { This module is used to buffer compressed audio data for usecases such as BT Sink.\n

    \n This module supports the following parameter IDs:\n
     - PARAM_ID_CONGESTION_BUF_CONFIG \n
     - PARAM_ID_CONGESTION_BUF_SIZE_CONFIG\n

   \n Supported Input Media Format:\n
*  - Data Format          : RAW_COMPRESSED\n
*  - fmt_id               : Don't care\n }

    @h2xmlm_dataMaxInputPorts    { 1 }
    @h2xmlm_dataMaxOutputPorts   { 1 }
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            { 1024 }
    @{                     <-- Start of the Module -->

    @h2xml_Select      {param_id_congestion_buf_config_t}
    @h2xmlm_InsertParameter
    @h2xml_Select      {param_id_congestion_buf_size_config_t}
    @h2xmlm_InsertParameter
 @}                     <-- End of the Module --> */

#endif /*__CONGESTION_BUF_H*/
