#ifndef AMRWB_DECODER_API_H_
#define AMRWB_DECODER_API_H_
/*==============================================================================
  @file amwrb_decoder_api.h
  @brief This file contains AMRWB decoder APIs

================================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/
// clang-format off
/** @h2xml_title1           {AMRWB Decoder Module API}
    @h2xml_title_agile_rev  {AMRWB Decoder Module API}
    @h2xml_title_date       {May 28, 2019} */

/*==============================================================================
   Include Files
==============================================================================*/

#include "media_fmt_api.h"
#include "common_enc_dec_api.h"
#include "vocoder_cmn_api.h"
/*==============================================================================
   Constants
==============================================================================*/

/* Input port ID of AMRWB module */
#define AMRWB_DEC_DATA_INPUT_PORT   0x2

/* Output port ID of AMRWB module */
#define AMRWB_DEC_DATA_OUTPUT_PORT  0x1

/* Max number of input ports of AMRWB module */
#define AMRWB_DEC_DATA_MAX_INPUT_PORTS 0x1

/* Max number of output ports of AMRWB module */
#define AMRWB_DEC_DATA_MAX_OUTPUT_PORTS 0x1

/* Stack size of AMRWB module */
#define AMRWB_DEC_MODULE_STACK_SIZE 8192

/*==============================================================================
   Module
==============================================================================*/

/* Module ID of AMRWB decoder module */
#define MODULE_ID_AMRWB_DEC 0x07001078

/**
    @h2xmlm_module         {"MODULE_ID_AMRWB_DEC", MODULE_ID_AMRWB_DEC}
    @h2xmlm_displayName    {"AMRWB Decoder"}
    @h2xmlm_description    {This module is used as the decoder for AMRWB use cases.\n
                            - This module has only one input and one output port.\n
                            - Media format is not directly set on the decoder, it's set on the EP module which
                            propagates it in the data path.\n
                            - Decodes data of format-id :
                               -MEDIA_FMT_ID_AMRWB\n
                               -MEDIA_FMT_ID_AMRWB_FS\n
                            - Supported Input Media Format\n 
                            -- Data format : RAW_COMPRESSED\n 
                            -- fmt_id :
                               -MEDIA_FMT_ID_AMRWB\n
                               -MEDIA_FMT_ID_AMRWB_FS\n
                            }
    @h2xmlm_dataMaxInputPorts   {AMRWB_DEC_DATA_MAX_INPUT_PORTS}
    @h2xmlm_dataMaxOutputPorts  {AMRWB_DEC_DATA_MAX_OUTPUT_PORTS}
    @h2xmlm_dataInputPorts      {IN=AMRWB_DEC_DATA_INPUT_PORT}
    @h2xmlm_dataOutputPorts     {OUT=AMRWB_DEC_DATA_OUTPUT_PORT}
    @h2xmlm_supportedContTypes {APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable       {true}
    @h2xmlm_stackSize           {AMRWB_DEC_MODULE_STACK_SIZE}
    @{                          <-- Start of the Module -->
    @}                     <-- End of the Module -->
*/

#endif //_AMRWB_DECODER_API_H_
