#ifndef HPCM_API_H
#define HPCM_API_H

/**
 * \file hpcm_api.h
 * \brief
 *       This file contains APIs supported by HPCM module
 *
 * \copyright
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @h2xml_title1           {HPCM Module}
    @h2xml_title_agile_rev  {HPCM Module}
    @h2xml_title_date       {June 23, 2021}
*/

/*==============================================================================
   Include Files
==============================================================================*/

#include "ar_defs.h"
#include "module_cmn_api.h"

/*==========================================================================
   Macros
========================================================================== */

/* Max number of input ports of HPCM module */
#define HPCM_MAX_IN_PORTS         0x1

/* Max number of output ports of HPCM module */
#define HPCM_MAX_OUT_PORTS        0x1

/* Stack size of HPCM module */
#define HPCM_STACK_SIZE_IN_BYTES  2048

#define HPCM_NONE_MODE            0x0

/* Indicates read mode of the module.
   HPCM delivers the data to client if configured in this mode. */
#define HPCM_READ_MODE            0x1

/* Indicates write mode of the module.
   Client injects data if HPCM is configured in this mode.
*/
#define HPCM_WRITE_MODE           0x2

/* Indicates the mode where module is configured for both
   read and write.
   First, client reads the data from module
   and then injects the data.
*/
#define HPCM_READ_WRITE_MODE      0x3

/* Bit to be set in mask of EVENT_ID_HPCM_HOST_BUF_DONE to indicate the
  info regd number of buffers to be used by client*/
#define HPCM_NUM_BUF_BIT        ( 1 << 2 )

/* Bit to set in mask of EVENT_ID_HPCM_HOST_BUF_DONE,
  to indicate the error occured during read processing */
#define HPCM_READ_ERROR_BIT      ( 1 << 3 )

/* Bit to set in mask of EVENT_ID_HPCM_HOST_BUF_DONE,
  to indicate the error occured during write processing */
#define HPCM_WRITE_ERROR_BIT     (1 << 4 )

/* Native frame size. If frame size is set to this
   value by client, it indicates that client's frame size
   can be same as container's frame size*/
#define HPCM_FRAME_SIZE_NATIVE    0x0

/* Frame size of 10ms */
#define HPCM_FRAME_SIZE_10_MS     (10)

/* Frame size of 20ms */
#define HPCM_FRAME_SIZE_20_MS     (20)

/*==============================================================================
   Param HPCM Config
==============================================================================*/
#define PARAM_ID_HPCM_CONFIG             0x08001378

/** @h2xmlp_parameter   {"PARAM_ID_HPCM_CONFIG", PARAM_ID_HPCM_CONFIG}
    @h2xmlp_description {Parameter used to enable module and send HPCM configuration.}
    @h2xmlp_toolPolicy  {Calibration}
*/

typedef struct param_id_hpcm_config_t param_id_hpcm_config_t;


#include "spf_begin_pack.h"
struct param_id_hpcm_config_t
{
     uint32_t enable;
/**< @h2xmle_description {Specifies whether the module needs to be enabled or disabled.}
     @h2xmle_default     {0x0}
     @h2xmle_rangeList   {"Disable"= 0;
                          "Enable"=1}
     @h2xmle_policy      {Basic}*/

     uint16_t mode;
/**< @h2xmle_description {Specifies the operating mode of this module.
                          Valid only when enable flag is set.}
     @h2xmle_default     {0x0}
     @h2xmle_rangeList   {"HPCM_NONE_MODE" = HPCM_NONE_MODE;
                          "HPCM_READ_MODE"= HPCM_READ_MODE;
                          "HPCM_WRITE_MODE"= HPCM_WRITE_MODE;
                          "HPCM_READ_WRITE_MODE"= HPCM_READ_WRITE_MODE}
     @h2xmle_policy      {Basic}*/

     uint16_t num_channels;
/**< @h2xmle_description {Number of channels associated with read/write buffer.
                          Valid only when enable flag is set.}
     @h2xmle_default     {1}
     @h2xmle_rangeList   {"1"=1}
     @h2xmle_policy      {Basic}*/

     uint32_t sampling_rate;
/**< @h2xmle_description {Sampling rate of the data written by client(in Hz).
                          Valid only when enable flag is set.}
     @h2xmle_default     {0x1f40}
     @h2xmle_rangeList   {"8000" = 8000;
                          "16000"= 16000;
                          "32000"= 32000;
                          "48000"= 48000;
                          "96000"= 96000}
     @h2xmle_policy      {Basic}*/

     uint32_t duration_ms;
/**< @h2xmle_description {Frame size of buffer(in milliseconds).
                          Size of 0 indicates that client will receive
                          buffer of size equal to container frame size.
                          Frame size of 10ms is valid only for Tx module.

                          This field is valid only when enable flag is set.}
     @h2xmle_default     {0x0}
     @h2xmle_rangeList   {"HPCM_FRAME_SIZE_NATIVE" = 0;
                          "HPCM_FRAME_SIZE_10_MS"  = 10;
                          "HPCM_FRAME_SIZE_20_MS"  = 20}
     @h2xmle_policy      {Basic}*/

     uint32_t reserved;
/**< @h2xmle_description {Reserved field for alignment. Must be set to 0.}
     @h2xmle_default     {0x0}
     @h2xmle_readOnly    {true}*/
}
#include "spf_end_pack.h"
;


/*==============================================================================
   Param HPCM Buffer Config
==============================================================================*/
#define PARAM_ID_HPCM_DATA_BUF_CFG        0x08001379

typedef struct param_id_hpcm_data_buf_cfg_t param_id_hpcm_data_buf_cfg_t;

/**
    @h2xmlp_parameter      {"PARAM_ID_HPCM_DATA_BUF_CFG", PARAM_ID_HPCM_DATA_BUF_CFG}
    @h2xmlp_description    {Parameter sent by the client indicating that read/write
                            buffers are available for the module to use.}
    @h2xmlp_toolPolicy     {Calibration}
*/
#include "spf_begin_pack.h"
struct param_id_hpcm_data_buf_cfg_t
{
    uint32_t mask;
/**< @h2xmle_description {Indicates which(read/write) buffers are available}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}

     @h2xmle_bitfield           {0x00000001}
     @h2xmle_bitName            {Bit_0_READ_BUF}
     @h2xmle_description        {Availability of read buffer}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0x00000002}
     @h2xmle_bitName            {Bit_1_WRITE_BUF}
     @h2xmle_description        {Availability of write buffer}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0xFFFFFFFC}
     @h2xmle_bitName            {Bit_31_2_Reserved}
     @h2xmle_description        {Reserved Bit[31:2]}
     @h2xmle_visibility         {hide}
     @h2xmle_bitfieldEnd
*/

    uint32_t rd_mem_map_handle;
 /**< @h2xmle_description {Memory map handle of the shared memory
                           corresponding to read buffers.
                           Valid only when read mode is enabled.}
      @h2xmle_default      {0x00000000}
      @h2xmle_range        {0x00000000..0xFFFFFFFF}
      @h2xmle_policy       {Basic}
*/

    uint32_t wr_mem_map_handle;
 /**< @h2xmle_description {Memory map handle of the shared memory
                           corresponding to read buffers.
                           Valid only when write mode is enabled.}
      @h2xmle_default      {0x00000000}
      @h2xmle_range        {0x00000000..0xFFFFFFFF}
      @h2xmle_policy       {Basic}
*/

     uint32_t rd_buff_addr_lsw;
/**< @h2xmle_description {Lower 32 bits of shared memory address of read buffer
                          to be filled with data from module.
                          Address is valid if mask field indicates that read
                          buffer is available.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t rd_buff_addr_msw;
/**< @h2xmle_description {Upper 32 bits of shared memory address of read buffer
                          to be filled with data from module.
                          Address is valid if mask field indicates that read
                          buffer is available.
                          The 64-bit number formed by rd_buff_addr_lsw and
                          rd_buff_addr_msw must be 32-byte aligned and must
                          have been previously mapped}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_addr_lsw;
/**< @h2xmle_description {Lower 32 bits of the shared memory of the write buffer
                          that contains the data to inject at the module.
                          Address is valid if mask field indicates that write
                          buffer is available.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_addr_msw;
/**< @h2xmle_description {Upper 32 bits of the shared memory of the write buffer
                          that contains the data to inject at the module.
                          Address is valid if mask field indicates that write
                          buffer is available.
                          The 64-bit number formed by wr_buff_addr_lsw and
                          wr_buff_addr_msw must be 32-byte aligned and must
                          have been previously mapped}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t rd_buff_size;
/**< @h2xmle_description {Maximum size(in bytes) of the read buffer to be filled.
                          This value is valid if the mask field indicates
                          that the read buffer is to be filled.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_size;
/**< @h2xmle_description {Size(in bytes) of the write buffer to be consumed.
                          This value is valid if the mask field indicates
                          that the write buffer is to be consumed.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

}
#include "spf_end_pack.h"
;

/*==============================================================================
   HPCM mode Event
==============================================================================*/
#define EVENT_ID_HPCM_MODE_INFO          0x08001A96
typedef struct event_id_hpcm_mode_t event_id_hpcm_mode_t;
#include "spf_begin_pack.h"
struct event_id_hpcm_mode_t
{
   uint32_t hpcm_staggered_mode;
/**< @h2xmle_description {hpcm staggered mode}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0x0000001}
     @h2xmle_policy      {Basic}
*/
}
#include "spf_end_pack.h"
;
/*==============================================================================
   Buf Done Event
==============================================================================*/
#define EVENT_ID_HPCM_HOST_BUF_DONE          0x0800137A
typedef struct event_id_hpcm_host_buf_done_t event_id_hpcm_host_buf_done_t;

/**
    @h2xmlp_parameter       {"EVENT_ID_HPCM_HOST_BUF_DONE", EVENT_ID_HPCM_HOST_BUF_DONE}
    @h2xmlp_description     {Event raised by the module indicating that module has finished
                             processing the buffer pushed previously using PARAM_ID_HPCM_DATA_BUF_CFG
                             and buffer can be reclaimed by client.}
    @h2xmlp_ToolPolicy      {NO_SUPPORT}
*/
#include "spf_begin_pack.h"
struct event_id_hpcm_host_buf_done_t
{
   uint32_t mask;
/**< @h2xmle_description {Notifies about which buffer is filled/consumed}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}

     @h2xmle_bitfield           {0x00000001}
     @h2xmle_bitName            {Bit_0_READ_BUF}
     @h2xmle_description        {When set to 1, indicates that read buffer is filled.}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0x00000002}
     @h2xmle_bitName            {Bit_1_WRITE_BUF}
     @h2xmle_description        {When set to 1, indicates that write buffer is consumed.}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0x00000004}
     @h2xmle_bitName            {Bit_2_NUM_BUF}
     @h2xmle_description        {Indicates that buffer size and duration are provided}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0x00000008}
     @h2xmle_bitName            {Bit_3_READ_ERROR}
     @h2xmle_description        {Indicates the error if occured during read processing}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0x00000010}
     @h2xmle_bitName            {Bit_4_WRITE_ERROR}
     @h2xmle_description        {Indicates the error if occured during write processing}
     @h2xmle_bitfieldEnd

     @h2xmle_bitfield           {0xFFFFFFE0}
     @h2xmle_bitName            {Bit_31_5_Reserved}
     @h2xmle_description        {Reserved Bit[31:5]}
     @h2xmle_visibility         {hide}
     @h2xmle_bitfieldEnd
*/

     uint32_t rd_buff_addr_lsw;
/**< @h2xmle_description {Lower 32 bits of shared memory address of read buffer
                          that has been filled with data from module.
                          Address is valid if mask field indicates that read
                          buffer is filled.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t rd_buff_addr_msw;
/**< @h2xmle_description {Upper 32 bits of shared memory address of read buffer
                          that has been filled with data from module.
                          Address is valid if mask field indicates that read
                          buffer is filled.
                          This shared memory buffer is same as the one that was
                          provided by client using PARAM_ID_HPCM_HOST_BUF_CFG.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_addr_lsw;
/**< @h2xmle_description {Lower 32 bits of the shared memory of the consumed write buffer.
                          Address is valid if mask field indicates that write
                          buffer is consumed.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_addr_msw;
/**< @h2xmle_description {Upper 32 bits of the shared memory of the consumed write buffer.
                          Address is valid if mask field indicates that write
                          buffer is consumed.
                          This shared memory buffer is same as the one that was
                          provided by client using PARAM_ID_HPCM_HOST_BUF_CFG.}}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t rd_buff_size;
/**< @h2xmle_description {Size of read buffer filled by module.
                          This value is valid if the mask field indicates
                          that the read buffer is filled.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t wr_buff_size;
/**< @h2xmle_description {Requested size of the next buffer to be pushed.
                          This value is valid if the mask field indicates
                          that the write buffer is consumed.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/

     uint32_t num_buffers;
/**< @h2xmle_description {Number of buffers required from client.
                          Client needs to allocate buffer of max size
                          before sending PARAM_ID_HPCM_CONFIG. On receiving
                          num_buffers value, it needs to partition the
                          buffers and send PARAM_ID_HPCM_DATA_BUF_CFG accordingly.}
     @h2xmle_default     {0x00000000}
     @h2xmle_range       {0x00000000..0xFFFFFFFF}
     @h2xmle_policy      {Basic}
*/
}
#include "spf_end_pack.h"
;

/*==============================================================================
   Module ID and Module Supported Info
==============================================================================*/
#define MODULE_ID_HPCM                      0x070010DD
/**
    @h2xmlm_module       {"MODULE_ID_HPCM", MODULE_ID_HPCM}
    @h2xmlm_displayName  {"HPCM"}
    @h2xmlm_description  { Host PCM module enables client to read/write the PCM data \n
                           in the Voice Tx/Rx path.\n
                           - This module supports the following parameter IDs:\n
                           - #PARAM_ID_HPCM_CONFIG\n
                           - #PARAM_ID_HPCM_DATA_BUF_CFG\n
                           - #EVENT_ID_HPCM_HOST_BUF_DONE\n
                           - Supported Input Media Format: \n
                           - Data Format          : FIXED \n
                           - fmt_id               : Don't care \n
                           - Sample Rates         : 8000, 16000, 32000, 48000, 96000\n
                           - Number of channels   : 1 \n
                           - Channel type         : Don't care \n
                           - Bits per sample      : 16 \n
                           - Q format             : Q15 \n
                           - Interleaving         : de-interleaved unpacked \n
                           - Signed/unsigned      : Signed \n}
    @h2xmlm_dataMaxInputPorts   {HPCM_MAX_IN_PORTS}
    @h2xmlm_dataMaxOutputPorts  {HPCM_MAX_OUT_PORTS}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_GC, APM_CONTAINER_TYPE_SC}
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           {HPCM_STACK_SIZE_IN_BYTES}
    @h2xmlm_toolPolicy          { Calibration }

    @{                          <-- Start of the Module -->
    @h2xml_Select               {"param_id_hpcm_config_t"}
    @h2xmlp_description         {Parameter used to enable module and send HPCM configuration.}
    @h2xmlm_InsertParameter

   @}                          <-- End of the Module --> **/
#endif // HPCM_API_H

