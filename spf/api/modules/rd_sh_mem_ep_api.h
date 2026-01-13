/**
 * \file rd_sh_mem_ep_api.h
 * \brief
 *  	 This file contains Shared mem module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RD_SH_MEM_EP_API_H_
#define RD_SH_MEM_EP_API_H_

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "common_enc_dec_api.h"

/**
    @h2xml_title1          {APIs of Read Shared Memory End Point Module}
    @h2xml_title_agile_rev {APIs of Read Shared Memory End Point Module}
    @h2xml_title_date      {August 13, 2018}
 */

/**
   @h2xmlx_xmlNumberFormat {int}
*/

/**
 * Data command to send an empty buffer to the shared memory end point module.
 * RD_SHARED_MEM_EP writes to this buffer & client reads.
 *
 * This command can be used to read PCM, raw compressed as well as packetized streams.
 *
 * Once buffer is filled, DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE event is raised.
 */
#define DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER                         0x04001003

#include "spf_begin_pack.h"
struct data_cmd_rd_sh_mem_ep_data_buffer_t
{
   uint32_t buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer */

   uint32_t buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer .

        The buffer address for each frame must be a valid address
        that was mapped via #APM_CMD_SHARED_MEM_MAP_REGIONS.
        The 64-bit number formed by buf_addr_lsw and buf_addr_msw must be
        aligned to the cache-line of the processor where spf runs (64-byte alignment for Hexagon).

        @tblsubhd{For a 32-bit shared memory address} This buf_addr_msw field
        must be set to 0.

        @tblsubhd{For a 36-bit address} Bits 31 to 4 of this
        buf_addr_msw field must be set to 0. */

   uint32_t mem_map_handle;
   /**< Unique identifier for the shared memory address.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t buf_size;
   /**< Number of bytes available for the spf to write. The
        first byte starts at the buffer address.

        @values @ge 0 */

}
#include "spf_end_pack.h"
;

/** Structure for DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER */
typedef struct data_cmd_rd_sh_mem_ep_data_buffer_t data_cmd_rd_sh_mem_ep_data_buffer_t;

/**
 *  Indicates that the referenced buffer has been filled and
 *  is available to the client for reading.
 *
 *  This is response to DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER
 *
    The referenced buffer contains an optional array of metadata if the client
    requested it in an open command. The buffer is followed by a variable
    amount of empty space, assuming metadata is present, followed by an integer
    number of encoded frames. Metadata presence is indicated by bit 30 of the
    flags field in the flags

    Buffer format
    A multiframe buffer becomes an array of frame metadata
    information structures, and then an array of audio frames. Data
    frames start with <i>offset</i>.
    @verbatim
    MetaData 0 (optional)
    MetaData 1 (optional)
       . . .
    MetaData n (optional)
    Extra space (optional)
    Frame 0 Payload (this always starts at an offset from buf_addr)
    Frame 1 Payload
       . . .
    Frame n-1 Payload

 */
#define DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE                0x05001002

/** Definition of a timestamp valid flag bitmask. */
#define RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG                AR_NON_GUID(0x80000000)

/** Definition of a timestamp valid flag shift value. */
#define RD_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG                   31

/** Definition of the frame metadata bitmask.
*/
#define RD_SH_MEM_EP_BIT_MASK_FRAME_METADATA_FLAG                 AR_NON_GUID(0x60000000)

/** Definition of the frame metadata shift value.
*/
#define RD_SH_MEM_EP_SHIFT_FRAME_METADATA_FLAG                    29

#include "spf_begin_pack.h"
/**
 * Complete payload struct
 * struct of memory at (buf_addr_msw|buf_addr_lsw)
 * {
 *
 * if metadata_enabled:
 *    {
 *       data_event_rd_sh_mem_ep_metadata_t metadata[num_frames];
 *       uint8_t padding1[if_any];
 *    }
 *    uint8_t frames[data_size];
 *    uint8_t padding2[if_any];
 * }
 */
struct data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_t
{
   uint32_t                status;
   /**< Status message (error code).

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */

   uint32_t                buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer being returned. */

   uint32_t                buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer being returned.

        The valid, mapped, 64-bit address is the same address that
        the client provides in #DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER. */

   uint32_t                 mem_map_handle;
   /**< Unique identifier for the shared memory address.

        The spf returns this handle through #DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER. */

   uint32_t                 data_size;
   /**< Total size of the data frames in bytes.

        @values @ge 0  */

   uint32_t                 offset;
   /**< Offset from the buffer address to the first byte of the data frame.
    * All frames are consecutive, starting from this offset.

        @values > 0 */

   uint32_t                 timestamp_lsw;
   /**< Lower 32 bits of the 64-bit session time in microseconds of the
        first sample in the buffer. */

   uint32_t                 timestamp_msw;
   /**< Upper 32 bits of the 64-bit session time in microseconds of the
        first sample in the buffer.

        the 64bit timestamp must be interpreted as a signed number.

        Source of the timestamp depends on the source feeding data to this module.
      */

   uint32_t                 flags;
   /**< Bit field of flags.

        @values{for bit 31}
        - 1 -- Timestamp is valid
        - 0 -- Timestamp is invalid
        - To set this bit, use #RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG and
        RD_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG

        @values{for bit 29-30}
        - 00 -- frame metadata absent
        - 01 -- Frame metadata is present as data_event_rd_sh_mem_ep_metadata_t
        - 10 -- Reserved
        - 11 -- Reserved
        - To set these bits, use #RD_SH_MEM_EP_BIT_MASK_FRAME_METADATA_FLAG and
          #RD_SH_MEM_EP_SHIFT_FRAME_METADATA_FLAG

        All other bits are reserved; the spf sets them to 0.

        When frame metadata is available, num_frames of consecutive instances of
        %data_event_rd_sh_mem_ep_metadata_t
         start at the buffer address
        (see <b>Buffer format</b>). */

   uint32_t                  num_frames;
   /**< Number of data frames in the buffer. */
}
#include "spf_end_pack.h"
;

/* Structure DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE */
typedef struct data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_t data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_t;

#include "spf_begin_pack.h"

/* Payload of the metadata that can be put in the data read buffer.
*/
struct data_event_rd_sh_mem_ep_metadata_t
{
   uint32_t          offset;
   /**< Offset from the buffer address in %data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_t to
        the frame associated with the metadata.

        @values > 0 */

   uint32_t          frame_size;
   /**< Size of each frame in bytes (E.g. encoded frame size).

        @values > 0 */

   uint32_t          pcm_length;
   /**< Number of PCM samples per channel corresponding to each frame_size
    * (E.g. number of PCM samples per channel used for encoding a frame).

      This field is always set to zero as there's no use case that needs it.

        @values = 0 */

   uint32_t          timestamp_lsw;
   /**< Lower 32 bits of the 64-bit session time in microseconds of the
        first sample in the frame. */

   uint32_t          timestamp_msw;
   /**< Upper 32 bits of the 64-bit session time in microseconds of the
        first sample in the frame.
    */

   uint32_t          flags;
   /**< Frame flags.

        @values{for bit 31}
        - 1 -- Timestamp is valid
        - 0 -- Timestamp is not valid
        - To set this bit, use #RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG and
        RD_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG

        All other bits are reserved; the spf sets them to 0. */
}
#include "spf_end_pack.h"
;

/* Structure for metadata that can be put in the data read buffer. */
typedef struct data_event_rd_sh_mem_ep_metadata_t data_event_rd_sh_mem_ep_metadata_t;

/**
 * Data command to send an empty buffer to the shared memory end point module.
 * RD_SHARED_MEM_EP writes data and metadata to this buffer & client reads.
 *
 * This command can be used to read PCM, raw compressed as well as packetized streams.
 *
 * DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2 command response, once buffer is filled
 */
#define DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2                         0x0400100B

#include "spf_begin_pack.h"
struct data_cmd_rd_sh_mem_ep_data_buffer_v2_t
{
   uint32_t data_buf_addr_lsw;
   /**< Lower 32 bits of the address of the data buffer */

   uint32_t data_buf_addr_msw;
   /**< Upper 32 bits of the address of the data buffer .

        The data buffer address for each frame must be a valid address
        that was mapped via #APM_CMD_SHARED_MEM_MAP_REGIONS.
        The 64-bit number formed by data_buf_addr_lsw and data_buf_addr_msw must be
        aligned to the cache-line of the processor where spf runs (64-byte alignment for Hexagon).

        @tblsubhd{For a 32-bit shared memory address} This data_buf_addr_msw field
        must be set to 0.

        @tblsubhd{For a 36-bit address} Bits 31 to 4 of this
        data_buf_addr_msw field must be set to 0. */

   uint32_t data_mem_map_handle;
   /**< Unique identifier for the shared memory address corresponding to data buffer.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t data_buf_size;
   /**< Number of bytes available for the spf to write data. The
        first byte starts at the specified data buffer address.

        @values @ge 0 */

   uint32_t md_buf_addr_lsw;
   /**< Lower 32 bits of the address of the metadata buffer */

   uint32_t md_buf_addr_msw;
   /**< Upper 32 bits of the address of the metadata buffer .

        The metadata buffer address for each frame must be a valid address
        that was mapped via #APM_CMD_SHARED_MEM_MAP_REGIONS.
        The 64-bit number formed by md_buf_addr_lsw and md_buf_addr_msw must be
        aligned to the cache-line of the processor where spf runs (64-byte alignment for Hexagon).

        @tblsubhd{For a 32-bit shared memory address} This md_buf_addr_msw field
        must be set to 0.

        @tblsubhd{For a 36-bit address} Bits 31 to 4 of this
        md_buf_addr_msw field must be set to 0. */

   uint32_t md_mem_map_handle;
   /**< Unique identifier for the shared memory address corresponding to metadata buffer.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t md_buf_size;
   /**< Number of bytes available for the spf to write metadata. The
        first byte starts at the specified metadata buffer address.

        @values @ge 0 */

}
#include "spf_end_pack.h"
;

/** Structure for DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 */
typedef struct data_cmd_rd_sh_mem_ep_data_buffer_v2_t data_cmd_rd_sh_mem_ep_data_buffer_v2_t;

/**
 *  Indicates that the referenced buffer has been filled and
 *  is available to the client for reading.
 *
 *  This is response to DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2
 *
 */
#define DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2                0x05001005


#include "spf_begin_pack.h"
struct data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t
{
   uint32_t                data_status;
   /**< Status message for data buffer (error code).

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */

   uint32_t                data_buf_addr_lsw;
   /**< Lower 32 bits of the address of the data buffer being returned. */

   uint32_t                data_buf_addr_msw;
   /**< Upper 32 bits of the data address of the buffer being returned.

        The valid, mapped, 64-bit address is the same address that
        the client provides in #DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2. */

   uint32_t                 data_mem_map_handle;
   /**< Unique identifier for the shared memory address corresponding to data buffer

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t                 data_size;
   /**< Total size of the data frames in bytes.

        @values @ge 0  */

   uint32_t                 timestamp_lsw;
   /**< Lower 32 bits of the 64-bit session time in microseconds of the
        first sample in the data buffer. */

   uint32_t                 timestamp_msw;
   /**< Upper 32 bits of the 64-bit session time in microseconds of the
        first sample in the data buffer.

        the 64bit timestamp must be interpreted as a signed number.

        Source of the timestamp depends on the source feeding data to this module.
      */

   uint32_t                 flags;
   /**< Bit field of flags.

        @values{for bit 31}
        - 1 -- Timestamp is valid
        - 0 -- Timestamp is invalid
        - To set this bit, use #RD_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG and
        RD_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG

        All other bits are reserved; the spf sets them to 0.
    */

   uint32_t                num_frames;
   /**< Number of data frames in the data buffer. */

   uint32_t                md_status;
   /**< Status message for metadata buffer(error code).

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */

   uint32_t                md_buf_addr_lsw;
   /**< Lower 32 bits of the address of the metadata buffer being returned. */

   uint32_t                md_buf_addr_msw;
   /**< Upper 32 bits of the data address of the metadata buffer being returned.

        The valid, mapped, 64-bit address is the same address that
        the client provides in #DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2. */

   uint32_t                md_mem_map_handle;
   /**< Unique identifier for the shared memory address corresponding to metadata buffer

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t                md_size;
   /**< Total size of the metadata frames in bytes.

        @values @ge 0  */
}
#include "spf_end_pack.h"
;

/* Structure DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2 */
typedef struct data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t data_cmd_rsp_rd_sh_mem_ep_data_buffer_done_v2_t;

/**
 * Media format sent from this module to the client.
 *
 * Payload media_format_t
 *
 * Event must be registered with APM_CMD_REGISTER_MODULE_EVENTS
 */
#define DATA_EVENT_ID_RD_SH_MEM_EP_MEDIA_FORMAT                        0x06001000

/**
    EOS event sent from this module to the client.
    This serves as a discontinuity marker.

    Event must be registered with APM_CMD_REGISTER_MODULE_EVENTS
*/
#define DATA_EVENT_ID_RD_SH_MEM_EP_EOS                                 0x06001001

#include "spf_begin_pack.h"
struct data_event_rd_sh_mem_ep_eos_t
{
   uint32_t    eos_reason;
   /**< EoS raised due to one of the following discontinuities
    * - pause
    * - other */
}
#include "spf_end_pack.h"
;

typedef struct data_event_rd_sh_mem_ep_eos_t data_event_rd_sh_mem_ep_eos_t;

/**
 * Input port ID of the Read Shared Memory EP
 */
#define PORT_ID_RD_SHARED_MEM_EP_INPUT                            0x2

/**
 * Output port ID of the Read Shared Memory EP
 * This Port is connected only in OFFLOAD(MDF) use-cases
 */
#define PORT_ID_RD_SHARED_MEM_EP_OUTPUT                            0x1

/**
 * ID of the Read Shared Memory End-Point Module
 *
 * This module has only one static input port with ID 2
 *
 *
 * Supported Input Media Format:
 *    - Any
 */
#define MODULE_ID_RD_SHARED_MEM_EP                                0x07001001
/**
    @h2xmlm_module         {"MODULE_ID_RD_SHARED_MEM_EP", MODULE_ID_RD_SHARED_MEM_EP}
    @h2xmlm_displayName    {"Read Shared Memory EndPoint"}
    @h2xmlm_description    {
                            This module is used to read data from spf into the host through packet exchange mechanism.
                            For regular use-case, this module has only one static input port with ID 2.
                            For MDF use-cases where the module is automatically inserted by the ARCT,
                            this module support one static output port with ID 1 and one static input port with ID 2.
                            }
    @h2xmlm_offloadInsert       { RD_EP }
    @h2xmlm_dataInputPorts      { IN  = PORT_ID_RD_SHARED_MEM_EP_INPUT}
    @h2xmlm_dataOutputPorts     { OUT = PORT_ID_RD_SHARED_MEM_EP_OUTPUT}
    @h2xmlm_dataMaxInputPorts   {1}
    @h2xmlm_dataMaxOutputPorts  {1}
    @h2xmlm_supportedContTypes { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable       {false}
    @h2xmlm_stackSize           { 1024 }
    @{                     <-- Start of the Module -->

*/

/**
 * Special value of num_frames_per_buffer to indicate that as many buffer need to be filled as possible.
 */
#define RD_SH_MEM_NUM_FRAMES_IN_BUF_AS_MUCH_AS_POSSIBLE               0

/*==============================================================================
   Param ID
==============================================================================*/

/**
   Configuration of the Read Shared Memory Module.
*/
#define PARAM_ID_RD_SH_MEM_CFG                                       0x08001007

/** Definition of a metadata control flags,  encoder frame info flag bitmask. */
#define RD_EP_CFG_MD_CNTRL_FLAGS_BIT_MASK_ENABLE_ENCODER_FRAME_MD AR_NON_GUID(0x00000001)

/** Definition of a metadata control flags,  encoder frame info shift value. */
#define RD_EP_CFG_MD_CNTRL_FLAGS_SHIFT_ENABLE_ENCODER_FRAME_MD 0

/** Definition of a metadata control flags, enable media format metadata flag bitmask. */
#define RD_EP_CFG_MD_CNTRL_FLAGS_BIT_MASK_ENABLE_MEDIA_FORMAT_MD AR_NON_GUID(0x00000002)

/** Definition of a metadata control flags,   enable media format metadata shift value. */
#define RD_EP_CFG_MD_CNTRL_FLAGS_SHIFT_ENABLE_MEDIA_FORMAT_MD 1

/*==============================================================================
   Param structure definitions
==============================================================================*/

/** @h2xmlp_parameter   {"PARAM_ID_RD_SH_MEM_CFG", PARAM_ID_RD_SH_MEM_CFG}
    @h2xmlp_description {Parameter for setting the configuration of read shared memory end point module.\n }
    @h2xmlp_toolPolicy  {Calibration} */
#include "spf_begin_pack.h"
struct param_id_rd_sh_mem_cfg_t
{
   uint32_t       num_frames_per_buffer;
   /**< @h2xmle_description {The number of frames per buffer that need to be populated in the Read buffers.
                             It's an error if even one frame cannot be filled.
                             If zero, then as many frames are filled as possible (only integral number of frames).
                             If N frames cannot be filled but M can be (where M &lt; N), then buffer is released after M.}
        @h2xmle_default     {0}
        @h2xmle_range       {0..0xFFFFFFFF}
        @h2xmle_policy      {Basic}
   */

   uint32_t metadata_control_flags;
   /**< @h2xmle_description {Specifies the control flags for the metadata for the read shared memory
                             end-point module.}
        @h2xmle_default     {0}
        @h2xmle_range       {0..3}
        @h2xmle_policy      {Basic}


      @h2xmle_bitfield        {0x00000001}
      @h2xmle_default         {0}
      @h2xmle_bitName         {Bit_0_ENABLE_ENCODER_FRAME_MD}
      @h2xmle_rangeList       {"Disable"=0; "Enable"=1}
      @h2xmle_description     {Specifies the control to enable/disable the per frame encoder information
                               which is communicated using the metadata ID MODULE_CMN_MD_ID_ENCODER_FRAME_INFO }
      @h2xmle_bitfieldEnd

      @h2xmle_bitfield        {0x00000002}
      @h2xmle_default         {1}
      @h2xmle_bitName         {Bit_1_ENABLE_MEDIA_FORMAT_MD}
      @h2xmle_description     { Specifies the control to enable/disable the media format communication from SPF to
                                Client as metatdata, which is communicated using the metadata ID
                                MODULE_CMN_MD_ID_MEDIA_FORMAT If enabled, the media format would be communicated
                                as metadata in the read buffer.}
      @h2xmle_bitfieldEnd

      @h2xmle_bitfield        {0xfffffffC}
      @h2xmle_bitName         {Bit_31_2_Reserved}
      @h2xmle_description     {Reserved Bit[31:2]}
      @h2xmle_visibility      {hide}
      @h2xmle_bitfieldEnd
   */
}
#include "spf_end_pack.h"
;

/* Type definition for the above structure. */
typedef struct param_id_rd_sh_mem_cfg_t param_id_rd_sh_mem_cfg_t;


/** @}                     <-- End of the Module --> */


#endif // RD_SH_MEM_EP_API_H_
