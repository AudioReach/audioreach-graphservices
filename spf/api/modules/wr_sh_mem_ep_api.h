/**
 * \file wr_sh_mem_ep_api.h
 * \brief
 *  	 This file contains Shared mem module APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef WR_SH_MEM_EP_API_H_
#define WR_SH_MEM_EP_API_H_

/*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "ar_defs.h"
#include "common_enc_dec_api.h"
#include "ar_guids.h"

/**
  @h2xml_title1          {Write Shared Memory End Point Module API}
  @h2xml_title_agile_rev {Write Shared Memory End Point Module API}
  @h2xml_title_date      {August 13, 2018}
*/

/**
   @h2xmlx_xmlNumberFormat {int}
*/
/**
 * Data command to write a buffer to the shared memory end point module.
 * The client writes to this buffer and WR_SHARED_MEM_EP reads.
 *
 * The command can be used for PCM, raw compressed raw bit streams as well as packetized streams.
 * Before issuing this command the graph must be opened and a media format issued (command or data).
 *
 * for PCM, the buffer must contain same number of samples on all channels.
 *
 * Once the buffer is consumed,  DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE event is raised by the module.
 *
 */
#define DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER             0x04001000

/** Definition of a timestamp valid flag bitmask. */
#define WR_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG    AR_NON_GUID(0x80000000)

/** Definition of a timestamp valid flag shift value. */
#define WR_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG       31

/** Definition of the last buffer flag bitmask.
*/
#define WR_SH_MEM_EP_BIT_MASK_LAST_BUFFER_FLAG        AR_NON_GUID(0x40000000)

/** Definition of the last buffer flag shift value.
*/
#define WR_SH_MEM_EP_SHIFT_LAST_BUFFER_FLAG           30

/** Definition of the shift value for the timestamp continue flag.
*/
#define WR_SH_MEM_EP_BIT_MASK_TS_CONTINUE_FLAG        AR_NON_GUID(0x20000000)

/** Definition of the shift value for the timestamp continue flag.
*/
#define WR_SH_MEM_EP_SHIFT_TS_CONTINUE_FLAG           29

/** Definition of an End of Frame (EOF) flag bitmask. */
#define WR_SH_MEM_EP_BIT_MASK_EOF_FLAG                AR_NON_GUID(0x00000010)

/** Definition of an EOF flag shift value. */
#define WR_SH_MEM_EP_SHIFT_EOF_FLAG                   4

#include "spf_begin_pack.h"
struct data_cmd_wr_sh_mem_ep_data_buffer_t
{
   uint32_t buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer containing the data */

   uint32_t buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer containing the data.

        The 64 bit buffer address must be a valid address
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
   /**< Number of valid bytes available in the buffer for processing. The
        first byte starts at the buffer address. */

   uint32_t timestamp_lsw;
   /**< Lower 32 bits of the 64-bit timestamp in microseconds of the
        first buffer sample. */

   uint32_t timestamp_msw;
   /**< Upper 32 bits of the 64-bit timestamp in microseconds of the
        first buffer sample.

        The 64-bit number of interpreted as signed number. */

   uint32_t flags;
   /**< Bitfield of flags.

        @values{for bit 31}
        - 1 -- Valid timestamp
        - 0 -- Invalid timestamp
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG and
          #WR_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG

        @values{for bit 30}
        - 1 -- Last buffer
        - 0 -- Not the last buffer
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_LAST_BUFFER_FLAG and
          #WR_SH_MEM_EP_SHIFT_LAST_BUFFER_FLAG

        @values{for bit 29}
        - 1 -- Continue the timestamp from the previous buffer
        - 0 -- Timestamp of the current buffer is not related to the timestamp
               of the previous buffer
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_TS_CONTINUE_FLAG and
          #WR_SH_MEM_EP_SHIFT_TS_CONTINUE_FLAG

        @values{for bit 4 (end-of-frame flag)}
        - 1 -- End of the frame
        - 0 -- Not the end of frame, or this information is not known
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_EOF_FLAG as the bitmask and
          #WR_SH_MEM_EP_SHIFT_EOF_FLAG

        All other bits are reserved; clients must set them to 0.

        @tblsubhd{If bit 31=0 and bit 29=1}
        The timestamp of the first sample in this buffer continues from the
        timestamp of the last sample in the previous buffer.

        The samples in the current buffer do not have a valid timestamp in
        the following situations:
        - If there is no previous buffer (this buffer is the first
          buffer sent after opening & starting the graph or after a flush operation)
        - If the previous buffer does not have a valid timestamp

        In these cases, the samples in the current buffer are played out as
        soon as possible.

        @tblsubhd{If bit 31=0 and bit 29=0}
        No timestamp is associated with the first sample in this buffer. The
        samples are played out as soon as possible.

        @tblsubhd{If bit 31=1 and bit 29 is ignored}
        The timestamp specified in this payload is honored.

        @tblsubhd{If bit 30=0}
        This buffer is not the last buffer. This case is useful
        in removing trailing samples in gapless use cases.

        @contcell
        @tblsubhd{For bit 4}
        The client can set this end-of-frame flag for every buffer sent in
        which the last byte is the end of a frame. If this flag is set, the
        buffer can contain data from multiple frames, but it must always end
        at a frame boundary. Restrictions allow the spf to detect an end of
        frame without requiring additional processing. */
}
#include "spf_end_pack.h"
;

/** Structure for DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER */
typedef struct data_cmd_wr_sh_mem_ep_data_buffer_t data_cmd_wr_sh_mem_ep_data_buffer_t;

/**
 *  Indicates that the referenced buffer has been fully consumed and
 *  is again available to the client.
 */
#define DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE    0x05001000

#include "spf_begin_pack.h"
struct data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_t
{
   uint32_t buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer being returned. */

   uint32_t buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer being returned.

        The valid, mapped, 64-bit address is the same address that
        the client provides in #DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER. */

   uint32_t mem_map_handle;
   /**< Unique identifier for the shared memory address.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t status;
   /**< Status message (error code) that indicates whether the referenced
        buffer has been successfully consumed.

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */
}
#include "spf_end_pack.h"
;

/* Structure DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE */
typedef struct data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_t data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_t;


/**
 * Data command to write a buffer and associated metadata  to the shared memory end point module.
 * The client writes data and metadata to this buffer and WR_SHARED_MEM_EP reads.
 *
 * The command can be used for PCM, raw compressed raw bit streams as well as packetized streams.
 * Before issuing this command the graph must be opened and a media format issued (command or data).
 *
 * for PCM, the buffer must contain same number of samples on all channels.
 *
 * The Metadata should be filled in the specified format at the corresponding address
 *
 * Once the buffer is consumed,  DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE event is raised by the module.
 *
 */
#define DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2             0x0400100A

#include "spf_begin_pack.h"
struct data_cmd_wr_sh_mem_ep_data_buffer_v2_t
{
   uint32_t data_buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer containing the data */

   uint32_t data_buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer containing the data.

        The 64 bit buffer address must be a valid address
        that was mapped via #APM_CMD_SHARED_MEM_MAP_REGIONS.
        The 64-bit number formed by data_buf_addr_lsw and data_buf_addr_msw must be
        aligned to the cache-line of the processor where spf runs (64-byte alignment for Hexagon).

        @tblsubhd{For a 32-bit shared memory address} This data_buf_addr_msw field
        must be set to 0.

        @tblsubhd{For a 36-bit address} Bits 31 to 4 of this
        data_buf_addr_msw field must be set to 0. */

   uint32_t data_mem_map_handle;
   /**< Unique identifier for the shared memory corresponding to data buffer address

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t data_buf_size;
   /**< Number of valid bytes available in the buffer for processing. The
        first byte starts at the data buffer address. */

   uint32_t timestamp_lsw;
   /**< Lower 32 bits of the 64-bit timestamp in microseconds of the
        first data buffer sample. */

   uint32_t timestamp_msw;
   /**< Upper 32 bits of the 64-bit timestamp in microseconds of the
        first data buffer sample.

        The 64-bit number of interpreted as signed number. */

   uint32_t flags;
   /**< Bitfield of flags.

        @values{for bit 31}
        - 1 -- Valid timestamp
        - 0 -- Invalid timestamp
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_TIMESTAMP_VALID_FLAG and
          #WR_SH_MEM_EP_SHIFT_TIMESTAMP_VALID_FLAG

        @values{for bit 30}
        - 1 -- Last data buffer
        - 0 -- Not the last data buffer
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_LAST_BUFFER_FLAG and
          #WR_SH_MEM_EP_SHIFT_LAST_BUFFER_FLAG

        @values{for bit 29}
        - 1 -- Continue the timestamp from the previous data buffer
        - 0 -- Timestamp of the current buffer is not related to the timestamp
               of the previous data buffer
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_TS_CONTINUE_FLAG and
          #WR_SH_MEM_EP_SHIFT_TS_CONTINUE_FLAG

        @values{for bit 4 (end-of-frame flag)}
        - 1 -- End of the frame
        - 0 -- Not the end of frame, or this information is not known
        - To set this bit, use #WR_SH_MEM_EP_BIT_MASK_EOF_FLAG as the bitmask and
          #WR_SH_MEM_EP_SHIFT_EOF_FLAG

        All other bits are reserved; clients must set them to 0.

        @tblsubhd{If bit 31=0 and bit 29=1}
        The timestamp of the first sample in this data buffer continues from the
        timestamp of the last sample in the previous data buffer.

        The samples in the current data buffer do not have a valid timestamp in
        the following situations:
        - If there is no previous data buffer (this buffer is the first
          data buffer sent after opening & starting the graph or after a flush operation)
        - If the previous data buffer does not have a valid timestamp

        In these cases, the samples in the current data buffer are played out as
        soon as possible.

        @tblsubhd{If bit 31=0 and bit 29=0}
        No timestamp is associated with the first sample in this data buffer. The
        samples are played out as soon as possible.

        @tblsubhd{If bit 31=1 and bit 29 is ignored}
        The timestamp specified in this payload is honored.

        @tblsubhd{If bit 30=0}
        This buffer is not the last data buffer. This case is useful
        in removing trailing samples in gapless use cases.

        @contcell
        @tblsubhd{For bit 4}
        The client can set this end-of-frame flag for every data buffer sent in
        which the last byte is the end of a frame. If this flag is set, the
        data buffer can contain data from multiple frames, but it must always end
        at a frame boundary. Restrictions allow the spf to detect an end of
        frame without requiring additional processing. */

   uint32_t md_buf_addr_lsw;
   /**< Lower 32 bits of the address of the buffer containing the metadata */

   uint32_t md_buf_addr_msw;
   /**< Upper 32 bits of the address of the buffer containing the metadata.

        The 64 bit buffer address must be a valid address
        that was mapped via #APM_CMD_SHARED_MEM_MAP_REGIONS.
        The 64-bit number formed by md_buf_addr_lsw and md_buf_addr_msw must be
        aligned to the cache-line of the processor where spf runs (64-byte alignment for Hexagon).

        @tblsubhd{For a 32-bit shared memory address} This md_buf_addr_msw field
        must be set to 0.

        @tblsubhd{For a 36-bit address} Bits 31 to 4 of this
        md_buf_addr_msw field must be set to 0. */

   uint32_t md_mem_map_handle;
   /**< Unique identifier for the shared memory corresponding to metadata buffer address.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS.*/

   uint32_t md_buf_size;
   /**< Number of valid bytes available in the metadata buffer for processing.
    * The first byte starts at the metadata buffer address.
    * */
}
#include "spf_end_pack.h"
;

/** Structure for DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2 */
typedef struct data_cmd_wr_sh_mem_ep_data_buffer_v2_t data_cmd_wr_sh_mem_ep_data_buffer_v2_t;

/**
 *  Indicates that the referenced write buffer has been fully consumed and
 *  is again available to the client.
 */
#define DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2    0x05001004

#include "spf_begin_pack.h"
struct data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_v2_t
{
   uint32_t data_buf_addr_lsw;
   /**< Lower 32 bits of the address of the data buffer being returned. */

   uint32_t data_buf_addr_msw;
   /**< Upper 32 bits of the address of the data buffer being returned.

        The valid, mapped, 64-bit data buffer address is the same address that
        the client provides in #DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2. */

   uint32_t data_mem_map_handle;
   /**< Unique identifier for the shared memory corresponding to data buffer address.

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t data_status;
   /**< Status message (error code) that indicates whether the referenced
        data buffer has been successfully consumed.

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */

   uint32_t md_buf_addr_lsw;
   /**< Lower 32 bits of the address of the metadata buffer being returned. */

   uint32_t md_buf_addr_msw;
   /**< Upper 32 bits of the address of the metadata buffer being returned.

        The valid, mapped, 64-bit metadata buffer address is the same address that
        the client provides in #DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2. */

   uint32_t md_mem_map_handle;
   /**< Unique identifier for the shared memory corresponding to metadata buffer address

        The spf returns this handle through #APM_CMD_RSP_SHARED_MEM_MAP_REGIONS. */

   uint32_t md_status;
   /**< Status message (error code) that indicates whether the referenced
        metadata buffer has been successfully consumed.

        @values Refer to @xrefcond{Q5,80-NF774-4,80-NA610-4} */
}
#include "spf_end_pack.h"
;

/* Structure DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2 */
typedef struct data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_v2_t data_cmd_rsp_wr_sh_mem_ep_data_buffer_done_v2_t;

/**
 *  Indicates an update to the media format, which applies to future buffers
    written to this stream.

    This command is accepted only when subgraph is in START state.

    Some decoders may not work without receiving either
    PARAM_ID_MEDIA_FORMAT or DATA_CMD_WR_SH_MEM_EP_MEDIA_FORMAT

    Payload is of type media_format_t
 */
#define DATA_CMD_WR_SH_MEM_EP_MEDIA_FORMAT         0x04001001

/**
 * Communicates an EoS marker, which indicates that the last buffer in a stream was delivered.
 *
 * Once the stream is received by another end point (E.g. hardware end point),
 * it raises DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED event.
 *
 * The token in the GPR payload is used as token in DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED for correlation.
 */
#define DATA_CMD_WR_SH_MEM_EP_EOS                  0x04001002

/**
 * EoS policy according to which last of the final end point raises the DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED
 * OR the last container which drops/renders the EoS raises the DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED event.
 *
 */
#define WR_SH_MEM_EP_EOS_POLICY_LAST               1


/**
 * EoS policy according to which each of the final EP raises the DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED
 * OR the each container which drop the EoS raises the DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED event.
 */
#define WR_SH_MEM_EP_EOS_POLICY_EACH                2

#include "spf_begin_pack.h"
struct data_cmd_wr_sh_mem_ep_eos_t
{
   uint32_t          policy;
   /**< Policy used to raise DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED
    *    WR_SH_MEM_EP_EOS_POLICY_LAST
    *    WR_SH_MEM_EP_EOS_POLICY_EACH */
}
#include "spf_end_pack.h"
;

/**
 * Structure for DATA_CMD_WR_SH_MEM_EP_EOS
 */
typedef struct data_cmd_wr_sh_mem_ep_eos_t data_cmd_wr_sh_mem_ep_eos_t;

/**
 * Indicates that DATA_CMD_WR_SH_MEM_EP_EOS has been received by the final end-point.
 * No more data is left to be rendered.
 *
 * Uses the same token as was sent in DATA_CMD_WR_SH_MEM_EP_EOS.
 *
 * the source port in the GPR packet will contain the SH MEM EP that received DATA_CMD_WR_SH_MEM_EP_EOS
 */
#define DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED          0x05001001

/**
 * Render status of EoS, where EoS message is rendered on final end device.
 */
#define WR_SH_MEM_EP_EOS_RENDER_STATUS_RENDERED       1
/**
 * Render status of EoS, where EoS message is dropped before it reached the final end device.
 */
#define WR_SH_MEM_EP_EOS_RENDER_STATUS_DROPPED        2

#include "spf_begin_pack.h"
struct data_cmd_rsp_wr_sh_mem_ep_eos_rendered_t
{
   uint32_t module_instance_id;
   /**< module instance id from which the DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED is being raised
    * Invalid (0) when dropped.  */

   uint32_t render_status;
   /**< Render status - 1 - Rendered. 2 - Dropped */
}
#include "spf_end_pack.h"
;


/** Structure for DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED */
typedef struct data_cmd_rsp_wr_sh_mem_ep_eos_rendered_t  data_cmd_rsp_wr_sh_mem_ep_eos_rendered_t;

/**
 * Output port ID of the Write Shared Memory EP
 */
#define PORT_ID_WR_SHARED_MEM_EP_OUTPUT               0x1

/**
 * Input port ID of the Write Shared Memory EP
 * This Port is connected only in OFFLOAD(MDF) use-cases
 */
#define PORT_ID_WR_SHARED_MEM_EP_INPUT               0x2

/**
 * ID of the Write Shared Memory End-Point Module
 *
 * This module has only one static output port with ID 1
 *
 * Supported Input Media Format:
 *    - Any
 */
#define MODULE_ID_WR_SHARED_MEM_EP                    0x07001000
/**
    @h2xmlm_module         {"MODULE_ID_WR_SHARED_MEM_EP", MODULE_ID_WR_SHARED_MEM_EP}
    @h2xmlm_displayName    {"Write Shared Memory EndPoint"}
    @h2xmlm_description    {
                            This module is used to write data to spf from the host through packet exchange mechanism.
                            For regular use-case, this module support only one static output port with ID 1
                            For MDF use-cases where the module is automatically inserted by the ARCT,
                            this module support one static output port with ID 1 and one static input port with ID 2.
                            }
    @h2xmlm_offloadInsert        { WR_EP }
    @h2xmlm_dataInputPorts       { IN = PORT_ID_WR_SHARED_MEM_EP_INPUT}
    @h2xmlm_dataOutputPorts      { OUT = PORT_ID_WR_SHARED_MEM_EP_OUTPUT}
    @h2xmlm_dataMaxInputPorts    { 1 }
    @h2xmlm_dataMaxOutputPorts   { 1 }
    @h2xmlm_supportedContTypes  { APM_CONTAINER_TYPE_GC }
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            { 1024 }
    @{                     <-- Start of the Module -->
    @h2xml_Select                {"media_format_t"}
    @h2xmlm_InsertParameter
    @}                     <-- End of the Module -->
*/

#endif // WR_SH_MEM_EP_API_H_
