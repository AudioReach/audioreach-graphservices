#ifndef CODEC_METADATA_API_H
#define CODEC_METADATA_API_H
/**
 *   \file codec_metadata_api.h
 * \brief
 *  	 This file contains codec related metadata IDs.
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

/** @h2xml_title1           {Metadata IDs}
    @h2xml_title_agile_rev  {Metadata IDs}
    @h2xml_title_date       {Apr 30 2019} */
/**
   @h2xmlx_xmlNumberFormat {int}
*/


/**
*  Metadata ID for Encoder frame info.
*/
#define MODULE_CMN_MD_ID_ENCODER_FRAME_INFO              0x0A001052


/* Payload of the metadata for encoder frame info,
*  that can be put in the read metadata buffer
 **/
#include "spf_begin_pack.h"
struct module_cmn_md_encoder_per_frame_info_t
{
   uint32_t          frame_size;
   /**< Size of each frame in bytes (E.g. encoded frame size).

        @values > 0 */

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

        All other bits are reserved; the spf sets them to 0.
     */
}
#include "spf_end_pack.h"
;

/* Structure for encoder frame info metadata */
typedef struct module_cmn_md_encoder_per_frame_info_t module_cmn_md_encoder_per_frame_info_t;


/**
*  Metadata ID for Codec.2.0 requirement.
*/

/** Metadata ID to specify the Start of the buffer
 *  This metadata has no payload.
 */
#define MODULE_CMN_MD_ID_BUFFER_START          0x0A001053


/* Payload of the metadata to specify the start of the buffer
 **/
#include "spf_begin_pack.h"
struct module_cmn_md_buffer_start_t
{
   uint32_t buffer_index_lsw;
   /** <
    *  Specifies the lower 32 bits of the 64-bit unique buffer index
    */

   uint32_t buffer_index_msw;
   /** <
    *  SSpecifies the higher 32 bits of the 64-bit unique buffer index
    */
}
#include "spf_end_pack.h"
;

/* Structure for Buffer Start metadata */
typedef struct module_cmn_md_buffer_start_t module_cmn_md_buffer_start_t;


/** Metadata ID to specify the end of the buffer
 */
#define MODULE_CMN_MD_ID_BUFFER_END            0x0A001054


/** Definition of metadata error status/result flag bitmask. */
#define MD_END_PAYLOAD_FLAGS_BIT_MASK_ERROR_RESULT                AR_NON_GUID(0x00000001)

/** Definition of metadata error status/result flag shift value. */
#define MD_END_PAYLOAD_FLAGS_SHIFT_ERROR_RESULT                   0

/** Definition of metadata error recovery done flag bitmask. */
#define MD_END_PAYLOAD_FLAGS_BIT_MASK_ERROR_RECOVERY_DONE         AR_NON_GUID(0x00000002)

/** Definition of metadata error status/result flag shift value. */
#define MD_END_PAYLOAD_FLAGS_SHIFT_ERROR_RECOVERY_DONE            1

/** Definition of metadata error result value. */
#define MD_END_RESULT_FAILED                                      1

/** Definition of metadata error result value. */
#define MD_END_RESULT_ERROR_RECOVERY_DONE                         1

/* Payload of the metadata to specify the end of the buffer
 **/
#include "spf_begin_pack.h"
struct module_cmn_md_buffer_end_t
{
   uint32_t buffer_index_lsw;
   /** <
    *  Specifies the lower 32 bits of the 64-bit unique buffer index
    */

   uint32_t buffer_index_msw;
   /** <
    *  Specifies the higher 32 bits of the 64-bit unique buffer index
    */

   uint32_t flags;
   /**< Field to specify any related information to from/to the client.
    *
    *   BIT_0 : specifies if any frame in the buffer has error
    *       0 : no error
    *       1 : at least one frame in the buffer has error
    *   BIT_1 : specifies if error recovery was done for any frame in the buffer
    *       0 : no error recovery
    *       1 : at least one frame in the buffer was recovered
    *
    *	Other bit field values are reserved for future use and must be set to 0
    */
}
#include "spf_end_pack.h"
;

/* Structure for Buffer End metadata */
typedef struct module_cmn_md_buffer_end_t module_cmn_md_buffer_end_t;


#ifdef __cplusplus
}
#endif /*__cplusplus*/


#endif /* CODEC_METADATA_API_H */
