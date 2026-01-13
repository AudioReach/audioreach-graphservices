#ifndef _TCPIP_GATEWAY_CMD_H_
#define _TCPIP_GATEWAY_CMD_H_
/**
*==============================================================================
*  \file tcpip_gateway_cmd.h
*  \brief
*                    T C P I P  G A T E W A Y  C M D
*                          H E A D E R  F I L E
*
*         This file contains definitions for server commands
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/
#include "ar_osal_types.h"

/* NOTE:
 * The commands in this file originate from ats_i.h. We cannot include
 * ats_i.h b/c it contains acdb.h which will require that you compile the AML
 * library. The ATS gateway server has no dependencies on ATS or AML libraries.
 */

 /*-----------------------------------------------------------------------------
 ** flag, page size, and buffer length definition for ats_main_buffer
 *----------------------------------------------------------------------------*/
#define ATS_BUFFER_LENGTH                   0x200000
#define ATS_HEADER_LENGTH                   8


 /* ATS Message formats
 * Request Format (for incoming messages)
 *
 * <--------- 4 bytes ----------->
 * +-----------------------------+
 * |  service id  |  command id  |
 * +-----------------------------+
 * |         data length         |
 * +_____________________________+
 * |                             |
 * |            data             |
 * |            ...              |
 * +~.-~.-~.-~.-~.-~.-~.-~.-~.-~.+
 *
 *
 * Response Format (outgoing messages)
 *
 * <-----------4bytes------------>
 * +-----------------------------+
 * |  service id  |  command id  |
 * +-----------------------------+
 * |         data length         |
 * +-----------------------------+
 * |            status           |
 * +_____________________________+
 * |                             |
 * |            data             |
 * |            ...              |
 * +~.-~.-~.-~.-~.-~.-~.-~.-~.-~.+
 */

#define ATS_SERVICE_COMMAND_ID_LENGTH       4
#define ATS_DATA_LENGTH_LENGTH              4
#define ATS_ERROR_CODE_LENGTH               4
#define ATS_ERROR_FRAME_LENGTH              12

#define ATS_SERVICE_COMMAND_ID_POSITION     0
#define ATS_DATA_LENGTH_POSITION            4
#define ATS_ACDB_BUFFER_POSITION            8

 /**< Extract the service id from the MSW of the 4byte service command id x*/
#define ATS_GET_SERVICE_ID(x) ((0xFFFF0000 & x))

/**< Defines command IDs for the Online Calibration service */
#define ATS_ONLINE_CMD_ID(x) ((0x4F4Eul << 16) | (0xFFFFul & x))
#define ATS_ONLINE_SERVICE_ID (0x4F4Eul << 16)

/** \addtogroup ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH
\{ */

/**
    Set the maximum buffer size to be used by ATS

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        There is no output structure; set this to NULL.
    \param[in] rsp_size
        There is no output structure; set this to 0.

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH ATS_ONLINE_CMD_ID(4)
/** \} */ /* end_addtogroup ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH */

#endif /*_TCPIP_GATEWAY_CMD_H_*/
