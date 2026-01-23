#ifndef _ATS_FTS_H_
#define _ATS_FTS_H_
/**
*==============================================================================
* \file ats_fts.h
* \brief
*                  A T S  F T S  H E A D E R  F I L E
*
*     The File Transfer Service(FTS) header file contains all the
*     definitions necessary for ATS to handle requests that operate ACDB SW
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/
#include "ats_i.h"
#include "ar_osal_mutex.h"
/*-----------------------------------------------------------------------------
* Defines and Constants
*----------------------------------------------------------------------------*/
#define ATS_FTS_MAJOR_VERSION 0x1
#define ATS_FTS_MINOR_VERSION 0x0

#define FTS_MAX_FILE_COUNT 100

typedef struct fts_file_table_t FtsFileTable;
#include "acdb_begin_pack.h"
struct fts_file_table_t {
    ar_osal_mutex_t lock;
    ar_fhandle fhandle[FTS_MAX_FILE_COUNT];
}
#include "acdb_end_pack.h"
;

/* ---------------------------------------------------------------------------
* Public Functions
*-------------------------------------------------------------------------- */

/**
* \brief
*		The File Transfer Service IOCTL
* \param [in] svc_cmd_id: The command to be issued
* \param [in] cmd_buf: Pointer to the command structure.
* \param [in] cmd_buf_size: Size of the command structure
* \param [out] rsp_buf: The response structre
* \param [in] rsp_buf_size: The size of the response
* \param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer
* \return 0 on success, non-zero on failure
*/
int32_t ats_fts_ioctl(
    uint32_t svc_cmd_id,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t *rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled
);

/**
* \brief
*		Initializes the file transfer service to allow interaction between
*		ACDB SW and and QST clients.
* \return AR_EOK, AR_EFAILED, AR_EHANDLE
*/
int32_t ats_fts_init(void);

/**
* \brief
*		Deinitializes the file transfer service to allow interaction between
*		ACDB SW and and QST clients.
* \return AR_EOK, AR_EFAILED, AR_EHANDLE
*/
int32_t ats_fts_deinit(void);
#endif /*_ATS_FTS_H_*/