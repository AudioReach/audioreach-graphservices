#ifndef __ACDB_DELTA_FILE_MGR_H__
#define __ACDB_DELTA_FILE_MGR_H__
/**
*=============================================================================
* \file acdb_delta_file_mgr.h
*
* \brief
*		This file contains the implementation of the delta acdb file manager
*		interfaces.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/
#include "ar_osal_types.h"
#include "acdb_delta_parser.h"
#include "acdb_file_mgr.h"

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

typedef enum _acdb_delta_data_persist_state {
    ACDB_DELTA_DATA_PERSIST_STATE_DISABLED = 0x0,
    ACDB_DELTA_DATA_PERSIST_STATE_ENABLED = 0x1
}AcdbDeltaPersistState;

enum AcdbDeltaDataCmds {
    ACDB_DELTA_DATA_CMD_INIT = 0x0,
    ACDB_DELTA_DATA_CMD_ADD_DATABASE,
    ACDB_DELTA_DATA_CMD_REMOVE_DATABASE,
    ACDB_DELTA_DATA_CMD_ENABLE_PERSISTENCE,
    ACDB_DELTA_DATA_CMD_RESET,
    ACDB_DELTA_DATA_CMD_GET_FILE_VERSION,
    ACDB_DELTA_DATA_CMD_INIT_HEAP,
    ACDB_DELTA_DATA_CMD_UPDATE_HEAP,
    ACDB_DELTA_DATA_CMD_SAVE,
    ACDB_DELTA_DATA_CMD_DELETE_ALL_FILES,
    ACDB_DELTA_DATA_CMD_GET_FILE_COUNT,
    ACDB_DELTA_DATA_CMD_SWAP_DELTA,
    ACDB_DELTA_DATA_CMD_IS_FILE_AT_PATH,
};

typedef struct _acdb_delta_data_swap_info_t AcdbDeltaDataSwapInfo;
struct _acdb_delta_data_swap_info_t
{
    /**< The file permissions specifier. See ar_osal_file_io.h */
    uint32_t file_access;
    /**< The index of the delta file in the delta file manager file list */
    uint32_t file_index;
    /**< The delta path to swap to */
    acdb_path_256_t path_info;
};

/* ---------------------------------------------------------------------------
* Class Definitions
*--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Function Declarations and Documentation
 *--------------------------------------------------------------------------- */

int32_t acdb_delta_data_is_persist_enabled(void);

int32_t acdb_delta_data_ioctl(uint32_t cmd_id,
void *req, uint32_t req_size,
void *rsp, uint32_t rsp_size);
#endif /* __ACDB_DELTA_FILE_MGR_H__ */

