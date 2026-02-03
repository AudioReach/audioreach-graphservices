#ifndef __ACDB_INIT_H__
#define __ACDB_INIT_H__
/**
*=============================================================================
* \file acdb_init.h
*
* \brief
*		Handles the initialization and de-initialization of ACDB SW.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

/* ---------------------------------------------------------------------------
 * Include Files
 *--------------------------------------------------------------------------- */
#include "ar_osal_types.h"
#include "acdb_file_mgr.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_types.h"

/* ---------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 *--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef enum acdb_init_ioctl_cmd_t
{
    /* Initializes all the ACDB SW layers */
    ACDB_INIT_CMD_INIT = 0x0,
    /* Adds an ACDB file set to the database and returns a acdb_handle_t for
     * the added database. A file set contains a *.qwsp and one or more
     * .acdb files. The number of file in a set is determined by the macro
     * ACDB_MAX_FILE_ADD_LIMIT */
    ACDB_INIT_CMD_ADD_DATABASE,
    /* Removes a database using the acdb_handle_t */
    ACDB_INIT_CMD_REMOVE_DATABASE,
    /* Releases resources in all ACDB SW layers */
    ACDB_INIT_CMD_RESET,
}acdb_init_ioctl_cmd_t;

typedef struct acdb_init_database_paths_t
{
    uint32_t num_files;
    acdb_path_t acdb_data_files[ACDB_MAX_FILE_ADD_LIMIT];
    acdb_path_t writable_path;
}acdb_init_database_paths_t;

/* ---------------------------------------------------------------------------
 * Function Declarations and Documentation
 *--------------------------------------------------------------------------- */

int32_t acdb_init_ioctl(uint32_t cmd_id,
    void* req, uint32_t sz_req,
    void* rsp, uint32_t sz_rsp);

#endif /* __ACDB_INIT_H__ */
