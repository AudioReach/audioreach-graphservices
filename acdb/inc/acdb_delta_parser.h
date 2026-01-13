#ifndef __ACDB_DELTA_PARSER_H__
#define __ACDB_DELTA_PARSER_H__
/**
*=============================================================================
* \file acdb_delta_parser.h
*
* \brief
*		The interface of the Acdb Delta Parser/Generator that handles parsing
*		and/or generating the ACDB Delta file.
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
#include "ar_osal_file_io.h"

#include "acdb.h"
#include "acdb_utility.h"
/* ---------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 *--------------------------------------------------------------------------- */

#define ACDB_DELTA_FILE_VERSION_MAJOR	0x00000001
#define ACDB_DELTA_FILE_VERSION_MINOR	0x00000000
#define ACDB_DELTA_FILE_REVISION        0x00000000

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

typedef struct acdb_delta_file_version_t
{
	uint32_t major;
	uint32_t minor;
	uint32_t revision;
	uint32_t cpl_info;
}acdb_delta_file_version_t;

//todo: possibly remove or make it external facing
typedef struct _acdb_delta_file_man_file_info_t AcdbDeltaFileManFileInfo;
struct _acdb_delta_file_man_file_info_t {
	uint32_t vm_id;
    /**< Index of the info structure in the delta file manager file list */
    uint32_t file_index;
    /**< Index of the associated acdb file in the acdb file manager file list */
    uint32_t acdb_file_index;
    /**< A flag indicating whether the delta file is updated */
	uint32_t is_updated;
    /**< A flag that determines the existance of the delta file */
	uint32_t exists;
    /**< The size of the delta file */
	uint32_t file_size;
    /**< File handle for the delta file */
	ar_fhandle file_handle;
    /**< The full delta file path */
	acdb_path_t delta_file_path;
    /**< Delta file version and type information */
	acdb_delta_file_version_t file_info;
};

typedef struct _acdb_delta_file_header_t AcdbDeltaFileHeader;
#include "acdb_begin_pack.h"
struct _acdb_delta_file_header_t {
	uint32_t delta_major;
	uint32_t delta_minor;
	uint32_t delta_revision;
	uint32_t acdb_major;
	uint32_t acdb_minor;
	uint32_t acdb_revision;
	uint32_t acdb_cpl_info;
	uint32_t file_data_size;
	uint32_t map_count;
}
#include "acdb_end_pack.h"
;

/* ---------------------------------------------------------------------------
 * Function Declarations and Documentation
 *--------------------------------------------------------------------------- */

int32_t acdb_delta_parser_is_file_valid(ar_fhandle fhandle, uint32_t file_size);

int32_t acdb_delta_parser_get_file_version(ar_fhandle fhandle, uint32_t file_size, acdb_delta_file_version_t* delta_finfo);

int32_t acdb_delta_parser_read_map(ar_fhandle fhandle, uint32_t *offset, acdb_delta_data_map_t *map);

int32_t acdb_delta_parser_write_file_header(ar_fhandle fhandle, acdb_delta_file_version_t* delta_finfo, uint32_t fdata_size, uint32_t map_count);

int32_t acdb_delta_parser_write_map(ar_fhandle fhandle, acdb_delta_data_map_t *map);

#endif /* __ACDB_DELTA_PARSER_H__ */
