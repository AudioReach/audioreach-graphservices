#ifndef __ACDB_INIT_UTILITY_H__
#define __ACDB_INIT_UTILITY_H__
/**
*=============================================================================
* \file acdb_init_utility.h
*
* \brief
*		Contains utility fucntions for ACDB SW initialiation. This inclues
*		initializaing the ACDB Data and ACDB Delta Data files.
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

#include "acdb.h"
#include "acdb_utility.h"
#include "acdb_parser.h"
/* ---------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 *--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

typedef struct acdb_init_util_file_properties_t
{
    /**< Treat ::file_access as function input or output */
    AcdbFunctionIO file_access_io_flag;
    /**< The file permissions specifier. See ar_osal_file_io.h */
    uint32_t file_access;
    /**< The size of the file */
    uint32_t file_size;
}acdb_init_util_file_properties_t;

typedef struct _acdb_init_util_delta_info_t AcdbInitUtilDeltaInfo;
struct _acdb_init_util_delta_info_t
{
    acdb_init_util_file_properties_t properties;
    /**< The length of the path */
    //uint32_t path_length;
    ///**<  A pointer to a null terminated file system path (directory or file) */
    //char_t *path;
    acdb_path_t delta_path;
};

/* ---------------------------------------------------------------------------
 * Function Declarations and Documentation
 *--------------------------------------------------------------------------- */

#define ACDB_UTILITY_INIT_SUCCESS 0
#define ACDB_UTILITY_INIT_FAILURE -1

void AcdbLogSwVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl);

void AcdbLogDeltaSwVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl);

void AcdbLogDeltaFileVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl);

void AcdbLogFileInfo(acdb_header_v1_t* header);

int32_t AcdbInitUtilGetFileData(const char_t* fname, ar_fhandle* fhandle,
    acdb_buffer_t* in_mem_file);
/**
*	\brief
*		Delete delta acdb file for existing acdb file
*
*	\param[in] acdb_file_path: The null terminated *.acdb file path string
*	\param[in] acdb_file_path_length: The length of the acdb file path
*	\param[in] delta_path: The delta path
*	\return 0 on success and non-zero otherwise
*
*   \sa
*   acdb_init_utility
*/
int32_t AcdbInitUtilDeleteDeltaFileData(
    const char_t* acdb_file_path, uint32_t acdb_file_path_length, acdb_path_t* delta_dir);

int32_t AcdbInitUtilDeleteDeltaFileData2(acdb_path_t* delta_file);


/**
*	\brief
*		Retrieves basic delta file properties such as file permissions,
*       file size, file name.
*
*       Callee is responsible for freeing memory associated with info->path
*       Callee must specify info->file_access when info->file_access_io_flag
*       is set to ACDB_FUNC_IO_IN
*       Callee must set info->file_access_io_flag to ACDB_FUNC_IO_OUT
*       to retrieve the file access specifier
*
*
*	\param[in] acdb_file_path: The null terminated *.acdb file path string
*	\param[in] acdb_file_path_length: The length of the acdb file path
*	\param[in] delta_path: The delta path
*	\param[out] info: delta file information returned after the function call
*	\return 0 on success and non-zero otherwise
*/
int32_t AcdbInitUtilGetDeltaInfo(
    const char_t* acdb_file_path, uint32_t acdb_file_path_length,
    acdb_path_t* delta_directory, AcdbInitUtilDeltaInfo *info);

int32_t AcdbInitUtilGetDeltaInfo2(acdb_path_t* delta_file_path,
    acdb_init_util_file_properties_t* info);

/**
*	\brief
*		Opens the delta file and retrieves the file handle
*
*	\param[in] info: The null terminated *.acdb file path string
*	\param[in] acdb_file_path_length: The length of the acdb file path
*	\param[in] delta_path: The delta path
*	\param[out] delta_fhandle: The delta file handle
*	\return 0 on success and non-zero otherwise
*
*   \sa
*   acdb_init_utility
*/
int32_t AcdbInitUtilOpenDeltaFile(
    AcdbInitUtilDeltaInfo *info, ar_fhandle* delta_fhandle);

/**
*	\brief
*		Loads the acdb file from the file handle as a read only buffer
*
*   \param[in] fname: The acdb file name
*	\param[in] fhandle: The acdb file handle
*	\param[out] in_mem_file: The pointer to the read only buffer
*	\return AR_EOK on success and an error otherwise
*
*   \sa
*   acdb_init_utility
*/
int32_t AcbdInitLoadInMemFile(const char_t* fname, ar_fhandle fhandle, acdb_buffer_t* in_mem_file);

/**
*	\brief
*		Unloads an previously loaded acdb file and frees
*       any resources used by the readonly buffer
*
*	\param[in] in_mem_file: The pointer to the read only buffer
*	\return AR_EOK on success and an error otherwise
*
*   \sa
*   acdb_init_utility
*/
int32_t AcbdInitUnloadInMemFile(acdb_buffer_t* in_mem_file);
#endif /* __ACDB_INIT_UTILITY_H__ */
