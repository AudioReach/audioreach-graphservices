#ifndef __ACDB_FILE_MGR_H__
#define __ACDB_FILE_MGR_H__
/**
*=============================================================================
* \file acdb_file_mgr.h
*
* \brief
*		This file contains the definition of the acdb file manager
*		interfaces.
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
#include "acdb_context_mgr.h"
#include "acdb_types.h"

/* ---------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 *--------------------------------------------------------------------------- */

#define ACDB_MAX_ACDB_FILES 16
#define INF 4294967295U

#define PTR_ARG_COUNT(...) \
    ((uint32_t)(sizeof((const void*[]){ __VA_ARGS__ })/sizeof(const void*)))

//#define ACDB_GET_CHUNK_INFO(...) AcdbGetChunkInfo2(PTR_ARG_COUNT(__VA_ARGS__), __VA_ARGS__)
#define ACDB_GET_CHUNK_INFO(...) \
    acdb_fm_get_db_chunks(PTR_ARG_COUNT(__VA_ARGS__), __VA_ARGS__)

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

 /**<Specifies the command set for the ACDB File Manager*/
enum AcdbFileManCmd {
    /**< Initializes the file manager */
    ACDB_FILE_MAN_INIT = 0,
    /**< Adds a database to the file manager */
    ACDB_FILE_MAN_ADD_DATABASE,
    /**< Removes a database from the file manager */
    ACDB_FILE_MAN_REMOVE_DATABASE,
    /**< Releases all resources aquired by the file manager */
    ACDB_FILE_MAN_RESET,
    /**< Retrieves the *.acdb file name for the specified database */
    ACDB_FILE_MAN_GET_FILE_NAME,
    /**< Retrieves the virtual machine identifier using the *.acdb file path */
    ACDB_FILE_MAN_GET_VM_ID_FROM_FILE_NAME,
    /**< Retrieves loaded *.acdb and *.qwsp file information for the primary
    database (the database initialied through acdb_init(...)) */
    ACDB_FILE_MAN_GET_HOST_DATABASE_FILE_SET_INFO,
    /**< Retrieves loaded *.acdb and *.qwsp file information for all the
    databases initialied through acdb_init(..) and acdb_add_database(...)) */
    ACDB_FILE_MAN_GET_ALL_DATABASE_FILE_SETS,
    /**< Retrieves file data for the specified database file (*.qwsp or *.acdb) */
    ACDB_FILE_MAN_GET_DATABASE_FILE_SET,
    /**< Sets the writable path for the specified database */
    ACDB_FILE_MAN_SET_WRITABLE_PATH,
    /**< Gets the writable path from the specified database */
    ACDB_FILE_MAN_GET_WRITABLE_PATH
};

typedef enum _acdb_file_type_t AcdbFileType;
enum _acdb_file_type_t {
    ACDB_FILE_TYPE_UNKNOWN,
    ACDB_FILE_TYPE_DATABASE,
    ACDB_FILE_TYPE_WORKSPACE
};

typedef struct _acdb_file_man_file_info_t AcdbFileManFileInfo;
struct _acdb_file_man_file_info_t{
    /**< The character length of the file path */
    uint32_t path_length;
    /**< The file path string */
    char_t *path;
    /**< A file handle to the file */
    ar_fhandle file_handle;
    /**< The type of file */
    AcdbFileType file_type;
    /**< The index of the file */
    uint32_t file_index;
    /**< The in-memory file buffer */
    acdb_buffer_t file;
};

typedef struct acdb_file_man_database_files_t
{
    uint32_t num_files;
    AcdbFileManFileInfo *file_info[ACDB_MAX_FILE_ADD_LIMIT];
}acdb_file_man_data_files_t;

typedef struct acdb_file_man_context_handle_t {
    uint32_t vm_id;
    acdb_file_man_handle_t file_man_handle;
}acdb_file_man_context_handle_t;

typedef struct acdb_file_man_writable_path_info_t
{
    acdb_file_man_handle_t handle;
    acdb_path_t writable_path;
}acdb_file_man_writable_path_info_t;

typedef struct acdb_file_man_writable_path_info_256_t
{
    acdb_file_man_handle_t handle;
    acdb_path_256_t writable_path;
}acdb_file_man_writable_path_info_256_t;

typedef struct _acdb_file_man_get_file_data_req_t AcdbFileManGetFileDataReq;
struct _acdb_file_man_get_file_data_req_t
{
    uint32_t acdb_handle;
	uint32_t file_offset;
	uint32_t file_data_len;
	uint32_t file_name_len;
	uint8_t *file_name;
};

typedef struct _acdb_file_man_rsp_t AcdbFileManBlob;
struct _acdb_file_man_rsp_t
{
    /*Size of the blob*/
	uint32_t size;
    /*Number of bytes filled in the buffer*/
	uint32_t bytes_filled;
    /*The buffer that contains a data blob*/
	uint8_t *buf;
};

/* ---------------------------------------------------------------------------
* Function Declarations and Documentation
*--------------------------------------------------------------------------- */

int32_t acdb_fm_get_db_chunks(uint32_t count, ...);

int32_t acdb_fm_read_db_mem(acdb_file_man_handle_t handle,
    void* buffer, size_t read_size, uint32_t* offset);

int32_t acdb_fm_get_db_mem_ptr(acdb_file_man_handle_t handle,
    void** file_ptr, size_t data_size, uint32_t* offset);

int32_t acdb_fm_get_db_mem_ptr_2(acdb_file_man_handle_t handle,
    void** file_ptr, uint32_t offset);

int32_t acdb_file_man_ioctl(uint32_t cmd_id,
    void *req, uint32_t sz_req,
    void *rsp, uint32_t sz_rsp);

int32_t FileSeekRead(void* buffer, size_t read_size, uint32_t *offset);

int32_t FileManReadBuffer(void* buffer, size_t read_size, uint32_t *offset);

int32_t FileManGetFilePointer1(void** file_ptr, size_t data_size,
    uint32_t *offset);

int32_t FileManGetFilePointer2(void** file_ptr, uint32_t offset);

/* \brief
*      Reads x bytes of data at the specified offset from the database
*      cache and writes it to the provided destination buffer.
*
*      The handle_override will select which handle to use (either from the
*      context manager or the file manager)
*
* \param[in/out] req : The read/seek param
*
* \sa AcdbFmHandleOverride
* \return AR_EOK on success, non-zero otherwise
*/
int32_t FileManDbReadAndSeek(acdb_fm_read_req_t* req);

/* \brief
*      Get a database cache memory pointer at the specified offset and
*      update the offset by data_size bytes.
*
*      The handle_override will select which handle to use (either from the
*      context manager or the file manager)
*
* \param[in/out] req : Parameters for retrieving the database memory pointer
*
* \sa AcdbFmHandleOverride
* \return AR_EOK on success, non-zero otherwise
*/
int32_t FileManGetDbPointerAndSeek(acdb_fm_file_ptr_req_t* req);

/* \brief
*      Get a database cache memory pointer at the specified offset.
*
*      The handle_override will select which handle to use (either from the
*      context manager or the file manager)
*
* \param[in/out] req : Parameters for retrieving the database memory pointer
*
* \sa AcdbFmHandleOverride
* \return AR_EOK on success, non-zero otherwise
*/
int32_t FileManGetDbPointer(acdb_fm_file_ptr_req_t* req);

int32_t FileManReadFileToBuffer(const char_t* fname, size_t *fsize,
    uint8_t *fbuffer, uint32_t fbuffer_size);

int32_t AcdbFileManGetAcdbDirectoryPath(acdb_path_256_t** path_info);

#endif /* __ACDB_FILE_MGR_H__ */
