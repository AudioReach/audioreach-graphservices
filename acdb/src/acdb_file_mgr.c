/**
*=============================================================================
* \file acdb_file_mgr.c
*
* \brief
*		This file contains the implementation of the acdb file manager
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

#include <stdarg.h>
#include "acdb_context_mgr.h"
#include "acdb_file_mgr.h"
#include "acdb_parser.h"
#include "acdb_init_utility.h"
#include "acdb_init.h"
#include "ar_osal_error.h"
#include "ar_osal_file_io.h"
#include "acdb_common.h"
#include "acdb_data_proc.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */

/**<
 * A File Manager macro that simplifies accessing the database info within the
 * File Manager context structure.
 *
 * This macro represents the database info at the current index set in
 * acdb_file_man_context.database_index
 *
 * NOTE: The acdb_file_man_context.database_index must me non-zero and initialized
 * before using this macro
 */
#define ACDB_FM_DB_INFO acdb_file_man_context \
.database_info[acdb_file_man_context.database_index]

/**<
 * A File Manager macro that simplifies accessing the database info within the
 * File Manager context structure.
 *
 * Specify the index of the database info to retrieve
 *
 * NOTE: This macro is mainly used in for loops when cycling through
 * databases info entries
 */
#define ACDB_FM_DB_INFO_AT_INDEX(index) acdb_file_man_context \
.database_info[index]

 /**<
  * A File Manager macro that simplifies accessing the workspace info within the
  * File Manager context structure.
  *
  * Specify the index of the workspace info to retrieve
  *
  * NOTE: This macro is mainly used in for loops when cycling through
  * workspace info entries
  */
#define ACDB_FM_WS_INFO_AT_INDEX(index) acdb_file_man_context \
.workspace_info[index]

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef enum {
    ACDB_FM_FILE_OP_OPEN,
    ACDB_FM_FILE_OP_CLOSE,
}AcdbFileManFileOp;

typedef enum {
    ACDB_PATH_TYPE_NONE = -1,
    ACDB_PATH_TYPE_QWSP_FILE = 0,
    ACDB_PATH_TYPE_ACDB_FILE,
    ACDB_PATH_TYPE_WRITEABLE_DIRECTORY,
    ACDB_PATH_TYPE_DELTA_DIRECTORY
} AcdbPathType;

/**< Indicates if AcdbFileManDbPathInfo or AcdbFileManDbPathInfoV2
should be used */
typedef enum {
    /**< Use  AcdbFileManDbPathInfo */
    ACDB_FM_DB_PATH_INFO_VERSION_1 = 1,
    /**< Use  AcdbFileManDbPathInfoV2 */
    ACDB_FM_DB_PATH_INFO_VERSION_2 = 2
}AcdbDatabasePathInfoVersion;

typedef struct _acdb_file_man_workspace_info_t AcdbFileManWorkspaceInfo;
struct _acdb_file_man_workspace_info_t {
    /**< The virtual machine id used by the database */
    uint32_t vm_id;
    /**< The workspace file handle */
    ar_fhandle file_handle;
    /**< The size of the workspace file */
    uint32_t file_size;
    /**< The path to the workspace file */
    acdb_path_256_t workspace_file;
};

typedef struct _acdb_file_man_database_info_t AcdbFileManDatabaseInfo;
struct _acdb_file_man_database_info_t {
    /**< The virtual machine id used by the database */
    uint32_t vm_id;
    /**< The database index */
    uint32_t file_index;
    /**< The databases file type */
    AcdbFileType file_type;
    /**< The file handle to the database */
    ar_fhandle file_handle;
    /**< The size of the database file */
    uint32_t database_cache_size;
    /**< A pointer to the database file cached in memory */
    void* database_cache;
    /**< The path to the database file */
    acdb_path_256_t database_file;
    /**< The path where the database files reside */
    acdb_path_256_t database_directory;
    /**< The path to the writable directory used for database operations */
    acdb_path_256_t writable_directory;
};

typedef struct _acdb_file_man_context_t AcdbFileManContext;
struct _acdb_file_man_context_t
{
    ar_osal_mutex_t file_man_lock;
    /**< The index of the database that the filemanager is
    currently pointing to */
    int32_t database_index;
    /**< The index of the newly added database */
    int32_t latest_database_index;
    /**< Number of databases being managed */
    int32_t database_count;
    /**< Number of workspace files being managed */
    int32_t workspace_count;
    /**< Maintains context info about each loaded database */
    AcdbFileManDatabaseInfo *database_info[ACDB_MAX_ACDB_FILES];
    /**< Maintains context info about each loaded database */
    AcdbFileManWorkspaceInfo *workspace_info[ACDB_MAX_ACDB_FILES];
};

typedef struct acdb_file_man_db_path_info_v2_t
{
    /**< The type of path (either a file or directory) */
    AcdbPathType path_type;
    /**< The size of the file. If path_type is a directory this
    should be zero */
    uint32_t file_size;
    /**< The length of the path (either file or directory)*/
    uint32_t path_length;
    /**< The path string */
    char_t *path;
}AcdbFileManDbPathInfoV2;

typedef struct acdb_file_man_db_path_info_t
{
    /**< The size of the file. If path_type is a directory this
    should be zero */
    uint32_t file_size;
    /**< The length of the path (either file or directory)*/
    uint32_t path_length;
    /**< The path string */
    char_t* path;
}AcdbFileManDbPathInfo;

/* ---------------------------------------------------------------------------
* Global Data Definitions
*--------------------------------------------------------------------------- */
static AcdbFileManContext acdb_file_man_context;

/* ---------------------------------------------------------------------------
* Static Variable Definitions
*--------------------------------------------------------------------------- */
int32_t AcdbFileManRemoveDatabase(acdb_file_man_handle_t* fm_handle);

/**
* \brief
*       1. Comparing Imports to Exports
*		    Checks for the existance of imports in the newly added
*           database compared to the exports in existing databases
*
*       2. Comparing Exports to Imports
*		    Checks for the existance of exports in the newly added
*           database compared to the imports in existing databases
*
*       If subgraphs are found between the new database and the
*       existing databases in 1. and 2. their GUIDs will be
*       compared. Validation fails if they do not match.
*
* \param[in] im_ex_shared_sg_property_id:
*   The imported or exported shared subgraph property ID
*       1. For option 1 this will be ACDB_GPROP_EXPORTED_SHARED_SUBGRAPHS.
*       2. For option 2 this will be ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS.
* \param[out] im_ex_shared_sg_property:
*   The imported or exports shared subgraph property
*       1. For option 1 this property will have data for
*           ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS.
*       2. For option 2 this property will have data for
*           ACDB_GPROP_EXPORTED_SHARED_SUBGRAPHS.
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbFileManValidateImExShSubgraphs(
    AcdbGlobalProperty im_ex_shared_sg_property_id,
    AcdbProperty* im_ex_shared_sg_property);

/* ---------------------------------------------------------------------------
* Function Declarations and Definitions
*--------------------------------------------------------------------------- */

int32_t AcdbFileManSetFileIndex(int32_t file_index)
{
    if (file_index < -1 || file_index > acdb_file_man_context.database_count)
        return AR_EBADPARAM;

    acdb_file_man_context.database_index = file_index;
    return AR_EOK;
}

int32_t AcdbFileManValidateImExShSubgraphs(
    AcdbGlobalProperty im_ex_shared_sg_property_id,
    AcdbProperty *im_ex_shared_sg_property)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo *new_db_info = NULL;
    AcdbFileManDatabaseInfo *existing_db_info_2 = NULL;
    AcdbSharedSubgraphGuidTable subgraph_guid_table = { 0 };
    AcdbSharedSubgraphDataGuid* subgraph_guid = NULL;
    uint8_t guid[ACDB_GUID_BYTE_LENGTH] = { 0 };

    if (IsNull(im_ex_shared_sg_property))
        return AR_EBADPARAM;

    subgraph_guid_table.num_subgraphs =
        *(uint32_t*)im_ex_shared_sg_property->property_data;

    //Exit if there are no imports/exports
    if (subgraph_guid_table.num_subgraphs == 0)
        return AR_EOK;

    subgraph_guid_table.guid_entries = (AcdbSharedSubgraphDataGuid*)
        (im_ex_shared_sg_property->property_data
            + sizeof(uint32_t));

    new_db_info = ACDB_FM_DB_INFO_AT_INDEX(
        acdb_file_man_context.latest_database_index);

    if(IsNull(new_db_info))
        return AR_EBADPARAM;

    for (int32_t i = 0; i < acdb_file_man_context.database_count; i++)
    {
        if (i == acdb_file_man_context.latest_database_index)
            continue;

        existing_db_info_2 = ACDB_FM_DB_INFO_AT_INDEX(i);
        if (IsNull(existing_db_info_2))
            continue;

        AcdbFileManSetFileIndex(i);

        for (uint32_t j = 0; j < subgraph_guid_table.num_subgraphs; j++)
        {
            subgraph_guid = &subgraph_guid_table.guid_entries[j];

            status = DataProcGetSharedSubgraphGuid(subgraph_guid->subgraph_id,
                im_ex_shared_sg_property_id, &guid[0]);

            if (status == AR_ENOTEXIST)
            {
                /* Either property doesnt exist or shared subgraph doesnt exist */
                status = AR_EOK;
                continue;
            }

            if (0 != ar_mem_cmp(
                &subgraph_guid->guid[0], &guid[0],
                ACDB_GUID_BYTE_LENGTH))
            {
                status = AR_EFAILED;
                ACDB_ERR("Error[%d]: There is a difference in subgraph data"
                    " for shared subgraph 0x%x between new VM-%d "
                    "and existing VM-%d", status, subgraph_guid->subgraph_id,
                    new_db_info->vm_id, existing_db_info_2->vm_id);
                return status;
            }
        }
    }

    return status;
}

int32_t AcdbFileManValidateSharedSubgraphs(void)
{
    int32_t status = AR_EOK;
    bool_t has_exports = FALSE;
    bool_t has_imports = FALSE;
    AcdbProperty imported_shared_sg_property = { 0 };
    AcdbProperty exported_shared_sg_property = { 0 };

    imported_shared_sg_property.property_id =
        ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS;
    imported_shared_sg_property.handle_override =
        ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER;
    exported_shared_sg_property.property_id =
        ACDB_GPROP_EXPORTED_SHARED_SUBGRAPHS;
    exported_shared_sg_property.handle_override =
        ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER;

    AcdbFileManSetFileIndex(acdb_file_man_context.latest_database_index);

    status = GetAcdbProperty(&imported_shared_sg_property);
    if (AR_FAILED(status) && AR_ENOTEXIST != status)
        return status;

    has_imports = AR_SUCCEEDED(status);

    status = GetAcdbProperty(&exported_shared_sg_property);
    if (AR_FAILED(status) && AR_ENOTEXIST != status)
        return status;

    has_exports = AR_SUCCEEDED(status);
    status = AR_EOK;

    if (has_imports)
    {
        status = AcdbFileManValidateImExShSubgraphs(
            ACDB_GPROP_EXPORTED_SHARED_SUBGRAPHS,
            &imported_shared_sg_property);
    }

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed comparing shared subgraphs: imports "
            "in new database to exports in existing database(s) ", status);
        return status;
    }

    if (has_exports)
    {
        status = AcdbFileManValidateImExShSubgraphs(
            ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS,
            &exported_shared_sg_property);
    }

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed comparing shared subgraphs: exports "
            "in new database to imports in existing database(s) ", status);
        return status;
    }

    return status;
}

/* ---------------------------------------------------------------------------
* helper functions that dont use any of the global variables
*--------------------------------------------------------------------------- */

/**
* \brief
* Retrieves the file name from the given path.
* Ex. path - c:\my\file.acdb file name - file.acdb
*
* \param[in] fpath: the file path to get the file name from
* \param[in] fpath_len: length of fpath
* \param[in/out] fname: the output file name
* \param[out] fname_len: length of the filename
*
* \return none
*/
int32_t GetFileNameFromPath(char_t* fpath, uint32_t fpath_len, char_t* fname, uint32_t *fname_len)
{
    if (fpath == NULL || fpath_len == 0)
    {
        ACDB_ERR("Error[%d]: The input file path is empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }
    else
    {
        //Delta file path is provided, so form the full path
        //Ex. ..\acdb_data + \ + acdb_data.acdb + delta
        uint32_t char_index = fpath_len;

        /* Detect windows\linux style path prefixes
        Absolute Paths
            Ex. C:\acdb_data\ar_acdb.acdb
            Ex. /acdb_data/ar_acdb.acdb
        Relative paths
            Ex. ..\acdb_data\ar_acdb.acdb
            Ex. ../acdb_data/ar_acdb.acdb
        */
        //if (!((fpath[0] == '.' && fpath[1] == '.') ||
        //    (fpath[1] == ':' && fpath[2] == '\\') ||
        //    (fpath[1] == ':' && fpath[2] == '/') ||
        //    fpath[0] == '/'))
        //{
        //    char_index = 0;
        //}

        while (--char_index > 0)
        {
            if (fpath[char_index] == '\\' ||
                fpath[char_index] == '/')
            {
                char_index++;
                break;
            }
        }

        fname = &fpath[char_index];
        if (IsNull(fname))
        {
            ACDB_ERR("Error[%d]: Unable to retrieve file name from %s", AR_EBADPARAM, fpath);
            return AR_EBADPARAM;
        }

        *fname_len = fpath_len - char_index;
    }

    return AR_EOK;
}

int32_t AcdbFileManGetDirectoryFromFilePath(const char* fpath, uint32_t fpath_len, acdb_path_256_t *path_info)
{
    int32_t status = AR_EOK;
    uint32_t last_slash_index = fpath_len;

    if (fpath == NULL || fpath_len == 0)
    {
        ACDB_ERR("Error[%d]: The input file path is empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    /* Detect windows\linux style path prefixes
    Absolute Paths
    Ex. C:\acdb_data\ar_acdb.acdb
    Ex. /acdb_data/ar_acdb.acdb
    Relative paths
    Ex. ..\acdb_data\ar_acdb.acdb
    Ex. ../acdb_data/ar_acdb.acdb
    */

    while (--last_slash_index > 0)
    {
        if (fpath[last_slash_index] == '\\' ||
            fpath[last_slash_index] == '/')
        {
            last_slash_index++;
            break;
        }
    }

    path_info->path_len = last_slash_index;
    status = ar_strcpy(path_info->path, sizeof(path_info->path),
        fpath, path_info->path_len);

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to extract directory path from %s",
            AR_EBADPARAM, fpath);
        return status;
    }

    return AR_EOK;
}

/* ---------------------------------------------------------------------------
* functions that use the global variables
*--------------------------------------------------------------------------- */

int32_t AcdbFileManInit(void)
{
    int32_t status = AR_EOK;

    if (!acdb_file_man_context.file_man_lock)
    {
        status = ar_osal_mutex_create(&acdb_file_man_context.file_man_lock);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: failed to create acdb client mutex",
                status);
        }
    }
    return status;
}

int32_t AcdbFileManGetAcdbDirectoryPath(acdb_path_256_t **path_info)
{
    int32_t status = AR_EOK;
    acdb_context_handle_t *handle = NULL;
    AcdbFileManDatabaseInfo *db = NULL;

    if (IsNull(path_info))
        return AR_EBADPARAM;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle) || IsNull(handle->file_manager_handle))
        return AR_EHANDLE;

    db = (AcdbFileManDatabaseInfo*)handle->file_manager_handle;

    *path_info = &db->database_directory;

    return status;
}

int32_t AcdbFileManAddAcdb(int32_t index, uint32_t *vm_id,
    AcdbFileManFileInfo *file_info)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo *db_info = NULL;

    if (IsNull(file_info) || IsNull(vm_id) || MAX_ACDB_FILE_COUNT == index)
        return AR_EBADPARAM;

    ACDB_FM_DB_INFO_AT_INDEX(index) =
        ACDB_MALLOC(AcdbFileManDatabaseInfo, 1);

    db_info = ACDB_FM_DB_INFO_AT_INDEX(index);
    if (IsNull(db_info))
        return AR_ENOMEMORY;

    ar_mem_set(db_info, 0,
        sizeof(AcdbFileManDatabaseInfo));

    db_info->file_index = index;
    db_info->database_cache = file_info->file.buffer;
    db_info->database_cache_size = file_info->file.size;
    db_info->file_handle = file_info->file_handle;
    db_info->file_type = file_info->file_type;
    db_info->database_file.path_len = file_info->path_length;
    ACDB_MEM_CPY_SAFE(
        &db_info->database_file.path[0], file_info->path_length,
        file_info->path, file_info->path_length);

    status = AcdbFileManGetDirectoryFromFilePath(file_info->path,
        file_info->path_length, &db_info->database_directory);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get acdb directory from path %s",
            AR_EBADPARAM, &file_info->path);
        return AR_EBADPARAM;
    }

    if (AR_FAILED(DataProcGetVmId(vm_id)))
    {
        ACDB_INFO("Warning[%d]: Using default VM ID for %s",
            status, file_info->path);
        *vm_id = ACDB_CTX_MAN_DEFAULT_DB_HANDLE;
    }

    db_info->vm_id = *vm_id;

    if (acdb_file_man_context.database_count > 1)
    {
        status = AcdbFileManValidateSharedSubgraphs();
        if (AR_FAILED(status))
        {
            AcdbFileManRemoveDatabase(
                (acdb_file_man_handle_t*)db_info);
        }
    }
    return status;
}

int32_t AcdbFileManAddQwsp(int32_t index,
    AcdbFileManFileInfo* file_info)
{
    AcdbFileManWorkspaceInfo* ws_info = NULL;
    if (IsNull(file_info) || MAX_ACDB_FILE_COUNT == index)
        return AR_EBADPARAM;

    ACDB_FM_WS_INFO_AT_INDEX(index) =
        ACDB_MALLOC(AcdbFileManWorkspaceInfo, 1);

    ws_info = ACDB_FM_WS_INFO_AT_INDEX(index);
    if (IsNull(ws_info))
        return AR_ENOMEMORY;

    ar_mem_set(ACDB_FM_WS_INFO_AT_INDEX(index), 0,
        sizeof(AcdbFileManWorkspaceInfo));

    ws_info->file_size = file_info->file.size;
    ws_info->file_handle = file_info->file_handle;
    ws_info->workspace_file.path_len =
        file_info->path_length;
    ACDB_MEM_CPY_SAFE(
        &ws_info->workspace_file.path[0], file_info->path_length,
        file_info->path, file_info->path_length);

    return AR_EOK;
}

int32_t AcdbFileManAddDatabase(acdb_file_man_data_files_t *db_files,
    acdb_file_man_context_handle_t *fm_ctx_handle)
{
    int32_t status = AR_EOK;
    uint32_t vm_id = 0;
    uint32_t index = 0;
    AcdbFileManFileInfo *db_file = NULL;

    if (IsNull(db_files) || IsNull(fm_ctx_handle))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (db_files->num_files > ACDB_MAX_FILE_ADD_LIMIT)
    {
        ACDB_ERR("Error[%d]: The size of the file set is more than %d",
            AR_ENORESOURCE, ACDB_MAX_FILE_ADD_LIMIT);
        return AR_EBADPARAM;
    }

    if (acdb_file_man_context.database_count == ACDB_MAX_ACDB_FILES)
    {
        ACDB_ERR("Error[%d]: Max number of files is %d",
            AR_ENORESOURCE, ACDB_MAX_ACDB_FILES);
        return AR_ENORESOURCE;
    }

    ACDB_MUTEX_LOCK(acdb_file_man_context.file_man_lock);

    for (uint32_t i = 0; i < db_files->num_files; i++)
    {
        db_file = db_files->file_info[i];

        //check for duplicate *.acdb file here using strstr. make sure the same file cannot be added twice
        for (int32_t j = 0; j < acdb_file_man_context.database_count; j++)
        {
            AcdbFileManDatabaseInfo* fm_db_info = ACDB_FM_DB_INFO_AT_INDEX(j);

            if (NULL == ar_strstr(&fm_db_info->database_file.path[0], &db_file->path[0]))
                continue;
            else
            {
                ACDB_ERR("Error[%d]: The database file %s already exists", AR_EALREADY,
                    db_file->path);
                return AR_EALREADY;
            }
        }

        for (index = 0; index < MAX_ACDB_FILE_COUNT; index++)
        {
            if (ACDB_FILE_TYPE_DATABASE == db_file->file_type &&
                IsNull(acdb_file_man_context.database_info[index]))
            {
                acdb_file_man_context.database_count++;
                acdb_file_man_context.database_index = index;
                acdb_file_man_context.latest_database_index = index;
                break;
            }
            else if (ACDB_FILE_TYPE_WORKSPACE == db_file->file_type &&
                IsNull(acdb_file_man_context.workspace_info[index]))
            {
                acdb_file_man_context.workspace_count++;
                break;
            }
        }

        if (MAX_ACDB_FILE_COUNT == index)
            index--;

        switch (db_file->file_type)
        {
        case ACDB_FILE_TYPE_DATABASE:
            status = AcdbFileManAddAcdb(index, &vm_id, db_file);
            break;
        case ACDB_FILE_TYPE_WORKSPACE:
            status = AcdbFileManAddQwsp(index, db_file);
            break;
        default:
            break;
        }

        if (AR_FAILED(status))
            break;
    }

    if (AR_SUCCEEDED(status))
    {
        fm_ctx_handle->vm_id = vm_id;
        fm_ctx_handle->file_man_handle = ACDB_FM_DB_INFO_AT_INDEX(index);
    }

    ACDB_MUTEX_UNLOCK(acdb_file_man_context.file_man_lock);
    return status;
}

int32_t AcdbFileManRemoveDatabase(acdb_file_man_handle_t *fm_handle)
{
    int32_t status = AR_EOK;
    uint32_t db_index = 0;
    bool_t had_workspace = 0;
    AcdbFileManDatabaseInfo *db_info = NULL;
    AcdbFileManWorkspaceInfo *ws_info = NULL;

    if (IsNull(fm_handle))
        return AR_EBADPARAM;

    db_info = (AcdbFileManDatabaseInfo*)fm_handle;
    if (IsNull(db_info))
        return AR_EBADPARAM;

    db_index = db_info->file_index;
    ACDB_FM_DB_INFO_AT_INDEX(db_index) = NULL;
    ws_info = ACDB_FM_WS_INFO_AT_INDEX(db_info->file_index);
    if (!IsNull(db_info->file_handle))
        (void)ar_fclose(db_info->file_handle);

    acdb_buffer_t in_mem_file;
    in_mem_file.buffer = db_info->database_cache;
    in_mem_file.size = db_info->database_cache_size;
    AcbdInitUnloadInMemFile(&in_mem_file);

    ACDB_FREE(db_info);

    if (!IsNull(ws_info))
    {
        ACDB_FM_WS_INFO_AT_INDEX(db_index) = NULL;
        if(!IsNull(ws_info->file_handle))
            (void)ar_fclose(ws_info->file_handle);
        ACDB_FREE(ws_info);
        had_workspace = TRUE;
    }

    ACDB_MUTEX_LOCK(acdb_file_man_context.file_man_lock);

    if (acdb_file_man_context.database_count > 0)
    {
        acdb_file_man_context.database_count--;

        if (had_workspace)
            acdb_file_man_context.workspace_count--;
    }

    ACDB_MUTEX_UNLOCK(acdb_file_man_context.file_man_lock);

    return status;
}

int32_t AcdbFileManReset(void)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo* db_info = NULL;

    for (int32_t i = 0; i < ACDB_MAX_ACDB_FILES; i++)
    {
        db_info = ACDB_FM_DB_INFO_AT_INDEX(i);

        if (IsNull(db_info))
            continue;

        status = AcdbFileManRemoveDatabase((acdb_file_man_handle_t)db_info);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to close %s", status,
                ACDB_FM_DB_INFO->database_file.path);
            status = AR_EFAILED;
        }
    }

    ar_osal_mutex_destroy(acdb_file_man_context.file_man_lock);
    ar_mem_set(&acdb_file_man_context, 0, sizeof(AcdbFileManContext));
    acdb_file_man_context.database_index = -1;
    return status;
}

int32_t AcdbFileManGetVmIdFromFileName(AcdbFile *acdb_file, uint32_t *vm_id)
{
    int32_t status = AR_ENOTEXIST;
    AcdbFileManDatabaseInfo* db_info = NULL;

    if (IsNull(acdb_file) || IsNull(vm_id))
    {
        return AR_EBADPARAM;
    }

    for (int32_t i = 0; i < acdb_file_man_context.database_count; i++)
    {
        db_info = ACDB_FM_DB_INFO_AT_INDEX(i);

        if (IsNull(db_info))
            continue;

        if (!ACDB_FIND_STR(acdb_file->fileName, db_info->database_file.path))
            continue;

        status = AR_EOK;
        *vm_id = db_info->vm_id;
    }

    return status;
}

int32_t AcdbFileManGetFileName(int32_t *findex, acdb_path_256_t *file_name_info)
{
    int32_t status = AR_EOK;

    size_t dst_str_size = sizeof(file_name_info->path);
    size_t src_str_size =
        ACDB_FM_DB_INFO_AT_INDEX(*findex)->database_file.path_len;

    if (src_str_size > dst_str_size)
    {
        ACDB_ERR("Error[%d]: Unable to copy file name. Source(%s) is "
            "longer than Destination(%s)", AR_EBADPARAM, src_str_size,
            dst_str_size);
        return AR_EBADPARAM;
    }

    if (IsNull(findex) || IsNull(file_name_info))
    {
        ACDB_ERR("Error[%d]: The input parameter(s) are null")
        return AR_EBADPARAM;
    }

    if (*findex < acdb_file_man_context.database_count)
    {
        if (src_str_size >= ACDB_MAX_PATH_LENGTH)
        {
            ACDB_ERR("Error[%d]: Acdb file name legnth "
                "is longer than 256 characters");
            return AR_EBADPARAM;
        }

        status = ACDB_STR_CPY_SAFE(file_name_info->path, dst_str_size,
            ACDB_FM_DB_INFO_AT_INDEX(*findex)->database_file.path,
            src_str_size);

        if (AR_EOK != status) return status;

        file_name_info->path_len =
            ACDB_FM_DB_INFO_AT_INDEX(*findex)->database_file.path_len;
    }
    else
    {
        ACDB_ERR("Error[%d]: The file index is greater than the file count");
        return AR_EBADPARAM;
    }

    return status;
}

int32_t AcdbFileManQwspFileIO(
    AcdbFileManWorkspaceInfo *ws_info, AcdbFileManFileOp file_op)
{
    int32_t status = AR_EOK;
    ar_fhandle fhandle = NULL;

    if (IsNull(ws_info))
    {
        ACDB_ERR("Error[%d]: Workspace file info is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    switch (file_op)
    {
    case ACDB_FM_FILE_OP_OPEN:
        status = ar_fopen(&fhandle, ws_info->workspace_file.path,
            AR_FOPEN_READ_ONLY);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to open the workspace file", status);
        }

        ws_info->file_handle = fhandle;
        ws_info->file_size = (uint32_t)ar_fsize(ws_info->file_handle);

        break;
    case ACDB_FM_FILE_OP_CLOSE:
        status = ar_fclose(ws_info->file_handle);
        ws_info->file_handle = NULL;
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to close the workspace file", status);
        }
        //Clear handle in case close is called again
        ws_info->file_handle = NULL;
        break;
    default:
        break;
    }

    return status;
}

int32_t AcdbFileManSetQwspPathInfo(
    AcdbDatabasePathInfoVersion version,
    void* file_info, void* path_info)
{
    int32_t status = AR_EOK;
    AcdbFileManWorkspaceInfo* ws_info = NULL;

    ws_info = (AcdbFileManWorkspaceInfo*)file_info;

    if (IsNull(ws_info))
        return AR_ENOTEXIST;

    switch (version)
    {
    case ACDB_FM_DB_PATH_INFO_VERSION_1:
        ((AcdbFileManDbPathInfo*)path_info)->file_size =
            ws_info->file_size;
        ((AcdbFileManDbPathInfo*)path_info)->path_length =
            ws_info->workspace_file.path_len;
        ((AcdbFileManDbPathInfo*)path_info)->path =
            &ws_info->workspace_file.path[0];
        break;
    case ACDB_FM_DB_PATH_INFO_VERSION_2:
        ((AcdbFileManDbPathInfoV2*)path_info)->file_size =
            ws_info->file_size;
        ((AcdbFileManDbPathInfoV2*)path_info)->path_type =
            ACDB_PATH_TYPE_QWSP_FILE;
        ((AcdbFileManDbPathInfoV2*)path_info)->path_length =
            ws_info->workspace_file.path_len;
        ((AcdbFileManDbPathInfoV2*)path_info)->path =
            &ws_info->workspace_file.path[0];
        break;
    default:
        status = AR_EBADPARAM;
        break;
    }

    return status;
}

int32_t AcdbFileManSetAcdbPathInfo(
    AcdbDatabasePathInfoVersion version,
    void* file_info, void* path_info)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo* db_info = NULL;

    db_info = (AcdbFileManDatabaseInfo*)file_info;

    if (IsNull(db_info))
        return AR_ENOTEXIST;

    switch (version)
    {
    case ACDB_FM_DB_PATH_INFO_VERSION_1:
        ((AcdbFileManDbPathInfo*)path_info)->file_size =
            db_info->database_cache_size;
        ((AcdbFileManDbPathInfo*)path_info)->path_length =
            db_info->database_file.path_len;
        ((AcdbFileManDbPathInfo*)path_info)->path =
            &db_info->database_file.path[0];
        break;
    case ACDB_FM_DB_PATH_INFO_VERSION_2:
        ((AcdbFileManDbPathInfoV2*)path_info)->file_size =
            db_info->database_cache_size;
        ((AcdbFileManDbPathInfoV2*)path_info)->path_type =
            ACDB_PATH_TYPE_ACDB_FILE;
        ((AcdbFileManDbPathInfoV2*)path_info)->path_length =
            db_info->database_file.path_len;
        ((AcdbFileManDbPathInfoV2*)path_info)->path =
            &db_info->database_file.path[0];
        break;
    default:
        status = AR_EBADPARAM;
        break;
    }

    return status;
}

int32_t AcdbFileManWriteLoadedFileInfo(
    AcdbDatabasePathInfoVersion version,
    AcdbPathType path_type, void *file_info,
    AcdbFileManBlob *rsp, uint32_t *blob_offset)
{
    int32_t status = AR_EOK;
    uint32_t path_info_struct_size = 0;
    acdb_buffer_t path_info_struct = { 0 };
    acdb_path_t db_file = { 0 };
    AcdbFileManDbPathInfoV2 db_path_info_v2 = { 0 };
    AcdbFileManDbPathInfo db_path_info_v1 = { 0 };
    AcdbFileManDatabaseInfo* db_info = NULL;
    AcdbFileManWorkspaceInfo* ws_info = NULL;

    if (IsNull(file_info) || IsNull(rsp) || IsNull(blob_offset))
        return AR_EBADPARAM;

    switch (version)
    {
    case ACDB_FM_DB_PATH_INFO_VERSION_1:
        path_info_struct.buffer = (void*)&db_path_info_v1;
        path_info_struct_size = sizeof(db_path_info_v1) - sizeof(intptr_t);
        break;
    case ACDB_FM_DB_PATH_INFO_VERSION_2:
        path_info_struct.buffer = (void*)&db_path_info_v2;
        path_info_struct_size = sizeof(db_path_info_v2) - sizeof(size_t);
        break;
    default:
        status = AR_EBADPARAM;
        break;
    }

    switch (path_type)
    {
    case ACDB_PATH_TYPE_QWSP_FILE:
        ws_info = (AcdbFileManWorkspaceInfo*)file_info;
        if (IsNull(ws_info)) return AR_ENOTEXIST;

        status = AcdbFileManSetQwspPathInfo(
            version, file_info, path_info_struct.buffer);
        break;
    case ACDB_PATH_TYPE_ACDB_FILE:
        db_info = (AcdbFileManDatabaseInfo*)file_info;
        if (IsNull(db_info)) return AR_ENOTEXIST;

        status = AcdbFileManSetAcdbPathInfo(
            version, file_info, path_info_struct.buffer);
        break;
    case ACDB_PATH_TYPE_WRITEABLE_DIRECTORY:
        db_info = (AcdbFileManDatabaseInfo*)file_info;
        if (IsNull(db_info)) return AR_ENOTEXIST;
        if (0 == db_info->writable_directory.path_len) return AR_ENOTEXIST;
        db_path_info_v2.file_size = 0;
        db_path_info_v2.path_type = ACDB_PATH_TYPE_WRITEABLE_DIRECTORY;
        db_path_info_v2.path_length = db_info->writable_directory.path_len;
        db_path_info_v2.path = &db_info->writable_directory.path[0];
        break;
    default:
        status = AR_EBADPARAM;
        break;
    }

    if (AR_FAILED(status))
        return status;

    switch (version)
    {
    case ACDB_FM_DB_PATH_INFO_VERSION_1:
        db_file.path_length = db_path_info_v1.path_length;
        db_file.path = db_path_info_v1.path;

        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(AcdbPathType),
            &db_path_info_v1.file_size, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);
        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(AcdbPathType),
            &db_path_info_v1.path_length, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);
        break;
    case ACDB_FM_DB_PATH_INFO_VERSION_2:
        db_file.path_length = db_path_info_v2.path_length;
        db_file.path = db_path_info_v2.path;

        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(AcdbPathType),
            &db_path_info_v2.path_type, sizeof(AcdbPathType));
        *blob_offset += sizeof(AcdbPathType);
        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(uint32_t),
            &db_path_info_v2.file_size, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);
        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(uint32_t),
            &db_path_info_v2.path_length, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);
        break;
    default:
        break;
    }

    ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, db_file.path_length,
        db_file.path, db_file.path_length);
    *blob_offset += db_file.path_length;

    return status;
}

int32_t AcdbFileManGetHostDatabaseFileInfo(AcdbFileManBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t sz_file_info_rsp = 0;
    uint32_t offset = 0;
    uint32_t offset_file_count = 0;
    int32_t i = 0;
    int32_t file_count = 0;
    AcdbFileManDatabaseInfo *db_info = NULL;
    AcdbFileManWorkspaceInfo *ws_info = NULL;

    /*
    The format of the output is:

    +-----------------------------+
    |            #files           |
    +-----------------------------+
    +-----------------------------+
    | fsize | fnamelength | fname | File #1
    +-----------------------------+
    ...
    ...
    +-----------------------------+
    | fsize | fnamelength | fname | File #N
    +-----------------------------+
    */

    if (acdb_file_man_context.database_count <= 0)
    {
        ACDB_ERR("Error[%d]: No database file found at index %d",
            AR_ENORESOURCE, i);
        return AR_ENORESOURCE;
    }

    ws_info = ACDB_FM_WS_INFO_AT_INDEX(i);
    db_info = ACDB_FM_DB_INFO_AT_INDEX(i);

    sz_file_info_rsp += sizeof(file_count);

    if (!IsNull(ws_info))
    {
        status = AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_OPEN);
        if (AR_FAILED(status)) return status;

        status = AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_CLOSE);
        if (AR_FAILED(status)) return status;

        // workspace file
        sz_file_info_rsp += sizeof(AcdbFileManDbPathInfo)
            - sizeof(intptr_t);
        sz_file_info_rsp += ws_info->workspace_file.path_len;
    }
    else
    {
        ACDB_DBG("Warning: No workspace file found for database in %s",
            &db_info->database_directory.path[0]);
    }

    if (!IsNull(db_info))
    {
        // acdb file
        sz_file_info_rsp += sizeof(AcdbFileManDbPathInfo)
            - sizeof(intptr_t);
        sz_file_info_rsp += db_info->database_file.path_len;
    }

    if (sz_file_info_rsp > rsp->size)
    {
        ACDB_ERR("Error[%d]: There isnt enough memory to "
            "copy file information", AR_ENOMEMORY);
        return AR_ENOMEMORY;
    }

    offset_file_count = 0;

    ws_info = ACDB_FM_WS_INFO_AT_INDEX(i);
    db_info = ACDB_FM_DB_INFO_AT_INDEX(i);
    file_count = 0;

    if (!IsNull(ws_info) && !IsNull(db_info))
        ws_info->vm_id = db_info->vm_id;
    else
    {
        ACDB_ERR("Error[%d]: The workspace/database info param are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    //Skip writing file_count and write it after determining file_count
    offset_file_count = offset;
    offset += sizeof(uint32_t);

    status = AcdbFileManWriteLoadedFileInfo(
        ACDB_FM_DB_PATH_INFO_VERSION_1,
        ACDB_PATH_TYPE_QWSP_FILE,
        (void*)ws_info, rsp, &offset);
    file_count += AR_SUCCEEDED(status) ? 1 : 0;

    status = AcdbFileManWriteLoadedFileInfo(
        ACDB_FM_DB_PATH_INFO_VERSION_1,
        ACDB_PATH_TYPE_ACDB_FILE,
        (void*)db_info, rsp, &offset);
    file_count += AR_SUCCEEDED(status) ? 1 : 0;

    ACDB_MEM_CPY_SAFE(
        rsp->buf + offset_file_count, sizeof(uint32_t),
        &file_count, sizeof(uint32_t));

    status = AR_EOK;

    rsp->bytes_filled = sz_file_info_rsp;

    return status;
}

int32_t AcdbFileManGetAllDatabasesFileInfo(AcdbFileManBlob* rsp)
{
    /*
    * The format of the output is:
    * +-------------------------------------+
    * |         #files sets                 |
    * +-------------------------------------+
    * +-------------------------------------+
    * |             acdb handle             | _
    * +-------------------------------------+  |
    * +-------------------------------------+  |
    * |               # files               |  |
    * +-------------------------------------+  |
    * +-------------------------------------+  | File Set #N
    * | path type | fsize | path len | path |  |
    * +-------------------------------------+  |
    * |                    ...                 |
    * +-------------------------------------+  |
    * | path type | fsize | path len | path | _|
    * +-------------------------------------+
    *                .
    *                .
    * +-------------------------------------+
    * |             acdb handle             | _
    * +-------------------------------------+  |
    * +-------------------------------------+  |
    * |               # files               |  |
    * +-------------------------------------+  |
    * +-------------------------------------+  | File Set #N
    * | path type | fsize | path len | path |  |
    * +-------------------------------------+  |
    * |                    ...                 |
    * +-------------------------------------+  |
    * | path type | fsize | path len | path | _|
    * +-------------------------------------+
    */

    int32_t status = AR_EOK;
    uint32_t sz_file_info_rsp = 0;
    uint32_t offset = 0;
    uint32_t offset_file_count = 0;
    int32_t i = 0;
    int32_t file_count = 0;
    int32_t fileset_count = 0;
    uint32_t acdb_handle = 0;
    AcdbFileManDatabaseInfo* db_info = NULL;
    AcdbFileManWorkspaceInfo* ws_info = NULL;
    AcdbFileManDbPathInfoV2 db_path_info = { 0 };

    sz_file_info_rsp += sizeof(fileset_count);
    fileset_count = acdb_file_man_context.database_count;

    for (i = 0; i < acdb_file_man_context.database_count; i++)
    {
        ws_info = ACDB_FM_WS_INFO_AT_INDEX(i);
        db_info = ACDB_FM_DB_INFO_AT_INDEX(i);

        sz_file_info_rsp += sizeof(acdb_handle);
        sz_file_info_rsp += sizeof(file_count);

        if (!IsNull(ws_info))
        {
            status = AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_OPEN);
            if (AR_FAILED(status)) return status;

            status = AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_CLOSE);
            if (AR_FAILED(status)) return status;

            // workspace file
            sz_file_info_rsp += sizeof(db_path_info) - sizeof(intptr_t);
            sz_file_info_rsp += ws_info->workspace_file.path_len;
        }
        else
        {
            ACDB_DBG("Warning: No workspace file found for database in %s",
                &db_info->database_directory.path[0]);
        }

        if (!IsNull(db_info))
        {
            // acdb file
            sz_file_info_rsp += sizeof(db_path_info) - sizeof(intptr_t);
            sz_file_info_rsp += db_info->database_file.path_len;

            // writable directory
            if (db_info->writable_directory.path_len > 0)
            {
                sz_file_info_rsp += sizeof(db_path_info) - sizeof(intptr_t);
                sz_file_info_rsp += db_info->writable_directory.path_len;
            }
        }
        else
        {
            ACDB_ERR("Error[%d]: No database file found at index %d",
                AR_ENORESOURCE, i);
            return AR_ENORESOURCE;
        }
    }

    if (sz_file_info_rsp > rsp->size)
    {
        ACDB_ERR("Error[%d]: There isnt enough memory to "
            "copy file information", AR_ENOMEMORY);
        return AR_ENOMEMORY;
    }

    ACDB_MEM_CPY_SAFE(
        rsp->buf, sizeof(uint32_t),
        &fileset_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    offset_file_count = 0;
    for (i = 0; i < acdb_file_man_context.database_count; i++)
    {
        ws_info = ACDB_FM_WS_INFO_AT_INDEX(i);
        db_info = ACDB_FM_DB_INFO_AT_INDEX(i);
        file_count = 0;

        if (!IsNull(ws_info) && !IsNull(db_info))
            ws_info->vm_id = db_info->vm_id;
        else if(IsNull(ws_info) && IsNull(db_info))
        {
            ACDB_ERR("Error[%d]: The workspace/database info param are null",
                AR_EBADPARAM);
            status = AR_EBADPARAM;
            break;
        }

        acdb_handle = db_info->vm_id;
        ACDB_MEM_CPY_SAFE(
            rsp->buf + offset, sizeof(uint32_t),
            &acdb_handle, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        //Skip writing file_count and write it after determining file_count
        offset_file_count = offset;
        offset += sizeof(uint32_t);

        status = AcdbFileManWriteLoadedFileInfo(
            ACDB_FM_DB_PATH_INFO_VERSION_2,
            ACDB_PATH_TYPE_QWSP_FILE,
            (void*)ws_info, rsp, &offset);
        file_count += AR_SUCCEEDED(status) ? 1 : 0;

        status = AcdbFileManWriteLoadedFileInfo(
            ACDB_FM_DB_PATH_INFO_VERSION_2,
            ACDB_PATH_TYPE_ACDB_FILE,
            (void*)db_info, rsp, &offset);
        file_count += AR_SUCCEEDED(status) ? 1 : 0;

        status = AcdbFileManWriteLoadedFileInfo(
            ACDB_FM_DB_PATH_INFO_VERSION_2,
            ACDB_PATH_TYPE_WRITEABLE_DIRECTORY,
            (void*)db_info, rsp, &offset);
        file_count += AR_SUCCEEDED(status) ? 1 : 0;

        ACDB_MEM_CPY_SAFE(
            rsp->buf + offset_file_count, sizeof(uint32_t),
            &file_count, sizeof(uint32_t));

        status = AR_EOK;
    }

    rsp->bytes_filled = sz_file_info_rsp;

    return status;
}

int32_t AcdbFileManGetQwspFileData(AcdbFileManWorkspaceInfo* ws_info,
     AcdbFileManGetFileDataReq* req, AcdbFileManBlob *rsp)
{
    int32_t status = AR_EOK;
    size_t data_copy_size = 0;
    size_t bytes_read = 0;

    if (IsNull(req) | IsNull(ws_info) | IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (ws_info->file_size < req->file_offset)
    {
        ACDB_ERR("Error[%d]: The provided offset is past the end of the file",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }
    if ((ws_info->file_size - req->file_offset) < req->file_data_len)
    {
        data_copy_size = (size_t)(ws_info->file_size - req->file_offset);
    }
    else
    {
        data_copy_size = (size_t)req->file_data_len;
    }

    status = AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_OPEN);
    if (AR_FAILED(status)) return status;

    status = ar_fseek(ws_info->file_handle,
        req->file_offset, AR_FSEEK_BEGIN);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to seek to file offset %d",
            status, req->file_offset);
        goto end;
    }

    status = ar_fread(ws_info->file_handle,
        (void*)rsp->buf, data_copy_size, &bytes_read);
    if (bytes_read != data_copy_size)
    {
        ACDB_DBG("Expected to read %d bytes, but read %d bytes",
            data_copy_size, bytes_read);
        goto end;
    }
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read data for %s",
            status, ws_info->workspace_file.path);
        goto end;
    }

end:

    AcdbFileManQwspFileIO(ws_info, ACDB_FM_FILE_OP_CLOSE);
    rsp->bytes_filled = (uint32_t)data_copy_size;
    return status;
}

int32_t AcdbFileManGetAcdbFileData(AcdbFileManDatabaseInfo *db_info,
    AcdbFileManGetFileDataReq* req, AcdbFileManBlob *rsp)
{
    int32_t status = AR_EOK;
    size_t data_copy_size = 0;

    if (IsNull(req) | IsNull(db_info) | IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (db_info->database_cache_size < req->file_offset)
    {
        ACDB_ERR("Error[%d]: The provided offset is past the end of the file",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }
    if ((db_info->database_cache_size - req->file_offset) < req->file_data_len)
    {
        data_copy_size = (size_t)(db_info->database_cache_size
            - req->file_offset);
    }
    else
    {
        data_copy_size = (size_t)req->file_data_len;
    }

    status = acdb_fm_read_db_mem((acdb_file_man_handle_t)db_info, rsp->buf,
        data_copy_size, &req->file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read data from %s",
            status, db_info->database_file.path);
        return status;
    }

    rsp->bytes_filled = (uint32_t)data_copy_size;
    return status;
}

int32_t AcdbFileManGetDatabaseFileSet(
    AcdbFileManGetFileDataReq* req, AcdbFileManBlob* rsp)
{
    int32_t status = AR_EOK;
    char_t* fname = NULL;
    uint32_t fname_len = 0;
    char_t* path = NULL;
    uint32_t path_len = 0;
    uint32_t db_count = acdb_file_man_context.database_count;
    bool_t found_handle = false;
    AcdbFileManDatabaseInfo* db_info = NULL;
    AcdbFileManWorkspaceInfo* ws_info = NULL;
    AcdbPathType path_type = ACDB_PATH_TYPE_NONE;
    const char* WKSP_FILE_NAME_EXT = ".qwsp";
    const char* ACDB_FILE_NAME_EXT = ".acdb";

    if (req == NULL || rsp == NULL)
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) are null");
        return AR_EBADPARAM;
    }

    for (uint32_t i = 0; i < db_count; i++)
    {
        db_info = ACDB_FM_DB_INFO_AT_INDEX(i);
        ws_info = ACDB_FM_WS_INFO_AT_INDEX(i);

        found_handle = db_info->vm_id == req->acdb_handle;

        if (found_handle)
            break;
    }

    if (!found_handle)
    {
        ACDB_ERR("Error[%d]: The provided handle is invalid. "
            "No matching database was found.", AR_EHANDLE);
        return AR_EHANDLE;
    }

    if (!IsNull(ACDB_FIND_STR((char_t*)req->file_name, WKSP_FILE_NAME_EXT)))
    {
        path_type = ACDB_PATH_TYPE_QWSP_FILE;
        path = &ws_info->workspace_file.path[0];
        path_len = ws_info->workspace_file.path_len;
    }
    else if (!IsNull(ACDB_FIND_STR((char_t*)req->file_name, ACDB_FILE_NAME_EXT)))
    {
        path_type = ACDB_PATH_TYPE_ACDB_FILE;
        path = &db_info->database_file.path[0];
        path_len = db_info->database_file.path_len;
    }
    else
    {
        ACDB_ERR("Error[%d]: Unknown file extension for file: %s. ",
            AR_EHANDLE, req->file_name);
        return AR_EBADPARAM;
    }

    status = GetFileNameFromPath(path, path_len, fname, &fname_len);

    fname = &path[path_len - fname_len];

    if (AR_FAILED(status) || fname == NULL)
    {
        ACDB_ERR("Error[%d]: Failed to get file name from path", status);
        return status;
    }

    if (IsNull(strstr((char*)fname, (char*)req->file_name)))
    {
        ACDB_ERR("Error[%d]: Unknown file %s. The file name %s does not match %s",
            AR_ENOTEXIST, req->file_name, req->file_name, fname);
        return AR_ENOTEXIST;
    }

    status = AR_EOK;

    switch (path_type)
    {
    case ACDB_PATH_TYPE_QWSP_FILE:
        status = AcdbFileManGetQwspFileData(ws_info, req, rsp);
        break;
    case ACDB_PATH_TYPE_ACDB_FILE:
        status = AcdbFileManGetAcdbFileData(db_info, req, rsp);
        break;
    default:
        ACDB_ERR("Error[%d]: The file type for %s is unknown",
            AR_EUNEXPECTED, db_info->database_file.path);
        return AR_EUNEXPECTED;
        break;
    }

    db_info = NULL;
    ws_info = NULL;

    return status;
}

int32_t AcdbFileManSetWritablePath(
    acdb_file_man_writable_path_info_t* info)
{
    AcdbFileManDatabaseInfo* db_info = NULL;

    if (IsNull(info))
        return AR_EBADPARAM;

    db_info = (AcdbFileManDatabaseInfo*)info->handle;

    if (IsNull(db_info))
        return AR_EHANDLE;

    ACDB_MEM_CPY_SAFE(
        &db_info->writable_directory.path[0],
        info->writable_path.path_length,
        info->writable_path.path, info->writable_path.path_length);

    db_info->writable_directory.path_len = info->writable_path.path_length;

    return AR_EOK;
}

int32_t AcdbFileManGetWritablePath(
    acdb_file_man_writable_path_info_256_t *info)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo *db_info = NULL;

    if (IsNull(info))
        return AR_EBADPARAM;

    db_info = (AcdbFileManDatabaseInfo*)info->handle;

    if (IsNull(db_info))
        return AR_EHANDLE;

    info->writable_path.path_len =
        db_info->writable_directory.path_len;
    ACDB_MEM_CPY_SAFE(
        &info->writable_path.path[0],
        db_info->writable_directory.path_len,
        &db_info->writable_directory.path[0],
        db_info->writable_directory.path_len);

    return status;
}

/* ---------------------------------------------------------------------------
* Public functions
*--------------------------------------------------------------------------- */

int32_t FileSeekRead(void* buffer, size_t read_size, uint32_t* offset)
{
    if (-1 == acdb_file_man_context.database_index)
        return AR_ENORESOURCE;
    int32_t status = AR_EOK;
    size_t bytes_read = 0;

    status = ar_fseek(ACDB_FM_DB_INFO->file_handle,
        *offset, AR_FSEEK_BEGIN);

    if (AR_FAILED(status)) return status;

    status = ar_fread(ACDB_FM_DB_INFO->file_handle,
        buffer, read_size, &bytes_read);

    *offset += (uint32_t)bytes_read;

    return status;
}

int32_t FileManReadFileToBuffer(const char_t* fname, size_t* fsize, uint8_t* fbuffer, uint32_t fbuffer_size)
{
    int32_t status = AR_EOK;
    ar_fhandle fhandle = NULL;
    size_t bytes_read = 0;

    if (fname == NULL)
    {
        return AR_EBADPARAM;
    }
    else
    {
        status = ar_fopen(&fhandle, fname, AR_FOPEN_READ_ONLY);
        if (AR_FAILED(status) || fhandle == NULL)
        {
            ACDB_ERR("Error[%d]: Unable to open file: %s", status, fname);
            return status;
        }

        *fsize = (uint32_t)ar_fsize(fhandle);

        if (fbuffer == NULL)
        {
            ar_fclose(fhandle);
            return AR_EOK;
        }

        if (*fsize > fbuffer_size)
        {
            ar_fclose(fhandle);
            ACDB_ERR("Error[%d]: File size (%d bytes) is more "
                "than buffer size (%d bytes)",
                AR_EBADPARAM, *fsize, fbuffer_size);
            return AR_EBADPARAM;
        }

        status = ar_fread(fhandle, (void*)fbuffer, *fsize, &bytes_read);
        if (AR_FAILED(status) || fhandle == NULL)
        {
            ar_fclose(fhandle);
            ACDB_ERR("Error[%d]: Unable to read file: %s", status, fname);
            return status;
        }

        if (bytes_read != *fsize)
        {
            status = AR_EBADPARAM;
            ACDB_ERR("Error[%d]: The bytes read (%d bytes) is not equal to "
                "the requested read size (%d bytes)",
                status, bytes_read, *fsize);
        }

        ar_fclose(fhandle);
    }
    return status;
}

/* ---------------------------------------------------------------------------
* Public functions: Database Read Operations
*--------------------------------------------------------------------------- */

int32_t acdb_get_db_chunk(acdb_file_man_handle_t handle,
    uint32_t chunk_id, uint32_t* chunk_offset, uint32_t* chunk_size)
{
    if (IsNull(handle) || IsNull(chunk_offset) || IsNull(chunk_size))
        return AR_EBADPARAM;

    AcdbFileManDatabaseInfo* db = (AcdbFileManDatabaseInfo*)handle;

    int32_t status = acdb_parser_get_chunk(
        db->database_cache,
        db->database_cache_size,
        chunk_id, chunk_offset, chunk_size);
    if (AR_FAILED(status))
    {
        ACDB_DBG("Error[%d]: Failed to get information for Chunk[0x%x]",
            status, chunk_id);
        return status;
    }

    if (*chunk_size <= 0)
    {
        ACDB_DBG("Warning[%d]: Chunk[0x%x] is empty", AR_ENOTEXIST, chunk_id);
        return AR_ENOTEXIST;
    }

    return AR_EOK;
}

int32_t acdb_fm_get_db_chunks(uint32_t count, ...)
{
    int32_t status = AR_EOK;
    va_list args;
    ChunkInfo* ci = NULL;
    acdb_context_handle_t * ctx_handle = NULL;
    acdb_file_man_handle_t fm_handle = NULL;
    va_start(args, count);

    for (uint32_t i = 0; i < count; i++)
    {
        ci = va_arg(args, ChunkInfo*);

        if (IsNull(ci))
            return AR_EBADPARAM;

        switch (ci->handle_override)
        {
        case ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER:
            fm_handle = ACDB_FM_DB_INFO;
            break;
        case ACDB_FM_HANDLE_OVERRIDE_CTX_MANAGER:
        default:
            ctx_handle = acdb_ctx_man_get_active_handle();

            if (IsNull(ctx_handle))
                return AR_EHANDLE;

            fm_handle = ctx_handle->file_manager_handle;
            break;
        }

        if (IsNull(fm_handle))
            return AR_EHANDLE;

        status = acdb_get_db_chunk(fm_handle,
            ci->chunk_id, &ci->chunk_offset, &ci->chunk_size);
        if (AR_FAILED(status))
        {
            return status;
        }
    }

    va_end(args);
    return status;
}

int32_t acdb_file_seek_read(acdb_file_man_handle_t handle,
    void* buffer, size_t read_size, uint32_t* offset)
{
    int32_t status = AR_EOK;
    size_t bytes_read = 0;
    AcdbFileManDatabaseInfo *db = NULL;

    if (IsNull(handle) || IsNull(buffer) || IsNull(offset))
        return AR_EBADPARAM;

    db = (AcdbFileManDatabaseInfo*)handle;

    status = ar_fseek(db->file_handle,
        *offset, AR_FSEEK_BEGIN);

    if (AR_FAILED(status)) return status;

    status = ar_fread(db->file_handle,
        buffer, read_size, &bytes_read);

    *offset += (uint32_t)bytes_read;

    return status;
}

int32_t acdb_fm_read_db_mem(acdb_file_man_handle_t handle,
    void* buffer, size_t read_size, uint32_t* offset)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo* db = NULL;
    uint8_t* buffer_ptr = NULL;

    if (read_size == 0)
        return status;

    if (IsNull(handle) || IsNull(buffer) || IsNull(offset))
        return AR_EBADPARAM;

    db = (AcdbFileManDatabaseInfo*)handle;
    buffer_ptr = (uint8_t*)db->database_cache;

    buffer_ptr += *offset;

    if ((*offset >= db->database_cache_size) ||
        (read_size > (db->database_cache_size - *offset)))
    {
        ACDB_ERR("Error[%d]: offset[%u] readsize[%zu] database_cache_size[%u] "
                "read beyond database cache bounds", AR_EBADPARAM, *offset,
                read_size, db->database_cache_size);
        return AR_EBADPARAM;
    }

    status = ar_mem_cpy(buffer, read_size, buffer_ptr, read_size);
    if (AR_FAILED(status)) return status;

    *offset += (uint32_t)read_size;

    return status;
}

int32_t acdb_fm_get_db_mem_ptr(acdb_file_man_handle_t handle,
    void** file_ptr, size_t data_size, uint32_t* offset)
{
    int32_t status = AR_EOK;
    AcdbFileManDatabaseInfo* db = NULL;

    if (IsNull(handle) || IsNull(file_ptr) || IsNull(offset))
        return AR_EBADPARAM;

    db = (AcdbFileManDatabaseInfo*)handle;

    if ((*offset >= db->database_cache_size) ||
        (data_size > (db->database_cache_size - *offset)))
    {
        ACDB_ERR("Error[%d]: offset[%u] datasize[%zu] database_cache_size[%u] "
                "read beyond database cache bounds", AR_EBADPARAM, *offset,
                data_size, db->database_cache_size);
        return AR_EBADPARAM;
    }

    *file_ptr = (uint8_t*)db->database_cache + *offset;
    *offset += (uint32_t)data_size;

    return status;
}

int32_t acdb_fm_get_db_mem_ptr_2(acdb_file_man_handle_t handle,
    void** file_ptr, uint32_t offset)
{
    int32_t status = AR_EOK;
    void* addr_start = NULL;
    void* addr_end = NULL;
    AcdbFileManDatabaseInfo* db = NULL;

    if (IsNull(handle) || IsNull(file_ptr))
        return AR_EBADPARAM;

    db = (AcdbFileManDatabaseInfo*)handle;
    addr_start = db->database_cache;
    addr_end = (uint8_t*)db->database_cache
        + db->database_cache_size;

    if((uint8_t*)addr_start + offset > (uint8_t*)addr_end)
        return AR_EBADPARAM;

    *file_ptr = (uint8_t*)db->database_cache + offset;

    return status;
}

int32_t FileManReadBuffer(void* buffer, size_t read_size, uint32_t* offset)
{
    acdb_context_handle_t* ctx_handle = NULL;

    ctx_handle = acdb_ctx_man_get_active_handle();

    if (IsNull(ctx_handle))
        return AR_EHANDLE;

    return acdb_fm_read_db_mem(ctx_handle->file_manager_handle,
        buffer, read_size, offset);
}

int32_t FileManGetFilePointer1(void** file_ptr, size_t data_size, uint32_t* offset)
{
    acdb_context_handle_t* handle = NULL;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle))
        return AR_EHANDLE;

    return acdb_fm_get_db_mem_ptr(handle->file_manager_handle,
        file_ptr, data_size, offset);
}

int32_t FileManGetFilePointer2(void** file_ptr, uint32_t offset)
{
    acdb_context_handle_t* handle = NULL;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle))
        return AR_EHANDLE;

    return acdb_fm_get_db_mem_ptr_2(handle->file_manager_handle,
        file_ptr, offset);
}

int32_t FileManDbReadAndSeek(acdb_fm_read_req_t *req)
{
    acdb_context_handle_t* ctx_handle = NULL;
    acdb_file_man_handle_t fm_handle = NULL;

    switch (req->handle_override)
    {
    case ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER:
        fm_handle = ACDB_FM_DB_INFO;
        break;
    case ACDB_FM_HANDLE_OVERRIDE_CTX_MANAGER:
    default:
        ctx_handle = acdb_ctx_man_get_active_handle();

        if (IsNull(ctx_handle))
            return AR_EHANDLE;

        fm_handle = ctx_handle->file_manager_handle;
        break;
    }

    return acdb_fm_read_db_mem(fm_handle,
        req->dst_buffer, req->read_size, &req->offset);
}

int32_t FileManGetDbPointerAndSeek(acdb_fm_file_ptr_req_t *req)
{
    acdb_context_handle_t* ctx_handle = NULL;
    acdb_file_man_handle_t fm_handle = NULL;

    switch (req->handle_override)
    {
    case ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER:
        fm_handle = ACDB_FM_DB_INFO;
        break;
    case ACDB_FM_HANDLE_OVERRIDE_CTX_MANAGER:
    default:
        ctx_handle = acdb_ctx_man_get_active_handle();

        if (IsNull(ctx_handle))
            return AR_EHANDLE;

        fm_handle = ctx_handle->file_manager_handle;
        break;
    }

    return acdb_fm_get_db_mem_ptr(fm_handle,
        &req->file_ptr, req->data_size, &req->offset);
}

int32_t FileManGetDbPointer(acdb_fm_file_ptr_req_t *req)
{
    acdb_context_handle_t* ctx_handle = NULL;
    acdb_file_man_handle_t fm_handle = NULL;

    switch (req->handle_override)
    {
    case ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER:
        fm_handle = ACDB_FM_DB_INFO;
        break;
    case ACDB_FM_HANDLE_OVERRIDE_CTX_MANAGER:
    default:
        ctx_handle = acdb_ctx_man_get_active_handle();

        if (IsNull(ctx_handle))
            return AR_EHANDLE;

        fm_handle = ctx_handle->file_manager_handle;
        break;
    }

    return acdb_fm_get_db_mem_ptr_2(fm_handle,
        &req->file_ptr, req->offset);
}

int32_t acdb_file_man_ioctl(uint32_t cmd_id,
    void *req, uint32_t req_size,
    void *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    switch (cmd_id)
    {
    case ACDB_FILE_MAN_INIT:
    {
        status = AcdbFileManInit();
        break;
    }
    case ACDB_FILE_MAN_ADD_DATABASE:
    {
        if (req == NULL || req_size != sizeof(acdb_file_man_data_files_t) ||
            rsp == NULL || rsp_size != sizeof(acdb_file_man_context_handle_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbFileManAddDatabase(
            (acdb_file_man_data_files_t*)req,
            (acdb_file_man_context_handle_t*)rsp);
        break;
    }
    case ACDB_FILE_MAN_REMOVE_DATABASE:
    {
        if (req == NULL || req_size != sizeof(acdb_file_man_handle_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbFileManRemoveDatabase(
            (acdb_file_man_handle_t*)req);
        break;
    }
    case ACDB_FILE_MAN_RESET:
    {
        status = AcdbFileManReset();
        break;
    }
    case ACDB_FILE_MAN_GET_VM_ID_FROM_FILE_NAME:
    {
        if (req == NULL || req_size != sizeof(AcdbFile) ||
            rsp == NULL || rsp_size != sizeof(uint32_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbFileManGetVmIdFromFileName(
            (AcdbFile*)req, (uint32_t*)rsp);
        break;
    }
    case ACDB_FILE_MAN_SET_WRITABLE_PATH:
    {
        if (req == NULL ||
            req_size != sizeof(acdb_file_man_writable_path_info_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbFileManSetWritablePath(
            (acdb_file_man_writable_path_info_t*)req);
        break;
    }
    case ACDB_FILE_MAN_GET_FILE_NAME:
    {
        if (req == NULL || req_size != sizeof(uint32_t) ||
            rsp == NULL || rsp_size != sizeof(acdb_path_256_t))
        {
            return AR_EBADPARAM;
        }

        status = AcdbFileManGetFileName(
            (int32_t*)req, (acdb_path_256_t*)rsp);
        break;
    }
    case ACDB_FILE_MAN_GET_HOST_DATABASE_FILE_SET_INFO:
    {
        if (rsp == NULL || rsp_size != sizeof(AcdbFileManBlob))
        {
            return AR_EBADPARAM;
        }

        status = AcdbFileManGetHostDatabaseFileInfo(
            (AcdbFileManBlob*)rsp);
        break;
    }
    case ACDB_FILE_MAN_GET_ALL_DATABASE_FILE_SETS:
    {
        if (rsp == NULL || rsp_size != sizeof(AcdbFileManBlob))
        {
            return AR_EBADPARAM;
        }

        status = AcdbFileManGetAllDatabasesFileInfo(
            (AcdbFileManBlob*)rsp);
        break;
    }
    case ACDB_FILE_MAN_GET_DATABASE_FILE_SET:
    {
        if (req == NULL || req_size == 0 ||
            rsp == NULL || rsp_size != sizeof(AcdbFileManBlob))
        {
            return AR_EBADPARAM;
        }

        status = AcdbFileManGetDatabaseFileSet(
            (AcdbFileManGetFileDataReq*)req,
            (AcdbFileManBlob*)rsp);
        break;
    }
    case ACDB_FILE_MAN_GET_WRITABLE_PATH:
    {
        if (req == NULL ||
            req_size != sizeof(acdb_file_man_writable_path_info_256_t))
        {
            return AR_EBADPARAM;
        }

        status = AcdbFileManGetWritablePath(req);
        break;
    }
    default:
        status = AR_EUNSUPPORTED;
        ACDB_ERR("Error[%d]: Unsupported Command[%08X]", status, cmd_id);
    }
    return status;
}
