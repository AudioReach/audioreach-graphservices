/**
*=============================================================================
* \file acdb_delta_file_mgr.c
*
* \brief
*		Contains the implementation of the delta acdb file manager
*		interface.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#include "ar_osal_error.h"
#include "ar_osal_file_io.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_init_utility.h"
#include "acdb_common.h"
#include "acdb_heap.h"
#include "acdb_data_proc.h"
#include "acdb_utility.h"
#include "acdb_context_mgr.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */
#define INF 4294967295U

/**< A File Manager macro that simplifies accessing the database info within the
 * File Manager context structure.
 *
 * Specify the index of the database info to retrieve
 *
 * NOTE: This macro is mainly used in for loops when cycling through
 * databases info entries
 */
#define ACDB_DFM_DB_INFO_AT_INDEX(index) acdb_delta_file_man_context \
.database_info[index]

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef struct _acdb_delta_file_man_database_info_t
AcdbDeltaFileManDatabaseInfo;
struct _acdb_delta_file_man_database_info_t {
    /**< The virtual machine id used by the database */
    uint32_t vm_id;
    /**< Index of the delta file in the delta file manager file list */
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
    /**< File path to the delta file */
    acdb_path_t delta_file_path;
    /**< Delta file version information */
    acdb_delta_file_version_t file_info;
};

typedef struct _acdb_delta_file_man_context_t AcdbDeltaFileManContext;
struct _acdb_delta_file_man_context_t
{
    ar_osal_mutex_t delta_lock;
    uint32_t database_count;
    AcdbDeltaFileManDatabaseInfo *database_info[MAX_ACDB_FILE_COUNT];
};

/* ---------------------------------------------------------------------------
* Static Variable Definitions
*--------------------------------------------------------------------------- */

/**< Maintains a list of AcdbDeltaFileManContext.*/
static AcdbDeltaFileManContext acdb_delta_file_man_context;

/**< Manages the state of the delta persistence.*/
static AcdbDeltaPersistState acdb_delta_persist_state;

/* ---------------------------------------------------------------------------
* Private Functions
*--------------------------------------------------------------------------- */

int32_t AcdbDeltaInit(void)
{
    int32_t status = AR_EOK;

    if (!acdb_delta_file_man_context.delta_lock)
    {
        status = ar_osal_mutex_create(&acdb_delta_file_man_context.delta_lock);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: failed to create acdb client mutex",
                status);
        }
    }
    return status;
}
int32_t AcdbDeltaAddDatabase(AcdbDeltaFileManFileInfo *info,
    acdb_delta_file_man_handle_t *handle)
{
	int32_t status = AR_EOK;
	uint32_t index = 0;
    AcdbDeltaFileManDatabaseInfo* db_info = NULL;

	if (info == NULL)
	{
		ACDB_ERR("Error[%d]: delta info is null", AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	if (acdb_delta_file_man_context.database_count >= MAX_ACDB_FILE_COUNT)
	{
		ACDB_ERR("Error[%d]: Max delta acdb file count exceeded. "
            "The max is %d. The current count is %d",
            AR_EBADPARAM, acdb_delta_file_man_context.database_count + 1);
		return AR_EBADPARAM;
	}

    ACDB_MUTEX_LOCK(acdb_delta_file_man_context.delta_lock);

    for (index = 0; index < MAX_ACDB_FILE_COUNT; index++)
    {
        if (IsNull(acdb_delta_file_man_context.database_info[index]))
            break;
    }

    if (MAX_ACDB_FILE_COUNT == index)
        index--;

    acdb_delta_file_man_context.database_info[index] =
        ACDB_MALLOC(AcdbDeltaFileManDatabaseInfo, 1);

    db_info = acdb_delta_file_man_context.database_info[index];

    ar_mem_set(db_info, 0, sizeof(AcdbDeltaFileManDatabaseInfo));
    acdb_delta_file_man_context.database_count++;

    db_info->vm_id = info->vm_id;
    db_info->file_index = index;
    db_info->acdb_file_index = info->acdb_file_index;
	db_info->file_info = info->file_info;
	db_info->is_updated = FALSE;
	db_info->exists = info->exists;
	db_info->file_size = info->file_size;
	db_info->file_handle = info->file_handle;
	db_info->delta_file_path.path_length =
        info->delta_file_path.path_length;
    db_info->delta_file_path.path =
        info->delta_file_path.path;

    *handle = db_info;
    ACDB_MUTEX_UNLOCK(acdb_delta_file_man_context.delta_lock);

	return status;
}

int32_t AcdbDeltaRemoveDatabase(acdb_delta_file_man_handle_t *dfm_handle)
{
    int32_t status = AR_EOK;
    AcdbDeltaFileManDatabaseInfo *db_info = NULL;

    if (IsNull(dfm_handle))
        return AR_EBADPARAM;

    db_info = (AcdbDeltaFileManDatabaseInfo*)dfm_handle;

    if (IsNull(db_info))
        return AR_EBADPARAM;

    ACDB_DFM_DB_INFO_AT_INDEX(db_info->acdb_file_index) = NULL;

    db_info->exists = FALSE;
    db_info->file_size = 0;

    if (!IsNull(db_info->file_handle))
    {
        (void)ar_fclose(db_info->file_handle);
        db_info->file_handle = NULL;
    }

    ACDB_FREE(db_info->delta_file_path.path);
    ACDB_FREE(db_info);

    ACDB_MUTEX_LOCK(acdb_delta_file_man_context.delta_lock);

    if (acdb_delta_file_man_context.database_count > 0)
        acdb_delta_file_man_context.database_count--;

    ACDB_MUTEX_UNLOCK(acdb_delta_file_man_context.delta_lock);

    return status;
}

int32_t AcdbDeltaDataCmdReset(void)
{
    int32_t status = AR_EOK;
    AcdbDeltaFileManDatabaseInfo* db_info = NULL;

    for (uint32_t i = 0; i < acdb_delta_file_man_context
        .database_count; i++)
    {
        db_info = ACDB_DFM_DB_INFO_AT_INDEX(i);

        if (IsNull(db_info))
            continue;

        status = AcdbDeltaRemoveDatabase(
            (acdb_delta_file_man_handle_t)db_info);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to remove delta database"
                " data at index %d", status, i);
            status = AR_EFAILED;
        }
    }

    ar_osal_mutex_destroy(acdb_delta_file_man_context.delta_lock);
    ar_mem_set(&acdb_delta_file_man_context, 0,
        sizeof(AcdbDeltaFileManContext));

    return status;
}
int32_t AcdbDeltaDataCmdGetDeltaVersion(uint32_t findex, uint32_t *delta_major, uint32_t *delta_minor)
{
	int32_t result = AR_EOK;
	uint32_t offset = 0;
	size_t bytes_read = 0;

    if (findex >= acdb_delta_file_man_context.database_count)
    {
        ACDB_ERR("Error[%d]: "
            "The file index %d is larger than the total file count %d",
            AR_EBADPARAM, findex, acdb_delta_file_man_context.database_count)
            return AR_EBADPARAM;
    }

    //todo: push this file parsing logic down to the delta file parser

	if (acdb_delta_file_man_context.database_info[findex]->exists == TRUE && acdb_delta_file_man_context.database_info[findex]->file_handle != NULL)
	{
		offset = 0;
		if (acdb_delta_file_man_context.database_info[findex]->file_size > sizeof(AcdbDeltaFileHeader) + sizeof(uint32_t))
		{
			int ret = ar_fseek(acdb_delta_file_man_context.database_info[findex]->file_handle, offset, AR_FSEEK_BEGIN);
			if (ret != 0)
			{
				ACDB_ERR("AcdbDeltaDataCmdGetDeltaVersion() failed, file seek to %d was unsuccessful", offset);
				return AR_EFAILED;
			}
			ret = ar_fread(acdb_delta_file_man_context.database_info[findex]->file_handle, &delta_major, sizeof(uint32_t), &bytes_read);
			if (ret != 0)
			{
				ACDB_ERR("AcdbDeltaDataCmdGetDeltaVersion() failed, delta_major read was unsuccessful");
				return AR_EFAILED;
			}
			offset += sizeof(uint32_t); // curDeltafilemajor
			ret = ar_fseek(acdb_delta_file_man_context.database_info[findex]->file_handle, offset, AR_FSEEK_BEGIN);
			if (ret != 0)
			{
				ACDB_ERR("AcdbDeltaDataCmdGetDeltaVersion() failed, file seek to %d was unsuccessful", offset);
				return AR_EFAILED;
			}
			ret = ar_fread(acdb_delta_file_man_context.database_info[findex]->file_handle, &delta_minor, sizeof(uint32_t), &bytes_read);
			if (ret != 0)
			{
				ACDB_ERR("AcdbDeltaDataCmdGetDeltaVersion() failed, delta_minor read was unsuccessful");
				return AR_EFAILED;
			}
			offset += sizeof(uint32_t); // curDeltafileminor
		}
	}

	return result;
}

int32_t AcdbDeltaDataCmdSave(void)
{
	int32_t status = AR_EOK;
    ar_fhandle *fhandle = NULL;
	uint32_t fsize = 0;
	uint32_t fdata_size = 0; ;
	LinkedList *p_map_list = NULL;
	LinkedList map_list = { 0 };
	LinkedListNode *cur_node = NULL;
	//acdb_path_256_t file_name_info = { 0 };
	acdb_delta_data_map_t *map = NULL;
    AcdbInitUtilDeltaInfo delta_info = { 0 };
    acdb_context_handle_t *context_handle = NULL;
    AcdbDeltaFileManDatabaseInfo *db_info = NULL;

    context_handle = acdb_ctx_man_get_active_handle();

    if (IsNull(context_handle) || IsNull(context_handle->delta_manager_handle))
    {
        ACDB_ERR("Warning[%d]: Unable to save delta file. There is no delta file",
            AR_EHANDLE);
        return AR_EOK;
    }

    db_info = (AcdbDeltaFileManDatabaseInfo*)
        context_handle->delta_manager_handle;

    fhandle = &db_info->file_handle;

	//Close and delete old delta file
	ar_fclose(*fhandle);

    status = ar_fdelete(db_info->delta_file_path.path);

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to delete delta file", status);
        return status;
    }

	/* Create new delta file and set ar_fhandle to acdb_delta_file_man_context
	 * at findex. Check to see if file exists otherwise create it */
    delta_info.properties.file_access_io_flag = ACDB_FUNC_IO_IN;
    delta_info.properties.file_access = AR_FOPEN_WRITE_ONLY;
    delta_info.delta_path = db_info->delta_file_path;

	status = AcdbInitUtilGetDeltaInfo2(
        &db_info->delta_file_path, &delta_info.properties);
    if (AR_FAILED(status))
	{
		ACDB_ERR_MSG_1("Unable to create a new delta acdb file", status);
        return status;
	}

    fsize = delta_info.properties.file_size;
    delta_info.properties.file_access = AR_FOPEN_READ_ONLY_WRITE;

	status = AcdbInitUtilOpenDeltaFile(&delta_info, fhandle);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to open delta file", status);
        return status;
    }

	db_info->file_handle = *fhandle;

	status = acdb_delta_parser_write_file_header(
		db_info->file_handle,
		&db_info->file_info, 0, 0);

    if (AR_FAILED(status)) goto end;

	p_map_list = &map_list;

	status = acdb_heap_ioctl(ACDB_HEAP_CMD_GET_MAP_LIST, NULL, 0,
        (uint8_t*)&p_map_list, sizeof(LinkedList));
	if (AR_EOK != status) goto end;

	cur_node = p_map_list->p_head;

	while (cur_node != NULL)
	{
        map = ((acdb_delta_data_map_t*)cur_node->p_struct);
        status = acdb_delta_parser_write_map(*fhandle, map);
        if (AR_EOK != status) break;
		cur_node = cur_node->p_next;
	}

	status = ar_fseek(*fhandle, 0, AR_FSEEK_BEGIN);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to seek delta file", status);
        goto end;
    }

	fsize = (uint32_t)ar_fsize(*fhandle);
	fdata_size = fsize - sizeof(AcdbDeltaFileHeader) + sizeof(uint32_t);

	status = acdb_delta_parser_write_file_header(
		db_info->file_handle,
		&db_info->file_info, fdata_size, p_map_list->length);

	if (AR_EOK != status) goto end;

	db_info->is_updated = TRUE;
	db_info->file_size = fsize;

end:
    AcdbListClear(p_map_list);
    p_map_list = NULL;
    ar_fclose(*fhandle);

	return status;
}
int32_t AcdbDeltaInitHeap(acdb_context_handle_t *handle)
{
    int32_t status = AR_EOK;
    uint32_t foffset = sizeof(AcdbDeltaFileHeader);
    acdb_delta_data_map_t *map = NULL;
    AcdbDeltaFileManDatabaseInfo *db_info = NULL;
    acdb_heap_map_handle_info_t map_handle_info = { 0 };

    /* todo: read entire delta file into memory, close file,
     * and write that memory into the heap format */

    if (IsNull(handle))
        return AR_EBADPARAM;

    db_info = (AcdbDeltaFileManDatabaseInfo*)handle->delta_manager_handle;

    if (IsNull(db_info))
        return AR_EHANDLE;

    map_handle_info.handle = handle->heap_handle;
    while (foffset < db_info->file_size)
    {
        map = ACDB_MALLOC(acdb_delta_data_map_t, 1);
        map_handle_info.map = map;

        if (IsNull(map))
        {
            ACDB_ERR("Error[%d]: Failed to allocate memory "
                "for delta data map.", status);
            status = AR_ENOMEMORY;
            break;
        }

        ACDB_CLEAR_BUFFER(*map);

        status = acdb_delta_parser_read_map(
            db_info->file_handle, &foffset, map);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read map "
                "from the *.acdbdelta file.", status);
            break;
        }

        status = acdb_heap_ioctl(ACDB_HEAP_CMD_ADD_MAP_USING_HANDLE,
            &map_handle_info, sizeof(acdb_delta_data_map_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to add map to the heap.", status);
            break;
        }
    }

    if (AR_FAILED(status))
    {
        uint32_t status2 = acdb_heap_ioctl(ACDB_HEAP_CMD_CLEAR_DATABASE_HEAP,
            handle->heap_handle, sizeof(acdb_heap_handle_t), NULL, 0);
        if (AR_FAILED(status2))
        {
            ACDB_ERR("Error[%d]: Unable to clear the heap.", status2);
        }
    }

    return status;
}

int32_t AcdbDeltaUpdateHeap(acdb_context_handle_t* handle)
{
    int32_t status = AR_EOK;
    uint32_t foffset = sizeof(AcdbDeltaFileHeader);
    acdb_delta_data_map_t* map = NULL;
    AcdbDeltaFileManDatabaseInfo* db_info = NULL;

    if (IsNull(handle))
        return AR_EBADPARAM;

    db_info = (AcdbDeltaFileManDatabaseInfo*)handle->delta_manager_handle;

    if (IsNull(db_info))
        return AR_EHANDLE;

    while (foffset < db_info->file_size)
    {
        map = ACDB_MALLOC(acdb_delta_data_map_t, 1);

        if (IsNull(map))
        {
            ACDB_ERR("Error[%d]: Failed to allocate memory "
                "for delta data map.", status);
            status = AR_ENOMEMORY;
            break;
        }

        ACDB_CLEAR_BUFFER(*map);

        status = acdb_delta_parser_read_map(
            db_info->file_handle, &foffset, map);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read map "
                "from the *.acdbdelta file.", status);
            break;
        }

        status = DataProcSetMapToHeap(map);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to set map to the heap.", status);
            break;
        }
    }

    if (AR_EOK != status)
    {
        status = acdb_heap_ioctl(ACDB_HEAP_CMD_CLEAR_DATABASE_HEAP,
            handle->heap_handle, sizeof(acdb_heap_handle_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to clear the heap.", status);
        }
    }

    return status;
}

int32_t AcdbDeltaDeleteFile(uint32_t database_index)
{
    int32_t status = AR_EOK;
    ar_fhandle *fhandle = NULL;
    acdb_path_256_t file_name_info = { 0 };

    if (database_index >= acdb_delta_file_man_context.database_count)
    {
        ACDB_ERR("Error[%d]: "
            "The file index %d is larger than the total file count %d",
            AR_EBADPARAM, database_index, acdb_delta_file_man_context.database_count)
            return AR_EBADPARAM;
    }

    fhandle = &ACDB_DFM_DB_INFO_AT_INDEX(database_index)->file_handle;

    memset(&file_name_info.path[0], 0, ACDB_MAX_PATH_LENGTH);
    file_name_info.path_len = 0;
    status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_FILE_NAME,
        &database_index, sizeof(uint32_t),
        &file_name_info, sizeof(file_name_info));

    //Close and delete old delta file
    status = ar_fclose(*fhandle);
    if (AR_EOK != status)
    {
        ACDB_ERR("Error[%d]: Failed to close delta file", status);
        return status;
    }

    status = AcdbInitUtilDeleteDeltaFileData(
        file_name_info.path, file_name_info.path_len,
        &ACDB_DFM_DB_INFO_AT_INDEX(database_index)->delta_file_path);

    if (AR_EOK != status) return status;

    ACDB_DFM_DB_INFO_AT_INDEX(database_index)->exists = FALSE;
    ACDB_DFM_DB_INFO_AT_INDEX(database_index)->is_updated = FALSE;

    return status;
}

int32_t AcdbDeltaDataSwapDelta(AcdbDeltaDataSwapInfo *swap_info)
{
    int32_t status = AR_EOK;
    AcdbDeltaFileManDatabaseInfo *db_info = NULL;
    AcdbInitUtilDeltaInfo delta_info = { 0 };
    acdb_path_256_t file_name_info = { 0 };
    acdb_path_t delta_dir = { 0 };

    if (IsNull(swap_info))
    {
        ACDB_ERR("Error[%d]: The swap info input parameter is null",
            AR_EBADPARAM)
            return AR_EBADPARAM;
    }

    if (swap_info->file_index >= acdb_delta_file_man_context.database_count)
    {
        ACDB_ERR("Error[%d]: "
            "The file index %d is larger than the total file count %d",
            AR_EBADPARAM, swap_info->file_index,
            acdb_delta_file_man_context.database_count)
        return AR_EBADPARAM;
    }

    db_info = ACDB_DFM_DB_INFO_AT_INDEX(swap_info->file_index);

    /* Close the previous delta file and open/create the new file */
    status = ar_fclose(db_info->file_handle);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to close %s ", status,
            db_info->delta_file_path.path);
        return status;
    }

    status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_FILE_NAME,
        &db_info->acdb_file_index, sizeof(uint32_t),
        &file_name_info, sizeof(file_name_info));

    //Open/Create rw_delta file
    delta_info.properties.file_access_io_flag = ACDB_FUNC_IO_IN;
    delta_info.properties.file_access = swap_info->file_access;

    delta_dir.path_length = swap_info->path_info.path_len;
    delta_dir.path = &swap_info->path_info.path[0];

    status = AcdbInitUtilGetDeltaInfo(
        &file_name_info.path[0], file_name_info.path_len,
        &delta_dir, &delta_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Failed to get read/write delta file info", status);
        return status;
    }

    status = AcdbInitUtilOpenDeltaFile(
        &delta_info, &db_info->file_handle);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Failed to open read/write delta file", status);
        return status;
    }

    ACDB_FREE(db_info->delta_file_path.path);
    db_info->file_size = delta_info.properties.file_size;
    db_info->delta_file_path = delta_info.delta_path;

    return status;
}

int32_t AcdbDeltaDataIsFileAtPath(AcdbDeltaDataSwapInfo *swap_info)
{
    int32_t status = AR_EOK;
    AcdbDeltaFileManDatabaseInfo *delta_finfo = NULL;
    AcdbInitUtilDeltaInfo delta_info = { 0 };
    acdb_path_256_t file_name_info = { 0 };
    acdb_path_t delta_dir = { 0 };

    if (IsNull(swap_info))
    {
        ACDB_ERR("Error[%d]: The swap info input parameter is null",
            AR_EBADPARAM)
            return AR_EBADPARAM;
    }

    if (swap_info->file_index >=
        acdb_delta_file_man_context.database_count)
    {
        ACDB_ERR("Error[%d]: "
            "The file index %d is larger than the total file count %d",
            AR_EBADPARAM, swap_info->file_index,
            acdb_delta_file_man_context.database_count)
            return AR_EBADPARAM;
    }

    delta_finfo = ACDB_DFM_DB_INFO_AT_INDEX(swap_info->file_index);
    delta_info.properties.file_access_io_flag = ACDB_FUNC_IO_IN;
    delta_info.properties.file_access = swap_info->file_access;

    delta_dir.path_length = swap_info->path_info.path_len;
    delta_dir.path = &swap_info->path_info.path[0];

    status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_FILE_NAME,
        &delta_finfo->acdb_file_index, sizeof(uint32_t),
        &file_name_info, sizeof(file_name_info));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Failed to get acdb file name at file index %d",
            status, delta_finfo->acdb_file_index);
        return status;
    }

    status = AcdbInitUtilGetDeltaInfo(
        &file_name_info.path[0], file_name_info.path_len,
        &delta_dir, &delta_info);
    if (AR_ENOTEXIST == status)
    {
        ACDB_ERR("Error[%d]: "
            "The delta file %s does not exist",
            status, delta_info.delta_path.path);
        goto end;
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Failed to open read/write delta file", status);
        goto end;
    }

end:
    ACDB_FREE(delta_info.delta_path.path);

    return status;
}

/* ---------------------------------------------------------------------------
* Public Functions
*--------------------------------------------------------------------------- */

int32_t acdb_delta_data_is_persist_enabled(void)
{
    return (int32_t)acdb_delta_persist_state;
}

int32_t acdb_delta_data_ioctl(uint32_t cmd_id,
	void *req, uint32_t req_size,
	void *rsp, uint32_t rsp_size)
{
	int32_t status = AR_EOK;

    switch (cmd_id)
    {
    case ACDB_DELTA_DATA_CMD_INIT:
    {
        status = AcdbDeltaInit();
        break;
    }
    case ACDB_DELTA_DATA_CMD_ADD_DATABASE:
    {
        if (req == NULL || req_size != sizeof(AcdbDeltaFileManFileInfo) ||
            rsp == NULL || rsp_size != sizeof(acdb_delta_file_man_handle_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbDeltaAddDatabase((AcdbDeltaFileManFileInfo *)req,
            (acdb_delta_file_man_handle_t*)rsp);
    }
    break;
    case ACDB_DELTA_DATA_CMD_REMOVE_DATABASE:
    {
        if (req == NULL || req_size != sizeof(acdb_delta_file_man_handle_t))
        {
            return AR_EBADPARAM;
        }
        status = AcdbDeltaRemoveDatabase((acdb_delta_file_man_handle_t*)req);
    }
    break;
    case ACDB_DELTA_DATA_CMD_ENABLE_PERSISTENCE:
    {
        if (req == NULL || req_size != sizeof(AcdbDeltaPersistState))
        {
            return AR_EBADPARAM;
        }

        acdb_delta_persist_state = *(AcdbDeltaPersistState*)req;
    }
    break;
    case ACDB_DELTA_DATA_CMD_RESET:
    {
        status = AcdbDeltaDataCmdReset();
    }
    break;
    case ACDB_DELTA_DATA_CMD_GET_FILE_VERSION:
    {
        uint32_t delta_major = 0;
        uint32_t delta_minor = 0;
        uint32_t *pDeltafile_index = NULL;
        acdb_delta_file_version_t *deltaVersion =
            ACDB_MALLOC(acdb_delta_file_version_t, 1);

        if (deltaVersion == NULL)
        {
            ACDB_FREE(deltaVersion);
            return AR_ENOMEMORY;
        }

        if (IsNull(req) || req_size != sizeof(uint32_t))
        {
            ACDB_FREE(deltaVersion);
            return AR_EBADPARAM;
        }

        pDeltafile_index = (uint32_t *)req;
        status = AcdbDeltaDataCmdGetDeltaVersion(
            *pDeltafile_index, &delta_major, &delta_minor);
        deltaVersion->major = delta_major;
        deltaVersion->minor = delta_minor;

        ACDB_MEM_CPY_SAFE(rsp, sizeof(acdb_delta_file_version_t),
            deltaVersion, sizeof(acdb_delta_file_version_t));
        ACDB_FREE(deltaVersion);
        status = AR_EOK;
    }
    break;
    case ACDB_DELTA_DATA_CMD_INIT_HEAP:
    {
        if (IsNull(req) || req_size != sizeof(acdb_context_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = AcdbDeltaInitHeap((acdb_context_handle_t*)req);
    }
    break;
    case ACDB_DELTA_DATA_CMD_UPDATE_HEAP:
    {
        if (IsNull(req) || req_size != sizeof(acdb_context_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = AcdbDeltaUpdateHeap((acdb_context_handle_t*)req);
    }
    break;
    case ACDB_DELTA_DATA_CMD_SAVE:
    {
        status = AcdbDeltaDataCmdSave();
    }
    break;
    case ACDB_DELTA_DATA_CMD_DELETE_ALL_FILES:
    {
        status = AcdbDeltaDeleteFile(0);//todo: check this last
    }
    break;
    case ACDB_DELTA_DATA_CMD_GET_FILE_COUNT:
    {
        if (IsNull(rsp) || rsp_size != sizeof(uint32_t))
        {
            return AR_EBADPARAM;
        }

        *(uint32_t*)rsp = acdb_delta_file_man_context.database_count;
    }
    break;
    case ACDB_DELTA_DATA_CMD_SWAP_DELTA:
    {
        if (IsNull(req) || req_size != sizeof(AcdbDeltaDataSwapInfo))
        {
            return AR_EBADPARAM;
        }

        status = AcdbDeltaDataSwapDelta((AcdbDeltaDataSwapInfo*)req);
    }
    break;
    case ACDB_DELTA_DATA_CMD_IS_FILE_AT_PATH:
    {
        if (IsNull(req) || req_size != sizeof(AcdbDeltaDataSwapInfo))
        {
            return AR_EBADPARAM;
        }

        status = AcdbDeltaDataIsFileAtPath((AcdbDeltaDataSwapInfo*)req);
    }
    break;
	default:
		status = AR_EUNSUPPORTED;
		ACDB_ERR("Error[%d]: Unsupported command %08X", status, cmd_id);
	}

	return status;
}
