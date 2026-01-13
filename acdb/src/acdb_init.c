/**
*=============================================================================
* \file acdb_init.c
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
#include "acdb_init.h"
#include "acdb_init_utility.h"
#include "acdb_parser.h"
#include "acdb_delta_parser.h"
#include "acdb_common.h"
#include "acdb_context_mgr.h"
#include "acdb_file_mgr.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_heap.h"

/* ---------------------------------------------------------------------------
* Global Data Definitions
*--------------------------------------------------------------------------- */

const char* WKSP_FILE_NAME_EXT = ".qwsp";
const char* ACDB_FILE_NAME_EXT = ".acdb";

/* ---------------------------------------------------------------------------
* helper functions
*--------------------------------------------------------------------------- */

bool_t AcdbInitDoSwVersionsMatch(acdb_file_version_t* acdb_finfo,
	acdb_delta_file_version_t* acdb_delta_finfo)
{
	if ((acdb_finfo->major == acdb_delta_finfo->major) &&
		(acdb_finfo->minor == acdb_delta_finfo->minor) &&
		(acdb_finfo->revision == acdb_delta_finfo->revision) &&
		(acdb_finfo->cpl_info == INF ||
			acdb_finfo->cpl_info == acdb_delta_finfo->cpl_info))
	{
		return TRUE;
	}
	return FALSE;
}

void AcdbInitUnloadAcdbFile(AcdbFileManFileInfo* acdb_file_info)
{
	if (!IsNull(acdb_file_info->file_handle))
	{
		(void)ar_fclose(acdb_file_info->file_handle);
	}

	acdb_file_info->file_handle = NULL;
	ACDB_FREE(acdb_file_info->file.buffer);
	acdb_file_info->file.buffer = NULL;
}

void AcdbInitUnloadDeltaFile(AcdbDeltaFileManFileInfo* delta_file_info)
{
	if (!IsNull(delta_file_info->file_handle))
	{
		(void)ar_fclose(delta_file_info->file_handle);
	}

	delta_file_info->file_handle = NULL;
	delta_file_info->exists = FALSE;
	delta_file_info->file_size = 0;

	ACDB_FREE(delta_file_info->delta_file_path.path);
}

int32_t AcdbInitLoadAcdbFile(AcdbFileManFileInfo *acdb_cmd_finfo,
	acdb_file_version_t *acdb_finfo)
{
	int32_t status = AR_EOK;
	ar_fhandle *fhandle = &acdb_cmd_finfo->file_handle;
	acdb_header_v1_t header_v1 = { 0 };

	if (ACDB_FIND_STR(acdb_cmd_finfo->path, WKSP_FILE_NAME_EXT) != NULL)
	{
        /* The workspace file is only opened when ARCT(or other ACDB client)
         * connects and querries for file information
         */
        acdb_cmd_finfo->file_type = ACDB_FILE_TYPE_WORKSPACE;
	}
	else if (ACDB_FIND_STR(acdb_cmd_finfo->path, ACDB_FILE_NAME_EXT) != NULL)
	{
        acdb_cmd_finfo->file_type = ACDB_FILE_TYPE_DATABASE;

        status = AcdbInitUtilGetFileData(
            acdb_cmd_finfo->path, fhandle,
            &acdb_cmd_finfo->file
        );

        if (AR_FAILED(status) || IsNull(fhandle))
            return status;

		status = acdb_parser_validate_file(
			&acdb_cmd_finfo->file);
		if (AR_FAILED(status))
			return status;

		status = acdb_parser_get_acdb_header_v1(
			&acdb_cmd_finfo->file,
			&header_v1);

		acdb_finfo->major = header_v1.file_version.major;
		acdb_finfo->minor = header_v1.file_version.minor;
		acdb_finfo->revision = header_v1.file_version.revision;
		acdb_finfo->cpl_info = header_v1.file_version.cpl_info;

		AcdbLogFileInfo(&header_v1);
	}
    else
    {
        //Provided file is not an acdb or workspace file
        ACDB_ERR("Error[%d]: %s is not a *.qwsp or *.acdb file.",
			AR_EBADPARAM, acdb_cmd_finfo->path);
        return AR_EBADPARAM;
    }

	fhandle = NULL;
	return status;
}

int32_t AcdbInitLoadDeltaFile(AcdbFileManFileInfo *acdb_cmd_finfo,
	acdb_file_version_t *acdb_file_version, acdb_path_t *delta_dir,
	AcdbDeltaFileManFileInfo *delta_finfo)
{
    int32_t status = AR_EOK;
    AcdbInitUtilDeltaInfo delta_info = { 0 };
    ar_fhandle *fhandle = &delta_finfo->file_handle;

    delta_info.properties.file_access_io_flag = ACDB_FUNC_IO_OUT;
    status = AcdbInitUtilGetDeltaInfo(
        acdb_cmd_finfo->path,
        acdb_cmd_finfo->path_length,
        delta_dir, &delta_info);
    if (AR_FAILED(status))
    {
        fhandle = NULL;
        delta_finfo->exists = FALSE;
		return status;
    }

    status = AcdbInitUtilOpenDeltaFile(&delta_info, fhandle);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to open the delta file %s",
            status, delta_info.delta_path.path);
		goto unload_file;
    }

	/* The delta file manager will be responsible for freeing the memory
	associated with delta_finfo->delta_file_path.path*/
	delta_finfo->delta_file_path = delta_info.delta_path;

    /* Validate the delta file only if it exists. Otherwise bypass
     * validation. */
    if (AR_FOPEN_WRITE_ONLY != delta_info.properties.file_access
		&& delta_info.properties.file_size > 0)
    {
        if (ACDB_PARSE_SUCCESS != acdb_delta_parser_is_file_valid(
            *fhandle, delta_info.properties.file_size))
        {
            status =  AR_EFAILED;
			goto unload_file;
        }

        status = acdb_delta_parser_get_file_version(
			*fhandle, delta_info.properties.file_size,
            &delta_finfo->file_info);
        if (AR_FAILED(status))
        {
			goto unload_file;
        }

		if (!AcdbInitDoSwVersionsMatch(
			acdb_file_version, &delta_finfo->file_info))
		{
			goto unload_file;
		}

        AcdbLogDeltaFileVersion(
            delta_finfo->file_info.major,
            delta_finfo->file_info.minor,
            delta_finfo->file_info.revision,
            delta_finfo->file_info.cpl_info
        );
    }

    delta_finfo->exists = TRUE;
    delta_finfo->file_size = delta_info.properties.file_size;
    delta_finfo->acdb_file_index = acdb_cmd_finfo->file_index;

	/* Set the acdb file version to new delta files */
	if (AR_FOPEN_WRITE_ONLY == delta_info.properties.file_access
		&& delta_finfo->file_size == 0)
	{
		ACDB_MEM_CPY_SAFE(&delta_finfo->file_info, sizeof(acdb_file_version_t),
			acdb_file_version, sizeof(acdb_file_version_t));
	}

unload_file:
	if(AR_FAILED(status))
		AcdbInitUnloadDeltaFile(delta_finfo);

    return status;
}

/* ---------------------------------------------------------------------------
* ioctl command implementations
*--------------------------------------------------------------------------- */

int32_t acdb_init_layers(void)
{
    int32_t status = AR_EOK;

	ACDB_PKT_LOG_INIT();

	status = AcdbARHeapInit();
	if (AR_FAILED(status))
	{
		return status;
	}

	AcdbLogSwVersion(
		ACDB_SOFTWARE_VERSION_MAJOR,
		ACDB_SOFTWARE_VERSION_MINOR,
		ACDB_SOFTWARE_VERSION_REVISION,
		ACDB_SOFTWARE_VERSION_CPLINFO);

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_INIT, NULL, 0, NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to initialize context manager.", status);
        return status;
    }
    status = acdb_file_man_ioctl(ACDB_FILE_MAN_INIT, NULL, 0, NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to initialize file manager.", status);
        return status;

    }
    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_INIT, NULL, 0, NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to initialize delta file manager.", status);
        return status;

    }
    status = acdb_heap_ioctl(ACDB_HEAP_CMD_INIT, NULL, 0, NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to initialize heap manager.", status);
        return status;

    }

    return status;
}

int32_t acdb_init_add_database(acdb_init_database_paths_t *database_paths,
	acdb_handle_t *acdb_handle)
{
	int32_t status = AR_EOK;
	uint32_t i = 0, j = 0;
	uint32_t remaining_file_slots = 0;
	uint32_t num_data_files = 0;
	bool_t should_ignore_delta_file = FALSE;
	bool_t is_writable_path_avalible = FALSE;
	acdb_file_version_t acdb_file_version = { 0 };
	AcdbFileManFileInfo *fm_file_info = NULL;
	AcdbDeltaFileManFileInfo *dfm_file_info = NULL;
	acdb_context_handle_t ctx_handle = { 0 };
	acdb_file_man_context_handle_t fm_ctx_handle = { 0 };
	acdb_file_man_data_files_t fm_db_files = { 0 };
	acdb_file_man_writable_path_info_t writable_path_info = { 0 };

	if (IsNull(database_paths) || database_paths->num_files == 0)
	{
		ACDB_ERR("Error[%d]: No database files were provided.", AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	if (database_paths->num_files > ACDB_MAX_FILE_ADD_LIMIT)
	{
		ACDB_ERR("Error[%d]: The max number of files that can be initalized "
			"is %d: one *.qwsp and one *.acdb", AR_EBADPARAM,
			ACDB_MAX_FILE_ADD_LIMIT);
		return AR_EBADPARAM;
	}

	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_AVAILABLE_FILE_SLOTS,
		NULL, 0, (uint8_t*)&remaining_file_slots, sizeof(uint32_t));
	if (AR_FAILED(status) || remaining_file_slots < database_paths->num_files)
	{
		ACDB_ERR("Error[%d]: Only %d/%d file slots available.", AR_ENORESOURCE,
			remaining_file_slots, MAX_ACDB_FILE_COUNT);
		status = AR_ENORESOURCE;
		goto end;
	}

	is_writable_path_avalible = !IsNull(database_paths->writable_path.path);

	fm_db_files.num_files = database_paths->num_files;
	fm_file_info = ACDB_MALLOC(
		AcdbFileManFileInfo, database_paths->num_files);
	dfm_file_info = ACDB_MALLOC(
		AcdbDeltaFileManFileInfo, database_paths->num_files);
	if (IsNull(fm_file_info) || IsNull(dfm_file_info))
	{
		ACDB_ERR("Error[%d]: Unable to allocate memory to store "
			"acdb data file information", AR_ENOMEMORY);
		goto end;
	}

	ar_mem_set(fm_file_info, 0, sizeof(AcdbFileManFileInfo)
		* database_paths->num_files);
	ar_mem_set(dfm_file_info, 0, sizeof(AcdbDeltaFileManFileInfo)
		* database_paths->num_files);

	for (i = 0; i < database_paths->num_files; i++)
	{
		fm_file_info[i].file_index = i;
		fm_file_info[i].path_length =
			database_paths->acdb_data_files[i].path_length;
		fm_file_info[i].path =
			database_paths->acdb_data_files[i].path;

		fm_db_files.file_info[i] = &fm_file_info[i];

		status = AcdbInitLoadAcdbFile(&fm_file_info[i], &acdb_file_version);
		if (AR_FAILED(status))
		{
			for (j = 0; j < database_paths->num_files; j++)
			{
				AcdbInitUnloadAcdbFile(&fm_file_info[j]);
				AcdbInitUnloadDeltaFile(&dfm_file_info[j]);
			}

			ACDB_ERR_MSG_1("Acdb initialization failed.", AR_EFAILED);
			status = AR_EFAILED;
			goto end;
		}

		if (ACDB_FILE_TYPE_WORKSPACE == fm_file_info[i].file_type) continue;

		num_data_files++;

		/* Load delta file */
		if (is_writable_path_avalible)
		{
			status = AcdbInitLoadDeltaFile(
				&fm_file_info[i], &acdb_file_version,
				&database_paths->writable_path, &dfm_file_info[i]);

			should_ignore_delta_file =
				AR_FAILED(status) || !dfm_file_info[i].exists ? TRUE : FALSE;
		}
	}

	if (num_data_files == 0)
	{
		ACDB_ERR("Error[%d]: No *.acdb files were found.", AR_ENORESOURCE);
		status = AR_ENORESOURCE;
		goto end;
	}

	status = acdb_file_man_ioctl(ACDB_FILE_MAN_ADD_DATABASE,
		&fm_db_files, sizeof(acdb_file_man_data_files_t),
		&fm_ctx_handle, sizeof(fm_ctx_handle));
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to add database file "
			"set (*.qwsp/*.acdb).", status);
		goto end;
	}

	uint32_t findex = 0;
	for (i = 0; i < database_paths->num_files; i++)
	{
		if (ACDB_FILE_TYPE_WORKSPACE == fm_file_info[i].file_type)
			continue;

		status = acdb_heap_ioctl(ACDB_HEAP_CMD_ADD_DATABASE,
			(uint8_t*)&fm_ctx_handle.vm_id, sizeof(uint32_t),
			(uint8_t*)&ctx_handle.heap_handle, sizeof(acdb_heap_handle_t));

		if (is_writable_path_avalible && !should_ignore_delta_file)
		{
			dfm_file_info[i].vm_id = fm_ctx_handle.vm_id;
			dfm_file_info[i].acdb_file_index = findex;

			status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_ADD_DATABASE,
				&dfm_file_info[i], sizeof(AcdbDeltaFileManFileInfo),
				&ctx_handle.delta_manager_handle, sizeof(acdb_delta_file_man_handle_t));
			if (AR_EOK != status)
			{
				/*if we fail to add the delta file, remove it from memory and continue */
				AcdbInitUnloadDeltaFile(&dfm_file_info[i]);
				ACDB_ERR_MSG_1("Failed to initialize delta acdb files.",
					status);
				goto end;
			}
		}

		ctx_handle.vm_id = fm_ctx_handle.vm_id;
		ctx_handle.file_manager_handle = fm_ctx_handle.file_man_handle;
		status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_ADD_DATABASE,
			(void*)&ctx_handle, sizeof(acdb_context_handle_t), NULL, 0);
		if (AR_FAILED(status))
		{
			//the context manager should not fail. This is a serious error
			ACDB_ERR("Error[%d]: Unable to update context manager "
				"with new database", status);
			goto end;
		}

		/* Load the contents of the delta file into the heap */

		if (is_writable_path_avalible && !should_ignore_delta_file)
		{
			uint32_t delta_status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_INIT_HEAP,
				&ctx_handle, sizeof(acdb_context_handle_t),
				NULL, 0);
			if (AR_EOK != delta_status)
			{
				ACDB_ERR("Warning[%d]: Unable to load delta file into heap", delta_status);
				status = delta_status;
			}
		}

		if (is_writable_path_avalible)
		{
			/* The delta file path serves two purposes:
			*	1. to store the delta files
			*	2. to store temporary files generated by ATS clients (e.g ARCT)
			* The delta file path will be set as the temporary file path managed
			* by the File Manager
			*/
			writable_path_info.handle = ctx_handle.file_manager_handle;
			writable_path_info.writable_path = database_paths->writable_path;

			status = acdb_file_man_ioctl(ACDB_FILE_MAN_SET_WRITABLE_PATH,
				&writable_path_info, sizeof(acdb_file_man_writable_path_info_t),
				NULL, 0);
			if (AR_FAILED(status))
			{
				ACDB_ERR("Error[%d]: Unable to set temporary file path using "
					"the delta file path. Skipping..", status);
				status = AR_EOK;
			}
		}
		else
		{
			ACDB_DBG("Unable to set temporary file path using "
				"the delta file path. No path was provided. Skipping..");
		}

		findex++;
	}

	if (acdb_handle)
	{
		status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_ACDB_CLIENT_HANDLE,
			&fm_ctx_handle.vm_id, sizeof(uint32_t),
			acdb_handle, sizeof(acdb_handle_t));
	}

end:

	ACDB_FREE(fm_file_info);
	ACDB_FREE(dfm_file_info);
	return status;
}

int32_t acdb_init_remove_database(acdb_handle_t *acdb_handle)
{
	int32_t status = AR_EOK;
	acdb_context_handle_t *ctx_handle = NULL;
	uint32_t vm_id = 0;

	if (IsNull(acdb_handle))
		return AR_EHANDLE;

	vm_id = ACDB_HANDLE_TO_UINT(acdb_handle);
	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE,
		&vm_id, sizeof(uint32_t),
		&ctx_handle, sizeof(acdb_context_handle_t));

	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to get context handle", status);
		return status;
	}

	/* Try to remove database data even if removing data
	 * from one layers fails */

	status = acdb_file_man_ioctl(ACDB_FILE_MAN_REMOVE_DATABASE,
		ctx_handle->file_manager_handle,
		sizeof(acdb_file_man_handle_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to remove "
			"database data from file manager.", status);
	}

	//Does the added database have delta data? if so, remove the delta data
	status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_REMOVE_DATABASE,
		ctx_handle->delta_manager_handle,
		sizeof(acdb_delta_file_man_handle_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to remove "
			"database data from delta file manager.", status);
	}

	status = acdb_heap_ioctl(ACDB_HEAP_CMD_REMOVE_DATABASE,
		ctx_handle->heap_handle, sizeof(acdb_heap_handle_t),
		NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to remove "
			"database data from heap manager.", status);
	}

	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_REMOVE_DATABASE,
		acdb_handle, sizeof(acdb_handle_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to remove "
			"database data from context manager.", status);
	}

	return status;
}

int32_t acdb_init_reset(void)
{
	int32_t status = AR_EOK;

	status = acdb_file_man_ioctl(ACDB_FILE_MAN_RESET,
		NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to reset "
			"file manager.", status);
	}

	status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_RESET,
		NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to reset "
			"delta file manager.", status);
	}

	status = acdb_heap_ioctl(ACDB_HEAP_CMD_RESET,
		NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to reset "
			"heap manager.", status);
	}

	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_RESET,
		NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to reset "
			"context manager.", status);
	}

	ACDB_PKT_LOG_DEINIT();

	status = AcdbARHeapDeinit();
	if (AR_FAILED(status))
	{
		return status;
	}

	return status;
}

int32_t acdb_init_ioctl(uint32_t cmd_id,
    void* req, uint32_t req_size,
    void* rsp, uint32_t rsp_size)
{
	__UNREFERENCED_PARAM(rsp);
	__UNREFERENCED_PARAM(rsp_size);

    int32_t status = AR_EOK;

    switch (cmd_id)
    {
    case ACDB_INIT_CMD_INIT:
        status = acdb_init_layers();
        break;
    case ACDB_INIT_CMD_ADD_DATABASE:
		if (IsNull(req) || req_size < sizeof(acdb_init_database_paths_t))
			return AR_EBADPARAM;

		status = acdb_init_add_database((acdb_init_database_paths_t*)req,
			(acdb_handle_t*)rsp);
        break;
    case ACDB_INIT_CMD_REMOVE_DATABASE:
		if (IsNull(req) || req_size < sizeof(acdb_handle_t))
			return AR_EBADPARAM;

		status = acdb_init_remove_database((acdb_handle_t*)req);
        break;
	case ACDB_INIT_CMD_RESET:
		status = acdb_init_reset();
		break;
    default:
        status = AR_EUNSUPPORTED;
        ACDB_ERR("Error[%d]: Unknown command id %d", cmd_id);
        break;
    }
    return status;
}
