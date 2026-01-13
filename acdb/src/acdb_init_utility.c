/**
*=============================================================================
* \file acdb_init_utility.c
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

#include "ar_osal_error.h"
#include "ar_osal_file_io.h"
#include "acdb_common.h"
#include "acdb_init_utility.h"
#include "acdb_types.h"
#include "acdb_parser.h"
#include <time.h>

int32_t AcbdInitLoadInMemFile(const char_t* fname, ar_fhandle fhandle, acdb_buffer_t* in_mem_file)
{
    in_mem_file->size = (uint32_t)ar_fsize(fhandle);

    if (in_mem_file->size == 0)
    {
        ACDB_ERR("Error[%d]: The file %s is empty", AR_EBADPARAM, fname);
        return AR_EBADPARAM;
    }

    int32_t status = ar_fmap(fhandle, &in_mem_file->buffer);
    if (AR_EUNSUPPORTED == status)
    {
        in_mem_file->buffer = (void*)ACDB_MALLOC(uint8_t, in_mem_file->size);

        if (IsNull(in_mem_file->buffer))
        {
            ACDB_ERR("Error[%d]: Not enough memory to allocate for file %s", AR_ENOMEMORY, fname);
            return AR_ENOMEMORY;
        }
        status = AR_EOK;
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to map memory for file %s", status, fname);
    }

    return status;
}

int32_t AcbdInitUnloadInMemFile(acdb_buffer_t* in_mem_file)
{
    if (IsNull(in_mem_file))
    {
        ACDB_ERR("Error[%d]: in_mem_file pointer is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    in_mem_file->size = 0;

    int32_t status = ar_funmap(in_mem_file->buffer);
    if (AR_EUNSUPPORTED == status)
    {
        ACDB_FREE(in_mem_file->buffer);
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to unmap memory for in_mem_file", status);
    }

    return status;
}

void AcdbLogSwVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl)
{
	ACDB_PKT_LOG_DATA("ACDB_SW_MAJOR", &(major), sizeof(major));
	ACDB_PKT_LOG_DATA("ACDB_SW_MINOR", &(minor), sizeof(minor));
	ACDB_PKT_LOG_DATA("ACDB_SW_REVISION", &(revision), sizeof(revision));

	if (cpl != INF)
	{
		ACDB_PKT_LOG_DATA("ACDB_SW_CPL", &(cpl), sizeof(cpl));
        ACDB_INFO("ACDB SW Version %u.%u.%u.%u", major, minor, revision, cpl);
	}
	else
	{
        ACDB_INFO("ACDB SW Version %u.%u.%u", major, minor, revision);
	}
}

void AcdbLogDeltaSwVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl)
{
	ACDB_PKT_LOG_DATA("ACDB_DELTA_SW_MAJOR", &(major), sizeof(major));
	ACDB_PKT_LOG_DATA("ACDB_DELTA_SW_MINOR", &(minor), sizeof(minor));
	ACDB_PKT_LOG_DATA("ACDB_DELTA_SW_REVISION", &(revision), sizeof(revision));

	if (cpl != INF)
	{
		ACDB_PKT_LOG_DATA("ACDB_DELTA_SW_CPL", &(cpl), sizeof(cpl));
        ACDB_INFO("ACDB Delta SW Version %u.%u.%u.%u", major, minor, revision, cpl);
	}
	else
	{
        ACDB_INFO("ACDB Delta SW Version %u.%u.%u", major, minor, revision);
	}
}

void AcdbLogDeltaFileVersion(uint32_t major, uint32_t minor, uint32_t revision, uint32_t cpl)
{
	ACDB_PKT_LOG_DATA("ACDB_DELTA_FILE_MAJOR", &(major), sizeof(major));
	ACDB_PKT_LOG_DATA("ACDB_DELTA_FILE_MINOR", &(minor), sizeof(minor));
	ACDB_PKT_LOG_DATA("ACDB_DELTA_FILE_REVISION", &(revision), sizeof(revision));

	if (cpl != INF)
	{
		ACDB_PKT_LOG_DATA("ACDB_DELTA_FILE_CPL", &(cpl), sizeof(cpl));
        ACDB_INFO("ACDB Delta File Version %u.%u.%u.%u", major, minor, revision, cpl);
	}
	else
	{
        ACDB_INFO("ACDB Delta File Version %u.%u.%u", major, minor, revision);
	}
}

void AcdbLogFileInfo(acdb_header_v1_t *header)
{
    time_t date_time = (time_t)header->date_modified;
    struct tm *gm_date_time = NULL;
    char_t* date_time_str = NULL;
    const uint32_t description_length = 100;
    char_t oem_info[100] = "";

    gm_date_time = gmtime(&date_time);

    if (gm_date_time)
        date_time_str = asctime(gm_date_time);

    if (256 == header->oem_info->legnth)
    {
        //trim and leave ..
        ar_strcpy(&oem_info[0], description_length,
            &header->oem_info->description[0], description_length);

        oem_info[description_length - 1] = '\0';
        oem_info[description_length - 2] = '.';
        oem_info[description_length - 3] = '.';
    }
    else
    {
        ar_strcpy(&oem_info[0], header->oem_info->legnth,
            &header->oem_info->description[0], header->oem_info->legnth);
    }

    ACDB_INFO("\nOEM Info: %s", oem_info);

    if (!date_time_str)
    {
        ACDB_INFO(
            "\nACDB File Version : v%u.%u.%u.%u",
            header->file_version.major,
            header->file_version.minor,
            header->file_version.revision,
            header->file_version.cpl_info);
    }
    else
    {
        ACDB_INFO(
            "\nACDB File Version : v%u.%u.%u.%u"
            "\nLast Modified     : %s",
            header->file_version.major,
            header->file_version.minor,
            header->file_version.revision,
            header->file_version.cpl_info,
            date_time_str);
    }
}

int32_t AcdbInitUtilGetFileData(const char_t* fname, ar_fhandle* fhandle,
    acdb_buffer_t *in_mem_file)
{
    int32_t status = AR_EOK;
    size_t bytes_read = 0;

    if (IsNull(fname) || IsNull(in_mem_file))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = ar_fopen(fhandle, fname, AR_FOPEN_READ_ONLY);
    if (AR_FAILED(status) || fhandle == NULL)
    {
        ACDB_ERR("Error[%d]: Unable to open file: %s", status, fname);
        return status;
    }

    status = ar_fseek(*fhandle, 0, AR_FSEEK_BEGIN);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to fseek file: %s", status, fname);
        return AR_EFAILED;
    }

    status = AcbdInitLoadInMemFile(fname, *fhandle, in_mem_file);
    if (AR_FAILED(status))
    {
        ACDB_ERR("ERROR[%d]: Failed to load in_mem_file %s", status, fname);
        return status;
    }

    status = ar_fread(*fhandle, in_mem_file->buffer, in_mem_file->size, &bytes_read);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read file: %s", status, fname);
        goto end;
    }

    if (bytes_read != in_mem_file->size)
    {
        status = AR_EBADPARAM;
        ACDB_ERR("Error[%d]: File size does not match "
            "the number of bytes read: %s", status, fname);
    }

end:
    if (AR_FAILED(status))
    {
        AcbdInitUnloadInMemFile(in_mem_file);
    }

    return status;
}

char *GetDeltaFileName_OLD(const char* fname, size_t fname_len,
    acdb_path_t *delta_dir, uint32_t *delta_fpath_length)
{
	char* delta_fname = NULL;
    char* delta_fname_ext = "delta";
    size_t ext_size = 6;
    size_t slash_size = 0;
	size_t delta_fname_size = 0;
	size_t remaining_size = 0;
    uint32_t delta_dir_length = 0;

	if (fname == NULL || fname_len == 0)
	{
		return NULL;
	}

    fname_len = ar_strlen(fname,
        ACDB_MAX_PATH_LENGTH);

	if (delta_dir == NULL)
	{
		//Delta file path is null, so use acdb file path and concatenate "delta"
		delta_fname_size = fname_len + ar_strlen(delta_fname_ext, ext_size) + 1;
		delta_fname = ACDB_MALLOC(char, delta_fname_size);

		if (IsNull(delta_fname)) return NULL;

		if (delta_fname != NULL)
		{
			ACDB_STR_CPY_SAFE(delta_fname, delta_fname_size, fname, fname_len);
			ACDB_STR_CAT_SAFE(delta_fname, delta_fname_size, delta_fname_ext,
                ar_strlen(delta_fname_ext, ext_size));
		}
	}
	else
	{
		//Delta file path is provided, so form the full path
		//Ex. ..\acdb_data + \ + acdb_data.acdb + delta
		uint32_t acdb_file_name_len = 0;
		uint32_t offset = 0;
		int32_t char_index = (int32_t)fname_len;
		char *slash = NULL;

		/* Detect windows\linux style path prefixes
		Absolute Paths
			Ex. C:\acdb_data\ar_acdb.acdb
			Ex. /acdb_data/ar_acdb.acdb
		Relative paths
			Ex. ..\acdb_data\ar_acdb.acdb
			Ex. ../acdb_data/ar_acdb.acdb
		*/
		//if (!((fname[0] == '.' && fname[1] == '.') ||
		//	(fname[1] == ':' && fname[2] == '\\') ||
		//	fname[0] == '/'))
		//{
		//	char_index = 0;
		//}

		while (--char_index > 0)
		{
			if (fname[char_index] == '\\' ||
				fname[char_index] == '/')
			{
                if (fname[char_index] == '/')
                {
                    slash = "/";
                    slash_size = 2;
                }

                if (fname[char_index] == '\\')
                {
                    slash = "\\";
                    slash_size = 3;
                }

				char_index++;
				break;
			}
		}

		acdb_file_name_len = (uint32_t)fname_len - char_index;
        delta_dir_length = (uint32_t)ar_strlen(delta_dir->path,
            delta_dir->path_length);

		if (IsNull(slash))
		{
			delta_fname_size =
                delta_dir_length
				+ (size_t)acdb_file_name_len
				+ ar_strlen(delta_fname_ext, ext_size) + 1UL;
		}
		else
		{
			delta_fname_size =
                delta_dir_length
                + ar_strlen(slash, slash_size)
                + acdb_file_name_len
                + (ar_strlen(delta_fname_ext, ext_size) + 1);
		}

		delta_fname = ACDB_MALLOC(char, delta_fname_size);//account for \0

		if (IsNull(delta_fname)) return NULL;

		//delta file path: ..\acdb_data
		ACDB_STR_CPY_SAFE(delta_fname + offset, delta_fname_size,
            delta_dir->path, delta_dir_length);
		offset += delta_dir_length;
		remaining_size = delta_fname_size - delta_dir_length;

		//slash
		if (!IsNull(slash))
		{
			ACDB_STR_CPY_SAFE(delta_fname + offset, remaining_size,
                slash, ar_strlen(slash, slash_size));
			offset += (uint32_t)ar_strlen(slash, slash_size);
			remaining_size = delta_fname_size
                - delta_dir_length - ar_strlen(slash, slash_size);
		}

		//acdb_data.acdbdelta
		ACDB_STR_CPY_SAFE(delta_fname + offset, remaining_size,
            fname + char_index, acdb_file_name_len);
		offset += acdb_file_name_len;
		if (IsNull(slash))
		{
			remaining_size = delta_fname_size
                - delta_dir_length - acdb_file_name_len;
		}
		else
		{
			remaining_size = delta_fname_size
                - delta_dir_length
                - ar_strlen(slash, slash_size) - acdb_file_name_len;
		}

        ACDB_STR_CAT_SAFE(delta_fname, delta_fname_size,
            delta_fname_ext, ar_strlen(delta_fname_ext, ext_size));

		uint32_t delta_file_name_len =
            (uint32_t)ar_strlen(delta_fname, delta_fname_size);
		if ((uint32_t)delta_fname_size != delta_file_name_len + 1UL)
		{
			ACDB_FREE(delta_fname);
			delta_fname = NULL;
			return delta_fname;
		}
	}

    *delta_fpath_length = (uint32_t)delta_fname_size;

	return delta_fname;
}

acdb_path_t AcdbInitUtilGetDeltaFilePath(
    const char* fname, size_t fname_len, acdb_path_t* delta_dir)
{
    char* delta_fname = NULL;
    char* delta_fname_ext = "delta";
    size_t ext_size = 6;
    size_t slash_size = 0;
    size_t delta_fname_size = 0;
    size_t remaining_size = 0;
    uint32_t delta_dir_length = 0;
    acdb_path_t delta_file_path = { 0 };

    if (fname == NULL || fname_len == 0)
    {
        return delta_file_path;
    }

    fname_len = ar_strlen(fname,
        ACDB_MAX_PATH_LENGTH);

    if (delta_dir == NULL)
    {
        //Delta file path is null, so use acdb file path and concatenate "delta"
        delta_fname_size = fname_len + ar_strlen(delta_fname_ext, ext_size) + 1;
        delta_fname = ACDB_MALLOC(char, delta_fname_size);

        if (IsNull(delta_fname)) return delta_file_path;

        if (delta_fname != NULL)
        {
            ACDB_STR_CPY_SAFE(delta_fname, delta_fname_size, fname, fname_len);
            ACDB_STR_CAT_SAFE(delta_fname, delta_fname_size, delta_fname_ext,
                ar_strlen(delta_fname_ext, ext_size));
        }
    }
    else
    {
        //Delta file path is provided, so form the full path
        //Ex. ..\acdb_data + \ + acdb_data.acdb + delta
        uint32_t acdb_file_name_len = 0;
        uint32_t offset = 0;
        int32_t char_index = (int32_t)fname_len;
        char* slash = NULL;

        /* Detect windows\linux style path prefixes
        Absolute Paths
            Ex. C:\acdb_data\ar_acdb.acdb
            Ex. /acdb_data/ar_acdb.acdb
        Relative paths
            Ex. ..\acdb_data\ar_acdb.acdb
            Ex. ../acdb_data/ar_acdb.acdb
        */
        //if (!((fname[0] == '.' && fname[1] == '.') ||
        //	(fname[1] == ':' && fname[2] == '\\') ||
        //	fname[0] == '/'))
        //{
        //	char_index = 0;
        //}

        while (--char_index > 0)
        {
            if (fname[char_index] == '\\' ||
                fname[char_index] == '/')
            {
                if (fname[char_index] == '/')
                {
                    slash = "/";
                    slash_size = 2;
                }

                if (fname[char_index] == '\\')
                {
                    slash = "\\";
                    slash_size = 3;
                }

                char_index++;
                break;
            }
        }

        acdb_file_name_len = (uint32_t)fname_len - char_index;
        delta_dir_length = (uint32_t)ar_strlen(delta_dir->path,
            delta_dir->path_length);

        if (IsNull(slash))
        {
            delta_fname_size =
                delta_dir_length
                + (size_t)acdb_file_name_len
                + ar_strlen(delta_fname_ext, ext_size) + 1UL;
        }
        else
        {
            delta_fname_size =
                delta_dir_length
                + ar_strlen(slash, slash_size)
                + acdb_file_name_len
                + (ar_strlen(delta_fname_ext, ext_size) + 1);
        }

        delta_fname = ACDB_MALLOC(char, delta_fname_size);//account for \0

        if (IsNull(delta_fname)) return delta_file_path;

        //delta file path: ..\acdb_data
        ACDB_STR_CPY_SAFE(delta_fname + offset, delta_fname_size,
            delta_dir->path, delta_dir_length);
        offset += delta_dir_length;
        remaining_size = delta_fname_size - delta_dir_length;

        //slash
        if (!IsNull(slash))
        {
            ACDB_STR_CPY_SAFE(delta_fname + offset, remaining_size,
                slash, ar_strlen(slash, slash_size));
            offset += (uint32_t)ar_strlen(slash, slash_size);
            remaining_size = delta_fname_size
                - delta_dir_length - ar_strlen(slash, slash_size);
        }

        //acdb_data.acdbdelta
        ACDB_STR_CPY_SAFE(delta_fname + offset, remaining_size,
            fname + char_index, acdb_file_name_len);
        offset += acdb_file_name_len;
        if (IsNull(slash))
        {
            remaining_size = delta_fname_size
                - delta_dir_length - acdb_file_name_len;
        }
        else
        {
            remaining_size = delta_fname_size
                - delta_dir_length
                - ar_strlen(slash, slash_size) - acdb_file_name_len;
        }

        ACDB_STR_CAT_SAFE(delta_fname, delta_fname_size,
            delta_fname_ext, ar_strlen(delta_fname_ext, ext_size));

        uint32_t delta_file_name_len =
            (uint32_t)ar_strlen(delta_fname, delta_fname_size);
        if ((uint32_t)delta_fname_size != delta_file_name_len + 1UL)
        {
            ACDB_FREE(delta_fname);
            delta_fname = NULL;
            return delta_file_path;
        }
    }

    delta_file_path.path_length = (uint32_t)delta_fname_size;
    delta_file_path.path = delta_fname;

    return delta_file_path;
}

int32_t AcdbInitUtilDeleteDeltaFileData(const char_t* acdb_file_path,
    uint32_t acdb_file_path_length, acdb_path_t* delta_dir)
{
	int32_t status = ACDB_UTILITY_INIT_SUCCESS;
    int32_t delta_result = AR_EOK;
    acdb_path_t delta_file_path = { 0 };

	delta_file_path = AcdbInitUtilGetDeltaFilePath(
        acdb_file_path, acdb_file_path_length, delta_dir);
	if (IsNull(delta_file_path.path))
	{
		ACDB_ERR("Unable to get delta file path string");
		return ACDB_UTILITY_INIT_FAILURE;
	}
	else
	{
		delta_result = ar_fdelete(delta_file_path.path);
		if (delta_result != 0)
		{
			ACDB_ERR("Error[%d]: Unable to delete delta acdb file", delta_result);
			status = ACDB_UTILITY_INIT_FAILURE;
		}

		ACDB_FREE(delta_file_path.path);
	}

	return status;
}

int32_t AcdbInitUtilGetDeltaInfo(
    const char_t* acdb_file_path, uint32_t acdb_file_path_length,
    acdb_path_t* delta_dir, AcdbInitUtilDeltaInfo *info)
{
    int32_t status = AR_EOK;
    ar_fhandle* fhandle = NULL;
    acdb_path_t delta_file_path = { 0 };

    if (IsNull(info))
    {
        ACDB_ERR("Error[%d]: The info input parameters is null",
            AR_EBADPARAM);

        return AR_EBADPARAM;
    }

    if (info->properties.file_access_io_flag == ACDB_FUNC_IO_UNUSED)
    {
        ACDB_ERR("Error[%d]: The file access IO flag is not set",
            AR_EBADPARAM);

        return AR_EBADPARAM;
    }

    if (IsNull(acdb_file_path) || acdb_file_path_length == 0)
    {
        ACDB_ERR("Error[%d]: The input file name is null or empty",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    delta_file_path = AcdbInitUtilGetDeltaFilePath(
        acdb_file_path, (size_t)acdb_file_path_length,
        delta_dir);
    if (delta_file_path.path == NULL)
    {
        ACDB_ERR("Error[%d]: The delta file path is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    info->properties.file_size = 0;
    info->delta_path = delta_file_path;

    /* Try opening the delta file with RW, then RO to determine the
    * access type */
    fhandle = ACDB_MALLOC(ar_fhandle, 1);
    if (IsNull(fhandle))
    {
        ACDB_ERR("Error[%d]: Unable to allocate memory for the file handle",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (info->properties.file_access_io_flag == ACDB_FUNC_IO_OUT)
    {
        info->properties.file_access = AR_FOPEN_READ_ONLY_WRITE;
        status = ar_fopen(fhandle, delta_file_path.path,
            info->properties.file_access);
        if (status == AR_ENOTEXIST)
        {
            ACDB_DBG(
                "Delta Acdb file does not exist. Creating new file...");
            info->properties.file_access = AR_FOPEN_WRITE_ONLY;
            status = ar_fopen(fhandle, delta_file_path.path,
                info->properties.file_access);
            if (status == AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: The %s file path does not exist",
                    status, delta_file_path.path);
            }
        }

        if (AR_FAILED(status))
        {
            info->properties.file_access = AR_FOPEN_READ_ONLY;
            status = ar_fopen(fhandle, delta_file_path.path,
                info->properties.file_access);
            if (status == AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: The %s file does not exist",
                    status, delta_file_path.path);
                goto end;
            }
        }
    }
    else if (info->properties.file_access_io_flag == ACDB_FUNC_IO_IN)
    {
        status = ar_fopen(fhandle, delta_file_path.path, info->properties.file_access);
        if (status == AR_ENOTEXIST)
        {
            ACDB_ERR("Error[%d]: The %s file path does not exist",
                status, delta_file_path.path);
            goto end;
        }
    }

    if (!IsNull(fhandle) && AR_SUCCEEDED(status))
    {
        info->properties.file_size = (uint32_t)ar_fsize(*fhandle);
        status = ar_fclose(*fhandle);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Unable to close %s", status, delta_file_path.path);
            goto end;
        }
    }

end:
    ACDB_FREE(fhandle);

    return status;
}

int32_t AcdbInitUtilGetDeltaInfo2(acdb_path_t* delta_file_path,
    acdb_init_util_file_properties_t* info)
{
    int32_t status = AR_EOK;
    ar_fhandle* fhandle = NULL;

    if (IsNull(info))
    {
        ACDB_ERR("Error[%d]: The info input parameters is null",
            AR_EBADPARAM);

        return AR_EBADPARAM;
    }

    if (info->file_access_io_flag == ACDB_FUNC_IO_UNUSED)
    {
        ACDB_ERR("Error[%d]: The file access IO flag is not set",
            AR_EBADPARAM);

        return AR_EBADPARAM;
    }

    /* Try opening the delta file with RW, then RO to determine the
    * access type */
    fhandle = ACDB_MALLOC(ar_fhandle, 1);
    if (IsNull(fhandle))
    {
        ACDB_ERR("Error[%d]: Unable to allocate memory for the file handle",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (info->file_access_io_flag == ACDB_FUNC_IO_OUT)
    {
        info->file_access = AR_FOPEN_READ_ONLY_WRITE;
        status = ar_fopen(fhandle, delta_file_path->path,
            info->file_access);
        if (status == AR_ENOTEXIST)
        {
            ACDB_DBG(
                "Delta Acdb file does not exist. Creating new file...");
            info->file_access = AR_FOPEN_WRITE_ONLY;
            status = ar_fopen(fhandle, delta_file_path->path,
                info->file_access);
            if (status == AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: The %s file path does not exist",
                    status, delta_file_path->path);
            }
        }

        if (AR_FAILED(status))
        {
            info->file_access = AR_FOPEN_READ_ONLY;
            status = ar_fopen(fhandle, delta_file_path->path,
                info->file_access);
            if (status == AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: The %s file does not exist",
                    status, delta_file_path->path);
                goto end;
            }
        }
    }
    else if (info->file_access_io_flag == ACDB_FUNC_IO_IN)
    {
        status = ar_fopen(fhandle, delta_file_path->path, info->file_access);
        if (status == AR_ENOTEXIST)
        {
            ACDB_ERR("Error[%d]: The %s file path does not exist",
                status, delta_file_path->path);
            goto end;
        }
    }

    if (!IsNull(fhandle) && AR_SUCCEEDED(status))
    {
        info->file_size = (uint32_t)ar_fsize(*fhandle);
        status = ar_fclose(*fhandle);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Unable to close %s", status, delta_file_path->path);
            goto end;
        }
    }

end:
    ACDB_FREE(fhandle);

    return status;
}

int32_t AcdbInitUtilOpenDeltaFile(
    AcdbInitUtilDeltaInfo *info, ar_fhandle* delta_fhandle)
{
    int32_t status = AR_EOK;

    if (IsNull(info))
    {
        ACDB_ERR("Error[%d]: One or more input parameters is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (IsNull(info->delta_path.path) || info->delta_path.path_length == 0)
    {
        ACDB_ERR("Error[%d]: The input file name is null or empty",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = ar_fopen(delta_fhandle, info->delta_path.path,
        info->properties.file_access);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to open delta acdb file", status);
        goto end;
    }

    status = ar_fseek(*delta_fhandle, 0, AR_FSEEK_BEGIN);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to seek file. Closing file..", status);
    }

end:
    if (AR_FAILED(status))
    {
        ar_fclose(*delta_fhandle);
        *delta_fhandle = NULL;
    }

    return status;
}
