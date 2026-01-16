/**
*=============================================================================
* \file acdb_parser.c
*
* \brief
*		Handle parsing the ACDB Data files.
*
* \copyright
*  Copyright (c) Qualcomm Innovation Center, Inc. All rights reserved.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

/* ---------------------------------------------------------------------------
* Include Files
*--------------------------------------------------------------------------- */

#include "ar_osal_file_io.h"
#include "ar_osal_error.h"
#include "ar_osal_mem_op.h"
#include "acdb_parser.h"
#include "acdb_common.h"
#include "acdb_utility.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */

#define ACDB_FILE_TYPE 0x0
#define ACDB_FILE_ID 0x42444341 // ACDB

#define ACDB_FILE_VERSION_MAJOR 0x00000001
#define ACDB_FILE_VERSION_MINOR 0x00000000

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef struct acdb_file_properties_t
{
	/**< Identifies the file */
	uint32_t file_id;
	/**< Indicates the type of file */
	uint32_t file_type;
	/**< The size of the data section of the file after the
	header and file properties */
	uint32_t file_data_size;
} acdb_file_properties_t;

typedef struct acdb_chunk_header_t
{
	/**< The chunk identifier. See acdb_parser.h for list of identifiers */
	uint32_t id;
	/**< The size of the chunk in bytes */
	uint32_t size;
}acdb_chunk_header_t;

/* ---------------------------------------------------------------------------
* Static Function Declarations and Definitions
*--------------------------------------------------------------------------- */

int32_t acdb_parser_get_chunk(
    void* file_buffer, uint32_t buffer_length,
    uint32_t chunk_id, uint32_t *chunk_offset, uint32_t *chunk_size)
{
    int32_t status = AR_ENOTEXIST;
    uint8_t *start_ptr = NULL;
    uint8_t *end_ptr = NULL;
    acdb_chunk_header_t *header = NULL;

    if (file_buffer == NULL || buffer_length == 0 ||
		buffer_length < sizeof(acdb_file_properties_t))
    {
        return AR_EBADPARAM;
    }

    /* Skip the file properties part of the acdb file to point
	to the first chunk */
    start_ptr = (uint8_t*)file_buffer + sizeof(acdb_file_properties_t);
    end_ptr = (uint8_t*)file_buffer + buffer_length;

    while (start_ptr < end_ptr)
    {
        if (start_ptr + sizeof(acdb_chunk_header_t) > end_ptr)
        {
            status = AR_EFAILED;
            break;
        }

        header = (acdb_chunk_header_t*)start_ptr;

        uint8_t* next_chunk = start_ptr + sizeof(acdb_chunk_header_t) + header->size;
        if (next_chunk > end_ptr)
        {
            status = AR_EFAILED;
            break;
        }

        if (header->id == chunk_id)
        {
            *chunk_offset = (uint32_t)(start_ptr
				- (uint8_t*)file_buffer + sizeof(acdb_chunk_header_t));
            *chunk_size = header->size;
            status = AR_EOK;
            break;
        }

        start_ptr = next_chunk;
    }

    return status;
}

int32_t acdb_parser_validate_file(acdb_buffer_t *in_mem_file)
{
	int32_t status = AR_EOK;
	acdb_file_properties_t *properties;

	if (IsNull(in_mem_file))
	{
		ACDB_ERR("Error[%d]: The input parameter is null",
			AR_EFAILED);
		return AR_EFAILED;
	}

	properties = (acdb_file_properties_t*)in_mem_file->buffer;

	if (in_mem_file->size < sizeof(acdb_file_properties_t))
	{
		ACDB_ERR("Error[%d]: The file is missing property information",
			AR_EFAILED);
		return AR_EFAILED;
	}

	if (properties->file_id != ACDB_FILE_ID &&
		properties->file_type != ACDB_FILE_TYPE)
	{
		ACDB_ERR("Error[%d]: The file is not an *.acdb file", AR_EFAILED);
		return AR_EFAILED;
	}

	if (in_mem_file->size != properties->file_data_size
		+ sizeof(acdb_file_properties_t))
	{
		ACDB_ERR("Error[%d]: The file size is incorrect.",
			AR_EFAILED, in_mem_file->size);
		return AR_EFAILED;
	}

	return status;
}

int32_t acdb_parser_get_acdb_header_v1(
	acdb_buffer_t* in_mem_file, acdb_header_v1_t *header)
{
	int32_t status = AR_EOK;
	uint32_t offset = 0;
	uint8_t* header_ptr = NULL;
	ChunkInfo ci_head = { 0 };

	if (IsNull(in_mem_file) || IsNull(header))
	{
		ACDB_ERR("Error[%d]: One or more input parameters are null",
			AR_EFAILED);
		return AR_EFAILED;
	}

	ci_head.chunk_id = ACDB_CHUNKID_HEAD;
	status = acdb_parser_get_chunk(in_mem_file->buffer, in_mem_file->size,
		ci_head.chunk_id, &ci_head.chunk_offset, &ci_head.chunk_size);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Chunk(%s) not found",
			AR_EFAILED, &ci_head.chunk_id);
		return status;
	}

	//Header Version
	header_ptr = (uint8_t*)in_mem_file->buffer + ci_head.chunk_offset;
	header->header_version = *(uint32_t*)header_ptr;
	offset += sizeof(uint32_t);

	//File version
	ACDB_MEM_CPY_SAFE(&header->file_version, sizeof(acdb_file_version_t),
		header_ptr + offset, sizeof(acdb_file_version_t));
	offset += sizeof(acdb_file_version_t);

	//Codec Info
	header->codec_info = (acdb_codec_info_t*)(header_ptr + offset);
	offset += sizeof(acdb_codec_info_t)
		+ header->codec_info->num_codecs * sizeof(acdb_codec_t);

	//Last Modified TimeStamp
	header->date_modified = *(uint32_t*)(header_ptr + offset);
	offset += sizeof(uint32_t);

	//OEM Info
	header->oem_info = (acdb_oem_info_t*)(header_ptr + offset);

	return status;
}
