/**
*=============================================================================
* \file acdb_delta_parser.c
*
* \brief
*		Contains the implementation of the Acdb Delta Parser/Generator.
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

#include "acdb_delta_parser.h"
#include "acdb_parser.h"
#include "acdb_common.h"
#include "acdb_types.h"
#include "acdb_heap.h"

 /* ---------------------------------------------------------------------------
  * Preprocessor Definitions and Constants
  *--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

int32_t file_seek_read(
	ar_fhandle fhandle, void* p_buf, size_t read_size, uint32_t *offset)
{
	int32_t status = AR_EOK;
	size_t bytes_read = 0;

	status = ar_fseek(fhandle, *offset, AR_FSEEK_BEGIN);

	if (AR_EOK != status) return status;

	status = ar_fread(fhandle, p_buf, read_size, &bytes_read);

	*offset += (uint32_t)bytes_read;

	return status;
}

int32_t acdb_delta_parser_read_file_header(
	ar_fhandle fhandle, AcdbDeltaFileHeader *file_header)
{
	uint32_t offset = 0;

	if (AR_EOK != file_seek_read(fhandle, file_header,
		sizeof(AcdbDeltaFileHeader), &offset))
	{
		return AR_EFAILED;
	}

	return AR_EOK;
}

int32_t acdb_delta_parser_verify_file_version(
	AcdbDeltaFileHeader *header)
{
	int32_t status = ACDB_PARSE_SUCCESS;//ACDB_PARSE_INVALID_FILE

	//File version must not be higher than the Software File Version

	if ((header->delta_major == 1 && header->delta_minor == 0) // ||
		/*(header->major == ?? && header->minor == ??)*/)
	{
		status =  ACDB_PARSE_SUCCESS;
	}
	else
	{
		ACDB_ERR("Unsupported delta file version %d.%d.%d",
			header->delta_major, header->delta_minor, header->delta_revision);
		status = ACDB_PARSE_INVALID_FILE;
	}

	return status;
}

/* ---------------------------------------------------------------------------
 * Public Function
 *--------------------------------------------------------------------------- */

int32_t acdb_delta_parser_is_file_valid(
	ar_fhandle fhandle, uint32_t file_size)
{
	int32_t status = ACDB_PARSE_SUCCESS;
	AcdbDeltaFileHeader file_header;

	if (fhandle == NULL)
	{
		ACDB_ERR("Error[%d]: The file handle is null", AR_EHANDLE);
		return ACDB_PARSE_INVALID_FILE;
	}

	if (file_size < sizeof(AcdbDeltaFileHeader))
	{
		ACDB_ERR("Error[%d]: The delta file size %d bytes is less than than"
            " file header %d bytes", AR_EBADPARAM, file_size,
            sizeof(AcdbDeltaFileHeader));
		return ACDB_PARSE_INVALID_FILE;
	}

	if (AR_EOK != acdb_delta_parser_read_file_header(fhandle, &file_header))
	{
		ACDB_ERR("Error[%d]: Failed to read delta file header.", AR_EFAILED);
		return ACDB_PARSE_INVALID_FILE;
	}

	if (file_header.file_data_size > file_size)
	{
		ACDB_ERR("Error[%d]: The file data size is larger than the "
			"actual file size.", AR_EFAILED);
		return ACDB_PARSE_INVALID_FILE;
	}

	if (ACDB_PARSE_SUCCESS !=
		acdb_delta_parser_verify_file_version(&file_header))
	{
		return ACDB_PARSE_INVALID_FILE;
	}

	if (file_size != file_header.file_data_size
        + (sizeof(AcdbDeltaFileHeader) - sizeof(uint32_t)))
	{
		ACDB_ERR("Error[%d]: The delta file data section size %d is incorrect."
            " It should be %d bytes",
            file_header.file_data_size,
            file_size - sizeof(AcdbDeltaFileHeader) - sizeof(uint32_t));
		return ACDB_PARSE_INVALID_FILE;
	}

	return status;
}

int32_t acdb_delta_parser_get_file_version(
	ar_fhandle fhandle, uint32_t file_size,
	acdb_delta_file_version_t* delta_finfo)
{
	AcdbDeltaFileHeader file_header;

	if (file_size < (sizeof(AcdbDeltaFileHeader)))
	{
		ACDB_ERR("AcdbDeltaFileGetSWVersion() failed, delta acdb file size = %d is less than AcdbDeltaFileHeader", file_size);
		return AR_EBADPARAM;
	}

	if (AR_EOK != acdb_delta_parser_read_file_header(fhandle, &file_header))
	{
		ACDB_ERR("failed with error code %d. Failed to read delta file header.")
		return AR_EFAILED;
	}

	delta_finfo->major = file_header.delta_major;
	delta_finfo->minor = file_header.delta_minor;
	delta_finfo->revision = file_header.delta_revision;
	delta_finfo->cpl_info = file_header.acdb_cpl_info;

	return AR_EOK;
}

int32_t acdb_delta_parser_read_delta_param_data(
	ar_fhandle fhandle, AcdbDeltaPersistanceData *persistance_data,
	uint32_t *offset)
{
	int32_t status = AR_EOK;
	uint32_t bytes_read = *offset;
	uint32_t persistance_data_size = 0;
	uint32_t file_size = 0;
	AcdbDeltaModuleCalData *caldata = NULL;

	file_size = (uint32_t)ar_fsize(fhandle);

	status = file_seek_read(fhandle, &persistance_data->data_size,
		sizeof(uint32_t), &bytes_read);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to read total delta param data size",
			AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	if (persistance_data->data_size > file_size)
	{
		ACDB_ERR("Error[%d]: The total delta param data size %d is greater "
			"than the file size %d",
			AR_EBADPARAM, persistance_data->data_size, file_size);
		return AR_EBADPARAM;
	}

	ACDB_CLEAR_BUFFER(persistance_data->cal_data_list);

	while (persistance_data_size < persistance_data->data_size)
	{
		caldata = ACDB_MALLOC(AcdbDeltaModuleCalData, 1);
		if (IsNull(caldata))
		{
			status = AR_ENOMEMORY;
			ACDB_ERR("Error[%d]: Not enoug memory to allocate delta "
				"param header", status);
			break;
		}

		ar_mem_set(caldata, 0, sizeof(AcdbDeltaModuleCalData));

		//Read Instance ID, Param ID, Param Size
		status = file_seek_read(fhandle, caldata,
			3 * sizeof(uint32_t), &bytes_read);
		if (AR_FAILED(status))
		{
			ACDB_ERR("Error[%d]: Unable to read delta param header "
				"<iid, pid, param size>", status);
			break;
		}

		if (caldata->param_size > persistance_data->data_size)
		{
			status = AR_EFAILED;
			ACDB_ERR("Error[%d]: The param size %d for iid,pid <0x%x, 0x%x>"
				" is greater than the aggragate delta param delta"
				" data size %d",
				status, caldata->param_size, caldata->module_iid,
				caldata->param_id, persistance_data->data_size);
			break;
		}

		// Read payload
		if (caldata->param_size > 0)
		{
			caldata->param_payload = ACDB_MALLOC(
				uint8_t, caldata->param_size);
			if (IsNull(caldata->param_payload))
			{
				status = AR_ENOMEMORY;
				ACDB_ERR("Error[%d]: Not enoug memory to allocate delta "
					"param payload", status);
				break;
			}

			status = file_seek_read(fhandle, caldata->param_payload,
				caldata->param_size, &bytes_read);
			if (AR_FAILED(status))
			{
				ACDB_ERR("Error[%d]: Unable to read delta "
					"param payload", status);
				break;
			}
		}

		LinkedListNode *node = AcdbListCreateNode(caldata);

		AcdbListAppend(&persistance_data->cal_data_list, node);

		persistance_data_size += 3 * sizeof(uint32_t) + caldata->param_size;

		caldata = NULL;
	}

	if (AR_FAILED(status))
	{
		if(!IsNull(caldata))
			ACDB_FREE(caldata->param_payload);
		ACDB_FREE(caldata);
	}
	else
		*offset = bytes_read;

	return status;
}

int32_t acdb_delta_parser_read_map(
	ar_fhandle fhandle, uint32_t *offset,
	acdb_delta_data_map_t *map)
{
	int32_t status = AR_EOK;
	uint32_t kv_pair_count = 0;
	uint32_t bytes_read = *offset;
    AcdbModuleTag* module_tag = NULL;
    AcdbGraphKeyVector* key_vector = NULL;
	uint32_t file_size = 0;

	if (map == NULL)
	{
		return AR_EBADPARAM;
	}

	file_size = (uint32_t)ar_fsize(fhandle);

    status = file_seek_read(fhandle, &map->key_vector_type,
		sizeof(uint32_t), &bytes_read);
	if (AR_FAILED(status))
    {
		ACDB_ERR("Error[%d]: Unable to read key vector type", status);
        return status;
    }

    //Read Module Tag or Graph Key Vector depending on key vector type
    switch (map->key_vector_type)
    {
    case TAG_KEY_VECTOR:
        module_tag = ACDB_MALLOC(AcdbModuleTag, 1);
        if (IsNull(module_tag))
        {
            status = AR_ENOMEMORY;
            ACDB_ERR_MSG_1("Unable to allocate memory for module tag", status);
            return status;
        }

        map->key_vector_data = (void*)module_tag;

        status = file_seek_read(fhandle, &module_tag->tag_id, sizeof(uint32_t), &bytes_read);
        if (AR_EOK != status)
        {
            ACDB_FREE(module_tag);
            ACDB_ERR_MSG_1("Unable to read module tag", status);
            return status;
        }

        key_vector = &module_tag->tag_key_vector;
        if (IsNull(key_vector))
        {
            status = AR_EBADPARAM;
            ACDB_FREE(module_tag);
            ACDB_ERR_MSG_1("Tag Key Vector is null", status);
            return status;
        }

        break;
    case CAL_KEY_VECTOR:
        key_vector = ACDB_MALLOC(AcdbGraphKeyVector, 1);
        if (IsNull(key_vector))
        {
            status = AR_ENOMEMORY;
            ACDB_ERR_MSG_1("Unable to allocate memory for Calibration Key Vector", status);
            return status;
        }

        map->key_vector_data = (void*)key_vector;
        break;
    default:
        break;
    }

    if (IsNull(key_vector))
    {
        ACDB_ERR("The Map Key vector is null");
        return AR_EBADPARAM;
    }

    ACDB_CLEAR_BUFFER(*key_vector);

	status = file_seek_read(fhandle, &kv_pair_count,
		sizeof(uint32_t), &bytes_read);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to read key vector length",
			status);
		return status;
	}

	if (kv_pair_count > ACDB_MAX_KEY_COUNT)
	{
		ACDB_ERR("Error[%d]: The key vector length %d is larger than "
			"the max %d", kv_pair_count, ACDB_MAX_KEY_COUNT);
		return AR_EBADPARAM;
	}

    key_vector->num_keys = kv_pair_count;

    if (kv_pair_count > 0)
    {
        key_vector->graph_key_vector = ACDB_MALLOC(
			AcdbKeyValuePair, kv_pair_count * sizeof(AcdbKeyValuePair));

        status = file_seek_read(fhandle, key_vector->graph_key_vector,
			kv_pair_count * sizeof(AcdbKeyValuePair), &bytes_read);
		if (AR_FAILED(status))
        {
            if (!IsNull(key_vector->graph_key_vector))
            {
                ACDB_FREE(key_vector->graph_key_vector);
            }

			ACDB_ERR("Error[%d]: Unable to read key vector",
				status);
            return status;
        }
    }

    module_tag = NULL;
    key_vector = NULL;

	status = file_seek_read(fhandle, &map->map_size,
		sizeof(uint32_t), &bytes_read);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to read map size",
			status);
		return status;
	}

	if (map->map_size > file_size)
	{
		ACDB_ERR("Error[%d]: The map size %d is larger than "
			"the file size %d", map->map_size, file_size);
		return AR_EBADPARAM;
	}

	status = file_seek_read(fhandle, &map->num_subgraphs,
		sizeof(uint32_t), &bytes_read);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to read subgraph count",
			status);
		return status;
	}

	if (map->num_subgraphs > file_size)
	{
		ACDB_ERR("Error[%d]: The subgraph count %d is greater than "
			"the file size %d", map->num_subgraphs, file_size);
		return AR_EBADPARAM;
	}

	LinkedListNode *sg_data_node = NULL;
	AcdbDeltaSubgraphData *sg_data = NULL;

	ACDB_CLEAR_BUFFER(map->subgraph_data_list);

	for (uint32_t i = 0; i < map->num_subgraphs; i++)
	{
		sg_data = ACDB_MALLOC(AcdbDeltaSubgraphData, 1);
		if (IsNull(sg_data))
		{
			status = AR_ENOMEMORY;
			ACDB_ERR("Error[%d]: Not enoug memory to allocate delta "
				"param data", status);
			break;
		}

		ar_mem_set(sg_data, 0, sizeof(AcdbDeltaSubgraphData));

		status = file_seek_read(fhandle, sg_data,
			2 * sizeof(uint32_t), &bytes_read);
		if (AR_FAILED(status))
		{
			ACDB_ERR("Error[%d]: Unable to read subgraph data header",
				status);
			break;
		}

		status = acdb_delta_parser_read_delta_param_data(
			fhandle, &sg_data->non_global_data, &bytes_read);
		if (AR_FAILED(status))
		{
			ACDB_ERR("Error[%d]: Unable to read regular/shared param "
				"data for subgraph 0x%x", status, sg_data->subgraph_id);
			break;
		}

		status = acdb_delta_parser_read_delta_param_data(
			fhandle, &sg_data->global_data, &bytes_read);
		if (AR_FAILED(status))
		{
			ACDB_ERR("Error[%d]: Unable to read global param "
				"data for subgraph 0x%x", status, sg_data->subgraph_id);
			break;
		}

		sg_data_node = AcdbListCreateNode(sg_data);
		AcdbListAppend(&map->subgraph_data_list, sg_data_node);
	}

	if (AR_FAILED(status))
	{
		acdb_heap_free_subgraph_data(sg_data);
		acdb_heap_free_map(map);
		return status;
	}

	*offset = bytes_read;

	sg_data_node = NULL;
	sg_data = NULL;
	return status;
}

int32_t acdb_delta_parser_write_file_header(
	ar_fhandle fhandle, acdb_delta_file_version_t* delta_finfo,
	uint32_t fdata_size, uint32_t map_count)
{
	size_t bytes_written = 0;
	AcdbDeltaFileHeader file_header;
	file_header.delta_major = ACDB_DELTA_FILE_VERSION_MAJOR;
	file_header.delta_minor = ACDB_DELTA_FILE_VERSION_MINOR;
	file_header.delta_revision = ACDB_DELTA_FILE_REVISION;

	file_header.acdb_major = delta_finfo->major;
	file_header.acdb_minor = delta_finfo->minor;
	file_header.acdb_revision = delta_finfo->revision;
	file_header.acdb_cpl_info = delta_finfo->cpl_info;
	file_header.file_data_size = fdata_size;
	file_header.map_count = map_count;

	int32_t status = ar_fwrite(fhandle, &file_header, sizeof(AcdbDeltaFileHeader), &bytes_written);
	if (AR_EOK != status)
	{
		ACDB_ERR_MSG_1("Unable to write the *.acdbdelta file header", status);
		return AR_EFAILED;
	}

	return AR_EOK;
}

int32_t acdb_delta_parser_write_delta_data(
	ar_fhandle fhandle, AcdbDeltaPersistanceData *persist_data)
{
	int32_t status = AR_EOK;
	size_t bytes_written = 0;
	AcdbDeltaModuleCalData cal_data;

	status = ar_fwrite(fhandle, &persist_data->data_size, sizeof(uint32_t), &bytes_written);
	if (AR_EOK != status)
	{
		ACDB_ERR_MSG_1("Unable to write global/non-global data size.", status);
		return AR_EFAILED;
	}

	if (persist_data->data_size == 0)
	{
		return AR_EOK;
	}

	LinkedListNode *cur_node = persist_data->cal_data_list.p_head;
	while (!IsNull(cur_node))
	{
		cal_data = *((AcdbDeltaModuleCalData*)cur_node->p_struct);

		status = ar_fwrite(fhandle, &cal_data.module_iid, sizeof(uint32_t), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write Module Instance ID.", status);
			return AR_EFAILED;
		}

		status = ar_fwrite(fhandle, &cal_data.param_id, sizeof(uint32_t), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write Parameter ID.", status);
			return AR_EFAILED;
		}

		status = ar_fwrite(fhandle, &cal_data.param_size, sizeof(uint32_t), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write Parameter Size.", status);
			return AR_EFAILED;
		}

		status = ar_fwrite(fhandle, (uint8_t*)cal_data.param_payload, (size_t)cal_data.param_size, &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write Parameter Payload.", status);
			return AR_EFAILED;
		}

		cur_node = cur_node->p_next;
	}

	return AR_EOK;
}

int32_t acdb_delta_parser_write_map(
	ar_fhandle fhandle, acdb_delta_data_map_t *map)
{
	int32_t status = AR_EOK;
    AcdbModuleTag* module_tag = NULL;
    AcdbGraphKeyVector* key_vector = NULL;
	if (IsNull(map)) return AR_EBADPARAM;

	uint32_t i = 0;
	size_t bytes_written = 0;

    status = ar_fwrite(fhandle, &map->key_vector_type, sizeof(uint32_t), &bytes_written);
    if (AR_EOK != status)
    {
        ACDB_ERR_MSG_1("Unable to write key vector type", status);
        return AR_EFAILED;
    }

    //Write Module Tag or Graph Key Vector depending on KV type
    switch (map->key_vector_type)
    {
    case TAG_KEY_VECTOR:
        module_tag = ((AcdbModuleTag*)map->key_vector_data);
        status = ar_fwrite(fhandle, &module_tag->tag_id, sizeof(uint32_t), &bytes_written);
        if (AR_EOK != status)
        {
            ACDB_ERR_MSG_1("Unable to write module tag", status);
            return AR_EFAILED;
        }

        key_vector = &module_tag->tag_key_vector;

        if (IsNull(key_vector))
        {
            ACDB_ERR("Map Tag Key Vector is null");
            return AR_EBADPARAM;
        }
        break;
    case CAL_KEY_VECTOR:
        key_vector = ((AcdbGraphKeyVector*)map->key_vector_data);

        if (IsNull(key_vector))
        {
            ACDB_ERR("Map Calibration Key Vector is null");
            return AR_EBADPARAM;
        }
        break;
    default:
        break;
    }

    if (IsNull(key_vector))
    {
        ACDB_ERR("The Map Key Vector is null");
        return AR_EBADPARAM;
    }

	status = ar_fwrite(fhandle, &key_vector->num_keys, sizeof(uint32_t), &bytes_written);
	if (AR_EOK != status)
	{
		ACDB_ERR_MSG_1("Unable to write number of cal key vector key pairs", status);
		return AR_EFAILED;
	}

	for (i = 0; i < key_vector->num_keys; i++)
	{
		status = ar_fwrite(fhandle, &key_vector->graph_key_vector[i], sizeof(AcdbKeyValuePair), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write the calibration key vector", status);
			return AR_EFAILED;
		}
	}

	status = ar_fwrite(fhandle, &map->map_size, sizeof(uint32_t), &bytes_written);
	if (AR_EOK != status)
	{
		ACDB_ERR_MSG_1("Unable to write map size", status);
		return AR_EFAILED;
	}

	status = ar_fwrite(fhandle, &map->num_subgraphs, sizeof(uint32_t), &bytes_written);
	if (AR_EOK != status)
	{
		ACDB_ERR_MSG_1("Unable to write number of subgraph", status);
		return AR_EFAILED;
	}

	LinkedListNode *sg_data_node = map->subgraph_data_list.p_head;
	AcdbDeltaSubgraphData *sg_data = NULL;

	do
	{
		sg_data = (AcdbDeltaSubgraphData*)sg_data_node->p_struct;

		status = ar_fwrite(fhandle, &sg_data->subgraph_id, sizeof(uint32_t), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write the subgraph ID", status);
			return AR_EFAILED;
		}

		status = ar_fwrite(fhandle, &sg_data->subgraph_data_size, sizeof(uint32_t), &bytes_written);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write the subgraph data size", status);
			return AR_EFAILED;
		}

		status = acdb_delta_parser_write_delta_data(fhandle, &sg_data->non_global_data);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write non-global persistance data", status);
			return AR_EFAILED;
		}

		status = acdb_delta_parser_write_delta_data(fhandle, &sg_data->global_data);
		if (AR_EOK != status)
		{
			ACDB_ERR_MSG_1("Unable to write global persistance data", status);
			return AR_EFAILED;
		}

	} while (TRUE != AcdbListSetNext(&sg_data_node));

	return AR_EOK;
}
