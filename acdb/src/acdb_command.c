
/**
*=============================================================================
* \file acdb_command.c
*
* \brief
*		Contains the implementation of the commands exposed by the
*		ACDB public interface.
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
#include "acdb_command.h"
#include "acdb_parser.h"
#include "acdb_file_mgr.h"
#include "acdb_common.h"
#include "acdb_data_proc.h"
#include "acdb_context_mgr.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */
#define ACDB_SOFTWARE_VERSION_MAJOR 0x00000001
#define ACDB_SOFTWARE_VERSION_MINOR 0x00000030
#define ACDB_SOFTWARE_VERSION_REVISION 0x00000000
#define ACDB_SOFTWARE_VERSION_CPLINFO 0x00000000

#define INF 4294967295U

#define ACDB_CLEAR_BUFFER(x) memset(&x, 0, sizeof(x))

/* ---------------------------------------------------------------------------
* Global Data Definitions
*--------------------------------------------------------------------------- */
uint32_t glb_buf_1[GLB_BUF_1_LENGTH];
uint32_t glb_buf_2[GLB_BUF_2_LENGTH];
uint32_t glb_buf_3[GLB_BUF_3_LENGTH];

/* ---------------------------------------------------------------------------
* Static Variable Definitions
*--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
* Static Function Declarations and Definitions
*--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */
typedef struct _acdb_audio_cal_context_info_t AcdbAudioCalContextInfo;
#include "acdb_begin_pack.h"
struct _acdb_audio_cal_context_info_t {
    AcdbOp op;
    AcdbOp data_op;
    /**< A flag indicating whether data is being requested for the first
    time (only CKV[new] is passed in) */
    bool_t is_first_time;
    /**< A flag indicating whether the module CKV found is the default key
    vector(no keys) */
    bool_t is_default_module_ckv;
    /**< A flag indicating whether process(true) or skip(false) the
    default CKV */
    bool_t ignore_get_default_data;
    /**< A flag indicating whether check for hw accel based calibraion */
    bool_t should_check_hw_accel;
    /**< A flag used to filter calibration based on processor domain */
    bool_t should_filter_cal_by_proc_domain;
    /**< Keeps track of module IIDs that are associated with the
    default CKV */
    AcdbUintList default_data_iid_list;
    /**< The Subgraph to get calibration for */
    uint32_t subgraph_id;
    /**< The Processor to get calibration for */
    uint32_t proc_id;
    /**< A pointer to a mapping that associates module instances with 
    the processor domains they run on */
    AcdbSubgraphPdmMap *sg_mod_iid_map;
    /**< An offset to a Subgrahps hardware accel module list */
    uint32_t hw_accel_module_list_offset;
    /**< The instance of the module that contains tag data */
    uint32_t instance_id;
    /**< The parameter(s) to get cal data for */
    AcdbUintListZS *parameter_list;
    /**< A pointer to the full CKV[new] */
    AcdbGraphKeyVector *ckv;
    /**< A pointer to the Delta CKV containing the difference between
    CKV[new] and CKV[old] */
    AcdbGraphKeyVector *delta_ckv;
    /**< A pointer to the Module CKV */
    AcdbGraphKeyVector *module_ckv;
    /**< The type of parameter to get data for (NONE, SHARED, GLOBAL
    SHARED) */
    /**< The parameter type: persistent, non-persistent, globaly persistent */
    AcdbDataPersistanceType param_type;
    /**< The DEF, DOT, and DOT2 data offsets */
    AcdbCkvLutEntryOffsets data_offsets;
    /**< A list of offloaded parameters from the global offloaded
    parameter property */
    AcdbUintList offloaded_parameter_list;
}
#include "acdb_end_pack.h"
;

typedef struct _acdb_tag_data_context_info_t AcdbTagDataContextInfo;
#include "acdb_begin_pack.h"
struct _acdb_tag_data_context_info_t {
    AcdbOp op;
    AcdbOp data_op;
    /**< The Subgraph that contains tag data */
    uint32_t subgraph_id;
    /**< The instance of the module that contains tag data */
    uint32_t instance_id;
    /**< The parameter(s) to get tag data for */
    AcdbUintListZS *parameter_list;
    /**< The module tag containing the tag ID and TKV */
    AcdbModuleTag *tag;
    /**< The type of parameter to get data for (NONE, SHARED, GLOBAL
    SHARED) */
    AcdbDataPersistanceType param_type;
    /**< The DEF and DOT offsets */
    AcdbDefDotPair data_offsets;
    /**< A list of offloaded parameters from the global offloaded
    parameter property */
    AcdbUintList offloaded_parameter_list;
}
#include "acdb_end_pack.h"
;

typedef struct _acdb_iid_ref_count_t AcdbIidRefCount;
#include "acdb_begin_pack.h"
struct _acdb_iid_ref_count_t
{
    uint32_t module_iid;
    uint32_t ref_count;
}
#include "acdb_end_pack.h"
;

/**< Contains offsets to the key id and value lists that
make up a key vector */
typedef struct _acdb_key_vector_lut_entry_t AcdbKeyVectorLutEntry;
struct _acdb_key_vector_lut_entry_t
{
    /**< Absolute offset of the key table that includes #keys
    and the key id list */
    uint32_t offset_key_tbl;
    /**< Absolute offset of the value combination in the LUT */
    uint32_t offset_value_list;
};

/**< Maintains offsets for key vectors in the Cal Key ID Table
and Cal Key Value LUT chunks */
typedef struct _acdb_key_vector_lut_t AcdbKeyVectorLut;
struct _acdb_key_vector_lut_t
{
    /**< The size of the lookup table in bytes*/
    uint32_t size;
    /**< Number of entries in the lookup table */
    uint32_t num_entries;
    /**< A pointer to the array that stores the lookup table
    entries. The format of an entry is:
    <#keys, Key ID Table Offset, Value LUT Offset */
    AcdbKeyVectorLutEntry* lookup_table;
};

/**< Maintains an unziped key vector; separate key list, separate value list */
typedef struct _acdb_key_value_list_t AcdbKeyValueList;
struct _acdb_key_value_list_t
{
    /**< Number of keys in the key vector */
    uint32_t num_keys;
    /**< list of key ids whose length is num_keys */
    uint32_t *key_list;
    /**< list of key value ids whose length is num_keys */
    uint32_t *value_list;
};

/* ---------------------------------------------------------------------------
* Function Prototypes
*--------------------------------------------------------------------------- */

/**
* \brief
*		Search Subgraph Calibration LUT for offsets to the Key ID and Key
*       Value tables. Returns a list of CKV entries for a subgraph.
*
* \param[in] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in] sz_ckv_entry_list: Size of the CKV entry list
* \param[out] ckv_entry_list: CKV Entries found during the search
* \param[out] num_entries: nNumber of CKV Entries found
* \return 0 on success, and non-zero on failure
*/
int32_t SearchSubgraphCalLut(
    uint32_t req_subgraph_id, uint32_t sz_ckv_entry_list,
    AcdbCalKeyTblEntry *ckv_entry_list, uint32_t *num_entries);

/**
* \brief
*		Search Subgraph Calibration LUT for offsets to the Key ID and Key
*       Value tables. Returns the absolute file offset to the list of CKV entries
*       for a subgraph.
*
* \param[in] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in] sz_ckv_entry_list: Size of the CKV entry list
* \param[out] ckv_entry_list: CKV Entries found during the search
* \param[out] num_entries: nNumber of CKV Entries found
* \return 0 on success, and non-zero on failure
*/
int32_t SearchSubgraphCalLut2(AcdbSgCalLutHeader *sg_lut_entry_header,
    uint32_t *ckv_entry_list_offset);

void AcdbClearAudioCalContextInfo(AcdbAudioCalContextInfo* info);

/**
* \brief
*		Finds the DEF, DOT, and DOT2 data offsets using the Cal Key Table Entry
*       offsets(Key ID Table offset, Value LUT offset) of a subgraph from the
*       Subgraph Calibration LUT chunk.
*       It also updates the module_ckv in the context info struct which is used
*       to locate data on the heap
*
* \param[in] ckv_entry: Contains offsets to the Key ID and Value LUT tables
* \param[in/out] info: Context info containing the module kv to be udpated
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbFindModuleCKV(AcdbCalKeyTblEntry *ckv_entry,
    AcdbAudioCalContextInfo *info);

/**
* \brief
*		Uses the DEF, DOT, and DOT2 data offsets in the context info to find
*       calibration data for different PID types(non-persist/persist)
*
* \param[in/out] info: Context info containing the module kv
* \param[in/out] blob_offset: current response blob offset
* \param[in/out] rsp: Response blob to write caldata to
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbGetSubgraphCalibration(AcdbAudioCalContextInfo *info,
    uint32_t *blob_offset, AcdbBlob *rsp);

/**
* \brief
*       Get the data pool offset of the Tag Key List associated with a Module
*       Tag
*
* \param[in] tag_id: The module tag to get the key ID list for
* \param[in/out] dpo: The absolute data pool offset that points to the tag
*                key table in the data pool
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t FindTagKeyList(uint32_t tag_id, uint32_t* dpo);

int32_t AcdbGetUsecaseSubgraphList(AcdbGraphKeyVector* gkv,
    AcdbUintList* subgraph_list, AcdbGetGraphRsp* graph);

/**
* \brief
*       Get the vcpm calibration table for the specified subgraph
*
* \param[in] num_subgraphs:
* \param[in] subgraph_id: the subgraph identifier
* \param[in/out] file_offset: the absolute file offset of the subgraphs
*            vcpm calibration table
* \param[in/out] subgraph_cal_table: the vcpm calibration table
*            for the specified subgraph
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t GetVcpmSubgraphCalTable(uint32_t num_subgraphs, uint32_t subgraph_id,
    uint32_t* file_offset, AcdbVcpmSubgraphCalTable* subgraph_cal_table);

/**
* \brief
*       Get offload parameter calibration data from the file
*       path specified in the parameter payload
*
* \param[in] op: Specifies the data operation being performed: get size or data
* \param[in] subgraph_id: the subgraph to get data from
* \param[in/out] module_header: The parameter data instance to get data for
* \param[in/out] caldata: The parameter payload containing the offload
*                parameter file path
* \param[in/out] rsp: The response buffer to write the data to
* \param[in/out] module_start_blob_offset: The starting offset of the
*                parameter data in the response blob (starts are the module
*                header which is [iid, pid, size, err, data(...)])
* \param[in/out] module_start_blob_offset: The ending offset of the
*                parameter data in the response blob
* \return AR_EOK on success, non-zero otherwise
*/
int32_t AcdbGetOffloadedParameterCal(
    AcdbOp op, uint32_t subgraph_id, AcdbDspModuleHeader* module_header,
    AcdbPayload* caldata, AcdbBlob* rsp,
    uint32_t* module_start_blob_offset, uint32_t* module_end_blob_offset);
/* ---------------------------------------------------------------------------
* Function Definitions
*--------------------------------------------------------------------------- */

/**
* \brief
*       Create partitions for a table and store these partitions in
*       partition_buf (use glb_buf2, the smallest global buffer)
*
*       Buffers:
*       buf - Contains the table that needs to be partitioned
*       partition_buf - Holds the partitions in the format:
*       [p1.offset, p1.size, ..., pn.offset, pn.size]
*
*       Example
*       Size Of a Partition =
*       Global Buffer Size - (Global Buffer Size % Table Entry Size)
*       Ex.
*       glb_buf size = 2500Bytes
*       Cal LUT Entry size = 12Bytes
*       2500 - (2500 % 12) =
*       2496 (208 = (2496/12) Cal LUT Entries can fit into one partition)
*
* \param[in] table_offset: offset of ACDB table
* \param[in] table_size: size of ACDB table
* \param[in] table_entry_size: size of an entry in the ACDB table
* \param[in] buf_size: size of the buffer that stores each partition
* \param[in/out] partition_buf: buffer that stores partition info
* \param[in/out] num_partitions: number of partitions in partition_buf
*
* \return TRUE (create partitions), FALSE (don't create partitions)
*/
bool_t create_partitions(uint32_t table_offset, size_t table_size,
	size_t table_entry_size, size_t buf_size, uint32_t* partition_buf,
	uint32_t* num_partitions)
{
	bool_t should_partition = FALSE;
	uint32_t partition_size = 0;
	uint32_t parition_offset = 0;

	if (table_size > buf_size)
	{
		should_partition = TRUE;
		//Determine Partition Size

        //Max Readable size
		partition_size = (uint32_t)(buf_size - (buf_size % table_entry_size));
        *num_partitions = (uint32_t)AcdbCeil((uint32_t)table_size, partition_size);
		parition_offset = 0;
		for (uint32_t i = 0; i < (*num_partitions) * 2; i++)
		{
			if (i % 2 == 0)
			{
                //Store Size at odd index
				partition_buf[i] = partition_size;
			}
			else
			{
                //Store Offset at even index
				partition_buf[i] = table_offset + parition_offset;
				parition_offset += partition_size;
			}
		}
	}

	return should_partition;
}

/**
* \brief
*       Compares key vector values using memcmp
*
* \param[in] key_vector: The key vector used in the comparision
* \param[in/out] cmp_from_kv_values: The key values from key_vector to
*                compare with
* \param[in/out] cmp_to_kv_values: The key values to compare against
* \param[in/out] num_keys: number of keys in the key vector
*
* \return AR_EOK on success, non-zero otherwise
*/
bool_t CompareKeyVectorValues(AcdbGraphKeyVector key_vector, uint32_t* cmp_from_kv_values,
	uint32_t *cmp_to_kv_values, uint32_t num_keys)
{
	for (uint32_t i = 0; i < num_keys; i++)
		cmp_from_kv_values[i] = key_vector.graph_key_vector[i].value;

	if (0 == ACDB_MEM_CMP(cmp_from_kv_values, cmp_to_kv_values, num_keys * sizeof(uint32_t)))
		return TRUE;

	return FALSE;
}

/**
* \brief
*       Compares key vector ids using memcmp. The keys
*       must be sorted before passing them to this api
*
* \param[in] key_vector: The key vector used in the comparision
* \param[in/out] cmp_from_kv_ids: The key ids from key_vector to
*                compare with
* \param[in/out] cmp_to_kv_ids: The key ids to compare against
* \param[in/out] num_keys: number of keys in the key vector
*
* \return TRUE on success, FALSE otherwise
*/
bool_t CompareKeyVectorIds(AcdbGraphKeyVector key_vector, uint32_t* cmp_from_kv_ids,
	uint32_t *cmp_to_kv_ids, uint32_t num_keys)
{
	for (uint32_t i = 0; i < num_keys; i++)
		cmp_from_kv_ids[i] = key_vector.graph_key_vector[i].key;

	if (0 == ACDB_MEM_CMP(cmp_from_kv_ids, cmp_to_kv_ids, num_keys * sizeof(uint32_t)))
		return TRUE;

	return FALSE;
}

/**
* \brief
*       Compares key vector ids using a for loop. The keys
*       must be sorted before passing them to this api
*
* \param[in] key_vector: The key vector used in the comparision
* \param[in] cmp_with_key_id_list: The key id list to compare with
*
* \return TRUE on success, FALSE otherwise
*/
bool_t CompareKeyVectorIds2(AcdbGraphKeyVector *key_vector,
    const AcdbUintList *cmp_with_key_id_list)
{
    if (IsNull(key_vector) || IsNull(cmp_with_key_id_list))
        return FALSE;

    if (cmp_with_key_id_list->count != key_vector->num_keys)
        return FALSE;

    for (uint32_t i = 0; i < cmp_with_key_id_list->count; i++)
    {
        if (cmp_with_key_id_list->list[i] != key_vector->graph_key_vector[i].key)
            return FALSE;
    }

    return TRUE;
}

/**
* \brief CopyFromFileToBuf
*		Copies data from the ACDB Data file at a given offset to the provided buffer
* \param[in] file_offset: location in the file to start reading from
* \param[in/out] dst_buf: the buffer to copy data into
* \param[in] sz_dst_buf: size of the destination buffer
* \param[in] sz_block: the block size used to read from the file
* \param[int] calblob: Module calibration blob passed in from the client
* \return AR_EOK on success, non-zero otherwise
*/
int32_t CopyFromFileToBuf(uint32_t file_offset, void* dst_buf, uint32_t sz_dst_buf, uint32_t sz_block)
{
	if (IsNull(dst_buf) || sz_block == 0 || sz_dst_buf == 0)
		return AR_EBADPARAM;

	int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t foffset = 0;
	//Block Size to use for reading from file

	//Destination size alighned to 'sz_max_buf' bytes
	uint32_t sz_dst_aligned = (sz_dst_buf - (sz_dst_buf % sz_block));

	//Size of the file read initially set to block size
	uint32_t read_size = sz_block;

	//The remaining bytes to read from the file into the destination
	uint32_t sz_remainder_block = (sz_dst_buf % sz_block);

	//Occurs when the block size is greater than the destination buffer size
	if (sz_dst_aligned == 0)
	{
		read_size = sz_remainder_block;
	}

	while (offset < sz_dst_buf)
	{
		if (offset + sz_remainder_block == sz_dst_buf)
		{
			read_size = sz_remainder_block;
		}

        foffset = file_offset + offset;
        status = FileManReadBuffer((uint8_t*)dst_buf + offset, read_size, &foffset);
        if (AR_EOK != status)
        {
            ACDB_ERR("Error[%d]: Failed to read data from file. The read size is %d bytes", read_size);
            return status;
        }

		if ((offset == sz_dst_aligned && sz_remainder_block != 0)||
			(sz_dst_aligned == 0 && sz_remainder_block != 0))
		{
			offset += sz_remainder_block;
			//read_size = sz_remainder_block;
		}
		else
		{
			offset += sz_block;
		}
	}

	return status;
}

/**
* \brief
*		Write data to a buffer ensuring not to write past the length of the buffer
* \param[in] dst_blob: the blob to write to
* \param[in] blob_offset: current offset within dst_blob
* \param[in] src_blob: the blob to write from
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbWriteBuffer(AcdbBlob *dst_buf, uint32_t *blob_offset, AcdbBlob *src_buf)
{
    if (*blob_offset
        + src_buf->buf_size > dst_buf->buf_size)
    {
        return AR_ENEEDMORE;
    }

    ACDB_MEM_CPY_SAFE((uint8_t*)dst_buf->buf + *blob_offset,
        src_buf->buf_size,
        src_buf->buf, src_buf->buf_size);
    *blob_offset += src_buf->buf_size;

    return AR_EOK;
}

/**
* \brief
*		Search Tag Data Lookup Table for a matching TKV and retrieve the
*       def and dot offsets
*
* \param[int] tkv: tag key vector to search for
* \param[in] tag_data_tbl_offset: offset of tag data lut for a <SG, Tag> pair
* \param[out] offset_pair: Offset of def and dot offsets
*
* \return 0 on success, and non-zero on failure
*/
int32_t TagDataSearchLut(AcdbGraphKeyVector *tkv,
    uint32_t tag_data_tbl_offset, AcdbDefDotPair *offset_pair)
{
    int32_t status = AR_EOK;
	uint32_t i = 0;
	ChunkInfo ci_tag_data_lut = { 0 };
    KeyTableHeader key_table_header = { 0 };
	size_t sz_tag_key_vector_entry = 0;
	uint32_t offset = 0;
	bool_t result = FALSE;

    ACDB_CLEAR_BUFFER(glb_buf_1);
    ACDB_CLEAR_BUFFER(glb_buf_3);

    ci_tag_data_lut.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_LUT;
    status = ACDB_GET_CHUNK_INFO(&ci_tag_data_lut);
    if (AR_FAILED(status))
    {
        return status;
    }

    offset = ci_tag_data_lut.chunk_offset + tag_data_tbl_offset;
    status = FileManReadBuffer(&glb_buf_1, 2 * sizeof(uint32_t), &offset);
    if (status != 0)
    {
        ACDB_ERR("Error[%d]: Unable to read TKV length and "
            "number of TKV value entries", status);
        return status;
    }

    key_table_header.num_keys = glb_buf_1[0];
    key_table_header.num_entries = glb_buf_1[1];

	sz_tag_key_vector_entry =
        key_table_header.num_keys * sizeof(uint32_t)
        + 2 * sizeof(uint32_t);
	//sz_tag_data_lut = num_tag_key_vector_entries * sz_tag_key_vector_entry;

	/* Number of keys for this LUT must match the
     * number of keys in the input */
	if (key_table_header.num_keys != tkv->num_keys)
	{
        ACDB_DBG("Error[%d]: The LUT table key count %d does not "
            "match input TKV key count %d",
            AR_EFAILED, key_table_header.num_keys, tkv->num_keys);
		return AR_EFAILED;
	}

	result = FALSE;
	for (i = 0; i < key_table_header.num_entries; i++)
	{
		ACDB_CLEAR_BUFFER(glb_buf_1);

        status = FileManReadBuffer(
            &glb_buf_1, sz_tag_key_vector_entry, &offset);
        if (status != 0)
        {
            ACDB_DBG("Error[%d]: Unable to read TKV values entry", AR_EFAILED);
            return AR_EFAILED;
        }

		if (TRUE == CompareKeyVectorValues(
            *tkv, glb_buf_3, glb_buf_1, tkv->num_keys))
		{
			offset_pair->offset_def = (glb_buf_1 + key_table_header.num_keys)[0];
            offset_pair->offset_dot = (glb_buf_1 + key_table_header.num_keys)[1];
			result = TRUE;
			break;
		}
	}

	ACDB_CLEAR_BUFFER(glb_buf_1);
	ACDB_CLEAR_BUFFER(glb_buf_3);

	if (FALSE == result)
	{
        ACDB_DBG("Error[%d]: Unable to find matching TKV", AR_ENOTEXIST);
		return AR_ENOTEXIST;
	}

	return status;
}

/**
* \brief
*		Search Tag Data Key Table for a <Subgraph, Tag ID> pair and retrieve the
*       offset of the tag data table
*
* \param[int] subgraph_id: Subgraph to search for
* \param[in] tag_id: Module Tag to search for
* \param[out] offset_tag_data_tbl: Offset of the Tag Data Table
*
* \return 0 on success, and non-zero on failure
*/
int32_t TagDataSearchKeyTable(uint32_t subgraph_id, uint32_t tag_id, uint32_t *offset_tag_data_tbl)
{
    int32_t status = AR_EOK;
    int32_t search_index_count = 2;
    SubgraphTagLutEntry entry = { subgraph_id, tag_id, 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };
    ChunkInfo ci_key_table = { 0 };

    if (IsNull(offset_tag_data_tbl))
    {
        ACDB_ERR("Error[%d]: "
            "The offset input parameter is null.", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_key_table.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_KEYTABLE;
    status = ACDB_GET_CHUNK_INFO(&ci_key_table);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to retrieve Tag Data Key Table chunk.", status);
        return status;
    }

    //Setup Table Information (skip table entry count)
    table_info.table_offset = ci_key_table.chunk_offset + sizeof(uint32_t);
    table_info.table_size = ci_key_table.chunk_size - sizeof(uint32_t);
    table_info.table_entry_size = sizeof(SubgraphTagLutEntry);

    //Setup Search Information
    search_info.num_search_keys = search_index_count;
    search_info.num_structure_elements =
        (sizeof(SubgraphTagLutEntry) / sizeof(uint32_t));
    search_info.table_entry_struct = &entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);

    if(AR_SUCCEEDED(status))
        *offset_tag_data_tbl = entry.offset;

    return status;
}

/**
* \brief
*		Retrieve tag data from the file manager or heap for a list of parameters
*
* \param[int] info: context information for tag data
* \param[out] rsp: Response blob containing calibration in the format of
*                  [<IID, PID, Size, Err Code, Data>, ...]
*
* \return 0 on success, and non-zero on failure
*/
int32_t TagDataGetParameterData(AcdbTagDataContextInfo *info, uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t tmp_blob_offset = 0;
    uint32_t data_offset = 0;
    uint32_t padded_param_size = 0;
    uint32_t param_dot_offset = 0;
    uint32_t entry_index = 0;
    uint32_t num_id_entries = 0;
    bool_t is_offloaded_param = FALSE;
    AcdbModIIDParamIDPair iid_pid_pair = { 0 };
    AcdbDspModuleHeader module_header = { 0 };
    ChunkInfo ci_def = { 0 };
    ChunkInfo ci_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbPayload caldata = { 0 };
    AcdbBlob buffer = { 0 };
    AcdbOp op = IsNull(rsp->buf) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (IsNull(info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: "
            "One or more input parameters are null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_def.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DEF;
    ci_dot.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(
        &ci_def, &ci_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to retrieve def, dot, or data pool tables", status);
        return status;
    }

    offset = ci_def.chunk_offset + info->data_offsets.offset_def;
    status = FileManReadBuffer(&num_id_entries, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Failed to read number of tagged <MID, PID> entries.", status);
        return status;
    }

    status = FileManReadBuffer(&glb_buf_3[0],
        num_id_entries * sizeof(AcdbModIIDParamIDPair), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read List of <MID, PID>.", status);
        return status;
    }

    iid_pid_pair.module_iid = info->instance_id;
    module_header.module_iid = info->instance_id;

    for (uint32_t i = 0; i < info->parameter_list->count; i++)
    {
        iid_pid_pair.parameter_id = info->parameter_list->list[i];
        module_header.parameter_id = info->parameter_list->list[i];

        if (SEARCH_ERROR == AcdbDataBinarySearch2((void*)&glb_buf_3,
            num_id_entries * sizeof(AcdbModIIDParamIDPair),
            &iid_pid_pair, 2,
            (int32_t)(sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)),
            &entry_index))
        {
            status = AR_ENOTEXIST;
            ACDB_DBG("Error[%d]: Unable to find Parameter(0x%x). Skipping..",
                status, module_header.parameter_id);
            continue;
        }

        status = IsOffloadedParam(module_header.parameter_id,
            &info->offloaded_parameter_list);

        is_offloaded_param = AR_SUCCEEDED(status) ? TRUE: FALSE;

        //Get from heap
        status = GetSubgraphCalData(
            info->param_type, ACDB_DATA_ACDB_CLIENT,
            &info->tag->tag_key_vector, info->subgraph_id,
            module_header.module_iid, module_header.parameter_id,
            is_offloaded_param, blob_offset, rsp);

        if (AR_SUCCEEDED(status))
        {
            continue;
        }

        //Get from file manager

        offset = ci_dot.chunk_offset
            + info->data_offsets.offset_dot;

        /* Calculation for DOT offset of <MID, PID> pair
        *
        * Offset of  +  Number of  +  Offset of the desired DOT entry based
        *    DOT       DOT entries         on index of <MID,PID> in DEF
        */
        param_dot_offset =
            offset + sizeof(uint32_t) + sizeof(uint32_t) * (uint32_t)(
                entry_index
                / (sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)));

        status = FileManReadBuffer(&data_offset,
            sizeof(uint32_t), &param_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Failed to read data pool offset from DOT.", status);
            return status;
        }

        offset = ci_data_pool.chunk_offset + data_offset;

        status = FileManReadBuffer(&module_header.param_size,
            sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Failed to read param size from data pool.", status);
            return status;
        }

        caldata.size = module_header.param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, offset);

        if (is_offloaded_param)
        {
            status = AcdbGetOffloadedParameterCal(
                info->op, info->subgraph_id, &module_header,
                &caldata, rsp, blob_offset, &tmp_blob_offset);
            if (AR_FAILED(status))
                return status;

            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }
        else
        {
            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }

        switch (op)
        {
        case ACDB_OP_GET_SIZE:
            rsp->buf_size += sizeof(AcdbDspModuleHeader)
                + padded_param_size;
            break;
        case ACDB_OP_GET_DATA:

            //Write Module IID, and Parameter ID
            buffer.buf = (void*)&module_header;
            buffer.buf_size = sizeof(AcdbDspModuleHeader);
            status = AcdbWriteBuffer(rsp, blob_offset, &buffer);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to write module header for"
                    "<sg, mod, param>[0x%x, 0x%x, 0x%x]",
                    status, info->subgraph_id, module_header.module_iid,
                    module_header.parameter_id);
                return status;
            }

            if (is_offloaded_param)
            {
                *blob_offset = tmp_blob_offset;
                continue;
            }

            //Write Payload
            if (rsp->buf_size < (*blob_offset + module_header.param_size))
                return AR_ENEEDMORE;

            if (module_header.param_size > 0)
            {
                status = FileManReadBuffer(
                    (uint8_t*)rsp->buf + *blob_offset,
                    module_header.param_size,
                    &offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: "
                        "Failed to read param(0x%x) data",
                        status, module_header.parameter_id);
                    return status;
                }

                *blob_offset += padded_param_size;
            }
            break;
        default:
            break;
        }

    }

    return status;
}

/**
* \brief
*		Retrieve tag data from the file manager or heap for:
*           1. An entire subgraph OR
*           2. An entire module
*
* \param[int] info: context information for tag data
* \param[int] blob_offset: offset within the rsp blob
* \param[out] rsp: Response blob containing calibration in the format of
*                  [<IID, PID, Size, Err Code, Data>, ...]
*
* \return 0 on success, and non-zero on failure
*/
int32_t TagDataGetSubgraphData(AcdbTagDataContextInfo *info,
    uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_def = { 0 };
    ChunkInfo ci_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    uint32_t num_id_entries = 0;
    uint32_t num_data_offset = 0;
    uint32_t num_param_cal_found = 0;
    uint32_t cur_def_offset = 0;
    uint32_t cur_dot_offset = 0;
    uint32_t cur_dpool_offset = 0;
    uint32_t data_offset = 0;
    uint32_t tmp_blob_offset = 0;
    uint32_t padded_param_size = 0;
    bool_t is_offloaded_param = FALSE;
    AcdbDspModuleHeader module_header = { 0 };
    AcdbPayload caldata = { 0 };
    AcdbBlob buffer = { 0 };

    ci_def.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DEF;
    ci_dot.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_def, &ci_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to retrieve def, dot, or data pool tables", status);
        return status;
    }

    cur_def_offset = ci_def.chunk_offset + info->data_offsets.offset_def;
    status = FileManReadBuffer(&num_id_entries, sizeof(uint32_t), &cur_def_offset);
    if (status != 0)
    {
        ACDB_ERR("Error[%d]: Unable to read number of Tag ID entries", AR_EFAILED);
        return AR_EFAILED;
    }

    //Tag Data DOT Table Chunk
    cur_dot_offset = ci_dot.chunk_offset + info->data_offsets.offset_dot;
    status = FileManReadBuffer(&num_data_offset, sizeof(uint32_t), &cur_dot_offset);
    if (status != 0)
    {
        ACDB_ERR("Error[%d]: Unable to read number of Tag ID entries", AR_EFAILED);
        return AR_EFAILED;
    }

    if (num_id_entries != num_data_offset)
    {
        ACDB_ERR("Error[%d]: Tag def entry count (%d) does not match"
            "Tag dot entry count (%d)",
            num_id_entries, num_data_offset, AR_EFAILED);
        return AR_EFAILED;
    }

    for (uint32_t i = 0; i < num_id_entries; i++)
    {
        status = FileManReadBuffer(&module_header, sizeof(AcdbMiidPidPair),
            &cur_def_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read <iid, pid> entry", status);
            return status;
        }

        //If Get Module Data is called
        if((info->data_op == ACDB_OP_GET_MODULE_DATA) &&
            (module_header.module_iid != info->instance_id))
        {
            cur_dot_offset += sizeof(uint32_t);
            continue;
        }

        num_param_cal_found++;

        status = IsOffloadedParam(module_header.parameter_id,
            &info->offloaded_parameter_list);

        is_offloaded_param = AR_SUCCEEDED(status) ? TRUE : FALSE;

        //Get data from Heap
        status = GetSubgraphCalData(info->param_type, ACDB_DATA_ACDB_CLIENT,
            &info->tag->tag_key_vector,
            info->subgraph_id, module_header.module_iid,
            module_header.parameter_id, is_offloaded_param, blob_offset, rsp);

        if (AR_SUCCEEDED(status))
        {
            cur_dot_offset += sizeof(uint32_t);
            continue;
        }

        //Get data from file manager
        status = FileManReadBuffer(
            &data_offset, sizeof(uint32_t), &cur_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read number of "
                "<iid, pid> entries", status);
            return status;
        }

        cur_dpool_offset = ci_data_pool.chunk_offset + data_offset;
        status = FileManReadBuffer(&module_header.param_size,
            sizeof(uint32_t), &cur_dpool_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read param size", status);
            return status;
        }

        caldata.size = module_header.param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, cur_dpool_offset);

        if (is_offloaded_param)
        {
            status = AcdbGetOffloadedParameterCal(
                info->op, info->subgraph_id, &module_header,
                &caldata, rsp, blob_offset, &tmp_blob_offset);
            if (AR_FAILED(status))
                return status;

            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }
        else
        {
            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }

        switch (info->op)
        {
        case ACDB_OP_GET_SIZE:
            rsp->buf_size +=
                sizeof(AcdbDspModuleHeader) + padded_param_size;
            break;
        case ACDB_OP_GET_DATA:
            //Write Module IID, and Parameter ID
            buffer.buf = (void*)&module_header;
            buffer.buf_size = sizeof(AcdbDspModuleHeader);
            status = AcdbWriteBuffer(rsp, blob_offset, &buffer);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to write module header for"
                    "<Subgraph(0x%x), Instance(0x%x), Parameter(0x%x)>",
                    status, info->subgraph_id, module_header.module_iid,
                    module_header.parameter_id);
                return status;
            }

            if (is_offloaded_param)
            {
                *blob_offset = tmp_blob_offset;
                continue;
            }

            //Write Payload
            if (rsp->buf_size < (*blob_offset + module_header.param_size))
                return AR_ENEEDMORE;

            if (module_header.param_size > 0)
            {
                buffer.buf = caldata.payload;
                buffer.buf_size = caldata.size;

                status = AcdbWriteBuffer(rsp, blob_offset, &buffer);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Unable to write param(0x%x) data",
                        status, module_header.parameter_id);
                    return status;
                }
            }

            *blob_offset += ACDB_PADDING_8_BYTE(caldata.size);

            break;
        default:
            break;
        }
    }

    if (num_param_cal_found == 0) return AR_ENOTEXIST;

    return status;
}

int32_t AcdbCmdGetModuleTagData(AcdbSgIdModuleTag *req, AcdbBlob *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    uint32_t offset_tag_data_tbl = 0;
    uint32_t blob_offset = 0;
    AcdbTagDataContextInfo info = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (rsp_size < sizeof(AcdbBlob))
    {
        return AR_EBADPARAM;
    }

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: "
            "One or more input parameters are null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    if (req->module_tag.tag_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: The TKV cannot be empty. If the intent is to "
            "retrieve default data, use the CKV-based 'GET' APIs", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->num_sg_ids == 0 || IsNull(req->sg_ids))
    {
        ACDB_ERR("Error[%d]: The subgraph list cannot be empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = AcdbSort2(
        req->module_tag.tag_key_vector.num_keys * sizeof(AcdbKeyValuePair),
        req->module_tag.tag_key_vector.graph_key_vector,
        sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to sort Tag Key Vector", AR_EBADPARAM);
        return status;
    }

    /* Tag data does not have a param type. Currently tag data is
     * stored under non-persistent data in the heap */
    info.param_type = ACDB_DATA_NON_PERSISTENT;
    info.op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    info.data_op = ACDB_OP_GET_SUBGRAPH_DATA;
    info.tag = &req->module_tag;

    GetOffloadedParamList(&info.offloaded_parameter_list);
    if (info.offloaded_parameter_list.count == 0)
    {
        ACDB_DBG("Error[%d]: No offloaded parameters found. Skipping..",
            status);
    }

    for (uint32_t i = 0; i < req->num_sg_ids; i++)
    {
        info.subgraph_id = req->sg_ids[i];

        // Search Tag Key Table Chunk
        offset_tag_data_tbl = 0;
        status = TagDataSearchKeyTable(info.subgraph_id,
                                       info.tag->tag_id,
                                       &offset_tag_data_tbl);
        if (AR_FAILED(status))
        {
            if (info.op == ACDB_OP_GET_SIZE)
                ACDB_DBG("Warning[%d]: No tag data for Tag(0x%x) "
                         "found under Subgraph(0x%x). Skipping..",
                         status, info.tag->tag_id, info.subgraph_id);
            status = AR_EOK;
            continue;
        }

        // Search Tag Data LUT
        status = TagDataSearchLut(&info.tag->tag_key_vector,
                                  offset_tag_data_tbl,
                                  &info.data_offsets);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Warning[%d]: No matching TKV "
                     "found under Subgraph(0x%x) with Tag(0x%x). Skipping..",
                     status, info.subgraph_id, info.tag->tag_id);
            status = AR_EOK;
            continue;
        }

        //Get Module Tag Data
        status = TagDataGetSubgraphData(&info, &blob_offset, rsp);
        if (AR_FAILED(status) && status != AR_ENOTEXIST)
        {
            break;
        }
    }

    if (AR_FAILED(status) && status != AR_ENOTEXIST)
        return status;

    else if (rsp->buf_size <= 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: No tag data found", status);
    }

    return status;
}

int32_t AcdbGetTagDataForSubgraph(AcdbTagDataContextInfo* info,
    uint32_t* blob_offset, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset_tag_data_tbl = 0;

    if (IsNull(info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: "
            "One or more input parameters are null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    GetOffloadedParamList(&info->offloaded_parameter_list);
    if (info->offloaded_parameter_list.count == 0)
    {
        ACDB_DBG("Error[%d]: No offloaded parameters found. Skipping..",
            status);
    }

    //Search Tag Key Table Chunk
    offset_tag_data_tbl = 0;
    status = TagDataSearchKeyTable(info->subgraph_id,
        info->tag->tag_id, &offset_tag_data_tbl);
    if (AR_FAILED(status) && status == AR_ENOTEXIST)
    {
        ACDB_ERR("Error[%d]: The <subgraph, tag>[0x0%x, 0x0%x] "
            "entry does not exist", status,
            info->subgraph_id, info->tag->tag_id);
        return status;
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured while searching "
            "the tag key table for entry <Subgraph, Tag>[0x0%x,0x0%x]",
            status, info->subgraph_id, info->tag->tag_id);
        return status;
    }

    //Search Tag Data LUT
    status = TagDataSearchLut(&info->tag->tag_key_vector,
        offset_tag_data_tbl, &info->data_offsets);
    if (AR_FAILED(status) && status == AR_ENOTEXIST)
    {
        return status;
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured while searching "
            "the tag data lut", status);
        return status;
    }

    if (info->parameter_list->count == 0)
    {
        //Get Tag data for an entire module
        status = TagDataGetSubgraphData(info, blob_offset, rsp);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            ACDB_ERR("Error[%d]: No data found for "
                "<subgraph, tag, module instance>[0x%x, 0x%x, 0x%x]",
                status, info->subgraph_id, info->tag->tag_id, info->instance_id);
            return status;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: An error occured while retrieving all tag"
                " data for <subgraph, tag, module instance>[0x%x, 0x%x, 0x%x]",
                status, info->subgraph_id, info->tag->tag_id, info->instance_id);
            return status;
        }
    }
    else
    {
        //Get Tag Data for the specified list of parameters
        status = TagDataGetParameterData(info, blob_offset, rsp);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            ACDB_ERR("Error[%d]: No data found with the parameter list "
                "for <subgraph, tag, module instance>[0x%x, 0x%x, 0x%x]",
                status, info->subgraph_id, info->tag->tag_id, info->instance_id);
            return status;
        }
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: An error occured while retrieving "
                "data with parameter list for "
                "<subgraph, tag, module instance>[0x%x, 0x%x, 0x%x]",
                status, info->subgraph_id, info->tag->tag_id, info->instance_id);
            return status;
        }
    }

    return status;
}

int32_t AcdbCmdGetTagData(AcdbGetTagDataReq* req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbTagDataContextInfo info = { 0 };
    AcdbSubgraph *subgraph = NULL;
    AcdbGetGraphRsp graph = { 0 };

    if (req->graph_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: No data exist for the empty GKV",
            AR_ENOTEXIST);
        return AR_ENOTEXIST;
    }
    else
    {
        ACDB_DBG("Retrieving Tag data for the following graph key vector:");
        LogKeyVector(&req->graph_key_vector, GRAPH_KEY_VECTOR);
    }

    if (req->module_tag.tag_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: The TKV cannot be empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = AcdbSort2(
        req->module_tag.tag_key_vector.num_keys * sizeof(AcdbKeyValuePair),
        req->module_tag.tag_key_vector.graph_key_vector,
        sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to sort Tag Key Vector", AR_EBADPARAM);
        return status;
    }

    /* Tag data does not have a param type. Currently tag data is
    * stored under non-persistent data in the heap */
    info.param_type = ACDB_DATA_NON_PERSISTENT;
    info.op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    info.data_op = ACDB_OP_GET_MODULE_DATA;
    info.tag = &req->module_tag;

    if (info.op == ACDB_OP_GET_SIZE)
    {
        ACDB_DBG("Getting data for Tag(0x%x) and TKV:",
            info.tag->tag_id);
        LogKeyVector(&info.tag->tag_key_vector, TAG_KEY_VECTOR);
    }

    status = AcdbGetUsecaseSubgraphList(
        &req->graph_key_vector, NULL, &graph);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get usecase subgraphs"
            " for the given graph key vector.",
            status);
        goto end;
    }

    AcdbModuleParamList* instance_param_list = NULL;
    bool_t found_subgraph = false;
    instance_param_list = req->instance_param_list;
    for (uint32_t i = 0; i < req->num_module_instance; i++)
    {
        subgraph = graph.subgraphs;
        if (IsNull(subgraph))
        {
            ACDB_ERR("Error[%d]: The subgraph list is null",
                status);
            break;
        }
        info.instance_id = instance_param_list->instance_id;
        info.subgraph_id = subgraph->sg_id;
        info.parameter_list = &instance_param_list->parameter_list;

        for (uint32_t j = 0; j < graph.num_subgraphs; j++)
        {
            info.subgraph_id = subgraph->sg_id;

            if (j != graph.num_subgraphs - 1)
                subgraph = (AcdbSubgraph*)((uint8_t*)subgraph + sizeof(AcdbSubgraph)
                + subgraph->num_dst_sgids * sizeof(uint32_t));

            found_subgraph = DoesSubgraphContainModule(info.subgraph_id,
                instance_param_list->instance_id, &status);

            if (found_subgraph)
                break;
        }

        if (i != req->num_module_instance - 1)
            instance_param_list = (AcdbModuleParamList*)((uint8_t*)instance_param_list
            + sizeof(AcdbModuleParamList)
            + instance_param_list->parameter_list.count * sizeof(uint32_t));

        if (!found_subgraph)
        {
            ACDB_ERR("Error[%d]: Module instance 0x%x not found in usecase"
                , status, info.instance_id);
            continue;
        }

        status = AcdbGetTagDataForSubgraph(&info, &blob_offset, rsp);
        if (AR_SUCCEEDED(status) || status == AR_ENOTEXIST)
        {
            status = AR_EOK;
            continue;
        }
        else
        {
            break;
        }
    }

    if (rsp->buf_size == 0)
        status = AR_ENOTEXIST;

end:
    //Clean Up Context Info
    info.tag = NULL;
    return status;
}

int32_t AcdbCmdSetTagData(AcdbSetTagDataReq *req)
{
    int32_t status = AR_EOK;
    uint32_t subgraph_id = 0;
    uint32_t num_subgraphs_found = 0;
    uint32_t offset_tag_data_tbl = 0;
    uint32_t offset_tag_key_ids = 0;
    AcdbUintList tag_key_id_list = { 0 };
    AcdbSubgraphParamData subgraph_param_data = { 0 };

    if (IsNull(req))
    {
        ACDB_ERR("Error[%d]: The input request is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->graph_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: The graph key vector cannot be empty.",
            AR_EUNSUPPORTED);
        return AR_EUNSUPPORTED;
    }
    else
    {
        ACDB_DBG("Setting tag data for the following graph key vector:");
        LogKeyVector(&req->graph_key_vector, GRAPH_KEY_VECTOR);
    }

    if (req->module_tag.tag_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: The TKV cannot be empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->blob_size == 0 || IsNull(req->blob))
    {
        ACDB_ERR("Error[%d]: The input blob is empty. There are not parameters to set",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    /* GLB_BUFFER_3 is used here as the filtered subgraph list. */
    ACDB_CLEAR_BUFFER(glb_buf_3);
    subgraph_param_data.subgraph_id_list.count = 0;
    subgraph_param_data.subgraph_id_list.list = &glb_buf_3[0];
    subgraph_param_data.data_size = req->blob_size;
    subgraph_param_data.data = req->blob;

    status = AcdbGetUsecaseSubgraphList(&req->graph_key_vector,
        &subgraph_param_data.subgraph_id_list, NULL);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get usecase subgraph list", status);
        return status;
    }

    status = AcdbSort2(
        req->module_tag.tag_key_vector.num_keys * sizeof(AcdbKeyValuePair),
        &req->module_tag.tag_key_vector,
        sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort the tag key vector");
        return status;
    }

    /* Verify that the input tkv's key ids match the the tag + tkv
    defined in the database */
    status = FindTagKeyList(req->module_tag.tag_id, &offset_tag_key_ids);
    if (AR_FAILED(status) && status == AR_ENOTEXIST)
    {
        ACDB_ERR("Error[%d]: The given tag key vectors Key IDs are not associated"
            " with Tag 0x0%x. Check the tags definition.", status,
            req->module_tag.tag_id, subgraph_id);
        return status;
    }
    else if AR_FAILED(status)
    {
        return status;
    }

    status = FileManReadBuffer(&tag_key_id_list.count,
        sizeof(uint32_t), &offset_tag_key_ids);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of keys.", status);
        return status;
    }

    if (tag_key_id_list.count != 0)
    {
        status = FileManGetFilePointer2((void**)&tag_key_id_list.list,
            offset_tag_key_ids);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read tag Key ID list", status);
            return status;
        }
    }

    if (!CompareKeyVectorIds2(&req->module_tag.tag_key_vector,
        &tag_key_id_list))
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: The given tag key vectors Key IDs for "
            "Tag 0x0%x do not match the tag defined in the database.",
            status, req->module_tag.tag_id, subgraph_id);
        return status;
    }

    /* Ensure the Tag + Subgraph combination exists in the database
     * before commiting data to the heap. */
    for (uint32_t i = 0; i < subgraph_param_data.subgraph_id_list.count; i++)
    {
        subgraph_id = subgraph_param_data.subgraph_id_list.list[i];

        status = TagDataSearchKeyTable(subgraph_id,
            req->module_tag.tag_id, &offset_tag_data_tbl);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            ACDB_DBG("Error[%d]: Tag 0x0%x not found in any "
                "module under Subgraph 0x0%x. Skipping..", status,
                req->module_tag.tag_id, subgraph_id);
            continue;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: An error occured while searching "
                "the tag key table for entry <Subgraph, Tag>[0x0%x,0x0%x]",
                status, subgraph_id, req->module_tag.tag_id);
            goto end;
        }

        subgraph_param_data.subgraph_id_list
            .list[num_subgraphs_found] = subgraph_id;
        num_subgraphs_found++;
    }

    subgraph_param_data.subgraph_id_list.count = num_subgraphs_found;

    if (num_subgraphs_found == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Tag 0x0%x not found in any "
            "subgraph under the provided usecase",
            status, req->module_tag.tag_id);
        goto end;
    }

    status = DataProcSetTagData(&req->module_tag, &subgraph_param_data);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to set tag data to heap", status);
        goto end;
    }

    if (acdb_delta_data_is_persist_enabled())
    {
        status = acdb_delta_data_ioctl(
            ACDB_DELTA_DATA_CMD_SAVE, NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to save delta file", status);
        }
    }
    else
    {
        ACDB_INFO("Error[%d]: Unable to save delta data. "
            "Is delta data persistance enabled?", status);
    }

end:
    ACDB_CLEAR_BUFFER(glb_buf_3);

    return status;
}

/**
* \brief
*		Retrieve calibration data for a parameter from the data pool
* \param[int] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in/out] rsp: A data blob containg calibration data
* \param[in] offset_pair: calibration data def and dot offsets
* \return 0 on success, and non-zero on failure
*/
int32_t CalDataGetParameterData(AcdbAudioCalContextInfo *info, uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t tmp_blob_offset = 0;
    uint32_t data_offset = 0;
    uint32_t padded_param_size = 0;
    uint32_t param_dot_offset = 0;
    uint32_t entry_index = 0;
    uint32_t num_id_entries = 0;
    uint32_t num_iid_found = 0;
    bool_t is_offloaded_param = FALSE;
    AcdbModIIDParamIDPair iid_pid_pair = { 0 };
    AcdbDspModuleHeader module_header = { 0 };
    ChunkInfo ci_def = { 0 };
    ChunkInfo ci_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbPayload caldata = { 0 };
    AcdbBlob buffer = { 0 };
    AcdbIidRefCount *iid_ref = NULL;
    AcdbOp op = IsNull(rsp->buf) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (IsNull(info) || IsNull(rsp))
    {
        ACDB_ERR("The input request, or response are null");
        return AR_EBADPARAM;
    }

    ci_def.chunk_id = ACDB_CHUNKID_CALDATADEF;
    ci_dot.chunk_id = ACDB_CHUNKID_CALDATADOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(&ci_def, &ci_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: "
            "Unable to retrieve def, dot, or data pool tables", status);
        return status;
    }

    offset = ci_def.chunk_offset + info->data_offsets.offset_def;

    status = FileManReadBuffer(&num_id_entries, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of <MID, PID> entries.", status);
        return status;
    }

    status = FileManReadBuffer(
        &glb_buf_3[0], num_id_entries * sizeof(AcdbModIIDParamIDPair), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read List of <MID, PID>.", status);
        return status;
    }

    iid_pid_pair.module_iid = info->instance_id;
    module_header.module_iid = info->instance_id;

    if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        //Ensure global buffer can store the default data IID Reference list
        if (GLB_BUF_1_LENGTH < num_id_entries * 2)
        {
            ACDB_ERR("Error[%d]: Need more memory to store IID reference list",
                AR_ENEEDMORE);
            return AR_ENEEDMORE;
        }

        ACDB_CLEAR_BUFFER(glb_buf_1);

        iid_ref = (AcdbIidRefCount*)glb_buf_1;
    }

    for (uint32_t i = 0; i < info->parameter_list->count; i++)
    {
        iid_pid_pair.parameter_id = info->parameter_list->list[i];
        module_header.parameter_id = info->parameter_list->list[i];

        if (SEARCH_ERROR == AcdbDataBinarySearch2((void*)&glb_buf_3,
            num_id_entries * sizeof(AcdbModIIDParamIDPair),
            &iid_pid_pair, 2,
            (int32_t)(sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)),
            &entry_index))
        {
            status = AR_ENOTEXIST;
            ACDB_DBG("Error[%d]: Unable to find Parameter(0x%x). Skipping..",
                status, module_header.parameter_id);
            continue;
        }

        if (info->is_default_module_ckv && info->ignore_get_default_data)
        {
            //Add IIDs to list and ignore get data
            if (iid_ref->module_iid != module_header.module_iid && num_iid_found == 0)
            {
                iid_ref->module_iid = module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
            }
            else if (iid_ref->module_iid != module_header.module_iid)
            {
                iid_ref++;
                iid_ref->module_iid = module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
            }
            else
            {
                /* Increase ref count of the current <IID, Ref Count> Obj */
                iid_ref->ref_count++;
            }

            continue;
        }
        else
        {
            /* For other CKVs, if the module is in the default data list, remove it */
            if (!IsNull(info->default_data_iid_list.list))
            {
                iid_ref = (AcdbIidRefCount*)
                    info->default_data_iid_list.list;
                bool_t found_iid = FALSE;
                for (uint32_t j = 0; j < info->
                    default_data_iid_list.count; j++)
                {
                    if ((module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count > 0)
                    {
                        iid_ref->ref_count--;
                        found_iid = TRUE;
                        break;
                    }
                    else if ((module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count <= 0)
                        break;

                    iid_ref++;
                }

                if (info->is_default_module_ckv && !found_iid)
                {
                    continue;
                }
            }
        }

        status = IsOffloadedParam(module_header.parameter_id,
            &info->offloaded_parameter_list);

        is_offloaded_param = AR_SUCCEEDED(status) ? TRUE : FALSE;

        //Get from heap
        status = GetSubgraphCalData(
            info->param_type, ACDB_DATA_ACDB_CLIENT,
            info->module_ckv, info->subgraph_id, module_header.module_iid,
            module_header.parameter_id, is_offloaded_param,
            blob_offset, rsp);

        if (AR_SUCCEEDED(status))
        {
            continue;
        }

        //Get from file manager

        offset = ci_dot.chunk_offset
            + info->data_offsets.offset_dot;

        /* Calculation for DOT offset of <MID, PID> pair
        *
        * Offset of  +  Number of  +  Offset of the desired DOT entry based
        *    DOT       DOT entries         on index of <MID,PID> in DEF
        */
        param_dot_offset =
            offset + sizeof(uint32_t) + sizeof(uint32_t) * (uint32_t)(
                entry_index
                / (sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)));

        status = FileManReadBuffer(&data_offset,
            sizeof(uint32_t), &param_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Failed to read data pool offset from DOT.", status);
            return status;
        }

        offset = ci_data_pool.chunk_offset + data_offset;

        status = FileManReadBuffer(&module_header.param_size,
            sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: "
                "Failed to read param size from data pool.", status);
            return status;
        }

        caldata.size = module_header.param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, offset);

        if (is_offloaded_param)
        {
            status = AcdbGetOffloadedParameterCal(
                info->op, info->subgraph_id, &module_header,
                &caldata, rsp, blob_offset, &tmp_blob_offset);
            if (AR_FAILED(status))
                return status;

            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }
        else
        {
            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }

        switch (op)
        {
        case ACDB_OP_GET_SIZE:
            rsp->buf_size += sizeof(AcdbDspModuleHeader)
            + padded_param_size;
            break;
        case ACDB_OP_GET_DATA:

            //Write Module IID, and Parameter ID
            buffer.buf = (void*)&module_header;
            buffer.buf_size = sizeof(AcdbDspModuleHeader);
            status = AcdbWriteBuffer(rsp, blob_offset, &buffer);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to write module header for"
                    "<Subgraph(0x%x), Instance(0x%x), Parameter(0x%x)>",
                    status, info->subgraph_id, module_header.module_iid,
                    module_header.parameter_id);
                return status;
            }

            if (is_offloaded_param)
            {
                *blob_offset = tmp_blob_offset;
                continue;
            }

            //Write Payload
            if (rsp->buf_size < (*blob_offset + module_header.param_size))
                return AR_ENEEDMORE;

            if (module_header.param_size > 0)
            {
                buffer.buf = caldata.payload;
                buffer.buf_size = caldata.size;

                status = AcdbWriteBuffer(rsp, blob_offset, &buffer);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Unable to write param(0x%x) data",
                        status, module_header.parameter_id);
                    return status;
                }
            }

            *blob_offset += ACDB_PADDING_8_BYTE(caldata.size);

            break;
        default:
            break;
        }

    }

    if (info->is_default_module_ckv && !info->ignore_get_default_data)
    {
        ACDB_FREE(info->default_data_iid_list.list);
        info->default_data_iid_list.list = NULL;
    }
    else if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        /* Copy the IID Ref Count list from GLB_BUF_1 since it will be
        * cleared outside of this call */
        info->default_data_iid_list.count = num_iid_found;

        //List of AcdbIidRefCount
        info->default_data_iid_list.list = (uint32_t*)
            ACDB_MALLOC(AcdbIidRefCount, num_iid_found);

        if (IsNull(info->default_data_iid_list.list))
        {
            ACDB_ERR("Error[%d]: Unable to allocate memory "
                "for instance id reference list", AR_ENOMEMORY);
            return AR_ENOMEMORY;
        }

        ACDB_MEM_CPY_SAFE(info->default_data_iid_list.list,
            num_iid_found * sizeof(AcdbIidRefCount),
            &glb_buf_1[0], num_iid_found * sizeof(AcdbIidRefCount));

        iid_ref = NULL;
    }


    return status;
}

int32_t AcdbGetCalDataForSubgraph(AcdbAudioCalContextInfo* info,
    uint32_t* blob_offset, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t ckv_list_offset = 0;
    uint32_t default_ckv_entry_offset = 0;
    bool_t found_param_data = 0;
    AcdbSgCalLutHeader sg_cal_lut_header = { 0 };
    AcdbCalKeyTblEntry ckv_entry = { 0 };

    if (IsNull(info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " req or rsp");
        return AR_EBADPARAM;
    }

    sg_cal_lut_header.subgraph_id = info->subgraph_id;
    status = SearchSubgraphCalLut2(&sg_cal_lut_header, &ckv_list_offset);
    if (AR_FAILED(status))
    {
        return status;
    }

    if (sg_cal_lut_header.num_ckv_entries == 0)
    {
        ACDB_ERR("Error[%d]: Subgraph(0x%x) has no CKV entries in"
            " the Subgraph Cal LUT. At least one entry should be"
            " present.",
            AR_ENOTEXIST, info->subgraph_id);
        return AR_ENOTEXIST;
    }

    info->ignore_get_default_data =
        sg_cal_lut_header.num_ckv_entries == 1 ? FALSE : TRUE;

    //The default CKV will be skipped and handeled last
    if (sg_cal_lut_header.num_ckv_entries > 1 && info->is_first_time)
        sg_cal_lut_header.num_ckv_entries++;

    default_ckv_entry_offset = ckv_list_offset;

    for (uint32_t k = 0; k < sg_cal_lut_header.num_ckv_entries; k++)
    {
        /* The Default CKV is always the first CKV in the list of CKVs to
        * search. It will be skipped and processed last */
        if ((k == sg_cal_lut_header.num_ckv_entries - 1) &&
            info->ignore_get_default_data == TRUE && info->is_first_time)
        {
            info->ignore_get_default_data = FALSE;

            status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                &default_ckv_entry_offset);
        }
        else
        {
            status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                &ckv_list_offset);
        }

        if (AR_FAILED(status))
        {
            return status;
        }

        status = AcdbFindModuleCKV(&ckv_entry, info);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            continue;
        }
        else if (AR_FAILED(status))
        {
            return status;
        }

        if (info->parameter_list->count == 0)
        {
            //Get data for an entire module
            status = AcdbGetSubgraphCalibration(info, blob_offset, rsp);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                continue;
            }
            else if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: An error occured while getting cal "
                    "data for <subgraph, module instance>[0x%x, 0x%x]",
                    status, info->subgraph_id, info->instance_id);
                return status;
            }
        }
        else
        {
            //Get Data for a list of parameters
            status = CalDataGetParameterData(info, blob_offset, rsp);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                continue;
            }
            else if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: An error occured while getting cal "
                    "data for <subgraph, module instance>[0x%x, 0x%x]",
                    status, info->subgraph_id, info->instance_id);
                return status;
            }
        }

        found_param_data = TRUE;
    }

    if (found_param_data)
    {
        status = AR_EOK;
    }

    if (status == AR_ENOTEXIST
        && !found_param_data)
    {
        ACDB_ERR("Error[%d]: No data found for "
            "<subgraph, module instance>[0x%x, 0x%x].", status,
            info->subgraph_id, info->instance_id);
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured while getting cal data for "
            "<subgraph, module instance>[0x%x, 0x%x].", status,
            info->subgraph_id, info->instance_id);
    }

    return status;
}

int32_t AcdbFindVoiceCalKeyValues(
    AcdbVcpmChunkInfo *ci_vcpm, AcdbUintList *ckv_values,
    AcdbVcpmCalDataObj *cal_data_obj, uint32_t *table_offset)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = *table_offset;
    uint32_t offset = 0;
    AcdbUintList values_list = { 0 };

    if (IsNull(ckv_values) || IsNull(cal_data_obj)
        || IsNull(table_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = FileManReadBuffer(cal_data_obj,
        sizeof(AcdbVcpmCalDataObj), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Cal "
            "Data Object Header.", status);
        return status;
    }

    offset = ci_vcpm->vcpm_cal_lut.chunk_offset
        + cal_data_obj->offset_vcpm_ckv_lut;
    status = FileManReadBuffer(&values_list.count, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice keys.", status);
        return status;
    }

    if (values_list.count != ckv_values->count)
    {
        //Go to Next Cal Data Obj
        *table_offset = file_offset
            + (cal_data_obj->num_data_offsets * sizeof(uint32_t));
        return AR_ENOTEXIST;
    }

    if (values_list.count != 0)
    {
        offset += sizeof(uint32_t);//num_entries is always 1
        status = FileManGetFilePointer1(
            (void*)&values_list.list, values_list.count * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to Voice Key IDs.", status);
            return status;
        }

        if (0 != ACDB_MEM_CMP(values_list.list, ckv_values->list,
            values_list.count * sizeof(uint32_t)))
        {
            //Go to Next Cal Data Obj
            *table_offset = file_offset
                + (cal_data_obj->num_data_offsets * sizeof(uint32_t));
            return AR_ENOTEXIST;
        }
    }

    *table_offset = file_offset;

    return status;
}

int32_t AcdbFindVoiceModuleCKV(
    AcdbAudioCalContextInfo* info, AcdbVcpmChunkInfo* ci_vcpm,
    AcdbVcpmCkvDataTable* cal_data_table, uint32_t* cal_data_table_offset,
    AcdbVcpmCalDataObj *cal_data_obj, uint32_t* cal_data_obj_offset)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = *cal_data_table_offset;
    uint32_t offset = 0;
    AcdbGraphKeyVector module_ckv = { 0 };
    AcdbUintList ckv_values = { 0 };

    if (IsNull(info) || IsNull(cal_data_table) ||
        IsNull(cal_data_table_offset) || IsNull(cal_data_obj_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = FileManReadBuffer(cal_data_table,
        sizeof(AcdbVcpmCkvDataTable), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read CKV "
            "Data Table Header.", status);
        return status;
    }

    //Set offset to point to the next ckv data table
    *cal_data_table_offset = file_offset + cal_data_table->table_size
        - sizeof(AcdbVcpmCkvDataTable)
        + sizeof(cal_data_table->table_size);

    //Set offset to first cal data object in the current CKV table
    *cal_data_obj_offset = file_offset;

    offset = ci_vcpm->vcpm_cal_key_table.chunk_offset +
        cal_data_table->offset_voice_key_table;
    status = FileManReadBuffer(&module_ckv.num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice keys.", status);
        return status;
    }

    /*
     * GLB_BUF_1:
     *   1. Used to store the key ids
     *   2. Also stores the CKV LUT used in the partition binary search
     * GLB_BUF_3:
     *   1. The first portion of the buffer stores the Module CKV
     *   2. The other portion stores one CKV LUT entry found
     *      during the partition binary search
     */
    if (module_ckv.num_keys > 0)
    {
        status = FileManReadBuffer(&glb_buf_1,
            module_ckv.num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to Voice Key IDs.", status);
            return status;
        }
    }

    module_ckv.graph_key_vector =
        (AcdbKeyValuePair*)&glb_buf_3[0];
    for (uint32_t i = 0; i < module_ckv.num_keys; i++)
    {
        module_ckv.graph_key_vector[i].key = glb_buf_1[i];
    }

    ckv_values.count = 0;
    ckv_values.list = &glb_buf_1[0];

    /* Check if the Module CKV exist within the usecase
     * CKV. Otherwise skip this ckv table */
    uint32_t num_keys_found = 0;
    for (uint32_t k = 0; k < module_ckv.num_keys; k++)
    {
        for (uint32_t l = 0; l < info->ckv->num_keys; l++)
        {
            if (module_ckv.graph_key_vector[k].key ==
                info->ckv->graph_key_vector[l].key)
            {
                ckv_values.list[num_keys_found++] =
                    info->ckv->graph_key_vector[l].value;
                module_ckv.graph_key_vector[k].value =
                    info->ckv->graph_key_vector[l].value;
                break;
            }
        }
    }

    if (info->ckv->num_keys == 0 && module_ckv.num_keys != 0)
        return AR_ENOTEXIST;
    if ((num_keys_found != module_ckv.num_keys))
        return AR_ENOTEXIST;

    ckv_values.count = num_keys_found;

    //check for cal dot table to see if values exist
    for (uint32_t i = 0; i < cal_data_table->num_caldata_obj; i++)
    {
        status = AcdbFindVoiceCalKeyValues(
            ci_vcpm, &ckv_values, cal_data_obj, &file_offset);

        if (AR_FAILED(status) && status != AR_ENOTEXIST)
            return status;
        else if (AR_SUCCEEDED(status)) break;
    }

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to find matching key vector.", status);
        return status;
    }

    info->module_ckv->num_keys = module_ckv.num_keys;

    if (info->module_ckv->num_keys > 0)
        ACDB_MEM_CPY_SAFE(info->module_ckv->graph_key_vector,
            module_ckv.num_keys * sizeof(AcdbKeyValuePair),
            module_ckv.graph_key_vector,
            module_ckv.num_keys * sizeof(AcdbKeyValuePair));


    /* Hypervisor
     * If we encounter the Default CKV
     * Indiciate that the default CKV has been found
     * Store the LUT Entry Offsets(DEF DOT, DOT2) separately for the default CKV
     * Skip getting data for the default CKV if the next CKV is what we are
     * looking for and it contains one of the IIDs that are also associated
     * with the default CKV,
     */

    if (module_ckv.num_keys == 0)
    {
        info->is_default_module_ckv = TRUE;
        //info->ignore_get_default_data = TRUE;

        /* Read IIDs into a tracking list. For non-default CKVs, if a module
         * is found remove it from the default CKV IID list*/
    }
    else
    {
        info->is_default_module_ckv = FALSE;
        info->ignore_get_default_data = TRUE;
    }

    return status;
}

/**
* \brief
*		Get calibration for parameters in a voice subgraph. There are
*       two modes:
*       1. Get all parameters under info->instance_id (module instance)
*           info->parameter_list->count == 0
*       2. Get specfic parameters under info->instance_id (module instance)
*           info->parameter_list->count > 0
*
* \param[in/out] info: Contains the module instance ID and the parameter list
*                      which is used for filtering out module instances
*                      parameters
* \param[in/out] ci_vcpm: The chunk information for voice calibration
* \param[in/out] ci_data_pool: The chunk information for the global datapool
* \param[in/out] cal_data_obj: The header of a cal data object table
* \param[in/out] cal_data_obj_offset: Offset to the voice cal data object
*                                     table in the *.acdb file
* \param[in/out] blob_offset: The current offset in the response blob
* \param[in/out] rsp: The calibration response structure
*
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbGetVoiceParameterCalData(
    AcdbAudioCalContextInfo* info,
    AcdbVcpmChunkInfo* ci_vcpm, ChunkInfo* ci_data_pool,
    AcdbVcpmCalDataObj *cal_data_obj, uint32_t cal_data_obj_offset,
    uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = 0;
    uint32_t tmp_blob_offset = 0;
    uint32_t id_pair_table_size = 0;
    uint32_t curr_cal_data_obj_table_offset = 0;
    uint32_t curr_cal_def_table_offset = 0;
    uint32_t data_pool_offset = 0;
    uint32_t data_pool_offset_index = 0;
    uint32_t num_params = 0;
    bool_t should_get_all_params = FALSE;
    bool_t is_offloaded_param = FALSE;
    AcdbMiidPidPair id_pair = { 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };
    AcdbDspModuleHeader module_header = { 0 };
    AcdbPayload caldata = { 0 };

    /* Binary Search through <IID PID> to find index of <IID PID>. Use the
     * index to calculate the Cal Data Object data pool offset to get to the
     * data pool offset */
    id_pair_table_size =
        cal_data_obj->num_data_offsets * sizeof(AcdbMiidPidPair);

    //Setup Table Information
    table_info.table_offset = ci_vcpm->vcpm_cal_def.chunk_offset +
        cal_data_obj->offset_cal_def + sizeof(uint32_t);//Skip num id pairs
    table_info.table_size = id_pair_table_size;
    table_info.table_entry_size = sizeof(AcdbMiidPidPair);

    //Setup Search Information
    search_info.num_search_keys = 2;//IID, PID
    search_info.num_structure_elements =
        (sizeof(AcdbMiidPidPair) / sizeof(uint32_t));
    search_info.table_entry_struct = &id_pair;

    if (info->parameter_list->count == 0)
    {
        should_get_all_params = TRUE;
        num_params = cal_data_obj->num_data_offsets;
        curr_cal_def_table_offset = table_info.table_offset;

        //Search for the first occurance of the module instance
        search_info.num_search_keys = 1;//IID
        id_pair.module_iid = info->instance_id;

        status = AcdbTableBinarySearch(&table_info, &search_info);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Unable to find first occurance of Module"
                " Instance ID(0x%x) . Skipping..",
                id_pair.module_iid, id_pair.parameter_id);
            return status;
        }

        data_pool_offset_index = search_info.entry_index;
        curr_cal_def_table_offset +=
            data_pool_offset_index * sizeof(AcdbMiidPidPair);
        curr_cal_data_obj_table_offset =
            cal_data_obj_offset + sizeof(AcdbVcpmCalDataObj) +
            data_pool_offset_index * sizeof(uint32_t);
    }
    else
    {
        num_params = info->parameter_list->count;
    }

    for (uint32_t i = 0; i < num_params; i++)
    {
        file_offset = cal_data_obj_offset + sizeof(AcdbVcpmCalDataObj);
        //id_pair.module_iid = info->instance_id;
        //id_pair.parameter_id = info->parameter_list->list[i];
        //module_header.module_iid = id_pair.module_iid;
        //module_header.parameter_id = id_pair.parameter_id;

        if (should_get_all_params)
        {
            //read iid pid from cal def table
            status = FileManReadBuffer(&id_pair, sizeof(AcdbMiidPidPair),
                &curr_cal_def_table_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read <instance id, parameter id> "
                    "pair in cal def table.", status);
                return status;
            }

            if (id_pair.module_iid != info->instance_id)
            {
                //curr_cal_data_obj_table_offset += sizeof(data_pool_offset);
                break;
            }
        }
        else
        {
            id_pair.module_iid = info->instance_id;
            id_pair.parameter_id = info->parameter_list->list[i];
        }

        module_header.module_iid = id_pair.module_iid;
        module_header.parameter_id = id_pair.parameter_id;


        /* Get data from heap */
        status = GetSubgraphCalData(
            info->param_type, ACDB_DATA_ACDB_CLIENT,
            info->module_ckv, info->subgraph_id, module_header.module_iid,
            module_header.parameter_id, is_offloaded_param,
            blob_offset, rsp);
        if (AR_SUCCEEDED(status))
        {
            if (should_get_all_params)
                curr_cal_data_obj_table_offset += sizeof(data_pool_offset);
            continue;
        }

        /* Get data from *.acdb file */
        if (should_get_all_params)
        {
            file_offset = curr_cal_data_obj_table_offset;
            curr_cal_data_obj_table_offset += sizeof(data_pool_offset);
        }
        else
        {
            status = AcdbTableBinarySearch(&table_info, &search_info);
            if (AR_FAILED(status))
            {
                ACDB_DBG("Failed to find Module Instance ID(0x%x) "
                    "Parameter ID(0x%x). Skipping..",
                    id_pair.module_iid, id_pair.parameter_id);
                continue;
            }

            data_pool_offset_index = search_info.entry_index;
            file_offset += data_pool_offset_index * sizeof(uint32_t);
        }

        status = FileManReadBuffer(&data_pool_offset,
            sizeof(uint32_t), &file_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read global data pool"
                " offset in cal data object table.", status);
            return status;
        }

        file_offset = ci_data_pool->chunk_offset + data_pool_offset;
        status = FileManReadBuffer(&module_header.param_size,
            sizeof(uint32_t), &file_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read parameter size.", status);
            return status;
        }

        caldata.size = module_header.param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, file_offset);

        status = IsOffloadedParam(module_header.parameter_id,
            &info->offloaded_parameter_list);

        is_offloaded_param = AR_SUCCEEDED(status) ? TRUE : FALSE;

        if (is_offloaded_param)
        {
            status = AcdbGetOffloadedParameterCal(
                info->op, info->subgraph_id, &module_header,
                &caldata, rsp, blob_offset, &tmp_blob_offset);
            if (AR_FAILED(status))
                return status;
        }

        switch (info->op)
        {
        case ACDB_OP_GET_SIZE:
            rsp->buf_size += sizeof(AcdbDspModuleHeader)
                + ACDB_ALIGN_8_BYTE(module_header.param_size);
            break;
        case ACDB_OP_GET_DATA:
            //Write spf module param header
            ACDB_MEM_CPY_SAFE(
                (uint8_t*)rsp->buf + *blob_offset, sizeof(AcdbDspModuleHeader),
                &module_header, sizeof(AcdbDspModuleHeader));
            *blob_offset += sizeof(AcdbDspModuleHeader);

            if (is_offloaded_param)
            {
                *blob_offset = tmp_blob_offset;
                continue;
            }

            if (module_header.param_size != 0)
            {
                status = FileManReadBuffer((uint8_t*)rsp->buf + *blob_offset,
                    module_header.param_size, &file_offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Failed to read parameter payload.",
                        status);
                    return status;
                }
                *blob_offset += ACDB_ALIGN_8_BYTE(module_header.param_size);
            }
            break;
        default:
            break;
        }
    }

    return status;
}

int32_t AcdbGetVoiceSubgraph(
    uint32_t subgraph_id, ChunkInfo *vcpm_sg_cal,
    AcdbVcpmSubgraphCalTable *vcpm_sg_cal_table,
    uint32_t *vcpm_sg_cal_table_offset)
{
    int32_t status = AR_EOK;
    AcdbVcpmSubgraphCalHeader vcpm_cal_header = { 0 };

    *vcpm_sg_cal_table_offset = vcpm_sg_cal->chunk_offset;
    status = FileManReadBuffer(&vcpm_cal_header,
        sizeof(AcdbVcpmSubgraphCalHeader), vcpm_sg_cal_table_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read VCPM module header.", status);
        return status;
    }

    //Search for the matching VCPM Subgraph Cal Data Table
    status = GetVcpmSubgraphCalTable(vcpm_cal_header.num_subgraphs,
        subgraph_id, vcpm_sg_cal_table_offset, vcpm_sg_cal_table);
    if (AR_FAILED(status))
    {
        return status;
    }

    return status;
}


int32_t AcdbGetVoiceCalDataForSubgraph(
    AcdbVcpmChunkInfo *ci_vcpm, ChunkInfo *ci_data_pool,
    AcdbAudioCalContextInfo *info,
    AcdbVcpmSubgraphCalTable *vcpm_sg_cal_table,
    uint32_t vcpm_sg_cal_table_offset,
    uint32_t* blob_offset, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    AcdbVcpmCkvDataTable cal_data_table = { 0 };
    AcdbVcpmCalDataObj cal_data_obj = { 0 };
    uint32_t file_offset = vcpm_sg_cal_table_offset;
    uint32_t cal_data_obj_offset = vcpm_sg_cal_table_offset;
    uint32_t current_rsp_size = 0;
    uint32_t retrieved_cal_rsp_size = 0;

    current_rsp_size = rsp->buf_size;
    //skip default and save for last if no other configuration is found

    //Search for matching key vector then find iid,pid and get voice cal data
    for (uint32_t i = 0; i < vcpm_sg_cal_table->num_ckv_data_table; i++)
    {
        status = AcdbFindVoiceModuleCKV(info, ci_vcpm,
            &cal_data_table, &file_offset,
            &cal_data_obj, &cal_data_obj_offset);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
            continue;
        else if(AR_FAILED(status))
        {
            return status;
        }

        //get calibration for list of parameters
        status = AcdbGetVoiceParameterCalData(
            info, ci_vcpm, ci_data_pool,
            &cal_data_obj, cal_data_obj_offset,
            blob_offset, rsp);

        retrieved_cal_rsp_size = rsp->buf_size - current_rsp_size;

        if (AR_ENOTEXIST == status /*&& 0 == retrieved_cal_rsp_size*/)
        {
            status = AR_EOK;
            continue;
        }
        if (AR_FAILED(status))
        {
            return status;
        }
    }

    return status;
}

int32_t AcdbCmdGetCalData(AcdbGetCalDataReq* req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    uint32_t vcpm_sg_cal_table_offset = 0;
    AcdbAudioCalContextInfo info;
    AcdbGetGraphRsp graph = { 0 };
    AcdbSubgraph *subgraph = NULL;
    ChunkInfo ci_data_pool = { 0 };
    bool_t found_subgraph = false;
    bool_t has_voice_data = FALSE;
    AcdbVcpmChunkInfo ci_vcpm = { 0 };
    AcdbVcpmSubgraphCalTable vcpm_sg_cal_table = { 0 };
    AcdbModuleParamList* instance_param_list = NULL;

    (void)ar_mem_set(&info, 0, sizeof(AcdbAudioCalContextInfo));

    if (req->graph_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: No data exist for the empty GKV",
            AR_ENOTEXIST);
        return AR_ENOTEXIST;
    }
    else
    {
        ACDB_DBG("Retrieving calibration data for the following graph key vector:");
        LogKeyVector(&req->graph_key_vector, GRAPH_KEY_VECTOR);
    }

    status = AcdbGetUsecaseSubgraphList(
        &req->graph_key_vector, NULL, &graph);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get usecase subgraphs"
            " for the given graph key vector.",
            status);
        goto end;
    }

    /* CKV Setup
    * 1. GLB_BUF_2 stores the module CKV that will be used to locate data in
    * the heap(if it exists)
    * 2. The Delta CKV and CKV[New] are allocated on the heap by
    * AcdbComputeDeltaCKV
    *
    * tmp - stores the amount of padding after graph_key_vectornum_keys
    * tmp2 - stores the position of the KeyValuePair list
    *
    * The first info.module_ckv->graph_key_vector assignment has the effect
    * of storing the address of the pointer in glb_buf_2 after
    * graph_key_vector.num_keys
    *
    * The second info.module_ckv->graph_key_vector assignment has the effect
    * of pointer the info.module_ckv->graph_key_vector to the actual list
    * of key value pairs
    *
    * Whats inside global buffer 2 after these operations?
    *
    * The first 'sizeof(AcdbGraphKeyVector)' bytes is AcdbGraphKeyVector
    * followed by 'sizeof(AcdbKeyValuePair) * num_keys' bytes which is
    * the KV list
    */
    info.module_ckv = (AcdbGraphKeyVector*)&glb_buf_2[0];
    uint32_t tmp = (sizeof(AcdbGraphKeyVector) - sizeof(AcdbKeyValuePair*)) / sizeof(uint32_t);
    uint32_t tmp2 = sizeof(AcdbGraphKeyVector) / sizeof(uint32_t);
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp];
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp2];

    /* This flag must be set to true since delta CKVs are
    * not applicable here */
    info.is_first_time = TRUE;
    info.op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    info.data_op = ACDB_OP_GET_MODULE_DATA;
    info.param_type = ACDB_DATA_DONT_CARE;
    info.ckv = &req->cal_key_vector;
    instance_param_list = req->instance_param_list;

    /* Check if voice data exists */
    ci_vcpm.vcpm_sg_cal.chunk_id = ACDB_CHUNKID_VCPM_CAL_DATA;
    ci_vcpm.vcmp_master_key_table.chunk_id = ACDB_CHUNKID_VCPM_MASTER_KEY;
    ci_vcpm.vcpm_cal_key_table.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;
    ci_vcpm.vcpm_cal_lut.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_LUT;
    ci_vcpm.vcpm_cal_def.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_DEF;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(
        &ci_vcpm.vcpm_sg_cal, &ci_vcpm.vcpm_cal_key_table,
        &ci_vcpm.vcpm_cal_lut, &ci_vcpm.vcpm_cal_def,
        &ci_data_pool);
    if (AR_SUCCEEDED(status))
    {
        //voice calibration exists
        has_voice_data = TRUE;
    }

    GetOffloadedParamList(&info.offloaded_parameter_list);
    if (info.offloaded_parameter_list.count == 0)
    {
        if (info.op == ACDB_OP_GET_SIZE)
            ACDB_DBG("Error[%d]: No offloaded parameters found. Skipping..",
                status);
    }

    for (uint32_t i = 0; i < req->num_module_instance; i++)
    {
        subgraph = graph.subgraphs;
        if (IsNull(subgraph))
        {
            ACDB_ERR("Error[%d]: The subgraph list is null",
                status);
            break;
        }
        info.instance_id = instance_param_list->instance_id;
        info.subgraph_id = subgraph->sg_id;
        info.parameter_list = &instance_param_list->parameter_list;

        for (uint32_t j = 0; j < graph.num_subgraphs; j++)
        {
            info.subgraph_id = subgraph->sg_id;

            if (j != graph.num_subgraphs - 1)
                subgraph = (AcdbSubgraph*)((uint8_t*)subgraph + sizeof(AcdbSubgraph)
                + subgraph->num_dst_sgids * sizeof(uint32_t));

            found_subgraph = DoesSubgraphContainModule(info.subgraph_id,
                instance_param_list->instance_id, &status);

            if (found_subgraph)
                break;
        }

        if (i != req->num_module_instance - 1)
            instance_param_list = (AcdbModuleParamList*)((uint8_t*)instance_param_list
                + sizeof(AcdbModuleParamList)
                + instance_param_list->parameter_list.count * sizeof(uint32_t));

        if (!found_subgraph)
        {
            ACDB_ERR("Error[%d]: Module instance 0x%x not found in usecase"
               , status,
                info.instance_id);
            continue;
        }

        bool_t is_audio_sg = TRUE;
        if (has_voice_data)
        {
            status = AcdbGetVoiceSubgraph(
                info.subgraph_id, &ci_vcpm.vcpm_sg_cal,
                &vcpm_sg_cal_table, &vcpm_sg_cal_table_offset);
            if (AR_SUCCEEDED(status))
                is_audio_sg = FALSE;
        }

        if (!is_audio_sg)
        {
            status = AcdbGetVoiceCalDataForSubgraph(
                &ci_vcpm, &ci_data_pool, &info,
                &vcpm_sg_cal_table, vcpm_sg_cal_table_offset,
                &blob_offset, rsp);
            if (status == AR_ENOTEXIST)
            {
                ACDB_DBG("Error[%d]: Voice subgraph 0x%x does not exist. "
                    "Skipping..", status);
                status = AR_EOK;
            }
            else if (AR_FAILED(status))
            {
                break;
            }
            continue;
        }

        status = AcdbGetCalDataForSubgraph(
            &info, &blob_offset, rsp);
        switch (status)
        {
        case AR_EOK:
            continue;
        case AR_ENOTEXIST:
            status = AR_EOK;
            if (!has_voice_data)
            {
                /* This subgraph does not exist if it wasnt found under
                    * audio and there is no voice calibration data */
                ACDB_DBG("Error[%d]: Subgraph 0x%x does not exist. "
                    "Skipping..", AR_ENOTEXIST);
                continue;
            }
            break;
        default:
            //ACDB_ERR("Error[%d]: Unable to get calibration from subgraph");
            break;
        }
    }

    if (rsp->buf_size == 0)
        status = AR_ENOTEXIST;

end:
    //Clean Up Context Info
    info.ckv = NULL;
    AcdbClearAudioCalContextInfo(&info);
    return status;
}

/**
* \brief
*       Search for a <Subgraph ID, Tag ID> pair and return the definition
*       table offset in the lut_entry parameter
*
* \param[in/out] ci_lut: chunk information for ACDB_CHUNKID_TAGGED_MODULE_LUT.
* \param[in/out] lut_entry: Contains the <Subgraph ID, Tag ID, Def Offset>.
*                           The Def Offset will be populated by the search
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t SearchTaggedModuleMapLut(ChunkInfo *ci_lut, SubgraphTagLutEntry *lut_entry)
{
    int32_t status = AR_EOK;
    //uint32_t offset = 0;

    //Lookup Table
    //Binary Search based on <Subgraph ID, Tag ID>
    uint32_t search_index_count = 2;
    uint32_t lut_size = 0;
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    if (IsNull(ci_lut) || IsNull(lut_entry))
    {
        ACDB_ERR("Error[%d]: Invalid input parameter",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    lut_size = ci_lut->chunk_size - sizeof(uint32_t);

    //Setup Table Information
    table_info.table_offset = ci_lut->chunk_offset + sizeof(uint32_t);
    table_info.table_size = lut_size;
    table_info.table_entry_size = sizeof(SubgraphTagLutEntry);

    //Setup Search Information
    search_info.num_search_keys = search_index_count;
    search_info.num_structure_elements =
        (sizeof(SubgraphTagLutEntry) / sizeof(uint32_t));
    search_info.table_entry_struct = lut_entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        //ACDB_DBG("Error[%d]: Failed to find Subgraph ID(0x%x) Tag ID(0x%x)",
        //    status, lut_entry->sg_id, lut_entry->tag_id);
        return status;
    }

    ACDB_CLEAR_BUFFER(glb_buf_1);

    return status;
}

/**
* \brief
*       Builds the tagged module list response. The size of the list is
*       accumulated on the first call. The data is filled once the
*       response buffer is allocated.
*
* \param[in/out] ci_def: chunk information for ACDB_CHUNKID_TAGGED_MODULE_DEF.
* \param[in/out] def_offset_list: list of def offsets definition tables that
*                                 contain <ModuleID, InstanceID>'s
* \param[in/out] rsp: the response structure to populate
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t BuildTaggedModulePayload(ChunkInfo *ci_def, AcdbUintList *def_offset_list, AcdbGetTaggedModulesRsp *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_modules = 0;
    uint32_t total_num_module_inst = 0;
    uint32_t sz_module_instances = 0;
    uint32_t expected_size = 0;
    uint32_t actual_size = 0;
    uint32_t mid_list_offset = 0;
    AcdbOp op = IsNull(rsp->tagged_mid_list) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (IsNull(ci_def) || IsNull(def_offset_list) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: Invalid input parameter",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    expected_size = rsp->num_tagged_mids * sizeof(AcdbModuleInstance);
    rsp->num_tagged_mids = 0;

    for (uint32_t i = 0; i < def_offset_list->count; i++)
    {
        offset = ci_def->chunk_offset;
        offset += def_offset_list->list[i];
        status = FileManReadBuffer(&num_modules, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Error[%d]: Unable to read number of module instances "
                "from definition table", status);
            return status;
        }

        if (num_modules == 0) continue;

        if (op == ACDB_OP_GET_SIZE)
        {
            total_num_module_inst += num_modules;
        }
        else
        {
            total_num_module_inst += num_modules;
            sz_module_instances = num_modules * sizeof(AcdbModuleInstance);
            actual_size += sz_module_instances;

            if (actual_size > expected_size)
            {
                ACDB_DBG("Error[%d]: Buffer not large enough to store "
                    "response. Expected Size: %d bytes. Actual Size: %d bytes",
                    AR_ENEEDMORE, expected_size, actual_size);
                return AR_ENEEDMORE;
            }

            status = FileManReadBuffer(
                (uint8_t*)rsp->tagged_mid_list + mid_list_offset,
                sz_module_instances, &offset);
            if (AR_FAILED(status))
            {
                ACDB_DBG("Error[%d]: Unable to read number of module instances"
                    " from definition table", status);
                return status;
            }

            mid_list_offset += sz_module_instances;
        }
    }

    rsp->num_tagged_mids = total_num_module_inst;

    if (rsp->num_tagged_mids == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: No data found", status);
    }

    return status;
}

int32_t AcdbCmdGetTaggedModules(AcdbGetTaggedModulesReq* req, AcdbGetTaggedModulesRsp* rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_lut = { 0 };
    ChunkInfo ci_def = { 0 };
    SubgraphTagLutEntry lut_entry = { 0 };

    uint32_t def_offset_list_length = GLB_BUF_2_LENGTH;
    AcdbUintList def_offset_list = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (req == NULL || rsp_size < sizeof(AcdbGetTaggedModulesRsp))
    {
        ACDB_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->num_sg_ids == 0 || IsNull(req->sg_ids))
    {
        ACDB_ERR("Error[%d]: The subgraph list cannot be empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    ci_lut.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_LUT;
    ci_def.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_DEF;
    status = ACDB_GET_CHUNK_INFO(&ci_lut, &ci_def);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Tagged Module "
            "lookup/definition tables.", status);
        return status;
    }

    def_offset_list.list = &glb_buf_2[0];

    lut_entry.tag_id = req->tag_id;

    for (uint32_t i = 0; i < req->num_sg_ids; i++)
    {
        lut_entry.sg_id = req->sg_ids[i];

        status = SearchTaggedModuleMapLut(&ci_lut, &lut_entry);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            //ACDB_DBG("Error[%d]: Subgraph(0x%x) does not contain Tag(0x%x). "
            //    "Skipping..", status, lut_entry.tag_id, lut_entry.sg_id);
            continue;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Error occured while looking for "
                "Tag(0x%x) under Subgraph(0x%x)", status,
                lut_entry.tag_id, lut_entry.sg_id);
            return status;
        }

        //Add to def offset list
        if (def_offset_list.count > def_offset_list_length)
        {
            /* This will only occur if there are 1000 subgraphs passed in to
             * this API that contain the tag that we are looking for. glb_buf_2
             * can store up to 1000 def offsets */
            ACDB_ERR("Error[%d]: Not enough space to store "
                "additional def offset", status);
            return AR_ENOMEMORY;
        }

        def_offset_list.list[def_offset_list.count] = lut_entry.offset;
        def_offset_list.count++;
    }

    if (def_offset_list.count == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Tag(0x%x) not found in subgraphs provided.",
            status, lut_entry.tag_id);
        return status;
    }

    //Build Instance ID List
    status = BuildTaggedModulePayload(&ci_def, &def_offset_list, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to build tagged module list response.", status);
    }

    return status;
}

/**
* \brief
*       Builds the tagged module list response. The size of the list is
*       accumulated on the first call. The data is filled once the
*       response buffer is allocated.
*
* \param[in/out] ci_def: chunk information for ACDB_CHUNKID_TAGGED_MODULE_DEF.
* \param[in/out] def_offset_list: list of def offsets definition tables that
*                                 contain <ModuleID, InstanceID>'s
* \param[in/out] rsp: the response structure to populate
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t BuildProcTaggedModulePayload(ChunkInfo* ci_def, AcdbUintList* subgraph_list, AcdbUintList* def_offset_list, AcdbGetProcTaggedModulesRsp* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_modules = 0;
    uint32_t total_num_module_inst = 0;
    uint32_t expected_size = 0;
    uint32_t actual_size = 0;
    uint32_t blob_offset = 0;
    /* Stores processor domain id and blob offset pairs.The offset is for 
     * a AcdbProcTaggedModules entry within the 
     * AcdbGetProcTaggedModulesRsp::proc_tagged_module_list */
    AcdbGenericList proc_domain_id_list = { 0 };
    AcdbProcDomainOffsetPair proc_domain_offset_pair = { 0 };
    AcdbSubgraphPdmMap sg_iid_map = { 0 };
    AcdbBlob proc_tagged_modules_blob = { 0 };
    AcdbOp op = IsNull(rsp->proc_tagged_module_list) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (IsNull(ci_def) || IsNull(def_offset_list) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: Invalid input parameter",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (op == ACDB_OP_GET_DATA && rsp->list_size == 0)
    {
        ACDB_DBG("Error[%d]: Unable to fill response since "
            "AcdbGetProcTaggedModulesRsp::list_size is zero",
            AR_EBADPARAM);
        return AR_EFAILED;
    }

    /* Use glb_buf_3 to store list of unique processors found while iterating 
     * through subgraphs and procs.
     * GLB_BUFFER_3 can hold up to GLB_BUF_3_LENGTH entries. We will never
     * have 500 procs, but we need to add the length check. */
    status = AcdbGenericListInit(&proc_domain_id_list, sizeof(AcdbProcDomainOffsetPair), 
        GLB_BUF_3_LENGTH * sizeof(uint32_t), (void**)&glb_buf_3);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to initialize list", status);
        return status;
    }

    proc_tagged_modules_blob.buf = (uint8_t*)rsp->proc_tagged_module_list;
    proc_tagged_modules_blob.buf_size = 0;

    expected_size = rsp->list_size;

    for (uint32_t i = 0; i < def_offset_list->count; i++)
    {
        ar_mem_set((void*)&sg_iid_map, 0, sizeof(AcdbSubgraphPdmMap));

        status = DataProcGetSubgraphProcIidMap(subgraph_list->list[i], &sg_iid_map);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Error[%d]: Failed to get subgraph-to-proccessor domain module map", status);
            return status;
        }

        offset = ci_def->chunk_offset;
        offset += def_offset_list->list[i];
        status = FileManReadBuffer(&num_modules, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Error[%d]: Unable to read number of module instances "
                "from definition table", status);
            return status;
        }

        if (num_modules == 0) continue;

        //get tagged module list
        AcdbModuleInstance* tagged_modules = NULL;
        status = FileManGetFilePointer2((void**)&tagged_modules, offset);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Error[%d]: Unable to read number of module instances "
                "from definition table", status);
            return status;
        }

        for (uint32_t k = 0; k < num_modules; k++)
        {
            uint32_t proc_domain_id = 0;
            status = DataProcGetProcDomainForModule(
                &sg_iid_map,
                tagged_modules[k].mid_iid, 
                &proc_domain_id);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to get proccessor domain ID for "
                    "sg: 0x%x iid: 0x%x", 
                    status, sg_iid_map.subgraph_id, tagged_modules[k].mid_iid);
                return status;
            }

            /* We only need to keep track of the total number of procs during the 
             * get_size call b/c the rsp should be populated with the total number 
             * of procs in the get_data call */
            //Add unique proc_domain_id entries to list
            bool_t is_new_proc = TRUE;
            AcdbGenericListItem found_proc_domain = { 0 };
            proc_domain_offset_pair.proc_domain_id = proc_domain_id;

            status = proc_domain_id_list.find(
                &proc_domain_id_list, &proc_domain_offset_pair, 
                sizeof(proc_domain_offset_pair), 1, &found_proc_domain);
            if (AR_SUCCEEDED(status))
            {
                is_new_proc = FALSE;

                if (!IsNull(found_proc_domain.item))
                {
                    proc_domain_offset_pair = *(AcdbProcDomainOffsetPair*)found_proc_domain.item;
                }
                else
                {
                    ACDB_ERR("Error[%d]: Unable to get proc offset pair from "
                        "item field after find operation", status);
                    return AR_EFAILED;
                }
            }

            if (is_new_proc && proc_domain_id_list.count < proc_domain_id_list.max_count)
            {
                blob_offset = proc_tagged_modules_blob.buf_size;
                proc_domain_offset_pair.offset = blob_offset;
                proc_domain_id_list.add_range(&proc_domain_id_list, 
                    &proc_domain_offset_pair, sizeof(AcdbProcDomainOffsetPair), 1);
                status = AR_EOK;

                if (proc_domain_id_list.count > 1)
                {
                    proc_domain_id_list.sort(&proc_domain_id_list, 0);
                }
            }
            if (op == ACDB_OP_GET_DATA)
            {
                /* Implement memory shifting logic. We dont want to create additional memory. 
                 * Add the first processor domain id and the modules associated with it
                 * If a new processor domain is discovered add it right after the first processor domains info
                 * If we encounter a module that has the proc domain of the first proc entry make room in the 
                 * memory regoin by shifting the subsequent proc info downward using memmove
                 */
                AcdbProcTaggedModules* proc_taggged_module = NULL;

                /* Add new proc to the end of the proc list */
                if (is_new_proc)
                {
                    actual_size = proc_tagged_modules_blob.buf_size 
                        + sizeof(AcdbProcTaggedModules) + num_modules * sizeof(AcdbModuleInstance);

                    if (actual_size > expected_size)
                    {
                        ACDB_DBG("Error[%d]: Buffer not large enough to store "
                            "response. Expected Size: %d bytes. Actual Size: %d bytes",
                            AR_ENEEDMORE, expected_size, actual_size);
                        return AR_ENEEDMORE;
                    }

                    uint32_t module_count = 1;

                    ACDB_MEM_CPY_SAFE(
                        proc_tagged_modules_blob.buf + blob_offset, sizeof(uint32_t), 
                        &proc_domain_id, sizeof(uint32_t));
                    blob_offset += sizeof(uint32_t);
                    ACDB_MEM_CPY_SAFE(
                        proc_tagged_modules_blob.buf + blob_offset, sizeof(uint32_t), 
                        &module_count, sizeof(uint32_t));
                    blob_offset += sizeof(uint32_t);
                    ACDB_MEM_CPY_SAFE(
                        proc_tagged_modules_blob.buf + blob_offset, sizeof(AcdbModuleInstance),
                        &tagged_modules[k], sizeof(AcdbModuleInstance));
                    blob_offset += sizeof(AcdbModuleInstance);

                    proc_tagged_modules_blob.buf_size += sizeof(AcdbProcTaggedModules) 
                        + module_count * sizeof(AcdbModuleInstance);
                    continue;
                }

                /* Add new module entry to an existing procs module 
                 * list and shift the memory of subsequent procs */
                proc_taggged_module = (AcdbProcTaggedModules*)(
                    (uint8_t*)rsp->proc_tagged_module_list + proc_domain_offset_pair.offset);

                if (proc_taggged_module != NULL)
                {
                    //Proc already exists, but we are adding a new module entry
                    uint32_t blob_module_entry_offset = proc_domain_offset_pair.offset 
                        + sizeof(AcdbProcTaggedModules) 
                        + proc_taggged_module->num_tagged_mids * sizeof(AcdbModuleInstance);
                    proc_taggged_module->num_tagged_mids++;

                    size_t size_of_data_to_move = (size_t)proc_tagged_modules_blob.buf_size 
                        - (size_t)blob_module_entry_offset;

                    actual_size = proc_tagged_modules_blob.buf_size + sizeof(AcdbModuleInstance);
                    if (actual_size > expected_size)
                    {
                        ACDB_DBG("Error[%d]: Buffer not large enough to store "
                            "response. Expected Size: %d bytes. Actual Size: %d bytes",
                            AR_ENEEDMORE, expected_size, actual_size);
                        return AR_ENEEDMORE;
                    }

                    if (0 != size_of_data_to_move)
                    {
                        ar_mem_move(
                            (uint8_t*)proc_tagged_modules_blob.buf 
                            + blob_module_entry_offset + sizeof(AcdbModuleInstance), size_of_data_to_move,
                            (uint8_t*)proc_tagged_modules_blob.buf 
                            + blob_module_entry_offset, size_of_data_to_move);
                    }

                    ACDB_MEM_CPY_SAFE(
                        proc_tagged_modules_blob.buf + blob_module_entry_offset, sizeof(AcdbModuleInstance), 
                        &tagged_modules[k], sizeof(AcdbModuleInstance));
                    proc_tagged_modules_blob.buf_size += sizeof(AcdbModuleInstance);

                    /* We need to update the offsets of our proc domain entries after shifting data */
                    for (uint32_t j = 0; j < proc_domain_id_list.count; j++)
                    {
                        AcdbProcDomainOffsetPair* p = (AcdbProcDomainOffsetPair*)proc_domain_id_list.list + j;
                        if (p->proc_domain_id == proc_domain_offset_pair.proc_domain_id)
                            continue;

                        if (p->offset > proc_domain_offset_pair.offset)
                        {
                            p->offset += sizeof(AcdbModuleInstance);
                        }
                    }
                }
            }
        }

        if (op == ACDB_OP_GET_SIZE)
        {
            total_num_module_inst += num_modules;
        }
    }

    if (op == ACDB_OP_GET_SIZE)
    {
        rsp->num_procs = proc_domain_id_list.count;
        rsp->list_size = rsp->num_procs * sizeof(AcdbProcTaggedModules)
            + total_num_module_inst * sizeof(AcdbModuleInstance);
    }

    if (rsp->num_procs == 0 || rsp->list_size == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: No tagged modules found", status);
    }

    return status;
}

int32_t AcdbCmdGetProcTaggedModules(AcdbGetProcTaggedModulesReq* req, AcdbGetProcTaggedModulesRsp* rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_lut = { 0 };
    ChunkInfo ci_def = { 0 };
    SubgraphTagLutEntry lut_entry = { 0 };
    uint32_t sg_def_offset_list_length = GLB_BUF_2_LENGTH/2;
    AcdbUintList def_offset_list = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (req == NULL || rsp_size < sizeof(AcdbGetProcTaggedModulesRsp))
    {
        ACDB_ERR("Error[%d]: Invalid input parameter(s)", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->num_sg_ids == 0 || IsNull(req->sg_ids))
    {
        ACDB_ERR("Error[%d]: The subgraph list cannot be empty", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    /* Use subgraph list here for setting the database context */
    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    ci_lut.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_LUT;
    ci_def.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_DEF;
    status = ACDB_GET_CHUNK_INFO(&ci_lut, &ci_def);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Tagged Module "
            "lookup/definition tables.", status);
        return status;
    }

    /* Repurpose the subgraph list here for storing subgraphs containing the 
     * tag we are searching for. def_offset_list and subgraph_list have 
     * matching indexes. For example:
     *
     *  subgraph_list.list[i] is associated with def_offset_list.list[i] 
     */
    def_offset_list.list = &glb_buf_2[0];
    subgraph_list.list = &glb_buf_2[sg_def_offset_list_length - 1];
    subgraph_list.count = 0;

    lut_entry.tag_id = req->tag_id;

    for (uint32_t i = 0; i < req->num_sg_ids; i++)
    {
        lut_entry.sg_id = req->sg_ids[i];

        status = SearchTaggedModuleMapLut(&ci_lut, &lut_entry);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            //ACDB_DBG("Error[%d]: Subgraph(0x%x) does not contain Tag(0x%x). "
            //    "Skipping..", status, lut_entry.tag_id, lut_entry.sg_id);
            continue;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Error occured while looking for "
                "Tag(0x%x) under Subgraph(0x%x)", status,
                lut_entry.tag_id, lut_entry.sg_id);
            return status;
        }

        //Add to def offset list
        if (def_offset_list.count > sg_def_offset_list_length ||
            subgraph_list.count > sg_def_offset_list_length)
        {
            /* This will only occur if there are 500 subgraphs passed in to
             * this API that contain the tag that we are looking for. glb_buf_2
             * can store up to 1000 entries: 500 sg ids, 500 def offsets */
            ACDB_ERR("Error[%d]: Not enough space to store "
                "additional def offset", status);
            return AR_ENOMEMORY;
        }

        def_offset_list.list[def_offset_list.count] = lut_entry.offset;
        subgraph_list.list[subgraph_list.count] = lut_entry.sg_id;
        def_offset_list.count++;
        subgraph_list.count++;
    }

    if (def_offset_list.count == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Tag(0x%x) not found in subgraphs provided.",
            status, lut_entry.tag_id);
        return status;
    }

    //Build Instance ID List
    status = BuildProcTaggedModulePayload(&ci_def, &subgraph_list, &def_offset_list, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to build tagged module list response.", status);
    }

    return status;
}

/**
* \brief
*       Search for a <Module ID, Key Table Offset, Value Table Offset>
*       tuple using the Module ID and Key Table Offset as search keys
*
* \param[in/out] cal_lut_entry: GSL Calibration Lookuptable entry in the
*           format of <MID, Key Table Off. Value Table Off.>
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t DriverDataSearchForModuleID(acdb_driver_cal_lut_entry_t *cal_lut_entry)
{
	int32_t status = AR_EOK;
	//uint32_t offset = 0;
	ChunkInfo gsl_cal_lut = { 0 };

	//Lookup Table
    //Binary Search based on MID and Key Table Offset
	uint32_t search_index_count = 2;
    uint32_t sz_gsl_cal_lut = 0;
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    gsl_cal_lut.chunk_id = ACDB_CHUNKID_GSL_CAL_LUT;
	status = ACDB_GET_CHUNK_INFO(&gsl_cal_lut);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Failed to get GSL Calibration Data Chunk", status);
		return status;
	}

    sz_gsl_cal_lut = gsl_cal_lut.chunk_size - sizeof(uint32_t);

    //Setup Table Information
    table_info.table_offset = gsl_cal_lut.chunk_offset + sizeof(uint32_t);
    table_info.table_size = sz_gsl_cal_lut;
    table_info.table_entry_size = sizeof(acdb_driver_cal_lut_entry_t);

    //Setup Search Information
    search_info.num_search_keys = search_index_count;
    search_info.num_structure_elements =
        (sizeof(acdb_driver_cal_lut_entry_t) / sizeof(uint32_t));
    search_info.table_entry_struct = cal_lut_entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to find Module ID(0x%x)", cal_lut_entry->mid);
        return status;
    }

	ACDB_CLEAR_BUFFER(glb_buf_1);

	return status;
}

int32_t DriverDataSearchForKeys(
    AcdbDriverData *req, uint32_t *offset_calkey_table)
{
	int32_t status = AR_EOK;
	uint32_t offset = 0;
    uint32_t num_keys = 0;
	ChunkInfo gsl_cal_key_tbl = { 0 };

    gsl_cal_key_tbl.chunk_id = ACDB_CHUNKID_GSL_CALKEY_TBL;
    status = ACDB_GET_CHUNK_INFO(&gsl_cal_key_tbl);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to get GSL Key Table Chunk", status);
		return status;
	}

    offset = gsl_cal_key_tbl.chunk_offset;

    do
    {
        *offset_calkey_table = offset;
        status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read number of keys", status);
            return status;
        }

        if (num_keys != req->key_vector.num_keys)
        {
            offset += num_keys * sizeof(uint32_t);
            continue;
        }

        if (num_keys > 0)
        {
            status = FileManReadBuffer(
                &glb_buf_1, num_keys * sizeof(uint32_t), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read key vector", status);
                return status;
            }

            if (TRUE == CompareKeyVectorIds(
                req->key_vector, glb_buf_3, glb_buf_1, num_keys))
            {
                *offset_calkey_table -= gsl_cal_key_tbl.chunk_offset;
                return status;
            }
        }
        else
        {
            *offset_calkey_table -= gsl_cal_key_tbl.chunk_offset;
            return status;
        }

    } while (offset <
        gsl_cal_key_tbl.chunk_offset + gsl_cal_key_tbl.chunk_size);

    status = AR_ENOTEXIST;
    ACDB_ERR("Error[%d]: Unable to find matching key vector. "
        "One or more key IDs do not exist.", status);

	ACDB_CLEAR_BUFFER(glb_buf_1);
	ACDB_CLEAR_BUFFER(glb_buf_3);

	return status;
}

int32_t DriverDataSearchCalDataLUT(AcdbDriverData *req, AcdbBlob* rsp,
    uint32_t offset_caldata_table, AcdbDefDotPair *offset_pair)
{
	int32_t status = AR_EOK;
	uint32_t offset = 0;
    uint32_t num_struct_elements = 0;
    uint32_t entry_size = 0;
    uint32_t table_size = 0;
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };
    KeyTableHeader caldata_lut_header = { 0 };
	ChunkInfo gsl_cal_data_tbl = { 0 };

    if (IsNull(req) || IsNull(rsp) || IsNull(offset_pair))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    gsl_cal_data_tbl.chunk_id = ACDB_CHUNKID_GSL_CALDATA_TBL;
    status = ACDB_GET_CHUNK_INFO(&gsl_cal_data_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get GSL "
            "Calibration Data Chunk", status);
        return status;
    }

    offset = gsl_cal_data_tbl.chunk_offset + offset_caldata_table;
    status = FileManReadBuffer(
        &caldata_lut_header, sizeof(KeyTableHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to seek/read GSL "
            "Calibration Data LUT header", status);
        return status;
    }

    //Plus 2 for def and dot offsets
    num_struct_elements = caldata_lut_header.num_keys + 2;
    entry_size = sizeof(uint32_t) * num_struct_elements;
    table_size = caldata_lut_header.num_entries * entry_size;

    //glb_buf_3 stores key vector values to search for
    for (uint32_t i = 0; i < req->key_vector.num_keys; i++)
    {
        glb_buf_3[i] = req->key_vector.graph_key_vector[i].value;
    }

    //Setup Table Information
    table_info.table_offset = offset;
    table_info.table_size = table_size;
    table_info.table_entry_size = entry_size;

    //Setup Search Information
    search_info.num_search_keys = caldata_lut_header.num_keys;
    search_info.num_structure_elements = num_struct_elements;
    search_info.table_entry_struct = &glb_buf_3;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find matching key vector. "
            "One or more key values do not match", status);
        return status;
    }

	ACDB_MEM_CPY_SAFE(offset_pair, sizeof(AcdbDefDotPair),
        &glb_buf_3[0] + (caldata_lut_header.num_keys) * sizeof(uint32_t),
		sizeof(AcdbDefDotPair));

	ACDB_CLEAR_BUFFER(glb_buf_1);
	ACDB_CLEAR_BUFFER(glb_buf_3);
	return status;
}

int32_t DriverDataGetCalibration(AcdbDriverData *req, AcdbBlob* rsp, AcdbDefDotPair *offset_pair)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_pids = 0;
    uint32_t num_caldata_offsets = 0;
    uint32_t param_size = 0;
    uint32_t *pid_list = NULL;
    uint32_t *caldata_offset_list = NULL;
    uint32_t param_offset = 0;
    uint32_t pid = 0;
    ChunkInfo ci_def = { 0 };
    ChunkInfo ci_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };

    if (IsNull(req) || IsNull(rsp) || IsNull(offset_pair))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_def.chunk_id = ACDB_CHUNKID_GSL_DEF;
    ci_dot.chunk_id = ACDB_CHUNKID_GSL_DOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_def, &ci_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get chunk info for either "
            "DEF, DOT, or Data Pool", status);
        return status;
    }

    //Def
    offset = ci_def.chunk_offset + offset_pair->offset_def;
    status = FileManReadBuffer(&num_pids, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of Parameter IDs", status);
        return status;
    }

    status = FileManReadBuffer(&glb_buf_2, sizeof(uint32_t)* num_pids, &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Parameter List", status);
        return status;
    }

    //Dot
    offset = ci_dot.chunk_offset + offset_pair->offset_dot;
    status = FileManReadBuffer(&num_caldata_offsets, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of parameter calibration offset", status);
        return status;
    }

    status = FileManReadBuffer(&glb_buf_3, sizeof(uint32_t)* num_caldata_offsets, &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read parameter calibration offset list", status);
        return status;
    }

    if (num_pids != num_caldata_offsets)
    {
        ACDB_ERR("Number of parameter IDs in DEF to not match number off offsets in DOT");
        return AR_EFAILED;
    }

    //glb_buf_2 stores pid list
    //glb_buf_3 stores dot data pool offsets
    pid_list = &glb_buf_2[0];
    caldata_offset_list = &glb_buf_3[0];

    if (rsp->buf != NULL)
    {
		if (rsp->buf_size >= sizeof(uint32_t))
		{
			ACDB_MEM_CPY_SAFE(rsp->buf, sizeof(uint32_t), &req->module_id, sizeof(uint32_t));
		}
		else
		{
			return AR_ENEEDMORE;
		}
        param_offset += sizeof(uint32_t);
    }
    else
    {
        rsp->buf_size += sizeof(req->module_id);
    }

    for (uint32_t i = 0; i < num_pids; i++)
    {
        pid = pid_list[i];
        offset = ci_data_pool.chunk_offset + caldata_offset_list[i];

        status = FileManReadBuffer(&param_size, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read parameter size", status);
            return status;
        }

        if (rsp->buf != NULL)
        {
			if (rsp->buf_size >= (param_offset + (2 * sizeof(uint32_t))))
			{
				ACDB_MEM_CPY_SAFE(rsp->buf + param_offset, sizeof(uint32_t),
                &pid, sizeof(uint32_t));
            param_offset += sizeof(uint32_t);

				ACDB_MEM_CPY_SAFE(rsp->buf + param_offset, sizeof(uint32_t),
                &param_size, sizeof(uint32_t));
            param_offset += sizeof(uint32_t);
			}
			else
			{
				return AR_ENEEDMORE;
			}

            if (param_size != 0)
            {
				if ((rsp->buf_size - param_offset) >= param_size)
				{
                status = FileManReadBuffer(
                    (uint8_t*)rsp->buf + param_offset,
                    param_size, &offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Failed to read "
                        "parameter payload", status);
                    return status;
                }
				}
				else
				{
					return AR_ENEEDMORE;
				}

                param_offset += param_size;
            }
        }
        else
        {
            //<PID, ParamSize, Payload[ParamSize]>
            rsp->buf_size += 2 * sizeof(uint32_t) + param_size;
        }
    }

    pid_list = NULL;
    caldata_offset_list = NULL;
    ACDB_CLEAR_BUFFER(glb_buf_1);
    ACDB_CLEAR_BUFFER(glb_buf_2);
    ACDB_CLEAR_BUFFER(glb_buf_3);

    return status;
}

int32_t AcdbCmdGetDriverData(AcdbDriverData *req, AcdbBlob* rsp, uint32_t rsp_size)
{
	int32_t status = AR_EOK;
    uint32_t cal_lut_entry_offset = 0;
	acdb_driver_cal_lut_entry_t cal_lut_entry = { 0 };
    AcdbDefDotPair offset_pair = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input "
            "parameters are null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

	if (rsp_size < sizeof(AcdbBlob))
	{
        ACDB_ERR("Error[%d]: The response structure size is smaller"
            "than the size of AcdbBlob ", AR_EBADPARAM);
        return AR_EBADPARAM;
	}

    if (req->key_vector.num_keys > 0)
    {
        status = AcdbSort2(
            req->key_vector.num_keys * sizeof(AcdbKeyValuePair),
            req->key_vector.graph_key_vector,
            sizeof(AcdbKeyValuePair), 0);

        if (AR_FAILED(status))
        {
            return status;
        }
    }

    /* The modules in the ACDB_CHUNKID_GSL_CAL_LUT can be associated with
     * more than one key vector. So performing a binary search on just the
     * module ID will not necessarily yield the correct result. In the
     * example below item 1 and 2 are possible candidates.
     *
     * Ex
     * <Module ID, Key Table Offset, LUT Offset>
     * List of GSL LUT Entries:
     * [0x801 KT1 LUT1 | 0x801 KT2 LUT2 | 0x802 KT3 LUT4 | ...]
     *                 [ 0x801 x   x    ] <== search key, x = dont care
     * To alleviate this we calculate the Key Table offset and use it in
     * the binary search so that the search key is unique.
     */
	cal_lut_entry.mid = req->module_id;
	cal_lut_entry.offset_caldata_table = 0;
	cal_lut_entry.offset_calkey_table = 0;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_DRIVER_MODULE,
        &cal_lut_entry, sizeof(cal_lut_entry),
        &cal_lut_entry_offset, sizeof(uint32_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set database context "
            "using driver module(0x%x)", status, req->module_id);
        return status;
    }

    /* A module will only have one entry in the Key Table and Lookup
     * Table if the key count is 0
     */
    //if (req->key_vector.num_keys > 0)
    //{
        status = DriverDataSearchForKeys(req,
            &cal_lut_entry.offset_calkey_table);
        if (AR_FAILED(status)) return status;
    //}

	status = DriverDataSearchForModuleID(&cal_lut_entry);
    if (AR_FAILED(status)) return status;

	status = DriverDataSearchCalDataLUT(req, rsp,
        cal_lut_entry.offset_caldata_table, &offset_pair);
	if (AR_FAILED(status)) return status;


    status = DriverDataGetCalibration(req, rsp, &offset_pair);
    if (AR_FAILED(status)) return status;

	return status;
}

int32_t BuildGetGraphResponse(AcdbGetGraphRsp *rsp, uint32_t sg_list_offset)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
	uint32_t expected_size = rsp->size;
    ChunkInfo ci_data_pool = { 0 };
    SgListHeader sg_list_header = { 0 };

    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The rsp input parameter is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Data Pool chunk info.",
            status);
        return status;
    }

    offset = ci_data_pool.chunk_offset + sg_list_offset;
    status = FileManReadBuffer(&sg_list_header, sizeof(SgListHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read the subgraph list header", status);
        return status;
    }

    rsp->num_subgraphs = sg_list_header.num_subgraphs;
    rsp->size = sg_list_header.size - sizeof(sg_list_header.num_subgraphs);

    if (IsNull(rsp->subgraphs))
    {
        return AR_EOK;
    }

	if (expected_size >= rsp->size)
	{
    status = FileManReadBuffer(rsp->subgraphs, rsp->size, &offset);
	}
	else
	{
		return AR_ENEEDMORE;
	}
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read the subgraph list", status);
        return status;
    }

    return status;
}

/**
* \brief
*		Retrieves the subgraphs list either as:
*       1. a unique set of subgraph ids (subgraph_list) or
*       2. the graph topology with source and destination subgraphs specified (graph)
*
* \depends The input gkv must be sorted
*
* \param[in] sg_list_offset: The relative offset of the subgraph list in the datapool
* \param[in/out] subgraph_list: A unique list of subgraph IDs where the list
*                               buffer is provided by the caller.
*                               *NOTE*: This can be NULL to ignore filling the parameter.
* \param[in/out] graph: The graph topology describing the relationship between
*                    subgraphs. The AcdbGetGraphRsp.subgraphs is returned by
*                    this function. It points to a location in the acdb file
*                    memory. This should not be modified subgraph list should
*                    not be modified.
*                    *NOTE*: This can be NULL to ignore filling the parameter.
*
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbGetSubgraphList(uint32_t sg_list_offset,
    AcdbUintList *subgraph_list, AcdbGetGraphRsp *graph)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t subgraph_list_size = 0;
    uint32_t subgraph_offset = 0;
    ChunkInfo ci_data_pool = { 0 };
    SgListHeader sg_list_header = { 0 };
    AcdbSubgraph *subgraphs = NULL;


    if (IsNull(subgraph_list) && IsNull(graph))
    {
        ACDB_ERR("Error[%d]: One of the subgraph list parameters needs to be provided.",
            status);
        return AR_EBADPARAM;
    }

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Data Pool chunk info.",
            status);
        return status;
    }

    offset = ci_data_pool.chunk_offset + sg_list_offset;
    status = FileManReadBuffer(&sg_list_header, sizeof(SgListHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read the subgraph list header", status);
        return status;
    }

    subgraph_list_size = sg_list_header.size - sizeof(sg_list_header.num_subgraphs);
    status = FileManGetFilePointer2((void **)&subgraphs, offset);


    if (!IsNull(subgraph_list))
    {
        subgraph_list->count = sg_list_header.num_subgraphs;

        if (!IsNull(subgraph_list->list))
        {
            for (uint32_t i = 0; i < sg_list_header.num_subgraphs; i++)
            {
                AcdbSubgraph* subgraph = (AcdbSubgraph*)
                    ((uint8_t*)subgraphs + subgraph_offset);
                subgraph_list->list[i] = subgraph->sg_id;
                subgraph_offset += sizeof(AcdbSubgraph)
                    + subgraph->num_dst_sgids * sizeof(uint32_t);
            }
        }
        else
        {
            ACDB_ERR("Error[%d]: The subgraph list cannot be null",
                AR_EBADPARAM);
            return AR_EBADPARAM;
        }
    }

    if (!IsNull(graph))
    {
        graph->num_subgraphs = sg_list_header.num_subgraphs;
        graph->size = subgraph_list_size;
        graph->subgraphs = subgraphs;
    }

    subgraphs = NULL;
    return status;
}

int32_t AcdbGetUsecaseSubgraphList(AcdbGraphKeyVector* gkv,
    AcdbUintList* subgraph_list, AcdbGetGraphRsp* graph)
{
    int32_t status = AR_EOK;
    AcdbGraphKeyVector graph_kv = { 0 };
    acdb_graph_info_t graph_info = { 0 };

    if (IsNull(gkv))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " GKV or Response", status);
        return AR_EBADPARAM;
    }

    if (gkv->num_keys == 0)
    {
        ACDB_DBG("Error[%d]: Detected empty usecase. "
            "No data will be returned. Skipping..", AR_EOK);
        return AR_EOK;
    }

    //GLB BUF 1 is used for the GKV search
    //GLB BUF 2 is used for storing the found GKV entry
    //GLB BUF 3 is used to store the sorted GKV

    graph_kv.num_keys = gkv->num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0], gkv->num_keys * sizeof(AcdbKeyValuePair),
        gkv->graph_key_vector, gkv->num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
    status = AcdbSort2(gkv->num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort graph key vector.", status);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
        &graph_kv, sizeof(AcdbGraphKeyVector),
        &graph_info, sizeof(acdb_graph_info_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find the graph key vector", status);
        return status;
    }

    status = AcdbGetSubgraphList(graph_info.sg_list_offset, subgraph_list, graph);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get subgraph list", status);
    }

    return status;
}

int32_t AcdbCmdGetGraph(AcdbGraphKeyVector *gkv, AcdbGetGraphRsp *rsp,
    uint32_t rsp_struct_size)
{
    int32_t status = AR_EOK;
    AcdbGraphKeyVector graph_kv = { 0 };
    acdb_graph_info_t graph_info = { 0 };

    if (IsNull(gkv) || IsNull(rsp) || IsNull(gkv->graph_key_vector))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " GKV or Response", status);
        return AR_EBADPARAM;
    }

    if (rsp_struct_size < sizeof(AcdbGetGraphRsp))
    {
        ACDB_ERR("Error[%d]: The size of the response structure is less "
            "than %d bytes", status, sizeof(AcdbGetGraphRsp));
        return AR_EBADPARAM;
    }

    if (IsNull(rsp->subgraphs))
    {
        //Log GKV when this API is called for the first time
        ACDB_DBG("Retrieving subgraph list for the following graph key vector:");
        LogKeyVector(gkv, GRAPH_KEY_VECTOR);
    }

    if (gkv->num_keys == 0)
    {
        ACDB_DBG("Error[%d]: Detected empty usecase. "
            "No data will be returned. Skipping..", AR_EOK);
        return AR_EOK;
    }
    //GLB BUF 1 is used for the GKV search
    //GLB BUF 2 is used for storing the found GKV entry
    //GLB BUF 3 is used to store the sorted GKV

    graph_kv.num_keys = gkv->num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0], gkv->num_keys * sizeof(AcdbKeyValuePair),
        gkv->graph_key_vector, gkv->num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
    status = AcdbSort2(gkv->num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort graph key vector.", status);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
        &graph_kv, sizeof(AcdbGraphKeyVector),
        &graph_info, sizeof(acdb_graph_info_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find the graph key vector", status);
        return status;
    }

    status = BuildGetGraphResponse(rsp, graph_info.sg_list_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to build response", status);
    }

    return status;
}

int32_t AcdbCmdGetGraphAlias(AcdbGraphKeyVector* gkv, AcdbString* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_key_tables = 0;
    uint32_t key_table_size = 0;
    uint32_t key_table_entry_size = 0;
    uint32_t gkv_alias_data_offset = 0;
    uint32_t expected_size = 0;
    uint32_t string_length = 0;
    bool_t found = FALSE;
    ChunkInfo ci_gkv_alias_table = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };
    KeyTableHeader key_table_header = { 0 };
    AcdbOp op = ACDB_OP_NONE;
    AcdbGraphKeyVector graph_kv = { 0 };
    acdb_graph_info_t graph_info = { 0 };

    if (IsNull(gkv) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " GKV or Response", status);
        return AR_EBADPARAM;
    }

    if (gkv->num_keys == 0)
    {
        ACDB_DBG("Error[%d]: Detected empty graph key vector. "
            "No data will be returned. Skipping..", AR_EOK);
        return AR_EOK;
    }

    if (IsNull(rsp->string))
        op = ACDB_OP_GET_SIZE;
    else
    {
        expected_size = rsp->length;
        op = ACDB_OP_GET_DATA;
    }

    if (gkv->num_keys > ACDB_MAX_KEY_COUNT - 1)
        return AR_ENOMEMORY;

    //GLB BUF 3 is used to store the sorted GKV and the found GKV entry
    graph_kv.num_keys = gkv->num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0], gkv->num_keys * sizeof(AcdbKeyValuePair),
        gkv->graph_key_vector, gkv->num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs (position 0 of AcdbKeyValuePair)
    status = AcdbSort2(gkv->num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort graph key vector.", status);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
        &graph_kv, sizeof(AcdbGraphKeyVector),
        &graph_info, sizeof(acdb_graph_info_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find the graph key vector", status);
        return status;
    }

    ci_gkv_alias_table.chunk_id = ACDB_CHUNKID_GKV_ALIAS;
    status = ACDB_GET_CHUNK_INFO(&ci_gkv_alias_table);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Graph Alias chunk data does not exist. Is it enabled?.",
            status);
        return status;
    }

    offset  = ci_gkv_alias_table.chunk_offset;
    status = FileManReadBuffer(&num_key_tables, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of GKV Key ID tables.",
            status);
        return status;
    }

    for (uint32_t i = 0; i < num_key_tables; i++)
    {
        status = FileManReadBuffer(&key_table_header,
            sizeof(KeyTableHeader), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read key table header.",
                status);
            return status;
        }

        key_table_entry_size = key_table_header.num_keys
            * sizeof(AcdbKeyValuePair)
            + sizeof(uint32_t);
        key_table_size = key_table_header.num_entries
            * key_table_entry_size;

        if (key_table_header.num_keys != graph_kv.num_keys)
        {
            offset += key_table_size;
            continue;
        }

        found = TRUE;
        break;
    }

    if (!found)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Graph alias not found for"
            " given graph key vector.", status);
        return status;
    }

    //Setup Table Information
    table_info.table_offset = offset;
    table_info.table_size = key_table_size;
    table_info.table_entry_size = key_table_entry_size;

    //Setup Search Information
    search_info.num_search_keys = key_table_header.num_keys * 2;
    search_info.num_structure_elements =
        key_table_header.num_keys * 2 + 1;//key_ids + gkv alias Offset
    search_info.table_entry_struct = &glb_buf_3;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find graph key vector. "
            "No matching key value pairs were found", status);
        return status;
    }

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get datapool chunk.",
            status);
        return status;
    }

    gkv_alias_data_offset = glb_buf_3[graph_kv.num_keys * 2];
    offset = ci_data_pool.chunk_offset + gkv_alias_data_offset;

    status = FileManReadBuffer(&string_length, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read graph alias string length.",
            status);
        return status;
    }

    rsp->length = string_length;

    if (0 == string_length)
    {
        ACDB_ERR("Error[%d]: The graph alias is empty for the provided "
            "graph key vector. Check if an alias has been assigned.",
            AR_ENOTEXIST);
        return status;
    }

    if (op == ACDB_OP_GET_DATA)
    {
        if (expected_size < string_length)
            return AR_ENOMEMORY;

        offset += sizeof(uint32_t);
        status = FileManReadBuffer(rsp->string, string_length, &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read usecase alias string.",
                status);
            return status;
        }
    }

    return status;
}

int32_t BuildSpfPropertyBlob(uint32_t prop_index, size_t spf_blob_offset,
	uint32_t *prop_data_offset,
	AcdbGetSubgraphDataRsp *pOutput)
{
	/*
	Order of Spf Property Data Blob:
	------------------------------------
	Property Index | Spf Property
	------------------------------------
	0 | Subgraph Config

	1 | Container Config

	2 | Module List

	3 | Module Properties

	4 | Module Connections

	5 | Data Links
	*/

	int32_t status = AR_EOK;
	uint32_t errcode = 0;

	/* Subgraph Spf Property Data Header:
	 * <MIID, PID, ParamSize> (does not include error code)*/
	uint32_t sz_sg_spf_prop_header = 3 * sizeof(uint32_t);
	uint32_t sz_spf_param = 0;
	uint32_t sz_padded_spf_param = 0;
	uint32_t padding = 0;
	uint32_t idx = 0;//GLB BUF index

	if (pOutput->spf_blob.buf != NULL)
	{
		//Copy Header
		if (pOutput->spf_blob.buf_size < (spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)) + sz_sg_spf_prop_header))
		{
			return AR_ENEEDMORE;
		}

		ACDB_MEM_CPY_SAFE(pOutput->spf_blob.buf + spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)), sz_sg_spf_prop_header,
            &glb_buf_1 + *prop_data_offset, sz_sg_spf_prop_header);

		*prop_data_offset += sz_sg_spf_prop_header - sizeof(sz_spf_param);

		//Copy Payload Size
		idx = (*prop_data_offset) / sizeof(uint32_t);
		sz_spf_param = glb_buf_1[idx];

		*prop_data_offset += sizeof(sz_spf_param);

		//Add paddig if necessary before sending the response back
		if ((sz_spf_param % 8) != 0)
		{
			sz_padded_spf_param = sz_spf_param + (8 - ((sz_spf_param % 8)));

			padding = (8 - ((sz_spf_param % 8)));
		}
		else
		{
			sz_padded_spf_param = sz_spf_param;
		}

		//Insert Error Code
		if (pOutput->spf_blob.buf_size < (spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)) + sizeof(errcode)))
        {
			return AR_ENEEDMORE;
		}

		ACDB_MEM_CPY_SAFE(pOutput->spf_blob.buf + spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)), sizeof(errcode),
            &errcode, sizeof(errcode));

		spf_blob_offset += sizeof(errcode);

		//Copy Payload
		idx = (*prop_data_offset) / sizeof(uint32_t);
		if (pOutput->spf_blob.buf_size < (spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)) + sz_spf_param))
		{
			return AR_ENEEDMORE;
		}

		ACDB_MEM_CPY_SAFE(pOutput->spf_blob.buf + spf_blob_offset + *prop_data_offset
            + (prop_index * sizeof(errcode)), sz_spf_param,
            &glb_buf_1[idx], sz_spf_param);

		*prop_data_offset += sz_spf_param;

		//Add Padding
		if ((sz_spf_param % 8) != 0)
		{
			memset((uint8_t*)pOutput->spf_blob.buf + spf_blob_offset + *prop_data_offset + (prop_index * sizeof(errcode)), 0, padding);
			*prop_data_offset += padding;
		}

	}
	else
	{
		//Add <IID, ParamID>
		*prop_data_offset += sz_sg_spf_prop_header - sizeof(uint32_t);

		//Copy Payload Size
		idx = (*prop_data_offset) / sizeof(uint32_t);
		sz_spf_param = glb_buf_1[idx];

		//Add paddig if necessary before sending the response back
		if ((sz_spf_param % 8) != 0)
		{
			sz_padded_spf_param = sz_spf_param + (8 - ((sz_spf_param % 8)));

			//*padded_bytes += (8 - ((sz_spf_param % 8)));
		}
		else
		{
			sz_padded_spf_param = sz_spf_param;
		}

		//Add Param Size
		*prop_data_offset += sizeof(sz_padded_spf_param);

		*prop_data_offset += sz_padded_spf_param;
	}

	return status;
}

int32_t BuildDriverPropertyBlob(uint32_t sz_driver_prop_data, uint32_t *driver_data_buf, AcdbGetSubgraphDataRsp *pOutput, uint32_t *rsp_offset)
{
	if (IsNull(driver_data_buf) || IsNull(rsp_offset))
	{
		return AR_EBADPARAM;
	}

	int32_t status = AR_EOK;
	uint32_t sg_driver_prop_offset = 0;

	//Subgraph Driver Property Data Header: <SubgraphID, #SubgraphProperties>
	size_t sz_sg_driver_prop_header = 2 * sizeof(uint32_t);

	//<SubgraphPropertyID, PropertySize>
	size_t sz_prop_header = 2 * sizeof(uint32_t);

	uint32_t sg_id = driver_data_buf[0];
	uint32_t num_sg_prop = driver_data_buf[1];
	uint32_t sz_prop = 0;
	uint32_t sz_all_prop_payload = 0;
	uint32_t tmp_sz_sg_driver_prop_data = 0;
	uint32_t index = 0;

	if (pOutput->driver_prop.sub_graph_prop_data != NULL)
	{
		//SG ID
		if (pOutput->driver_prop.size < (*rsp_offset + sizeof(uint32_t)))
		{
			return AR_ENEEDMORE;
		}

		ACDB_MEM_CPY_SAFE(pOutput->driver_prop.sub_graph_prop_data
            + *rsp_offset, sizeof(uint32_t),
            &sg_id, sizeof(uint32_t));

		sg_driver_prop_offset += sizeof(sg_id);
		*rsp_offset += sizeof(sg_id);

		//Number of SG Properties
		if (pOutput->driver_prop.size < (*rsp_offset + sizeof(uint32_t)))
		{
			return AR_ENEEDMORE;
		}

		ACDB_MEM_CPY_SAFE(pOutput->driver_prop.sub_graph_prop_data
            + *rsp_offset, sizeof(uint32_t),
            &num_sg_prop, sizeof(uint32_t));

		sg_driver_prop_offset += sizeof(num_sg_prop);
		*rsp_offset += sizeof(num_sg_prop);

		for (uint32_t i = 0; i < num_sg_prop; i++)
		{
			//SG Property ID
			index = (uint32_t)(sg_driver_prop_offset / sizeof(uint32_t));
			if (pOutput->driver_prop.size < (*rsp_offset + sizeof(uint32_t)))
			{
				return AR_ENEEDMORE;
			}

			ACDB_MEM_CPY_SAFE(pOutput->driver_prop.sub_graph_prop_data
                + *rsp_offset, sizeof(uint32_t),
                &driver_data_buf[index], sizeof(uint32_t));

			sg_driver_prop_offset += sizeof(uint32_t);
			*rsp_offset += sizeof(uint32_t);

			//Property Size
			index = (uint32_t)(sg_driver_prop_offset / sizeof(uint32_t));
			if (pOutput->driver_prop.size < (*rsp_offset + sizeof(uint32_t)))
			{
				return AR_ENEEDMORE;
			}

			ACDB_MEM_CPY_SAFE(pOutput->driver_prop.sub_graph_prop_data
                + *rsp_offset, sizeof(uint32_t),
                &driver_data_buf[index], sizeof(uint32_t));

			index = (uint32_t)(sg_driver_prop_offset / sizeof(uint32_t));
			sz_prop = driver_data_buf[index];
			sz_all_prop_payload += sz_prop;

			sg_driver_prop_offset += sizeof(uint32_t);
			*rsp_offset += sizeof(uint32_t);

			//Property Paylaod
			index = (uint32_t)(sg_driver_prop_offset / sizeof(uint32_t));
			if (pOutput->driver_prop.size < (*rsp_offset + sz_prop))
			{
				return AR_ENEEDMORE;
			}

			ACDB_MEM_CPY_SAFE(pOutput->driver_prop.sub_graph_prop_data
                + *rsp_offset, sz_prop,
                &driver_data_buf[index], sz_prop);

			sg_driver_prop_offset += sz_prop;
			*rsp_offset += sz_prop;
		}
	}
	else
	{
		sg_driver_prop_offset += (uint32_t)(sz_sg_driver_prop_header);
		*rsp_offset += (uint32_t)(sz_sg_driver_prop_header);

		for (uint32_t i = 0; i < num_sg_prop; i++)
		{
			//SG Property ID
			sg_driver_prop_offset += sizeof(uint32_t);
			*rsp_offset += sizeof(uint32_t);

			//Property Size
			index = (uint32_t)(sg_driver_prop_offset / sizeof(uint32_t));
			sz_prop = driver_data_buf[index];

			sg_driver_prop_offset += sizeof(uint32_t);
			*rsp_offset += sizeof(uint32_t);

			//Skip the actual payload
			sg_driver_prop_offset += sz_prop;
			*rsp_offset += sz_prop;

			//Property Paylaod
			sz_all_prop_payload += sz_prop;
		}
	}

	//Accumulate size of subgraph property data
	tmp_sz_sg_driver_prop_data =
		(uint32_t)sz_sg_driver_prop_header + num_sg_prop *((uint32_t)sz_prop_header)
		+sz_all_prop_payload;

	if (sz_driver_prop_data != tmp_sz_sg_driver_prop_data)
	{
		status = AR_EFAILED;
		ACDB_ERR_MSG_1("Driver property data size does not match accumulated data size", status);
	}

	return status;
}

int32_t BuildSubgraphDataRsp(AcdbSgIdGraphKeyVector *pInput, uint32_t sg_data_offset, AcdbGetSubgraphDataRsp *pOutput)
{
	int32_t status = AR_EOK;
	uint32_t i = 0;
	uint32_t offset = 0;

	//Data offset for spf portion of the output Blob
	uint32_t spf_blob_offset = 0;
	uint32_t driver_prop_data_offset = 0;
    ChunkInfo ci_data_pool = { 0 };
	//Subgraph Property Data Header: <TotalPropertyDataSize, #Subgraphs>
	size_t sz_sg_prop_data_header = 2 * sizeof(uint32_t);

	//Subgraph Property Data Header: <SubgraphID, DataSize>
	size_t sz_sg_obj_header = 2 * sizeof(uint32_t);

	//Accumulated sum of driver property data size for all subgraphs
	size_t sz_all_driver_prop_data = 0;

	//Size of driver property data for a subgraphs
	size_t sz_sg_driver_prop_data = 0;

	//Size of spf property data for a subgraph
	size_t sz_sg_spf_prop_data = 0;

	//Size of the Spf Data portion of the output blob
	size_t sz_spf_blob = 0;
	bool_t found = FALSE;

	ACDB_CLEAR_BUFFER(glb_buf_1);
	ACDB_CLEAR_BUFFER(glb_buf_3);

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get data pool chunk", status);

        return status;
    }

	//status = AcdbGetChunkInfo(ACDB_CHUNKID_DATAPOOL, &chkBuf, &chkLen);

	//if (AR_EOK != status) return status;

	//Sort Subgraph IDs
	//for (i = 0; i < pInput->num_sgid; i++)
	//{
	//	glb_buf_3[i] = pInput->sg_ids[i];
	//}

	//AcdbSort(glb_buf_3, pInput->num_sgid);

	for (i = 0; i < pInput->num_sgid; i++)
	{
		found = FALSE;
        offset = ci_data_pool.chunk_offset + sg_data_offset + (uint32_t)sz_sg_prop_data_header;
		do
		{
            status = FileManReadBuffer(&glb_buf_1, sz_sg_obj_header, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read subgraph ID from subgraph property data", status);

                return status;
            }

			if (0 == ACDB_MEM_CMP(&glb_buf_1[0], &pInput->sg_ids[i], sizeof(uint32_t)))
			{
				found = TRUE;
				break;
			}
			else
			{
                offset += glb_buf_1[1]; //+ (uint32_t)sz_sg_prop_data_header - sz_sg_obj_header;
			}

		} while (offset < ci_data_pool.chunk_offset + ci_data_pool.chunk_size && !found);

		if (!found)
		{
			ACDB_ERR("Error[%d]: subgraph 0x%x does not exist", AR_EFAILED, pInput->sg_ids[i]);

			return AR_EFAILED;
		}
		else
		{
			//copy driver prop and spf prop data
			//offset += (uint32_t)sz_sg_obj_header;

			ACDB_CLEAR_BUFFER(glb_buf_1);

            status = FileManReadBuffer(&sz_sg_driver_prop_data, sizeof(uint32_t), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read subgraph driver property size", status);

                return status;
            }

			sz_all_driver_prop_data += sz_sg_driver_prop_data;

            status = FileManReadBuffer(&glb_buf_1, sz_sg_driver_prop_data, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read subgraph driver properties", status);

                return status;
            }

			//Build Driver Property Data Blob
			status = BuildDriverPropertyBlob((uint32_t)sz_sg_driver_prop_data, &glb_buf_1[0], pOutput, &driver_prop_data_offset);
			if (AR_EOK != status)
			{
				ACDB_ERR("Error[%d]: Unable to parse driver property data", status);
				return status;
			}

			ACDB_CLEAR_BUFFER(glb_buf_1);

            status = FileManReadBuffer(&sz_sg_spf_prop_data, sizeof(uint32_t), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read subgraph SPF property size", status);

                return status;
            }

            status = FileManReadBuffer(&glb_buf_1, sz_sg_spf_prop_data, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read subgraph SPF properties", status);

                return status;
            }

			uint32_t prop_data_offset = 0;

			int property_index = 0;
			while (prop_data_offset < sz_sg_spf_prop_data)
			{
				status = BuildSpfPropertyBlob(property_index, spf_blob_offset, &prop_data_offset, pOutput);

				if (AR_EOK != status)
				{
					ACDB_ERR("Error[%d]: Unable to build spf blob. Encountered error while "
                        "getting property at index %d", status, property_index);

					return status;
				}

				property_index++;
			}

			//Add sizeof(error code) for each spf property
			sz_spf_blob += (sz_sg_spf_prop_data + (property_index * sizeof(uint32_t)));

			spf_blob_offset = (uint32_t)sz_spf_blob;
		}
	}

	pOutput->driver_prop.num_sgid = pInput->num_sgid;

	pOutput->driver_prop.size = (uint32_t)sz_all_driver_prop_data;

	pOutput->spf_blob.buf_size = (uint32_t)sz_spf_blob;

	return status;
}

int32_t AcdbCmdGetSubgraphData(AcdbSgIdGraphKeyVector *req, AcdbGetSubgraphDataRsp *rsp)
{
	int32_t status = AR_EOK;
    AcdbGraphKeyVector graph_kv = { 0 };
    acdb_graph_info_t graph_info = { 0 };

    graph_kv.num_keys = req->graph_key_vector.num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0],
        graph_kv.num_keys * sizeof(AcdbKeyValuePair),
        req->graph_key_vector.graph_key_vector,
        graph_kv.num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
    status = AcdbSort2(graph_kv.num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort graph key vector.", status);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
        &graph_kv, sizeof(AcdbGraphKeyVector),
        &graph_info, sizeof(acdb_graph_info_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find the graph key vector", status);
        return status;
    }

	status = BuildSubgraphDataRsp(req, graph_info.sg_prop_data_offset, rsp);

	if (AR_EOK != status) return status;

	return status;
}

/**
* \brief
*		Searches the Subgraph Connection LUT for matching <src, dst> subgraph
*       connection and retreives the <def, dot> offsets.
*
* \param[in/out] connection: A subgraph connection to get the def
*                            and dot offsets for
* \param[in] table_info: information about the Subgraph Connection LUT
*
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbSearchSubgraphConnectionLut(AcdbSubgraphConnection *connection,
    AcdbTableInfo *table_info)
{
    int32_t status = AR_EOK;
    AcdbTableSearchInfo search_info = { 0 };

    if (IsNull(connection) || IsNull(table_info))
    {
        return AR_EBADPARAM;
    }

    //format :
    //LUT = SourceSubgraphId, DestinationSubgraphId, DefOffset, DotOffset

    //Setup Table Information
    //table_info.table_offset = offset;
    //table_info.table_size = key_table_size;
    //table_info.table_entry_size = key_table_entry_size;

    //Setup Search Information
    search_info.num_search_keys = 2;//Source and Destination Subgraph IDs
    search_info.num_structure_elements =
        sizeof(AcdbSubgraphConnection) / sizeof(uint32_t);
    search_info.table_entry_struct = connection;

    status = AcdbTableBinarySearch(table_info, &search_info);

    return status;
}

int32_t AcdbGetSubgraphConnectionData(AcdbSubgraphConnection *connection,
    ChunkInfo *def, ChunkInfo *dot, ChunkInfo *data_pool,
    uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t num_def_entries = 0;
    uint32_t num_dot_entries = 0;
    uint32_t def_offset = 0;
    uint32_t dot_offset = 0;
    uint32_t data_pool_offset = 0;
    uint32_t param_size = 0;
    uint32_t padding = 0;
    AcdbOp op = ACDB_OP_NONE;
    AcdbDspModuleHeader apm_conn_param = { 0 };

    op = IsNull(rsp->buf) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    def_offset = def->chunk_offset + connection->def_offset;
    dot_offset = dot->chunk_offset + connection->dot_offset;

    status = FileManReadBuffer(&num_def_entries, sizeof(uint32_t), &def_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read def entry count", status);
        return status;
    }

    status = FileManReadBuffer(&num_dot_entries, sizeof(uint32_t), &dot_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read dot entry count", status);
        return status;
    }

    //Num Entries in Def and Num Entries in Dot should be equal
    if (num_def_entries != num_dot_entries)
    {
        ACDB_ERR("Error[%d]: Number of entries between Def and "
            "Dot tables do not match.", AR_EFAILED);
        return AR_EFAILED;
    }

    for (uint32_t k = 0; k < num_def_entries; k++)
    {
        status = FileManReadBuffer(&apm_conn_param,
            sizeof(AcdbMiidPidPair), &def_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read APM "
                "module instance and parameter IDs", status);
            return status;
        }

        status = FileManReadBuffer(&data_pool_offset,
            sizeof(uint32_t), &dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read datapool offset", status);
            return status;
        }

        uint32_t dpo = data_pool->chunk_offset + data_pool_offset;
        status = FileManReadBuffer(&param_size,
            sizeof(uint32_t), &dpo);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read parameter size for "
                "APM parameter[0x%x]", status, apm_conn_param.parameter_id);
            return status;
        }

        padding = ACDB_PADDING_8_BYTE(param_size);
        apm_conn_param.param_size = param_size;

        if (op == ACDB_OP_GET_SIZE)
        {
            rsp->buf_size += sizeof(apm_conn_param)
                + apm_conn_param.param_size + padding;
        }
        else if (op == ACDB_OP_GET_DATA)
        {
            if (rsp->buf_size < *blob_offset + sizeof(AcdbDspModuleHeader)
                + apm_conn_param.param_size)
            {
                return AR_ENEEDMORE;
            }

            ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(apm_conn_param),
                &apm_conn_param, sizeof(apm_conn_param));
            *blob_offset += sizeof(apm_conn_param);

            status = FileManReadBuffer((uint8_t*)rsp->buf + *blob_offset,
                param_size, &dpo);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read size of APM"
                    " connection parameter[0x%x]", status, apm_conn_param.parameter_id);
                return status;
            }

            *blob_offset += param_size;

            //Add Padding
            if (padding)
            {
                ar_mem_set((void*)((uint8_t*)rsp->buf + *blob_offset),
                    0, padding);
                *blob_offset += padding;
            }
        }
    }

    return status;
}

int32_t AcdbCmdGetSubgraphConnections(AcdbSubGraphList* req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t blob_offset = 0;
    //uint32_t expected_size = 0;
    ChunkInfo ci_lut = { 0 };
    ChunkInfo ci_def = { 0 };
    ChunkInfo ci_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbUintList subgraph_list = {0};
    AcdbSubgraph *subgraph = NULL;
    AcdbSubgraphConnection subgraph_connection = { 0 };
    AcdbTableInfo lut_info = { 0 };

    //set file index based on subgraph list
    for (uint32_t i = 0; i < req->num_subgraphs; i++)
    {
        subgraph = (AcdbSubgraph*)((uint8_t*)req->subgraphs + offset);
        glb_buf_3[i] = subgraph->sg_id;

        offset += sizeof(AcdbSubgraph)
            + subgraph->num_dst_sgids * sizeof(uint32_t);
    }

    subgraph_list.count = req->num_subgraphs;
    subgraph_list.list = &glb_buf_3[0];

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    ACDB_CLEAR_BUFFER(glb_buf_3);

    ci_lut.chunk_id = ACDB_CHUNKID_SGCONNLUT;
    ci_def.chunk_id = ACDB_CHUNKID_SGCONNDEF;
    ci_dot.chunk_id = ACDB_CHUNKID_SGCONNDOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_lut, &ci_def, &ci_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read one or more chunks", status);
        return status;
    }

    lut_info.table_size = ci_lut.chunk_size - sizeof(uint32_t);
    lut_info.table_offset = ci_lut.chunk_offset + sizeof(uint32_t);
    lut_info.table_entry_size = sizeof(AcdbSubgraphConnection);
    offset = 0;

    for (uint32_t i = 0; i < req->num_subgraphs; i++)
    {
        subgraph = (AcdbSubgraph*)((uint8_t*)req->subgraphs + offset);
        offset += sizeof(AcdbSubgraph)
            + subgraph->num_dst_sgids * sizeof(uint32_t);

        for (uint32_t j = 0; j < subgraph->num_dst_sgids; j++)
        {
            subgraph_connection.src_subgraph_id = subgraph->sg_id;
            subgraph_connection.dst_subgraph_id = subgraph->dst_sg_ids[j];

            status = AcdbSearchSubgraphConnectionLut(
                &subgraph_connection, &lut_info);
            if (AR_FAILED(status))
            {
                //connection not found
                return status;
            }

            status = AcdbGetSubgraphConnectionData(&subgraph_connection,
                &ci_def, &ci_dot, &ci_data_pool, &blob_offset, rsp);
            if (AR_FAILED(status))
            {
                //connection data not found
                return status;
            }
        }
    }

    subgraph = NULL;

    if (rsp->buf_size == 0)
        return AR_ENOTEXIST;

    return status;
}

int32_t AcdbGetOffloadedParameterCal(
     AcdbOp op, uint32_t subgraph_id, AcdbDspModuleHeader *module_header,
    AcdbPayload *caldata, AcdbBlob* rsp,
    uint32_t *module_start_blob_offset, uint32_t *module_end_blob_offset)
{
    int32_t status = AR_EOK;
    uint32_t tmp_blob_offset = 0;

    if (op == ACDB_OP_GET_SIZE)
        tmp_blob_offset = rsp->buf_size;
    else
    {
        tmp_blob_offset = *module_start_blob_offset;
        //*module_start_blob_offset = *module_end_blob_offset;
        //*module_start_blob_offset = *module_end_blob_offset;
    }

    tmp_blob_offset += sizeof(AcdbDspModuleHeader);

    status = GetOffloadedParameterData(
        caldata, &module_header->param_size, rsp, &tmp_blob_offset);
    if (AR_FAILED(status) && status != AR_ENOTEXIST)
    {
        return status;
    }
    else if (AR_FAILED(status) && status == AR_ENOTEXIST)
    {
        if (op == ACDB_OP_GET_SIZE)
            ACDB_ERR("Error[%d]: No file path provided for offloaded "
                "parameter [sg: 0x%x, inst.: 0x%x, param: 0x%x]", status,
                subgraph_id, module_header->module_iid,
                module_header->parameter_id);
        status = AR_EOK;
    }

    if (op == ACDB_OP_GET_DATA)
        *module_end_blob_offset = tmp_blob_offset;
    //padded_param_size =
    //    ACDB_ALIGN_8_BYTE(module_header.param_size);

    return status;
}

int32_t AcdbGetSubgraphCalibration(AcdbAudioCalContextInfo *info,
    uint32_t *blob_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t cur_def_offset = 0;
    uint32_t cur_dot_offset = 0;
    uint32_t cur_dpool_offset = 0;
    uint32_t data_offset = 0;
    uint32_t padded_param_size = 0;
    uint32_t num_param_cal_found = 0;
    uint32_t num_iid_found = 0;
    uint32_t tmp_blob_offset = 0;
    bool_t is_offloaded_param = FALSE;
    ChunkInfo ci_cal_def = { 0 };
    ChunkInfo ci_cal_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    uint32_t num_id_entries = 0;
    AcdbDspModuleHeader module_header = { 0 };
    AcdbIidRefCount *iid_ref = NULL;
    AcdbBlob src = { 0 };
    AcdbPayload caldata = { 0 };
    AcdbHwAccelMemType mem_type = ACDB_HW_ACCEL_MEM_TYPE(info->proc_id);

    ci_cal_def.chunk_id = ACDB_CHUNKID_CALDATADEF;
    ci_cal_dot.chunk_id = ACDB_CHUNKID_CALDATADOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_cal_def,
        &ci_cal_dot, &ci_data_pool);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration "
            "DEF, DOT, or Datapool chunk information", status);
        return status;
    }

    // Skip number of DOT offsets since number of IID Pairs is the same thing
    cur_dot_offset = ci_cal_dot.chunk_offset + info->data_offsets.offset_dot
        + sizeof(uint32_t);
    cur_def_offset = ci_cal_def.chunk_offset + info->data_offsets.offset_def;
    status = FileManReadBuffer(&num_id_entries, sizeof(uint32_t), &cur_def_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of "
            "<iid, pid> entries", status);
        return status;
    }

    if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        //Ensure global buffer can store the default data IID Reference list
        if (GLB_BUF_1_LENGTH < num_id_entries * 2)
        {
            ACDB_ERR("Error[%d]: Need more memory to store IID reference list",
                AR_ENEEDMORE);
            return AR_ENEEDMORE;
        }

        ACDB_CLEAR_BUFFER(glb_buf_1);

        iid_ref = (AcdbIidRefCount*)glb_buf_1;
    }

    for (uint32_t i = 0; i < num_id_entries; i++)
    {
        status = FileManReadBuffer(&module_header, sizeof(AcdbMiidPidPair),
            &cur_def_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read <iid, pid> entry", status);
            return status;
        }

        //If Get Module Data is called
        if ((info->data_op == ACDB_OP_GET_MODULE_DATA) &&
            (module_header.module_iid != info->instance_id))
        {
            cur_dot_offset += sizeof(uint32_t);
            continue;
        }

        if (info->is_default_module_ckv && info->ignore_get_default_data)
        {
            //Add IIDs to list and ignore get data
            if (iid_ref->module_iid != module_header.module_iid && num_iid_found == 0)
            {
                iid_ref->module_iid = module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
                //iid_ref++;
            }
            else if (iid_ref->module_iid != module_header.module_iid)
            {
                iid_ref++;
                iid_ref->module_iid = module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
            }
            else
            {
                /* Increase ref count of the current <IID, Ref Count> Obj */
                iid_ref->ref_count++;
            }

            continue;
        }
        else
        {
            /* For other CKVs, if the module is in the default data list, remove it */
            if (!IsNull(info->default_data_iid_list.list))
            {
                iid_ref = (AcdbIidRefCount*)
                    info->default_data_iid_list.list;
                bool_t found_iid = FALSE;
                for (uint32_t j = 0; j < info->
                    default_data_iid_list.count; j++)
                {
                    if ((module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count > 0)
                    {
                        iid_ref->ref_count--;
                        found_iid = TRUE;
                        break;
                    }
                    else if ((module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count <= 0)
                        break;

                    iid_ref++;
                }

                if (info->is_default_module_ckv && !found_iid)
                {
                    cur_dot_offset += sizeof(uint32_t);
                    continue;
                }
            }
        }

        //todo: Swap to this impementation when Global Persist is supported
        //status = DataProcGetPersistenceType(
        //    module_header.parameter_id, &param_type);
        //if (AR_FAILED(status))
        //{
        //    ACDB_ERR("Error[%d]: Failed to get parameter persist type "
        //        "for Parameter(0x%x)", status, module_header.parameter_id);
        //    return status;
        //}

        //if (info->param_type != param_type)
        //{
        //    cur_dot_offset += sizeof(uint32_t);
        //    continue;
        //}

        switch (info->param_type)
        {
        case ACDB_DATA_NON_PERSISTENT:
            if (AR_SUCCEEDED(IsPidPersistent(module_header.parameter_id)))
            {
                //cur_def_offset += sizeof(AcdbMiidPidPair);
                cur_dot_offset += sizeof(uint32_t);
                continue;
            }
            break;
        case ACDB_DATA_PERSISTENT:
            if (AR_FAILED(IsPidPersistent(module_header.parameter_id)))
            {
                //cur_def_offset += sizeof(AcdbMiidPidPair);
                cur_dot_offset += sizeof(uint32_t);
                continue;
            }
            break;
        //case ACDB_DATA_GLOBALY_PERSISTENT:
        //    break;
        case ACDB_DATA_DONT_CARE:
        default:
            break;
        }

        if (info->param_type == ACDB_DATA_PERSISTENT && info->should_filter_cal_by_proc_domain)
        {
            //check for proc id

            uint32_t proc_domain_id = 0;
            status = DataProcGetProcDomainForModule(
                info->sg_mod_iid_map,
                module_header.module_iid,
                &proc_domain_id);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to get proccessor domain ID for "
                    "sg: 0x%x iid: 0x%x",
                    status, info->subgraph_id, module_header.module_iid);
                return status;
            }

            if (proc_domain_id != ACDB_HW_ACCEL_PROC_ID(info->proc_id))
            {
                //go to next parameter
                cur_dot_offset += sizeof(uint32_t);
                continue;
            }
        }

        if (info->should_check_hw_accel)
        {
            status = DataProcIsHwAccelParam(info->hw_accel_module_list_offset,
                module_header.module_iid, module_header.parameter_id);

            switch (mem_type)
            {
            case ACDB_HW_ACCEL_MEM_DEFAULT:
                if (AR_SUCCEEDED(status))
                {
                    cur_dot_offset += sizeof(uint32_t);
                    continue;
                }
                break;
            case ACDB_HW_ACCEL_MEM_CMA:
                if (AR_FAILED(status))
                {
                    cur_dot_offset += sizeof(uint32_t);
                    continue;
                }
                break;
            case ACDB_HW_ACCEL_MEM_BOTH:
                status = AR_EBADPARAM;
                ACDB_ERR("Error[%d]: The HW Accel Memory Type is set to BOTH. "
                "It needs to be either DEFAULT or CMA", status);
                goto end;
            }
        }

        num_param_cal_found++;

        status = IsOffloadedParam(module_header.parameter_id,
            &info->offloaded_parameter_list);
        is_offloaded_param = AR_SUCCEEDED(status) ? TRUE : FALSE;

        //Get data from Heap
        status = GetSubgraphCalData(info->param_type, ACDB_DATA_ACDB_CLIENT,
            info->module_ckv, info->subgraph_id, module_header.module_iid,
            module_header.parameter_id, is_offloaded_param, blob_offset, rsp);

        if (AR_SUCCEEDED(status))
        {
            //cur_def_offset += sizeof(AcdbMiidPidPair);
            cur_dot_offset += sizeof(uint32_t);
            continue;
        }

        //Get data from file
        status = FileManReadBuffer(
            &data_offset, sizeof(uint32_t), &cur_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read number of "
                "<iid, pid> entries", status);
            return status;
        }

        cur_dpool_offset = ci_data_pool.chunk_offset + data_offset;
        status = FileManReadBuffer(
            &module_header.param_size, sizeof(uint32_t), &cur_dpool_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read param size", status);
            return status;
        }

        src.buf_size = sizeof(module_header);
        src.buf = (void*)&module_header;
        tmp_blob_offset = 0;
        caldata.size = module_header.param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, cur_dpool_offset);

        if (is_offloaded_param)
        {
            status = AcdbGetOffloadedParameterCal(
                info->op, info->subgraph_id, &module_header,
                &caldata, rsp, blob_offset, &tmp_blob_offset);
            if (AR_FAILED(status))
                return status;

            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }
        else
        {
            padded_param_size =
                ACDB_ALIGN_8_BYTE(module_header.param_size);
        }


        switch (info->op)
        {
        case ACDB_OP_GET_SIZE:
            rsp->buf_size += sizeof(AcdbDspModuleHeader)
            + padded_param_size;
            break;
        case ACDB_OP_GET_DATA:
            status = AcdbWriteBuffer(rsp, blob_offset, &src);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Need more memory to write module header",
                    status);
                return status;
            }

            if (is_offloaded_param)
            {
                *blob_offset = tmp_blob_offset;
                continue;
            }

            if (rsp->buf_size < (*blob_offset + padded_param_size))
            {
                ACDB_ERR("Error[%d]: Need more memory to write param data",
                    status);
                return AR_ENEEDMORE;
            }

            if (module_header.param_size > 0)
            {
                src.buf = caldata.payload;
                src.buf_size = caldata.size;

                status = AcdbWriteBuffer(rsp, blob_offset, &src);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Unable to write param data",
                        status);
                    return status;
                }
            }

            *blob_offset += ACDB_PADDING_8_BYTE(caldata.size);
            break;
        default:
            break;
        }
    }
end:
    if (info->is_default_module_ckv && !info->ignore_get_default_data)
    {
        ACDB_FREE(info->default_data_iid_list.list);
        info->default_data_iid_list.list = NULL;
    }
    else if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        /* Copy the IID Ref Count list from GLB_BUF_1 since it will be
        * cleared outside of this call */
        info->default_data_iid_list.count = num_iid_found;

        //List of AcdbIidRefCount
        info->default_data_iid_list.list = (uint32_t*)
            ACDB_MALLOC(AcdbIidRefCount, num_iid_found);

        if (IsNull(info->default_data_iid_list.list))
        {
            ACDB_ERR("Error[%d]: Unable to allocate memory "
                "for instance id reference list", AR_ENOMEMORY);
            return AR_ENOMEMORY;
        }

        ACDB_MEM_CPY_SAFE(info->default_data_iid_list.list,
            num_iid_found * sizeof(AcdbIidRefCount),
            &glb_buf_1[0], num_iid_found * sizeof(AcdbIidRefCount));

        iid_ref = NULL;
    }

    if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        return AR_EOK;
    }
    else if (num_param_cal_found == 0) return AR_ENOTEXIST;

    return status;
}

int32_t AcdbFindModuleCKV(AcdbCalKeyTblEntry *ckv_entry,
    AcdbAudioCalContextInfo *info)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys_found = 0;
    uint32_t key_table_size = 0;
    uint32_t key_table_entry_size = 0;
    ChunkInfo ci_sg_key_tbl = { 0 };
    ChunkInfo ci_cal_lut = { 0 };
    AcdbGraphKeyVector module_ckv = { 0 };
    KeyTableHeader key_table_header = { 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    if (IsNull(ckv_entry) || IsNull(info))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (IsNull(info->module_ckv))
    {
        ACDB_ERR("Error[%d]: The module CKV in the context"
            " info struct is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_sg_key_tbl.chunk_id = ACDB_CHUNKID_CALKEYTBL;
    ci_cal_lut.chunk_id = ACDB_CHUNKID_CALDATALUT;
    status = ACDB_GET_CHUNK_INFO(&ci_sg_key_tbl, &ci_cal_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph CKV Tables "
            "(Key ID and Value Lookup)chunk information", status);
        return status;
    }

    /*
     * GLB_BUF_1:
     *   1. Used to store the key ids
     *   2. Also stores the CKV LUT used in the partition binary search
     * GLB_BUF_3:
     *   1. The first portion of the buffer stores the Module CKV
     *   2. The other portion stores one CKV LUT entry found
     *      the partition binary search during
     */
    offset = ci_sg_key_tbl.chunk_offset + ckv_entry->offset_cal_key_tbl;
    status = FileManReadBuffer(&module_ckv.num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of CKV keys", status);
        return status;
    }

    if (module_ckv.num_keys > 0)
    {
        status = FileManReadBuffer(&glb_buf_1,
            module_ckv.num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read key id list", status);
        }
    }

    uint32_t ckv_lut_entry_index = module_ckv.num_keys * 2;

    module_ckv.graph_key_vector =
        (AcdbKeyValuePair*)&glb_buf_3[0];
    for (uint32_t i = 0; i < module_ckv.num_keys; i++)
    {
        module_ckv.graph_key_vector[i].key = glb_buf_1[i];
    }

    /* Check if the Module CKV exist within the new CKV. If it doesn't
     * skip this module CKV */
    num_keys_found = 0;
    for (uint32_t k = 0; k < module_ckv.num_keys; k++)
    {
        for (uint32_t l = 0; l < info->ckv->num_keys; l++)
        {
            if (module_ckv.graph_key_vector[k].key ==
                info->ckv->graph_key_vector[l].key)
            {
                glb_buf_3[ckv_lut_entry_index + num_keys_found] =
                    info->ckv->graph_key_vector[l].value;
                module_ckv.graph_key_vector[k].value =
                    info->ckv->graph_key_vector[l].value;
                num_keys_found += 1;
                break;
            }
        }
    }

    if (info->ckv->num_keys == 0 && module_ckv.num_keys != 0 &&
        info->is_first_time)
        return AR_ENOTEXIST;
    if (module_ckv.num_keys == 0 && !info->is_first_time)
        return AR_ENOTEXIST;
    if ((num_keys_found != module_ckv.num_keys) && !info->is_first_time)
        return AR_ENOTEXIST;
    if (!info->is_first_time)
    {
        bool_t deltaKey = FALSE;//Is delta key vector found

        /* We are checking for all the key combinations. Compare the KeyVector
         * KeyIDs in the CalKeyTable to the DeltaKV KeyIDs
         * Case 1:
         *   If all the keys are missing, go to the next CKV KeyID table offset
         * Case 2:
         *   If its a partial match, break and get the module data
         */
        for (uint32_t k = 0; k < module_ckv.num_keys; k++)
        {
            for (uint32_t l = 0; l < info->delta_ckv->num_keys; l++)
            {
                if (module_ckv.graph_key_vector[k].key ==
                    info->delta_ckv->graph_key_vector[l].key)
                {
                    deltaKey = TRUE;
                    break;
                }
            }

            if (deltaKey)
                break;
        }

        if (!deltaKey)
            return AR_ENOTEXIST;
            //continue;//return AR_ENOTEXIST as there is no difference
    }

    //Search LUT for Value Entry
    offset = ci_cal_lut.chunk_offset + ckv_entry->offset_cal_lut;
    status = FileManReadBuffer(&key_table_header, sizeof(KeyTableHeader),
        &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read value lookup table header",
            status);
    }

    if (0 == key_table_header.num_entries)
    {
        /* The lookup table should not be empty. If this is true,
         * then there is an issue with the ACDB file. */

        if (0 == module_ckv.num_keys)
        {
            ACDB_ERR("Error[%d]: Subgraph (0x%x) | There is a module in this"
                " subgraph with missing default calibration data. Check the"
                " subgraph.",
                AR_EFAILED, info->subgraph_id);
        }
        else
        {
            ACDB_ERR("Error[%d]: Subgraph (0x%x) | There is a module in this"
                " subgraph with missing calibration data for the module ckv"
                " below: ",
                AR_EFAILED, info->subgraph_id);

            LogKeyVector(&module_ckv, CAL_KEY_VECTOR);
        }

        return AR_EFAILED;
    }

    key_table_entry_size = (module_ckv.num_keys * sizeof(uint32_t))
        + sizeof(AcdbCkvLutEntryOffsets);
    key_table_size = key_table_header.num_entries * key_table_entry_size;

    //Setup Table Information
    table_info.table_offset = offset;
    table_info.table_size = key_table_size;
    table_info.table_entry_size = key_table_entry_size;

    //Setup Search Information
    search_info.num_search_keys = key_table_header.num_keys;
    search_info.num_structure_elements =
        key_table_header.num_keys + 3;//Values + DEF + DOT + DOT2
    search_info.table_entry_struct = &glb_buf_3[ckv_lut_entry_index];

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        //ACDB_ERR("Error[%d]: Unable to find cal key vector. "
        //    "No matching values were found", status);

        //if (info->op == ACDB_OP_GET_SIZE)
        //    LogKeyVector(&module_ckv, CAL_KEY_VECTOR);

        return status;
    }

    ACDB_MEM_CPY_SAFE(&info->data_offsets, sizeof(AcdbCkvLutEntryOffsets),
        &glb_buf_3[ckv_lut_entry_index + module_ckv.num_keys],
        sizeof(AcdbCkvLutEntryOffsets));

    info->module_ckv->num_keys = module_ckv.num_keys;

    if(info->module_ckv->num_keys > 0)
        ACDB_MEM_CPY_SAFE(info->module_ckv->graph_key_vector,
            module_ckv.num_keys * sizeof(AcdbKeyValuePair),
            module_ckv.graph_key_vector,
            module_ckv.num_keys * sizeof(AcdbKeyValuePair));


    /* Hypervisor
     * If we encounter the Default CKV
     * Indiciate that the default CKV has been found
     * Store the LUT Entry Offsets(DEF DOT, DOT2) separately for the default CKV
     * Skip getting data for the default CKV if the next CKV is what we are
     * looking for and it contains one of the IIDs that are also associated
     * with the default CKV,
     */

    if (module_ckv.num_keys == 0)
    {
        info->is_default_module_ckv = TRUE;
        //info->ignore_get_default_data = TRUE;

        //Read IIDs into a tracking list. For non-default CKVs, if a module is found remove it from the default CKV IID list
    }
    else
    {
        info->is_default_module_ckv = FALSE;
        info->ignore_get_default_data = TRUE;
    }

    return status;
}

/**
* \brief
*		Calculates the Delta Key Vector which is the difference between the
*       old and new key vector and also updates the is_first_time flag in the
*       context info struct
*
* \depends
*       The Delta CKV and CKV[New] in the context info struct must be freed
*       when no longer in use
*
* \param[in] ckv_new: The current calibration key vector
* \param[in] ckv_prior: The previous calibration key vector
* \param[out] context_info: Context info containing the Delta CKV and CKV[New]
*             to be updated
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbComputeDeltaCKV(
    AcdbGraphKeyVector* ckv_new, AcdbGraphKeyVector* ckv_prior,
    AcdbAudioCalContextInfo *context_info)
{
    int32_t status = AR_EOK;
    bool_t first_time = FALSE;
    uint32_t kv_size = 0;
    AcdbGraphKeyVector *cmdKV = NULL;
    AcdbGraphKeyVector *deltaKV = NULL;

    if (IsNull(ckv_new) || IsNull(ckv_prior) || IsNull(context_info))
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) is null.",
            AR_EBADPARAM);

        return AR_EBADPARAM;
    }

    cmdKV = ACDB_MALLOC(AcdbGraphKeyVector, 1);
    if (IsNull(cmdKV))
    {
        ACDB_ERR("Error[%d]: Insufficient memory for allocating ckv",
            AR_ENOMEMORY);
        return AR_ENOMEMORY;
    }

    (void)ar_mem_set(cmdKV, 0, sizeof(AcdbGraphKeyVector));

    if (ckv_prior->num_keys == 0)
    {
        first_time = TRUE;
        cmdKV->num_keys = ckv_new->num_keys;

        if(cmdKV->num_keys > 0)
            cmdKV->graph_key_vector =
            ACDB_MALLOC(AcdbKeyValuePair, cmdKV->num_keys);

        if (IsNull(cmdKV->graph_key_vector) && cmdKV->num_keys > 0)
        {
            status = AR_ENOMEMORY;
            ACDB_ERR("Error[%d]: Insufficient memory for allocating ckv",
                status);
            goto end;
        }

        kv_size = cmdKV->num_keys * sizeof(AcdbKeyValuePair);
        (void)ar_mem_set(cmdKV->graph_key_vector, 0, kv_size);
        ACDB_MEM_CPY_SAFE(cmdKV->graph_key_vector, kv_size,
            ckv_new->graph_key_vector, kv_size);
    }
    else
    {
        status = AcdbSort2(
            ckv_prior->num_keys * sizeof(AcdbKeyValuePair),
            ckv_prior->graph_key_vector,
            sizeof(AcdbKeyValuePair), 0);

        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to sort the old CKV");
            goto end;
        }

        status = AcdbSort2(
            ckv_new->num_keys * sizeof(AcdbKeyValuePair),
            ckv_new->graph_key_vector,
            sizeof(AcdbKeyValuePair), 0);

        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to sort the new CKV");
            goto end;
        }

        //compute delta KV (from prior and new) and number of keys
        if (ckv_prior->num_keys != ckv_new->num_keys)
        {
            ACDB_ERR("CKV[old] num of keys = %d do not match "
                "CKV[new] num of keys = %d",
                ckv_prior->num_keys,
                ckv_new->num_keys);
            status = AR_EFAILED;
            goto end;
        }

        cmdKV->num_keys = ckv_new->num_keys;

        if (cmdKV->num_keys > 0)
            cmdKV->graph_key_vector =
            ACDB_MALLOC(AcdbKeyValuePair, cmdKV->num_keys);

        if (IsNull(cmdKV->graph_key_vector) && cmdKV->num_keys > 0)
        {
            ACDB_ERR("Error[%d]: Insufficient memory for allocating ckv",
                AR_ENOMEMORY);
            status = AR_ENOMEMORY;
            goto end;
        }

        kv_size = cmdKV->num_keys * sizeof(AcdbKeyValuePair);
        (void)ar_mem_set(cmdKV->graph_key_vector, 0, kv_size);

        for (uint32_t i = 0; i < cmdKV->num_keys; i++)
        {
            ACDB_MEM_CPY_SAFE(cmdKV->graph_key_vector, kv_size,
                ckv_new->graph_key_vector, kv_size);
        }

        uint32_t key_count = 0;
        for (uint32_t i = 0; i < ckv_prior->num_keys; i++)
        {
            if (ckv_prior->graph_key_vector[i].key !=
                ckv_new->graph_key_vector[i].key)
            {
                status = AR_ENOTEXIST;
                break;
            }
            if (ckv_prior->graph_key_vector[i].value !=
                ckv_new->graph_key_vector[i].value)
                key_count++;
        }

        if (AR_EOK != status)
        {
            ACDB_ERR_MSG_1("CKV[new] and CKV[old] have ""different sets of "
                "keys", status);
            goto end;
        }

        if (key_count == 0)
        {
            ACDB_ERR("Error[%d]: No calibration data can be found. There is no"
                " difference between CKV[new] and CKV[old].", AR_ENOTEXIST);

            status = AR_ENOTEXIST;
            goto end;
        }

        deltaKV = ACDB_MALLOC(AcdbGraphKeyVector, 1);
        if (deltaKV == NULL)
        {
            ACDB_ERR("Error[%d]: Insufficient memory for allocating delta ckv",
                AR_ENOMEMORY);
            status = AR_ENOMEMORY;
            goto end;
        }
        (void)ar_mem_set(deltaKV, 0, sizeof(AcdbGraphKeyVector));

        deltaKV->num_keys = key_count;
        deltaKV->graph_key_vector = ACDB_MALLOC(AcdbKeyValuePair, key_count);
        if (IsNull(deltaKV->graph_key_vector))
        {
            ACDB_ERR("Error[%d]: Insufficient memory to allocate delta ckv key"
                " value pair list", AR_ENOMEMORY);
            status = AR_ENOMEMORY;
            goto end;
        }

        (void)ar_mem_set(deltaKV->graph_key_vector, 0,
            key_count * sizeof(AcdbKeyValuePair));

        key_count = 0;
        for (uint32_t i = 0; i < ckv_prior->num_keys; i++)
        {
            if (ckv_prior->graph_key_vector[i].value !=
                ckv_new->graph_key_vector[i].value)
            {
                deltaKV->graph_key_vector[key_count].key =
                    ckv_new->graph_key_vector[i].key;
                deltaKV->graph_key_vector[key_count].value =
                    ckv_new->graph_key_vector[i].value;
                key_count++;
            }
        }
    }

end:
    if (AR_FAILED(status))
    {
        if (!IsNull(cmdKV))
        {
            ACDB_FREE(cmdKV->graph_key_vector);
            ACDB_FREE(cmdKV);
        }

        if (!IsNull(deltaKV))
        {
            ACDB_FREE(deltaKV->graph_key_vector);
            ACDB_FREE(deltaKV);
        }

        return status;
    }

    context_info->ckv = cmdKV;
    context_info->delta_ckv = deltaKV;
    context_info->is_first_time = first_time;

    return status;
}

/**
* \brief
*		Frees memory allocated to the CKV and Delta CKV
*
* \param[in/out] info: Context info containing the Delta CKV and CKV[New]
* \return none
*/
void AcdbClearAudioCalContextInfo(AcdbAudioCalContextInfo* info)
{
    if (IsNull(info))
    {
        ACDB_ERR("Error[%d]: Input parameter is null",
            AR_EBADPARAM);
        return;
    }

    if (!IsNull(info->ckv))
    {
        if (!IsNull(info->ckv->graph_key_vector))
            ACDB_FREE(info->ckv->graph_key_vector);
        ACDB_FREE(info->ckv);
    }

    if (!IsNull(info->delta_ckv))
    {
        if (!IsNull(info->delta_ckv->graph_key_vector))
            ACDB_FREE(info->delta_ckv->graph_key_vector);
        ACDB_FREE(info->delta_ckv);
    }

    info->module_ckv = NULL;
    info->delta_ckv = NULL;
    info->ckv = NULL;

    return;
}

int32_t AcdbCmdGetSubgraphCalDataNonPersist(AcdbSgIdCalKeyVector *req,
    AcdbBlob *rsp, uint32_t rsp_struct_size)
{
    int32_t status = AR_EOK;
    bool_t found_sg = FALSE;
    bool_t has_cal_data = FALSE;
    uint32_t offset = 0;
    uint32_t prev_sg_cal_lut_offset = 0;
    uint32_t prev_subgraph_id = 0;
    uint32_t sg_cal_lut_offset = 0;
    uint32_t default_ckv_entry_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t num_subgraph = 0;
    uint32_t num_subgraph_found = 0;
    ChunkInfo ci_sg_cal_lut = { 0 };
    AcdbSgCalLutHeader sg_cal_lut_header = { 0 };
    AcdbCalKeyTblEntry ckv_entry = { 0 };
    AcdbAudioCalContextInfo info;
    AcdbUintList subgraph_list = { 0 };

    (void)ar_mem_set(&info, 0, sizeof(AcdbAudioCalContextInfo));

    if (rsp_struct_size < sizeof(AcdbBlob))
    {
        ACDB_ERR("Error[%d]: The response structure size is less than %d",
            AR_EBADPARAM, sizeof(AcdbBlob));
        return AR_EBADPARAM;
    }

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null");
        return AR_EBADPARAM;
    }

    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    ci_sg_cal_lut.chunk_id = ACDB_CHUNKID_CALSGLUT;
    status = ACDB_GET_CHUNK_INFO(&ci_sg_cal_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration LUT "
            "chunk information", status);
        return status;
    }

    info.param_type = ACDB_DATA_NON_PERSISTENT;
    if (rsp->buf_size > 0 && !IsNull(rsp->buf))
    {
        info.op = ACDB_OP_GET_DATA;
        memset(rsp->buf, 0, rsp->buf_size);
    }
    else
        info.op = ACDB_OP_GET_SIZE;

    if (info.op == ACDB_OP_GET_SIZE)
    {
        //Log CKV when this API is called for the first time
        ACDB_DBG("Retrieving non-persistent calibration for "
            "the following cal key vector:");
        ACDB_DBG("CKV[new]:");
        LogKeyVector(&req->cal_key_vector_new, CAL_KEY_VECTOR);
        ACDB_DBG("CKV[old]:");
        LogKeyVector(&req->cal_key_vector_prior, CAL_KEY_VECTOR);
    }

    /* CKV Setup
     * 1. GLB_BUF_2 stores the module CKV that will be used to locate data in
     * the heap(if it exists)
     * 2. The Delta CKV and CKV[New] are allocated on the heap by
     * AcdbComputeDeltaCKV
     *
     * tmp - stores the amount of padding after graph_key_vectornum_keys
     * tmp2 - stores the position of the KeyValuePair list
     *
     * The first info.module_ckv->graph_key_vector assignment has the effect
     * of storing the address of the pointer in glb_buf_2 after
     * graph_key_vector.num_keys
     *
     * The second info.module_ckv->graph_key_vector assignment has the effect
     * of pointer the info.module_ckv->graph_key_vector to the actual list
     * of key value pairs
     *
     * Whats inside global buffer 2 after these operations?
     *
     * The first 'sizeof(AcdbGraphKeyVector)' bytes is AcdbGraphKeyVector
     * followed by 'sizeof(AcdbKeyValuePair) * num_keys' bytes which is
     * the KV list
     */
    info.module_ckv = (AcdbGraphKeyVector*)&glb_buf_2[0];
    uint32_t tmp = (sizeof(AcdbGraphKeyVector) - sizeof(AcdbKeyValuePair *)) / sizeof(uint32_t);
    uint32_t tmp2 = sizeof(AcdbGraphKeyVector) / sizeof(uint32_t);
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp];
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp2];

    status = AcdbComputeDeltaCKV(
        &req->cal_key_vector_new, &req->cal_key_vector_prior, &info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get the delta CKV", status);
        AcdbClearAudioCalContextInfo(&info);
        return status;
    }

    offset = ci_sg_cal_lut.chunk_offset;
    status = FileManReadBuffer(&num_subgraph,
        sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of Subgraphs",
            status);
        AcdbClearAudioCalContextInfo(&info);
        return status;
    }

    /* Sort the subgraph list so that the linear search for subgraph
     * takes less time. The Subgraph CAL LUT sorts the subgraphs. By
     * sorting the input subgraph list we can locate the subgraphs
     * in the chunk sequentially. Therefore there is no need to reset
     * the table offset */
    status = AcdbSort2(req->num_sg_ids * sizeof(uint32_t),
        req->sg_ids, sizeof(uint32_t), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort subgraph list",
            status);
        AcdbClearAudioCalContextInfo(&info);
        return status;
    }

    GetOffloadedParamList(&info.offloaded_parameter_list);
    if (info.offloaded_parameter_list.count == 0)
    {
        ACDB_DBG("Error[%d]: No offloaded parameters found. Skipping..",
            status);
    }

    prev_sg_cal_lut_offset = offset;
    for (uint32_t i = 0; i < req->num_sg_ids; i++)
    {
        found_sg = FALSE;
        has_cal_data = FALSE;
        /*offset = tmp_offset;*/

        while(offset < ci_sg_cal_lut.chunk_offset + ci_sg_cal_lut.chunk_size)
        {
            status = FileManReadBuffer(&sg_cal_lut_header,
                sizeof(AcdbSgCalLutHeader), &offset);
            if (AR_FAILED(status))
            {
                ACDB_DBG("Error[%d]: Unable to read Subgraph "
                    "Cal LUT header", status);
            }

            if (req->sg_ids[i] == sg_cal_lut_header.subgraph_id)
            {
                found_sg = TRUE;
                prev_sg_cal_lut_offset = offset - sizeof(AcdbSgCalLutHeader);
                prev_subgraph_id = sg_cal_lut_header.subgraph_id;
                break;
            }
            else if (
                (req->sg_ids[i] < sg_cal_lut_header.subgraph_id) ||
                (req->sg_ids[i] > prev_subgraph_id &&
                 req->sg_ids[i] < sg_cal_lut_header.subgraph_id))
            {
                /* The input subgraph is a voice subgraph or it
                 * does not exist */
                offset = prev_sg_cal_lut_offset;
                break;
            }
            else
            {
                //Go to next Subgraph entry
                offset += (sg_cal_lut_header.num_ckv_entries
                        * sizeof(AcdbCalKeyTblEntry));
            }
        }

        if (!found_sg)
        {
            if(info.op == ACDB_OP_GET_SIZE)
                ACDB_DBG("Error[%d]: Subgraph(%x) is not an audio subgraph."
                    " Skipping..",
                    AR_ENOTEXIST, req->sg_ids[i]);
            continue;
        }

        if (sg_cal_lut_header.num_ckv_entries == 0)
        {
            ACDB_DBG("Error[%d]: Subgraph(%x) contains zero CKV entries in"
                " the Subgraph Cal LUT. At least one entry should be"
                " present. Skipping..",
                AR_ENOTEXIST, req->sg_ids[i]);
            continue;
        }

        info.ignore_get_default_data =
            sg_cal_lut_header.num_ckv_entries == 1 ? FALSE : TRUE;

        //The default CKV will be skipped and handeled last
        if (sg_cal_lut_header.num_ckv_entries > 1 && info.is_first_time)
            sg_cal_lut_header.num_ckv_entries++;

        for (uint32_t k = 0; k < sg_cal_lut_header.num_ckv_entries; k++)
        {
            /* The Default CKV is always the first CKV in the list of CKVs to
             * search. It will be skipped and processed last */
            if ((k == sg_cal_lut_header.num_ckv_entries - 1) &&
                info.ignore_get_default_data == TRUE && info.is_first_time)
            {
                sg_cal_lut_offset = default_ckv_entry_offset;
                info.ignore_get_default_data = FALSE;

                status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                    &sg_cal_lut_offset);
            }
            else
            {
                status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                    &offset);
                sg_cal_lut_offset = offset;
            }

            if (AR_FAILED(status))
            {
                AcdbClearAudioCalContextInfo(&info);
                return status;
            }

            info.subgraph_id = sg_cal_lut_header.subgraph_id;

            status = AcdbFindModuleCKV(&ckv_entry, &info);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                continue;
            }
            else if(AR_FAILED(status))
            {
                AcdbClearAudioCalContextInfo(&info);
                return status;
            }

            if (info.is_default_module_ckv)
            {
                default_ckv_entry_offset =
                    sg_cal_lut_offset - sizeof(ckv_entry);
            }

            //Get Calibration
            status = AcdbGetSubgraphCalibration(&info, &blob_offset, rsp);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                //No calibration found for subgraph with module ckv_entry
                //has_cal_data = FALSE;
                continue;
            }
            else if (AR_FAILED(status) && status != AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: An error occured while getting "
                    "calibration data for Subgraph(%x)", status,
                    sg_cal_lut_header.subgraph_id);
                AcdbClearAudioCalContextInfo(&info);
                return status;
            }

            if (info.is_default_module_ckv && info.ignore_get_default_data)
            {
                continue;
            }

            has_cal_data = TRUE;
        }

        if (AR_FAILED(status) && !has_cal_data)
        {
            ACDB_DBG("Warning[%d]: Unable to retrieve calibration data for "
                "Subgraph(%x). Skipping..", status,
                sg_cal_lut_header.subgraph_id);
            status = AR_EOK;
        }
        else
        {
            status = AR_EOK;
            num_subgraph_found++;
        }
    }

    if (num_subgraph_found == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_DBG("Error[%d]: No calibration found", status);
    }

    //Clean Up Context Info
    AcdbClearAudioCalContextInfo(&info);

    return status;
}

int32_t GetVcpmSubgraphCalTable(uint32_t num_subgraphs, uint32_t subgraph_id,
    uint32_t *file_offset, AcdbVcpmSubgraphCalTable *subgraph_cal_table)
{
    int32_t status = AR_EOK;
    bool_t found = FALSE;
    uint32_t offset = *file_offset;

    if (IsNull(subgraph_cal_table) || IsNull(file_offset))
    {
        return AR_EBADPARAM;
    }

    for (uint32_t i = 0; i < num_subgraphs; i++)
    {
        status = FileManReadBuffer(subgraph_cal_table, sizeof(AcdbVcpmSubgraphCalTable), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Module Header.", status);
            return status;
        }

        if (subgraph_id == subgraph_cal_table->subgraph_id)
        {
            *file_offset = offset;
            found = TRUE;
            return AR_EOK;
        }

        /* Minus sizeof <Major, Minor, Offset in MKT, Num CKV Tbls> since
        this was read as part of FileManReadBuffer for subgraph_cal_table */
        offset += subgraph_cal_table->table_size - (4 * sizeof(uint32_t));
    }

    status = !found ? AR_ENOTEXIST : status;

    return status;
}

int32_t GetVcpmMasterKeyTable(AcdbVcpmBlobInfo *vcpm_info,
	uint32_t file_offset, AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t master_key_table_file_offset = 0;
    uint32_t cal_key_id_table_file_offset = 0;
    uint32_t num_keys = 0;
    uint32_t num_keys_found = 0;
    uint32_t sz_key_table = 0;
    ChunkInfo ci_vcpm_master_key = { 0 };
    AcdbVcpmKeyInfo *master_key_list = NULL;
    AcdbUintList cal_key_id_list = { 0 };
    uint32_t found_key_index = 0;
    AcdbBlob key_bit_check_list = { 0 };

    ci_vcpm_master_key.chunk_id = ACDB_CHUNKID_VCPM_MASTER_KEY;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_master_key);
    if (AR_FAILED(status)) return status;

    master_key_table_file_offset = ci_vcpm_master_key.chunk_offset + file_offset;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &master_key_table_file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number "
            "of vcpm master keys.", status);
        return status;
    }

    //determine what keys will actually be in the master key table
    status = FileManGetFilePointer2(
        (void**)&master_key_list, master_key_table_file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get "
            "pointer to vcpm master keys.", status);
        return status;
    }

    if (vcpm_info->op == ACDB_OP_GET_DATA && num_keys > 0)
    {
        key_bit_check_list.buf_size =
            ACDB_ALIGN_8_BYTE(num_keys);
        key_bit_check_list.buf =
            ACDB_MALLOC(uint8_t, key_bit_check_list.buf_size);
        if (IsNull(key_bit_check_list.buf))
            return AR_ENOMEMORY;

        status = ar_mem_set(
            key_bit_check_list.buf, 0, key_bit_check_list.buf_size);
        if (AR_FAILED(status))
        {
            ACDB_DBG("Error[%d]: Failed to memset key check list.", status);
            goto end;
        }
    }

    /* determine master key table based on found cal key id tables */
    for (uint32_t i = 0; i < num_keys; i++)
    {
        for (uint32_t j = 0; j < vcpm_info->
            cal_key_id_table_offset_list.count; j++)
        {
            cal_key_id_table_file_offset =
                vcpm_info->cal_key_id_table_offset_list.list[j];

            status = FileManReadBuffer(
                &cal_key_id_list.count, sizeof(uint32_t),
                &cal_key_id_table_file_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read num cal key ids.", status);
                goto end;
            }

            status = FileManGetFilePointer2(
                (void**)&cal_key_id_list.list, cal_key_id_table_file_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read cal key table.", status);
                goto end;
            }

            if (0 == AcdbDataBinarySearch2(
                cal_key_id_list.list, cal_key_id_list.count * sizeof(uint32_t),
                &master_key_list[i].key_id, 1, 1, &found_key_index))
            {
                if (vcpm_info->op == ACDB_OP_GET_DATA)
                    ((uint8_t*)key_bit_check_list.buf)[i] = 1;
                num_keys_found++;
                break;
            }
        }
    }

    sz_key_table = num_keys_found * sizeof(AcdbVcpmKeyInfo);

    switch (vcpm_info->op)
    {
    case ACDB_OP_GET_SIZE:
        vcpm_info->chunk_master_key.size += sizeof(uint32_t);

        if (sz_key_table > 0)
        {
            vcpm_info->chunk_master_key.size += sz_key_table;
        }

        break;
    case ACDB_OP_GET_DATA:

        if (IsNull(rsp->buf))
        {
            status = AR_EFAILED;
            goto end;
        }

        //Write Num Keys
        if(vcpm_info->chunk_master_key.offset
            + sizeof(uint32_t) > tot_cal_size)
        {
            status = AR_ENEEDMORE;
            goto end;
        }

        ACDB_MEM_CPY_SAFE(
            (uint8_t*)rsp->buf + vcpm_info->chunk_master_key.offset,
            sizeof(uint32_t), &num_keys_found, sizeof(uint32_t));
        vcpm_info->chunk_master_key.offset += sizeof(uint32_t);

        if (sz_key_table == 0)
            goto end;

        //Write Chunk data
        if (vcpm_info->chunk_master_key.offset
            + sz_key_table > tot_cal_size)
        {
            status = AR_ENEEDMORE;
            goto end;
        }

        if (num_keys == num_keys_found)
        {
            //just write the entire table
            status = FileManReadBuffer(
                (uint8_t*)rsp->buf + vcpm_info->chunk_master_key.offset,
                sz_key_table, &master_key_table_file_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read "
                    "number of vcpm master keys.", status);
                goto end;
            }
        }
        else
        {
            //only write the key for the ckv data tables that were found
            uint32_t key_offset = 0;
            for (uint32_t i = 0; i < num_keys; i++)
            {
                if (((uint8_t*)key_bit_check_list.buf)[i] == 0)
                    continue;

                ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf
                    + vcpm_info->chunk_master_key.offset + key_offset,
                    sizeof(AcdbVcpmKeyInfo),
                    &master_key_list[i], sizeof(AcdbVcpmKeyInfo));
                key_offset += sizeof(AcdbVcpmKeyInfo);
            }
        }

        vcpm_info->chunk_master_key.offset += sz_key_table;

        break;
    default:
        break;
    }

end:
    if (vcpm_info->op == ACDB_OP_GET_DATA)
        ACDB_FREE(key_bit_check_list.buf);

    return status;
}

int32_t IsDefaultVcpmCalibrationKeyIDTable(AcdbVcpmBlobInfo *vcpm_info,
    uint32_t table_offset)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    ChunkInfo ci_vcpm_cal_key = { 0 };

    ci_vcpm_cal_key.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_key);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to get VCPM Cal Key Table Chunk");
        return status;
    }

    offset = ci_vcpm_cal_key.chunk_offset + table_offset;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice calibration keys.", status);
        return status;
    }

    vcpm_info->is_default_module_ckv = num_keys == 0 ? TRUE : FALSE;

    if (vcpm_info->is_default_module_ckv &&
        vcpm_info->ignore_get_default_data)
        return AR_EOK;

    return status;
}


int32_t GetVcpmCalibrationKeyIDTable(AcdbVcpmBlobInfo *vcpm_info,
	uint32_t table_offset, AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    uint32_t sz_key_table = 0;
    ChunkInfo ci_vcpm_cal_key = { 0 };

    ci_vcpm_cal_key.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_key);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to get VCPM Cal Key Table Chunk");
        return status;
    }

    offset = ci_vcpm_cal_key.chunk_offset + table_offset;

    if (vcpm_info->op == ACDB_OP_GET_SIZE &&
        vcpm_info->cal_key_id_table_offset_list.count
        + 1 < GLB_BUF_3_LENGTH / 2)
    {
        vcpm_info->cal_key_id_table_offset_list
            .list[vcpm_info->cal_key_id_table_offset_list.count] = offset;
        vcpm_info->cal_key_id_table_offset_list.count++;
    }
    else if (vcpm_info->cal_key_id_table_offset_list.count
        + 1 > GLB_BUF_3_LENGTH / 2)
    {
        ACDB_ERR("Error[%d]: No space to store key id table offsets.",
            AR_ENOMEMORY);
        return AR_ENOMEMORY;
    }

    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of"
            " voice calibration keys.", status);
        return status;
    }

    sz_key_table = num_keys * sizeof(uint32_t);

    switch (vcpm_info->op)
    {
    case ACDB_OP_GET_SIZE:

        vcpm_info->chunk_cal_key_id.size += sizeof(uint32_t);

        if (sz_key_table > 0)
        {
            vcpm_info->chunk_cal_key_id.size += sz_key_table;
        }
        break;
    case ACDB_OP_GET_DATA:

        if (IsNull(rsp->buf)) return AR_EFAILED;

        /* If the Master Key table doesnt have any keys, then it is evident
         * that the voice key table is empty. It is a valid scenario if
         * num_keys is zero.
         */

        //Write Cal Key Table to Voc Cal Key Chunk
        //Write Num Keys

        if ((vcpm_info->chunk_cal_key_id.offset + sizeof(num_keys))
            > tot_cal_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + vcpm_info->chunk_cal_key_id.offset,
            sizeof(num_keys), &num_keys, sizeof(num_keys));
        vcpm_info->chunk_cal_key_id.offset += sizeof(num_keys);

        if (sz_key_table > 0)
        {
            //Write Key IDs
            if ((vcpm_info->chunk_cal_key_id.offset + sz_key_table)
                > tot_cal_size)
            {
                return AR_ENEEDMORE;
            }

            status = FileManReadBuffer(
                (uint8_t*)rsp->buf + vcpm_info->chunk_cal_key_id.offset,
                sz_key_table, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read voice calibration keys.",
                    status);
                return status;
            }
            vcpm_info->chunk_cal_key_id.offset += sz_key_table;
        }
        break;
    default:
        break;
    }

    return status;
}

int32_t GetVcpmCalibrationKeyValueTable(AcdbVcpmBlobInfo *vcpm_info, uint32_t table_offset,
	AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    uint32_t sz_key_table = 0;
    ChunkInfo ci_vcpm_cal_lut = { 0 };

    ci_vcpm_cal_lut.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_LUT;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_lut);
    if (AR_FAILED(status)) return status;

    offset = ci_vcpm_cal_lut.chunk_offset + table_offset;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice calibration key values.", status);
        return status;
    }

    sz_key_table = num_keys * sizeof(uint32_t);

    switch (vcpm_info->op)
    {
    case ACDB_OP_GET_SIZE:

        vcpm_info->chunk_cal_key_lut.size += sizeof(uint32_t);

        if (sz_key_table > 0)
        {
            vcpm_info->chunk_cal_key_lut.size += sz_key_table;
        }
        break;
    case ACDB_OP_GET_DATA:

        if (IsNull(rsp->buf)) return AR_EFAILED;

        //Write Num Keys
        if ((vcpm_info->chunk_cal_key_lut.offset + sizeof(num_keys))
            > tot_cal_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + vcpm_info->chunk_cal_key_lut.offset,
            sizeof(num_keys), &num_keys, sizeof(num_keys));
        vcpm_info->chunk_cal_key_lut.offset += sizeof(num_keys);

        if (sz_key_table > 0)
        {
            //Write Key Values
            offset += sizeof(uint32_t);//num entries is always 1
            if ((vcpm_info->chunk_cal_key_lut.offset + sz_key_table)
                > tot_cal_size)
            {
                return AR_ENEEDMORE;
            }

            status = FileManReadBuffer((uint8_t*)rsp->buf +
                vcpm_info->chunk_cal_key_lut.offset, sz_key_table, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read voice calibration key values.", status);
                return status;
            }
            vcpm_info->chunk_cal_key_lut.offset += sz_key_table;
        }
        break;
    default:
        break;
    }

    return status;
}

int32_t GetVcpmModuleParamPair(
    AcdbVcpmBlobInfo *vcpm_info, AcdbMiidPidPair *id_pair,
    bool_t *is_offloaded_param, bool_t *should_skip_param,
    AcdbVcpmParamInfo *param_info,
    uint32_t table_offset, AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    ChunkInfo ci_vcpm_cal_def = { 0 };
    AcdbHwAccelMemType mem_type = ACDB_HW_ACCEL_MEM_TYPE(vcpm_info->proc_id);
    AcdbIidRefCount *iid_ref = NULL;
    uint32_t proc_domain_id = 0;

    if (IsNull(vcpm_info) || IsNull(id_pair) ||
        IsNull(param_info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_vcpm_cal_def.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_DEF;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_def);
    if (AR_FAILED(status)) return status;

    //Skip num_mid_pid_pairs
    offset = ci_vcpm_cal_def.chunk_offset + table_offset + sizeof(uint32_t);

    status = FileManReadBuffer(id_pair, sizeof(AcdbMiidPidPair), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read <iid, pid>.", status);
        return status;
    }

    if (vcpm_info->should_filter_cal_by_proc_domain)
    {
        status = DataProcGetProcDomainForModule(
            vcpm_info->sg_mod_iid_map,
            id_pair->module_iid,
            &proc_domain_id);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to get proccessor domain ID for "
                "sg: 0x%x iid: 0x%x",
                status, vcpm_info->subgraph_id, id_pair->module_iid);
            //return status;
        }

        if ((proc_domain_id != ACDB_HW_ACCEL_PROC_ID(vcpm_info->proc_id)) && AR_SUCCEEDED(status))
        {
            //go to next parameter
            *should_skip_param = TRUE;
            return AR_EOK;
        }
    }

    if (vcpm_info->should_check_hw_accel)
    {
        status = DataProcIsHwAccelParam(vcpm_info->hw_accel_module_list_offset,
            id_pair->module_iid, id_pair->parameter_id);

        *should_skip_param = TRUE;

        switch (mem_type)
        {
        case ACDB_HW_ACCEL_MEM_DEFAULT:
            if (AR_SUCCEEDED(status)) return AR_EOK;
            break;
        case ACDB_HW_ACCEL_MEM_CMA:
            if (AR_FAILED(status)) return AR_EOK;
            break;
        case ACDB_HW_ACCEL_MEM_BOTH:
            /*This should not occur, but is here to resolve a
            compiler warning. Not possible since GSL should only
            pass in DEFAULT or CMA. Return success to skip param*/
            return AR_EOK;
        }

        *should_skip_param = FALSE;
        status = AR_EOK;
    }


    iid_ref = (AcdbIidRefCount*)vcpm_info->referenced_iid_list.list;

    if (!vcpm_info->is_default_module_ckv &&
        !vcpm_info->ignore_iid_list_update)
    {
        if ((iid_ref)->module_iid != id_pair->module_iid &&
            vcpm_info->referenced_iid_list.count > 0)
            iid_ref += vcpm_info->referenced_iid_list.count - 1;

        //Add IIDs to list and ignore get data
        if ((iid_ref)->module_iid != id_pair->module_iid &&
            vcpm_info->referenced_iid_list.count == 0)
        {
            (iid_ref)->module_iid = id_pair->module_iid;
            (iid_ref)->ref_count = 1;
            vcpm_info->referenced_iid_list.count++;
        }
        else if ((iid_ref)->module_iid != id_pair->module_iid)
        {
            iid_ref++;
            iid_ref->module_iid = id_pair->module_iid;
            iid_ref->ref_count = 1;
            vcpm_info->referenced_iid_list.count++;
        }
        else
        {
            /* Increase ref count of the current <IID, Ref Count> Obj */
            (iid_ref)->ref_count++;
        }
    }
    else if (vcpm_info->is_default_module_ckv)
    {
        /* For default CKVs, if the module is in the default data list, remove it */
        if (!IsNull(vcpm_info->referenced_iid_list.list))
        {
            bool_t found_iid = FALSE;
            for (uint32_t j = 0; j < vcpm_info->
                referenced_iid_list.count; j++)
            {
                if ((id_pair->module_iid == iid_ref->module_iid)
                    && iid_ref->ref_count > 0)
                {
                    iid_ref->ref_count--;
                    found_iid = TRUE;
                    break;
                }
                else if ((id_pair->module_iid == iid_ref->module_iid)
                    && iid_ref->ref_count <= 0)
                {
                    found_iid = TRUE;
                    *should_skip_param = TRUE;
                    return AR_EOK;
                }

                iid_ref++;
            }

            if (found_iid)
            {
                *should_skip_param = TRUE;
                return AR_EOK;
            }

            *should_skip_param = FALSE;
        }
    }

    if (!IsNull(is_offloaded_param))
    {
        /* Defer handling offloaded params until later as long as
        * is_offloaded_param is not NULL */
        *is_offloaded_param = (AR_EOK == IsOffloadedParam(
            id_pair->parameter_id, &vcpm_info->offloaded_param_list))
            ? TRUE : FALSE;

        if(*is_offloaded_param)
            return status;
    }

    param_info->is_persistent =
        AR_SUCCEEDED(
            IsPidPersistent(id_pair->parameter_id)
        ) ? 0x1 : 0x0;

    switch (vcpm_info->op)
    {
    case ACDB_OP_GET_SIZE:
        vcpm_info->chunk_data_pool.size += sizeof(AcdbMiidPidPair);
        break;
    case ACDB_OP_GET_DATA:
        if (IsNull(rsp->buf)) return AR_EFAILED;

        if((vcpm_info->chunk_data_pool.offset + sizeof(AcdbMiidPidPair))
            > tot_cal_size)
            return AR_ENEEDMORE;

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + vcpm_info->chunk_data_pool.offset,
            sizeof(AcdbMiidPidPair), id_pair, sizeof(AcdbMiidPidPair));

        param_info->offset_vcpm_data_pool =
            vcpm_info->chunk_data_pool.offset -
            vcpm_info->chunk_data_pool.base_offset;
        vcpm_info->chunk_data_pool.offset += sizeof(AcdbMiidPidPair);
        break;
    default:
        break;
    }
    return status;
}

int32_t GetVcpmParamPayload(
    AcdbVcpmBlobInfo *vcpm_info, AcdbMiidPidPair *id_pair,
    AcdbVcpmParamInfo *param_info, bool_t is_offloaded_param,
    uint32_t table_offset, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t data_pool_blob_offset = 0;
    uint32_t param_size = 0;
    uint32_t padded_param_size = 0;
    uint32_t padding = 0;
    uint32_t error_code = 0;
    uint32_t offloaded_param_size_offset = 0;
    AcdbBlob blob = { 0 };
    AcdbPayload caldata = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbGraphKeyVector kv = { 0 };
    AcdbDataPersistanceType persist_type = ACDB_DATA_UNKNOWN;

    if (IsNull(vcpm_info) || IsNull(id_pair) ||
        IsNull(param_info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    persist_type = (AcdbDataPersistanceType)param_info->is_persistent;

    if (is_offloaded_param)
    {
        if (vcpm_info->op == ACDB_OP_GET_SIZE)
            offloaded_param_size_offset =
            vcpm_info->chunk_data_pool.base_offset
            + vcpm_info->chunk_data_pool.size;
        else if (vcpm_info->op == ACDB_OP_GET_DATA)
            offloaded_param_size_offset =
            vcpm_info->chunk_data_pool.offset;

        data_pool_blob_offset = offloaded_param_size_offset;
        blob.buf_size = offloaded_param_size_offset;
    }
    else
    {
        if (vcpm_info->op == ACDB_OP_GET_SIZE)
            data_pool_blob_offset =
            vcpm_info->chunk_data_pool.base_offset
            + vcpm_info->chunk_data_pool.size;
        else if (vcpm_info->op == ACDB_OP_GET_DATA)
            data_pool_blob_offset =
            vcpm_info->chunk_data_pool.offset;

        //Get data from heap
        blob.buf_size = rsp->buf_size;
    }

    if(vcpm_info->op == ACDB_OP_GET_SIZE)
        blob.buf = NULL;
    else if (vcpm_info->op == ACDB_OP_GET_DATA)
        blob.buf = rsp->buf;

    acdb_heap_request_t heap_req = { 0 };
    heap_req.persist_type = persist_type;
    heap_req.client = ACDB_DATA_ACDB_CLIENT;
    heap_req.key_vector = &kv;
    heap_req.subgraph_id = vcpm_info->subgraph_id;
    heap_req.module_iid = id_pair->module_iid;
    heap_req.param_id = id_pair->parameter_id;
    heap_req.is_offloaded_param = is_offloaded_param;
    heap_req.should_write_iid_pid = FALSE;
    heap_req.blob = &blob;
    heap_req.blob_offset = data_pool_blob_offset;

    status = DataProcGetHeapSubgraphCalData(&heap_req);

    data_pool_blob_offset = heap_req.blob_offset;
    //status = GetSubgraphCalData(
    //    persist_type, ACDB_DATA_ACDB_CLIENT,
    //    &kv, vcpm_info->subgraph_id, id_pair->module_iid,
    //    id_pair->parameter_id, is_offloaded_param,
    //    &data_pool_blob_offset, &blob);

    if (AR_SUCCEEDED(status))
    {
        if (is_offloaded_param)
        {
            data_pool_blob_offset -= offloaded_param_size_offset;
            blob.buf_size -= offloaded_param_size_offset;
        }
        else
            data_pool_blob_offset -= vcpm_info->chunk_data_pool.offset;

        switch (vcpm_info->op)
        {
        case ACDB_OP_GET_SIZE:
            vcpm_info->chunk_data_pool.size +=
                blob.buf_size;
            break;
        case ACDB_OP_GET_DATA:
            if (IsNull(rsp->buf)) return AR_EFAILED;
            vcpm_info->chunk_data_pool.offset += data_pool_blob_offset;
            break;

        default:
            break;
        }

        return status;
    }

    status = AR_EOK;

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool);
    if (AR_FAILED(status)) return status;

    offset = ci_data_pool.chunk_offset + table_offset;
    status = FileManReadBuffer(&param_size, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read parameter size.", status);
        return status;
    }


    if (is_offloaded_param)
    {
        uint32_t tmp_dpo = 0;

        if (vcpm_info->op == ACDB_OP_GET_SIZE)
            offloaded_param_size_offset =
                vcpm_info->chunk_data_pool.base_offset
                + vcpm_info->chunk_data_pool.size;
        else if (vcpm_info->op == ACDB_OP_GET_DATA)
            offloaded_param_size_offset =
                vcpm_info->chunk_data_pool.offset;

        //Make room to write param size and error code later
        tmp_dpo = offloaded_param_size_offset + 2 * sizeof(uint32_t);

        caldata.size = param_size;
        status = FileManGetFilePointer2((void**)&caldata.payload, offset);

        status = GetOffloadedParameterData(
            &caldata, &param_size, rsp, &tmp_dpo);
        if (AR_FAILED(status) && status != AR_ENOTEXIST)
        {
            return status;
        }
        else if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            if (vcpm_info->op == ACDB_OP_GET_SIZE)
                ACDB_ERR("Error[%d]: No file path provided for offloaded "
                    "parameter. <subgraph, module inst., param>"
                    "[0x%x, 0x%x, 0x%x]", status,
                    vcpm_info->subgraph_id, id_pair->module_iid,
                    id_pair->parameter_id);
            status = AR_EOK;
        }

        if (vcpm_info->op == ACDB_OP_GET_DATA)
        {
            vcpm_info->chunk_data_pool.offset = tmp_dpo;
        }

        padded_param_size =
            ACDB_ALIGN_8_BYTE(param_size);
    }
    else
    {
        padding = ACDB_PADDING_8_BYTE(param_size);
        padded_param_size = ACDB_ALIGN_8_BYTE(param_size);
    }

    status = AR_EOK;

    switch (vcpm_info->op)
    {
    case ACDB_OP_GET_SIZE:
        //Write size, errorcode, payload
        vcpm_info->chunk_data_pool.size +=
            2 * sizeof(uint32_t) + padded_param_size;
        break;
    case ACDB_OP_GET_DATA:
        if (IsNull(rsp->buf)) return AR_EFAILED;

        if (is_offloaded_param)
        {
            ACDB_MEM_CPY_SAFE(rsp->buf + offloaded_param_size_offset,
                sizeof(uint32_t), &param_size, sizeof(uint32_t));
            offloaded_param_size_offset += sizeof(uint32_t);

            ACDB_MEM_CPY_SAFE(rsp->buf + offloaded_param_size_offset,
                sizeof(uint32_t), &error_code, sizeof(uint32_t));

            return status;
        }

        //Param Size
        ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->chunk_data_pool.offset,
            sizeof(uint32_t), &param_size, sizeof(uint32_t));
        vcpm_info->chunk_data_pool.offset += sizeof(uint32_t);

        //Error Code
        ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->chunk_data_pool.offset,
            sizeof(uint32_t), &error_code, sizeof(uint32_t));
        vcpm_info->chunk_data_pool.offset += sizeof(uint32_t);

        if (param_size == 0) return status;

        //Payload
        status = FileManReadBuffer(
            (uint8_t*)rsp->buf + vcpm_info->chunk_data_pool.offset,
            (size_t)param_size, &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read parameter payload.", status);
            return status;
        }
        vcpm_info->chunk_data_pool.offset += param_size;

        //Padding
        ar_mem_set((uint8_t*)rsp->buf + vcpm_info->chunk_data_pool.offset,
            0, padding);

        vcpm_info->chunk_data_pool.offset += padding;
        break;

    default:
        break;
    }

    return status;
}

int32_t GetVcpmOffloadedData(
    AcdbVcpmBlobInfo *vcpm_info, AcdbBlob *rsp,
    uint32_t total_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t offset_data_pool = 0;
    bool_t should_skip_param = FALSE;
    AcdbMiidPidPair id_pair = { 0 };
    AcdbVcpmParamInfo param_info = { 0 };
    AcdbUintList datapool_offset_list = { 0 };
    AcdbVcpmOffloadedParamInfo *offloaded_param_info = NULL;
    if (IsNull(vcpm_info) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One ore more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    LinkedListNode *opi_node = vcpm_info->offloaded_param_info_list.p_head;
    if (vcpm_info->offloaded_param_info_list.length == 0)
        return status;
    if (IsNull(opi_node) && vcpm_info->offloaded_param_info_list.length > 0)
    {
        ACDB_ERR("Error[%d]: The offloaded param list is empty although "
            "there are %d params in the list",
            AR_EBADPARAM, vcpm_info->offloaded_param_info_list.length);
        return AR_EBADPARAM;
    }

    //keep track of data offsets
    uint32_t offset_list_index = 0;
    datapool_offset_list.count = vcpm_info->offloaded_param_info_list.length;
    datapool_offset_list.list = (uint32_t*)ACDB_MALLOC(AcdbFileToVcpmDataPoolOffsetInfo, datapool_offset_list.count);

    if (datapool_offset_list.list == NULL)
    {
        ACDB_ERR("Error[%d]: Failed allocate memory", AR_EFAILED);
        goto end;
    }

    ar_mem_set(datapool_offset_list.list, 0, sizeof(AcdbFileToVcpmDataPoolOffsetInfo) * datapool_offset_list.count);

    vcpm_info->ignore_iid_list_update = TRUE;

    do
    {
        offloaded_param_info =
            (AcdbVcpmOffloadedParamInfo*)opi_node->p_struct;

        bool_t found_existing_offset = FALSE;
        AcdbFileToVcpmDataPoolOffsetInfo* offset_pair = NULL;

        /* prevent writing the same payload multiple times in the data pool */
        for (uint32_t i = 0; i < datapool_offset_list.count; i++)
        {
            offset_pair = (AcdbFileToVcpmDataPoolOffsetInfo*)datapool_offset_list.list + i;
            if (offloaded_param_info->file_offset_data_pool == offset_pair->file_offset_data_pool)
            {
                found_existing_offset = TRUE;
                break;
            }
        }

        if (!found_existing_offset)
        {
            //Add new entry
            offset_pair = (AcdbFileToVcpmDataPoolOffsetInfo*)datapool_offset_list.list + offset_list_index;
            offset_pair->file_offset_cal_def = offloaded_param_info->file_offset_cal_def;
            offset_pair->file_offset_data_pool = offloaded_param_info->file_offset_data_pool;
            offset_list_index++;
        }

        if (found_existing_offset)
        {
            param_info.offset_vcpm_data_pool = offset_pair->vcpm_offset_data_pool;
        }
        else
        {
            status = GetVcpmModuleParamPair(
                vcpm_info, &id_pair, NULL, &should_skip_param, &param_info,
                offloaded_param_info->file_offset_cal_def, rsp, total_cal_size);
            if (AR_FAILED(status))
            {
                goto end;
            }

            offset_pair->vcpm_offset_data_pool = param_info.offset_vcpm_data_pool;

            if (should_skip_param)
            {
                ACDB_ERR("skipped iid: %x pid:%x", id_pair.module_iid, id_pair.parameter_id)
                continue;
            }

            offset_data_pool = offloaded_param_info->file_offset_data_pool;
            status = GetVcpmParamPayload(vcpm_info, &id_pair, &param_info, TRUE,
                offset_data_pool, rsp);
            if (AR_FAILED(status))
            {
                goto end;
            }
        }

        /* Update Param Info for offloaded param in the VCPM Subgraph
         * info Chunk */
        if (!IsNull(rsp->buf) && vcpm_info->op == ACDB_OP_GET_DATA)
        {
            if((offloaded_param_info->blob_offset_vcpm_param_info
                + sizeof(AcdbVcpmParamInfo)) > total_cal_size)
                return AR_ENEEDMORE;
            ACDB_MEM_CPY_SAFE(rsp->buf + offloaded_param_info->
                blob_offset_vcpm_param_info, sizeof(AcdbVcpmParamInfo),
                &param_info, sizeof(AcdbVcpmParamInfo));
        }

    } while (TRUE != AcdbListSetNext(&opi_node));

end:
    ACDB_FREE(datapool_offset_list.list);
    return status;
}

int32_t GetVcpmCalDataObject(AcdbVcpmBlobInfo *vcpm_info, uint32_t *cal_obj_size,
	uint32_t *table_offset, AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = *table_offset;
    uint32_t offset_data_pool = 0;
    uint32_t offset_vcpm_ckv_lut = 0;
    uint32_t total_data_offset_found = 0;
    uint32_t tmp_offset = 0;
    bool_t is_offloaded_param = FALSE;
    bool_t should_skip_param = FALSE;
    AcdbVcpmCalDataObj data_obj = { 0 };
    AcdbVcpmParamInfo param_info = { 0 };
    AcdbMiidPidPair id_pair = { 0 };
    LinkedListNode *opi_node = NULL;
    AcdbVcpmOffloadedParamInfo *opi = NULL;

    if (IsNull(vcpm_info) || IsNull(cal_obj_size) || IsNull(table_offset) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: Input parameter(s) is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    file_offset = *table_offset;
    status = FileManReadBuffer(&data_obj, sizeof(AcdbVcpmCalDataObj), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read cal data object.", status);
        return status;
    }

    offset_vcpm_ckv_lut = data_obj.offset_vcpm_ckv_lut;
    data_obj.offset_vcpm_ckv_lut = vcpm_info->chunk_cal_key_lut.offset;

    /* Write CKV LUT offset and num param payload offsets to
     * VCPM Subgraph Info Chunk.
     */
    *cal_obj_size += 2 * sizeof(uint32_t);//<LUT Offset, NumDataOffsets>
    if (!IsNull(rsp->buf) && vcpm_info->op == ACDB_OP_GET_DATA)
    {
        opi_node = vcpm_info->curr_opi_node;

        data_obj.offset_vcpm_ckv_lut -=
            vcpm_info->chunk_cal_key_lut.base_offset;

        if (tot_cal_size < (vcpm_info->chunk_subgraph_info.offset
            + (2 * sizeof(uint32_t))))
            return AR_ENEEDMORE;

        tmp_offset = vcpm_info->chunk_subgraph_info.offset;
        vcpm_info->chunk_subgraph_info.offset += 2 * sizeof(uint32_t);

        //ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->chunk_subgraph_info.offset,
        //    sizeof(uint32_t), &data_obj.offset_vcpm_ckv_lut, sizeof(uint32_t));
        //vcpm_info->chunk_subgraph_info.offset += sizeof(uint32_t);

        //tmp_offset = vcpm_info->chunk_subgraph_info.offset;

        //ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->chunk_subgraph_info.offset,
        //    sizeof(uint32_t), &data_obj.num_data_offsets, sizeof(uint32_t));
        //vcpm_info->chunk_subgraph_info.offset += sizeof(uint32_t);
	}

    for (uint32_t i = 0; i < data_obj.num_data_offsets; i++)
    {
        should_skip_param = FALSE;

        status = GetVcpmModuleParamPair(vcpm_info, &id_pair,
            &is_offloaded_param, &should_skip_param ,
            &param_info, data_obj.offset_cal_def, rsp, tot_cal_size);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to get <IID, PID> %d/%d",
                status, i, data_obj.num_data_offsets);
            return status;
        }

        if (!vcpm_info->ignore_get_default_data && should_skip_param)
        {
            data_obj.offset_cal_def += sizeof(AcdbMiidPidPair);
            file_offset += sizeof(uint32_t);
            continue;
        }

        if (vcpm_info->should_check_hw_accel && should_skip_param)
        {
            data_obj.offset_cal_def += sizeof(AcdbMiidPidPair);
            file_offset += sizeof(uint32_t);
            continue;
        }

        *cal_obj_size += sizeof(AcdbVcpmParamInfo);

        status = FileManReadBuffer(
            &offset_data_pool, sizeof(uint32_t), &file_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read CalDataObj's data"
                " pool offset. Offset %d of %d",
                status, i, data_obj.num_data_offsets);
            return status;
        }

        /* Offloaded parameters are defered till later: when the size of the
         * VCPM blob is calculated. These params are added at the end of the
         * VCPM datapool.
         */
        if (!is_offloaded_param)
        {
            status = GetVcpmParamPayload(
                vcpm_info, &id_pair, &param_info, FALSE, offset_data_pool, rsp);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to get payload for"
                    " <IID, PID> %d/%d",
                    status, i, data_obj.num_data_offsets);
                return status;
            }
        }
        else
        {
            /* If the param is an offloaded param add its data to the end of the datapool
            * Save the offset_data_pool, data_obj.offset_cal_def, and blob offset of the
            * CaldataObj.ParamInfo.offset
            */

            if (vcpm_info->op == ACDB_OP_GET_SIZE)
            {
                opi = ACDB_MALLOC(AcdbVcpmOffloadedParamInfo, 1);

                if (IsNull(opi))
                {
                    return AR_ENOMEMORY;
                }

                opi->file_offset_cal_def = data_obj.offset_cal_def;
                opi->file_offset_data_pool = offset_data_pool;
                opi->blob_offset_vcpm_param_info =
                    vcpm_info->chunk_subgraph_info.offset;

                opi_node = AcdbListCreateNode(opi);
                if (!IsNull(opi_node))
                {
                    status = AcdbListAppend(
                        &vcpm_info->offloaded_param_info_list,
                        opi_node);
                }

                if(IsNull(opi_node))
                    return AR_ENOMEMORY;
            }
            else if (vcpm_info->op == ACDB_OP_GET_DATA)
            {
                if(IsNull(opi_node))
                    return AR_ENOMEMORY;

                opi = (AcdbVcpmOffloadedParamInfo*)opi_node->p_struct;

                if (IsNull(opi))
                {
                    return AR_EBADPARAM;
                }

                opi->file_offset_cal_def = data_obj.offset_cal_def;
                opi->file_offset_data_pool = offset_data_pool;
                opi->blob_offset_vcpm_param_info =
                    vcpm_info->chunk_subgraph_info.offset;

                AcdbListSetNext(&opi_node);
                vcpm_info->curr_opi_node = opi_node;
            }
        }

        /* Go to next Global Data Pool Offset within the CalDataObj
         * Go to next <IID, PID> pair within the Cal Def Table */
        data_obj.offset_cal_def += sizeof(AcdbMiidPidPair);
        total_data_offset_found++;

        //Write Param Info to VCPM Subgraph info Chunk
        if (!IsNull(rsp->buf) && vcpm_info->op == ACDB_OP_GET_DATA)
        {
			if (tot_cal_size < (vcpm_info->chunk_subgraph_info.offset
                + sizeof(AcdbVcpmParamInfo)))
                return AR_ENEEDMORE;

            ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->chunk_subgraph_info.offset,
            sizeof(AcdbVcpmParamInfo), &param_info, sizeof(AcdbVcpmParamInfo));

            vcpm_info->chunk_subgraph_info.offset += sizeof(AcdbVcpmParamInfo);
        }
    }

    *table_offset = file_offset;

    if (total_data_offset_found == 0)
    {
        *cal_obj_size = 0;
        if(vcpm_info->chunk_subgraph_info.offset > 0 && vcpm_info->op == ACDB_OP_GET_DATA)
            vcpm_info->chunk_subgraph_info.offset -= 2 * sizeof(uint32_t);
        return status;
    }

    //write total number of data offsets found at offset
    if (!IsNull(rsp->buf) && vcpm_info->op == ACDB_OP_GET_DATA)
    {
        data_obj.num_data_offsets = total_data_offset_found;

        //tmp_offset = vcpm_info->chunk_subgraph_info.offset;

        ACDB_MEM_CPY_SAFE(rsp->buf + tmp_offset,
            sizeof(uint32_t), &data_obj.offset_vcpm_ckv_lut, sizeof(uint32_t));
        tmp_offset += sizeof(uint32_t);

        ACDB_MEM_CPY_SAFE(rsp->buf + tmp_offset,
            sizeof(uint32_t), &data_obj.num_data_offsets, sizeof(uint32_t));

        //ACDB_MEM_CPY_SAFE(rsp->buf + tmp_offset,
        //    sizeof(uint32_t), &data_obj.num_data_offsets, sizeof(uint32_t));
    }

    status = GetVcpmCalibrationKeyValueTable(vcpm_info,
        offset_vcpm_ckv_lut, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get CKV LUT", status);
        return status;
    }


    return status;
}

int32_t GetVcpmCalibrationDataTable(AcdbVcpmBlobInfo *vcpm_info,
	uint32_t *data_table_size, uint32_t *table_offset, bool_t *has_data,
    AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t offset_voice_key_table = 0; //file offset
    uint32_t table_blob_offset = 0;
    uint32_t cal_dot_size = 0;
    uint32_t tmp_cal_dot_size = 0;
    AcdbVcpmCkvDataTable caldata_table = { 0 };

    if (IsNull(vcpm_info) || IsNull(data_table_size) ||
        IsNull(rsp) || IsNull(table_offset))
    {
        ACDB_ERR("Error[%d]: Input paramert(s) is null");
        return AR_EBADPARAM;
    }

    offset = *table_offset;
    status = FileManReadBuffer(&caldata_table,
        sizeof(AcdbVcpmCkvDataTable), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Module Header.", status);
        return status;
    }

    offset_voice_key_table = caldata_table.offset_voice_key_table;
    caldata_table.offset_voice_key_table = vcpm_info->chunk_cal_key_id.offset;

    //Write Voc Cal Key Table to Voc Cal Key Chunk
    status = IsDefaultVcpmCalibrationKeyIDTable(vcpm_info,
        offset_voice_key_table);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read get calibration key id table.", status);
        return status;
    }

    if (vcpm_info->ignore_get_default_data && vcpm_info->is_default_module_ckv)
    {
        //skip default ckv table
        offset += caldata_table.table_size
            + sizeof(uint32_t) - sizeof(AcdbVcpmCkvDataTable);
        *table_offset = offset;
        return AR_EOK;
    }

    //Make room to write header and remember table offset
    if (vcpm_info->op == ACDB_OP_GET_DATA)
    {
        table_blob_offset = vcpm_info->chunk_subgraph_info.offset;
        vcpm_info->chunk_subgraph_info.offset += sizeof(caldata_table);
    }

    //Clear cal data table size read from acdb and recaculate for VCPM blob
    caldata_table.table_size = 0;
    uint32_t num_caldata_obj_found = 0;
    for (uint32_t i = 0; i < caldata_table.num_caldata_obj; i++)
    {
        tmp_cal_dot_size = 0;
        status = GetVcpmCalDataObject(vcpm_info, &tmp_cal_dot_size,
			&offset, rsp, tot_cal_size);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to get VCPM Cal"
                " Data Object. Skipping..", status);
            continue;
        }

        if (tmp_cal_dot_size > 0)
        {
            num_caldata_obj_found++;
            cal_dot_size += tmp_cal_dot_size;
        }

        /* Ignore adding mmodules to the default iid list since
        they only need to be added once */
        if(!vcpm_info->ignore_iid_list_update)
            vcpm_info->ignore_iid_list_update = TRUE;
    }

    vcpm_info->ignore_iid_list_update = FALSE;
    *table_offset = offset;

    //Only write ckv data table if it has data
    if (cal_dot_size == 0)
    {
        if (vcpm_info->is_default_module_ckv)
        {
            vcpm_info->ignore_get_default_data = TRUE;
        }

        if (!IsNull(has_data))
            *has_data = FALSE;

        return AR_EOK;
    }

    status = GetVcpmCalibrationKeyIDTable(vcpm_info,
        offset_voice_key_table, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read get calibration key id table.", status);
        return status;
    }

    /* Size of the CKV Data Table is the size of the header:
    * <Voice Cal Key Table Offset, Cal Dot Size, Cal Data Obj Count>
    * + Cal Dot Size */
    caldata_table.table_size = 3 * sizeof(uint32_t)
        + cal_dot_size;
    caldata_table.cal_dot_size = cal_dot_size;
    caldata_table.num_caldata_obj = num_caldata_obj_found;
    *data_table_size += sizeof(uint32_t) + caldata_table.table_size;

    //Write CKV Data Table Header info to VCPM Subgraph Info Chunk
    if (!IsNull(rsp->buf) && vcpm_info->op == ACDB_OP_GET_DATA)
    {
        caldata_table.offset_voice_key_table -=
            vcpm_info->chunk_cal_key_id.base_offset;

        if ((table_blob_offset + sizeof(caldata_table)) > tot_cal_size)
            return AR_ENEEDMORE;

        ACDB_MEM_CPY_SAFE(rsp->buf + table_blob_offset,
            sizeof(caldata_table), &caldata_table, sizeof(caldata_table));
	}

    if(!IsNull(has_data))
        *has_data = TRUE;

    return status;
}

int32_t GetVcpmSubgraphChunkData(AcdbVcpmBlobInfo *vcpm_info,
    uint32_t table_offset, AcdbVcpmSubgraphCalTable *subgraph_cal_table,
	AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t chunk_size = 0;
    //Number of Subgraphs is always 1 for each VCPM Subgraph Blob
    uint32_t num_subgraphs = 1;
    uint32_t offset_vcpm_master_key_table = 0;
    uint32_t cal_data_table_size = 0;
    uint32_t chunk_offset_master_key =
        vcpm_info->chunk_master_key.base_offset;
    uint32_t chunk_offset_voice_cal_key =
        vcpm_info->chunk_cal_key_id.base_offset;
    uint32_t chunk_offset_voice_cal_lut =
        vcpm_info->chunk_cal_key_lut.base_offset;
    uint32_t chunk_offset_data_pool =
        vcpm_info->chunk_data_pool.base_offset;

    if (IsNull(vcpm_info) || IsNull(subgraph_cal_table) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    vcpm_info->op = ACDB_OP_GET_DATA;

    //Save the base offset of each chunk so that chunk size can be written
    chunk_offset_master_key    -= sizeof(chunk_size);
    chunk_offset_voice_cal_key -= sizeof(chunk_size);
    chunk_offset_voice_cal_lut -= sizeof(chunk_size);
    chunk_offset_data_pool     -= sizeof(chunk_size);

    /* Write Subgraph Cal Data Table Header to VCPM Subgraph Info
    and move blob offset */
    offset_vcpm_master_key_table =
        subgraph_cal_table->offset_vcpm_master_key_table;

    if (vcpm_info->ignore_get_default_data &&
        subgraph_cal_table->num_ckv_data_table > 0)
    {
        subgraph_cal_table->num_ckv_data_table -= 1;
    }

    subgraph_cal_table->offset_vcpm_master_key_table = 0;
    subgraph_cal_table->num_ckv_data_table =
        vcpm_info->ckv_data_table_offset_list.count;

    if (!IsNull(rsp->buf))
    {
        if ((vcpm_info->chunk_subgraph_info.offset + sizeof(uint32_t))
            > tot_cal_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf
            + vcpm_info->chunk_subgraph_info.offset,
            sizeof(uint32_t), &num_subgraphs, sizeof(uint32_t));
        vcpm_info->chunk_subgraph_info.offset += sizeof(uint32_t);

        if ((vcpm_info->chunk_subgraph_info.offset
            + sizeof(AcdbVcpmSubgraphCalTable))
            > tot_cal_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf
            + vcpm_info->chunk_subgraph_info.offset,
            sizeof(AcdbVcpmSubgraphCalTable),
            subgraph_cal_table, sizeof(AcdbVcpmSubgraphCalTable));
        vcpm_info->chunk_subgraph_info.offset +=
            sizeof(AcdbVcpmSubgraphCalTable);
    }

    status = GetVcpmMasterKeyTable(vcpm_info,
		offset_vcpm_master_key_table, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        return status;
    }

    vcpm_info->curr_opi_node = vcpm_info->offloaded_param_info_list.p_head;

    for (uint32_t i = 0; i < vcpm_info->ckv_data_table_offset_list.count; i++)
    {
        table_offset = vcpm_info->ckv_data_table_offset_list.list[i];

        status = GetVcpmCalibrationDataTable(vcpm_info, &cal_data_table_size,
            &table_offset, NULL, rsp, tot_cal_size);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Subgraph(0x%x) - "
                "Failed to get Calibration Data Table %d/%d",
                vcpm_info->subgraph_id, i,
                subgraph_cal_table->num_ckv_data_table);
            return status;
        }
    }

    vcpm_info->is_default_module_ckv = FALSE;

    /*Write Chunk Sizes for mkt, vckt, vclut, and vcpmdp*/
    if (rsp->buf != NULL)
    {
        if ((chunk_offset_master_key + sizeof(chunk_size)) > tot_cal_size)
            return AR_ENEEDMORE;

        chunk_size = vcpm_info->chunk_master_key.size;
        ACDB_MEM_CPY_SAFE(rsp->buf + chunk_offset_master_key,
            sizeof(chunk_size), &chunk_size, sizeof(chunk_size));

        if((chunk_offset_voice_cal_key + sizeof(chunk_size)) > tot_cal_size)
            return AR_ENEEDMORE;

        chunk_size = vcpm_info->chunk_cal_key_id.size;
        ACDB_MEM_CPY_SAFE(rsp->buf + chunk_offset_voice_cal_key,
            sizeof(chunk_size), &chunk_size, sizeof(chunk_size));

        if((chunk_offset_voice_cal_lut + sizeof(chunk_size)) > tot_cal_size)
            return AR_ENEEDMORE;

        chunk_size = vcpm_info->chunk_cal_key_lut.size;
        ACDB_MEM_CPY_SAFE(rsp->buf + chunk_offset_voice_cal_lut,
            sizeof(chunk_size), &chunk_size, sizeof(chunk_size));

        if((chunk_offset_data_pool + sizeof(chunk_size)) > tot_cal_size)
            return AR_ENEEDMORE;

        chunk_size = vcpm_info->chunk_data_pool.size;
        ACDB_MEM_CPY_SAFE(rsp->buf + chunk_offset_data_pool,
            sizeof(chunk_size), &chunk_size, sizeof(chunk_size));
	}

    return status;
}

int32_t GetVcpmSubgraphChunkInfo(AcdbVcpmBlobInfo *vcpm_info,
    uint32_t table_offset, AcdbVcpmSubgraphCalTable *subgraph_cal_table,
	AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    uint32_t cal_data_table_offset = 0;
    bool_t has_data = FALSE;

    vcpm_info->op = ACDB_OP_GET_SIZE;

    //Clear table size read from file and recalculate it based on blob
    subgraph_cal_table->table_size = 0;

    /* The default ckv is always the first ckv data table */
    uint32_t default_ckv_table_offset = table_offset;
    vcpm_info->ignore_get_default_data = TRUE;

    for (uint32_t i = 0; i < subgraph_cal_table->num_ckv_data_table + 1; i++)
    {
        if (i == subgraph_cal_table->num_ckv_data_table)
        {
            vcpm_info->ignore_get_default_data = FALSE;
            table_offset = default_ckv_table_offset;
        }
        else if (i > 0)
        {
            vcpm_info->ignore_get_default_data = FALSE;
        }

        cal_data_table_offset = table_offset;

        status = GetVcpmCalibrationDataTable(
            vcpm_info, &subgraph_cal_table->table_size,
			&table_offset, &has_data, rsp, tot_cal_size);
        if (AR_FAILED(status))
        {
            return status;
        }

        if (has_data && vcpm_info->ckv_data_table_offset_list.count
            + 1 < GLB_BUF_3_LENGTH/2)
        {
            vcpm_info->ckv_data_table_offset_list
                .list[vcpm_info->ckv_data_table_offset_list.count] =
                cal_data_table_offset;
            vcpm_info->ckv_data_table_offset_list.count++;
        }
    }

    vcpm_info->is_default_module_ckv = FALSE;

    status = GetVcpmMasterKeyTable(vcpm_info,
        subgraph_cal_table->offset_vcpm_master_key_table, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        return status;
    }

    //Size of <Major, Minor, Master Key Off., #Data Tables>
    subgraph_cal_table->table_size += 4 * sizeof(uint32_t);

    vcpm_info->chunk_subgraph_info.size =
        sizeof(uint32_t) + //num_subgraphs
        sizeof(subgraph_cal_table->subgraph_id) +
        sizeof(subgraph_cal_table->table_size) +
        subgraph_cal_table->table_size;

    //Calculate Chunk Offsets to use when building the response
    blob_offset = vcpm_info->offset_vcpm_blob;
    blob_offset += sizeof(AcdbDspModuleHeader);//VCPM Blob Header

    vcpm_info->chunk_subgraph_info.base_offset = blob_offset;
    vcpm_info->chunk_subgraph_info.offset = blob_offset;
    blob_offset += vcpm_info->chunk_subgraph_info.size;

    vcpm_info->chunk_master_key.base_offset = blob_offset;
    vcpm_info->chunk_master_key.offset = blob_offset;
    blob_offset += sizeof(uint32_t) + vcpm_info->chunk_master_key.size;

    vcpm_info->chunk_cal_key_id.base_offset = blob_offset;
    vcpm_info->chunk_cal_key_id.offset = blob_offset;
    blob_offset += sizeof(uint32_t) + vcpm_info->chunk_cal_key_id.size;

    vcpm_info->chunk_cal_key_lut.base_offset = blob_offset;
    vcpm_info->chunk_cal_key_lut.offset = blob_offset;
    blob_offset += sizeof(uint32_t) + vcpm_info->chunk_cal_key_lut.size;

    vcpm_info->chunk_data_pool.base_offset = blob_offset;
    vcpm_info->chunk_data_pool.offset = blob_offset;

    /* Make room to write chunk size */
    vcpm_info->chunk_master_key.base_offset  += sizeof(uint32_t);
    vcpm_info->chunk_master_key.offset       += sizeof(uint32_t);
    vcpm_info->chunk_cal_key_id.base_offset  += sizeof(uint32_t);
    vcpm_info->chunk_cal_key_id.offset       += sizeof(uint32_t);
    vcpm_info->chunk_cal_key_lut.base_offset += sizeof(uint32_t);
    vcpm_info->chunk_cal_key_lut.offset      += sizeof(uint32_t);
    vcpm_info->chunk_data_pool.base_offset   += sizeof(uint32_t);
    vcpm_info->chunk_data_pool.offset        += sizeof(uint32_t);

    return status;
}

int32_t BuildVcpmBlob(AcdbVcpmBlobInfo *vcpm_info,
    AcdbBlob *rsp, uint32_t tot_cal_size)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = 0;
    uint32_t vcpm_blob_offset = 0;
    uint32_t padding = 0;
    uint32_t padded_param_size = 0;
    uint32_t prev_data_pool_size = 0;
    ChunkInfo ci_vcpm_cal = { 0 };
    AcdbVcpmSubgraphCalHeader subgraph_cal_header = { 0 };
    AcdbDspModuleHeader fwk_module_header = { 0 };
    AcdbVcpmSubgraphCalTable subgraph_cal_table_header = { 0 };

    if (IsNull(vcpm_info) || IsNull(rsp))
    {
        ACDB_DBG("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_vcpm_cal.chunk_id = ACDB_CHUNKID_VCPM_CAL_DATA;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal);
    if (AR_FAILED(status)) return status;

    file_offset = ci_vcpm_cal.chunk_offset;
    status = FileManReadBuffer(&subgraph_cal_header,
        sizeof(AcdbVcpmSubgraphCalHeader), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Module Header.", status);
        return status;
    }

    //Search for the matching VCPM Subgraph Cal Data Table
    status = GetVcpmSubgraphCalTable(subgraph_cal_header.num_subgraphs,
        vcpm_info->subgraph_id, &file_offset, &subgraph_cal_table_header);
    if (AR_FAILED(status))
    {
        return status;
    }

    ACDB_CLEAR_BUFFER(glb_buf_1);
    vcpm_info->referenced_iid_list.count = 0;
    vcpm_info->referenced_iid_list.list = &glb_buf_1[0];

    /* This lists are small so glb_buff 3 split in half should be good enough */
    ACDB_CLEAR_BUFFER(glb_buf_3);
    vcpm_info->cal_key_id_table_offset_list.count = 0;
    vcpm_info->cal_key_id_table_offset_list.list = &glb_buf_3[0];

    vcpm_info->ckv_data_table_offset_list.count = 0;
    vcpm_info->ckv_data_table_offset_list.list = &glb_buf_3[GLB_BUF_3_LENGTH/2];

    status = GetVcpmSubgraphChunkInfo(
		vcpm_info, file_offset, &subgraph_cal_table_header, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to calculate vcpm "
            "subgraph cal data size", status);
        goto end;
    }

    prev_data_pool_size = vcpm_info->chunk_data_pool.size;
    //Calculate Size of vcpm blob: sizeof(chunk.size) + chunk.size
    fwk_module_header.param_size =
        vcpm_info->chunk_subgraph_info.size                  +
        sizeof(uint32_t) + vcpm_info->chunk_master_key.size  +
        sizeof(uint32_t) + vcpm_info->chunk_cal_key_id.size  +
        sizeof(uint32_t) + vcpm_info->chunk_cal_key_lut.size +
        sizeof(uint32_t) + vcpm_info->chunk_data_pool.size;

    /* Get offloaded data size: Add any offloaded parameters at the end
    * of the vcpm data pool */
    status = GetVcpmOffloadedData(vcpm_info, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        goto end;
    }

    //Recalculate vcpm blob size since the offloaded param size has been added
    fwk_module_header.param_size -= prev_data_pool_size;
    fwk_module_header.param_size += vcpm_info->chunk_data_pool.size;

    padded_param_size = ACDB_ALIGN_8_BYTE(fwk_module_header.param_size);
    padding = padded_param_size - fwk_module_header.param_size;

    rsp->buf_size += padded_param_size;
    rsp->buf_size += sizeof(AcdbDspModuleHeader);

    if (IsNull(rsp->buf))
    {
        goto end;
    }

    status = GetVcpmSubgraphChunkData(vcpm_info, file_offset,
		&subgraph_cal_table_header, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        goto end;
    }

    /* Get offloaded data: Add any offloaded parameters at the end
     * of the vcpm data pool */
    status = GetVcpmOffloadedData(vcpm_info, rsp, tot_cal_size);
    if (AR_FAILED(status))
    {
        goto end;
    }

    //Write VCPM Framework Module Header
    fwk_module_header.module_iid = subgraph_cal_header.module_iid;
    fwk_module_header.parameter_id = subgraph_cal_header.parameter_id;
    if (!IsNull(rsp->buf))
    {
        if ((vcpm_info->offset_vcpm_blob + sizeof(AcdbDspModuleHeader))
            > tot_cal_size)
        {
            status = AR_ENEEDMORE;
            goto end;
        }

        ACDB_MEM_CPY_SAFE(rsp->buf + vcpm_info->offset_vcpm_blob,
            sizeof(AcdbDspModuleHeader),
            &fwk_module_header, sizeof(AcdbDspModuleHeader));

        vcpm_blob_offset += vcpm_info->offset_vcpm_blob +
            sizeof(AcdbDspModuleHeader) + fwk_module_header.param_size;

        //Padding
        memset((uint8_t*)rsp->buf + vcpm_blob_offset,
            0, padding);
    }

end:
    ACDB_CLEAR_BUFFER(glb_buf_1);
    AcdbListClear2(&vcpm_info->offloaded_param_info_list, AcdbFree);

    return status;
}

int32_t AcdbGetSupbgraphCalPersist(
    AcdbAudioCalContextInfo *info, uint32_t *blob_offset,
    AcdbSgIdPersistCalData* rsp)
{
    int32_t status = AR_EOK;
    bool_t found_sg = FALSE;
    bool_t has_persist_cal = FALSE;
    uint32_t offset = 0;
    uint32_t sg_cal_lut_offset = 0;
    uint32_t default_ckv_entry_offset = 0;
    uint32_t sg_persist_header_offset = 0;
    uint32_t sg_persist_cal_offset = 0;
    uint32_t num_subgraph = 0;
    ChunkInfo ci_sg_cal_lut = { 0 };
    AcdbSgCalLutHeader sg_cal_lut_header = { 0 };
    AcdbCalKeyTblEntry ckv_entry = { 0 };
    AcdbBlob vcpm_blob = { 0 };
    AcdbBlob audio_blob = { 0 };
    AcdbSgIdPersistData sg_persist_data = { 0 };

    if (IsNull(info) || IsNull(rsp))
    {
        ACDB_DBG("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_sg_cal_lut.chunk_id = ACDB_CHUNKID_CALSGLUT;
    status = ACDB_GET_CHUNK_INFO(&ci_sg_cal_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration LUT "
            "chunk information", status);
        return status;
    }

    offset = ci_sg_cal_lut.chunk_offset;
    status = FileManReadBuffer(&num_subgraph,
        sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of Subgraphs",
            status);
        AcdbClearAudioCalContextInfo(info);
        return status;
    }

    found_sg = FALSE;
    audio_blob.buf_size = rsp->cal_data_size;
    audio_blob.buf = (void*)rsp->cal_data;
    has_persist_cal = FALSE;

    //Get VCPM Subgraph Data
    if (info->is_first_time)
    {
        AcdbVcpmBlobInfo vcpm_info;
        int32_t vcpm_status = AR_EOK;
        uint32_t vcpm_blob_offset = 0;

        (void)ar_mem_set(&vcpm_info, 0, sizeof(AcdbVcpmBlobInfo));

        vcpm_blob.buf_size = 0;
        vcpm_blob.buf = (void*)rsp->cal_data;

        if (info->op == ACDB_OP_GET_SIZE)
        {
            rsp->cal_data_size += sizeof(AcdbSgIdPersistData);
            sg_persist_cal_offset = rsp->cal_data_size;
        }
        else if (info->op == ACDB_OP_GET_DATA)
        {
            vcpm_blob_offset = *blob_offset;
            *blob_offset += sizeof(AcdbSgIdPersistData);
            sg_persist_cal_offset = *blob_offset;
        }

        vcpm_info.offset_vcpm_blob = sg_persist_cal_offset;
        vcpm_info.subgraph_id = info->subgraph_id;
        vcpm_info.proc_id = info->proc_id;
        vcpm_info.should_filter_cal_by_proc_domain = info->should_filter_cal_by_proc_domain;
        vcpm_info.sg_mod_iid_map = info->sg_mod_iid_map;
        vcpm_info.offloaded_param_list = info->offloaded_parameter_list;
        vcpm_info.should_check_hw_accel = info->should_check_hw_accel;
        vcpm_info.hw_accel_module_list_offset =
            info->hw_accel_module_list_offset;

        vcpm_status = BuildVcpmBlob(
            &vcpm_info, &vcpm_blob, rsp->cal_data_size);
        if (AR_SUCCEEDED(vcpm_status))
        {
            if (info->op == ACDB_OP_GET_SIZE)
            {
                rsp->cal_data_size += vcpm_blob.buf_size;
                sg_persist_cal_offset = 0;
            }
            else if (info->op == ACDB_OP_GET_DATA)
            {
                if (rsp->cal_data_size < (vcpm_blob_offset
                    + sizeof(uint32_t)))
                {
                    return AR_ENEEDMORE;
                }

                ACDB_MEM_CPY_SAFE(rsp->cal_data + vcpm_blob_offset,
                    sizeof(uint32_t), &info->subgraph_id, sizeof(uint32_t));
                vcpm_blob_offset += sizeof(uint32_t);

                if (rsp->cal_data_size < (vcpm_blob_offset
                    + sizeof(vcpm_blob.buf_size)))
                {
                    return AR_ENEEDMORE;
                }

                ACDB_MEM_CPY_SAFE(rsp->cal_data + vcpm_blob_offset,
                    sizeof(vcpm_blob.buf_size),
                    &vcpm_blob.buf_size, sizeof(vcpm_blob.buf_size));
                vcpm_blob_offset += sizeof(vcpm_blob.buf_size);

                *blob_offset += vcpm_blob.buf_size;
            }

            return vcpm_status;
        }

        if (AR_FAILED(vcpm_status) && vcpm_status != AR_ENOTEXIST)
        {
            return vcpm_status;
        }
        else
        {
            if (info->op == ACDB_OP_GET_SIZE)
                rsp->cal_data_size -= sizeof(AcdbSgIdPersistData);
            else if (info->op == ACDB_OP_GET_DATA)
                *blob_offset -= sizeof(AcdbSgIdPersistData);
        }
    }

    for (uint32_t j = 0; j < num_subgraph; j++)
    {
        status = FileManReadBuffer(&sg_cal_lut_header,
            sizeof(AcdbSgCalLutHeader), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read Subgraph "
                "Cal LUT header", status);
        }

        if (info->subgraph_id == sg_cal_lut_header.subgraph_id)
        {
            found_sg = TRUE;
            break;
        }
        else
        {
            //Go to next Subgraph entry
            offset += (sg_cal_lut_header.num_ckv_entries
                * sizeof(AcdbCalKeyTblEntry));
        }
    }

    if (!found_sg)
    {
        ACDB_DBG("Error[%d]: Subgraph(%x) does not exist. Skipping..",
            AR_ENOTEXIST, info->subgraph_id);
        return AR_ENOTEXIST;
    }

    if (sg_cal_lut_header.num_ckv_entries == 0)
    {
        ACDB_DBG("Error[%d]: Subgraph(%x) contains zero CKV entries in"
            " the Subgraph Cal LUT. At least one entry should be"
            " present. Skipping..",
            AR_ENOTEXIST, info->subgraph_id);
        return AR_ENOTEXIST;
    }

    /* Save starting offset of a subgraphs persist cal. Move the blob
     * offset to start at the calibration. If there is no calibration
     * move the offset back by subtracting the size of the header and
     * skip the subgraph.
     */
    if (info->op == ACDB_OP_GET_SIZE)
    {
        //rsp->cal_data_size += sizeof(AcdbSgIdPersistData);
        audio_blob.buf_size += sizeof(AcdbSgIdPersistData);
    }
    else if (info->op == ACDB_OP_GET_DATA)
    {
        sg_persist_header_offset = *blob_offset;
        *blob_offset += sizeof(AcdbSgIdPersistData);
        sg_persist_cal_offset = *blob_offset;
    }

    info->ignore_get_default_data =
        sg_cal_lut_header.num_ckv_entries == 1 ? FALSE : TRUE;

    //The default CKV will be skipped and handeled last
    if (sg_cal_lut_header.num_ckv_entries > 1 && info->is_first_time)
        sg_cal_lut_header.num_ckv_entries++;

    for (uint32_t k = 0; k < sg_cal_lut_header.num_ckv_entries; k++)
    {
        /* The Default CKV is always the first CKV in the list of CKVs to
        * search. It will be skipped and processed last */
        if ((k == sg_cal_lut_header.num_ckv_entries - 1) &&
            info->ignore_get_default_data == TRUE && info->is_first_time)
        {
            sg_cal_lut_offset = default_ckv_entry_offset;
            info->ignore_get_default_data = FALSE;

            status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                &sg_cal_lut_offset);
        }
        else
        {
            status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                &offset);
            sg_cal_lut_offset = offset;
        }

        if (AR_FAILED(status))
        {
            AcdbClearAudioCalContextInfo(info);
            return status;
        }

        info->subgraph_id = sg_cal_lut_header.subgraph_id;

        status = AcdbFindModuleCKV(&ckv_entry, info);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            continue;
        }
        else if (AR_FAILED(status))
        {
            AcdbClearAudioCalContextInfo(info);
            return status;
        }

        if (info->is_default_module_ckv)
        {
            default_ckv_entry_offset =
                sg_cal_lut_offset - sizeof(ckv_entry);
        }

        //Get Calibration
        status = AcdbGetSubgraphCalibration(
            info, blob_offset, &audio_blob);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            //No calibration found for subgraph with module ckv_entry
            //has_persist_cal = FALSE;
            continue;
        }
        else if (AR_FAILED(status) && status != AR_ENOTEXIST)
        {
            ACDB_ERR("Error[%d]: An error occured while getting "
                "calibration data for Subgraph(%x)", status,
                info->subgraph_id);
            AcdbClearAudioCalContextInfo(info);
            return status;
        }

        if (info->is_default_module_ckv && info->ignore_get_default_data)
        {
            continue;
        }

        has_persist_cal = TRUE;
    }

    if (AR_FAILED(status) && !has_persist_cal)
    {
        //if (info->op == ACDB_OP_GET_SIZE)
        //    rsp->cal_data_size -= sizeof(AcdbSgIdPersistData);
        if (info->op == ACDB_OP_GET_DATA)
            *blob_offset -= sizeof(AcdbSgIdPersistData);

        if (info->op == ACDB_OP_GET_SIZE)
            ACDB_DBG("Warning[%d]: Unable to retrieve calibration data for "
                "Subgraph(%x). Skipping..", status,
                info->subgraph_id);
    }
    else
    {
        status = AR_EOK;

        if (info->op == ACDB_OP_GET_SIZE)
            rsp->cal_data_size = audio_blob.buf_size;
        else if (info->op == ACDB_OP_GET_DATA)
        {
            //Write subgraph persist data header
            sg_persist_data.sg_id = info->subgraph_id;
            //sg_persist_data.persist_data_size = audio_blob.buf_size;
            sg_persist_data.persist_data_size =
                *blob_offset - sg_persist_cal_offset;

            if (rsp->cal_data_size < (sg_persist_header_offset
                + sizeof(AcdbSgIdPersistData)))
            {
                return AR_ENEEDMORE;
            }

            ACDB_MEM_CPY_SAFE(rsp->cal_data + sg_persist_header_offset,
                sizeof(AcdbSgIdPersistData),
                &sg_persist_data, sizeof(AcdbSgIdPersistData));
        }
    }

    return status;
}

int32_t AcdbCmdGetSubgraphCalDataPersist(
    AcdbSgIdCalKeyVector* req, AcdbSgIdPersistCalData* rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbAudioCalContextInfo info;
    AcdbUintList subgraph_list = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    (void)ar_mem_set(&info, 0, sizeof(AcdbAudioCalContextInfo));

    rsp->num_sg_ids = 0;

    if (rsp->cal_data_size > 0 && !IsNull(rsp->cal_data))
    {
        info.op = ACDB_OP_GET_DATA;
        memset(rsp->cal_data, 0, rsp->cal_data_size);
    }
    else
        info.op = ACDB_OP_GET_SIZE;

    if (info.op == ACDB_OP_GET_SIZE)
    {
        //Log CKV when this API is called for the first time
        ACDB_DBG("Retrieving persistent calibration for "
            "the following cal key vector:");
        ACDB_DBG("CKV[new]:");
        LogKeyVector(&req->cal_key_vector_new, CAL_KEY_VECTOR);
        ACDB_DBG("CKV[old]:");
        LogKeyVector(&req->cal_key_vector_prior, CAL_KEY_VECTOR);
    }

    /* CKV Setup
    * 1. GLB_BUF_2 stores the module CKV that will be used to locate data in
    * the heap(if it exists)
    * 2. The Delta CKV and CKV[New] are allocated on the heap by
    * AcdbComputeDeltaCKV
    *
    * tmp - stores the amount of padding after graph_key_vectornum_keys
    * tmp2 - stores the position of the KeyValuePair list
    *
    * The first info->module_ckv->graph_key_vector assignment has the effect
    * of storing the address of the pointer in glb_buf_2 after
    * graph_key_vector.num_keys
    *
    * The second info->module_ckv->graph_key_vector assignment has the effect
    * of pointer the info->module_ckv->graph_key_vector to the actual list
    * of key value pairs
    *
    * Whats inside global buffer 2 after these operations?
    *
    * The first 'sizeof(AcdbGraphKeyVector)' bytes is AcdbGraphKeyVector
    * followed by 'sizeof(AcdbKeyValuePair) * num_keys' bytes which is
    * the KV list
    */
    info.module_ckv = (AcdbGraphKeyVector*)&glb_buf_2[0];
    uint32_t tmp = (sizeof(AcdbGraphKeyVector)
        - sizeof(AcdbKeyValuePair*)) / sizeof(uint32_t);
    uint32_t tmp2 = sizeof(AcdbGraphKeyVector) / sizeof(uint32_t);
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp];
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp2];
    info.should_check_hw_accel = FALSE;
    info.param_type = ACDB_DATA_PERSISTENT;

    status = AcdbComputeDeltaCKV(
        &req->cal_key_vector_new,
        &req->cal_key_vector_prior, &info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get the delta CKV", status);
        AcdbClearAudioCalContextInfo(&info);
        return status;
    }

    (void)GetOffloadedParamList(&info.offloaded_parameter_list);
    if (info.offloaded_parameter_list.count == 0)
    {
        ACDB_DBG("Error[%d]: No offloaded parameters found. Skipping..",
            status);
    }

    for (uint32_t i = 0; i < req->num_sg_ids; i++)
    {
        status = AR_EOK;
        info.subgraph_id = req->sg_ids[i];

        status = AcdbGetSupbgraphCalPersist(
            &info, &blob_offset, rsp);
        if (status == AR_ENOTEXIST)
        {
            ACDB_DBG("Error[%d]: No calibration found for Subraph(0x%x)",
                status, info.subgraph_id);
            status = AR_EOK;
            continue;
        }
        else if (AR_FAILED(status))
            break;

        rsp->num_sg_ids++;
    }

    if (rsp->num_sg_ids == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: No calibration found", status);
    }

    AcdbClearAudioCalContextInfo(&info);

    return status;
}

int32_t AcdbCmdGetHwAccelInfo(
    AcdbHwAccelSubgraphInfoReq* req, AcdbHwAccelSubgraphInfoRsp* rsp)
{
    int32_t status = AR_EOK;
    uint32_t current_size = 0;
    uint32_t expected_size = 0;
    uint32_t num_subgraphs_found = 0;
    AcdbHwAccelSubgraphInfo hw_accel_sg_info = { 0 };
    AcdbOp op = IsNull(rsp->subgraph_list) ?
        ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->subgraph_list.count == 0)
    {
        ACDB_ERR("Error[%d]: The subgraph list is empty",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &req->subgraph_list, sizeof(AcdbUintList), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    expected_size = rsp->list_size;

    for (uint32_t i = 0; i < req->subgraph_list.count; i++)
    {
        hw_accel_sg_info.subgraph_id = req->subgraph_list.list[i];

        status = DataProcGetHwAccelSubgraphInfo(&hw_accel_sg_info);
        if (AR_FAILED(status) && status != AR_ENOTEXIST)
        {
            break;
        }

        if (op == ACDB_OP_GET_SIZE)
        {
            rsp->list_size += sizeof(AcdbHwAccelSubgraph);
            rsp->num_subgraphs = ++num_subgraphs_found;

            if (AR_ENOTEXIST == status)
            {
                status = AR_EOK;
            }
        }
        else if (op == ACDB_OP_GET_DATA && !IsNull(rsp->subgraph_list))
        {
            if (current_size > expected_size)
            {
                return AR_ENEEDMORE;
            }

            rsp->subgraph_list[i].subgraph_id = hw_accel_sg_info.subgraph_id;
            rsp->subgraph_list[i].mem_type = hw_accel_sg_info.mem_type;

            if (AR_ENOTEXIST == status)
            {
                rsp->subgraph_list[i].mem_type = ACDB_HW_ACCEL_MEM_DEFAULT;
                status = AR_EOK;
            }

            current_size += sizeof(AcdbHwAccelSubgraph);
        }
    }

    return status;
}

int32_t AcdbCmdGetProcSubgraphCalDataPersist(
    AcdbProcSubgraphPersistCalReq *req, AcdbSgIdPersistCalData *rsp)
{
    int32_t status = AR_EOK;
    uint32_t blob_offset = 0;
    AcdbHwAccelSubgraphInfo hw_accel_sg_info = { 0 };
    AcdbAudioCalContextInfo info;
    AcdbHwAccelMemType mem_type = ACDB_HW_ACCEL_MEM_DEFAULT;
    AcdbUintList subgraph_list = { 0 };
    AcdbSubgraphPdmMap sg_mod_iid_map = { 0 };

    //mask out mem type
    //uint32_t proc_id_mask = 0x3FFFFFFF;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    for (uint32_t i = 0; i < req->num_subgraphs; i++)
    {
        glb_buf_3[i] = req->subgraph_list->subgraph_id;
    }

    subgraph_list.count = req->num_subgraphs;
    subgraph_list.list = &glb_buf_3[0];

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

    ACDB_CLEAR_BUFFER(glb_buf_3);

    (void)ar_mem_set(&info, 0, sizeof(AcdbAudioCalContextInfo));

    //we should filter calibration based on proc in this api
    info.should_filter_cal_by_proc_domain = TRUE;
    rsp->num_sg_ids = 0;

    if (rsp->cal_data_size > 0 && !IsNull(rsp->cal_data))
    {
        info.op = ACDB_OP_GET_DATA;
        memset(rsp->cal_data, 0, rsp->cal_data_size);
    }
    else
        info.op = ACDB_OP_GET_SIZE;

    if (info.op == ACDB_OP_GET_SIZE)
    {
        //Log CKV when this API is called for the first time
        ACDB_DBG("Retrieving processor-based persistent calibration for "
            "the following cal key vector:");
        ACDB_DBG("CKV[new]:");
        LogKeyVector(&req->cal_key_vector_new, CAL_KEY_VECTOR);
        ACDB_DBG("CKV[old]:");
        LogKeyVector(&req->cal_key_vector_prior, CAL_KEY_VECTOR);
    }

    /* CKV Setup
    * 1. GLB_BUF_2 stores the module CKV that will be used to locate data in
    * the heap(if it exists)
    * 2. The Delta CKV and CKV[New] are allocated on the heap by
    * AcdbComputeDeltaCKV
    *
    * tmp - stores the amount of padding after graph_key_vectornum_keys
    * tmp2 - stores the position of the KeyValuePair list
    *
    * The first info->module_ckv->graph_key_vector assignment has the effect
    * of storing the address of the pointer in glb_buf_2 after
    * graph_key_vector.num_keys
    *
    * The second info->module_ckv->graph_key_vector assignment has the effect
    * of pointer the info->module_ckv->graph_key_vector to the actual list
    * of key value pairs
    *
    * Whats inside global buffer 2 after these operations?
    *
    * The first 'sizeof(AcdbGraphKeyVector)' bytes is AcdbGraphKeyVector
    * followed by 'sizeof(AcdbKeyValuePair) * num_keys' bytes which is
    * the KV list
    */
    info.module_ckv = (AcdbGraphKeyVector*)&glb_buf_2[0];
    uint32_t tmp = (sizeof(AcdbGraphKeyVector)
        - sizeof(AcdbKeyValuePair*)) / sizeof(uint32_t);
    uint32_t tmp2 = sizeof(AcdbGraphKeyVector) / sizeof(uint32_t);
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp];
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp2];
    info.should_check_hw_accel = TRUE;
    info.param_type = ACDB_DATA_PERSISTENT;

    status = AcdbComputeDeltaCKV(
        &req->cal_key_vector_new,
        &req->cal_key_vector_prior, &info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get the delta CKV", status);
        AcdbClearAudioCalContextInfo(&info);
        return status;
    }

    (void)GetOffloadedParamList(&info.offloaded_parameter_list);
    if (info.offloaded_parameter_list.count == 0)
    {
        ACDB_DBG("Warning[%d]: No offloaded parameters found. Skipping..",
            status);
    }

    for (uint32_t i = 0; i < req->num_subgraphs; i++)
    {
        status = AR_EOK;
        info.subgraph_id = req->subgraph_list[i].subgraph_id;
        info.proc_id = req->subgraph_list[i].proc_id;

        hw_accel_sg_info.subgraph_id = info.subgraph_id;
        mem_type = ACDB_HW_ACCEL_MEM_TYPE(info.proc_id);

        status = DataProcGetHwAccelSubgraphInfo(&hw_accel_sg_info);
        if (AR_FAILED(status) && mem_type == ACDB_HW_ACCEL_MEM_CMA)
        {
            status = AR_EOK;
            continue;
        }

        info.hw_accel_module_list_offset =
            hw_accel_sg_info.module_list_offset;

        status = DataProcGetSubgraphProcIidMap(info.subgraph_id, &sg_mod_iid_map);
        if (AR_EOK != status)
        {
            //Return even if it can't find data for one of the given subgraphs
            goto end;
        }

        info.sg_mod_iid_map = &sg_mod_iid_map;

        status = AcdbGetSupbgraphCalPersist(
            &info, &blob_offset, rsp);
        if (status == AR_ENOTEXIST)
        {
            ACDB_DBG("Warning[%d]: No calibration found for Subraph(0x%x)",
                status, info.subgraph_id);
            status = AR_EOK;
            continue;
        }
        else if (AR_FAILED(status))
            break;

        rsp->num_sg_ids++;
    }

end:

    if (rsp->num_sg_ids == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: No calibration found", status);
    }

    AcdbClearAudioCalContextInfo(&info);

    return status;
}

/* TODO: This api needs to be supported when the ACDB file supports global
* persistent data. This API also needs to be refactored and follow the
* approach used in AcdbCmdGetSubgraphCalNonPersist
*/
// int32_t AcdbCmdGetSubgraphGlbPersistIds(AcdbSgIdCalKeyVector *pInput, AcdbGlbPsistIdentifierList *pOutput, uint32_t rsp_struct_size)
// {
//     __UNREFERENCED_PARAM(pInput);
//     __UNREFERENCED_PARAM(pOutput);
//     __UNREFERENCED_PARAM(rsp_struct_size);
//     return AR_ENOTEXIST;
// }

/* TODO: This api needs to be supported when the ACDB file supports global
 * persistent data. This API also needs to be refactored and follow the
 * approach used in AcdbCmdGetSubgraphCalNonPersist
 */
//int32_t AcdbCmdGetSubgraphGlbPersistIds(AcdbSgIdCalKeyVector *pInput, AcdbGlbPsistIdentifierList *pOutput, uint32_t rsp_struct_size)
//{
//	int32_t result = AR_EOK;
//	uint32_t entryCnt = 0;
//	uint32_t chkBuf = 0;
//	uint32_t chkLen = 0;
//	uint32_t sgLutChkBuf = 0;
//	uint32_t sgLutChkLen = 0;
//	uint32_t calKeyChkBuf = 0;
//	uint32_t calKeyChkLen = 0;
//	uint32_t calLutChkBuf = 0;
//	uint32_t calLutChkLen = 0;
//	uint32_t calDef2ChkBuf = 0;
//	uint32_t calDef2ChkLen = 0;
//	uint32_t pidMapChkBuf = 0;
//	uint32_t pidMapChkLen = 0;
//	uint32_t offset = 0;
//	uint32_t data_offset = 0;
//	size_t totalsize = 0;
//	uint32_t calKeyTblOffset = 0;
//	uint32_t calDataTblOffset = 0;
//	uint32_t calDataDefOffset = 0;
//	bool_t found = FALSE;
//	bool_t key_found = FALSE;
//	bool_t first_time = FALSE;
//	uint32_t* iid_list = NULL;
//
//	ACDB_PKT_LOG_DATA("NumSGIDs", &pInput->num_sg_ids, sizeof(pInput->num_sg_ids));
//	ACDB_PKT_LOG_DATA("SGIDs", pInput->sg_ids, sizeof(pInput->sg_ids) * pInput->num_sg_ids);
//	ACDB_PKT_LOG_DATA("CKVPrior_NumKeys", &pInput->cal_key_vector_prior.num_keys, sizeof(pInput->cal_key_vector_prior.num_keys));
//	if (pInput->cal_key_vector_prior.num_keys != 0)
//		ACDB_PKT_LOG_DATA("CKVPrior_KV", pInput->cal_key_vector_prior.graph_key_vector, sizeof(pInput->cal_key_vector_prior.graph_key_vector) * pInput->cal_key_vector_prior.num_keys);
//	ACDB_PKT_LOG_DATA("CKVNew_NumKeys", &pInput->cal_key_vector_new.num_keys, sizeof(pInput->cal_key_vector_new.num_keys));
//	if (pInput->cal_key_vector_new.num_keys != 0)
//		ACDB_PKT_LOG_DATA("CKVNew_KV", pInput->cal_key_vector_new.graph_key_vector, sizeof(pInput->cal_key_vector_new.graph_key_vector) * pInput->cal_key_vector_new.num_keys);
//
//	if (rsp_struct_size < 12)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, rsp_struct_size is invalid");
//		return AR_EBADPARAM;
//	}
//
//	if (pInput->cal_key_vector_prior.num_keys == 0)
//		first_time = TRUE;
//
//	AcdbGraphKeyVector* deltaKV = (AcdbGraphKeyVector*)malloc(sizeof(AcdbGraphKeyVector));
//	if (deltaKV == NULL)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, Insufficient memory to allocate deltaKV");
//		return AR_ENOMEMORY;
//	}
//
//	if (pInput->cal_key_vector_prior.num_keys == 0)
//	{
//		first_time = TRUE;
//		deltaKV->num_keys = pInput->cal_key_vector_new.num_keys;
//		deltaKV->graph_key_vector = (AcdbKeyValuePair*)malloc(2 * sizeof(uint32_t) * deltaKV->num_keys);
//		if (IsNull(deltaKV->graph_key_vector))
//		{
//			ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, Insufficient memory to allocate deltaKV->graph_key_vector");
//			return AR_ENOMEMORY;
//		}
//
//		for (uint32_t i = 0; i < deltaKV->num_keys; i++)
//		{
//			deltaKV->graph_key_vector[i].key = pInput->cal_key_vector_new.graph_key_vector[i].key;
//			deltaKV->graph_key_vector[i].value = pInput->cal_key_vector_new.graph_key_vector[i].value;
//		}
//	}
//	else
//	{
//		//compute delta KV (from prior and new) and number of keys
//		if (pInput->cal_key_vector_prior.num_keys != pInput->cal_key_vector_new.num_keys)
//		{
//			ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, calkeyvectorprior - num of keys do not match calkeyvectornew - num of keys");
//			return AR_EFAILED;
//		}
//		uint32_t cnt = 0;
//		for (uint32_t i = 0; i < pInput->cal_key_vector_prior.num_keys; i++)
//		{
//			if (pInput->cal_key_vector_prior.graph_key_vector[i].value != pInput->cal_key_vector_new.graph_key_vector[i].value)
//				cnt++;
//		}
//		deltaKV->num_keys = cnt;
//		deltaKV->graph_key_vector = (AcdbKeyValuePair*)malloc(2 * sizeof(uint32_t) * cnt);
//		if (IsNull(deltaKV->graph_key_vector))
//		{
//			ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, Insufficient memory to allocate deltaKV->graph_key_vector");
//			return AR_ENOMEMORY;
//		}
//
//		cnt = 0;
//		for (uint32_t i = 0; i < pInput->cal_key_vector_prior.num_keys; i++)
//		{
//			if (pInput->cal_key_vector_prior.graph_key_vector[i].value != pInput->cal_key_vector_new.graph_key_vector[i].value)
//			{
//				deltaKV->graph_key_vector[cnt].key = pInput->cal_key_vector_new.graph_key_vector[i].key;
//				deltaKV->graph_key_vector[cnt].value = pInput->cal_key_vector_new.graph_key_vector[i].value;
//				cnt++;
//			}
//		}
//	}
//
//	ACDB_PKT_LOG_DATA("deltaNumKeys", &deltaKV->num_keys, sizeof(deltaKV->num_keys));
//	ACDB_PKT_LOG_DATA("deltaKV", &deltaKV->graph_key_vector, sizeof(deltaKV->graph_key_vector) * deltaKV->num_keys);
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_CALSGLUT, &sgLutChkBuf, &sgLutChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_CALKEYTBL, &calKeyChkBuf, &calKeyChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_CALDATALUT, &calLutChkBuf, &calLutChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_CALDATADEF, &calDef2ChkBuf, &calDef2ChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_PIDPERSIST, &pidMapChkBuf, &pidMapChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_DATAPOOL, &chkBuf, &chkLen);
//	if (result != AR_EOK)
//		return result;
//
//	for (uint32_t i = 0;i < pInput->num_sg_ids;i++)
//	{
//		uint32_t sgID = pInput->sg_ids[i];
//		offset = sizeof(uint32_t); //ignore num of SGID's in ACDB_CHUNKID_CALSGLUT chunk
//		found = FALSE;
//		do
//		{
//			memset(&glb_buf_1, 0, sizeof(glb_buf_1));
//			int ret = file_seek(sgLutChkBuf + offset, AR_FSEEK_BEGIN);
//			if (ret != 0)
//			{
//				ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", sgLutChkBuf + offset);
//				return AR_EFAILED;
//			}
//			ret = file_read(&glb_buf_1, 2 * sizeof(uint32_t));
//			if (ret != 0)
//			{
//				ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, sgID read was unsuccessful");
//				return AR_EFAILED;
//			}
//
//			if (memcmp(&sgID, &glb_buf_1[0], sizeof(sgID)) == 0)
//			{
//				found = TRUE;
//				uint32_t num_cktbl_entries = glb_buf_1[1];
//				offset = offset + (2 * sizeof(uint32_t));
//				for (uint32_t j = 0; j < num_cktbl_entries;j++)
//				{
//					memset(&glb_buf_1, 0, sizeof(glb_buf_1));
//					ret = file_seek(sgLutChkBuf + offset, AR_FSEEK_BEGIN);
//					if (ret != 0)
//					{
//						ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", sgLutChkBuf + offset);
//						return AR_EFAILED;
//					}
//					ret = file_read(&glb_buf_1, 2 * sizeof(uint32_t));
//					if (ret != 0)
//					{
//						ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, calKeyTblOffset read was unsuccessful");
//						return AR_EFAILED;
//					}
//
//					offset = offset + (2 * sizeof(uint32_t));
//					calKeyTblOffset = glb_buf_1[0];
//					calDataTblOffset = glb_buf_1[1];
//
//					ACDB_PKT_LOG_DATA("calKeyTblOffset", &calKeyTblOffset, sizeof(calKeyTblOffset));
//					ACDB_PKT_LOG_DATA("calDataTblOffset", &calDataTblOffset, sizeof(calDataTblOffset));
//
//					if (calKeyTblOffset == 0xffffffff && !first_time)
//						continue;
//					else
//					{
//						if (calKeyTblOffset != 0xffffffff)
//						{
//							uint32_t num_keys = 0;
//							memset(&glb_buf_1, 0, sizeof(glb_buf_1));
//							ret = file_seek(calKeyChkBuf + calKeyTblOffset, AR_FSEEK_BEGIN);
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calKeyChkBuf + calKeyTblOffset);
//								return AR_EFAILED;
//							}
//							ret = file_read(&num_keys, sizeof(uint32_t));
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, num of keys read was unsuccessful");
//								return AR_EFAILED;
//							}
//
//							ret = file_seek(calKeyChkBuf + calKeyTblOffset + sizeof(num_keys), AR_FSEEK_BEGIN);
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calKeyChkBuf + calKeyTblOffset + sizeof(num_keys));
//								return AR_EFAILED;
//							}
//
//							if (num_keys > 0)
//							{
//								ret = file_read(&glb_buf_1, num_keys * sizeof(num_keys));
//								if (ret != 0)
//								{
//									ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, keys read was unsuccessful");
//									return AR_EFAILED;
//								}
//							}
//
//							//perform SG key validation with CKV->keys provided, if SG key doesn't exist in CKV, flag an error, since the input is invalid
//							for (uint32_t k = 0; k < num_keys; k++)
//							{
//								key_found = FALSE;
//								for (uint32_t l = 0; l < deltaKV->num_keys; l++)
//								{
//									if (glb_buf_1[k] == deltaKV->graph_key_vector[l].key)
//									{
//										key_found = TRUE;
//										break;
//									}
//								}
//								if (!key_found)
//								{
//									ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, key doesn't exist %d", glb_buf_1[i]);
//									return AR_EFAILED;
//								}
//
//							}
//						}
//
//						uint32_t num_entries = 0;
//						uint32_t num_values = 0;
//						memset(&glb_buf_2, 0, sizeof(glb_buf_2));
//						ret = file_seek(calLutChkBuf + calDataTblOffset, AR_FSEEK_BEGIN);
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calLutChkBuf + calDataTblOffset);
//							return AR_EFAILED;
//						}
//						ret = file_read(&num_entries, sizeof(uint32_t));
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, num of entries read was unsuccessful");
//							return AR_EFAILED;
//						}
//
//						ret = file_seek(calLutChkBuf + calDataTblOffset + sizeof(num_entries), AR_FSEEK_BEGIN);
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calLutChkBuf + calDataTblOffset + sizeof(num_entries));
//							return AR_EFAILED;
//						}
//						ret = file_read(&num_values, sizeof(uint32_t));
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, num of values read was unsuccessful");
//							return AR_EFAILED;
//						}
//
//						ret = file_seek(calLutChkBuf + calDataTblOffset + sizeof(num_entries) + sizeof(num_values), AR_FSEEK_BEGIN);
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calLutChkBuf + calDataTblOffset + sizeof(num_entries) + sizeof(num_values));
//							return AR_EFAILED;
//						}
//						ret = file_read(&glb_buf_2, num_entries * ((num_values * sizeof(uint32_t)) + (3 * sizeof(uint32_t))));
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, values read was unsuccessful");
//							return AR_EFAILED;
//						}
//
//						ACDB_PKT_LOG_DATA("NumEntries", &num_entries, sizeof(num_entries));
//						ACDB_PKT_LOG_DATA("NumValues", &num_values, sizeof(num_values));
//						ACDB_PKT_LOG_DATA("Values", &glb_buf_2, num_entries * ((num_values * sizeof(uint32_t)) + (3 * sizeof(uint32_t))));
//
//						uint32_t temp_offset = 0;
//						uint32_t marked_offset = 0;
//
//						for (uint32_t k = 0; k < num_entries; k++, temp_offset += 4)
//						{
//							for (uint32_t m = 0;m < num_values; m++, temp_offset++)
//							{
//								key_found = FALSE;
//								for (uint32_t n = 0;n < deltaKV->num_keys;n++)
//								{
//									if (glb_buf_1[m] == deltaKV->graph_key_vector[n].key && glb_buf_2[temp_offset] == deltaKV->graph_key_vector[n].value)
//									{
//										marked_offset = temp_offset;
//										key_found = TRUE;
//									}
//								}
//							}
//						}
//						if (!key_found && !first_time)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, value doesn't exist");
//							return AR_EFAILED; //return error is there is one mis-match
//						}
//
//						calDataDefOffset = glb_buf_2[marked_offset + 3]; //DEF2 offset
//
//						ACDB_PKT_LOG_DATA("calDataDefOffset", &calDataDefOffset, sizeof(calDataDefOffset));
//
//						ret = file_seek(calDef2ChkBuf + calDataDefOffset, AR_FSEEK_BEGIN);
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calDef2ChkBuf + calDataDefOffset);
//							return AR_EFAILED;
//						}
//						ret = file_read(&num_entries, sizeof(uint32_t));
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, DEF2 offset read was unsuccessful");
//							return AR_EFAILED;
//						}
//
//						calDataDefOffset += sizeof(uint32_t); //num of entries
//						ret = file_seek(calDef2ChkBuf + calDataDefOffset, AR_FSEEK_BEGIN);
//						if (ret != 0)
//						{
//							ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calDef2ChkBuf + calDataDefOffset);
//							return AR_EFAILED;
//						}
//
//						do
//						{
//
//							uint32_t pid = 0;
//							uint32_t num_of_iids = 0;
//							uint32_t cal_ID = 0;
//							ret = file_read(&cal_ID, sizeof(uint32_t));
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, calId read was unsuccessful");
//								return AR_EFAILED;
//							}
//
//							calDataDefOffset += sizeof(uint32_t); //calID value;
//
//							ret = file_seek(calDef2ChkBuf + calDataDefOffset, AR_FSEEK_BEGIN);
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calDef2ChkBuf + calDataDefOffset);
//								return AR_EFAILED;
//							}
//							ret = file_read(&pid, sizeof(pid)); // pid
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, pid read was unsuccessful");
//								return AR_EFAILED;
//							}
//
//							calDataDefOffset += sizeof(pid); //pid value;
//
//							ret = file_seek(calDef2ChkBuf + calDataDefOffset, AR_FSEEK_BEGIN);
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calDef2ChkBuf + calDataDefOffset);
//								return AR_EFAILED;
//							}
//							ret = file_read(&num_of_iids, sizeof(num_of_iids)); // num of iid's
//							if (ret != 0)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, num of iid's read was unsuccessful");
//								return AR_EFAILED;
//							}
//
//							iid_list = (uint32_t*)malloc(sizeof(uint32_t) * num_of_iids);
//							if (iid_list == NULL)
//							{
//								ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, cannot allocate memory for iid_list");
//								return AR_ENOMEMORY;
//							}
//
//							calDataDefOffset += sizeof(uint32_t); // num of iid's
//							uint32_t iid_offset = 0;
//							for (uint32_t r = 0; r < num_of_iids; r++)
//							{
//								memset(&glb_buf_3, 0, sizeof(glb_buf_3));
//								ret = file_seek(calDef2ChkBuf + calDataDefOffset, AR_FSEEK_BEGIN);
//								if (ret != 0)
//								{
//									ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, file seek to %d was unsuccessful", calDef2ChkBuf + calDataDefOffset);
//									return AR_EFAILED;
//								}
//								ret = file_read(&glb_buf_3, sizeof(uint32_t)); // iid value;
//								if (ret != 0)
//								{
//									ACDB_ERR("AcdbCmdGetSubgraphGlbPersistIds() failed, iid value read was unsuccessful");
//									return AR_EFAILED;
//								}
//
//								ACDB_MEM_CPY(&iid_list + iid_offset, &glb_buf_3, sizeof(uint32_t));
//								iid_offset += sizeof(uint32_t);
//								calDataDefOffset += sizeof(uint32_t);
//							}
//
//							totalsize += sizeof(cal_ID) + sizeof(num_of_iids);
//							totalsize += sizeof(iid_list);
//
//							if (pOutput->global_persistent_cal_info != NULL)
//							{
//								if (pOutput->size >= (data_offset + (2 * sizeof(uint32_t))))
//								{
//								ACDB_MEM_CPY(pOutput->global_persistent_cal_info + data_offset, &cal_ID, sizeof(cal_ID));
//								data_offset += sizeof(cal_ID);
//								ACDB_MEM_CPY(pOutput->global_persistent_cal_info + data_offset, &num_of_iids, sizeof(num_of_iids));
//								data_offset += sizeof(num_of_iids);
//								}
//								else
//								{
//									return AR_ENEEDMORE;
//								}
//								for (uint32_t r = 0; r < num_of_iids; r++)
//								{
//									if (pOutput->size >= (data_offset + sizeof(uint32_t)))
//									{
//									ACDB_MEM_CPY(pOutput->global_persistent_cal_info + data_offset, &iid_list[r], sizeof(uint32_t));
//									}
//									else
//									{
//										return AR_ENEEDMORE;
//									}
//									data_offset += sizeof(uint32_t);
//								}
//							}
//
//							entryCnt++;
//						} while (entryCnt < num_entries);
//
//					}
//
//				}
//			}
//			else
//			{
//				offset = offset + (2 * sizeof(uint32_t) + (2 * sizeof(uint32_t) * glb_buf_1[1]));
//			}
//		} while (offset < sgLutChkLen && !found);
//	}
//	if (iid_list != NULL)
//		free(iid_list);
//
//	pOutput->num_glb_persist_identifiers = entryCnt;
//	pOutput->size = (uint32_t)totalsize;
//
//	ACDB_PKT_LOG_DATA("RspBufSize", &pOutput->size, sizeof(pOutput->size));
//	ACDB_PKT_LOG_DATA("RspBufNumGlbIds", &pOutput->num_glb_persist_identifiers, sizeof(pOutput->num_glb_persist_identifiers));
//	if (pOutput->global_persistent_cal_info != NULL)
//	{
//		ACDB_PKT_LOG_DATA("RspBuf", pOutput->global_persistent_cal_info, totalsize);
//	}
//
//	return result;
//}

/* TODO: This api needs to be supported when the ACDB file supports global
* persistent data. This API also needs to be refactored and follow the
* approach used in AcdbCmdGetSubgraphCalNonPersist
*/
// int32_t AcdbCmdGetSubgraphGlbPersistCalData(AcdbGlbPersistCalDataCmdType *pInput, AcdbBlob *pOutput, uint32_t rsp_struct_size)
// {
//     __UNREFERENCED_PARAM(pInput);
//     __UNREFERENCED_PARAM(pOutput);
//     __UNREFERENCED_PARAM(rsp_struct_size);
//     return AR_ENOTEXIST;
// }

/*TODO: This api needs to be supported when the ACDB file supports global persistent data. This API also needs to be refactored */
//int32_t AcdbCmdGetSubgraphGlbPersistCalData(AcdbGlbPersistCalDataCmdType *pInput, AcdbBlob *pOutput, uint32_t rsp_struct_size)
//{
//	int32_t result = AR_EOK;
//	uint32_t chkBuf = 0;
//	uint32_t chkLen = 0;
//	uint32_t pidMapChkBuf = 0;
//	uint32_t pidMapChkLen = 0;
//	uint32_t pid_offset = 0;
//	uint32_t calBlobSize = 0;
//	size_t totalsize = 0;
//	uint32_t data_offset = 0;
//	bool_t cal_id_found = FALSE;
//	uint32_t pid = 0;
//
//	ACDB_PKT_LOG_DATA("CalID", &pInput->cal_Id, sizeof(pInput->cal_Id));
//
//	if (rsp_struct_size < 8)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, rsp_struct_size is invalid");
//		return AR_EFAILED;
//	}
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_PIDPERSIST, &pidMapChkBuf, &pidMapChkLen);
//	if (result != AR_EOK)
//		return result;
//
//	result = AcdbGetChunkInfo(ACDB_CHUNKID_DATAPOOL, &chkBuf, &chkLen);
//	if (result != AR_EOK)
//		return result;
//
//	uint32_t calID = pInput->cal_Id;
//	pid_offset += (2 * sizeof(uint32_t));//size and num of calId's
//	do
//	{
//		memset(&glb_buf_1, 0, sizeof(glb_buf_1));
//		int ret = file_seek(pidMapChkBuf + pid_offset, AR_FSEEK_BEGIN);
//		if (ret != 0)
//		{
//			ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, file seek to %d was unsuccessful", pidMapChkBuf + pid_offset);
//			return AR_EFAILED;
//		}
//		ret = file_read(&glb_buf_1, 3 * sizeof(uint32_t));
//		if (ret != 0)
//		{
//			ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, calID read was unsuccessful");
//			return AR_EFAILED;
//		}
//
//		if (calID == glb_buf_1[0])
//		{
//			pid = glb_buf_1[1];
//			data_offset = glb_buf_1[2];
//			cal_id_found = TRUE;
//			break;
//		}
//		else
//		{
//			pid_offset += ((4 * sizeof(uint32_t)) + (glb_buf_1[3] * sizeof(uint32_t)));
//		}
//
//	} while (pid_offset < pidMapChkLen && !cal_id_found);
//	if (!cal_id_found)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, cal_ID %d is not found", calID);
//		return AR_EFAILED;
//	}
//
//	ACDB_PKT_LOG_DATA("DataOffset", &data_offset, sizeof(data_offset));
//
//	//read the payload for each cal_identifier
//	uint32_t param_size = 0, new_param_size = 0, errcode = 0, iid_val = 0;
//	uint64_t zero_val_payload = 0;
//	int ret = file_seek(chkBuf + data_offset, AR_FSEEK_BEGIN);
//	if (ret != 0)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, file seek to %d was unsuccessful", chkBuf + data_offset);
//		return AR_EFAILED;
//	}
//	ret = file_read(&param_size, sizeof(param_size));
//	if (ret != 0)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, param_size read was unsuccessful");
//		return AR_EFAILED;
//	}
//	ACDB_PKT_LOG_DATA("ParamSize", &param_size, sizeof(param_size));
//	data_offset += sizeof(param_size);
//
//	memset(&glb_buf_1, 0, sizeof(glb_buf_1));
//	ret = file_seek(chkBuf + data_offset, AR_FSEEK_BEGIN);
//	if (ret != 0)
//	{
//		ACDB_ERR("AcdbCmdGetSubgraphGlbPersistCalData() failed, file seek to %d was unsuccessful", chkBuf + data_offset);
//		return AR_EFAILED;
//	}
//
//	//Add paddig if necessary before sending the response back
//	if ((param_size % 8) != 0)
//	{
//		new_param_size = param_size + (8 - ((param_size % 8)));
//	}
//	else
//	{
//		new_param_size = param_size;
//	}
//
//	totalsize += sizeof(iid_val) + sizeof(pid) + sizeof(errcode) + sizeof(new_param_size);
//	totalsize += new_param_size;
//
//	if (pOutput->buf != NULL)
//	{
//		if (pOutput->buf_size >= (calBlobSize + (4 * sizeof(uint32_t))))
//		{
//		ACDB_MEM_CPY(pOutput->buf + calBlobSize, &iid_val, sizeof(iid_val));
//		calBlobSize += sizeof(iid_val);
//		ACDB_MEM_CPY(pOutput->buf + calBlobSize, &pid, sizeof(pid));
//		calBlobSize += sizeof(pid);
//		ACDB_MEM_CPY(pOutput->buf + calBlobSize, &param_size, sizeof(param_size));
//		calBlobSize += sizeof(param_size);
//		ACDB_MEM_CPY(pOutput->buf + calBlobSize, &errcode, sizeof(errcode));
//		calBlobSize += sizeof(errcode);
//		}
//		else
//		{
//			return AR_ENEEDMORE;
//		}
//
//		if (param_size != 0)
//		{
//			if (param_size < sizeof(glb_buf_1))
//			{
//				ret = file_read(&glb_buf_1, param_size);
//				if (ret != 0)
//				{
//					ACDB_ERR_MSG_1("Failed to read parameter payload from database.", ret);
//					ACDB_ERR("IID: %x PID: %x Size: %d", iid_val, pid, param_size);
//					return ret;
//				}
//				if (pOutput->buf_size >= (calBlobSize + param_size))
//				{
//				ACDB_MEM_CPY(pOutput->buf + calBlobSize, &glb_buf_1, param_size);
//			}
//			else
//			{
//					return AR_ENEEDMORE;
//				}
//			}
//			else
//			{
//				//ret = CopyFromFileToBuf(chkBuf + data_offset, (uint8_t*)(pOutput->buf) + calBlobSize, param_size, sizeof(glb_buf_1));
//				if (pOutput->buf_size >= (calBlobSize + param_size))
//				{
//				ret = CopyFromFileToBuf(chkBuf + data_offset, (uint8_t*)(pOutput->buf) + calBlobSize, param_size, param_size);
//				if (AR_EOK != ret)
//				{
//					ACDB_ERR_MSG_1("Failed to read parameter payload from database.", ret);
//					ACDB_ERR("IID: %x PID: %x Size: %d", iid_val, pid, param_size);
//					return ret;
//				}
//			}
//				else
//				{
//					return AR_ENEEDMORE;
//				}
//			}
//		}
//		calBlobSize += param_size;
//
//		if (pOutput->buf_size >= (calBlobSize + new_param_size - param_size))
//		{
//		ACDB_MEM_CPY(pOutput->buf + calBlobSize, &zero_val_payload, new_param_size - param_size);
//		}
//		else
//		{
//			return AR_ENEEDMORE;
//		}
//		calBlobSize += (new_param_size - param_size);
//
//		ACDB_PKT_LOG_DATA("RspBuf", pOutput->buf, totalsize);
//	}
//	pOutput->buf_size = (uint32_t)totalsize;
//	ACDB_PKT_LOG_DATA("RspBufSize", &pOutput->buf_size, sizeof(pOutput->buf_size));
//	return result;
//}

/**
* \brief
*		Sets parameter calibration to the heap and saves to the delta file if
*       delta support is enabled.
*
* \param[in/out] info: Context info containing the module kv
* \param[in/out] req: Contains calibration to be set
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbSetSubgraphCalibration(AcdbAudioCalContextInfo *info,
    AcdbSetCalDataReq *req)
{
    int32_t status = AR_EOK;
    uint32_t cur_def_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t num_param_cal_found = 0;
    uint32_t num_iid_found = 0;
    ChunkInfo ci_cal_def = { 0 };
    uint32_t num_id_entries = 0;
    AcdbModuleHeader blob_module_header = { 0 };
    AcdbModuleHeader file_module_header = { 0 };
    AcdbSubgraphParamData subgraph_param_data = { 0 };
    AcdbIidRefCount* iid_ref = NULL;

    ci_cal_def.chunk_id = ACDB_CHUNKID_CALDATADEF;
    status = ACDB_GET_CHUNK_INFO(&ci_cal_def);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration "
            "DEF chunk information", status);
        return status;
    }

    cur_def_offset = ci_cal_def.chunk_offset + info->data_offsets.offset_def;
    status = FileManReadBuffer(&num_id_entries, sizeof(uint32_t), &cur_def_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of "
            "<iid, pid> entries", status);
        return status;
    }

    if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        //Ensure global buffer can store the default data IID Reference list
        if (GLB_BUF_1_LENGTH < num_id_entries * 2)
        {
            ACDB_ERR("Error[%d]: Need more memory to store IID reference list",
                AR_ENEEDMORE);
            return AR_ENEEDMORE;
        }

        ACDB_CLEAR_BUFFER(glb_buf_1);

        iid_ref = (AcdbIidRefCount*)glb_buf_1;
    }

    /* Parse the input cal blob, find the matching  <IID,PID> pair and set
     * the calibration to the heap */
    for (uint32_t i = 0; i < num_id_entries; i++)
    {
        status = FileManReadBuffer(&file_module_header, sizeof(AcdbMiidPidPair),
            &cur_def_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read number of "
                "<iid, pid> entries", status);
            goto end;
        }

        if (info->is_default_module_ckv && info->ignore_get_default_data)
        {
            //Add IIDs to list and ignore set data
            if (iid_ref->module_iid != file_module_header.module_iid && num_iid_found == 0)
            {
                iid_ref->module_iid = file_module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
                //iid_ref++;
            }
            else if (iid_ref->module_iid != file_module_header.module_iid)
            {
                iid_ref++;
                iid_ref->module_iid = file_module_header.module_iid;
                iid_ref->ref_count = 1;
                num_iid_found++;
            }
            else
            {
                /* Increase ref count of the current <IID, Ref Count> Obj */
                iid_ref->ref_count++;
            }

            continue;
        }
        else
        {
            /* For other CKVs, if the module is in the default data list, remove it */
            if (!IsNull(info->default_data_iid_list.list))
            {
                iid_ref = (AcdbIidRefCount*)
                    info->default_data_iid_list.list;
                bool_t found_iid = FALSE;
                for (uint32_t j = 0; j < info->
                    default_data_iid_list.count; j++)
                {
                    if ((file_module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count > 0)
                    {
                        iid_ref->ref_count--;
                        found_iid = TRUE;
                        break;
                    }
                    else if ((file_module_header.module_iid == iid_ref->module_iid)
                        && iid_ref->ref_count <= 0)
                        break;

                    iid_ref++;
                }

                if (info->is_default_module_ckv && !found_iid)
                {
                    //cur_dot_offset += sizeof(uint32_t);
                    continue;
                }
            }
        }

        blob_offset = 0;
        do
        {
            ACDB_MEM_CPY_SAFE(&blob_module_header, sizeof(AcdbModuleHeader),
                (uint8_t*)req->cal_blob + blob_offset,
                sizeof(AcdbModuleHeader));

            if (0 == memcmp(&file_module_header, &blob_module_header,
                sizeof(AcdbMiidPidPair)))
            {
                //set calibration to heap
                subgraph_param_data.data_size = sizeof(AcdbDspModuleHeader) +
                    ACDB_ALIGN_8_BYTE(blob_module_header.param_size);
                subgraph_param_data.data =
                    (uint8_t*)req->cal_blob + blob_offset;
                subgraph_param_data.subgraph_id_list.count = 1;
                subgraph_param_data.subgraph_id_list.list = glb_buf_3;
                /* Use glb_buf_3 to resolve Warning C4366 caused by:
                 * (uint32_t*)&info->subgraph_id */
                glb_buf_3[0] = info->subgraph_id;

                status = DataProcSetCalData(
                    info->module_ckv, &subgraph_param_data);
                if (AR_FAILED(status))
                {
                    ACDB_DBG("Error[%d]: Failed to set calibration for "
                        "Subgraph(0x%x) Module(0x%x) Parameter(0x%x)");
                }

                num_param_cal_found++;
                break;
            }

            blob_offset += sizeof(AcdbDspModuleHeader) +
                 + ACDB_ALIGN_8_BYTE(blob_module_header.param_size);
        } while (blob_offset < req->cal_blob_size);
    }

end:
    if (info->is_default_module_ckv && !info->ignore_get_default_data)
    {
        ACDB_FREE(info->default_data_iid_list.list);
        info->default_data_iid_list.list = NULL;
    }
    else if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        /* Copy the IID Ref Count list from GLB_BUF_1 since it will be
        * cleared outside of this call */
        info->default_data_iid_list.count = num_iid_found;

        //List of AcdbIidRefCount
        info->default_data_iid_list.list = (uint32_t*)
            ACDB_MALLOC(AcdbIidRefCount, num_iid_found);

        if (IsNull(info->default_data_iid_list.list))
        {
            ACDB_ERR("Error[%d]: Unable to allocate memory "
                "for instance id reference list", AR_ENOMEMORY);
            return AR_ENOMEMORY;
        }

        ACDB_MEM_CPY_SAFE(info->default_data_iid_list.list,
            num_iid_found * sizeof(AcdbIidRefCount),
            &glb_buf_1[0], num_iid_found * sizeof(AcdbIidRefCount));

        iid_ref = NULL;
    }

    if (info->is_default_module_ckv && info->ignore_get_default_data)
    {
        return AR_EOK;
    }
    else if (num_param_cal_found == 0) return AR_ENOTEXIST;

    return status;
}

int32_t AcdbCmdSetCalData(AcdbSetCalDataReq *req)
{
    int32_t status = AR_EOK;
    bool_t is_data_set = FALSE;
    uint32_t offset = 0;
    uint32_t num_subgraph = 0;
    uint32_t subgraph_id = 0;
    //Number of subgraphs that data was found for
    uint32_t num_subgraph_found = 0;
    uint32_t ckv_list_offset = 0;
    uint32_t default_ckv_entry_offset = 0;
    AcdbSubgraph* subgraph = NULL;
    ChunkInfo ci_sg_cal_lut = { 0 };
    AcdbSgCalLutHeader sg_cal_lut_header = { 0 };
    AcdbCalKeyTblEntry ckv_entry = { 0 };
    AcdbAudioCalContextInfo info;
    AcdbGetGraphRsp graph = {0};

    (void)ar_mem_set(&info, 0, sizeof(AcdbAudioCalContextInfo));

    if (IsNull(req))
    {
        ACDB_ERR("Error[%d]: The input parameter is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->cal_blob_size == 0 || IsNull(req->cal_blob))
    {
        ACDB_ERR("Error[%d]: The input blob is empty. "
            "There are no parameters to set.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->graph_key_vector.num_keys == 0)
    {
        ACDB_ERR("Error[%d]: The graph key vector can not be empty.",
            AR_EUNSUPPORTED);
        return AR_EUNSUPPORTED;
    }
    else
    {
        ACDB_DBG("Setting cal data for the following graph key vector:");
        LogKeyVector(&req->graph_key_vector, GRAPH_KEY_VECTOR);
    }

    status = AcdbGetUsecaseSubgraphList(
        &req->graph_key_vector, NULL, &graph);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get usecase subgraphs.",
            status);
        goto end;
    }

    ci_sg_cal_lut.chunk_id = ACDB_CHUNKID_CALSGLUT;
    status = ACDB_GET_CHUNK_INFO(&ci_sg_cal_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration LUT "
            "chunk information", status);
        return status;
    }

    /* CKV Setup
    * 1. GLB_BUF_2 stores the module CKV that will be used to locate data in
    * the heap(if it exists)
    * 2. The Delta CKV and CKV[New] are allocated on the heap by
    * AcdbComputeDeltaCKV
    *
    * tmp - stores the amount of padding after graph_key_vectornum_keys
    * tmp2 - stores the position of the KeyValuePair list
    *
    * The first info.module_ckv->graph_key_vector assignment has the effect
    * of storing the address of the pointer in glb_buf_2 after
    * graph_key_vector.num_keys
    *
    * The second info.module_ckv->graph_key_vector assignment has the effect
    * of pointer the info.module_ckv->graph_key_vector to the actual list
    * of key value pairs
    *
    * Whats inside global buffer 2 after these operations?
    *
    * The first 'sizeof(AcdbGraphKeyVector)' bytes is AcdbGraphKeyVector
    * followed by 'sizeof(AcdbKeyValuePair) * num_keys' bytes which is
    * the KV list
    */
    info.module_ckv = (AcdbGraphKeyVector*)&glb_buf_2[0];
    uint32_t tmp = (sizeof(AcdbGraphKeyVector) - sizeof(AcdbKeyValuePair *)) / sizeof(uint32_t);
    uint32_t tmp2 = sizeof(AcdbGraphKeyVector) / sizeof(uint32_t);
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp];
    info.module_ckv->graph_key_vector = (AcdbKeyValuePair*)&glb_buf_2[tmp2];

    info.ckv = &req->cal_key_vector;

    /* For Set Data this flag must be set to true since delta CKVs are
     * not applicable */
    info.is_first_time = TRUE;

    offset = ci_sg_cal_lut.chunk_offset;
    status = FileManReadBuffer(&num_subgraph,
        sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of Subgraphs",
            status);
        goto end;
    }

    subgraph = graph.subgraphs;
    if (IsNull(subgraph))
    {
        ACDB_ERR("Error[%d]: The subgraph list is null",
            status);
        goto end;
    }

    subgraph_id = 0;
    for (uint32_t i = 0; i < graph.num_subgraphs; i++)
    {
        subgraph_id = subgraph->sg_id;
        offset = ci_sg_cal_lut.chunk_offset + sizeof(uint32_t);

        //Go to the next subgraph as long as we are not on the last subgraph
        if(i != graph.num_subgraphs - 1)
            subgraph = (AcdbSubgraph*)((uint8_t*)subgraph
                + sizeof(AcdbSubgraph)
                + subgraph->num_dst_sgids * sizeof(uint32_t));

        sg_cal_lut_header.subgraph_id = subgraph_id;
        status = SearchSubgraphCalLut2(&sg_cal_lut_header, &ckv_list_offset);
        if (AR_ENOTEXIST == status)
        {
            ACDB_ERR("Error[%d] Subgraph(%x) does not exist. Skipping..",
                AR_ENOTEXIST, subgraph_id);
            continue;
        }

        if (sg_cal_lut_header.num_ckv_entries == 0)
        {
            ACDB_ERR("Error[%d]: Subgraph(%x) contains zero CKV entries in"
                " the Subgraph Cal LUT. At least one entry should be"
                " present. Skipping..",
                AR_ENOTEXIST, subgraph_id);
            continue;
        }

        info.ignore_get_default_data =
            sg_cal_lut_header.num_ckv_entries == 1 ? FALSE : TRUE;

        //The default CKV will be skipped and handeled last
        if (sg_cal_lut_header.num_ckv_entries > 1)
            sg_cal_lut_header.num_ckv_entries++;

        default_ckv_entry_offset = ckv_list_offset;

        for (uint32_t k = 0; k < sg_cal_lut_header.num_ckv_entries; k++)
        {
            /* The Default CKV is always the first CKV in the list of CKVs to
             * search. It will be skipped and processed last */
            if ((k == sg_cal_lut_header.num_ckv_entries - 1) &&
                info.ignore_get_default_data == TRUE)
            {
                info.ignore_get_default_data = FALSE;

                status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                    &default_ckv_entry_offset);
            }
            else
            {
                status = FileManReadBuffer(&ckv_entry, sizeof(ckv_entry),
                    &ckv_list_offset);
            }

            if (AR_FAILED(status))
            {
                goto end;
            }

            info.subgraph_id = sg_cal_lut_header.subgraph_id;

            status = AcdbFindModuleCKV(&ckv_entry, &info);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                continue;
            }
            else if (AR_FAILED(status))
            {
                goto end;
            }

            //Set Calibration to heap and save to delta file
            status = AcdbSetSubgraphCalibration(&info, req);
            if (AR_FAILED(status) && status == AR_ENOTEXIST)
            {
                continue;
            }

            is_data_set = TRUE;
        }

        if (AR_FAILED(status) && !is_data_set)
        {
            ACDB_DBG("Error[%d]: Unable to set calibration data for "
                "Subgraph(%x). Skipping..", status,
                sg_cal_lut_header.subgraph_id);
            status = AR_EOK;
        }
        else
        {
            status = AR_EOK;
            is_data_set = FALSE;
            num_subgraph_found++;
        }
    }

    if (num_subgraph_found == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Unable to set calibration for the "
            "provided usecase graph key vector", status);
        goto end;
    }

    //Save Heap data to Delta File if there is data to save
    if (acdb_delta_data_is_persist_enabled())
    {
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SAVE,
            NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to save delta file.", status);
        }
    }
    else
    {
        ACDB_ERR("Error[%d]: Unable to save delta data. Is delta data"
            " persistance enabled?", status);
    }

end:

    //Clean Up Context Info
    info.ckv = NULL;
    AcdbClearAudioCalContextInfo(&info);

    return status;
}

int32_t AcdbGetAmdbProcDeregData(
    acdb_amdb_proc_reg_data_t* proc_reg_data, uint32_t expected_size,
    uint32_t *blob_offset, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t data_size = 0;
    acdb_amdb_module_reg_info_t* module_reg_data = NULL;
    AcdbOp op = ACDB_OP_NONE;

    if (IsNull(rsp))
        return AR_EBADPARAM;

    op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (ACDB_OP_GET_SIZE == op)
    {
        return status;
    }

    module_reg_data = proc_reg_data->module_reg_data;
    data_size = *(uint32_t*)module_reg_data;

    for (uint32_t j = 0; j < proc_reg_data->module_count; j++)
    {
        uint32_t module_id = *((uint32_t*)module_reg_data + 3);
        if (*blob_offset > expected_size)
            return AR_ENEEDMORE;

        ACDB_MEM_CPY_SAFE(rsp->buf + *blob_offset, sizeof(uint32_t),
            &module_id, sizeof(uint32_t));
        *blob_offset += sizeof(module_id);

        //Go to next module
        module_reg_data = (acdb_amdb_module_reg_info_t*)
            ((uint8_t*)module_reg_data + data_size
                + sizeof(uint32_t));
        data_size = *(uint32_t*)module_reg_data;
    }

	return status;
}

int32_t AcdbGetAmdbProcRegData(
    acdb_amdb_proc_reg_data_t* proc_reg_data, uint32_t expected_size,
    uint32_t *blob_offset,  AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t data_size = 0;
    acdb_amdb_module_reg_info_t* module_reg_data = NULL;
    AcdbOp op = ACDB_OP_NONE;
    void* moudule_reg_data_start = NULL;

    if (IsNull(rsp))
        return AR_EBADPARAM;

    op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    if (ACDB_OP_GET_SIZE == op)
    {
        return status;
    }

    module_reg_data = proc_reg_data->module_reg_data;
    data_size = *(uint32_t*)module_reg_data;

    for (uint32_t j = 0; j < proc_reg_data->module_count; j++)
    {
        if (*blob_offset > expected_size)
            return AR_ENEEDMORE;

        moudule_reg_data_start = (uint8_t*)module_reg_data
            + sizeof(uint32_t);

        ACDB_MEM_CPY_SAFE(
            rsp->buf + *blob_offset, data_size,
            moudule_reg_data_start, data_size);
        *blob_offset += data_size;

        //Go to next module
        module_reg_data = (acdb_amdb_module_reg_info_t*)
            ((uint8_t*)module_reg_data + data_size
                + sizeof(uint32_t));
        data_size = *(uint32_t*)module_reg_data;
    }

	return status;
}

int32_t AcdbGetAmdbProcRegDeregData(
    acdb_amdb_reg_dereg_info_type_t info_type,
    bool_t use_active_context,
    uint32_t proc_id, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t blob_offset = 0;
    uint32_t expected_size = 0;
    uint32_t processor_count = 0;
    uint32_t total_num_modules = 0;
    uint32_t total_proc_data_size = 0;
    uint32_t curr_struct_version = 0;
    uint32_t db_index = 0;
    uint32_t amdb_proc_reg_data_header_size = 0;
    bool_t found = FALSE;
    uint32_t db_count = 0;
    ChunkInfo ci_amdb_reg = { 0 };
    acdb_amdb_module_reg_info_t module_reg_info = { 0 };
    acdb_amdb_proc_reg_data_t proc_reg_data = { 0 };
    acdb_spf_amdb_module_reg_t spf_amdb_reg = { 0 };
    acdb_amdb_module_dereg_t spf_amdb_dereg = { 0 };
    AcdbOp op = ACDB_OP_NONE;

    if (IsNull(rsp))
        return AR_EBADPARAM;

    op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    expected_size = rsp->buf_size;
    ci_amdb_reg.chunk_id = ACDB_CHUNKID_AMDB_REG_DATA;
    proc_reg_data.module_reg_data = &module_reg_info;

    if (ACDB_OP_GET_DATA == op)
    {
        /* Make space to write the header, collect the total
        * number of modules */
        switch (info_type)
        {
        case ACDB_AMDB_INFO_REGISTRATION:
            if (sizeof(acdb_spf_amdb_module_reg_t) > expected_size)
                return AR_ENEEDMORE;
            blob_offset += sizeof(acdb_spf_amdb_module_reg_t);
            break;
        case ACDB_AMDB_INFO_DEREGISTRATION:
            if (sizeof(acdb_amdb_module_dereg_t) > expected_size)
                return AR_ENEEDMORE;
            blob_offset += sizeof(acdb_amdb_module_dereg_t);
            break;
        default:
            status = AR_EUNSUPPORTED;
            ACDB_ERR("Error[%d]: Unknown AMDB info type", status);
            return status;
        }
    }

    db_count = use_active_context ? 1 : ACDB_CTX_MAN_DATABASE_COUNT;
    for (db_index = 0; db_index < db_count; db_index++)
    {
        if (!use_active_context)
        {
            status = acdb_ctx_man_ioctl(
                ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_INDEX,
                &db_index, sizeof(uint32_t), NULL, 0);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to set database context",
                    status);
                return status;
            }
        }

        status = ACDB_GET_CHUNK_INFO(&ci_amdb_reg);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to get AMDB "
                "registration data chunk.", status);
            return status;
        }

        offset = ci_amdb_reg.chunk_offset;
        status = FileManReadBuffer(&processor_count,
            sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read processor count.", status);
            return status;
        }

        amdb_proc_reg_data_header_size =
            sizeof(acdb_amdb_proc_reg_data_t)
            - sizeof(acdb_amdb_module_reg_info_t*);
        for (uint32_t i = 0; i < processor_count; i++)
        {
            status = FileManReadBuffer(&proc_reg_data,
                amdb_proc_reg_data_header_size, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to get processor reg "
                    "from database.", status);
                return status;
            }

            if (proc_id == proc_reg_data.proc_id)
            {
                status = FileManGetFilePointer2((void **)&proc_reg_data.module_reg_data, offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Unable to get module reg "
                        "info for Proccessor %d from database.",
                        status, proc_reg_data.proc_id);
                    return status;
                }

                found = TRUE;
                break;
            }

            // Go to next processor reg data
            offset += proc_reg_data.data_size
                - amdb_proc_reg_data_header_size
                + sizeof(proc_reg_data.data_size);
        }

        if (!found)
        {
            status = AR_ENOTEXIST;
            ACDB_ERR("Warning[%d]: Processor ID(%d) does not exist in "
                "database for VM-%d. Skipping..", AR_ENOTEXIST, proc_id, 0);
            continue;
        }

        status = AR_EOK;
        total_num_modules += proc_reg_data.module_count;
        /* Remove acdb_amdb_module_reg_info_t::data_size in all modules
        * from the total proc reg data output size */
        total_proc_data_size += proc_reg_data.data_size
            - sizeof(uint32_t) * proc_reg_data.module_count;

        if (!curr_struct_version)
            curr_struct_version = proc_reg_data.struct_version;
        else if (curr_struct_version != proc_reg_data.struct_version)
        {
            /* User needs to correct their files b/c we can only send
            * 1 structure version in the response for
            * ACDB_AMDB_INFO_REGISTRATION */
            ACDB_ERR("Error[%d]: The AMDB structure version is different "
                "between database at index %d with v%d and %d with v%d. "
                "Only one struct version is allowed in registration data "
                "response", AR_EFAILED, db_index - 1, curr_struct_version,
                db_index, proc_reg_data.struct_version);
            return AR_EFAILED;
        }

        switch (info_type)
        {
        case ACDB_AMDB_INFO_REGISTRATION:
            status = AcdbGetAmdbProcRegData(
                &proc_reg_data, expected_size, &blob_offset, rsp);
            break;
        case ACDB_AMDB_INFO_DEREGISTRATION:
            status = AcdbGetAmdbProcDeregData(
                &proc_reg_data, expected_size, &blob_offset, rsp);
            break;
        default:
            status = AR_EUNSUPPORTED;
            ACDB_ERR("Error[%d]: Unknown AMDB info type",
                AR_EUNSUPPORTED);
            break;
        }
    }

    if (AR_FAILED(status))
    {
        return status;
    }

    /* Write AMDB reg/dereg response header */
    switch (info_type)
    {
    case ACDB_AMDB_INFO_REGISTRATION:

        rsp->buf_size = sizeof(acdb_spf_amdb_module_reg_t)
            + total_proc_data_size - (sizeof(acdb_spf_amdb_module_reg_t)
                * db_count);
        if (ACDB_OP_GET_SIZE == op) return status;

        //get data
        spf_amdb_reg.proc_id = proc_id;
        spf_amdb_reg.num_modules = total_num_modules;
        spf_amdb_reg.struct_version = curr_struct_version;

        ACDB_MEM_CPY_SAFE(
            (uint8_t*)rsp->buf, sizeof(acdb_spf_amdb_module_reg_t),
            &spf_amdb_reg, sizeof(acdb_spf_amdb_module_reg_t));
        break;
    case ACDB_AMDB_INFO_DEREGISTRATION:
        rsp->buf_size = sizeof(acdb_amdb_module_dereg_t)
            + sizeof(uint32_t) * total_num_modules;

        if (ACDB_OP_GET_SIZE == op) return status;

        //get data
        spf_amdb_dereg.proc_id = proc_id;
        spf_amdb_dereg.num_modules = total_num_modules;

        ACDB_MEM_CPY_SAFE(
            (uint8_t*)rsp->buf, sizeof(acdb_amdb_module_dereg_t),
            &spf_amdb_dereg, sizeof(acdb_amdb_module_dereg_t));
        break;
    default:
        status = AR_EUNSUPPORTED;
        ACDB_ERR("Error[%d]: Unknown AMDB info type", AR_EUNSUPPORTED);
        break;
    }

	return status;
}

int32_t AcdbGetAmdbBootLoadModuleData(
    bool_t use_active_context, uint32_t proc_id, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t blob_offset = 0;
    uint32_t processor_count = 0;
    uint32_t expected_size = 0;
    uint32_t db_count = 0;
    uint32_t total_num_modules = 0;
    bool_t found = FALSE;
    ChunkInfo ci_boot_load = { 0 };
    acdb_amdb_bootup_proc_table_entry_t* proc_entry = NULL;
    uint32_t *bootup_modules = NULL;
    acdb_amdb_bootup_module_t bootup_module = { 0 };
    acdb_amdb_proc_bootup_data_t bootup_proc_data = { 0 };
    AcdbOp op = ACDB_OP_NONE;

    ci_boot_load.chunk_id = ACDB_CHUNKID_BOOTUP_LOAD_MODULES;


    op = IsNull(rsp->buf) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;
    expected_size = rsp->buf_size;

    if (ACDB_OP_GET_DATA == op)
    {
        /* Make room to write acdb_amdb_proc_bootup_data_t header */
        blob_offset = sizeof(bootup_proc_data);
    }

    db_count = use_active_context ? 1 : ACDB_CTX_MAN_DATABASE_COUNT;
    for (uint32_t db_index = 0; db_index < db_count; db_index++)
    {
        if (!use_active_context)
        {
            status = acdb_ctx_man_ioctl(
                ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_INDEX,
                &db_index, sizeof(uint32_t), NULL, 0);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to set database context",
                    status);
                return status;
            }
        }

        status = ACDB_GET_CHUNK_INFO(&ci_boot_load);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to get AMDB registration data chunk.",
                status);
            return status;
        }

        offset = ci_boot_load.chunk_offset;

        status = FileManReadBuffer(&processor_count, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read processor count.", status);
            return status;
        }

        status = FileManGetFilePointer2((void **)&proc_entry, offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read processor count.", status);
            return status;
        }

        for (uint32_t i = 0; i < processor_count; i++)
        {
            if (proc_id == proc_entry->proc_id)
            {
                found = TRUE;
                break;
            }

            // Go to next processor bootup entry
            proc_entry = (acdb_amdb_bootup_proc_table_entry_t*)
                ((uint8_t*)proc_entry + proc_entry->num_modules
                    * sizeof(uint32_t) + sizeof(acdb_amdb_bootup_proc_table_entry_t));
        }

        if (!found)
        {
            ACDB_ERR("Error[%d]: Processor ID(%d) does not exist",
                AR_ENOTEXIST, proc_id);
            return AR_ENOTEXIST;
        }

        total_num_modules += proc_entry->num_modules;

        if (ACDB_OP_GET_SIZE == op) continue;

        bootup_modules = &proc_entry->module_ids[0];
        for (uint32_t j = 0; j < proc_entry->num_modules; j++)
        {
            if (blob_offset > expected_size)
                return AR_ENEEDMORE;

            bootup_module.module_id = bootup_modules[j];

            ACDB_MEM_CPY_SAFE(
                (uint8_t*)rsp->buf + blob_offset, sizeof(bootup_module),
                &bootup_module, sizeof(bootup_module));
            blob_offset += sizeof(bootup_module);
        }
    }

    switch (op)
    {
    case ACDB_OP_GET_SIZE:
        rsp->buf_size = sizeof(acdb_amdb_proc_bootup_data_t)
            + sizeof(acdb_amdb_bootup_module_t) * total_num_modules;
        break;
    case ACDB_OP_GET_DATA:
        bootup_proc_data.proc_id = proc_id;
        bootup_proc_data.num_modules = total_num_modules;

        ACDB_MEM_CPY_SAFE(
            (uint8_t*)rsp->buf, sizeof(bootup_proc_data),
            &bootup_proc_data, sizeof(bootup_proc_data));
        break;
    default:
        break;
    }

    return status;
}

int32_t AcdbCmdGetAmdbRegData(AcdbAmdbProcID *req, AcdbBlob *rsp)
{
	int32_t status = AR_EOK;

	if (IsNull(req) || IsNull(rsp))
	{
		ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
		return AR_EBADPARAM;
	}

    status = AcdbGetAmdbProcRegDeregData(ACDB_AMDB_INFO_REGISTRATION,
        FALSE, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB module registration info.",
            status);
        return status;
    }

	return status;
}

int32_t AcdbCmdGetAmdbDeregData(AcdbAmdbProcID* req,
    AcdbBlob* rsp)
{
    int32_t status = AR_EOK;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = AcdbGetAmdbProcRegDeregData(ACDB_AMDB_INFO_DEREGISTRATION,
        FALSE, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB module de-registration info.",
            status);
        return status;
    }

	return status;
}

int32_t AcdbCmdGetSubgraphProcIds(AcdbCmdGetSubgraphProcIdsReq *req,
    AcdbCmdGetSubgraphProcIdsRsp *rsp, uint32_t rsp_size)
{
	int32_t status = AR_EOK;
	uint32_t num_sgIds = 0;
	uint32_t total_sz = 0;
	uint32_t data_offset = 0;
	uint32_t proc_offset = 0;
	uint32_t num_modules_proc = 0;
    AcdbSubgraphPdmMap sg_mod_iid_map = { 0 };
    AcdbUintList subgraph_list = { 0 };

	if (rsp_size < sizeof(AcdbCmdGetSubgraphProcIdsRsp))
	{
		ACDB_ERR("Error[%d]: The response structure size is less than %d",
            AR_EBADPARAM, sizeof(AcdbCmdGetSubgraphProcIdsRsp));
		return AR_EBADPARAM;
	}

    subgraph_list.count = req->num_sg_ids;
    subgraph_list.list = req->sg_ids;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
        &subgraph_list, sizeof(subgraph_list), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set file index",
            status);
        return status;
    }

	for (uint32_t i = 0; i < req->num_sg_ids; i++)
	{
        ar_mem_set((void*)&sg_mod_iid_map, 0, sizeof(AcdbSubgraphPdmMap));
		proc_offset = 0;
		status = DataProcGetSubgraphProcIidMap(req->sg_ids[i], &sg_mod_iid_map);
		if (AR_EOK != status)
		{
			//Return even if it can't find data for one of the given subgraphs
            goto end;
		}

		num_sgIds++;
        total_sz += sizeof(AcdbSgProcIdsMap)
            + sg_mod_iid_map.proc_count * sizeof(uint32_t); //sg_mod_iid_map->size;
		if (rsp->sg_proc_ids != NULL)
		{
            if (rsp->size < (data_offset + (2 * sizeof(uint32_t))))
            {
                status = AR_ENEEDMORE;
                goto end;
            }

			ACDB_MEM_CPY_SAFE(
                rsp->sg_proc_ids + data_offset,
                sizeof(sg_mod_iid_map.subgraph_id),
                &sg_mod_iid_map.subgraph_id,
                sizeof(sg_mod_iid_map.subgraph_id));
			data_offset += sizeof(sg_mod_iid_map.subgraph_id);

			ACDB_MEM_CPY_SAFE(rsp->sg_proc_ids + data_offset,
                sizeof(sg_mod_iid_map.proc_count),
                &sg_mod_iid_map.proc_count,
                sizeof(sg_mod_iid_map.proc_count));
			data_offset += sizeof(sg_mod_iid_map.proc_count);

			for (uint32_t j = 0; j < sg_mod_iid_map.proc_count; j++)
			{
				if (rsp->size < (data_offset + sizeof(uint32_t)))
				{
                    status = AR_ENEEDMORE;
                    goto end;
				}

                ACDB_MEM_CPY_SAFE(rsp->sg_proc_ids + data_offset,
                    sizeof(uint32_t),
                    sg_mod_iid_map.proc_info + proc_offset,
                    sizeof(uint32_t));
                data_offset += sizeof(uint32_t); //size of each procID

				proc_offset += sizeof(uint32_t);
				ACDB_MEM_CPY_SAFE(&num_modules_proc,
                    sizeof(uint32_t),
                    sg_mod_iid_map.proc_info + proc_offset,
                    sizeof(uint32_t));
				proc_offset += (sizeof(num_modules_proc)
                    + (num_modules_proc * sizeof(AcdbModuleInstance)));
			}
		}
	}

end:
    if (AR_FAILED(status))
    {
        return status;
    }

	rsp->num_sg_ids = num_sgIds;
	rsp->size = total_sz;
	return status;
}

int32_t AcdbCmdGetAmdbBootupLoadModules(AcdbAmdbProcID *req,
    AcdbBlob *rsp)
{
	int32_t status = AR_EOK;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    status = AcdbGetAmdbBootLoadModuleData(FALSE, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB bootup load/unload info.",
            status);
        return status;
    }

	return status;
}

int32_t AcdbCmdGetAmdbRegDataV2(AcdbAmdbDbHandle *req, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    bool_t should_use_handle = TRUE;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (IsNull(req->acdb_handle))
    {
        should_use_handle = FALSE;
    }

    if (should_use_handle)
    {
        status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
            &req->acdb_handle, sizeof(acdb_handle_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to set databae context",
                status);
            return status;
        }
    }

    status = AcdbGetAmdbProcRegDeregData(ACDB_AMDB_INFO_REGISTRATION,
        should_use_handle, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB module registration info.",
            status);
        return status;
    }

    return status;
}

int32_t AcdbCmdGetAmdbDeregDataV2(AcdbAmdbDbHandle *req, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    bool_t should_use_handle = TRUE;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (IsNull(req->acdb_handle))
    {
        should_use_handle = FALSE;
    }

    if (should_use_handle)
    {
        status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
            &req->acdb_handle, sizeof(acdb_handle_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to set databae context",
                status);
            return status;
        }
    }

    status = AcdbGetAmdbProcRegDeregData(ACDB_AMDB_INFO_DEREGISTRATION,
        should_use_handle, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB module de-registration info.",
            status);
        return status;
    }

    return status;
}

int32_t AcdbCmdGetAmdbBootupLoadModulesV2(AcdbAmdbDbHandle *req, AcdbBlob *rsp)
{
    int32_t status = AR_EOK;
    bool_t should_use_handle = TRUE;

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (IsNull(req->acdb_handle))
    {
        should_use_handle = FALSE;
    }

    if (should_use_handle)
    {
        status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
            &req->acdb_handle, sizeof(acdb_handle_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to set databae context",
                status);
            return status;
        }
    }

    status = AcdbGetAmdbBootLoadModuleData(
        should_use_handle, req->proc_id, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get AMDB bootup load/unload info.",
            status);
        return status;
    }

	return status;
}

/**
* \brief SearchTaggedModuleMapLutForAnyTag
*		Search the Tagged Module Map LUT for SubgraphTagEntries that match the input subgraph with any tag.
* \param[int] sg_id: Subgraph ID to search for
* \param[int] sg_lut_buf: List of Tagged Module Map entries
* \param[int] buf_size: size of Tagged Module Map buffer
* \param[out] tag_id: The Tag ID associated with the Subgraph
* \param[out] def_offset: Offset of the Module(s) associated with the tag
* \param[out] entry_offset: Offset of the SubgraphTagLutEntry in the sg_lut_buf
* \return AR_EOK on success, and AR_ENOTEXIST otherwise as well as tag id and def offset
*/
int32_t SearchTaggedModuleMapLutForAnyTag(uint32_t sg_id, uint32_t* sg_lut_buf, uint32_t buf_size, uint32_t *tag_id, uint32_t* def_offset, uint32_t *entry_offset)
{
	uint32_t entry_offset_tmp = 0;
	uint32_t search_index_count = 1;
	//Search for any tag
	SubgraphTagLutEntry sgTagEntry;

	sgTagEntry.sg_id = sg_id;
	sgTagEntry.tag_id = 0;
	sgTagEntry.offset = 0;

	if (SEARCH_ERROR == AcdbDataBinarySearch2((void*)sg_lut_buf, buf_size,
		&sgTagEntry, search_index_count,
		(int32_t)(sizeof(SubgraphTagLutEntry) / sizeof(uint32_t)),
		&entry_offset_tmp))
	{
		return AR_ENOTEXIST;
	}

	ACDB_MEM_CPY_SAFE(&sgTagEntry, sizeof(SubgraphTagLutEntry),
        sg_lut_buf + entry_offset_tmp * sizeof(uint32_t),
        sizeof(SubgraphTagLutEntry));

	if (sg_id == sgTagEntry.sg_id)
	{
		*tag_id = sgTagEntry.tag_id;
		*def_offset = sgTagEntry.offset;
		*entry_offset = entry_offset_tmp;
	}

	return AR_EOK;
}

/**
* \brief
*       Search for the first occurance of a <Subgraph ID, Tag ID, Def Offset>
*       tuple using the Subgraph ID as a search key and returns the file
*       offset of the first occurrance.
*
* \param[in/out] sg_tag_entry: Tag Key Data Table entry in the
*           format of <Subgraph ID, Tag ID, Def Offset>
* \param[in/out] file_offset: The absolute offset of the
*           <Subgraph ID, Tag ID, Def Offset> entry
* \return AR_EOK on success, non-zero otherwise
*/
int32_t TaggedModuleMapLutFindFirstOfSubgraphID(
    ChunkInfo *ci_tagged_module_map_lut, SubgraphTagLutEntry *sg_tag_entry,
    uint32_t *file_offset)
{
    int32_t status = AR_EOK;
    uint32_t search_index_count = 1;//Binary Search based on Subgraph id
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    if (IsNull(sg_tag_entry) || IsNull(file_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    //Setup Table Information
    table_info.table_offset = ci_tagged_module_map_lut->chunk_offset
        + sizeof(uint32_t);
    table_info.table_size = ci_tagged_module_map_lut->chunk_size
        - sizeof(uint32_t);
    table_info.table_entry_size = sizeof(SubgraphTagLutEntry);

    //Setup Search Information
    search_info.num_search_keys = search_index_count;
    search_info.num_structure_elements =
        (sizeof(SubgraphTagLutEntry) / sizeof(uint32_t));
    search_info.table_entry_struct = sg_tag_entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_DBG("Error[%d]: No tags found under Subgraph(0x%x).",
            status, sg_tag_entry->sg_id);
        return status;
    }

    *file_offset = ci_tagged_module_map_lut->chunk_offset
        + sizeof(uint32_t) //Number of <SubgraphID, Tag> entries
        + search_info.entry_offset;

    return status;
}

int32_t GetTagsFromGkvGetSize(
    ChunkInfo *lut_chunk, ChunkInfo *def_chunk,
    AcdbUintList* subgraph_list,
    AcdbTagDefOffsetPairList *tag_defofst_list,
    AcdbCmdGetTagsFromGkvRsp* rsp)
{
    int32_t status = AR_EOK;
    uint32_t cur_sg_id = 0;
    uint32_t offset = 0;
    uint32_t def_offset = 0;
    uint32_t num_modules = 0;
    uint32_t sz_tag_module_obj = 0;
    uint32_t sz_module_list = 0;
    bool_t new_tag_found = TRUE;
    SubgraphTagLutEntry* tagged_module_lut = NULL;
    AcdbUintList found_tags = { 0 };
    SubgraphTagLutEntry sg_tag_entry = { 0 };
    uint32_t sg_tag_entry_offset = 0;
    uint32_t lut_end_offset = 0;
    AcdbTagDefOffsetPair tag_def_pair = { 0 };

    /* GLB BUF 1 stores <Tag ID, Def Offset> entries
     * GLB BUF 2 stores the tags already found
     * GLB BUF 3 stores the subgraph list */
    if (IsNull(subgraph_list) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) are null", status);
        return AR_EBADPARAM;
    }

    offset = lut_chunk->chunk_offset + sizeof(uint32_t);//skip num entries
    status = FileManGetFilePointer2((void**)&tagged_module_lut, offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get file pointer to"
            " tagged module lookup table", status);
        return status;
    }

    rsp->num_tags = 0;
    rsp->list_size = 0;
    found_tags.list = &glb_buf_2[0];
    lut_end_offset =
        lut_chunk->chunk_offset + lut_chunk->chunk_size;

    for (uint32_t i = 0; i < subgraph_list->count; i++)
    {
        cur_sg_id = subgraph_list->list[i];
        sg_tag_entry.sg_id = cur_sg_id;
        sg_tag_entry.tag_id = 0;

        status = TaggedModuleMapLutFindFirstOfSubgraphID(
            lut_chunk, &sg_tag_entry, &sg_tag_entry_offset);
        if (AR_ENOTEXIST == status)
        {
            status = AR_EOK;
            continue;
        }
        else if (AR_FAILED(status))
        {
            return status;
        }

        //Set offset to next <Subgraph ID, Tag ID, Def Offset> entry
        sg_tag_entry_offset += sizeof(sg_tag_entry);

        do
        {
            if (cur_sg_id != sg_tag_entry.sg_id)
                break;

            //Get <Module ID, Instance ID> list from Def offset
            def_offset = def_chunk->chunk_offset + sg_tag_entry.offset;
            tag_def_pair.tag_id = sg_tag_entry.tag_id;
            tag_def_pair.def_offset = def_offset;
            new_tag_found = TRUE;
            offset = 0;

            status = FileManReadBuffer(
                &num_modules, sizeof(uint32_t), &def_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read number "
                    "of modules", status);
                return status;
            }

            offset += sizeof(num_modules);
            sz_module_list = num_modules * sizeof(AcdbModule);

            if (sz_module_list == 0)
            {
                ACDB_DBG("Ignoring unused tag Tag(0x%x). It is "
                    "not associated with any module.", tag_def_pair.tag_id);
                continue;
            }

            for (uint32_t j = 0; j < found_tags.count; j++)
            {
                if (tag_def_pair.tag_id == found_tags.list[j])
                {
                    new_tag_found = FALSE;
                    break;
                }
            }

            if (!new_tag_found)
            {
                //found tag id in found_tags_list
                sz_tag_module_obj = sz_module_list;
            }
            else
            {
                //A new tag is being added

                found_tags.list[found_tags.count++] = tag_def_pair.tag_id;
                sz_tag_module_obj = sizeof(tag_def_pair.tag_id)
                    + sizeof(num_modules) + sz_module_list;
                rsp->num_tags += 1;
            }

            if (tag_defofst_list->count + 1 > tag_defofst_list->max_count)
            {
                ACDB_ERR_MSG_1("Tag definition offset list is full", status);
                status = AR_EFAILED;
                break;
            }
            else
            {
                tag_defofst_list->list[tag_defofst_list->count++] = tag_def_pair;
            }

            rsp->list_size += sz_tag_module_obj;

            if (sg_tag_entry_offset == lut_end_offset)
                break;

            //go to next entry
            status = FileManReadBuffer(&sg_tag_entry,
                sizeof(sg_tag_entry), &sg_tag_entry_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Unable to read "
                    "subgraph & tag lut entry", status);
                return status;
            }
        } while (sg_tag_entry_offset <= lut_end_offset);
    }

    return status;
}

int32_t GetTagsFromGkvGetData(
    AcdbTagDefOffsetPairList *tag_defofst_list,
    AcdbCmdGetTagsFromGkvRsp* rsp)
{
    int32_t status = AR_EOK;
    uint32_t rsp_offset = 0;
    uint32_t tag_id = 0;
    uint32_t def_offset = 0;
    uint32_t num_modules = 0;
    uint32_t sz_module_list = 0;
    uint32_t expected_size = 0;
    uint32_t prev_tag_id = 0;
    uint32_t total_num_modules = 0;
    uint32_t rsp_offset_num_modules = 0;
    uint32_t sz_tag_defofst_list = 0;
    uint8_t* mid_iid_list = NULL;
    AcdbTagDefOffsetPair *tag_def_pair = NULL;

    if (IsNull(tag_defofst_list) || IsNull(rsp)
        || IsNull(rsp->tag_module_list))
    {
        ACDB_ERR("Error[%d]: One or more input parameters "
            "are null", AR_EBADPARAM)
        return AR_EBADPARAM;
    }

    expected_size = rsp->list_size;
    sz_tag_defofst_list =
        tag_defofst_list->count * tag_defofst_list->element_size;

    //Sort tag def list based on tag ID
    status = AcdbSort2(
        sz_tag_defofst_list,
        (uint32_t*)tag_defofst_list->list,
        2 * sizeof(uint32_t), 0);

    if (AR_FAILED(status))
    {
        ACDB_ERR_MSG_1("Failed to sort Tag ID & def offset list", status);
        return status;
    }

    for (uint32_t i = 0; i < tag_defofst_list->count; i++)
    {
        tag_def_pair = &tag_defofst_list->list[i];
        tag_id = tag_def_pair->tag_id;
        num_modules = 0;
        sz_module_list = 0;

        def_offset = tag_def_pair->def_offset;
        status = FileManReadBuffer(
            &num_modules, sizeof(uint32_t), &def_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read number of modules", status);
            return status;
        }

        sz_module_list = num_modules * sizeof(AcdbModule);

        if (sz_module_list == 0)
            continue;

        if (prev_tag_id != tag_id || i == 0)
        {
            if (expected_size < (rsp_offset + sizeof(tag_id)))
                return AR_ENEEDMORE;

            //Write Tag ID
            ACDB_MEM_CPY_SAFE(rsp->tag_module_list + rsp_offset,
                sizeof(tag_id), &tag_id, sizeof(tag_id));
            rsp_offset += sizeof(tag_id);

            if (expected_size < (rsp_offset + sizeof(num_modules)))
                return AR_ENEEDMORE;

            //Write num modules
            ACDB_MEM_CPY_SAFE(rsp->tag_module_list + rsp_offset,
                sizeof(num_modules), &num_modules, sizeof(num_modules));
            rsp_offset_num_modules = rsp_offset;
            rsp_offset += sizeof(num_modules);
            total_num_modules = num_modules;

            /* Write module id list:
             * [<module id, instance id>...<module id, instance id>] */
            if (num_modules != 0)
            {
                if (expected_size < (rsp_offset + sz_module_list))
                    return AR_ENEEDMORE;

                status = FileManGetFilePointer2((void**)&mid_iid_list, def_offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR_MSG_1("Failed to read Tag module list", status);
                    return status;
                }

                ACDB_MEM_CPY_SAFE(rsp->tag_module_list + rsp_offset,
                    sz_module_list, mid_iid_list, sz_module_list);

                rsp_offset += sz_module_list;
                def_offset += sz_module_list;
            }
        }
        else
        {
            //update num_modules and write new <module id, instance id>...
            total_num_modules += num_modules;
            if (expected_size < (rsp_offset_num_modules + sizeof(total_num_modules)))
                return AR_ENEEDMORE;

            ACDB_MEM_CPY_SAFE(rsp->tag_module_list + rsp_offset_num_modules,
                sizeof(total_num_modules), &total_num_modules, sizeof(total_num_modules));

            if (num_modules != 0)
            {
                if (expected_size < (rsp_offset + sz_module_list))
                    return AR_ENEEDMORE;

                status = FileManGetFilePointer2((void**)&mid_iid_list, def_offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR_MSG_1("Failed to read Tag module list", status);
                    return status;
                }

                ACDB_MEM_CPY_SAFE(rsp->tag_module_list + rsp_offset,
                    sz_module_list, mid_iid_list, sz_module_list);

                rsp_offset += sz_module_list;
                def_offset += sz_module_list;
            }
        }

        if (AR_FAILED(status))
        {
            ACDB_ERR_MSG_1("Failed to read Tag module list from file", status);
            return status;
        }

        prev_tag_id = tag_id;
    }

    return status;
}

int32_t BuildGetTagsFromGkvRsp(AcdbUintList* subgraph_list,
    AcdbCmdGetTagsFromGkvRsp* rsp)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_lut = { 0 };
    ChunkInfo ci_def = { 0 };

    AcdbTagDefOffsetPairList tag_defofst_list = { 0 };
    AcdbOp op = ACDB_OP_NONE;

    ci_lut.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_LUT;
    ci_def.chunk_id = ACDB_CHUNKID_TAGGED_MODULE_DEF;
    status = ACDB_GET_CHUNK_INFO(&ci_lut, &ci_def);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get one or more chunks", status);
        return status;
    }

    op = IsNull(rsp->tag_module_list) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    tag_defofst_list.max_count = (uint32_t)(sizeof(glb_buf_1) / sizeof(uint32_t));
    tag_defofst_list.element_size = sizeof(AcdbTagDefOffsetPair);
    tag_defofst_list.list = (AcdbTagDefOffsetPair*)&glb_buf_1[0];

    status = GetTagsFromGkvGetSize(&ci_lut, &ci_def,
        subgraph_list, (void*)&tag_defofst_list, rsp);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get size of "
            "tagged module list", status);
        return status;
    }

    if (op == ACDB_OP_GET_DATA)
    {
        status = GetTagsFromGkvGetData((void*)&tag_defofst_list, rsp);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to get "
                "tagged module list", status);
        }
    }

    ACDB_CLEAR_BUFFER(glb_buf_1);
    ACDB_CLEAR_BUFFER(glb_buf_2);
    ACDB_CLEAR_BUFFER(glb_buf_3);

    if (rsp->num_tags == 0)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR_MSG_1("No tags were found", status);
    }

    return status;
}

int32_t AcdbCmdGetTagsFromGkv(AcdbCmdGetTagsFromGkvReq *req, AcdbCmdGetTagsFromGkvRsp *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    AcdbGraphKeyVector graph_kv = { 0 };
    AcdbUintList subgraph_list = { 0 };

    if (req->graph_key_vector->num_keys == 0)
    {
        ACDB_ERR("Error[%d]: No data exist for the empty GKV",
            AR_ENOTEXIST);
        return AR_ENOTEXIST;
    }
    else
    {
        ACDB_DBG("Retrieving Tag list for the following graph key vector:");
        LogKeyVector(req->graph_key_vector, GRAPH_KEY_VECTOR);
    }

    if (rsp_size < sizeof(AcdbCmdGetTagsFromGkvRsp))
    {
        ACDB_ERR("Error[%d]: The response structure size is less than %d",
            AR_EBADPARAM, sizeof(AcdbCmdGetTagsFromGkvRsp));
        return AR_EBADPARAM;
    }

    //GLB BUF 3 is used to store the sorted GKV
    graph_kv.num_keys = req->graph_key_vector->num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0],
        graph_kv.num_keys * sizeof(AcdbKeyValuePair),
        req->graph_key_vector->graph_key_vector,
        graph_kv.num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
    status = AcdbSort2(graph_kv.num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort the graph key vector.", status);
        return status;
    }

    subgraph_list.list = &glb_buf_3[0];

    status = AcdbGetUsecaseSubgraphList(req->graph_key_vector,
        &subgraph_list, NULL);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get subgraphs "
            "from graph key vector", status);
        return status;
    }

    status = BuildGetTagsFromGkvRsp(&subgraph_list, rsp);

    if (AR_FAILED(status)) return status;

    return status;
}

/**
* \brief
*		Interleaves two lists. If List 1 is [1 2 3 4] and List 2 is [5 6 7 8]
*       The resulting list is List[1 5 2 6 3 7 4 8]
*
* Note: An inplace shuffle can be used zip within the same array
*
* \param[in] num_elem_1: Number of elements in list 1
* \param[in] list_1: List to be interleaved with list 2
* \param[in] num_elem_2: Number of elements in list 2
* \param[in] list_2: List to be interleaved with list 1
* \param[in] num_elem_3: Number of elements in list 3
* \param[in/out] list_3: The interleaved list
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbZip1(uint32_t num_elem_1, uint32_t *list_1,
    uint32_t num_elem_2, uint32_t *list_2,
    uint32_t num_elem_3, uint32_t *list_3)
{
    if (num_elem_1 != num_elem_2)
        return AR_EBADPARAM;

    if(IsNull(list_1) || IsNull(list_2))
        return AR_EBADPARAM;

    if(num_elem_3 != num_elem_1 + num_elem_2)
        return AR_EBADPARAM;

    uint32_t index_1 = 0, index_2 = 0;
    for (uint32_t i = 0; i < num_elem_3 ; i++)
    {
        if (i % 2 == 0)
        {
            list_3[i] = list_1[index_1];
            index_1++;
        }
        else
        {
            list_3[i] = list_2[index_2];
            index_2++;
        }
    }

    return AR_EOK;
}

/**
* \brief
*		Checks for the existance of a CKV within the lookup table
*
* \param[in] kv_list: contains the key id and value lists that are
*            used to compare against an entry in the lookup table
* \param[in] lookup: a look up table that contains
*            <key tbl off/value tbl off> pairs
* \param[in/out] status: AR status
*
* \return FALSE(0) or TRUE(1)
*/
bool_t LookupContainsCKV(AcdbKeyValueList *kv_list,
    AcdbKeyVectorLut* lookup, int32_t *status)
{
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    uint32_t *key_list = NULL;
    uint32_t *value_list = NULL;
    uint32_t *tmp_buf = NULL;
    bool_t contains_ckv = FALSE;
    if (IsNull(kv_list) || IsNull(lookup) || IsNull(status))
        return AR_EBADPARAM;

    *status = AR_EOK;
    AcdbKeyVectorLutEntry entry = { 0 };
    for (uint32_t i = 0; i < lookup->num_entries; i++)
    {
        entry = lookup->lookup_table[i];
        offset = entry.offset_key_tbl;

        *status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
        if (AR_FAILED(*status))
        {
            ACDB_ERR("Error[%d]: Failed to read number of keys.", *status);
            return contains_ckv;
        }

        if (num_keys != kv_list->num_keys)
            continue;

        if (num_keys == 0)
            return TRUE;

        if (IsNull(tmp_buf))
        {
            tmp_buf = ACDB_MALLOC(uint32_t, 2 * num_keys);
            if (IsNull(tmp_buf))
            {
                *status = AR_ENOMEMORY;
                return contains_ckv;
            }
            key_list = &tmp_buf[0];
            value_list = &tmp_buf[num_keys];
        }

        *status = FileManReadBuffer(key_list,
            num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(*status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key ID List", *status);
            goto end;
        }

        if (0 != ACDB_MEM_CMP(kv_list->key_list, key_list,
            num_keys * sizeof(uint32_t)))
        {
            continue;
        }

        offset = entry.offset_value_list;
        *status = FileManReadBuffer(value_list,
            num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(*status))
        {
            ACDB_ERR("Error[%d]: Failed to read Value List", *status);
            goto end;
        }

        if (0 == ACDB_MEM_CMP(kv_list->value_list, value_list,
            num_keys * sizeof(uint32_t)))
        {
            contains_ckv = TRUE;
            break;
        }
    }

end:

    if (!IsNull(tmp_buf))
    {
        ACDB_FREE(tmp_buf);
        tmp_buf = NULL;
        key_list = NULL;
        value_list = NULL;
    }

    return contains_ckv;
}

/**
* \brief
*		Adds a <key tbl off/value tbl off> pair to the lookup table. The
*       value tbl off. points to an entry with in the Value LUT, i.e the
*       actual list of values.
*       Ex. value tbl off -> [v1, v2, v3, def, dot] (one entry in the
*       Value LUT)
*
* \param[in] entry: a <key tbl off/value tbl off> pair
*            used to compare against an entry in the lookup table
* \param[in] lookup: a look up table that contains
*            <key tbl off/value tbl off> pairs
*
* \return 0 on success, and non-zero on failure
*/
int32_t AddCkvEntryToLookup(AcdbKeyVectorLutEntry *entry,
    AcdbKeyVectorLut* lookup)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_calkeytbl = { 0 };
    ChunkInfo ci_callut = { 0 };

    ci_calkeytbl.chunk_id = ACDB_CHUNKID_CALKEYTBL;
    ci_callut.chunk_id = ACDB_CHUNKID_CALDATALUT;

    status = ACDB_GET_CHUNK_INFO(&ci_calkeytbl, &ci_callut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get chunk info for either "
            "Cal Key or Cal Lookup table.", AR_EBADPARAM);
        return status;
    }

    if (IsNull(entry) || IsNull(lookup))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " key vector entry or lookup.", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (lookup->size == 0)
    {
        ACDB_ERR("Error[%d]: The lookup table size is zero", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (lookup->num_entries * sizeof(entry) >= lookup->size)
    {
        ACDB_ERR("Error[%d]: The lookup table is full", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ACDB_MEM_CPY_SAFE(&lookup->lookup_table[lookup->num_entries],
        sizeof(*entry), entry, sizeof(*entry));
    lookup->num_entries++;

    return AR_EOK;
}

/**
* \brief
*		Retrieves all the audio cal key vector combinations for a set of keys given
*       the offset of the Key ID and Key Value tables
*
* \depends
*       Makes use of GLB_BUF_3 to store key vector data
*
* \param[in/out] lookup: Keeps track of key vectors already found
*            Key ID and Key Value tables
* \param[in] cal_key_table_entry: An entry that holds the offsets to the
*            Key ID and Key Value tables
* \param[in/out] blob_offset: current offset in the rsp
* \param[in] expected_size: the expected size of the rsp.list_size
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t GetAllAudioCKVVariations(AcdbKeyVectorLut *lookup,
    AcdbCalKeyTblEntry *cal_key_table_entry,
    uint32_t *blob_offset, uint32_t expected_size, AcdbKeyVectorList *rsp)
{
    int32_t status = AR_EOK;
    //bool_t found = FALSE;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    //uint32_t num_lut_entries = 0;
    ChunkInfo ci_calkeytbl = { 0 };
    ChunkInfo ci_callut = { 0 };
    AcdbOp op = ACDB_OP_NONE;
    KeyTableHeader key_value_table_header = { 0 };
    uint32_t *key_id_list = NULL;
    uint32_t *key_value_list = NULL;
    uint32_t *ckv = NULL;
    /* Contains offsets to key table and offset of a particualr value list
     * in the value lut. The offsets include the respective chunk offset */
    AcdbKeyVectorLutEntry ckv_entry = { 0 };
    AcdbKeyValueList kv_list = { 0 };

    if (IsNull(lookup) || IsNull(cal_key_table_entry)
        || IsNull(blob_offset) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    op = IsNull(rsp->key_vector_list) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    ci_calkeytbl.chunk_id = ACDB_CHUNKID_CALKEYTBL;
    ci_callut.chunk_id = ACDB_CHUNKID_CALDATALUT;

    status = ACDB_GET_CHUNK_INFO(&ci_calkeytbl, &ci_callut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get chunk info for either "
            "Cal Key or Cal Lookup table.", AR_EBADPARAM);
        return status;
    }

    offset = ci_calkeytbl.chunk_offset +
        cal_key_table_entry->offset_cal_key_tbl;
    ckv_entry.offset_key_tbl = offset;

    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of keys.", status);
        return status;
    }

    if (num_keys != 0)
    {
        status = FileManReadBuffer(&glb_buf_3[0],
            num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key ID List", status);
            return status;
        }
    }

    offset = ci_callut.chunk_offset +
        cal_key_table_entry->offset_cal_lut;
    status = FileManReadBuffer(&key_value_table_header,
        sizeof(KeyTableHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of values "
            "and lut entries.", status);
        return status;
    }

    if (num_keys != key_value_table_header.num_keys)
    {
        ACDB_ERR("Error[%d]: Number of keys and values are"
            " different!", AR_EFAILED);
        return AR_EFAILED;
    }
    //GLB_BUF_3 stores the key vector IDs followed by the Values
    //Ex. [K1 K2 K2 V1 V2 V3]
    key_id_list = &glb_buf_3[0];
    key_value_list = &glb_buf_3[num_keys];
    ckv = &glb_buf_3[num_keys * 2];

    kv_list.num_keys = num_keys;
    kv_list.key_list = key_id_list;
    kv_list.value_list = key_value_list;

    for (uint32_t i = 0; i < key_value_table_header.num_entries; i++)
    {
        ckv_entry.offset_value_list = offset;

        if (num_keys != 0)
        {
            status = FileManReadBuffer(key_value_list,
                num_keys * sizeof(uint32_t), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
                return status;
            }
        }

        offset += sizeof(AcdbCkvLutEntryOffsets);

        /* Check to see if we already accounted for the CKV. If so, skip
         * the CKV. Otherwise add the CKV to the lookup */
        if (LookupContainsCKV(&kv_list, lookup, &status)
            && AR_SUCCEEDED(status))
        {
            continue;
        }

        status = AddCkvEntryToLookup(&ckv_entry, lookup);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to add ckv entry to lookup.", status);
        }

        rsp->num_key_vectors ++;
        rsp->list_size += (sizeof(num_keys)
            + num_keys * sizeof(AcdbKeyValuePair));

        if (op == ACDB_OP_GET_SIZE) continue;

        //Write Key Vector
        status = AcdbZip1(num_keys, key_id_list,
            num_keys, key_value_list,
            num_keys * 2, ckv);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to zip key id and"
                " key value list.", status);
            return status;
        }

        //Write num keys
        if (*blob_offset
            + sizeof(uint32_t) > expected_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
            sizeof(uint32_t),
            &num_keys, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);

        if (num_keys == 0) continue;

        //Write Key Vector
        if (*blob_offset
            + num_keys * sizeof(AcdbKeyValuePair) > expected_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
            num_keys * sizeof(AcdbKeyValuePair),
            ckv, num_keys * sizeof(AcdbKeyValuePair));
        *blob_offset += num_keys * sizeof(AcdbKeyValuePair);

        //<CKV.Values, DEF, DOT, DOT2>
        //offset += sizeof(AcdbCkvLutEntryOffsets);
    }

    ACDB_CLEAR_BUFFER(glb_buf_3);
    return status;
}

/**
* \brief
*		Retrieves all the voice cal key vector combinations
*       for one voice subgraph
*
* \depends
*       Makes use of GLB_BUF_3 to store key vector data
*
* \param[in/out] lookup: Keeps track of key vectors already found
*            Key ID and Key Value tables
* \param[in] file_offset: absolute file offset of a
*            subgraphs vcpm cal data
* \param[in/out] blob_offset: current offset in the rsp
* \param[in] expected_size: the expected size of the rsp.list_size
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t GetAllVoiceCKVVariations(AcdbKeyVectorLut *lookup,
    uint32_t *file_offset, AcdbVcpmSubgraphCalTable *sg_cal_data_tbl_header,
    uint32_t *blob_offset, uint32_t expected_size, AcdbKeyVectorList *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t kv_tbl_offset = 0;
    uint32_t num_keys = 0;
    uint32_t *ckv = NULL;
    uint32_t *key_id_list = NULL;
    uint32_t *key_value_list = NULL;
    AcdbKeyVectorLutEntry ckv_entry = { 0 };
    AcdbKeyValueList kv_list = { 0 };
    ChunkInfo ci_vcpm_key_tbl = { 0 };
    ChunkInfo ci_vcpm_value_tbl = { 0 };
    AcdbVcpmCkvDataTable ckv_data_tbl_header = { 0 };
    AcdbVcpmCalDataObj cal_data_obj = { 0 };
    AcdbOp op = ACDB_OP_NONE;

    if (IsNull(lookup) || IsNull(file_offset)
        || IsNull(sg_cal_data_tbl_header)
        || IsNull(blob_offset) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    op = IsNull(rsp->key_vector_list) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    ci_vcpm_key_tbl.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;
    ci_vcpm_value_tbl.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_LUT;
    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_key_tbl, &ci_vcpm_value_tbl);
    if (AR_FAILED(status))
    {
        if (ci_vcpm_key_tbl.chunk_size == 0)
            ACDB_ERR("Error[%d]: Failed to get chunk info for the"
                " VCPM Calibration Key Table", status);
        if (ci_vcpm_value_tbl.chunk_size == 0)
            ACDB_ERR("Error[%d]: Failed to get chunk info for the"
                " VCPM Calibration Data Table", status);
    }

    offset = *file_offset;

    for (uint32_t i = 0; i < sg_cal_data_tbl_header->num_ckv_data_table; i++)
    {
        //Get Voice Key Table offset and combine key id list with value list
        status = FileManReadBuffer(&ckv_data_tbl_header,
            sizeof(AcdbVcpmCkvDataTable), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read VCPM CKV Data Table header.",
                status);
            return status;
        }

        for (uint32_t j = 0; j < ckv_data_tbl_header.num_caldata_obj; j++)
        {
            status = FileManReadBuffer(&cal_data_obj,
                sizeof(AcdbVcpmCalDataObj), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read VCPM Cal Data Obj" ,
                    status);
                return status;
            }

            offset += cal_data_obj.num_data_offsets * sizeof(uint32_t);

            ckv_entry.offset_key_tbl = ci_vcpm_key_tbl.chunk_offset
                + ckv_data_tbl_header.offset_voice_key_table;
            ckv_entry.offset_value_list = ci_vcpm_value_tbl.chunk_offset
                + cal_data_obj.offset_vcpm_ckv_lut
                + 2 * sizeof(uint32_t);

            kv_tbl_offset = ckv_entry.offset_key_tbl;

            //read number of keys from key table
            status = FileManReadBuffer(&num_keys,
                sizeof(uint32_t), &kv_tbl_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read VCPM Cal Data Obj"
                    , status);
                return status;
            }

            //GLB_BUF_3 stores the key vector IDs followed by the Values
            //Ex. [K1 K2 K2 V1 V2 V3]
            key_id_list = &glb_buf_3[0];
            key_value_list = &glb_buf_3[num_keys];
            ckv = &glb_buf_3[num_keys * 2];

            kv_list.num_keys = num_keys;
            kv_list.key_list = key_id_list;
            kv_list.value_list = key_value_list;

            if (num_keys != 0)
            {
                status = FileManReadBuffer(&glb_buf_3[0],
                    num_keys * sizeof(uint32_t), &kv_tbl_offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Failed to read Key ID List", status);
                    return status;
                }

                /* Skip #keys and #entries(#entries is always 1 for
                 * each voice value table */
                kv_tbl_offset = ckv_entry.offset_value_list;
                status = FileManReadBuffer(key_value_list,
                    num_keys * sizeof(uint32_t), &kv_tbl_offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
                    return status;
                }
            }

            /* Check to see if we already accounted for the CKV. If so, skip
            * the CKV. Otherwise add the CKV to the lookup */
            if (LookupContainsCKV(&kv_list, lookup, &status)
                && AR_SUCCEEDED(status))
            {
                continue;
            }

            status = AddCkvEntryToLookup(&ckv_entry, lookup);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to add ckv entry to lookup.", status);
            }

            rsp->num_key_vectors++;
            rsp->list_size += (sizeof(num_keys)
                + num_keys * sizeof(AcdbKeyValuePair));

            if (op == ACDB_OP_GET_SIZE) continue;

            //Write Key Vector
            status = AcdbZip1(num_keys, key_id_list,
                num_keys, key_value_list,
                num_keys * 2, ckv);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to zip key id and"
                    " key value list.", status);
                return status;
            }

            //Write num keys
            if (*blob_offset
                + sizeof(uint32_t) > expected_size)
            {
                return AR_ENEEDMORE;
            }

            ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
                sizeof(uint32_t), &num_keys, sizeof(uint32_t));
            *blob_offset += sizeof(uint32_t);

            if (num_keys == 0) continue;

            //Write Key Vector
            if (*blob_offset
                + num_keys * sizeof(AcdbKeyValuePair) > expected_size)
            {
                return AR_ENEEDMORE;
            }

            ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
                num_keys * sizeof(AcdbKeyValuePair),
                ckv, num_keys * sizeof(AcdbKeyValuePair));
            *blob_offset += num_keys * sizeof(AcdbKeyValuePair);

        }
    }

    return status;
}

/**
* \brief
*		Builds a list of cal key vectors using the subgraphs defined in a graph
*
* \param[in] sg_list_offset: Offset of the subgraph list
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t BuildCalKeyVectorList(
    AcdbKeyVectorList *rsp, uint32_t sg_list_offset)
{
    int32_t status = AR_EOK;
    bool_t ignore_voice_ckv = FALSE;
    uint32_t offset = 0;
    uint32_t sg_vcpm_data_offset = 0;
    uint32_t data_pool_offset = 0;
    uint32_t ckv_list_offset = 0;
    uint32_t blob_offset = 0;
    //The expected size of rps.key_vector_list set by client
    uint32_t expected_size = 0;
    ChunkInfo ci_data_pool = { 0 };
    ChunkInfo ci_vcpm_cal = { 0 };
    SgListHeader sg_list_header = { 0 };
    SgListObjHeader sg_obj = { 0 };
    AcdbSgCalLutHeader sg_entry_header = { 0 };
    AcdbCalKeyTblEntry e = { 0 };
    /* Keeps track of key vectors that have already been found */
    AcdbKeyVectorLut lookup = { 0 };
    AcdbVcpmSubgraphCalHeader sg_vcpm_caldata_header = { 0 };
    AcdbVcpmSubgraphCalTable sg_cal_tbl_header = { 0 };
    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The input parameter rsp is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (!IsNull(rsp->key_vector_list))
    {
        expected_size = rsp->list_size;
        rsp->list_size = 0;
        rsp->num_key_vectors = 0;
    }

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    ci_vcpm_cal.chunk_id = ACDB_CHUNKID_VCPM_CAL_DATA;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool, &ci_vcpm_cal);
    if (AR_FAILED(status))
    {
        if (0 == ci_vcpm_cal.chunk_size)
        {
            ignore_voice_ckv = TRUE;
            ACDB_DBG("Warning[%d]: No voice cal data found in file. "
                "Ignoring voice ckvs..", status);
            status = AR_EOK;
        }
        if (0 == ci_data_pool.chunk_size)
        {
            ACDB_ERR("Error[%d]: Unable to retrieve graph ckvs. "
                "Datapool chunk is empty.", status);
            return status;
        }
    }

    //The KV Lookup Table uses GLB BUF 1
    ACDB_CLEAR_BUFFER(glb_buf_1);
    lookup.size = sizeof(glb_buf_1);
    lookup.lookup_table = (AcdbKeyVectorLutEntry*)&glb_buf_1;

    data_pool_offset = ci_data_pool.chunk_offset + sg_list_offset;
    status = FileManReadBuffer(&sg_list_header,
        sizeof(SgListHeader), &data_pool_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read the subgraph"
            " list header", status);
        return status;
    }

    if (!ignore_voice_ckv)
    {
        offset = ci_vcpm_cal.chunk_offset;
        status = FileManReadBuffer(&sg_vcpm_caldata_header,
            sizeof(AcdbVcpmSubgraphCalHeader), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: VCPM Subgraph Caldata header.", status);
            return status;
        }
    }


    // Loop through each subgraph and combine all the key vectors into a list
    for (uint32_t i = 0; i < sg_list_header.num_subgraphs; i++)
    {

        status = FileManReadBuffer(&sg_obj, sizeof(SgListObjHeader),
            &data_pool_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read the subgraph"
                " object header", status);
            return status;
        }

        //Skip over subgraph destinations
        data_pool_offset += sg_obj.num_subgraphs * sizeof(uint32_t);

        //Get Voice CKVs for a voice subgraph
        if (!ignore_voice_ckv)
        {
            sg_vcpm_data_offset = offset;
            status = GetVcpmSubgraphCalTable(sg_vcpm_caldata_header.num_subgraphs,
                sg_obj.subgraph_id, &sg_vcpm_data_offset, &sg_cal_tbl_header);
            if (AR_SUCCEEDED(status))
            {
                status = GetAllVoiceCKVVariations(&lookup, &sg_vcpm_data_offset,
                    &sg_cal_tbl_header, &blob_offset, expected_size, rsp);
                if (AR_FAILED(status) && status != AR_ENOTEXIST)
                {
                    ACDB_ERR("Error[%d]: Failed to get Voice CKVs for "
                        "Subgraph(0x%x)", status);
                    return status;
                }

                continue;
            }
        }

        //Get Audio CKVs for a subgraph
        sg_entry_header.subgraph_id = sg_obj.subgraph_id;
        status = SearchSubgraphCalLut2(&sg_entry_header, &ckv_list_offset);
        if (AR_ENOTEXIST == status)
        {
            ACDB_DBG("Warning[%d]: Unable to find audio ckv table for "
                "for Subgraph(0x%x). Skipping..", status, sg_obj.subgraph_id);
            continue;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to find audio ckv table for "
                "for Subgraph(0x%x).", status, sg_obj.subgraph_id);
            return status;
        }

        //Search List of Offsets for matching CKV
        for (uint32_t j = 0; j < sg_entry_header.num_ckv_entries; j++)
        {
            status = FileManReadBuffer(&e, sizeof(AcdbCalKeyTblEntry),
                &ckv_list_offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: CKV key table and"
                    " value table offsets", status);
                return status;
            }

            status = GetAllAudioCKVVariations(
                &lookup, &e, &blob_offset, expected_size, rsp);
            if (AR_FAILED(status) && status != AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: CKV key table and"
                    " value table offsets", status);
                return status;
            }
        }
    }

    return status;
}

/**
* \brief
*       Search for the first occurance of a <Subgraph ID, Tag ID, Def Offset>
*       tuple using the Subgraph ID as a search key and returns the file
*       offset of the first occurrance.
*
* \param[in/out] sg_tag_entry: Tag Key Data Table entry in the
*           format of <Subgraph ID, Tag ID, Def Offset>
*
* \return AR_EOK on success, non-zero otherwise
*/
int32_t TagKeyTableFindFirstOfSubgraphID(SubgraphTagLutEntry *sg_tag_entry, uint32_t* file_offset)
{
    int32_t status = AR_EOK;
    //uint32_t offset = 0;
    ChunkInfo ci_tag_key_tbl = { 0 };

    //Binary Search based on Subgraph id
    uint32_t search_index_count = 1;
    uint32_t sz_gsl_cal_lut = 0;
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    if (IsNull(sg_tag_entry) || IsNull(file_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_tag_key_tbl.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_KEYTABLE;
    status = ACDB_GET_CHUNK_INFO(&ci_tag_key_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get Module Tag Key Table Chunk",
            status);
        return status;
    }

    sz_gsl_cal_lut = ci_tag_key_tbl.chunk_size - sizeof(uint32_t);

    //Setup Table Information
    table_info.table_offset = ci_tag_key_tbl.chunk_offset + sizeof(uint32_t);
    table_info.table_size = sz_gsl_cal_lut;
    table_info.table_entry_size = sizeof(SubgraphTagLutEntry);

    //Setup Search Information
    search_info.num_search_keys = search_index_count;
    search_info.num_structure_elements =
        (sizeof(SubgraphTagLutEntry) / sizeof(uint32_t));
    search_info.table_entry_struct = sg_tag_entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to find Subgraph ID(0x%x)", sg_tag_entry->sg_id);
        return status;
    }

    *file_offset = ci_tag_key_tbl.chunk_offset
        + sizeof(uint32_t) //Number of <SubgraphID, Tag> entries
        + search_info.entry_offset;

    ACDB_CLEAR_BUFFER(glb_buf_1);

    return status;
}

int32_t FindTagKeyList(uint32_t tag_id, uint32_t* dpo)
{
    int32_t status = AR_EOK;
    ChunkInfo ci_tag_key_list_lut = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };
    TagKeyListEntry tag_key_list_entry = { 0 };

    if (IsNull(dpo))
    {
        ACDB_ERR("Error[%d]: One or more input parameters is null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_tag_key_list_lut.chunk_id = ACDB_CHUNKID_MODULE_TAG_KEY_LIST_LUT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool, &ci_tag_key_list_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get Module Tag Key Table Chunk",
            status);
        return status;
    }

    tag_key_list_entry.tag_id = tag_id;

    //Setup Table Information
    table_info.table_offset =
        ci_tag_key_list_lut.chunk_offset + sizeof(uint32_t);
    table_info.table_size = ci_tag_key_list_lut.chunk_size
        - sizeof(uint32_t);
    table_info.table_entry_size = sizeof(TagKeyListEntry);

    //Setup Search Information
    search_info.num_search_keys = 1;//Binary Search based on Tag id
    search_info.num_structure_elements =
        (sizeof(TagKeyListEntry) / sizeof(uint32_t));
    search_info.table_entry_struct = &tag_key_list_entry;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to find Tag ID(0x%x)", tag_id);
        return status;
    }

    //Key Table format: [Table Size, Num Keys, KeyID+]
    *dpo = ci_data_pool.chunk_offset + tag_key_list_entry.key_list_offset
        + sizeof(uint32_t);//Skip size
    ACDB_CLEAR_BUFFER(glb_buf_1);

    return status;
}

/**
* \brief
*		Retrieves all the audio cal key vector combinations for a set of keys given
*       the offset of the Key ID and Key Value tables
*
* \depends
*       Makes use of GLB_BUF_3 to store key vector data
*
* \param[in/out] lookup: Keeps track of key vectors already found
*            Key ID and Key Value tables
* \param[in] cal_key_table_entry: An entry that holds the offsets to the
*            Key ID and Key Value tables
* \param[in/out] blob_offset: current offset in the rsp
* \param[in] expected_size: the expected size of the rsp.list_size
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t GetAllTKVVariations(SubgraphTagLutEntry *sg_tag_entry,
    uint32_t *blob_offset, uint32_t expected_size, AcdbTagKeyVectorList *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    ChunkInfo ci_tag_data_lut_tbl = { 0 };
    AcdbOp op = ACDB_OP_NONE;
    KeyTableHeader key_value_table_header = { 0 };
    uint32_t *key_id_list = NULL;
    uint32_t *key_value_list = NULL;
    uint32_t *tkv = NULL;

    op = IsNull(rsp->key_vector_list) ? ACDB_OP_GET_SIZE : ACDB_OP_GET_DATA;

    ci_tag_data_lut_tbl.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_LUT;

    status = ACDB_GET_CHUNK_INFO(&ci_tag_data_lut_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to get chunk info for: "
            "Tag Key List/Data tables or Datapool.", AR_EBADPARAM);
        return status;
    }

    status = FindTagKeyList(sg_tag_entry->tag_id, &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to find Tag(0x%x)",
            AR_EBADPARAM, sg_tag_entry->tag_id);
        return status;
    }

    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of keys.", status);
        return status;
    }

    if (num_keys != 0)
    {
        status = FileManReadBuffer(&glb_buf_3[0],
            num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key ID List", status);
            return status;
        }
    }

    offset = ci_tag_data_lut_tbl.chunk_offset +
        sg_tag_entry->offset;
    status = FileManReadBuffer(&key_value_table_header,
        sizeof(KeyTableHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of values "
            "and lut entries.", status);
        return status;
    }

    if (num_keys != key_value_table_header.num_keys)
    {
        ACDB_ERR("Error[%d]: Number of keys and values are"
            " different!", AR_EFAILED);
        return AR_EFAILED;
    }
    //GLB_BUF_3 stores the key vector IDs followed by the Values
    //Ex. [K1 K2 K2 V1 V2 V3]
    key_id_list = &glb_buf_3[0];
    key_value_list = &glb_buf_3[num_keys];
    tkv = &glb_buf_3[num_keys * 2];

    for (uint32_t i = 0; i < key_value_table_header.num_entries; i++)
    {
        if (num_keys != 0)
        {
            status = FileManReadBuffer(key_value_list,
                num_keys * sizeof(uint32_t), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
                return status;
            }
        }

        //Skip Def and Dot offsets
        offset += 2 * sizeof(uint32_t);

        rsp->num_key_vectors++;
        rsp->list_size += (sizeof(sg_tag_entry->tag_id) + sizeof(num_keys)
            + num_keys * sizeof(AcdbKeyValuePair));

        if (op == ACDB_OP_GET_SIZE) continue;

        //Write Key Vector
        status = AcdbZip1(num_keys, key_id_list,
            num_keys, key_value_list,
            num_keys * 2, tkv);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to zip key id and"
                " key value list.", status);
            return status;
        }

        //Write Tag ID
        if (*blob_offset
            + sizeof(uint32_t) > expected_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
            sizeof(uint32_t), &sg_tag_entry->tag_id, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);

        //Write num keys
        if (*blob_offset
            + sizeof(uint32_t) > expected_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
            sizeof(uint32_t), &num_keys, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);

        if (num_keys == 0) continue;

        //Write Key Vector
        if (*blob_offset
            + num_keys * sizeof(AcdbKeyValuePair) > expected_size)
        {
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->key_vector_list + *blob_offset,
            num_keys * sizeof(AcdbKeyValuePair),
            tkv, num_keys * sizeof(AcdbKeyValuePair));
        *blob_offset += num_keys * sizeof(AcdbKeyValuePair);
    }

    ACDB_CLEAR_BUFFER(glb_buf_3);
    return status;
}

/**
* \brief
*		Builds a list of tag key vectors using the subgraphs defined in a graph
*
* \depends
*       Makes use of GLB_BUF_2 to keep track of tags that were found
*
* \param[in] sg_list_offset: Offset of the subgraph list
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t BuildTagKeyVectorList(
    AcdbTagKeyVectorList *rsp, uint32_t sg_list_offset)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t data_pool_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t end_offset = 0;
    //The expected size of rps.key_vector_list set by client
    uint32_t expected_size = 0;
    ChunkInfo ci_data_pool = { 0 };
    ChunkInfo ci_tag_data_lut = { 0 };
    ChunkInfo ci_tag_key_tbl = { 0 };
    SgListHeader sg_list_header = { 0 };
    SgListObjHeader sg_obj = { 0 };
    SubgraphTagLutEntry sg_tag_entry = { 0 };
    AcdbUintList found_tags = { 0 };
    bool_t skip_tag = FALSE;

    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The input parameter rsp is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (!IsNull(rsp->key_vector_list))
    {
        expected_size = rsp->list_size;
        rsp->list_size = 0;
        rsp->num_key_vectors = 0;
    }

    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;
    ci_tag_data_lut.chunk_id = ACDB_CHUNKID_MODULE_TAG_KEY_LIST_LUT;
    ci_tag_key_tbl.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_KEYTABLE;
    status = ACDB_GET_CHUNK_INFO(&ci_data_pool,
        &ci_tag_data_lut, &ci_tag_key_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve chunk info for: "
            "data pool or tag data.", status);
        return status;
    }

    data_pool_offset = ci_data_pool.chunk_offset + sg_list_offset;
    status = FileManReadBuffer(&sg_list_header,
        sizeof(SgListHeader), &data_pool_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read the subgraph"
            " list header", status);
        return status;
    }

    //Setup list of found tags using GLB_BUFFER_2
    found_tags.list = &glb_buf_2[0];

    // Loop through each subgraph and combine all the key vectors into a list
    for (uint32_t i = 0; i < sg_list_header.num_subgraphs; i++)
    {
        status = FileManReadBuffer(&sg_obj, sizeof(SgListObjHeader),
            &data_pool_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read the subgraph"
                " object header", status);
            return status;
        }

        sg_tag_entry.sg_id = sg_obj.subgraph_id;

        //Skip over subgraph destinations
        data_pool_offset += sg_obj.num_subgraphs * sizeof(uint32_t);

        status = TagKeyTableFindFirstOfSubgraphID(&sg_tag_entry, &offset);
        if (AR_FAILED(status) && status == AR_ENOTEXIST)
        {
            ACDB_DBG("Error[%d]: No module tags found in Subgraph(0x%x)."
                " Skipping..", status, sg_tag_entry.sg_id);
            status = AR_EOK;
            continue;
        }
        else if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Subgraph(0x%x) Tag entry"
                " in Module Tag Key Table.", status, sg_tag_entry.sg_id);
            return status;
        }

        end_offset = ci_tag_key_tbl.chunk_offset + ci_tag_key_tbl.chunk_size;
        while (offset < end_offset)
        {
            status = FileManReadBuffer(&sg_tag_entry,
                sizeof(SubgraphTagLutEntry), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read Subgraph Tag entry"
                    " in Module Tag Key Table.", status);
                return status;
            }

            if (sg_tag_entry.sg_id != sg_obj.subgraph_id)
                break;

            /* Skip a tag if we already found the same tag in a
            * subgraph. Tags are required to have the same tag key vector,
            * so we avoid adding duplicate tag key vectors by skipping the
            * tags already found.*/
            for (size_t j = 0; j < found_tags.count; j++)
            {
                if (found_tags.list[j] == sg_tag_entry.tag_id)
                {
                    skip_tag = TRUE;
                    break;
                }
                skip_tag = FALSE;
            }

            if (skip_tag) continue;

            status = GetAllTKVVariations(&sg_tag_entry,
                &blob_offset, expected_size, rsp);
            if (AR_FAILED(status) && status != AR_ENOTEXIST)
            {
                ACDB_ERR("Error[%d]: Failed to get TKVs for "
                    "Subgraph(0x%x) & Tag(0x%x)", status);
                return status;
            }

            if (AR_SUCCEEDED(status))
                found_tags.list[found_tags.count++] = sg_tag_entry.tag_id;
        }
    }

    return status;
}

/**
* \brief
*		Retrieves a list of Tag or Calibration Key Vectors given a GKV
*
* \param[in] kv_type: the type of key vector to get data for
* \param[in] AcdbGraphKeyVector: the graph key vector to get keys vectors from
* \param[out] rsp: the Key Vector List to be populated
* \param[out] rsp_size: the size of the kv_list_rsp structure
*
* \return 0 on success, and non-zero on failure
*/
int32_t GetUsecaseKeyVectorList(KeyVectorType kv_type, AcdbGraphKeyVector *gkv,
    void *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    void *kv_list = NULL;
    AcdbGraphKeyVector graph_kv = { 0 };
    acdb_graph_info_t graph_info = { 0 };

    if (IsNull(gkv) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null:"
            " GKV or Response", status);
        return AR_EBADPARAM;
    }

    if (gkv->num_keys > ACDB_MAX_KEY_COUNT)
        return AR_EBADPARAM;

    switch (kv_type)
    {
    case CAL_KEY_VECTOR:
        if (rsp_size < sizeof(AcdbKeyVectorList))
        {
            ACDB_ERR("Error[%d]: The size of the response structure is less "
                "than %d bytes", status, sizeof(AcdbKeyVectorList));
            return AR_EBADPARAM;
        }

        kv_list = ((AcdbKeyVectorList*)rsp)->key_vector_list;
        break;
    case TAG_KEY_VECTOR:
        if (rsp_size < sizeof(AcdbTagKeyVectorList))
        {
            ACDB_ERR("Error[%d]: The size of the response structure is less "
                "than %d bytes", status, sizeof(AcdbTagKeyVectorList));
            return AR_EBADPARAM;
        }

        kv_list = ((AcdbTagKeyVectorList*)rsp)->key_vector_list;
        break;
    default:
        break;
    }

    if (IsNull(kv_list))
    {
        /* Print only during the size querry,i.e the first time this
         * api is called */
        ACDB_DBG("Retrieving subgraph list for the following"
            " graph key vector:");
        LogKeyVector(gkv, GRAPH_KEY_VECTOR);
    }

    graph_kv.num_keys = gkv->num_keys;
    graph_kv.graph_key_vector = (AcdbKeyValuePair*)&glb_buf_3[0];
    ACDB_MEM_CPY_SAFE(&glb_buf_3[0], gkv->num_keys * sizeof(AcdbKeyValuePair),
        gkv->graph_key_vector, gkv->num_keys * sizeof(AcdbKeyValuePair));

    //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
    status = AcdbSort2(gkv->num_keys * sizeof(AcdbKeyValuePair),
        graph_kv.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to sort graph key vector.", status);
        return status;
    }

    status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
        &graph_kv, sizeof(AcdbGraphKeyVector),
        &graph_info, sizeof(acdb_graph_info_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to find the graph key vector", status);
        return status;
    }

    switch (kv_type)
    {
    case CAL_KEY_VECTOR:
        status = BuildCalKeyVectorList(
            (AcdbKeyVectorList*)rsp, graph_info.sg_list_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to build calibration key vector list",
                status);
            return status;
        }
        break;
    case TAG_KEY_VECTOR:
        status = BuildTagKeyVectorList(
            (AcdbTagKeyVectorList*)rsp, graph_info.sg_list_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to build tag key vector list",
                status);
            return status;
        }
        break;
    default:
        break;
    }

    return status;
}

int32_t AcdbCmdGetGraphCalKeyVectors(AcdbGraphKeyVector *gkv,
    AcdbKeyVectorList *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;

    status = GetUsecaseKeyVectorList(CAL_KEY_VECTOR, gkv, rsp, rsp_size);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured "
            "while retrieving CKV list", status);
        return status;
    }

    return status;
}

int32_t AcdbCmdGetGraphTagKeyVectors(AcdbGraphKeyVector *gkv,
    AcdbTagKeyVectorList *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;

    status = GetUsecaseKeyVectorList(TAG_KEY_VECTOR, gkv, rsp, rsp_size);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured.", status);
        return status;
    }

    return status;
}

/**
* \brief
*		Retrieves all the graph key vector combinations for a set of keys given
*       the offset of the Graph Key Value table
*
* \depends
*       GLB_BUF_3 is used to store gkv data
*
* \param[in] graph_keys: A list of graph Key IDs
* \param[in] gkv_lut_offset: An entry that holds the offset to the
*            Graph Key Value look up table
* \param[in/out] blob_offset: offset within the rsp.key_vector_list
* \param[in] expected_size: The expected size of rsp.key_vector_list
* \param[out] rsp: The Key Vector List to be populated
* \return 0 on success, and non-zero on failure
*/
int32_t GetAllGraphKvVariations(
    AcdbUintList *graph_keys, uint32_t gkv_lut_offset,
    uint32_t *blob_offset, uint32_t expected_size, AcdbKeyVectorList *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t value_list_size = 0;
    KeyTableHeader key_table_header = { 0 };
    ChunkInfo ci_key_value_table = { 0 };
    //AcdbOp op = ACDB_OP_NONE;
    uint32_t *key_value_list = NULL;
    uint32_t *gkv = NULL;

    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The input response parameter is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_key_value_table.chunk_id = ACDB_CHUNKID_GKVLUTTBL;
    status = ACDB_GET_CHUNK_INFO(&ci_key_value_table);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Graph Key LUT Chunk.",
            status);
        return status;
    }

    offset = ci_key_value_table.chunk_offset + gkv_lut_offset;
    status = FileManReadBuffer(&key_table_header,
        sizeof(KeyTableHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read key table header.",
            status);
        return status;
    }

    if (graph_keys->count != key_table_header.num_keys)
    {
        ACDB_ERR("Error[%d]: There is a mismatch between the length "
            "of the input key id list and the number of keys in the GKV LUT.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    //Only includes size of value list
    value_list_size = key_table_header.num_keys
        * sizeof(uint32_t);
    /* Recalculate list_size when getting data
    num entries x (#keys + sizeof(KeyValuePairList)) */
    rsp->list_size += key_table_header.num_entries
        * ((uint32_t)sizeof(uint32_t) + 2UL * value_list_size);
    rsp->num_key_vectors += key_table_header.num_entries;

    if (IsNull(rsp->key_vector_list)) return status;

    key_value_list = &glb_buf_3[0];
    gkv = &glb_buf_3[key_table_header.num_keys];

    for (uint32_t i = 0; i < key_table_header.num_entries; i++)
    {
        //read value list
        status = FileManReadBuffer(key_value_list,
            key_table_header.num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
            return status;
        }

        //Skip SG List and Data offsets
        offset += 2 * sizeof(uint32_t);

        status = AcdbZip1(key_table_header.num_keys, graph_keys->list,
            key_table_header.num_keys, key_value_list,
            key_table_header.num_keys * 2, gkv);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to zip key id and"
                " key value list.", status);
            return status;
        }

        //Write key vector to buffer

        // Write num keys
        if (*blob_offset + sizeof(uint32_t) > expected_size)
        {
            ACDB_ERR("Error[%d]: Unable to write number of keys. "
                "The actual key vector list size is greater than"
                " the expected size %d bytes.",
                AR_ENEEDMORE, expected_size);
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE(rsp->key_vector_list + *blob_offset, sizeof(uint32_t),
            &graph_keys->count, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);

        // Write key vector
        if (*blob_offset + 2 * value_list_size > expected_size)
        {
            ACDB_ERR("Error[%d]: Unable to write key vector. "
                "The actual key vector list size is greater than"
                " the expected size %d bytes.",
                AR_ENEEDMORE, expected_size);
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE(
            rsp->key_vector_list + *blob_offset, 2UL * (size_t)value_list_size,
            gkv                                , 2UL * (size_t)value_list_size);

        *blob_offset += 2 * value_list_size;
    }

    return status;
}

int32_t AcdbCmdGetSupportedGraphKeyVectors(AcdbUintList *key_id_list,
    AcdbKeyVectorList *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_key_tables = 0;
    uint32_t key_table_size = 0;
    uint32_t key_table_entry_size = 0;
    uint32_t num_gkvs_found = 0;
    uint32_t num_keys_found = 0;
    uint32_t entry_index = 0;
    uint32_t blob_offset = 0;
    uint32_t expected_size = 0;//Expected size of rsp.key_vector_list
    ChunkInfo ci_key_id_table = { 0 };
    KeyTableHeader key_table_header = { 0 };
    AcdbUintList graph_keys = { 0 };

    if (IsNull(key_id_list) || IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The gkv input parameter is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (rsp_size < sizeof(AcdbKeyVectorList))
    {
        ACDB_ERR("Error[%d]: The response structure size is less than %d",
            AR_EBADPARAM, sizeof(AcdbKeyVectorList));
        return AR_EBADPARAM;
    }

    if (rsp->list_size == 0 && !IsNull(rsp->key_vector_list))
    {
        ACDB_ERR("Error[%d]: The key vector list size is zero, "
            "but the key vector list is not null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (!IsNull(rsp->key_vector_list))
    {
        //Recalculate list size and #kvs when gettig data
        expected_size = rsp->list_size;
        rsp->list_size = 0;
        rsp->num_key_vectors = 0;
    }

    /* GLB_BUF_2 stores a graph key table entry [key1,key2,... lutOffset]
     * graph_keys will point to the key id list
     */
    graph_keys.list = &glb_buf_2[0];

    ci_key_id_table.chunk_id = ACDB_CHUNKID_GKVKEYTBL;
    status = ACDB_GET_CHUNK_INFO(&ci_key_id_table);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to retrieve Graph Key ID Chunk.",
            status);
        return status;
    }

    offset = ci_key_id_table.chunk_offset;
    status = FileManReadBuffer(&num_key_tables, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read number of GKV Key ID tables.",
            status);
        return status;
    }

    for (uint32_t i = 0; i < num_key_tables; i++)
    {
        status = FileManReadBuffer(&key_table_header,
            sizeof(KeyTableHeader), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Unable to read key table header.",
                status);
            return status;
        }

        key_table_entry_size = key_table_header.num_keys
            * sizeof(uint32_t)
            + sizeof(uint32_t);
        key_table_size = key_table_header.num_entries
            * key_table_entry_size;
        graph_keys.count = key_table_header.num_keys;

        /* If there are less keys than the provided keys, the GKV
         * does not support the capability(ies) that are needed */
        if (key_table_header.num_keys < key_id_list->count)
        {
            offset += key_table_size;
            continue;
        }
        else
        {
            //Read key vector and see if it contains the provided keys

            for (uint32_t k = 0; k < key_table_header.num_entries; k++)
            {
                num_keys_found = 0;

                //Read Graph Keys
                status = FileManReadBuffer(&glb_buf_2, key_table_entry_size, &offset);
                if (AR_FAILED(status))
                {
                    ACDB_ERR("Error[%d]: Unable to read number of GKV Key ID tables.",
                        status);
                    return status;
                }


                for (uint32_t j = 0; j < key_id_list->count; j++)
                {
                    if (AR_SUCCEEDED(AcdbDataBinarySearch2(
                        graph_keys.list,
                        key_table_header.num_keys * sizeof(uint32_t),
                        &key_id_list->list[j], 1, 1, &entry_index)))
                    {
                        num_keys_found++;
                    }
                }

                if (num_keys_found == key_id_list->count)
                {
                    //Go to LUT and collect all the Key Combinations
                    status = GetAllGraphKvVariations(
                        &graph_keys, glb_buf_2[graph_keys.count],
                        &blob_offset, expected_size, rsp);
                    if (AR_FAILED(status))
                    {
                        ACDB_ERR("Error[%d]: Failed to get all GKV "
                            "variations for:",
                            status);

                        LogKeyIDs(&graph_keys, GRAPH_KEY_VECTOR);
                        return status;
                    }

                    num_gkvs_found++;
                }
            }
        }
    }

    if (!num_gkvs_found)
    {
        ACDB_ERR("Error[%d]: Failed to find data. No graph key vector supports"
            " all the provided keys:",AR_ENOTEXIST);

        for (uint32_t i = 0; i < key_id_list->count; i++)
        {
            ACDB_ERR("Graph Key: 0x%x", key_id_list->list[i]);
        }
        return AR_ENOTEXIST;
    }

    return status;
}

/**
* \brief
*		Retrieves all the driver key vector combinations for a set of
*       keys given the offset of the Key and Value tables
*
* \depends
*       GLB_BUF_3 is used to store kv data
*
* \param[in] cal_key_table_entry: An entry that holds the offsets to the
*            Key ID and Key Value tables
* \param[in/out] blob_offset: current offset in the rsp
* \param[in] expected_size: the expected size of the rsp.list_size
* \param[out] rsp: The Key Vector List to be populated
*
* \return 0 on success, and non-zero on failure
*/
int32_t GetAllDriverKvVariations(
    acdb_driver_cal_lut_entry_t *cal_lut_entry, uint32_t *blob_offset,
    uint32_t expected_size, AcdbKeyVectorList *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t value_list_size = 0;
    uint32_t num_keys = 0;
    KeyTableHeader key_table_header = { 0 };
    //AcdbOp op = ACDB_OP_NONE;
    uint32_t *key_list = NULL;
    uint32_t *value_list = NULL;
    uint32_t *driver_kv = NULL;
    ChunkInfo gsl_cal_key_tbl = { 0 };
    ChunkInfo gsl_cal_lut_tbl = { 0 };

    gsl_cal_key_tbl.chunk_id = ACDB_CHUNKID_GSL_CALKEY_TBL;
    gsl_cal_lut_tbl.chunk_id = ACDB_CHUNKID_GSL_CALDATA_TBL;
    status = ACDB_GET_CHUNK_INFO(&gsl_cal_key_tbl, &gsl_cal_lut_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get GSL Key Table or"
            " GSL Value Table Chunk", status);
        return status;
    }

    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The input response parameter is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    offset = gsl_cal_key_tbl.chunk_offset
        + cal_lut_entry->offset_calkey_table;

    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of keys.", status);
        return status;
    }

    if (num_keys != 0)
    {
        status = FileManReadBuffer(&glb_buf_3[0],
            num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key ID List", status);
            return status;
        }
    }

    offset = gsl_cal_lut_tbl.chunk_offset
        + cal_lut_entry->offset_caldata_table;
    status = FileManReadBuffer(&key_table_header,
        sizeof(KeyTableHeader), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to read key table header.",
            status);
        return status;
    }

    if (num_keys != key_table_header.num_keys)
    {
        ACDB_ERR("Error[%d]: There is a mismatch between the length "
            "of the key id list and the number of keys in the "
            "Driver Key LUT.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    //Only includes size of value list
    value_list_size = key_table_header.num_keys
        * sizeof(uint32_t);
    /* Recalculate list_size when getting data
    num entries x (#keys + sizeof(KeyValuePairList)) */
    rsp->list_size += key_table_header.num_entries
        * ((uint32_t)sizeof(uint32_t) + 2UL * value_list_size);
    rsp->num_key_vectors += key_table_header.num_entries;

    if (IsNull(rsp->key_vector_list)) return status;

    key_list = &glb_buf_3[0];
    value_list = &glb_buf_3[key_table_header.num_keys];
    driver_kv = &glb_buf_3[2 * key_table_header.num_keys];

    for (uint32_t i = 0; i < key_table_header.num_entries; i++)
    {
        //Read value list
        status = FileManReadBuffer(value_list,
            key_table_header.num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
            return status;
        }

        //Skip SG List and Data offsets
        offset += 2 * sizeof(uint32_t);

        status = AcdbZip1(key_table_header.num_keys, key_list,
            key_table_header.num_keys, value_list,
            key_table_header.num_keys * 2, driver_kv);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to zip key id and"
                " key value list.", status);
            return status;
        }

        //Write key vector to buffer

        // Write num keys
        if (*blob_offset + sizeof(uint32_t) > expected_size)
        {
            ACDB_ERR("Error[%d]: Unable to write number of keys. "
                "The actual key vector list size is greater than"
                " the expected size %d bytes.",
                AR_ENEEDMORE, expected_size);
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE(rsp->key_vector_list + *blob_offset, sizeof(uint32_t),
            &num_keys, sizeof(uint32_t));
        *blob_offset += sizeof(uint32_t);

        // Write key vector
        if (*blob_offset + 2 * value_list_size > expected_size)
        {
            ACDB_ERR("Error[%d]: Unable to write key vector. "
                "The actual key vector list size is greater than"
                " the expected size %d bytes.",
                AR_ENEEDMORE, expected_size);
            return AR_ENEEDMORE;
        }

        ACDB_MEM_CPY_SAFE(
            rsp->key_vector_list + *blob_offset, 2UL * (size_t)value_list_size,
            driver_kv                          , 2UL * (size_t)value_list_size);
        *blob_offset += 2 * value_list_size;
    }

    return status;
}

int32_t AcdbCmdGetDriverModuleKeyVectors(
    uint32_t module_id, AcdbKeyVectorList *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t blob_offset = 0;
    uint32_t expected_size = 0;
    uint32_t end_gsl_cal_lut_offset = 0;
    acdb_driver_cal_lut_entry_t cal_lut_entry = { 0 };
    ChunkInfo gsl_cal_lut = { 0 };

    if (IsNull(rsp))
    {
        ACDB_ERR("Error[%d]: The input response parameter is null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (rsp_size < sizeof(AcdbKeyVectorList))
    {
        ACDB_ERR("Error[%d]: The response structure size is less than %d",
            AR_EBADPARAM, sizeof(AcdbKeyVectorList));
        return AR_EBADPARAM;
    }

    if (rsp->list_size == 0 && !IsNull(rsp->key_vector_list))
    {
        ACDB_ERR("Error[%d]: The key vector list size is zero, "
            "but the key vector list is not null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    /* Algorithm
    * 1. Find the first occurance of the Module ID in the GSL Cal LUT
    * 2. Use the offset of that entry to find remaining
    *   <Module ID, Key Table, Value table> entries
    * 3. zip key id list and value list and write to reponse buffer
    */
    cal_lut_entry.mid = module_id;

    status = acdb_ctx_man_ioctl(
        ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_DRIVER_MODULE,
        &cal_lut_entry, sizeof(cal_lut_entry),
        &offset, sizeof(uint32_t));
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: No key vectors found for driver module(0x%x)"
            , status, module_id);
        return status;
    }

    gsl_cal_lut.chunk_id = ACDB_CHUNKID_GSL_CAL_LUT;
    status = ACDB_GET_CHUNK_INFO(&gsl_cal_lut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get GSL Cal LUT Chunk", status);
        return status;
    }

    if (!IsNull(rsp->key_vector_list))
    {
        //Recalculate list size and #kvs when gettig data
        expected_size = rsp->list_size;
        rsp->list_size = 0;
        rsp->num_key_vectors = 0;
    }

    end_gsl_cal_lut_offset = gsl_cal_lut.chunk_offset
        + gsl_cal_lut.chunk_size;

    while(offset < end_gsl_cal_lut_offset)
    {
        status = FileManReadBuffer(&cal_lut_entry, sizeof(acdb_driver_cal_lut_entry_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read GSL Cal LUT entry"
                " of entries.", status);
            return status;
        }

        if (cal_lut_entry.mid != module_id) break;

        status = GetAllDriverKvVariations(
            &cal_lut_entry, &blob_offset, expected_size, rsp);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to get all key vector variations."
                , status);
            return status;
        }
    }

    return status;
}

int32_t SearchSubgraphCalLut(
    uint32_t req_subgraph_id, uint32_t sz_ckv_entry_list,
    AcdbCalKeyTblEntry *ckv_entry_list, uint32_t *num_entries)
{
    int32_t status = AR_EOK;
    bool_t sg_found = FALSE;
    uint32_t num_subgraphs = 0;
    uint32_t num_ckv_tbl_entries = 0;
    uint32_t subgraph_id = 0;
    uint32_t offset = 0;
    ChunkInfo ci_calsglut = { 0 };

    if (IsNull(ckv_entry_list))
    {
        ACDB_ERR("Error[%d]: The provided input parameter(s) are null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    //Search for Persist/Non-persist/Global-persist caldata in ACDB files

    ci_calsglut.chunk_id = ACDB_CHUNKID_CALSGLUT;
    status = ACDB_GET_CHUNK_INFO(&ci_calsglut);
    if (AR_FAILED(status)) return status;

    offset = ci_calsglut.chunk_offset;
    status = FileManReadBuffer(&num_subgraphs, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of subgraphs.", status);
        return status;
    }

    for (uint32_t i = 0; i < num_subgraphs; i++)
    {
        status = FileManReadBuffer(&glb_buf_3[0], 2 * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read subgraph and number of entries.", status);
            return status;
        }

        subgraph_id = glb_buf_3[0];
        num_ckv_tbl_entries = glb_buf_3[1];

        if (subgraph_id == req_subgraph_id)
        {
            sg_found = TRUE;
            //Read number of <Cal Key ID List Offset, Cal Key Value List Offset> Entries
            *num_entries = num_ckv_tbl_entries;

            if (num_ckv_tbl_entries == 0)
            {
                ACDB_CLEAR_BUFFER(glb_buf_3);
                ACDB_ERR("Error[%d]: Subgraph(%x) does not have CKV table entries.",
                    AR_ENOTEXIST, subgraph_id);
                return AR_ENOTEXIST;
            }

            if (sz_ckv_entry_list < num_ckv_tbl_entries * sizeof(uint32_t))
            {
                return AR_ENEEDMORE;
            }

            status = FileManReadBuffer(ckv_entry_list,
                num_ckv_tbl_entries * sizeof(AcdbCalKeyTblEntry), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read CKV table entries for Subgraph(%x)",
                    status, subgraph_id);
                return status;
            }

            break;
        }
        else
        {
            //List<CalKeyTable Off., LUT Off.>
            offset += 2 * sizeof(uint32_t) * num_ckv_tbl_entries;
        }
    }

    if (!sg_found)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Could not find calibration data for Subgraph(%x)",
            status, req_subgraph_id);
    }

    ACDB_CLEAR_BUFFER(glb_buf_3);

    return status;
}

int32_t SearchSubgraphCalLut2(AcdbSgCalLutHeader *sg_lut_entry_header,
    uint32_t *ckv_entry_list_offset)
{
    int32_t status = AR_EOK;
    bool_t sg_found = FALSE;
    uint32_t num_subgraphs = 0;
    uint32_t offset = 0;
    ChunkInfo ci_calsglut = { 0 };
    AcdbSgCalLutHeader entry_header = { 0 };

    if (IsNull(sg_lut_entry_header) || IsNull(ckv_entry_list_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameter(s) are null.",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_calsglut.chunk_id = ACDB_CHUNKID_CALSGLUT;
    status = ACDB_GET_CHUNK_INFO(&ci_calsglut);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get Subgraph Calibration"
            " Lookup table chunk info.");
        return status;
    }

    offset = ci_calsglut.chunk_offset;
    status = FileManReadBuffer(&num_subgraphs, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of subgraphs.", status);
        return status;
    }

    for (uint32_t i = 0; i < num_subgraphs; i++)
    {
        status = FileManReadBuffer(&entry_header,
            sizeof(AcdbSgCalLutHeader), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read subgraph lookup"
                " table entry header.", status);
            return status;
        }

        if (entry_header.subgraph_id == sg_lut_entry_header->subgraph_id)
        {
            sg_found = TRUE;

            if (entry_header.num_ckv_entries == 0)
            {
                ACDB_CLEAR_BUFFER(glb_buf_3);
                ACDB_DBG("Warning[%d]: Subgraph(0x%x) does not"
                    " does not have CKVs",
                    AR_ENOTEXIST, entry_header.subgraph_id);
                return AR_ENOTEXIST;
            }
            sg_lut_entry_header->num_ckv_entries =
                entry_header.num_ckv_entries;
            *ckv_entry_list_offset = offset;
            break;
        }
        else
        {
            //List<CalKeyTable Off., LUT Off.>
            offset += 2 * sizeof(uint32_t)
                * entry_header.num_ckv_entries;
        }
    }

    if (!sg_found)
    {
        status = AR_ENOTEXIST;
        ACDB_ERR("Error[%d]: Unable to find calibration data for Subgraph(0x%x)",
            status, sg_lut_entry_header->subgraph_id);
    }

    return status;
}

/**
* \brief
*		Matches the requeset CKV with the Key ID and Key Value Tables. Returns
*       the offsets to the DEF, DOT(used for non-persistent/persistent and
*       DOT2(used for global-persistent) tables
* \param[in] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in] offset_key_table: Offset of Key ID table
* \param[in] offset_cal_lut: Offset of Key Value LUT
* \param[out] ckv_lut_entry: Offsets to DEF, DOT, and DOT2 for the input request
* \return 0 on success, and non-zero on failure
*/
int32_t SearchForMatchingCalKeyVector(AcdbParameterCalData *req,
    uint32_t offset_key_table, uint32_t offset_cal_lut,
    AcdbCkvLutEntryOffsets* ckv_lut_entry)
{
    int32_t status = AR_EOK;
    bool_t found = FALSE;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    uint32_t num_values = 0;
    uint32_t num_lut_entries = 0;
    ChunkInfo ci_calkeytbl = { 0 };
    ChunkInfo ci_callut = { 0 };

    if (IsNull(req) || IsNull(ckv_lut_entry))
    {
        ACDB_ERR("The input request, DEF offset, or DOT offset are null");
        return AR_EBADPARAM;
    }

    ci_calkeytbl.chunk_id = ACDB_CHUNKID_CALKEYTBL;
    ci_callut.chunk_id = ACDB_CHUNKID_CALDATALUT;

    status = ACDB_GET_CHUNK_INFO(&ci_calkeytbl, &ci_callut);
    if (AR_FAILED(status)) return status;

    //Get Key List
    offset = ci_calkeytbl.chunk_offset + offset_key_table;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of keys.", status);
        return status;
    }

    if (req->cal_key_vector.num_keys != num_keys)
    {
        return AR_ENOTEXIST;
    }

    if (num_keys != 0)
    {
        status = FileManReadBuffer(&glb_buf_3[0], num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key ID List", status);
            return status;
        }

        //Sort Key Vector by Key IDs(position 0 of AcdbKeyValuePair)
        status = AcdbSort2(num_keys * sizeof(AcdbKeyValuePair),
            req->cal_key_vector.graph_key_vector, sizeof(AcdbKeyValuePair), 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to sort input request key vector.", status);
            return status;
        }

        if (!CompareKeyVectorIds(req->cal_key_vector, glb_buf_2, glb_buf_3, num_keys))
        {
            return AR_ENOTEXIST;
        }
    }

    offset = ci_callut.chunk_offset + offset_cal_lut;
    status = FileManReadBuffer(&glb_buf_3[0], 2 * sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of values and lut entries.", status);
        return status;
    }

    num_values = glb_buf_3[0];
    num_lut_entries = glb_buf_3[1];

    if (num_keys != num_values)
    {
        ACDB_ERR("Error[%d]: Number of keys and values are different!", AR_EFAILED);
        return AR_EFAILED;
    }

    //Compare CKV Values and get
    for (uint32_t i = 0; i < num_lut_entries; i++)
    {
        if (num_values == 0)
        {
            found = TRUE;
            status = FileManReadBuffer(ckv_lut_entry, sizeof(AcdbCkvLutEntryOffsets), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read ckv lut entry.", status);
                return status;
            }

            break;
        }

        status = FileManReadBuffer(&glb_buf_3[0], num_values * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read Key Value List.", status);
            return status;
        }

        if (CompareKeyVectorValues(req->cal_key_vector, glb_buf_2, glb_buf_3, num_keys))
        {
            found = TRUE;
            status = FileManReadBuffer(ckv_lut_entry, sizeof(AcdbCkvLutEntryOffsets), &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read ckv lut entry offsets.", status);
                return status;
            }

            break;
        }
        else
        {
            //<CKV.Values, DEF, DOT, DOT2>
            offset += sizeof(AcdbCkvLutEntryOffsets);
        }
    }

    if (!found)
    {
        ACDB_ERR("Error[%d]: No matching calibration key vector was found", AR_ENOTEXIST);
        status = AR_ENOTEXIST;
    }

    ACDB_CLEAR_BUFFER(glb_buf_2);
    ACDB_CLEAR_BUFFER(glb_buf_3);
    return status;
}

/**
* \brief
*		Retrieve calibration data for a parameter from the data pool
* \param[int] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in/out] rsp: A data blob containg calibration data
* \param[in] offset_pair: calibration data def and dot offsets
* \return 0 on success, and non-zero on failure
*/
int32_t BuildParameterCalDataBlob(AcdbParameterCalData *req, AcdbBlob *rsp,
    AcdbDefDotPair *offset_pair)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t param_size = 0;
    uint32_t error_code = 0;
    uint32_t param_dot_offset = 0;
    uint32_t data_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t num_iid_pid_entries = 0;
    uint32_t entry_index = 0;
    ChunkInfo ci_caldef = { 0 };
    ChunkInfo ci_caldot = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbModIIDParamIDPair iid_pid_pair = { 0 };

    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("The input request, or response are null");
        return AR_EBADPARAM;
    }

    ci_caldef.chunk_id = ACDB_CHUNKID_CALDATADEF;
    ci_caldot.chunk_id = ACDB_CHUNKID_CALDATADOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(&ci_caldef, &ci_caldot, &ci_data_pool);
    if (AR_FAILED(status)) return status;

    offset = ci_caldef.chunk_offset + offset_pair->offset_def;

    status = FileManReadBuffer(&num_iid_pid_entries, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of <MID, PID> entries.", status);
        return status;
    }

    status = FileManReadBuffer(&glb_buf_3[0], num_iid_pid_entries * sizeof(AcdbModIIDParamIDPair), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read List of <MID, PID>.", status);
        return status;
    }

    iid_pid_pair.module_iid = req->module_iid;
    iid_pid_pair.parameter_id = req->parameter_id;

    if (SEARCH_ERROR == AcdbDataBinarySearch2((void*)&glb_buf_3,
        num_iid_pid_entries * sizeof(AcdbModIIDParamIDPair),
        &iid_pid_pair, 2,
        (int32_t)(sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)),
        &entry_index))
    {
        //MID PID not found
        return AR_ENOTEXIST;
    }
    else
    {
        offset = ci_caldot.chunk_offset + offset_pair->offset_dot;

        /* Calculation for DOT offset of <MID, PID> pair
        *
        * Offset of  +  Number of  +  Offset of the desired DOT entry based on
        *    DOT       DOT entries           index of <MID,PID> in DEF
        */
        param_dot_offset = offset + sizeof(uint32_t) + sizeof(uint32_t) * (uint32_t)(
            entry_index / (sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)));

        status = FileManReadBuffer(&data_offset, sizeof(uint32_t), &param_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read data pool offset from DOT.", status);
            return status;
        }

        offset = ci_data_pool.chunk_offset + data_offset;

        status = FileManReadBuffer(&param_size, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read param size from data pool.", status);
            return status;
        }

        rsp->buf_size = sizeof(AcdbModIIDParamIDPair) + 2 * sizeof(uint32_t) + param_size;

        //Write Module IID, and Parameter ID
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(AcdbModIIDParamIDPair),
            &iid_pid_pair, sizeof(AcdbModIIDParamIDPair));
        blob_offset += sizeof(AcdbModIIDParamIDPair);

        //Write Parameter Size
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
            &param_size, sizeof(uint32_t));
        blob_offset += sizeof(uint32_t);

        //Write Error code
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
            &error_code, sizeof(uint32_t));
        blob_offset += sizeof(uint32_t);

        //Write Payload
        if (param_size != 0)
        {
            status = FileManReadBuffer((uint8_t*)rsp->buf + blob_offset,
                param_size, &offset);
            if (AR_FAILED(status))
            {
                ACDB_ERR("Error[%d]: Failed to read param payload of %d bytes.",
                    status, param_size);
                return status;
            }
        }
    }

    return status;
}

int32_t SearchForMatchingVoiceCalKeyValues(AcdbParameterCalData *req,
    AcdbVcpmCalDataObj *cal_data_obj, uint32_t *table_offset)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = *table_offset;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    ChunkInfo ci_vcpm_cal_lut = { 0 };

    if (IsNull(req) || IsNull(cal_data_obj) || IsNull(table_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_vcpm_cal_lut.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_LUT;

    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_lut);
    if (AR_FAILED(status)) return status;

    status = FileManReadBuffer(cal_data_obj,
        sizeof(AcdbVcpmCalDataObj), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Cal "
            "Data Object Header.", status);
        return status;
    }

    offset = ci_vcpm_cal_lut.chunk_offset + cal_data_obj->offset_vcpm_ckv_lut;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice keys.", status);
        return status;
    }

    if (num_keys != req->cal_key_vector.num_keys)
    {
        //Go to Next Cal Data Obj
        *table_offset = file_offset
            + (cal_data_obj->num_data_offsets * sizeof(uint32_t));
        return AR_ENOTEXIST;
    }

    if (num_keys != 0)
    {
        offset += sizeof(uint32_t);//num_entries is always 1
        status = FileManReadBuffer(&glb_buf_1, num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to Voice Key IDs.", status);
            return status;
        }

        if (FALSE == CompareKeyVectorValues(
            req->cal_key_vector, glb_buf_3, glb_buf_1, num_keys))
        {
            //Go to Next Cal Data Obj
            *table_offset = file_offset
                + (cal_data_obj->num_data_offsets * sizeof(uint32_t));
            return AR_ENOTEXIST;
        }
    }

    *table_offset = file_offset;

    return status;
}

int32_t SearchForMatchingVoiceCalKeyIDs(AcdbParameterCalData *req,
    AcdbVcpmCkvDataTable *cal_data_table, uint32_t *table_offset)
{
    int32_t status = AR_EOK;
    uint32_t file_offset = *table_offset;
    uint32_t offset = 0;
    uint32_t num_keys = 0;
    ChunkInfo ci_vcpm_cal_key = { 0 };

    if (IsNull(req) || IsNull(cal_data_table) || IsNull(table_offset))
    {
        ACDB_ERR("Error[%d]: One or more input parameters are null",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_vcpm_cal_key.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;

    status = ACDB_GET_CHUNK_INFO(&ci_vcpm_cal_key);
    if (AR_FAILED(status)) return status;

    status = FileManReadBuffer(cal_data_table,
        sizeof(AcdbVcpmCkvDataTable), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read CKV "
            "Data Table Header.", status);
        return status;
    }

    offset = ci_vcpm_cal_key.chunk_offset +
        cal_data_table->offset_voice_key_table;
    status = FileManReadBuffer(&num_keys, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of voice keys.", status);
        return status;
    }

    if (num_keys != req->cal_key_vector.num_keys)
    {
        //Go to Next CKV Data Table
        *table_offset = file_offset
            + sizeof(uint32_t) //table size
            + cal_data_table->table_size
            - sizeof(AcdbVcpmCkvDataTable);
        return AR_ENOTEXIST;
    }

    if (num_keys != 0)
    {
        status = FileManReadBuffer(&glb_buf_1, num_keys * sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to Voice Key IDs.", status);
            return status;
        }

        if (FALSE == CompareKeyVectorIds(
            req->cal_key_vector, glb_buf_3, glb_buf_1, num_keys))
        {
            //Go to Next CKV Data Table
            *table_offset = file_offset
                + sizeof(uint32_t) //table size
                + cal_data_table->table_size
                - sizeof(AcdbVcpmCkvDataTable);
            return AR_ENOTEXIST;
        }
    }

    *table_offset = file_offset;

    return status;
}

int32_t GetVoiceParameterCalData(AcdbParameterCalData *req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t i = 0;
    uint32_t file_offset = 0;
    uint32_t blob_offset = 0;
    uint32_t param_size = 0;
    uint32_t error_code = 0;
    uint32_t id_pair_table_size = 0;
    uint32_t data_pool_offset = 0;
    uint32_t data_pool_offset_index = 0;
    ChunkInfo ci_vcpm_cal = { 0 };
    ChunkInfo ci_vcpm_cal_key = { 0 };
    ChunkInfo ci_vcpm_cal_lut = { 0 };
    ChunkInfo ci_vcpm_cal_def = { 0 };
    ChunkInfo ci_data_pool = { 0 };
    AcdbVcpmSubgraphCalHeader subgraph_cal_header = { 0 };
    AcdbVcpmSubgraphCalTable subgraph_cal_table_header = { 0 };
    AcdbVcpmCkvDataTable cal_data_table = { 0 };
    AcdbVcpmCalDataObj cal_data_obj = { 0 };
    AcdbMiidPidPair id_pair = { 0 };
    AcdbTableInfo table_info = { 0 };
    AcdbTableSearchInfo search_info = { 0 };

    ci_vcpm_cal.chunk_id = ACDB_CHUNKID_VCPM_CAL_DATA;
    ci_vcpm_cal_key.chunk_id = ACDB_CHUNKID_VCPM_CALKEY_TABLE;
    ci_vcpm_cal_lut.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_LUT;
    ci_vcpm_cal_def.chunk_id = ACDB_CHUNKID_VCPM_CALDATA_DEF;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(
        &ci_vcpm_cal,       &ci_vcpm_cal_lut,
        &ci_vcpm_cal_key,   &ci_vcpm_cal_def,
        &ci_data_pool);
    if (AR_FAILED(status)) return status;

    file_offset = ci_vcpm_cal.chunk_offset;
    status = FileManReadBuffer(&subgraph_cal_header,
        sizeof(AcdbVcpmSubgraphCalHeader), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read Module Header.", status);
        return status;
    }

    //Search for the matching VCPM Subgraph Cal Data Table
    status = GetVcpmSubgraphCalTable(subgraph_cal_header.num_subgraphs,
        req->subgraph_id, &file_offset, &subgraph_cal_table_header);
    if (AR_FAILED(status))
    {
        return status;
    }

    //Search for matching key vector then find iid,pid and get voice cal data
    for (i = 0; i < subgraph_cal_table_header.num_ckv_data_table; i++)
    {
        status = SearchForMatchingVoiceCalKeyIDs(
            req, &cal_data_table, &file_offset);

        if (AR_FAILED(status) && status != AR_ENOTEXIST)
            return status;
        else if (AR_SUCCEEDED(status)) break;
    }

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to find matching key vector.", status);
        return status;
    }

    for (i = 0; i < cal_data_table.num_caldata_obj; i++)
    {
        status = SearchForMatchingVoiceCalKeyValues(
            req, &cal_data_obj, &file_offset);

        if (AR_FAILED(status) && status != AR_ENOTEXIST)
            return status;
        else if (AR_SUCCEEDED(status)) break;
    }

    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to find matching key vector.", status);
        return status;
    }

    /* Binary Search through <IID PID> to find index of <IID PID>. Use the
     * index to calculate the Cal Data Object data pool offset get to the
     * data pool offset */
    id_pair_table_size =
        cal_data_obj.num_data_offsets * sizeof(AcdbMiidPidPair);

    id_pair.module_iid = req->module_iid;
    id_pair.parameter_id = req->parameter_id;

    //Setup Table Information
    table_info.table_offset = ci_vcpm_cal_def.chunk_offset +
        cal_data_obj.offset_cal_def + sizeof(uint32_t);//Skip num id pairs
    table_info.table_size = id_pair_table_size;
    table_info.table_entry_size = sizeof(AcdbMiidPidPair);

    //Setup Search Information
    search_info.num_search_keys = 2;//IID, PID
    search_info.num_structure_elements =
        (sizeof(AcdbMiidPidPair) / sizeof(uint32_t));
    search_info.table_entry_struct = &id_pair;

    status = AcdbTableBinarySearch(&table_info, &search_info);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Failed to find Module Instance ID(0x%x) "
            "Parameter ID(0x%x)", id_pair.module_iid, id_pair.parameter_id);
        return status;
    }

    data_pool_offset_index = search_info.entry_index;
    file_offset += data_pool_offset_index * sizeof(uint32_t);

    //Get parameter data from the data pool
    status = FileManReadBuffer(&data_pool_offset,
        sizeof(uint32_t), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read global "
            "data pool offset.", status);
        return status;
    }

    file_offset = ci_data_pool.chunk_offset + data_pool_offset;
    status = FileManReadBuffer(&param_size, sizeof(uint32_t), &file_offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read parameter size.", status);
        return status;
    }

    rsp->buf_size = sizeof(AcdbMiidPidPair) +
        2 * sizeof(uint32_t) + param_size;

    //Write Module IID, and Parameter ID
    ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset,
        sizeof(AcdbMiidPidPair), &id_pair, sizeof(AcdbMiidPidPair));
    blob_offset += sizeof(AcdbMiidPidPair);

    //Write Parameter Size
    ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
        &param_size, sizeof(uint32_t));
    blob_offset += sizeof(uint32_t);

    //Write Error code
    ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
        &error_code, sizeof(uint32_t));
    blob_offset += sizeof(uint32_t);

    if (param_size != 0)
    {
        status = FileManReadBuffer((uint8_t*)rsp->buf + blob_offset,
            param_size, &file_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read parameter payload.", status);
            return status;
        }
        blob_offset += param_size;
    }

    return status;
}

/**
* \brief
*		Get calibration data for one parameter
* \param[int] req: Request containing the subgraph, module instance, parameter, and CKV
* \param[in/out] rsp: A data blob containg calibration data
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbGetParameterCalData(AcdbParameterCalData *req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    AcdbCalKeyTblEntry *cal_key_entry_list = NULL;
    AcdbCkvLutEntryOffsets ckv_lut_entry = { 0 };
    uint32_t num_entries = 0;
    if (IsNull(req) || IsNull(rsp))
    {
        ACDB_ERR("The input request and/or response is null");
        return AR_EBADPARAM;
    }
    //Search for Voice Subgraph Calibration Data
    status = GetVoiceParameterCalData(req, rsp);
    if (AR_FAILED(status) && status != AR_ENOTEXIST)
    {
        return status;
    }
    else if (AR_SUCCEEDED(status)) return status;

    //Find Subgraph and Possible CKV offsets
    cal_key_entry_list = (AcdbCalKeyTblEntry*)&glb_buf_1[0];

    status = SearchSubgraphCalLut(req->subgraph_id, sizeof(glb_buf_1),
        cal_key_entry_list, &num_entries);
    if (AR_FAILED(status))
    {
        return status;
    }

    //Search List of Offsets for matching CKV
    for (uint32_t i = 0; i < num_entries; i++)
    {
        AcdbCalKeyTblEntry e = cal_key_entry_list[i];
        status = SearchForMatchingCalKeyVector(req,
            e.offset_cal_key_tbl, e.offset_cal_lut, &ckv_lut_entry);
        if (AR_SUCCEEDED(status)) break;
    }

    if (AR_FAILED(status))
    {
        //Either CKV not found or another error occured
        ACDB_ERR("Error[%d]: Could not find a matcing CKV.", status);
        return status;
    }

    //Use offset from CKV LUT to find Module Calibration
    status = BuildParameterCalDataBlob(req, rsp,
        (AcdbDefDotPair*)(void*)&ckv_lut_entry);

    return status;
}

/**
* \brief
*		Retrieve tag data for a parameter from the data pool
* \param[int] req: Request containing the subgraph, module instance, parameter, and module tag
* \param[in/out] rsp: A data blob containg tag data
* \param[in] offset_pair: Tag data def and dot offsets
* \return 0 on success, and non-zero on failure
*/
int32_t BuildParameterTagDataBlob(AcdbParameterTagData *req, AcdbBlob *rsp, AcdbDefDotPair *offset_pair)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t blob_offset = 0;
    uint32_t data_offset = 0;
    uint32_t param_size = 0;
    uint32_t error_code = 0;
    uint32_t param_dot_offset = 0;
    uint32_t entry_index = 0;
    uint32_t num_iid_pid_entries = 0;
    AcdbModIIDParamIDPair iid_pid_pair = { 0 };
    ChunkInfo ci_tag_data_def = { 0 };
    ChunkInfo ci_tag_data_dot = { 0 };
    ChunkInfo ci_data_pool = { 0 };

    if (IsNull(req) || IsNull(offset_pair))
    {
        ACDB_ERR("Error[%d]: The input request, response, or offset pair is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    ci_tag_data_def.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DEF;
    ci_tag_data_dot.chunk_id = ACDB_CHUNKID_MODULE_TAGDATA_DOT;
    ci_data_pool.chunk_id = ACDB_CHUNKID_DATAPOOL;

    status = ACDB_GET_CHUNK_INFO(
        &ci_tag_data_def, &ci_tag_data_dot, &ci_data_pool);

    offset = ci_tag_data_def.chunk_offset + offset_pair->offset_def;
    status = FileManReadBuffer(&num_iid_pid_entries, sizeof(uint32_t), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read number of tagged <MID, PID> entries.", status);
        return status;
    }

    status = FileManReadBuffer(&glb_buf_3[0], num_iid_pid_entries * sizeof(AcdbModIIDParamIDPair), &offset);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to read List of <MID, PID>.", status);
        return status;
    }

    iid_pid_pair.module_iid = req->module_iid;
    iid_pid_pair.parameter_id = req->parameter_id;

    if (SEARCH_ERROR == AcdbDataBinarySearch2((void*)&glb_buf_3,
        num_iid_pid_entries * sizeof(AcdbModIIDParamIDPair),
        &iid_pid_pair, 2,
        (int32_t)(sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)),
        &entry_index))
    {
        //MID PID not found
        return AR_ENOTEXIST;
    }
    else
    {
        offset = ci_tag_data_dot.chunk_offset + offset_pair->offset_dot;

        /* Calculation for DOT offset of <MID, PID> pair
        *
        * Offset of  +  Number of  +  Offset of the desired DOT entry based on
        *    DOT       DOT entries           index of <MID,PID> in DEF
        */
        param_dot_offset = offset + sizeof(uint32_t) + sizeof(uint32_t) * (uint32_t)(
            entry_index / (sizeof(AcdbModIIDParamIDPair) / sizeof(uint32_t)));

        status = FileManReadBuffer(&data_offset, sizeof(uint32_t), &param_dot_offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read data pool offset from DOT.", status);
            return status;
        }

        offset = ci_data_pool.chunk_offset + data_offset;

        status = FileManReadBuffer(&param_size, sizeof(uint32_t), &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read param size from data pool.", status);
            return status;
        }

        rsp->buf_size = sizeof(AcdbModIIDParamIDPair) + 2 * sizeof(uint32_t) + param_size;

        //Write Module IID, and Parameter ID
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(AcdbModIIDParamIDPair),
            &iid_pid_pair, sizeof(AcdbModIIDParamIDPair));
        blob_offset += sizeof(AcdbModIIDParamIDPair);

        //Write Parameter Size
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
            &param_size, sizeof(uint32_t));
        blob_offset += sizeof(uint32_t);

        //Write Error code
        ACDB_MEM_CPY_SAFE((uint8_t*)rsp->buf + blob_offset, sizeof(uint32_t),
            &error_code, sizeof(uint32_t));
        blob_offset += sizeof(uint32_t);

        //Write Payload
        status = FileManReadBuffer((uint8_t*)rsp->buf + blob_offset,
            param_size, &offset);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to read param payload of %d bytes.",
                status, param_size);
            return status;
        }
    }

    return status;
}

/**
* \brief
*		Get Tag data for one parameter
* \param[int] req: Request containing the subgraph, module instance, parameter, and module tag
* \param[in/out] rsp: A data blob containg tag data
* \return 0 on success, and non-zero on failure
*/
int32_t AcdbGetParameterTagData(AcdbParameterTagData *req, AcdbBlob* rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset_tag_data_tbl = 0;
    AcdbSgIdModuleTag sg_module_tag = { 0 };
    AcdbDefDotPair offset_pair = { 0 };

    status = AcdbSort2(
        req->module_tag.tag_key_vector.num_keys * sizeof(AcdbKeyValuePair),
        req->module_tag.tag_key_vector.graph_key_vector,
        sizeof(AcdbKeyValuePair), 0);

    status = TagDataSearchKeyTable(req->subgraph_id, req->module_tag.tag_id,
        &offset_tag_data_tbl);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to search for Subgraph(%x) Tag(%x)",
            status, req->subgraph_id, req->module_tag.tag_id);
        return status;
    }

    sg_module_tag.module_tag = req->module_tag;
    sg_module_tag.num_sg_ids = 1;
    sg_module_tag.sg_ids = &req->subgraph_id;

    status = TagDataSearchLut(&sg_module_tag.module_tag.tag_key_vector,
        offset_tag_data_tbl, &offset_pair);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to search tag data LUT for Subgraph(%x) Tag(%x)",
            status, req->subgraph_id, req->module_tag.tag_id);
        return status;
    }

    status = BuildParameterTagDataBlob(req, rsp, &offset_pair);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to build tag data blob for Subgraph(%x) Tag(%x)",
            status, req->subgraph_id, req->module_tag.tag_id);
    }

    return status;
}
