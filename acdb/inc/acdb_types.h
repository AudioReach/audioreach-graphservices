#ifndef __ACDB_TYPES_H__
#define __ACDB_TYPES_H__
/**
*=============================================================================
* \file acdb_types.h
*
* \brief
*		Contains type definitions, constatns, and macros used across ACDB SW
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/
#include "ar_osal_types.h"
#include "acdb.h"

/*-----------------------------------------------------------------------------
* Macros
*----------------------------------------------------------------------------*/

/**< Length in bytes of global unique identifiers */
#define ACDB_GUID_BYTE_LENGTH 16

/**< The max character length of a string */
#define ACDB_MAX_PATH_LENGTH 256

 /**< The number of elements in Global Buffer 1 */
#define GLB_BUF_1_LENGTH 2500

/**< The number of elements in Global Buffer 2 */
#define GLB_BUF_2_LENGTH 1000

/**< The number of elements in Global Buffer 3 */
#define GLB_BUF_3_LENGTH 500

/**< Max number of keys that can be used. This is capped at half the capacity
of the smallest global buffer length GLB_BUF_3_LENGTH*/
#define ACDB_MAX_KEY_COUNT (GLB_BUF_3_LENGTH/2)

/*-----------------------------------------------------------------------------
* Enums Types
*----------------------------------------------------------------------------*/

/**< An enumeration for handles that control the where file manager
retrieves data from  */
typedef enum _acdb_handle_override_t {
    /**< Context Manager Handle
    This is the default handle used by all acdb_ioctl and/or ats commands. */
    ACDB_FM_HANDLE_OVERRIDE_CTX_MANAGER = 0,
    /**< File Manager Handle
    This handle is used mainly by the file manager during validation for new databases.  */
    ACDB_FM_HANDLE_OVERRIDE_FILE_MANAGER
} AcdbHandleOverride;

 typedef enum _acdb_op_t {
    ACDB_OP_NONE,
    ACDB_OP_GET_SIZE,
    ACDB_OP_GET_DATA,
    ACDB_OP_GET_PARAM_DATA,
    ACDB_OP_GET_MODULE_DATA,
    ACDB_OP_GET_SUBGRAPH_DATA,
}AcdbOp;

typedef enum _key_vector_type_t {
    TAG_KEY_VECTOR = 0,
    CAL_KEY_VECTOR,
    GRAPH_KEY_VECTOR,
}KeyVectorType;


typedef enum acdb_amdb_reg_dereg_info_type_t
{
    ACDB_AMDB_INFO_REGISTRATION,
    ACDB_AMDB_INFO_DEREGISTRATION,
}acdb_amdb_reg_dereg_info_type_t;

/*-----------------------------------------------------------------------------
* Structure Types
*----------------------------------------------------------------------------*/

/**< Holds a pointer to memory of the specified size */
typedef struct acdb_buffer_t
{
    /**< Size of the buffer */
    uint32_t size;
    /**< Pointer to the buffer in memory */
    void *buffer;
}acdb_buffer_t;

/**< Holds a pointer to a path string */
typedef struct acdb_path_t
{
    /**< The character length of a path in bytes including the
    null terminating character \0 */
    uint32_t path_length;
    /**< Pointer to the path string memory */
    char_t *path;
}acdb_path_t;

/**< Holds 256-byte charater strings */
typedef struct acdb_path_256_t {
    uint32_t path_len;
    char_t path[ACDB_MAX_PATH_LENGTH];
}acdb_path_256_t;

/**< A linked list node containing a pointer to some
value/structure and the next node */
typedef struct _linked_list_node_t LinkedListNode;
struct _linked_list_node_t
{
    void* p_struct;
    LinkedListNode* p_next;
};

typedef struct _linked_list_t LinkedList;
struct _linked_list_t
{
    uint32_t length;
    LinkedListNode* p_head;
    LinkedListNode* p_tail;
}
;

typedef struct _acdb_fm_read_seek_req_t acdb_fm_read_req_t;
struct _acdb_fm_read_seek_req_t
{
    /**< Determines which handle to use to retrieve data in the file manager.
    By default the context manager handle is used */
    AcdbHandleOverride handle_override;
    /**< Pointer to the memory to read data into */
    void* dst_buffer;
    /**< The number of bytes to read */
    size_t read_size;
    /**< Identifies the property */
    uint32_t offset;
};

typedef struct _acdb_fm_mem_ptr_t
{
    /**< Determines which handle to use to retrieve data in the file manager.
    By default the context manager handle is used */
    AcdbHandleOverride handle_override;
    void *file_ptr;
    size_t data_size;
    uint32_t offset;
}acdb_fm_file_ptr_req_t;

typedef struct _chunk_info ChunkInfo;
struct _chunk_info {
    /**< Determines which handle to use to retrieve data in the file manager.
    By default the context manager handle is used */
    AcdbHandleOverride handle_override;
    uint32_t chunk_id;
    uint32_t chunk_size;
    uint32_t chunk_offset;
};

typedef struct _acdb_def_dot_pair_t AcdbDefDotPair;
struct _acdb_def_dot_pair_t {
    uint32_t offset_def;
    uint32_t offset_dot;
};

typedef struct _partition Partition;
struct _partition {
    uint32_t size;
    uint32_t offset;
};

typedef struct _key_table_header_t KeyTableHeader;
struct _key_table_header_t {
    uint32_t num_keys;
    uint32_t num_entries;
};

/**< Holds offsets to the subgraph sequence list properties for the
subgraphs under a graph */
typedef struct acdb_graph_info_t
{
    /**< Absolute offset to the subgraph list where subgraphs are listed
    * in reverse order from sink to source */
    uint32_t sg_list_offset;
    /**< Absolute offset to the subgraph property data list
    *for all the subgraph in the graph*/
    uint32_t sg_prop_data_offset;
}acdb_graph_info_t;

typedef struct _sg_list_header_t SgListHeader;
struct _sg_list_header_t {
    uint32_t size;
    uint32_t num_subgraphs;
};

typedef struct _sg_list_obj_header_t SgListObjHeader;
struct _sg_list_obj_header_t {
    uint32_t subgraph_id;
    uint32_t num_subgraphs;
};

/**< Represents and entry in the Module Tag Key Data LUT  or Tagged
Module LUT chunks */
typedef struct _subgraph_tag_key_lut_entry_t SubgraphTagLutEntry;
struct _subgraph_tag_key_lut_entry_t {
    /**< Subgraph ID */
    uint32_t sg_id;
    /**< Module Tag */
    uint32_t tag_id;
    /**<  Module Tag Key Data LUT: an offset of the tag key value lut
    Tagged Module LUT: an offset to a list of <MID, PID> pairs*/
    uint32_t offset;
};

/**< Represents and entry in the Module Tag Key List LUT Chunk */
typedef struct _tag_key_list_entry_t TagKeyListEntry;
struct _tag_key_list_entry_t {
    /**< Module Tag */
    uint32_t tag_id;
    /**< Offset of the key list in the data pool */
    uint32_t key_list_offset;
};

/**< A Tag and Definition Offset pair */
typedef struct _tag_def_offset_pair AcdbTagDefOffsetPair;
struct _tag_def_offset_pair {
    uint32_t tag_id;
    uint32_t def_offset;
};

typedef struct acdb_driver_cal_lut_entry_t {
    uint32_t mid;
    uint32_t offset_calkey_table;
    uint32_t offset_caldata_table;
}acdb_driver_cal_lut_entry_t;

typedef struct _gsl_cal_lut_header_t GslCalDataLutHeader;
struct _gsl_cal_lut_header_t
{
    uint32_t num_keys;
    uint32_t num_entries;
};

typedef struct _calibration_identifier_map_t CalibrationIdMap;
struct _calibration_identifier_map_t
{
    uint32_t cal_id;
    uint32_t param_id;
    uint32_t cal_data_offset;
};

typedef struct _acdb_parameter_tag_data_t AcdbParameterTagData;
struct _acdb_parameter_tag_data_t {
    uint32_t subgraph_id;
    uint32_t module_iid;
    uint32_t parameter_id;
    AcdbModuleTag module_tag;
};

typedef struct _acdb_parameter_cal_data_t AcdbParameterCalData;
struct _acdb_parameter_cal_data_t {
    uint32_t subgraph_id;
    uint32_t module_iid;
    uint32_t parameter_id;
    AcdbGraphKeyVector cal_key_vector;
};

typedef struct _acdb_mod_iid_param_id_pair_t AcdbModIIDParamIDPair;
struct _acdb_mod_iid_param_id_pair_t {
    uint32_t module_iid;
    uint32_t parameter_id;
};

typedef struct _acdb_sg_cal_lut_header_t AcdbSgCalLutHeader;
struct _acdb_sg_cal_lut_header_t {
    uint32_t subgraph_id;
    uint32_t num_ckv_entries;
};

typedef struct _acdb_cal_key_tbl_entry AcdbCalKeyTblEntry;
struct _acdb_cal_key_tbl_entry {
    uint32_t offset_cal_key_tbl;
    uint32_t offset_cal_lut;
};

typedef struct _acdb_ckv_lut_entry_offsets_t AcdbCkvLutEntryOffsets;
struct _acdb_ckv_lut_entry_offsets_t {
    uint32_t offset_def;
    uint32_t offset_dot;
    uint32_t offset_dot2;
};

/**< The Header format used when retrieving calibration data for the DSP */
typedef struct _acdb_dsp_module_header_t AcdbDspModuleHeader;
struct _acdb_dsp_module_header_t
{
    /**< Module Instance ID*/
    uint32_t module_iid;
    /**< Parameter ID*/
    uint32_t parameter_id;
    /**< Size of the parameter*/
    uint32_t param_size;
    /**< Error code set by the dsp*/
    uint32_t error_code;
};

/**< Same as AcdbDspModuleHeader except that this format does not
contain the error code */
typedef struct _acdb_module_header_t AcdbModuleHeader;
struct _acdb_module_header_t
{
    /**< Module Instance ID*/
    uint32_t module_iid;
    /**< Parameter ID*/
    uint32_t parameter_id;
    /**< Size of the parameter*/
    uint32_t param_size;
};

/*VCPM Structures Start*/
typedef struct _acdb_vcpm_subgraph_cal_header_t AcdbVcpmSubgraphCalHeader;
struct _acdb_vcpm_subgraph_cal_header_t
{
    /**< VCPM Module Instance ID*/
    uint32_t module_iid;
    /**< VCPM Parameter ID*/
    uint32_t parameter_id;
    /**< Number of VCPM Subgraphs*/
    uint32_t num_subgraphs;
};

typedef struct _acdb_vcpm_subgraph_cal_table_t AcdbVcpmSubgraphCalTable;
struct _acdb_vcpm_subgraph_cal_table_t
{
    /**< */
    uint32_t subgraph_id;
    /**< */
    uint32_t table_size;
    /**< */
    uint32_t major;
    /**< */
    uint32_t minor;
    /**< */
    uint32_t offset_vcpm_master_key_table;
    /**< */
    uint32_t num_ckv_data_table;
    //List of voice ckv data tables
};

typedef struct _acdb_vcpm_ckv_data_table_t AcdbVcpmCkvDataTable;
struct _acdb_vcpm_ckv_data_table_t
{
    /**< Size of the VCPM Calibration Data Table*/
    uint32_t table_size;
    /**< Offset of the Voice Calibration Key ID table in the Voice Key Chunk*/
    uint32_t offset_voice_key_table;
    /**< Size of the calibration data offset table*/
    uint32_t cal_dot_size;
    /**< Number of Calibration data objects*/
    uint32_t num_caldata_obj;
    //Cal Dot Table
};

typedef struct _acdb_vcpm_caldata_object_t AcdbVcpmCalDataObj;
struct _acdb_vcpm_caldata_object_t
{
    /**< Offset of the Voice CKV LUT in the VCPM CKV LUT Chunk*/
    uint32_t offset_vcpm_ckv_lut;
    /**< Offset of the VCPM Cal Definition table in the VCPM Cal Def Chunk*/
    uint32_t offset_cal_def;
    /**< The number of parameter calibration payloads in the data pool
    This should be the same as the number of <IID, PID> pairs in the
    Cal Def Table*/
    uint32_t num_data_offsets;
    //Cal Dot Tables...
};

typedef struct _acdb_vcpm_param_info_t AcdbVcpmParamInfo;
struct _acdb_vcpm_param_info_t
{
    /**< Offset of the parameter in the VCPM data pool*/
    uint32_t offset_vcpm_data_pool;
    /**< Flag to check the wheter a parameter is persistent. 0:false, 1:true*/
    uint32_t is_persistent;
};


typedef struct _acdb_mid_pid_pair_t AcdbMiidPidPair;
struct _acdb_mid_pid_pair_t
{
    /**< Module Instance ID*/
    uint32_t module_iid;
    /**< Parameter ID*/
    uint32_t parameter_id;
};

typedef struct _acdb_vcpm_key_info_t AcdbVcpmKeyInfo;
struct _acdb_vcpm_key_info_t
{
    /**< The Voice Calibration Key ID*/
    uint32_t key_id;
    /**< */
    uint32_t is_dynamic;
};

typedef struct _acdb_vcpm_chunk_properties_t AcdbVcpmChunkProperties;
struct _acdb_vcpm_chunk_properties_t
{
    /**< The chunks base offset (excluding the chunk size)*/
    uint32_t base_offset;
    /**< The current offset */
    uint32_t offset;
    /**< The chunk size */
    uint32_t size;
};

//typedef struct _acdb_vcpm_kv_info_t AcdbVcpmKvInfo;
//#include "acdb_begin_pack.h"
//struct _acdb_vcpm_kv_info_t
//{
//    /**< Flag for detecting an empty key vector
//    0:Not an empty key vector 1: Is an empty key vector*/
//    uint32_t is_zero_kv;
//    /**< Offset of key vector key(s) in VCPM Key ID Chunk */
//    uint32_t offset_cal_key_id;
//    /**< Offset of key vector value(s) in VCPM Key LUT Chunk */
//    uint32_t offset_cal_key_lut;
//}
//#include "acdb_end_pack.h"
//;

typedef struct _acdb_vcpm_offloaded_param_info_t AcdbVcpmOffloadedParamInfo;
struct _acdb_vcpm_offloaded_param_info_t
{
    /**< File offset to the <IID, PID> pair in the VCPM Cal DEF Chunk */
    uint32_t file_offset_cal_def;
    /**< File offset to the parameters payload in the Global Datapool Chunk */
    uint32_t file_offset_data_pool;
    /**< Blob offset of the CalDataObj[n].ParamInfo.offset in the VCPM
    Subgraph Info Chunk */
    uint32_t blob_offset_vcpm_param_info;
};

typedef struct _acdb_file_to_vcpm_data_pool_offset_info_t AcdbFileToVcpmDataPoolOffsetInfo;
struct _acdb_file_to_vcpm_data_pool_offset_info_t
{
    /**< File offset to the <IID, PID> pair in the VCPM Cal DEF Chunk */
    uint32_t file_offset_cal_def;
    /**< File offset to the parameters payload in the Global Datapool Chunk */
    uint32_t file_offset_data_pool;
    /**< Blob offset to the parameter info in the VCPM Datapool Chunk */
    uint32_t vcpm_offset_data_pool;
};

typedef struct _acdb_proc_domain_module_list_t AcdbProcDomainModuleList;
#include "acdb_begin_pack.h"
struct _acdb_proc_domain_module_list_t
{
    /**< The processor domain that the modules in the list run under */
    uint32_t proc_domain_id;
    /**< The number of modules in the module list */
    uint32_t module_count;
    /**< A list of modules associated with proc_domain_id */
    AcdbModuleInstance module_list[0];
}
#include "acdb_end_pack.h"
;

typedef struct _acdb_subgraph_proc_domain_module_map_t
AcdbSubgraphPdmMap;
#include "acdb_begin_pack.h"
struct _acdb_subgraph_proc_domain_module_map_t
{
    /**< The subgraph associated with the modules */
    uint32_t subgraph_id;
    /**< the number of processor domains running in the subgraph */
    uint32_t proc_count;
    /**< the size of the proccessor domain module list */
    uint32_t size;
    /**< A list that maps modules to a processor domain */
    AcdbProcDomainModuleList* proc_info;
}
#include "acdb_end_pack.h"
;

typedef struct _acdb_vcpm_blob_info_t AcdbVcpmBlobInfo;
struct _acdb_vcpm_blob_info_t
{
    /**< Current operation being performed */
    AcdbOp op;
    /**< The VCPM Subgraph ID*/
    uint32_t subgraph_id;
    /**< The Processor to get calibration for */
    uint32_t proc_id;
    /**< A flag used to filter calibration based on processor domain */
    bool_t should_filter_cal_by_proc_domain;
    /**< A pointer to a mapping that associates module instances with
    the processor domains they run on */
    AcdbSubgraphPdmMap* sg_mod_iid_map;
    /**< A flag indicating whether check for hw accel based calibraion */
    bool_t should_check_hw_accel;
    /**< An offset to a Subgrahps hardware accel module list */
    uint32_t hw_accel_module_list_offset;
    /**< Starting offset of the VCPM Framework Module blob */
    uint32_t offset_vcpm_blob;
    /**< The number of offloaded parameters found */
    uint32_t num_offloaded_params;
    /**< A pointer to the current offloaded parameter info node */
    LinkedListNode* curr_opi_node;
    /**< List of AcdbVcpmOffloadedParamInfo for writting offloaded params
    at the end of the vcpm datapool */
    LinkedList offloaded_param_info_list;
    /**< List of offloaded parameter IDs*/
    AcdbUintList offloaded_param_list;
    /**< 0:Zero CKV has NOT been writen 1: Zero CKV has been writen */
    //AcdbVcpmKvInfo zero_key_vector_info;
    /**< A flag indicating whether the module CKV found is the default key
    vector(no keys) */
    bool_t is_default_module_ckv;
    /**< A flag indicating whether process(true) or skip(false) the
    default CKV */
    bool_t ignore_get_default_data;
    /**< A flag indicating whether to add (true) iids to the referenced_iid_list
    or do nothing (false) */
    bool_t ignore_iid_list_update;
    /**< Keeps track of module IIDs that are used in CKVs. This does not include
    the default CKV. The list contains AcdbIidRefCount objects */
    AcdbUintList referenced_iid_list;
    /**< A list of relative offsets to the ckv data tables with data to write */
    AcdbUintList ckv_data_table_offset_list;
    /**< A list of absolute offsets to the found cal key id tables */
    AcdbUintList cal_key_id_table_offset_list;
    /**< VCPM Subgraph Info Chunk*/
    AcdbVcpmChunkProperties chunk_subgraph_info;
    /**< Master Key Table Chunk that contains the super set of calibration
    keys used in the subgraph */
    AcdbVcpmChunkProperties chunk_master_key;
    /**< Voice Cal Key Table chunk that contains various key combinations.
    The keys are a subset of the keys defined in the Master Key Table */
    AcdbVcpmChunkProperties chunk_cal_key_id;
    /**< Voice Cal Key Lookup table that contains the values of the key
    combinations in the Voice Cal Key Table chunk */
    AcdbVcpmChunkProperties chunk_cal_key_lut;
    /**< Datapool chunk that contains calibration data for modules within
    the vcpm subgraph */
    AcdbVcpmChunkProperties chunk_data_pool;
};

typedef struct _acdb_vcpm_chunk_info_t AcdbVcpmChunkInfo;
struct _acdb_vcpm_chunk_info_t
{
    ChunkInfo vcpm_sg_cal;
    ChunkInfo vcmp_master_key_table;
    ChunkInfo vcpm_cal_key_table;
    ChunkInfo vcpm_cal_lut;
    ChunkInfo vcpm_cal_def;
};

/*VCPM Structures End*/

typedef struct _acdb_property_entry_t AcdbPropertyEntry;
struct _acdb_property_entry_t
{
    uint32_t property_id;
    uint32_t offset_property_data;
};

typedef struct _acdb_offloaded_param_header_t AcdbOffloadedParamHeader;
struct _acdb_offloaded_param_header_t
{
    /**< the alignment that determines the amount of padding added before the data */
    uint32_t alignment;
    /**< the starting offset of the data */
    uint32_t data_offset;
    /**< Size of the data starting at data_offset */
    uint32_t data_size;
    /*uint8_t data[0]*/
    /*padding = data_length % 4*/
};

/**< Contains a list of subgraphs and parameter data under the subgraphs. The
parameter data can be calibration or tag data */
typedef struct _acdb_subgraph_param_data_t AcdbSubgraphParamData;
struct _acdb_subgraph_param_data_t {
    /**< The list of subgraphs */
    AcdbUintList subgraph_id_list;
    /**<  Configures the cal/tag data blob parser to bypass the
    error code if its not included with each parameter. For example,
    param data set from qact is in the fomrat:
    <Instance ID, Param ID, Size, Data[Size]>*/
    bool_t ignore_error_code;
    /**< The size of the subgraph parameter data */
    uint32_t data_size;
    /**< Parameter data in the format of:
    [1]<Instance ID, Param ID, Size, Error Code, Data[Size]>
    ...
    [n]<Instance ID, Param ID, Size, Error Code, Data[Size]>*/
    void* data;
};

/**< Represents an entry within the subgraph connection lookup table */
typedef struct _acdb_subgraph_connection_t AcdbSubgraphConnection;
struct _acdb_subgraph_connection_t
{
    /**< The ID of source subgraph */
    uint32_t src_subgraph_id;
    /**< The ID of destination subgraph */
    uint32_t dst_subgraph_id;
    /**< The offset within the subgraph connection definition table */
    uint32_t def_offset;
    /**< The offset within the subgraph connection data offset table */
    uint32_t dot_offset;
};

typedef struct _acdb_shared_subgrah_data_guid_entry_t AcdbSharedSubgraphDataGuid;
struct _acdb_shared_subgrah_data_guid_entry_t {
    /**< The identifier for the shared subgraph */
    uint32_t subgraph_id;
    /**< A globally unique 128-bit integer representing the shared subgraphs data. */
    uint8_t guid[ACDB_GUID_BYTE_LENGTH];
};

typedef struct _acdb_shared_subgraph_guid_table_t AcdbSharedSubgraphGuidTable;
struct _acdb_shared_subgraph_guid_table_t {
    uint32_t num_subgraphs;
    AcdbSharedSubgraphDataGuid* guid_entries;
};

typedef struct _acdb_range_t AcdbRange;
struct _acdb_range_t {
    uint32_t min;
    uint32_t max;
};

typedef struct _acdb_delta_module_cal_data_t AcdbDeltaModuleCalData;
struct _acdb_delta_module_cal_data_t {
    uint32_t module_iid;
    uint32_t param_id;
    uint32_t param_size;
    void* param_payload;
};

typedef struct _acdb_delta_persistence_payload_t AcdbDeltaPersistanceData;
struct _acdb_delta_persistence_payload_t {
    uint32_t data_size;
    LinkedList cal_data_list;//List of AcdbDeltaModuleCalData
};

typedef struct _acdb_delta_subgraph_data_t AcdbDeltaSubgraphData;
struct _acdb_delta_subgraph_data_t {
    uint32_t subgraph_id;
    uint32_t subgraph_data_size;
    AcdbDeltaPersistanceData non_global_data;
    AcdbDeltaPersistanceData global_data;
};

/**< Maps a Key Vector to subgraph parameter data instances */
typedef struct acdb_delta_data_map_t {
    /**< Key vector type that describes the data in key_vector_data.
    If type=TAG_KEY_VECTOR key_vector_data=AcdbModuleTag.
    If type=CAL_KEY_VECTOR key_vector_data=AcdbGraphKeyVector */
    KeyVectorType key_vector_type;
    /**< Pointer to AcdbGraphKeyVector Calibration key Vector or AcdbModuleTag*/
    void* key_vector_data;
    /**< Size of the Map*/
    uint32_t map_size;
    /**< Number of subgraphs in the map*/
    uint32_t num_subgraphs;
    /**< List of AcdbDeltaSubgraphData*/
    LinkedList subgraph_data_list;
}acdb_delta_data_map_t;

typedef struct acdb_amdb_module_reg_info_t
{
    /**< Size of the module registration data */
    uint32_t data_size;
    /**< The the processor domain ID*/
    uint16_t interface_type;
    uint16_t interface_version;
    uint32_t module_type;
    uint32_t module_id;
    uint16_t file_name_length;
    uint16_t tag_length;
    uint32_t error_code;
    /**< The *.so file name and tag string data */
    //uint8_t data[0];

}acdb_amdb_module_reg_info_t;

typedef struct acdb_amdb_proc_reg_data_t
{
    /**< Size of the processor registration data */
    uint32_t data_size;
    /**< The ID of the processor domain that the
    AMDB modules will run under */
    uint32_t proc_id;
    /**< The number of custom modules under the processor.
    See acdb_amdb_module_reg_info_t */
    uint32_t module_count;
    /**< The version of the spf acdb_spf_amdb_module_reg_info_t. See
    amdb_module_registration_t in amdb_api.h*/
    uint32_t struct_version;
    /* All AMDB custom module data for the processor domain */
    acdb_amdb_module_reg_info_t *module_reg_data;
}acdb_amdb_proc_reg_data_t;

/**< The SPF AMDB module registration v1 structure */
typedef struct acdb_spf_amdb_module_reg_info_t
{
    uint16_t interface_type;
    uint16_t interface_version;
    uint32_t module_type;
    uint32_t module_id;
    uint16_t file_name_length;
    uint16_t tag_length;
    uint32_t error_code;
    /**< The *.so file name and tag string data */
    //uint8_t data[0];

}acdb_spf_amdb_module_reg_info_t;

/* Processor domain based AMDB module registration data.
See AMDB_CMD_REGISTER_MODULES in spf\amdb_api.h */
typedef struct acdb_spf_amdb_module_reg_t
{
    /**< The ID of the processor domain that the
    AMDB modules will run under */
    uint32_t proc_id;
    /**< The number of custom modules under the processor.
    See acdb_amdb_module_reg_info_t */
    uint32_t num_modules;
    /**< The version of the spf acdb_spf_amdb_module_reg_info_t. See
    amdb_module_registration_t in amdb_api.h*/
    uint32_t struct_version;
    acdb_spf_amdb_module_reg_info_t reg_info[0];
}acdb_spf_amdb_module_reg_t;

/* Processor domain based AMDB module de-registration data.
See AMDB_CMD_DEREGISTER_MODULES in spf\amdb_api.h */
typedef struct acdb_amdb_module_dereg_t
{
    /**< The ID of the processor domain that the
    AMDB modules will run under */
    uint32_t proc_id;
    /**< Number of modules being de-registered */
    uint32_t num_modules;
    /**< List of modules being de-registered */
    uint32_t module_id[0];
}acdb_amdb_module_dereg_t;

typedef struct acdb_amdb_bootup_proc_table_entry_t
{
    /**< The ID of the processor domain that the
    AMDB modules will run under */
    uint32_t proc_id;
    /**< Number of modules bootup modules */
    uint32_t num_modules;
    /**< List of bootup module IDs */
    uint32_t module_ids[0];
}acdb_amdb_bootup_proc_table_entry_t;

typedef struct acdb_amdb_bootup_module_t
{
    /**< ID of the module being loaded at boot */
    uint32_t module_id;
    /**< LSW of the Handle to the bootup module */
    uint32_t handle_lsw;
    /**< MSW of the Handle to the bootup module. */
    uint32_t handle_msw;
}acdb_amdb_bootup_module_t;

/* Processor domain based AMDB module bootup load/unload data.
See AMDB_CMD_LOAD_MODULES in spf\amdb_api.h */
typedef struct acdb_amdb_proc_bootup_data_t
{
    /**< The ID of the processor domain that the
    AMDB modules will run under */
    uint32_t proc_id;
    /**< Result of the module loading. For out-of-band payload
    this block will be directly updated. */
    uint32_t error_code;
    /**< Number of modules bootup modules */
    uint32_t num_modules;
    /**< List of module bootup loading/unload info */
    acdb_amdb_bootup_module_t load_unload_info[0];
}acdb_amdb_proc_bootup_data_t;

typedef struct _acdb_tag_def_offset_pair_list_t AcdbTagDefOffsetPairList;
struct _acdb_tag_def_offset_pair_list_t
{
    /**< Number of elemts in the list */
    uint32_t count;
    /**< Max number of elemts that this list can store */
    uint32_t max_count;
    /**< The size of an element. For example <uint a; uint b> is an element where the size is 8
     * bytes */
    uint32_t element_size;
    /**< Pointer to AcdbTagDefOffsetPair */
    AcdbTagDefOffsetPair* list;
};

typedef struct _acdb_proc_domain_offset_pair_t AcdbProcDomainOffsetPair;
struct _acdb_proc_domain_offset_pair_t
{
    /**< The processor domain id */
    uint32_t proc_domain_id;
    /**< An general purpose offset */
    uint32_t offset;
};

typedef struct _acdb_generic_list_item_t AcdbGenericListItem;
struct _acdb_generic_list_item_t
{
    /**< The index of an item in an AcdbGenericList instance  */
    uint32_t index;
    /**< A pointer to the item in AcdbGenericList::list */
    void* item;
};

/**
* \brief ACDB_GENERIC_LIST_ADD
*		Adds a range of elements to a generic list
* \param [in] list: pointer to a AcdbGenericList type
* \param [in] items: one or more items to add to the list
* \param [in] item_size: the size of one item
* \param [in] count: the number of items to add to the list
*/
typedef int32_t(*ACDB_GENERIC_LIST_ADD)(
    void* list, void* items, uint32_t item_size, uint32_t count);

/**
* \brief ACDB_GENERIC_LIST_FIND
*		Searches for an element in a AcdbGenericList
*       each
* \param [in] list: pointer to a AcdbGenericList type
* \param [in] item: the item to search for. The item must be
*                   4 bytes or more. If more then its size must be a
*                   multiple of 4. This is required by the binary search
*                   used in the find function. For example an item
*                   can be a structure with two 4 byte fields
* \param [in] item_size: the size of the item
* \param [in] num_search_keys: the number of 4 byte components to use
*                              for the search
* \param [out] found_item: the item found in the list containing the
*                          index and a pointer to the item
*/
typedef int32_t(*ACDB_GENERIC_LIST_FIND)(
    void* list, void* item, uint32_t item_size,
    uint32_t num_search_keys, AcdbGenericListItem* found_item);

/**
* \brief ACDB_GENERIC_LIST_FIND
*		Searches for an element in a AcdbGenericList
*       each
* \param [in] list: pointer to a AcdbGenericList type
* \param [in] key_elem_struct_position: the 4byte key to sort by. Specify the
*                                       position of the key within your structure. E.g
*           struct _some_struct{
*               int32_t a; position 0
*               int32_t b; position 1
*               int32_t c; position 2
*               }
*/
typedef int32_t(*ACDB_GENERIC_LIST_SORT)(
    void* list, uint32_t key_elem_struct_position);

/**< A list with an opaque pointer to store homogeneous elements of a particular size  */
typedef struct _acdb_generic_list_t AcdbGenericList;
struct _acdb_generic_list_t
{
    /**< Number of elemts in the list */
    uint32_t count;
    /**< Max number of elemts that this list can store */
    uint32_t max_count;
    /**< The size of an element. For example <uint a; uint b> is an element where the size is 8
     * bytes */
    uint32_t element_size;
    /**< Pointer to contiguous memory containing items of size element_size */
    void* list;
    /**< Pointer to a function that adds a range of elements to the list */
    ACDB_GENERIC_LIST_ADD add_range;
    ACDB_GENERIC_LIST_FIND find;
    ACDB_GENERIC_LIST_SORT sort;
};

#endif /*__ACDB_TYPES_H__*/
