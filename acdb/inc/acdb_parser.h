#ifndef __ACDB_PARSER_H__
#define __ACDB_PARSER_H__
/**
*=============================================================================
* \file acdb_parser.h
*
* \brief
*		Handle parsing the ACDB Data files.
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
#include "ar_osal_types.h"
#include "ar_osal_file_io.h"
#include "acdb_types.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */

#define ACDB_PARSE_COMPRESSED 1
#define ACDB_PARSE_SUCCESS 0
#define ACDB_PARSE_FAILURE -1
#define ACDB_PARSE_CHUNK_NOT_FOUND -2
#define ACDB_PARSE_INVALID_FILE -3

/******************************************************************************
* File Chunks
******************************************************************************/

/*
#define ACDB 0x42444341
#define HEAD 0x44414548
*/

#define ACDB_CHUNKID_HEAD                       0x44414548 //HEAD

//Graph Key Vector
#define ACDB_CHUNKID_GKVKEYTBL                  0x54564b47 //GKVT
#define ACDB_CHUNKID_GKVLUTTBL                  0x4c564b47 //GKVL
#define ACDB_CHUNKID_GKV_ALIAS                  0x534c4147 //GALS

//Subgraph Connections
#define ACDB_CHUNKID_SGCONNLUT                  0x554c4353 //SCLU
#define ACDB_CHUNKID_SGCONNDEF                  0x45444353 //SCDE
#define ACDB_CHUNKID_SGCONNDOT                  0x4f444353 //SCDO

//Subgraph Calibration
#define ACDB_CHUNKID_CALSGLUT                   0x554c5343 //CSLU
#define ACDB_CHUNKID_CALKEYTBL                  0x544b4143 //CAKT
#define ACDB_CHUNKID_CALDATALUT                 0x554c4443 //CDLU
#define ACDB_CHUNKID_CALDATADEF                 0x45444443 //CDDE
#define ACDB_CHUNKID_CALDATADOT                 0x4f444443 //CDD0
#define ACDB_CHUNKID_CALDATADEF2                0x32444443 //CDD2

//PID Persistance
#define ACDB_CHUNKID_PIDPERSIST                 0x43545050 //PPTC
#define ACDB_CHUNKID_GLB_PID_PERSIST_MAP        0x4750504d //GPPM (Global PID Persist Map)

//Datapool
#define ACDB_CHUNKID_DATAPOOL                   0x4c4f4f50 //POOL

//Module Tag Data
#define ACDB_CHUNKID_MODULE_TAGDATA_KEYTABLE    0x544b544d //MTKT
#define ACDB_CHUNKID_MODULE_TAG_KEY_LIST_LUT    0x4c4b544d //MTKL
#define ACDB_CHUNKID_MODULE_TAGDATA_LUT         0x554c544d //MTLU
#define ACDB_CHUNKID_MODULE_TAGDATA_DEF         0x4544544d //MTDE
#define ACDB_CHUNKID_MODULE_TAGDATA_DOT         0x4f44544d //MTDO

//Tagged Modules
#define ACDB_CHUNKID_TAGGED_MODULE_LUT          0x554c4d54 //TMLU
#define ACDB_CHUNKID_TAGGED_MODULE_DEF          0x45444d54 //TMDE
#define ACDB_CHUNKID_TAGGED_MODULE_MAP          0x204c544d

//GSL Calibration Data
#define ACDB_CHUNKID_GSL_CAL_LUT                0x554c4347 //GCLU
#define ACDB_CHUNKID_GSL_CALKEY_TBL             0x544b4347 //GCKT
#define ACDB_CHUNKID_GSL_CALDATA_TBL            0x54444347 //GCDT
#define ACDB_CHUNKID_GSL_DEF                    0x45444347 //GCDE
#define ACDB_CHUNKID_GSL_DOT                    0x4f444347 //GCDO

//Subgraph Module Map
#define ACDB_CHUNKID_SG_IID_MAP                 0x54494753 //SGIT

//AMDB
#define ACDB_CHUNKID_AMDB_REG_DATA              0x4D444F4D //MODM
#define ACDB_CHUNKID_BOOTUP_LOAD_MODULES        0x50555442 //BTUP

//VCPM
#define ACDB_CHUNKID_VCPM_CAL_DATA              0x44434356  //VCCD
#define ACDB_CHUNKID_VCPM_MASTER_KEY            0x4b4d4356  //VCMK
#define ACDB_CHUNKID_VCPM_CALKEY_TABLE          0x544b4356  //VCKT
#define ACDB_CHUNKID_VCPM_CALDATA_LUT           0x554c4356  //VCLU
#define ACDB_CHUNKID_VCPM_CALDATA_DEF           0x45444356  //VCDE

//Hardware Accel Subgraph Info
#define ACDB_CHUNKID_HW_ACCEL_SUBGRAPH_INFO     0x49534148  //HASI

//Global Properties
#define ACDB_CHUNKID_GLOBAL_PROP                0x4f525047 //GPRO


/******************************************************************************
* Global Properties
******************************************************************************/

typedef enum AcdbGlobalProperty
{
    /**<
    * This property maintains a list of uint32_t parameters IDs. Offloaded
    * parameters are parameters that are stored in a file separate from the
    * *.acdb file. The ABNF format of the property is:
    *
    *      Property    = EntryCount ParamID+
    *
    *      DWORDs: EntryCount, ParamID
    */
    ACDB_GPROP_OFFLOADED_PARAM_INFO = 0x000133B7,

    /**< Property ID: HWAC (0x43415748)
    * This property maintains hardware acceleration info for subgraphs that
    * contains hw accel parameter data. The ABNF format of the property is:
    *
    *      Property = NumSubgraphs HwAccelSubgraph+
    *      HwAccelSubgraph = SubgraphID ProccesorID HwAccelModuleParamListOffset
    *      HwAccelModuleParamList = NumModules HwAccelModuleParam+
    *      HwAccelModuleParam = ModuleInstanceID ParameterID
    *
    *      DWORDs: NumSubgraphs, SubgraphID, ProccesorID,
    *              HwAccelModuleParamListOffset, NumModules,
    *              ModuleInstanceID, ParameterID
    */
    ACDB_GPROP_HW_ACCEL_SUBGRAPH_INFO = 0x43415748,

    /**< Property ID: IMSS
    * This property contains the subgraph data GUID for imported
    * shared subgraphs.
    *
    *      Property = NumSubgraphs SubgraphGuidEntry+
    *      SubgraphGuidEntry = SubgraphID Guid
    *
    *      DWORDs: NumSubgraphs, SubgraphID
    */
    ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS = 0x53534D49,

    /**< Property ID: EXSS
    * This property contains the subgraph data GUID for exported
    * shared subgraphs.
    *
    *      Property = NumSubgraphs SubgraphGuidEntry+
    *      SubgraphGuidEntry = SubgraphID Guid
    *
    *      DWORDs: NumSubgraphs, SubgraphID
    */
    ACDB_GPROP_EXPORTED_SHARED_SUBGRAPHS = 0x53535845,

    /**< Property ID: SGIR
    * This property contains the subgraph id range [min, max]
    *
    *      Property = SubgraphIdMin SubgraphIdMax
    *
    *      DWORDs: SubgraphIdMin, SubgraphIdMax
    */
    ACDB_GPROP_SUBGRAPH_ID_RANGE = 0x52494753,

    /**< Property ID: VMID
    * The Virtual Machine ID used by the database. This is
    * mainly used by automotive clients.
    *
    *      Property = VMID
    *
    *      DWORDs: VMID
    */
    ACDB_GPROP_VIRTUAL_MACHINE_ID = 0X44494D56,
}AcdbGlobalProperty;

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4200)
#endif

typedef struct acdb_file_version_t
{
    /**< The file major version */
    uint8_t major;
    /**< The file minor version */
    uint8_t minor;
    /**< The file revision number */
    uint8_t revision;
    /**< The cpl version */
    uint8_t cpl_info;
}acdb_file_version_t;

typedef struct acdb_codec_t
{
    /**< The codec id */
    uint32_t codec_id;
    /**< The codec major version */
    uint32_t major;
    /**< The codec minor version */
    uint32_t minor;
}acdb_codec_t;

typedef struct acdb_codec_info_t
{
    /**< The number of codecs */
    uint32_t num_codecs;
    /**< List of codecs used in the database */
    acdb_codec_t codecs[0];
}acdb_codec_info_t;

typedef struct acdb_oem_info_t
{
    /**< The character length of the description */
    uint32_t legnth;
    /**< An OEM description limited to 255 characters */
    char_t description[0];
}acdb_oem_info_t;

/**< Version 1 of the ACDB Header Chunk */
typedef struct acdb_header_v1_t
{
    /**< The version of the header */
    uint32_t header_version;
    /**< The version of the file */
    acdb_file_version_t file_version;
    /**< Codec ID and Version information used in the file */
    acdb_codec_info_t* codec_info;
    /**< A timestamp of when the file was last modified */
    uint32_t date_modified;
    /**< OEM specific information */
    acdb_oem_info_t* oem_info;
}acdb_header_v1_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif
/* ---------------------------------------------------------------------------
* Function Declarations and Documentation
*--------------------------------------------------------------------------- */

int32_t acdb_parser_get_chunk(
    void* file_buffer, uint32_t buffer_length,
    uint32_t chunk_id, uint32_t *chunk_offset, uint32_t *chunk_size);

int32_t acdb_parser_validate_file(acdb_buffer_t* in_mem_file);

int32_t acdb_parser_get_acdb_header_v1(
    acdb_buffer_t* in_mem_file, acdb_header_v1_t* header);

#endif /* __ACDB_PARSER_H__ */
