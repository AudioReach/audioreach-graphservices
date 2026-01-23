#ifndef __ACDB_COMMAND_H__
#define __ACDB_COMMAND_H__
/**
*=============================================================================
* \file acdb_command.h
*
* \brief
*		Contains the definition of the commands exposed by the
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
#include "acdb.h"
#include "acdb_file_mgr.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_utility.h"

/* ---------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 *--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------
* Class Definitions
*--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Function Declarations and Documentation
 *--------------------------------------------------------------------------- */

int32_t AcdbCmdGetGraph(
    AcdbGraphKeyVector *gkv, AcdbGetGraphRsp *getGraphRsp,
    uint32_t rsp_struct_size);

int32_t AcdbCmdGetSubgraphData(
    AcdbSgIdGraphKeyVector *pInput,
    AcdbGetSubgraphDataRsp *pOutput);

int32_t AcdbCmdGetSubgraphConnections(
    AcdbSubGraphList* req, AcdbBlob* rsp);

int32_t AcdbCmdGetSubgraphCalDataNonPersist(
    AcdbSgIdCalKeyVector *pInput,
    AcdbBlob *pOutput, uint32_t rsp_struct_size);

int32_t AcdbCmdGetSubgraphCalDataPersist(
    AcdbSgIdCalKeyVector *pInput,
    AcdbSgIdPersistCalData *pOutput);

//int32_t AcdbCmdGetSubgraphGlbPersistIds(
//    AcdbSgIdCalKeyVector *pInput,
//    AcdbGlbPsistIdentifierList *pOutput, uint32_t rsp_struct_size);
//
//int32_t AcdbCmdGetSubgraphGlbPersistCalData(
//    AcdbGlbPersistCalDataCmdType *pInput, AcdbBlob *pOutput,
//    uint32_t rsp_struct_size);

int32_t AcdbCmdGetModuleTagData(
    AcdbSgIdModuleTag* sg_mod_tag, AcdbBlob* rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetTaggedModules(
    AcdbGetTaggedModulesReq* req,
    AcdbGetTaggedModulesRsp* rsp, uint32_t rsp_size);

int32_t AcdbCmdGetProcTaggedModules(
    AcdbGetProcTaggedModulesReq* req,
    AcdbGetProcTaggedModulesRsp* rsp, uint32_t rsp_size);

int32_t AcdbCmdGetDriverData(
    AcdbDriverData *driver_data, AcdbBlob* rsp,
    uint32_t rsp_size );

int32_t AcdbCmdSetCalData(
    AcdbSetCalDataReq *req);

int32_t AcdbCmdGetAmdbRegData(
    AcdbAmdbProcID *req, AcdbBlob* rsp);

int32_t AcdbCmdGetAmdbDeregData(
    AcdbAmdbProcID *req, AcdbBlob* rsp);

int32_t AcdbCmdGetSubgraphProcIds(
    AcdbCmdGetSubgraphProcIdsReq *req,
    AcdbCmdGetSubgraphProcIdsRsp* rsp, uint32_t rsp_size);

int32_t AcdbCmdGetAmdbBootupLoadModules(
    AcdbAmdbProcID *req, AcdbBlob* rsp);

int32_t AcdbCmdGetTagsFromGkv(
    AcdbCmdGetTagsFromGkvReq *req, AcdbCmdGetTagsFromGkvRsp* rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetGraphCalKeyVectors(
    AcdbGraphKeyVector *gkv, AcdbKeyVectorList *rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetSupportedGraphKeyVectors(
    AcdbUintList *key_id_list, AcdbKeyVectorList *rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetDriverModuleKeyVectors(
    uint32_t module_id, AcdbKeyVectorList *rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetGraphTagKeyVectors(
    AcdbGraphKeyVector *gkv, AcdbTagKeyVectorList *rsp,
    uint32_t rsp_size);

int32_t AcdbCmdGetCalData(
    AcdbGetCalDataReq *req, AcdbBlob *rsp);

int32_t AcdbCmdGetTagData(
    AcdbGetTagDataReq *req, AcdbBlob *rsp);

int32_t AcdbCmdSetTagData(AcdbSetTagDataReq *req);

int32_t AcdbCmdGetHwAccelInfo(
    AcdbHwAccelSubgraphInfoReq* req,
    AcdbHwAccelSubgraphInfoRsp* rsp);

int32_t AcdbCmdGetProcSubgraphCalDataPersist(
    AcdbProcSubgraphPersistCalReq* req,
    AcdbSgIdPersistCalData* rsp);

int32_t AcdbCmdGetAmdbRegDataV2(
    AcdbAmdbDbHandle* req, AcdbBlob* rsp);

int32_t AcdbCmdGetAmdbDeregDataV2(
    AcdbAmdbDbHandle* req, AcdbBlob* rsp);

int32_t AcdbCmdGetAmdbBootupLoadModulesV2(
    AcdbAmdbDbHandle* req, AcdbBlob* rsp);

int32_t AcdbCmdGetGraphAlias(
    AcdbGraphKeyVector *req, AcdbString *rsp);
/******************************************************************************
* Functions Only Used by ATS
*******************************************************************************
*/

int32_t AcdbGetParameterCalData(
    AcdbParameterCalData *req, AcdbBlob* rsp);

int32_t AcdbGetParameterTagData(
    AcdbParameterTagData *req, AcdbBlob* rsp);
#endif /* __ACDB_COMMAND_H__ */
