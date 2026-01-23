#ifndef _ATS_COMMAND_H_
#define _ATS_COMMAND_H_
/**
*==============================================================================
* \file ats_command.h
* \brief
*                  A T S  C M D  H E A D E R  F I L E
*
*     The ATS CMD header file defines functionality that process requests
*     from ATS clients and retrieves the response from ACDB.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include "acdb.h"
#include "acdb_file_mgr.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_utility.h"
#include "acdb_data_proc.h"
#include "ats_common.h"
#include "ats_i.h"

int32_t AtsCmdGetHostDatabaseFileSetInfo(AcdbFileManBlob *rsp);

int32_t AtsCmdGetAllDatabasesFileSetInfo(AcdbFileManBlob* rsp);

int32_t AtsCmdGetLoadedFileData(AcdbFileManGetFileDataReq *req, AcdbFileManBlob *rsp);

int32_t AtsCmdGetHeapEntryInfo(acdb_handle_t acdb_handle, AcdbBufferContext* rsp);

int32_t AtsCmdGetHeapEntryData(acdb_handle_t acdb_handle, AcdbGraphKeyVector* key_vector, AcdbBufferContext* rsp);

int32_t AtsCmdGetCalDataNonPersist(AtsGetSubgraphCalDataReq *req, AcdbBufferContext *rsp);

int32_t AtsCmdSetCalDataNonPersist(bool_t should_persist, AcdbGraphKeyVector* cal_key_vector,
    AcdbSubgraphParamData* subgraph_param_data);

int32_t AtsCmdGetCalDataPersist(AtsGetSubgraphCalDataReq *req, AcdbBufferContext *rsp);

int32_t AtsCmdSetCalDataPersist(bool_t should_persist, AcdbGraphKeyVector* cal_key_vector,
    AcdbSubgraphParamData* subgraph_param_data);

int32_t AtsCmdGetTagData(AtsGetSubgraphTagDataReq* req, AcdbBufferContext *rsp);

int32_t AtsCmdSetTagData(bool_t should_persist, AcdbModuleTag* module_tag,
    AcdbSubgraphParamData* subgraph_param_data);

int32_t AtsCmdDeleteDeltaFiles(void);

int32_t AtsCmdGetTempFilePath(uint32_t acdb_handle, AtsGetTempPath* path);
#endif /*_ATS_COMMAND_H_*/
