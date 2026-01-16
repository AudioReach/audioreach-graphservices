/**
*=============================================================================
* \file acdb.c
*
* \brief
*      Contains the implementation of the public interface to the Audio
*      Calibration Database (ACDB) module.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/
#include "ar_osal_error.h"
#include "ar_osal_file_io.h"
#include "ar_osal_mutex.h"
#include "acdb.h"
#include "acdb_file_mgr.h"
#include "acdb_delta_file_mgr.h"
#include "acdb_init.h"
#include "acdb_init_utility.h"
#include "acdb_command.h"
#include "acdb_common.h"
#include "acdb_utility.h"
#include "acdb_context_mgr.h"
#include "acdb_heap.h"

/* ---------------------------------------------------------------------------
* Global Data Definitions
*--------------------------------------------------------------------------- */

int32_t acdb_cmd_set_temp_path(AcdbSetTempPathReq *req);

/* ----------------------------------------------------------------------------
* Public Function Definitions
*--------------------------------------------------------------------------- */

int32_t acdb_init(AcdbDataFiles *acdb_data_files, AcdbFile* delta_file_path)
{
	int32_t status = AR_EOK;
	acdb_init_database_paths_t db_paths = { 0 };

	if (IsNull(acdb_data_files) || acdb_data_files->num_files == 0)
	{
		ACDB_ERR("Error[%d]: No database files were provided.", AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	db_paths.num_files = acdb_data_files->num_files;

	for (uint32_t i = 0; i < db_paths.num_files; i++)
	{
		db_paths.acdb_data_files[i].path_length =
			acdb_data_files->acdbFiles[i].fileNameLen;
		db_paths.acdb_data_files[i].path =
			&acdb_data_files->acdbFiles[i].fileName[0];
	}

	if (!IsNull(delta_file_path))
	{
		db_paths.writable_path.path_length = delta_file_path->fileNameLen;
		db_paths.writable_path.path = &delta_file_path->fileName[0];
	}

	status = acdb_init_ioctl(ACDB_INIT_CMD_INIT, NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Failed to initialize layers.", status);
		return status;
	}

	status = acdb_init_ioctl(ACDB_INIT_CMD_ADD_DATABASE,
		&db_paths, sizeof(acdb_init_database_paths_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to add files to database.", status);
		return status;
	}

	return status;
}
int32_t acdb_flash_init(uint32_t* acdbdata_base_addr)
{
	*acdbdata_base_addr = 0x0;
	int32_t status = AR_EOK;
	return status;
}

int32_t acdb_deinit()
{
	int32_t status = AR_EOK;

	status = acdb_init_ioctl(ACDB_INIT_CMD_RESET,
		NULL, 0, NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Failed to de-initialized ACDB SW", status);
		return status;
	}

	return status;
}
int32_t acdb_add_database(AcdbDatabaseFiles *acdb_data_files,
	AcdbFile *writable_path, acdb_handle_t *acdb_handle)
{
	int32_t status = AR_EOK;
	acdb_init_database_paths_t db_paths = { 0 };

	if (IsNull(acdb_data_files) || acdb_data_files->num_files == 0)
	{
		ACDB_ERR("Error[%d]: No database files were provided.", AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	db_paths.num_files = acdb_data_files->num_files;

	for (uint32_t i = 0; i < db_paths.num_files; i++)
	{
		db_paths.acdb_data_files[i].path_length =
			acdb_data_files->database_files[i].fileNameLen;
		db_paths.acdb_data_files[i].path =
			&acdb_data_files->database_files[i].fileName[0];
	}

	if (!IsNull(writable_path))
	{
		db_paths.writable_path.path_length = writable_path->fileNameLen;
		db_paths.writable_path.path = &writable_path->fileName[0];
	}

	status = acdb_init_ioctl(ACDB_INIT_CMD_ADD_DATABASE,
		&db_paths, sizeof(acdb_init_database_paths_t),
		acdb_handle, sizeof(acdb_handle_t));
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to add files to database.", status);
		return status;
	}

	return status;
}

int32_t acdb_remove_database(const acdb_handle_t *acdb_handle)
{
	int32_t status = AR_EOK;

	if (IsNull(acdb_handle))
	{
		ACDB_ERR("Error[%d]: The input parameter is null.", AR_EBADPARAM);
		return AR_EBADPARAM;;
	}

	status = acdb_init_ioctl(ACDB_INIT_CMD_REMOVE_DATABASE,
		(acdb_handle_t)acdb_handle, sizeof(acdb_handle_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to add files to database.", status);
		return status;
	}

	return status;
}

int32_t acdb_get_handle(AcdbFile *acdb_file, acdb_handle_t *acdb_handle)
{
	int32_t status = AR_EOK;
	uint32_t vm_id = 0;

	if (IsNull(acdb_file) || IsNull(acdb_handle))
	{
		return AR_EBADPARAM;
	}

	status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_VM_ID_FROM_FILE_NAME,
		acdb_file, sizeof(AcdbFile),
		&vm_id, sizeof(uint32_t));

	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_ACDB_CLIENT_HANDLE,
		&vm_id, sizeof(uint32_t), acdb_handle, sizeof(acdb_handle_t));

	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Unable to retrieve the database handle for %s",
			status, acdb_file->fileName);
	}

	return status;
}

int32_t acdbCmdIsPersistenceSupported(__UNUSED uint32_t *resp)
{
    __UNREFERENCED_PARAM(resp);
    /* This function should not be used. Use the acdb_iotcl with
     * the ACDB_CMD_ENABLE_PERSISTENCE command*/
	return AR_ENOTIMPL;
}

int32_t acdb_ioctl(uint32_t cmd_id,
	const void *cmd_struct,
	uint32_t cmd_struct_size,
	void *rsp_struct,
	uint32_t rsp_struct_size)
{
	int32_t status = AR_EOK;

	ACDB_PKT_LOG_DATA("ACDB_IOCTL_CMD_ID", &cmd_id, sizeof(cmd_id));

	ACDB_MUTEX_LOCK(ACDB_CTX_MAN_CLIENT_CMD_LOCK);

	switch (cmd_id) {
	case ACDB_CMD_GET_GRAPH:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGraphKeyVector) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbGraphKeyVector *req = (AcdbGraphKeyVector *)cmd_struct;
			AcdbGetGraphRsp *rsp = (AcdbGetGraphRsp *)rsp_struct;

			if (req->num_keys == 0 || req->num_keys >= ACDB_MAX_KEY_COUNT)
			{
				status = AR_EBADPARAM;
			}
			else
				status = AcdbCmdGetGraph(req, rsp, rsp_struct_size);
		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_DATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSgIdGraphKeyVector) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSgIdGraphKeyVector *req = (AcdbSgIdGraphKeyVector*)cmd_struct;
			AcdbGetSubgraphDataRsp *rsp = (AcdbGetSubgraphDataRsp*)rsp_struct;
			if (req->sg_ids == NULL ||
				req->graph_key_vector.graph_key_vector == NULL ||
				req->graph_key_vector.num_keys >= ACDB_MAX_KEY_COUNT)
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetSubgraphData(req, rsp);
			}
		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_CONNECTIONS:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSubGraphList) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSubGraphList *req = (AcdbSubGraphList*)cmd_struct;
			AcdbBlob *rsp = (AcdbBlob*)rsp_struct;
			if ((req->num_subgraphs == 0) || (req->subgraphs == NULL))
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetSubgraphConnections(req, rsp);
			}
		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_CALIBRATION_DATA_NONPERSIST:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSgIdCalKeyVector) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSgIdCalKeyVector *req = (AcdbSgIdCalKeyVector*)cmd_struct;
			AcdbBlob *rsp = (AcdbBlob*)rsp_struct;
			if ((req->num_sg_ids == 0) || (req->sg_ids == NULL))
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetSubgraphCalDataNonPersist(req, rsp, rsp_struct_size);
			}
		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_CALIBRATION_DATA_PERSIST:
		if (IsNull(cmd_struct) ||
			cmd_struct_size != sizeof(AcdbSgIdCalKeyVector) ||
			IsNull(rsp_struct) ||
			rsp_struct_size != sizeof(AcdbSgIdPersistCalData))
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSgIdCalKeyVector *req = (AcdbSgIdCalKeyVector*)cmd_struct;
			AcdbSgIdPersistCalData *rsp = (AcdbSgIdPersistCalData*)rsp_struct;
			if ((req->num_sg_ids == 0) || (req->sg_ids == NULL))
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetSubgraphCalDataPersist(req, rsp);
			}
		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_IDENTIFIERS:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSgIdCalKeyVector) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			//todo: Commenting out to suppress warnings. Uncomment when this api is supported
			// AcdbSgIdCalKeyVector *req = (AcdbSgIdCalKeyVector*)cmd_struct;
			// AcdbGlbPsistIdentifierList  *rsp = (AcdbGlbPsistIdentifierList*)rsp_struct;
			// if ((req->num_sg_ids == 0) || (req->sg_ids == NULL))
			// {
			// 	status = AR_EBADPARAM;
			// }
			// else
			// {
			// 	status = AcdbCmdGetSubgraphGlbPersistIds(req, rsp, rsp_struct_size);
			// }

			status = AR_ENOTEXIST;

		}
		break;
	case ACDB_CMD_GET_SUBGRAPH_GLB_PSIST_CALDATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGlbPersistCalDataCmdType) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			//todo: Commenting out to suppress warnings. Uncomment when this api is supported
			// AcdbGlbPersistCalDataCmdType *req = (AcdbGlbPersistCalDataCmdType*)cmd_struct;
			// AcdbBlob  *rsp = (AcdbBlob*)rsp_struct;
			// if (req->cal_Id == 0)
			// {
			// 	status = AR_EBADPARAM;
			// }
			// else
			// {
			// 	status = AcdbCmdGetSubgraphGlbPersistCalData(req, rsp, rsp_struct_size);
			// }

			status = AR_ENOTEXIST;

		}
		break;
	case ACDB_CMD_GET_MODULE_TAG_DATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSgIdModuleTag) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSgIdModuleTag *req = (AcdbSgIdModuleTag*)cmd_struct;
			AcdbBlob  *rsp = (AcdbBlob*)rsp_struct;
		    status = AcdbCmdGetModuleTagData(req, rsp, rsp_struct_size);

		}
		break;
	case ACDB_CMD_GET_TAGGED_MODULES:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGetTaggedModulesReq) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbGetTaggedModulesReq *req = (AcdbGetTaggedModulesReq*)cmd_struct;
			AcdbGetTaggedModulesRsp  *rsp = (AcdbGetTaggedModulesRsp*)rsp_struct;
		    status = AcdbCmdGetTaggedModules(req, rsp, rsp_struct_size);
		}
		break;
	case ACDB_CMD_GET_PROC_TAGGED_MODULES:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGetProcTaggedModulesReq) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbGetProcTaggedModulesReq* req = (AcdbGetProcTaggedModulesReq*)cmd_struct;
			AcdbGetProcTaggedModulesRsp* rsp = (AcdbGetProcTaggedModulesRsp*)rsp_struct;
			status = AcdbCmdGetProcTaggedModules(req, rsp, rsp_struct_size);
		}
		break;
	case ACDB_CMD_GET_DRIVER_DATA:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbDriverData) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbDriverData *req = (AcdbDriverData*)cmd_struct;
            AcdbBlob  *rsp = (AcdbBlob*)rsp_struct;

            status = AcdbCmdGetDriverData(req, rsp, rsp_struct_size);
        }
		break;
	case ACDB_CMD_SET_CAL_DATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSetCalDataReq))
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbSetCalDataReq *req = (AcdbSetCalDataReq*)cmd_struct;
			status = AcdbCmdSetCalData(req);
		}
		break;
	case ACDB_CMD_ENABLE_PERSISTANCE:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(uint8_t))
		{
			status = AR_EBADPARAM;
		}
		else
		{
			uint8_t *req = (uint8_t*)cmd_struct;
            AcdbDeltaPersistState state = *req == 1 ?
                ACDB_DELTA_DATA_PERSIST_STATE_ENABLED :
                ACDB_DELTA_DATA_PERSIST_STATE_DISABLED;

            status = acdb_delta_data_ioctl(
                ACDB_DELTA_DATA_CMD_ENABLE_PERSISTENCE,
                &state, sizeof(AcdbDeltaPersistState), NULL, 0);
		}
		break;
	case ACDB_CMD_GET_AMDB_REGISTRATION_DATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbProcID) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbRegData(
			(AcdbAmdbProcID*)cmd_struct, (AcdbBlob*)rsp_struct);
		break;
	case ACDB_CMD_GET_AMDB_DEREGISTRATION_DATA:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbProcID) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbDeregData(
			(AcdbAmdbProcID*)cmd_struct, (AcdbBlob*)rsp_struct);
		break;
	case ACDB_CMD_GET_SUBGRAPH_PROCIDS:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbCmdGetSubgraphProcIdsReq) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbCmdGetSubgraphProcIdsReq *req =
				(AcdbCmdGetSubgraphProcIdsReq*)cmd_struct;
			AcdbCmdGetSubgraphProcIdsRsp *rsp =
				(AcdbCmdGetSubgraphProcIdsRsp*)rsp_struct;
			if (req->num_sg_ids == 0)
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetSubgraphProcIds(req, rsp, rsp_struct_size);
			}
		}
		break;
	case ACDB_CMD_GET_AMDB_BOOTUP_LOAD_MODULES:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbProcID) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbBootupLoadModules(
			(AcdbAmdbProcID*)cmd_struct, (AcdbBlob*)rsp_struct);

		break;
	case ACDB_CMD_GET_TAGS_FROM_GKV:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbCmdGetTagsFromGkvReq) ||
			IsNull(rsp_struct) || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbCmdGetTagsFromGkvReq *req = (AcdbCmdGetTagsFromGkvReq*)cmd_struct;
			AcdbCmdGetTagsFromGkvRsp *rsp = (AcdbCmdGetTagsFromGkvRsp*)rsp_struct;
			if (req->graph_key_vector->num_keys == 0 ||
				req->graph_key_vector->num_keys >= ACDB_MAX_KEY_COUNT)
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetTagsFromGkv(req, rsp, rsp_struct_size);
			}
		}
		break;
    case ACDB_CMD_GET_GRAPH_CAL_KVS:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGraphKeyVector) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbGraphKeyVector *req = (AcdbGraphKeyVector*)cmd_struct;
            AcdbKeyVectorList *rsp = (AcdbKeyVectorList*)rsp_struct;
            if (req->num_keys == 0 || req->num_keys >= ACDB_MAX_KEY_COUNT)
            {
                status = AR_EBADPARAM;
            }
            else
            {
                status = AcdbCmdGetGraphCalKeyVectors(
                    req, rsp, rsp_struct_size);
            }
        }
        break;
    case ACDB_CMD_GET_SUPPORTED_GKVS:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbUintList) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbUintList *req = (AcdbUintList*)cmd_struct;
            AcdbKeyVectorList *rsp = (AcdbKeyVectorList*)rsp_struct;

            status = AcdbCmdGetSupportedGraphKeyVectors(
                req, rsp, rsp_struct_size);
        }
        break;
    case ACDB_CMD_GET_DRIVER_MODULE_KVS:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(uint32_t) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            uint32_t *req = (uint32_t*)cmd_struct;
            AcdbKeyVectorList *rsp = (AcdbKeyVectorList*)rsp_struct;

            status = AcdbCmdGetDriverModuleKeyVectors(
                *req, rsp, rsp_struct_size);
        }
        break;
    case ACDB_CMD_GET_GRAPH_TAG_KVS:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGraphKeyVector) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbGraphKeyVector *req = (AcdbGraphKeyVector*)cmd_struct;
            AcdbTagKeyVectorList *rsp = (AcdbTagKeyVectorList*)rsp_struct;
            if (req->num_keys == 0 || req->num_keys >= ACDB_MAX_KEY_COUNT)
            {
                status = AR_EBADPARAM;
            }
            else
            {
                status = AcdbCmdGetGraphTagKeyVectors(
                    req, rsp, rsp_struct_size);
            }
        }
        break;
    case ACDB_CMD_GET_CAL_DATA:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGetCalDataReq) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbGetCalDataReq *req = (AcdbGetCalDataReq*)cmd_struct;
            AcdbBlob *rsp = (AcdbBlob*)rsp_struct;
            status = AcdbCmdGetCalData(req, rsp);
        }
        break;
    case ACDB_CMD_GET_TAG_DATA:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbGetTagDataReq) ||
            IsNull(rsp_struct) || rsp_struct_size == 0)
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbGetTagDataReq *req = (AcdbGetTagDataReq*)cmd_struct;
            AcdbBlob *rsp = (AcdbBlob*)rsp_struct;
            status = AcdbCmdGetTagData(req, rsp);
        }
        break;
    case ACDB_CMD_SET_TAG_DATA:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSetTagDataReq))
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbSetTagDataReq *req = (AcdbSetTagDataReq*)cmd_struct;
            status = AcdbCmdSetTagData(req);
        }
        break;
    case ACDB_CMD_SET_TEMP_PATH:
        if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbSetTempPathReq))
        {
            status = AR_EBADPARAM;
        }
        else
        {
            AcdbSetTempPathReq *req = (AcdbSetTempPathReq*)cmd_struct;
            status = acdb_cmd_set_temp_path(req);
        }
        break;
	case ACDB_CMD_GET_HW_ACCEL_SUBGRAPH_INFO:
		if (IsNull(cmd_struct) ||
			cmd_struct_size != sizeof(AcdbHwAccelSubgraphInfoReq) ||
			IsNull(rsp_struct) ||
			rsp_struct_size != sizeof(AcdbHwAccelSubgraphInfoRsp))
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbHwAccelSubgraphInfoReq* req =
				(AcdbHwAccelSubgraphInfoReq*)cmd_struct;
			AcdbHwAccelSubgraphInfoRsp* rsp =
				(AcdbHwAccelSubgraphInfoRsp*)rsp_struct;
			status = AcdbCmdGetHwAccelInfo(req, rsp);
		}
		break;
	case ACDB_CMD_GET_PROC_SUBGRAPH_CAL_DATA_PERSIST:
		if (IsNull(cmd_struct)  ||
			cmd_struct_size != sizeof(AcdbProcSubgraphPersistCalReq) ||
			IsNull(rsp_struct) ||
			rsp_struct_size != sizeof(AcdbSgIdPersistCalData))
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbProcSubgraphPersistCalReq* req =
				(AcdbProcSubgraphPersistCalReq*)cmd_struct;
			AcdbSgIdPersistCalData* rsp =
				(AcdbSgIdPersistCalData*)rsp_struct;
			if (req->num_subgraphs == 0)
			{
				status = AR_EBADPARAM;
			}
			else
			{
				status = AcdbCmdGetProcSubgraphCalDataPersist(req, rsp);
			}
		}
		break;
	case ACDB_CMD_GET_AMDB_REGISTRATION_DATA_V2:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbDbHandle) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbRegDataV2(
			(AcdbAmdbDbHandle*)cmd_struct, (AcdbBlob*)rsp_struct);
		break;
	case ACDB_CMD_GET_AMDB_DEREGISTRATION_DATA_V2:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbDbHandle) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbDeregDataV2(
			(AcdbAmdbDbHandle*)cmd_struct, (AcdbBlob*)rsp_struct);
		break;
	case ACDB_CMD_GET_AMDB_BOOTUP_LOAD_MODULES_V2:
		if (IsNull(cmd_struct) || cmd_struct_size != sizeof(AcdbAmdbDbHandle) ||
			IsNull(rsp_struct) || rsp_struct_size != sizeof(AcdbBlob))
		{
			status = AR_EBADPARAM;
		}

		status = AcdbCmdGetAmdbBootupLoadModulesV2(
			(AcdbAmdbDbHandle*)cmd_struct, (AcdbBlob*)rsp_struct);

		break;
	case ACDB_CMD_GET_GRAPH_ALIAS:
		if (cmd_struct == NULL || cmd_struct_size != sizeof(AcdbGraphKeyVector) ||
			rsp_struct == NULL || rsp_struct_size == 0)
		{
			status = AR_EBADPARAM;
		}
		else
		{
			AcdbGraphKeyVector* req = (AcdbGraphKeyVector*)cmd_struct;
			AcdbString* rsp = (AcdbString*)rsp_struct;

			if (req->num_keys == 0 || req->num_keys >= ACDB_MAX_KEY_COUNT)
			{
				status = AR_EBADPARAM;
			}
			else
				status = AcdbCmdGetGraphAlias(req, rsp);
		}
		break;
	default:
		status = AR_ENOTEXIST;
		ACDB_ERR("Error[%d]: Received unsupported command request"
            " with Command ID[%08X]", cmd_id);
		break;
	}

	ACDB_MUTEX_UNLOCK(ACDB_CTX_MAN_CLIENT_CMD_LOCK);

	return status;
}

/* ----------------------------------------------------------------------------
* Private Function Definitions
*--------------------------------------------------------------------------- */

int32_t acdb_cmd_set_temp_path(AcdbSetTempPathReq *req)
{
    int32_t status = AR_EOK;
    bool_t rw_delta_exists = FALSE;
	uint32_t findex = 0;
	uint32_t host_db_index = 0;
    acdb_context_handle_t *ctx_handle = NULL;
    AcdbDeltaDataSwapInfo swap_finfo = { 0 };
    /**< read-only directory */
	acdb_file_man_writable_path_info_256_t ro_dir = { 0 };
	acdb_handle_t acdb_handle = NULL;

    if (IsNull(req))
    {
        return AR_EBADPARAM;
    }

    if (req->path_length == 0)
    {
        ACDB_ERR("Error[%d]: The directory path length is zero ",
            AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (req->path_length > ACDB_MAX_PATH_LENGTH)
    {
        ACDB_ERR("Error[%d]: The directory path length %d "
            "is greater than the max path length %d",
            AR_EBADPARAM, req->path_length, ACDB_MAX_PATH_LENGTH);
        return AR_EBADPARAM;
    }

    swap_finfo.file_access = AR_FOPEN_READ_ONLY_WRITE;
    swap_finfo.path_info.path_len = req->path_length;

    status = ar_strcpy(
        &swap_finfo.path_info.path[0], ACDB_MAX_PATH_LENGTH,
        &req->path[0], ACDB_MAX_PATH_LENGTH);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to copy writeable path", status);
        return status;
    }

	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE_USING_INDEX,
		&host_db_index, sizeof(uint32_t),
		&ctx_handle, sizeof(acdb_context_handle_t));
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Failed to get context handle", status);
		return status;
	}

	acdb_handle = ACDB_UINT_TO_HANDLE(ctx_handle->vm_id);
	status = acdb_ctx_man_ioctl(ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
		&acdb_handle, sizeof(acdb_handle_t), NULL, 0);
	if (AR_FAILED(status))
	{
		ACDB_ERR("Error[%d]: Failed to set context handle", status);
		return status;
	}

    /* Get read-only path */
	ro_dir.handle = ctx_handle->file_manager_handle;

	status = acdb_file_man_ioctl(ACDB_FILE_MAN_GET_WRITABLE_PATH,
		&ro_dir, sizeof(acdb_file_man_writable_path_info_256_t),
		NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to get readonly path", status);
        return status;
    }

    /* Set the read/write path which will serve as the new temp directory */
	acdb_file_man_writable_path_info_t a = {0};
	a.handle = ctx_handle->file_manager_handle;
	a.writable_path.path_length = swap_finfo.path_info.path_len;
	a.writable_path.path = &swap_finfo.path_info.path[0];

    status = acdb_file_man_ioctl(ACDB_FILE_MAN_SET_WRITABLE_PATH,
        &a, sizeof(acdb_file_man_writable_path_info_t), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Unable to set writable path", status);
        return status;
    }

	findex = host_db_index;
    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_IS_FILE_AT_PATH,
        &swap_finfo, sizeof(AcdbDeltaDataSwapInfo),
        NULL, 0);
    if (AR_ENOTEXIST == status)
    {
        rw_delta_exists = FALSE;
    }
    else if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: An error occured while trying to verify"
            " the existance of the following path %s", status,
            &swap_finfo.path_info.path[0]);
        return status;
    }
    else
    {
        rw_delta_exists = TRUE;
    }

    if (rw_delta_exists)
    {
		/* Scenario 2
		* Both the ro and rw files exist. Load the ro delta first followed
		* by the rw delta. Do not reload ro_delta since the rw_delta will
		* already contain the latest changes.
		* This scenario will occur if:
		*	1. the device is rebooted and
		*	2. the rw delta file still exists on target
		*	3. this api is called again
        *
        * The ro_delta is already loaded during init. Load the rw_delta */

            swap_finfo.file_access = AR_FOPEN_READ_ONLY_WRITE;
            swap_finfo.file_index = findex;

        /* Swap the ro_delta for the rw_delta in the delta file manager */
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SWAP_DELTA,
            &swap_finfo, sizeof(AcdbDeltaDataSwapInfo), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to swap read-only "
                "with read/write delta file", status);
            return status;
        }

        /* load the rw_delta onto the heap */
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_UPDATE_HEAP,
			ctx_handle, sizeof(acdb_context_handle_t), NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to update heap with "
                "data from the read/write delta", status);
            return status;
        }
		return status;
    }

    /* Scenario 1
	* This scenario occurs when:
    *   1. AML is already initialized.
    *   2. The ro_delta is already loaded onto the heap and its possible
	*	   that other data has already been set to the heap by QACT or
	*	   a GSL client through the set cal data APIs
    *   3. The rw_delta does not exist
	* Steps
    *	1. Get the temp path that is set during acdb_init. This is the
	*	   ro_delta path that we need to remember
    *	2. Update the delta file manager with the rw_delta directory as
	*      the new delta file path (this will replace the ro_delta file
	*      info in the delta file manager)
    *	3. Save heap to the rw_delta file
    *	4. Update the delta file manager with the ro_delta file path to
	*      load the ro_delta file contents
    *	5. Load the ro_delta to the heap
    *	6. Again, Update the delta file manager with the rw_delta
	*      directory as the new delta file path
    *	7. Load the rw_delta on top
    *
    * After all these steps, the location of the ro_delta is forgoten.
    */
    swap_finfo.file_access = AR_FOPEN_WRITE_ONLY;
    swap_finfo.file_index = findex;

    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SWAP_DELTA,
        &swap_finfo, sizeof(AcdbDeltaDataSwapInfo), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to swap read-only "
            "with read/write delta file", status);
        return status;
    }

        /* Save the heap to the rw_delta file */
        status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SAVE,
            NULL, 0, NULL, 0);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to save delta file", status);
        }

    /* Update the delta file manager with the ro_delta file
	* path to load the ro_delta file contents */
    swap_finfo.file_access = AR_FOPEN_READ_ONLY;
    swap_finfo.file_index = findex;
    swap_finfo.path_info.path_len = ro_dir.writable_path.path_len;
    status = ar_strcpy(
        swap_finfo.path_info.path, ACDB_MAX_PATH_LENGTH,
        &ro_dir.writable_path.path[0], ACDB_MAX_PATH_LENGTH);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to copy read-only path string",
            status);
        return status;
    }

    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SWAP_DELTA,
        &swap_finfo, sizeof(AcdbDeltaDataSwapInfo), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to swap read/write "
            "with read-only delta file", status);
        return status;
    }

    /* Load the ro_delta to the heap */
    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_INIT_HEAP,
		ctx_handle, sizeof(acdb_context_handle_t), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to save delta file", status);
    }

    /* Again, Update the delta file manager with the rw_delta
	* directory as the new delta file path */
    swap_finfo.file_access = AR_FOPEN_READ_ONLY_WRITE;
    swap_finfo.file_index = findex;
    swap_finfo.path_info.path_len = req->path_length;
    status = ar_strcpy(
        &swap_finfo.path_info.path[0], ACDB_MAX_PATH_LENGTH,
        &req->path[0], ACDB_MAX_PATH_LENGTH);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to copy read-only path string",
            status);
        return status;
    }

    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_SWAP_DELTA,
        &swap_finfo, sizeof(AcdbDeltaDataSwapInfo), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to swap read/write "
            "with read-only delta file", status);
        return status;
    }

    /* load the rw_delta on top */
    status = acdb_delta_data_ioctl(ACDB_DELTA_DATA_CMD_UPDATE_HEAP,
		ctx_handle, sizeof(acdb_context_handle_t), NULL, 0);
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to update heap with delta data", status);
    }

    return status;
}
