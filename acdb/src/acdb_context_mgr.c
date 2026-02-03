/**
*=============================================================================
* \file acdb_contet_mgr.c
*
* \brief
*      The handle manager that maintains handles to different aml layers
*      such as the file manager, delta file manager, and delta data heap
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/
#include "ar_osal_error.h"
#include "acdb_context_mgr.h"
#include "acdb_parser.h"
#include "acdb_data_proc.h"
#include "acdb_utility.h"

/* ---------------------------------------------------------------------------
* Macros
*--------------------------------------------------------------------------- */

#define ACDB_MAX_ACDB_FILES 16

#define ACDB_BIT_SET(value, bit) (value &= ~(1 << bit))
#define ACDB_BIT_UNSET(value, bit) (value |= ~(0xFFFFFFFE << bit))
#define ACDB_SUBGRAPH_TO_VM_ID(sg_id) ((sg_id & 0x0F000000) >> 24)

/* ---------------------------------------------------------------------------
* Types
*--------------------------------------------------------------------------- */

typedef struct _acdb_man_context_t AcdbCtxManContext;
struct _acdb_man_context_t
{
    ar_osal_mutex_t acdb_client_lock;
    ar_osal_mutex_t ctx_man_lock;
    /**< a bit field representing the available file slots.
    0 = taken, 1 = open */
    //uint32_t active_db_slots;
    /**< The index of the database that the filemanager is
    currently pointing to */
    acdb_context_handle_t *active_db;
    /**< Current Number of databases being managed */
    uint32_t database_count;
    /**< Maintains handle info about each loaded database */
    acdb_context_handle_t *database_info[ACDB_MAX_ACDB_FILES];
};

typedef struct acdb_man_subgraph_location_t acdb_man_subgraph_location_t;
struct acdb_man_subgraph_location_t
{
    uint32_t subgraph_id;
    acdb_context_handle_t* handle;
};

/* ---------------------------------------------------------------------------
* Global Variables
*--------------------------------------------------------------------------- */

static AcdbCtxManContext acdb_ctx_man_context;

/**< NOTE: In the case where setting the active handle for a list of subgraphs
* results in more that one subgraph belonging to a different file:
*
* subgraphID + db handle (location that subgraph was found) */
//static acdb_man_subgraph_location_t subgraph_location_cache[20];

/* ---------------------------------------------------------------------------
* Private functions
*--------------------------------------------------------------------------- */

int32_t acdb_ctx_man_init(void)
{
    int32_t status = AR_EOK;

    if (!acdb_ctx_man_context.acdb_client_lock)
    {
        status = ar_osal_mutex_create(&acdb_ctx_man_context.acdb_client_lock);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: failed to create acdb client mutex",
                status);
        }
    }

    if (!acdb_ctx_man_context.ctx_man_lock)
    {
        status = ar_osal_mutex_create(&acdb_ctx_man_context.ctx_man_lock);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: failed to create context manager mutex",
                status);
        }
    }

    //acdb_ctx_man_context.active_db_slots = 0xFFFFFFFF;

    return status;
}

int32_t acdb_ctx_man_add_database(acdb_context_handle_t *handle)
{
    int32_t status = AR_EOK;
    uint32_t index = 0;
    acdb_context_handle_t *db_ctx = NULL;

    for (index = 0; index < MAX_ACDB_FILE_COUNT; index++)
    {
        if (IsNull(acdb_ctx_man_context.database_info[index]))
            break;
    }

    if (MAX_ACDB_FILE_COUNT == index)
        index--;

    acdb_ctx_man_context.database_info[index] =
        ACDB_MALLOC(acdb_context_handle_t, 1);

    if (IsNull(acdb_ctx_man_context.database_info[index]))
        return AR_ENOMEMORY;

    ACDB_MUTEX_LOCK(acdb_ctx_man_context.ctx_man_lock);
    db_ctx = acdb_ctx_man_context.database_info[index];

    ar_mem_set(db_ctx, 0, sizeof(acdb_context_handle_t));

    db_ctx->vm_id = handle->vm_id;
    db_ctx->database_index = index;
    db_ctx->file_manager_handle = handle->file_manager_handle;
    db_ctx->delta_manager_handle = handle->delta_manager_handle;
    db_ctx->heap_handle = handle->heap_handle;

    //ACDB_BIT_SET(acdb_ctx_man_context.active_db_slots, index);
    acdb_ctx_man_context.database_count++;
    if (1 == acdb_ctx_man_context.database_count)
        acdb_ctx_man_context.active_db =
        acdb_ctx_man_context.database_info[index];
    ACDB_MUTEX_UNLOCK(acdb_ctx_man_context.ctx_man_lock);

    return status;
}

int32_t acdb_ctx_man_remove_database(acdb_handle_t *handle)
{
    int32_t status = AR_EOK;
    // uint32_t db_index = 0;
    acdb_context_handle_t* ctx_handle = NULL;
    uint32_t vm_id = 0;

    if (IsNull(handle))
        return AR_EBADPARAM;

    vm_id = ACDB_HANDLE_TO_UINT(handle);
    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        ctx_handle = acdb_ctx_man_context.database_info[i];

        if (IsNull(ctx_handle))
            continue;

        if (vm_id == acdb_ctx_man_context.database_info[i]->vm_id)
        {
            // db_index = ctx_handle->database_index;
            acdb_ctx_man_context.database_info[i] = NULL;
            break;
        }
    }

    ACDB_FREE(ctx_handle);

    ACDB_MUTEX_LOCK(acdb_ctx_man_context.ctx_man_lock);

    // ACDB_BIT_UNSET(acdb_ctx_man_context.active_db_slots, db_index);

    if (acdb_ctx_man_context.database_count > 0)
    {
        acdb_ctx_man_context.database_count--;
    }

    ACDB_MUTEX_UNLOCK(acdb_ctx_man_context.ctx_man_lock);

    return status;
}

int32_t acdb_ctx_man_reset(void)
{
    int32_t status = AR_EOK;
    acdb_context_handle_t *db_info = NULL;
    acdb_handle_t acdb_handle = NULL;

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        db_info = acdb_ctx_man_context.database_info[i];

        if (IsNull(db_info))
            continue;

        acdb_handle = (acdb_handle_t)(uintptr_t)db_info->vm_id;
        status = acdb_ctx_man_remove_database(&acdb_handle);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to remove data base at index %d",
                status, db_info->vm_id);
            status = AR_EFAILED;
        }
    }

    ar_osal_mutex_destroy(acdb_ctx_man_context.ctx_man_lock);
    ar_osal_mutex_destroy(acdb_ctx_man_context.acdb_client_lock);
    ar_mem_set(&acdb_ctx_man_context, 0, sizeof(AcdbCtxManContext));
    return status;
}

int32_t acdb_ctx_man_get_acdb_client_handle(uint32_t acdb_handle,
    acdb_handle_t *db_handle)
{
    if (IsNull(db_handle))
        return AR_EBADPARAM;

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        if (acdb_handle == acdb_ctx_man_context.database_info[i]->vm_id)
        {
            *db_handle = ACDB_UINT_TO_HANDLE(acdb_handle);
            return AR_EOK;
        }
    }

    return AR_ENOTEXIST;
}

int32_t acdb_ctx_man_get_context_handle(uint32_t acdb_handle,
    acdb_context_handle_t **ctx_handle)
{
    int32_t status = AR_EOK;
    bool_t found = FALSE;

    if (IsNull(ctx_handle))
        return AR_EBADPARAM;

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        if (acdb_handle == acdb_ctx_man_context.database_info[i]->vm_id)
        {
            *ctx_handle = acdb_ctx_man_context.database_info[i];
            found = TRUE;
            break;
        }
    }

    if (!found)
        return AR_ENOTEXIST;

    return status;
}

int32_t acdb_ctx_man_get_context_handle_using_index(uint32_t db_index,
    acdb_context_handle_t** ctx_handle)
{
    int32_t status = AR_EOK;

    if (IsNull(ctx_handle))
        return AR_EBADPARAM;

    if(db_index > acdb_ctx_man_context.database_count)
        return AR_EBADPARAM;

    *ctx_handle = acdb_ctx_man_context.database_info[db_index];

    if (IsNull(*ctx_handle))
    {
        ACDB_ERR("Error[%d]: No database context was found at "
            "index %d", db_index);
        return AR_ENOTEXIST;
    }

    return status;
}

int32_t acdb_ctx_man_set_context_handle(acdb_handle_t *handle)
{
    int32_t status = AR_EOK;
    uint32_t vm_id = 0;

    vm_id = ACDB_HANDLE_TO_UINT(handle);
    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        if (vm_id != acdb_ctx_man_context.database_info[i]->vm_id)
            continue;

        acdb_ctx_man_context.active_db =
            acdb_ctx_man_context.database_info[i];
        break;
    }

    return status;
}

int32_t acdb_ctx_man_set_context_handle_using_index(uint32_t db_index)
{
    int32_t status = AR_EOK;

    if (db_index > acdb_ctx_man_context.database_count)
        return AR_EBADPARAM;

    acdb_ctx_man_context.active_db =
        acdb_ctx_man_context.database_info[db_index];

    if (IsNull(acdb_ctx_man_context.active_db))
    {
        ACDB_ERR("Error[%d]: No database context was found at "
            "index %d", db_index);
        return AR_ENOTEXIST;
    }

    return status;
}

int32_t acdb_ctx_man_set_handle_using_gkv(
    AcdbGraphKeyVector* gkv, acdb_graph_info_t* graph_info)
{
    int32_t status = AR_ENOTEXIST;
    uint32_t gkv_lut_offset = 0;

    if (IsNull(gkv) || IsNull(graph_info))
    {
        return AR_EBADPARAM;
    }

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        acdb_ctx_man_context.active_db =
            acdb_ctx_man_context.database_info[i];

        status = DataProcSearchGkvKeyTable(gkv, &gkv_lut_offset);
        if (AR_ENOTEXIST == status)
            continue;
        else if (AR_FAILED(status))
        {
            return status;
        }

        status = DataProcSearchGkvLut(gkv, gkv_lut_offset, graph_info);
        if (AR_ENOTEXIST == status)
            continue;
        else if (AR_FAILED(status))
        {
            return status;
        }

        return status;
    }

    ACDB_DBG("Error[%d]: Unable to set active database."
        "Graph key vector not found in any file", status);

    return status;
}

int32_t acdb_ctx_man_set_handle_using_subgraph(
    AcdbUintList* subgraph_id_list)
{
    uint32_t status = AR_EOK;
    uint32_t vm_id = 0;
    uint32_t subgraph_id = 0;
    uint32_t num_subgraphs_found = 0;
    AcdbRange sg_range = { 0 };
    AcdbSharedSubgraphGuidTable shared_sg_guid_table = { 0 };

    /* if a subgraph is shared, it can exist in one file plus 1 or more other
    * files. This means that it is possible for it to be outside the subgraph
    * id range. if the shared subgraph is outside the range, check the files
    * import/export shared subgraph properties to make sure its in the
    * current file */

    if (acdb_ctx_man_context.database_count == 1)
    {
        acdb_ctx_man_context.active_db =
            acdb_ctx_man_context.database_info[0];
        return AR_EOK;
    }

    if (IsNull(subgraph_id_list) || IsNull(subgraph_id_list->list) ||
        0 == subgraph_id_list->count)
    {
        return AR_EBADPARAM;
    }

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        num_subgraphs_found = 0;
        acdb_ctx_man_context.active_db =
            acdb_ctx_man_context.database_info[i];

        if (1 == subgraph_id_list->count)
        {
            vm_id = ACDB_SUBGRAPH_TO_VM_ID(subgraph_id_list->list[0]);

            if (vm_id == acdb_ctx_man_context.database_info[i]->vm_id)
            {
                return AR_EOK;
            }
        }
        else
        {
            status = DataProcGetIdRange(
                ACDB_GPROP_SUBGRAPH_ID_RANGE, &sg_range);
            if (AR_FAILED(status))
            {
                return status;
            }

            for (uint32_t j = 0; j < subgraph_id_list->count; j++)
            {
                subgraph_id = subgraph_id_list->list[j];
                if (DataProcIsValueInRange(subgraph_id, sg_range))
                {
                    num_subgraphs_found++;
                }
                else
                {
                    //check imports
                    status = DataProcGetSharedSubgraphGuidTable(
                        ACDB_GPROP_IMPORTED_SHARED_SUBGRAPHS,
                        &shared_sg_guid_table);
                    if (AR_FAILED(status))
                    {
                        return status;
                    }

                    if (DataProcDoesSharedSubgraphExist(
                        subgraph_id, &shared_sg_guid_table))
                    {
                        num_subgraphs_found++;
                    }
                }

                if (num_subgraphs_found == 0)
                    break;
            }
        }

        if (num_subgraphs_found == subgraph_id_list->count)
        {
            return AR_EOK;
        }
    }

    /* The active context can only be set to one database. The acdb sw
    * apis will fail to find subgraphs if subgraphs exist accross different files.
    * For example: SG1 is defined in file 1, SG2 and SG3 are defined in File 2.
    * If the context were set to file 1, acdb sw wont be able to find SG2 and SG3.
    */
    ACDB_DBG("Error[%d]: Unable to set active database."
        "Not all subgraphs were found in the same file", AR_ENOTEXIST);

    return AR_ENOTEXIST;
}

int32_t acdb_ctx_man_set_handle_using_driver_module(
    acdb_driver_cal_lut_entry_t *cal_lut_entry,
    uint32_t *cal_lut_entry_offset)
{
    int32_t status = AR_EOK;

    for (uint32_t i = 0; i < acdb_ctx_man_context.database_count; i++)
    {
        acdb_ctx_man_context.active_db =
            acdb_ctx_man_context.database_info[i];

        status = DriverDataFindFirstOfModuleID(
            cal_lut_entry, cal_lut_entry_offset);
        if (AR_SUCCEEDED(status))
        {
            return AR_EOK;
        }
    }

    ACDB_DBG("Error[%d]: Unable to set active database. "
        "Driver module 0x%x not found in any file",
        status, cal_lut_entry->mid);

    return status;
}

/* ---------------------------------------------------------------------------
* Public Functions
*--------------------------------------------------------------------------- */

acdb_context_handle_t *acdb_ctx_man_get_active_handle(void)
{
    return acdb_ctx_man_context.active_db;
}

ar_osal_mutex_t acdb_ctx_man_get_client_lock(void)
{
    return acdb_ctx_man_context.acdb_client_lock;
}

uint32_t acdb_ctx_man_get_database_count(void)
{
    return acdb_ctx_man_context.database_count;
}

int32_t acdb_ctx_man_ioctl(uint32_t cmd_id,
	void* req,
	uint32_t req_size,
    void* rsp,
	uint32_t rsp_size)
{
    int32_t status = AR_EOK;

	switch (cmd_id)
	{
    case ACDB_CTX_MAN_CMD_INIT:
        status = acdb_ctx_man_init();
        break;
	case ACDB_CTX_MAN_CMD_ADD_DATABASE:
        if (req == NULL || req_size != sizeof(acdb_context_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_add_database((acdb_context_handle_t*)req);
		break;
	case ACDB_CTX_MAN_CMD_REMOVE_DATABASE:
        if (req == NULL || req_size != sizeof(acdb_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_remove_database((acdb_handle_t*)req);
		break;
    case ACDB_CTX_MAN_CMD_RESET:
        status = acdb_ctx_man_reset();
        break;
    case ACDB_CTX_MAN_CMD_GET_AVAILABLE_FILE_SLOTS:
        if (rsp == NULL || rsp_size != sizeof(uint32_t))
        {
            return AR_EBADPARAM;
        }

        *(uint32_t*)rsp = ACDB_MAX_ACDB_FILES
            - acdb_ctx_man_context.database_count;
        break;
    case ACDB_CTX_MAN_CMD_GET_ACDB_CLIENT_HANDLE:
        if (req == NULL || req_size != sizeof(uint32_t) ||
            rsp == NULL || rsp_size != sizeof(acdb_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_get_acdb_client_handle(
            *(uint32_t*)req, (acdb_handle_t*)rsp);
        break;
	case ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE:
        if (req == NULL || req_size != sizeof(uint32_t) ||
            rsp == NULL || rsp_size != sizeof(acdb_context_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_get_context_handle(*(uint32_t*)req, rsp);
		break;
    case ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE_USING_INDEX:
        if (req == NULL || req_size != sizeof(uint32_t) ||
            rsp == NULL || rsp_size != sizeof(acdb_context_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_get_context_handle_using_index(
            *(uint32_t*)req, rsp);
        break;
    case ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE:
        if (req == NULL || req_size != sizeof(acdb_handle_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_set_context_handle((acdb_handle_t*)req);
        break;
    case ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_INDEX:
        if (req == NULL || req_size != sizeof(uint32_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_set_context_handle_using_index(
            *(uint32_t*)req);
        break;
    case ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV:
        if (req == NULL || req_size != sizeof(AcdbGraphKeyVector) ||
            rsp == NULL || rsp_size != sizeof(acdb_graph_info_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_set_handle_using_gkv(
            (AcdbGraphKeyVector*)req, (acdb_graph_info_t*)rsp);
        break;
    case ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS:
        if (req == NULL || req_size != sizeof(AcdbUintList))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_set_handle_using_subgraph(
            (AcdbUintList*)req);
        break;
    case ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_DRIVER_MODULE:
        if (req == NULL || req_size != sizeof(acdb_driver_cal_lut_entry_t) ||
            rsp == NULL || rsp_size != sizeof(uint32_t))
        {
            return AR_EBADPARAM;
        }

        status = acdb_ctx_man_set_handle_using_driver_module(
            (acdb_driver_cal_lut_entry_t*)req, (uint32_t*)rsp);
        break;
    default:
        status = AR_EUNSUPPORTED;
        break;
	}

    return status;
}
