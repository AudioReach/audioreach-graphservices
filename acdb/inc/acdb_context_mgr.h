#ifndef __ACDB_CONTEXT_MGR_H__
#define __ACDB_CONTEXT_MGR_H__

/**
*=============================================================================
* \file acdb_context_mgr.h
*
* \brief
*		Manages the active database context for an acdb_ioctl command. The
*		context can only be changed per command since acdb_ioctl commands
*		are guarded by a lock.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#include "ar_osal_types.h"
#include "ar_osal_mutex.h"
#include "acdb_common.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */

#define ACDB_CTX_MAN_DEFAULT_DB_HANDLE 0

/**< A Pointer to the active context manager database handle  */
#define ACDB_CTX_MAN_ACTIVE_HANDLE acdb_man_get_active_handle()

/**< The total number of databases being managed  */
#define ACDB_CTX_MAN_DATABASE_COUNT acdb_ctx_man_get_database_count()

/**< The lock for incoming ACDB client commands.(e.g ATS online
commands from QACT and acdb_ioctl commands from GSL */
#define ACDB_CTX_MAN_CLIENT_CMD_LOCK acdb_ctx_man_get_client_lock()

#define ACDB_MAGIC_WORD 0x00ACDB00
#define ACDB_HANDLE_MASK 0xF
/**< Casts a pointer to a acdb_handle_t to a uint */
#define ACDB_HANDLE_TO_UINT(handle) \
(ACDB_HANDLE_MASK & (uint32_t)(uintptr_t)*handle)

/**< Casts a uint handle to a acdb_handle_t */
#define ACDB_UINT_TO_HANDLE(handle) \
(acdb_handle_t)(uintptr_t)(ACDB_MAGIC_WORD |(handle & ACDB_HANDLE_MASK));

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

/**< A handle to a heap object */
typedef void *acdb_heap_handle_t;

/**< A handle to a file manager object */
typedef void *acdb_file_man_handle_t;

/**< A handle to a delta file manager object */
typedef void *acdb_delta_file_man_handle_t;

/**< A context handle that holds references to the file manager,
delta file manager, and heap objects for a database */
typedef struct acdb_context_handle_t acdb_context_handle_t;
struct acdb_context_handle_t {
	uint32_t vm_id;
	uint32_t database_index;
	/**< A handle to a file manager object */
	acdb_file_man_handle_t file_manager_handle;
	/**< A handle to a delta file manager object*/
	acdb_delta_file_man_handle_t delta_manager_handle;
	/**< A handle to heap object*/
	acdb_heap_handle_t heap_handle;
};

typedef enum acdb_ctx_manager_command_t
{
	/**< Initializes the context manager */
	ACDB_CTX_MAN_CMD_INIT = 0,
	/**< Adds a data to the manager */
	ACDB_CTX_MAN_CMD_ADD_DATABASE,
	/**< Removes a database from the manager using the clients acdb_handle_t */
	ACDB_CTX_MAN_CMD_REMOVE_DATABASE,
	/**< De-initializes the context manager and frees resources */
	ACDB_CTX_MAN_CMD_RESET,
	/**< Get the number of remaining file slots */
	ACDB_CTX_MAN_CMD_GET_AVAILABLE_FILE_SLOTS,
	/**< Get the acdb client handle */
	ACDB_CTX_MAN_CMD_GET_ACDB_CLIENT_HANDLE,
	/**< Get the context handle associated with the database using
	the virtual machine identifier */
	ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE,
	/**< Get the context handle associated with the database using
	the an index */
	ACDB_CTX_MAN_CMD_GET_CONTEXT_HANDLE_USING_INDEX,
	/**< Set the active context handle using the acdb handle */
	ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE,
	/**< Set the active context handle using a database index */
	ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_INDEX,
	/**< Set the active context handle using a Graph Key Vector */
	ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_GKV,
	/**< Set the active context handle using one or more subgraphs */
	ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_SUBGRAPHS,
	/**< Set the active context handle using a driver module id */
	ACDB_CTX_MAN_CMD_SET_CONTEXT_HANDLE_USING_DRIVER_MODULE,
}acdb_ctx_manager_command_t;

/* ---------------------------------------------------------------------------
* Funcions
*--------------------------------------------------------------------------- */

/**
* \brief
*		Retrieves the active context handle
*
* \return a pointer to the active context handle, or
*		  NULL if the context manager is not initialized
*/
acdb_context_handle_t *acdb_ctx_man_get_active_handle(void);

/**
* \brief
*		Retrieves the active context handle
*
* \return a pointer to the active context handle, or
*		  NULL if the context manager is not initialized
*/
ar_osal_mutex_t acdb_ctx_man_get_client_lock(void);

/**
* \brief
*		Retrieves the total number of databases being managed
*
* \return the number of databases
*/
uint32_t acdb_ctx_man_get_database_count(void);

/**
* \brief
*		The context manager ioctl used to execute the commands
*		defined under acdb_ctx_manager_command_t
*
* \param[in] cmd_id: The command to execute. See acdb_ctx_manager_command_t
* \param[in/out] req: The command request structure
* \param[in] sz_req: The size of the request structure
* \param[in/out] rsp: The command response structure
* \param[in] sz_rsp: The size of the response structure
*
* \sa acdb_ctx_manager_command_t
* \return 0 on success, non-zero on failure
*/
int32_t acdb_ctx_man_ioctl(uint32_t cmd_id,
	void *req, uint32_t sz_req,
	void *rsp, uint32_t sz_rsp);

#endif /*__ACDB_CONTEXT_MGR_H__*/
