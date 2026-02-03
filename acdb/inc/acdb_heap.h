#ifndef __ACDB_HEAP_H__
#define __ACDB_HEAP_H__
/**
*==============================================================================
* \file acdb_heap.h
*
* \brief
*		Manages the calibration data set by ACDB SW clients in RAM.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include "acdb_delta_parser.h"
#include "acdb_context_mgr.h"

enum TreeDirection {
	TREE_DIR_LEFT = -1,
	TREE_DIR_NONE,
	TREE_DIR_RIGHT
};

enum AcdbHeapCmd {
	ACDB_HEAP_CMD_INIT = 0,
	ACDB_HEAP_CMD_ADD_DATABASE,
	ACDB_HEAP_CMD_REMOVE_DATABASE,
	ACDB_HEAP_CMD_RESET,
	ACDB_HEAP_CMD_CLEAR_DATABASE_HEAP,
	ACDB_HEAP_CMD_ADD_MAP,
	ACDB_HEAP_CMD_ADD_MAP_USING_HANDLE,
	ACDB_HEAP_CMD_GET_MAP,
	ACDB_HEAP_CMD_GET_MAP_LIST,
	ACDB_HEAP_CMD_REMOVE_MAP,
	ACDB_HEAP_CMD_GET_HEAP_INFO,
};

typedef struct _acdb_tree_node_t AcdbTreeNode;
struct _acdb_tree_node_t
{
	int32_t depth;      /**< Tree depth of the node */
	void *p_struct;     /**< Data stored in the node */
	AcdbTreeNode *left;     /**< Left subtree */
	AcdbTreeNode *right;    /**< Right subtree */
	AcdbTreeNode *parent;   /**< parent node */
    uint32_t type;      /**< Node Type (GSL, ARCT,...) */
};

typedef struct _kv_length_bin_t KVSubgraphMapBin;
struct _kv_length_bin_t
{
	/**< The length of the key vector string */
	uint32_t str_key_vector_size;
	/**< The key vector string */
	char_t *str_key_vector;
    /**< Maps a keyvector to a subgraph containing calibration data */
    acdb_delta_data_map_t *map;
};

typedef struct acdb_heap_map_handle_info_t
{
	acdb_heap_handle_t handle;
	acdb_delta_data_map_t *map;
}acdb_heap_map_handle_info_t;

void acdb_heap_free_subgraph_data(AcdbDeltaSubgraphData* subgraph_data);

void acdb_heap_free_map(acdb_delta_data_map_t* map);

AcdbGraphKeyVector *get_key_vector_from_map(acdb_delta_data_map_t* map);

int32_t acdb_heap_ioctl(uint32_t cmd_id,
	void* req, uint32_t req_size,
	void* rsp, uint32_t rsp_size);

#endif /*__ACDB_HEAP_H__*/
