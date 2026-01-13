#ifndef __ACDB_UTILITY_H__
#define __ACDB_UTILITY_H__
/**
*=============================================================================
* \file acdb_utility.h
*
* \brief
*		Provides utility functions to be used accross ACDB SW.
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
#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "ar_osal_heap.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_string.h"
#include "acdb_types.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */
#define SEARCH_SUCCESS 0

#define SEARCH_ERROR -1

#define IsNull(ptr) (ptr == NULL)

#define ACDB_FIND_STR(string, sub_string) ar_strstr(string, sub_string)

#define ACDB_MEM_CPY_SAFE(dest, dest_size, src, src_size) ar_mem_cpy((int8_t*) dest, dest_size, (int8_t*)src, src_size)

#define ACDB_STR_CPY_SAFE(dest, dest_size, src, src_size) ar_strcpy(dest, dest_size, src, src_size)

#define ACDB_STR_CAT_SAFE(dest, dest_size, src, src_size) ar_strcat(dest, dest_size, src, src_size)

#define ACDB_ALIGN_8_BYTE(byte_size) AcdbAlign(8, byte_size)

#define ACDB_PADDING_8_BYTE(byte_size) AcdbPadding(8, byte_size)

#define ACDB_MALLOC(type, count) (type*)AcdbMalloc(sizeof(type)*count)

#define ACDB_FREE(data) AcdbFree((void*)data)

//TODO: Remove this function once its avalible in the OSAL
#ifndef ar_sscanf
#if defined(_WIN64) || defined(_WIN32)
#define ar_sscanf(buf, format, ...) sscanf_s(buf, format, __VA_ARGS__)
#elif defined(__linux__)
#define ar_sscanf(buf, format, ...) sscanf(buf, format, __VA_ARGS__)
#endif
#endif

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef enum _acdb_function_io_t {
    ACDB_FUNC_IO_UNUSED = 0x0,
    ACDB_FUNC_IO_IN,
    ACDB_FUNC_IO_OUT,
}AcdbFunctionIO;

/* ---------------------------------------------------------------------------
* Function Callbacks
*--------------------------------------------------------------------------- */

/**
* \brief
*		A Callback for freeing objects pointed to by linked list nodes. This
*       callback is used in conjunction with AcdbListClear2(...)
*
* \param [in] object: The object to free
*/
typedef void(*ACDB_LIST_CLEAR_CALLBACK)(
    void* object);

/* ---------------------------------------------------------------------------
* Struct Definitions
*--------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
* Function Declarations and Documentation
*--------------------------------------------------------------------------- */

//bool_t IsNullVar(uint32_t count, ...);

int32_t AcdbARHeapInit(void);

int32_t AcdbARHeapDeinit(void);

void* AcdbMalloc(size_t size);

void AcdbFree(void* data);

/**
* \brief AcdbDataBinarySearch2
*		Performs a binary search on an array of structures or basic types
* \param [in] p_array: array to be searched
* \param [in] sz_arr: size of p_array
* \param [in] p_cmd: the structure that is used as a search key
* \param [in] n_search_cmd_params: number of structure members to use in the search
* \param [in] n_total_cmd_params: number of search key(s) used in the search
* \param [in] index: index of the located object
*/
int32_t AcdbDataBinarySearch2(void *p_array, size_t sz_arr, void *p_cmd,
	int32_t n_search_cmd_params, int32_t n_total_cmd_params, uint32_t *index);

/**
* \brief AcdbSort
*		Performs insertion sort on an array of basic types
* \param [in/out] p_array: array to be sorted
* \param [in] sz_arr: size of p_array
*/
void AcdbSort(void* p_array, uint32_t sz_arr);

/**
* \brief AcdbSort2
*		Performs insertion sort on an array of basic/user defined types
* \param [in] sz_arr: byte size of p_array
* \param [in/out] p_array: array to be sorted
* \param [in] sz_elem: size of an element in the array
* \param [in] key_elem_pos: position of the sorting key within the element (e.g 0, 1, 2, etc...)
* \return 0 on success, non-zero on failure
*/
int32_t AcdbSort2(size_t sz_arr, void* p_array, size_t sz_elem, uint32_t key_elem_pos);

/**
* \brief AcdbAlign
*		Performs byte alignment
* \param [in] byte_alignment: number of bytes to align by
* \param [in] byte_size: byte size to align
* \return new aligned byte size, but if already aligned returns byte_size
*/
uint32_t AcdbAlign(uint32_t byte_alignment, uint32_t byte_size);

/**
* \brief
*		Returns padding based on byte alignment and size
* \param [in] byte_alignment: number of bytes to align by
* \param [in] byte_size: byte size to align
* \return non-zero padding if not aligned, otherwise returns 0
*/
uint32_t AcdbPadding(uint32_t byte_alignment, uint32_t byte_size);

/**
* \brief AcdbListCreateNode
*		Performs byte alignment
* \param [in/out] p_array: array to be sorted
* \param [in] p_array: size of p_array
* \return NULL on error, LinkedListNode pointer on success
*/
LinkedListNode *AcdbListCreateNode(void *p_struct);

/**
* \brief AcdbListAppend
*		Add node at the end of the linked list
* \param [in/out] list: linked list to append to
* \param [in] node: linked list node to append
* \return 0 success, non-zero on failure
*/
int32_t AcdbListAppend(LinkedList *list, LinkedListNode *node);

/**
* \brief AcdbListClear
*		Clear a linked list by freeing each node. *NOTE* This function does not
*       free the objects pointed to by each node.
* \param [in/out] list: linked list to free
*/
void AcdbListClear(LinkedList *list);

/**
* \brief AcdbListClear2
*		Clear the linked list and use a callback to free the objects
*       pointed to by each node.
*       *NOTE* This function operates the same as AcdbListClear if
*       the free_obj_cb callback is NULL.
* \param [in/out] list: linked list to free
* \param [in] free_obj_cb:  a function callback that knows how to
*                           free the object pointed to by the node
*/
void AcdbListClear2(LinkedList *list, ACDB_LIST_CLEAR_CALLBACK free_obj_callback);

/**
* \brief AcdbListFreeAndSetNext
*		Deletes a given node and sets the node to its next node
* \param [in/out] node: address of node within a linked list
*/
void AcdbListFreeAndSetNext(LinkedListNode** node);

/**
* \brief AcdbListSetNext
*		Sets a given node to its next node
* \param [in/out] node: node within a linked list
*/
//void AcdbListSetNext(LinkedListNode* node);
bool_t AcdbListSetNext(LinkedListNode** node);

/**
* \brief  AcdbListMerge
*		Merges two linked list together and sets the merge from list to NULL
* \param[in] merge_to: list to merge to
* \param[in] merge_from: list to merge from
* \return
* 0 -- Success
* Nonzero -- Failure
*/
int32_t AcdbListMerge(LinkedList *merge_to, LinkedList *merge_from);

/**
* \brief AcdbListMoveToEnd
*		Moves a node within a list to the end
* \param[in] list: The linked list to modify
* \param[in] node: The node within list to move to the end
* \param[in] prev_node: The node within list that precedes node
* \return a map pointer on success, Null on failure
*/
void AcdbListMoveToEnd(LinkedList *list, LinkedListNode** node, LinkedListNode** prev_node);

/**
* \brief AcdbListRemove
*		Detatches a node from the given list. The previous node
*       is attached to the node right of the detached node. The caller
*       is responsible for freeing the node
* \param [in] list: The linked list containing prev and node
* \param [in] prev: The previous node
* \param [in] node: The node to detach
* \return 0 on success, non-zero on failure
*/
int32_t AcdbListRemove(LinkedList *list, LinkedListNode *prev, LinkedListNode *node);

/**
* \brief LogKeyVector
*		Prints the keyvector to the console/log
* \param [in] key_vector: pointer to key vector to log
* \param [in] type: The type of key vector(GKV, CKV, TKV)
*/
void LogKeyVector(const AcdbGraphKeyVector *key_vector, KeyVectorType type);

/**
* \brief LogKeyIDs
*		Prints the key ids to the console/log
* \param [in] keys: list of uint32 key ids
* \param [in] type: The type of key vector(GKV, CKV, TKV)
*/
void LogKeyIDs(const AcdbUintList *keys, KeyVectorType type);

uint32_t AcdbCeil(uint32_t x, uint32_t y);

/**
* \brief AcdbGenericListInit
*		Initializes a generic list by setting the element size, max number of elements, list data, and function pointers
* \param [in] list: The list to initialize
* \param [in] element_size: The size of list elements in bytes
* \param [in] max_element_count: The max number of elements the list can store
* \param [in] list_data: A pointer to the memory used for storing data
*/
int32_t AcdbGenericListInit(AcdbGenericList* list, uint32_t element_size, uint32_t max_element_count, void** list_data);
#endif /* __ACDB_UTILITY_H__ */
