/**
*=============================================================================
* \file acdb_utility.c
*
* \brief
*		Provides utility functions that are used accross ACDB Software
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

#include "acdb_utility.h"
#include "acdb_common.h"
//#include <stdarg.h>

/* ---------------------------------------------------------------------------
* Globals
*--------------------------------------------------------------------------- */

static ar_heap_info glb_ar_heap_info =
{
	AR_HEAP_ALIGN_DEFAULT,
	AR_HEAP_POOL_DEFAULT,
	AR_HEAP_ID_DEFAULT,
	AR_HEAP_TAG_DEFAULT
 };

/* ---------------------------------------------------------------------------
* Functions
*--------------------------------------------------------------------------- */

//bool_t IsNullVar(uint32_t count, ...)
//{
//    va_list args;
//    va_start(args, count);
//    void* ptr = NULL;
//    for (uint32_t i = 0; i < count; i++)
//    {
//        ptr = va_arg(args, void*);
//        if (ptr == NULL) return TRUE;
//    }
//    va_end(args);
//    return FALSE;
//}

int32_t AcdbARHeapInit(void)
{
    int32_t status = AR_EOK;
    glb_ar_heap_info.align_bytes = AR_HEAP_ALIGN_DEFAULT;
    glb_ar_heap_info.heap_id = AR_HEAP_ID_DEFAULT;
    glb_ar_heap_info.pool_type = AR_HEAP_POOL_DEFAULT;
    glb_ar_heap_info.tag = AR_HEAP_TAG_DEFAULT;

    status = ar_heap_init();
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to initialize ar heap", status);
    }
    return status;
}

int32_t AcdbARHeapDeinit(void)
{
    int32_t status = AR_EOK;

    status = ar_heap_deinit();
    if (AR_FAILED(status))
    {
        ACDB_ERR("Error[%d]: Failed to de-initialize ar heap", status);
    }
    return status;
}

void* AcdbMalloc(size_t size)
{
    return ar_heap_malloc(size, &glb_ar_heap_info);
}

void AcdbFree(void* data)
{
	if (IsNull(data))
		return;

    ar_heap_free(data, &glb_ar_heap_info);
}

//int32_t AcdbOffsetMemCpy(uint8_t* dst, uint8_t *src, uint32_t *offset, uint32_t size)
//{
//    if (IsNull(dst) || IsNull(src) || IsNull(offset))
//    {
//        return AR_EBADPARAM;
//    }
//
//    ACDB_MEM_CPY(dst + *offset, src, size);
//    offset += size;
//
//    return AR_EOK;
//}

 int32_t AcdbDataCompareSearchKeys(
     uint32_t* left, uint32_t *right, int num_params)
 {
     int32_t i = 0;
     uint32_t* left_value = NULL;
     uint32_t* right_value = NULL;

     // Assuming that the indices are all uint32_t.
     for (i = 0; i < num_params; i++)
     {
         left_value = left + i;
         right_value = right + i;

         if (*left_value > *right_value)
         {
             return 1;
         }
         else if (*left_value < *right_value)
         {
             return -1;
         }
     }
     return 0;
 }

 //int32_t AcdbDataCompareIndices(uint32_t* lookup, uint32_t *key,
 //    int num_params)
 //{
 //    int32_t i = 0;
 //    uint32_t* lookupVal = NULL;
 //    uint32_t* keyVal = NULL;

 //    // Assuming that the indices are all uint32_t.
 //    for (i = 0; i < num_params; i++)
 //    {
 //        lookupVal = lookup + i;
 //        keyVal = key + i;

 //        if (*lookupVal > *keyVal)
 //        {
 //            return 1;
 //        }
 //        else if (*lookupVal < *keyVal)
 //        {
 //            return -1;
 //        }
 //    }
 //    return 0;
 //}
//
//int32_t AcdbDataBinarySearch(void *p_array, int32_t max, int32_t indexCount,
//    void *p_cmd, int32_t n_param_count, uint32_t *index)
//{
//    int32_t result = SEARCH_ERROR;
//    int32_t min = 0;
//    int32_t mid = 0;
//    int32_t compareResult = 0;
//
//    uint32_t *lookUpArray = (uint32_t *)p_array;
//
//    while (max >= min)
//    {
//        mid = (min + max) / 2;
//
//        compareResult = AcdbDataCompareIndices(&lookUpArray[indexCount * mid],
//            (uint32_t *)p_cmd, n_param_count);
//
//        if (compareResult > 0) // search lower array
//        {
//            max = mid - 1;
//        }
//        else if (compareResult < 0) // search upper array
//        {
//            min = mid + 1;
//        }
//        else
//        {
//            // If its a partial search then the found index could no be the very first item
//            // Find the first occurence of this element by going backward
//            while (0 == AcdbDataCompareIndices(&lookUpArray[indexCount * (mid - 1)],
//                (uint32_t *)p_cmd, n_param_count))
//            {
//                mid = mid - 1;
//            }
//            *index = (uint32_t)mid;
//            result = SEARCH_SUCCESS;
//            break;
//        }
//    }
//
//    return result;
//}
//

//Binary Search already assumes that the lookup array and p_cmd is made up of uint32 types

int32_t AcdbDataBinarySearch2(void *p_array, size_t sz_arr, void *p_cmd,
	int32_t n_search_cmd_params, int32_t n_total_cmd_params, uint32_t *index)
{
	int32_t result = SEARCH_ERROR;
	int32_t min = 0;
	int32_t max = (int32_t)(sz_arr / (n_total_cmd_params * sizeof(uint32_t))) - 1;
	int32_t mid = 0;
	int32_t compareResult = 0;
	uint32_t *lookUpArray = (uint32_t *)p_array;
	uint32_t *search_key = (uint32_t *)p_cmd;

	while (max >= min)
	{
		mid = (min + max) / 2;

		compareResult = AcdbDataCompareSearchKeys(
			search_key, &lookUpArray[n_total_cmd_params * mid],
            n_search_cmd_params );

		if (compareResult < 0) // search lower array
		{
			max = mid - 1;
		}
		else if (compareResult > 0) // search upper array
		{
			min = mid + 1;
		}
		else
		{
            /* If its a partial search then the found index could no be the
			 * very first item. Find the first occurence of this element
			 * by going backward
			 */
			if (mid > 0)
			{
				while (0 == AcdbDataCompareSearchKeys(
					search_key, &lookUpArray[n_total_cmd_params * (mid - 1)],
					n_search_cmd_params))
				{
					if (mid <= min) break;

					mid = mid - 1;
				}
			}

			*index = (uint32_t)mid * n_total_cmd_params;
			result = SEARCH_SUCCESS;
			break;
		}
	}

	return result;
}

void AcdbSort(void* p_array, uint32_t sz_arr)
{
	//insertion sort

	uint32_t* lst = (uint32_t*)p_array;
	uint32_t tmp = 0;
	int32_t j = 0;
	uint32_t elem_count = sz_arr / sizeof(uint32_t);

	for (uint32_t i = 0; i + 1UL < elem_count; i++)
	{
		j = i;
		while (j > -1)
		{
			if (lst[j] > lst[j + 1])
			{
				tmp = lst[j];
				lst[j] = lst[j + 1];
				lst[j + 1] = tmp;
			}
			j--;
		}
	}
}

int32_t AcdbSort2(size_t sz_arr, void* p_array, size_t sz_elem, uint32_t key_elem_pos)
{
	if (IsNull(p_array) || sz_arr == 0 || sz_elem == 0 || sz_arr < sz_elem)
		return AR_EBADPARAM;

	if (1 == sz_arr / sz_elem) return AR_EOK;

	uint32_t* lst = (uint32_t*)p_array;
	uint32_t elem_count = (uint32_t)sz_arr / (uint32_t)sz_elem;
	int32_t elem_member_count = (uint32_t)sz_elem / sizeof(uint32_t);
	int32_t lst_len = elem_count * elem_member_count;
    uint32_t *tmp_elem = ACDB_MALLOC(uint32_t, elem_member_count);
	int32_t j = 0;

	if (IsNull(tmp_elem)) return AR_ENOMEMORY;

	for (int32_t i = 0; i < lst_len - elem_member_count; i += elem_member_count)
	{
		j = i;
		while (j > -1)
		{
			uint32_t a = lst[j + key_elem_pos];
			uint32_t b = lst[j + key_elem_pos + elem_member_count];
			if (a > b)
			{
				ACDB_MEM_CPY_SAFE((void*)tmp_elem, sz_elem, &lst[j], sz_elem);
				ACDB_MEM_CPY_SAFE(&lst[j], sz_elem, &lst[j + elem_member_count], sz_elem);
				ACDB_MEM_CPY_SAFE(&lst[j + elem_member_count], sz_elem, tmp_elem, sz_elem);
			}
			j -= elem_member_count;
		}
	}

	ACDB_FREE(tmp_elem);
	return AR_EOK;
}

uint32_t AcdbAlign(uint32_t byte_alignment, uint32_t byte_size)
{
	uint32_t aligned_byte_size = 0;

	if ((byte_size % byte_alignment) != 0)
	{
		aligned_byte_size = byte_size + (byte_alignment - ((byte_size % byte_alignment)));
	}
	else
	{
		aligned_byte_size = byte_size;
	}

	return aligned_byte_size;
}

uint32_t AcdbPadding(uint32_t byte_alignment, uint32_t byte_size)
{
    if ((byte_size % byte_alignment) != 0)
        return (byte_alignment - ((byte_size % byte_alignment)));

    return 0;
}

LinkedListNode *AcdbListCreateNode(void *p_struct)
{
	LinkedListNode *lnode = ACDB_MALLOC(LinkedListNode, 1);

	if (lnode == NULL) return NULL;

	lnode->p_next = NULL;

	lnode->p_struct = p_struct;

	return lnode;
}

int32_t AcdbListAppend(LinkedList *list, LinkedListNode *node)
{
	//If the list is empty set the head
	if (IsNull(list->p_head) && IsNull(list->p_tail))
	{
		list->length = 0;

		list->p_head = node;

		list->p_tail = node;

		list->length++;
	}
	else
	{
		//get what tail is currently pointing to and point it to the inserted node
		list->p_tail->p_next = node;

		//set the inserted node to tail
		list->p_tail = node;

		list->length++;
	}

	return AR_EOK;
}

void AcdbListClear(LinkedList *list)
{
	if (IsNull(list)) return;

	LinkedListNode *cur_node = list->p_head;

	while (!IsNull(cur_node))
	{
		AcdbListFreeAndSetNext(&cur_node);
	}

	list->length = 0;

	list->p_head = NULL;

	list->p_tail = NULL;
}

void AcdbListClear2(LinkedList *list, ACDB_LIST_CLEAR_CALLBACK free_obj_callback)
{
    if (IsNull(list)) return;

    LinkedListNode *cur_node = list->p_head;

    while (!IsNull(cur_node))
    {
        if(!IsNull(free_obj_callback) && !IsNull(cur_node->p_struct))
            free_obj_callback(cur_node->p_struct);

        AcdbListFreeAndSetNext(&cur_node);
    }

    list->length = 0;

    list->p_head = NULL;

    list->p_tail = NULL;
}

void AcdbListFreeAndSetNext(LinkedListNode** node)
{
	if (*node == NULL) return;

	LinkedListNode *p_temp = NULL;

	p_temp = (*node)->p_next;

	ACDB_FREE(*node);

	*node = p_temp;

	p_temp = NULL;
}

//void AcdbListSetNext(LinkedListNode* node)
//{
//	if (node == NULL) return;
//
//	node = node->p_next;
//}

bool_t AcdbListSetNext(LinkedListNode** node)
{
	if (*node == NULL) return TRUE;

	*node = (*node)->p_next;
	return (*node) == NULL;
}

int32_t AcdbListMerge(LinkedList *merge_to, LinkedList *merge_from)
{
	if (IsNull(merge_to->p_head) && IsNull(merge_to->p_tail))
	{
		merge_to->p_head = merge_from->p_head;
		merge_to->p_tail = merge_from->p_tail;
		merge_to->length = merge_from->length;
	}
	else
	{
		merge_to->p_tail->p_next = merge_from->p_head;
		merge_to->p_tail = merge_from->p_tail;
		merge_to->length += merge_from->length;
	}

	merge_from->length = 0;
	merge_from->p_head = NULL;
	merge_from->p_tail = NULL;

	return 0;
}

void AcdbListMoveToEnd(LinkedList *list, LinkedListNode** node, LinkedListNode** prev_node)
{
	if (IsNull(list) || list->length == 0 || list->length == 1) return;

	LinkedListNode *tmp = NULL;

	if (list->length == 2)
	{
		//Swap Head and Tail
		tmp = list->p_head;
		list->p_head = list->p_tail;
		list->p_tail = tmp;
		list->p_tail->p_next = NULL;
		list->p_head->p_next = list->p_tail;
		tmp = NULL;
		return;
	}

	if (list->p_head == *node && IsNull(*prev_node))
	{
		list->p_head = list->p_head->p_next;
		(*node)->p_next = NULL;
		AcdbListAppend(list, *node);
		return;
	}
	else if (list->p_tail == *node)
	{
		return;
	}

	(*prev_node)->p_next = (*node)->p_next;
	(*node)->p_next = NULL;
	AcdbListAppend(list, *node);
}

int32_t AcdbListRemove(LinkedList *list, LinkedListNode *prev, LinkedListNode *node)
{
	if (IsNull(list) || IsNull(node)) return AR_EFAILED;

	if (IsNull(list->p_head) || IsNull(list->p_tail)) return AR_EFAILED;

	if (list->length == 1)
	{
		list->length = 0;
		list->p_head = NULL;
		list->p_tail = NULL;
		return AR_EOK;
	}
	else if (list->p_tail == node)
	{
		list->length--;
		if (!IsNull(prev))
		{
			prev->p_next = NULL;
		}
		node->p_next = NULL;
		return AR_EOK;
	}
	else if (list->p_head == node && IsNull(prev))
	{
		list->length--;
		list->p_head = list->p_head->p_next;
		node->p_next = NULL;
		return AR_EOK;
	}

	list->length--;
	if (!IsNull(prev))
	{
		prev->p_next = node->p_next;
	}
	node->p_next = NULL;

	return AR_EOK;
}

void LogKeyIDs(const AcdbUintList *keys, KeyVectorType type)
{
    if (keys == NULL) return;

    switch (type)
    {
    case GRAPH_KEY_VECTOR:
        ACDB_DBG("Graph Key IDs(%d) Keys:", keys->count);
        break;
    case CAL_KEY_VECTOR:
        ACDB_DBG("Calibration Key IDs(%d) Keys:", keys->count);
        break;
    case TAG_KEY_VECTOR:
        ACDB_DBG("Tag Key IDs(%d) Keys:", keys->count);
        break;
    default:
        return;
    }

    for (uint32_t i = 0; i < keys->count; i++)
        ACDB_DBG("[Key:0x%08x]", keys->list[i]);
}

void LogKeyVector(const AcdbGraphKeyVector *key_vector, KeyVectorType type)
{
    if (key_vector == NULL || key_vector->graph_key_vector == NULL) return;

    switch (type)
    {
    case GRAPH_KEY_VECTOR:
        ACDB_DBG("Graph Key Vector with %d key(s):", key_vector->num_keys);
        break;
    case CAL_KEY_VECTOR:
        ACDB_DBG("Calibration Key Vector with %d key(s):", key_vector->num_keys);
        break;
    case TAG_KEY_VECTOR:
        ACDB_DBG("Tag Key Vector with %d key(s):", key_vector->num_keys);
        break;
    default:
        return;
    }

    for (uint32_t i = 0; i < key_vector->num_keys; i++)
    {
        ACDB_DBG("[Key:0x%08x Val:0x%08x]",
            key_vector->graph_key_vector[i].key,
            key_vector->graph_key_vector[i].value);
    }
}

uint32_t AcdbCeil(uint32_t x, uint32_t y)
{
    return ((uint32_t)x % (uint32_t)y) == 0 ? x / y : x / y + 1;
}

int32_t AcdbGenericListAddRange(void* list, void* items, uint32_t item_size, uint32_t count)
{
	AcdbGenericList* gen_list = (void*)list;

	//Add one or more items to the list
	if (IsNull(list) || IsNull(items))
		return AR_EBADPARAM;
	if (IsNull(gen_list->list))
		return AR_EFAILED;
	if (item_size == 0 || count == 0)
	{
		ACDB_DBG("Warning[%d]: Unable to add items to the list "
			"since item size or count is zero.", AR_EOK);
		return AR_EOK;
	}

	/* Not enough space to add new items to this list */
	if (count > gen_list->max_count ||
		gen_list->count + count > gen_list->max_count)
	{
		ACDB_DBG("Warning[%d]: No enough space to add new items to list.");
		ACDB_DBG("List | max length %d.", gen_list->max_count);
		ACDB_DBG("List | current length %d.", gen_list->count);
		ACDB_DBG("List | number of items to add %d.", count);
		return AR_ENEEDMORE;
	}

	uint8_t* list_data = NULL;
	if (gen_list->count == 0)
	{
		list_data = (uint8_t*)gen_list->list;
	}
	else
	{
		list_data = (uint8_t*)gen_list->list + gen_list->element_size * gen_list->count;
	}

	ACDB_MEM_CPY_SAFE(list_data, item_size * count, items, item_size * count);
	gen_list->count += count;

	return AR_EOK;
}

int32_t AcdbGenericListFind(void* list, void* item, uint32_t item_size, uint32_t num_search_keys, AcdbGenericListItem* found_item)
{
	int32_t status = AR_EOK;
	AcdbGenericList* gen_list = (void*)list;
	if (IsNull(list) || IsNull(item) || IsNull(found_item))
		return AR_EBADPARAM;
	if (IsNull(gen_list->list))
		return AR_EFAILED;
	if (item_size == 0 || item_size != gen_list->element_size)
		return AR_EFAILED;

	uint32_t list_size = gen_list->element_size * gen_list->count;
	uint32_t item_index = 0;
	uint32_t num_struct_elements = item_size / sizeof(uint32_t);

	if (list_size == 0)
	{
		/* The list is empty */
		return AR_ENOTEXIST;
	}
	if (SEARCH_ERROR == AcdbDataBinarySearch2(
		gen_list->list, list_size,
		item, num_search_keys,
		num_struct_elements, &item_index))
	{
		return AR_ENOTEXIST;
	}

	found_item->index = item_index / num_struct_elements;
	found_item->item = (uint8_t*)gen_list->list + found_item->index * gen_list->element_size;

	return status;
}

int32_t AcdbGenericListSort(void* list, uint32_t key_elem_struct_position)
{
	int32_t status = AR_EOK;
	AcdbGenericList* gen_list = (void*)list;
	if (IsNull(list))
		return AR_EBADPARAM;
	if (IsNull(gen_list->list))
		return AR_EFAILED;

	size_t list_size = (size_t)(gen_list->element_size * gen_list->count);
	status = AcdbSort2(list_size, gen_list->list, gen_list->element_size, key_elem_struct_position);

	return status;
}

int32_t AcdbGenericListInit(AcdbGenericList* list, uint32_t element_size, uint32_t max_list_size, void** list_data)
{
	if (IsNull(list))
	{
		ACDB_ERR("Error[%d]: list input parameter is null", AR_EBADPARAM);
		return AR_EBADPARAM;
	}
	if (IsNull(list_data))
	{
		ACDB_ERR("Error[%d]: list_data input parameter is null", AR_EBADPARAM);
		return AR_EBADPARAM;
	}
	if (element_size == 0 || max_list_size == 0)
	{
		ACDB_DBG("Error[%d]: List max list size and/or element size cannot be zero", AR_EBADPARAM);
		return AR_EBADPARAM;
	}

	/* Set list properties */
	list->count = 0;
	list->element_size = element_size;
	list->max_count = max_list_size / element_size;
	list->list = list_data;

	/* Set function pointers */
	list->add_range = AcdbGenericListAddRange;
	list->find = AcdbGenericListFind;
	list->sort = AcdbGenericListSort;

	return AR_EOK;
}
