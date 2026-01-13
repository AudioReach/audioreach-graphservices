#ifndef AR_UTIL_LIST_H
#define AR_UTIL_LIST_H

/**
 * \file ar_util_list.h
 * \brief
 *        Defines public AudioReach UTIL APIs for double linked list.
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_types.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef struct ar_list_node_t ar_list_node_t;
typedef struct ar_list_t ar_list_t;

typedef void (*ar_list_lock_enter_fn_t)(void);
typedef void (*ar_list_lock_leave_fn_t)(void);

struct ar_list_node_t
{
	/**< Indicates the last known list for which this node belonged. */
	ar_list_t *list;
	/**< The previous node. */
	ar_list_node_t *prev;
	/**< The next node. */
	ar_list_node_t *next;
};

struct ar_list_t
{
	/**< A special dummy node to implement the NULL object pattern. */
	ar_list_node_t dummy;
	/**< The number of nodes linked to this linked list. */
	uint32_t size;
	/**< Optional, the user supplied lock implementation function. */
	ar_list_lock_enter_fn_t lock_fn;
	/**< optional, the user supplied unlock implementation function. */
	ar_list_lock_leave_fn_t unlock_fn;
	/**< Enable secure linked list flag. */
	bool_t en_secure;
};

/** ar_list_for_each_entry: iterate over list */
#define ar_list_for_each_entry(iter, list)   \
	for (iter = (list)->dummy.next; \
	iter != &((list)->dummy); iter = iter->next) 

/**
 * \brief ar_list_init: initialize a list to itself.
 *       if lock_fn and unlock_fn are not provided 
 *	     client has to synchronize the list operations.
 * \param[in] list: pointer to ar_list_t. 
 * \param[in_opt] lock_fn: lock function pointer.
 * \param[in_opt] unlock_fn: unlock function pointer.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_init(ar_list_t *list,
	ar_list_lock_enter_fn_t lock_fn,
	ar_list_lock_leave_fn_t unlock_fn);

/**
 * \brief ar_list_init_node
 *
 * \param[in] node: pointer to ar_list_node_t.  
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */                       
int32_t ar_list_init_node(ar_list_node_t *node);

/**
 * \brief ar_list_add_tail
 *
 * \param[in] list: pointer to ar_list_t. 
 * \param[in] node: node to be added to the list.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_add_tail(ar_list_t *list, ar_list_node_t *node);

/**
 * \brief ar_list_remove_head
 *
 * \param[in] list: pointer to ar_list_t. 
 * \param[out]ret_node: pointer to the removed node.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_remove_head(ar_list_t *list, ar_list_node_t **ret_node);

/**
 * \brief ar_list_delete
 *
 * \param[in] list: pointer to ar_list_t. 
 * \param[in] node: pointer to node to be deleted.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_delete(ar_list_t *list, ar_list_node_t *node);

/**
 * \brief ar_list_clear
 *
 * \param[in] list: pointer to ar_list_t.  
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_clear(ar_list_t *list);

/**
* \brief ar_list_is_empty: check if the list is empty.
*
* \param[in] list: pointer to ar_list_t.
*
* \return
*  1 if the list is empty
*  0 otherwise
*/
static inline int32_t ar_list_is_empty(ar_list_t *list)
{
	return (list->dummy.next == &list->dummy);
}

/**
* \brief ar_list_get_head: return the head node from list.
*
* \param[in] list: pointer to ar_list_t.
*
* \return
*  address of head node
*/
static inline ar_list_node_t* ar_list_get_head(ar_list_t *list)
{
	return list->dummy.next;
}

/**
* \brief ar_list_get_tail: return the tail node from list.
*
* \param[in] list: pointer to ar_list_t.
*
* \return
*  address of tail node
*/
static inline ar_list_node_t* ar_list_get_tail(ar_list_t *list)
{
	return list->dummy.prev;
}

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* AR_UTIL_LIST_H */
