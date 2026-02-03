/**
 * \file ar_util_list.c
 * \brief
 *        This file contains the implementation for double linked list.
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_util_list.h"
#include "ar_osal_error.h"

 /* Verify that the header of the linking node points to itself. This helps
  * catch programming errors where the same node is inserted more than once on
  * a linked list.
  */
static int32_t ar_list_secure_node_is_unlinked(ar_list_t *list, ar_list_node_t *node)
{
	if ((list->en_secure) && ((node->next != node) || (node->prev != node)))
	{
		return AR_EBADPARAM;
	}

	return AR_EOK;
}

/* Verify that the header of the de-linking node is linked to a linked list.
 * This helps catch memory corruption issues, and programming errors where
 * the same node was inserted twice (i.e. init_node(node1),
 * insert(list1, node1), insert(list2, node1), error).
 */
static int32_t ar_list_node_is_linked(ar_list_node_t *node)
{
	if ((node->prev->next != node) || (node->next->prev != node))
	{
		return AR_EBADPARAM;
	}

	return AR_EOK;
}

static int32_t ar_list_insert_node_before(ar_list_t *list,
	ar_list_node_t *ref_node,
	ar_list_node_t *new_node)
{
	int32_t status = AR_EOK;

	status = ar_list_node_is_linked(ref_node);
	if (status != AR_EOK)
	{
		goto end;
	}

	status = ar_list_secure_node_is_unlinked(list, new_node);
	if (status != AR_EOK)
	{
		goto end;
	}

	new_node->list = list;
	ref_node->prev->next = new_node;
	new_node->prev = ref_node->prev;
	new_node->next = ref_node;
	ref_node->prev = new_node;

end:

	return status;
}

static int32_t ar_list_delete_node(ar_list_node_t *node)
{
	int32_t status = AR_EOK;

	status = ar_list_node_is_linked(node);
	if (status != AR_EOK)
	{
		goto end;
	}

	/* Verify that the header of the unlinking node was not already corrupted.
	 * This helps catch buffer overflow attacks targeting the linked list  */
	node->prev->next = node->next;
	node->next->prev = node->prev;
	node->prev = node;
	node->next = node;

end:
	return status;
}



static int32_t ar_list_is_not_empty(ar_list_t *list)
{
	return (list->dummy.next != &list->dummy);
}


/**
 * \brief ar_list_init: Initialize a list to itself.
 *       if lock_fn and unlock_fn are not provided
 *	     client has to synchronize the list operations.
 *
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
	ar_list_lock_leave_fn_t unlock_fn)
{
	int32_t status = AR_EOK;

	if (list == NULL)
	{
		status = AR_EBADPARAM;
		goto end;
	}

	list->dummy.prev = &list->dummy;
	list->dummy.next = &list->dummy;
	list->size = 0;
	list->en_secure = 1;
	list->unlock_fn = NULL;
	list->lock_fn = NULL;

	if ((NULL != lock_fn) && (NULL != unlock_fn))
	{
		list->lock_fn = lock_fn;
		list->unlock_fn = unlock_fn;
	}

end:
	return status;
}

/**
 * \brief ar_list_init_node: initialize the list node.
 *
 * \param[in] node: pointer to ar_list_node_t.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_init_node(ar_list_node_t *node)
{
	if (NULL == node)
	{
		return AR_EBADPARAM;
	}

	node->list = NULL;
	node->prev = node;
	node->next = node;

	return AR_EOK;
}
/**
 * \brief ar_list_add_tail: Add a node tot he tail of list.
 *
 * \param[in] list: pointer to ar_list_t.
 * \param[in] node: node to be added to the list.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_add_tail(ar_list_t *list, ar_list_node_t *node)
{
	int32_t status = AR_EOK;
	if ((list == NULL) || (node == NULL))
	{
		status = AR_EBADPARAM;
		goto end;
	}

	if (list->lock_fn)
	{
		list->lock_fn();
	}

	status = ar_list_insert_node_before(list, &list->dummy, node);
	if (AR_EOK == status)
	{
		list->size += 1;
	}

	if (list->unlock_fn)
	{
		list->unlock_fn();
	}
end:
	return status;
}
/**
 * \brief ar_list_remove_head: Remove a node from head of the list.
 *
 * \param[in] list: pointer to ar_list_t.
 * \param[out]ret_node: pointer to the removed node.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_remove_head(ar_list_t *list, ar_list_node_t **ret_node)
{
	int32_t status = AR_EOK;
	ar_list_node_t *node = NULL;

	if (list == NULL || ret_node == NULL)
	{
		status = AR_EBADPARAM;
		goto end;
	}

	if (list->lock_fn)
	{
		list->lock_fn();
	}

	if (ar_list_is_empty(list))
	{
		if (list->unlock_fn)
		{
			list->unlock_fn();
		}
		status = AR_ENOTEXIST;
		goto end;
	}

	node = list->dummy.next;

	status = ar_list_delete_node(node);
	if (AR_EOK != status)
	{
		if (list->unlock_fn)
		{
			list->unlock_fn();
		}
		goto end;
	}

	list->size -= 1;
	if (list->unlock_fn)
	{
		list->unlock_fn();
	}

	*ret_node = node;

end:
	return status;
}


/**
 * \brief ar_list_delete: delete a node from list.
 *
 * \param[in] list: pointer to ar_list_t.
 * \param[in] node: pointer to node to be deleted.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_delete(ar_list_t *list, ar_list_node_t *node)
{
	int32_t status = AR_EOK;

	if (list == NULL || node == NULL)
	{
		status = AR_EBADPARAM;
		goto end;
	}

	if (list->lock_fn)
	{
		list->lock_fn();
	}

	status = ar_list_delete_node(node);
	if (AR_EOK != status)
	{
		if (list->unlock_fn)
		{
			list->unlock_fn();
		}
		goto end;
	}

	list->size -= 1;
	if (list->unlock_fn)
	{
		list->unlock_fn();
	}

end:
	return status;
}
/**
 * \brief ar_list_clear: clear the list
 *
 * \param[in] list: pointer to ar_list_t.
 *
 * \return
 *  0 -- Success
 *  Nonzero -- Failure
 */
int32_t ar_list_clear(ar_list_t *list)
{
	int32_t status = AR_EOK;
	ar_list_node_t *node = NULL;

	if (list == NULL)
	{
		status = AR_EBADPARAM;
		goto end;
	}

	if (list->lock_fn)
	{
		list->lock_fn();
	}

	while (ar_list_is_not_empty(list))
	{
		node = list->dummy.next;
		status = ar_list_delete_node(node);
		if (AR_EOK != status)
		{
			if (list->unlock_fn)
			{
				list->unlock_fn();
			}
			goto end;
		}
	}
	list->size = 0;
	if (list->unlock_fn)
	{
		list->unlock_fn();
	}

end:
	return status;
}
