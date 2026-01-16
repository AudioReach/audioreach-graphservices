/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_util_list.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "ar_osal_mutex.h"
#include <malloc.h>

void * mutex_handle = NULL;
#define AR_NODES_MAX (10)

static void list_lock_enter_fn_t(void)
{
	if (NULL != mutex_handle)
	{
		if (AR_EOK != ar_osal_mutex_lock(mutex_handle))
		{
			AR_LOG_ERR(LOG_TAG,"failed to acquire mutex ");
		}
	}
}

static void list_lock_leave_fn_t(void)
{
	if (NULL != mutex_handle)
	{
		if (AR_EOK != ar_osal_mutex_unlock(mutex_handle))
		{
			AR_LOG_ERR(LOG_TAG,"failed to release mutex ");
		}
	}
}

void ar_test_util_list_main()
{
	int32_t status = AR_EOK;
	ar_list_node_t *nodes[AR_NODES_MAX] = { NULL };
	int32_t list_count = 0;
	ar_list_node_t *removed_node = NULL;
	ar_list_t test_list = {0};

	status = ar_osal_mutex_create(&mutex_handle);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"mutex creation failed %d ", status);
		goto end;
	}

	status = ar_list_init(&test_list, list_lock_enter_fn_t, list_lock_leave_fn_t);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"list init failed %d ", status);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG,"check if list is empty %d ", ar_list_is_empty(&test_list));
	AR_LOG_INFO(LOG_TAG,"list head 0x%p ", ar_list_get_head(&test_list));
	AR_LOG_INFO(LOG_TAG,"list tail 0x%p ", ar_list_get_tail(&test_list));

	for (list_count = 0; list_count < AR_NODES_MAX; )
	{
		nodes[list_count] = malloc(sizeof(ar_list_node_t));
		if (NULL == nodes[list_count])
		{
			AR_LOG_ERR(LOG_TAG,"node[%d] allocation failed ", list_count);
			status = AR_ENOMEMORY;
			goto end;
		}

		list_count++;

		status = ar_list_init_node(nodes[list_count - 1]);
		if (AR_EOK != status)
		{
			AR_LOG_ERR(LOG_TAG,"list node[%d] init failed %d ", list_count - 1, status);
			goto end;
		}
		AR_LOG_INFO(LOG_TAG,"list node[%d]:0x%p created ", list_count - 1, nodes[list_count - 1]);
	}

	for (int32_t i = 0; i < list_count; i++)
	{
		status = ar_list_add_tail(&test_list, nodes[i]);
		if (AR_EOK != status)
		{
			AR_LOG_ERR(LOG_TAG,"failed to add node[%d] to list err:%d ", i, status);
			goto end;
		}
		AR_LOG_INFO(LOG_TAG," node[%d][0x%p] added to the list ", i, nodes[i]);
	}
	AR_LOG_INFO(LOG_TAG,"list size %d ", test_list.size);

	status = ar_list_remove_head(&test_list, &removed_node);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to remove node from list head %d ", status);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG,"node[0x%p] removed from the list head ", removed_node);
	AR_LOG_INFO(LOG_TAG,"list size %d ", test_list.size);

	removed_node = NULL;
	status = ar_list_remove_head(&test_list, &removed_node);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to remove node from list head %d ", status);
		goto end;
	}
	AR_LOG_INFO(LOG_TAG,"node[0x%p] removed from the list head ", removed_node);
	AR_LOG_INFO(LOG_TAG,"delete node[0x%p] from the list", nodes[5]);
	AR_LOG_INFO(LOG_TAG,"list size %d ", test_list.size);

	status = ar_list_delete(&test_list, nodes[5]);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to delete node[0x%p], err: %d ", nodes[5], status);
	}

	AR_LOG_INFO(LOG_TAG,"node[0x%p] deleted from list ", nodes[5]);
	AR_LOG_INFO(LOG_TAG,"list size %d ", test_list.size);

	AR_LOG_INFO(LOG_TAG,"check if list is empty %d ", ar_list_is_empty(&test_list));
	AR_LOG_INFO(LOG_TAG,"list head 0x%p ", ar_list_get_head(&test_list));
	AR_LOG_INFO(LOG_TAG,"list tail 0x%p ", ar_list_get_tail(&test_list));


	status = ar_list_clear(&test_list);
	if (AR_EOK != status)
	{
		AR_LOG_ERR(LOG_TAG,"failed to clear the list ");
	}
	AR_LOG_INFO(LOG_TAG,"list cleared ");
	AR_LOG_INFO(LOG_TAG,"list size %d ", test_list.size);
end:
	for (int32_t i = 0; i < list_count; i++)
	{
		if (nodes[i])
		{
			AR_LOG_INFO(LOG_TAG," free node[%d][0x%p] ", i, nodes[i]);
			free(nodes[i]);
		}
	}
	if (NULL != mutex_handle)
	{
		ar_osal_mutex_destroy(mutex_handle);
		mutex_handle = NULL;
	}
	return;
}
