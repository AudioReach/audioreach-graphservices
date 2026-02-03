/**
*==============================================================================
* \file acdb_heap.h
*
* \brief
*      Manages the calibration data set by ACDB SW clients in RAM.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#include <stdio.h>
#include "acdb_heap.h"
#include "acdb_common.h"
#include "acdb_context_mgr.h"
#include "acdb_types.h"

/* ---------------------------------------------------------------------------
* Preprocessor Definitions and Constants
*--------------------------------------------------------------------------- */

#define ACDB_MAX(a,b) (((a) > (b)) ? (a) : (b))
#define ACDB_MIN(a,b) (((a) < (b)) ? (a) : (b))
#define HEX_DIGITS 8
#define ACDB_MAX_ACDB_FILES 16

/**< A File Manager macro that simplifies accessing the database info within the
 * File Manager context structure.
 *
 * This macro represents the database info at the current index set in
 * acdb_file_man_context.database_index
 *
 * NOTE: The acdb_file_man_context.database_index must me non-zero and initialized
 * before using this macro
 */
#define ACDB_HEAP_DB_INFO acdb_heap_context \
.heap_info[acdb_heap_context.active_heap_index]

 /**< A File Manager macro that simplifies accessing the database info within the
  * File Manager context structure.
  *
  * Specify the index of the database info to retrieve
  *
  * NOTE: This macro is mainly used in for loops when cycling through
  * databases info entries
  */
#define ACDB_HEAP_DB_INFO_AT_INDEX(index) acdb_heap_context \
.heap_info[index]

/* ---------------------------------------------------------------------------
* Type Declarations
*--------------------------------------------------------------------------- */

typedef struct _acdb_heap_info_t AcdbHeapInfo;
struct _acdb_heap_info_t
{
    /**< The virtual machine id used by the database */
    uint32_t vm_id;
    /**< The index of the associated database */
    int32_t database_index;
    /**< Root of the associated tree */
    AcdbTreeNode* root;
};

typedef struct _acdb_heap_context_t AcdbHeapContext;
struct _acdb_heap_context_t
{
    ar_osal_mutex_t heap_lock;
    /**< The index of the heap currently being accessed */
    int32_t active_heap_index;
    /**< Number of active delta data heaps */
    int32_t heap_count;
    /**< List of heap information */
    AcdbHeapInfo *heap_info[MAX_ACDB_FILE_COUNT];
};

/* ---------------------------------------------------------------------------
* Static Variable Definitions
*--------------------------------------------------------------------------- */

static AcdbHeapContext acdb_heap_context;

/* ---------------------------------------------------------------------------
* Function Prototypes
*--------------------------------------------------------------------------- */

int32_t acdb_heap_clear(acdb_heap_handle_t handle);

/* ---------------------------------------------------------------------------
* Helper functions
*--------------------------------------------------------------------------- */

/**
* \breif
*	Converts a key vector to a string.
*	Caller is responsible for freeing the returned string pointer
*
* \return pointer to key vector string on succes, null on failure
*/
char *acdb_heap_key_vector_to_string(
    const AcdbGraphKeyVector *key_vector, size_t *sz_str_key_vector)
{
	/* Example
	Format	: <key, value>...<key, value>
	Input	: <0xA, 0x1><0xB, 0x1><0xC, 0x1>
	Output  : 'A1B1C1' in Big Endian
	*/
	if (IsNull(key_vector)) return NULL;

	uint32_t offset = 0;
	//Max Key Vector String length = 8 * 2 * key_vector->num_keys;
	size_t str_size = 0;
	//8 Hex Digits in 32-bit integer * 2 members in <key,value>
    uint32_t sz_str_kv_pair = 16 + 1;
	char tmp[16 + 1] = "";
	char *key_vector_str = NULL;

	for (uint32_t i = 0; i < key_vector->num_keys; i++)
	{
        if (0 > ar_sprintf(tmp, sz_str_kv_pair, "%08x%08x",
            key_vector->graph_key_vector[i].key,
            key_vector->graph_key_vector[i].value))
        {
            return NULL;
        }
        str_size += ar_strlen(tmp, (size_t)sz_str_kv_pair);
	}

	str_size += 1;// '\0'

	key_vector_str = ACDB_MALLOC(char, str_size);
	if (IsNull(key_vector_str)) return NULL;
	memset(key_vector_str, 0, str_size);

	for (uint32_t i = 0; i < key_vector->num_keys; i++)
	{
        if (key_vector_str + offset < key_vector_str + str_size)
        {
            if (0 > ar_sprintf(key_vector_str + offset, sz_str_kv_pair,
                "%08x%08x",
                key_vector->graph_key_vector[i].key,
                key_vector->graph_key_vector[i].value))
            {
                ACDB_FREE(key_vector_str);
                return NULL;
            }
            offset = (uint32_t)ar_strlen(key_vector_str, str_size);
        }
	}

	*sz_str_key_vector = offset;
	return key_vector_str;
}

/**
* \breif
*	Get Calibration or Tag Key Vector from the KV to Subgraph Map
*
* \param[in/out] map: map to extract key vector from
* \return pointer to key vector
*/
AcdbGraphKeyVector *get_key_vector_from_map(
    acdb_delta_data_map_t* map)
{
    AcdbGraphKeyVector *kv = NULL;

    if (IsNull(map))
        return NULL;

    if (IsNull(map->key_vector_data))
        return NULL;

    switch (map->key_vector_type)
    {
    case TAG_KEY_VECTOR:
        kv = &((AcdbModuleTag*)map->key_vector_data)->tag_key_vector;
        break;
    case CAL_KEY_VECTOR:
        kv = ((AcdbGraphKeyVector*)map->key_vector_data);
        break;
    default:
        break;
    }

    return kv;
}

bool_t acdb_tree_is_leaf(AcdbTreeNode *tnode)
{
    if (tnode == NULL)
        return FALSE;

    //or if the depth of the node is zero

    //No left or right subtrees, but has a parent, so it must be a leaf
    if (IsNull(tnode->left) && IsNull(tnode->right) &&
        !IsNull(tnode->parent))
    {
        return TRUE;
    }
    return FALSE;
}

bool_t acdb_tree_is_tree_empty(AcdbTreeNode *root)
{
    if (IsNull(root) ||
        (IsNull(root->p_struct) &&
            IsNull(root->left) &&
            IsNull(root->right) &&
            IsNull(root->parent)))
    {
        return TRUE;
    }
    return FALSE;
}

bool_t acdb_tree_is_tree(AcdbTreeNode *tnode)
{
    return !acdb_tree_is_leaf(tnode);
}

bool_t acdb_tree_is_balanced(AcdbTreeNode *tnode, int32_t *factor)
{
    //difference = right.depth - left.depth
    //-1 - left heavy
    // 0 - balanced
    // 1 - right heavy
    int32_t diff = 0;

    //if both left and right are non-null this is the equivalent of
    //diff = tnode->right->depth - tnode->left->depth;
    if (!acdb_tree_is_leaf(tnode))
    {
        if (!IsNull(tnode->right))
        {
            diff += tnode->right->depth;
        }
        if (!IsNull(tnode->left))
        {
            diff += -1 * tnode->left->depth;
        }
    }

    *factor = diff;

    if (diff < -1 || diff > 1)
        return FALSE;

    return TRUE;
}

void acdb_tree_update_depth(AcdbTreeNode *tnode)
{
    AcdbTreeNode *p_cur_node;
    p_cur_node = tnode;

    while (p_cur_node != NULL)
    {
        if (IsNull(p_cur_node))
        {
            break;
        }

        if (!acdb_tree_is_leaf(p_cur_node) && !IsNull(p_cur_node))
        {
            if (IsNull(p_cur_node->right))
            {
                p_cur_node->depth = 1 + p_cur_node->left->depth;
            }
            else if (IsNull(p_cur_node->left))
            {
                p_cur_node->depth = 1 + p_cur_node->right->depth;
            }
            else
            {
                p_cur_node->depth = 1 + ACDB_MAX(p_cur_node->left->depth, p_cur_node->right->depth);
            }
        }
        else if (acdb_tree_is_leaf(p_cur_node) && !IsNull(p_cur_node))
        {
            p_cur_node->depth = 1;
        }

        p_cur_node = p_cur_node->parent;
    }

    p_cur_node = NULL;
}

int32_t acdb_tree_direction(AcdbTreeNode *p_x, AcdbTreeNode *p_y)
{
    if (IsNull(p_x) || IsNull(p_y))
    {
        return TREE_DIR_NONE;
    }
    if (IsNull(p_x->p_struct) || IsNull(p_y->p_struct))
    {
        return TREE_DIR_NONE;
    }

    int32_t direction = strcmp(
        ((KVSubgraphMapBin*)p_x->p_struct)->str_key_vector,
        ((KVSubgraphMapBin*)p_y->p_struct)->str_key_vector);

    if (direction < 0)
    {
        return TREE_DIR_LEFT;
    }
    else if (direction > 0)
    {
        return TREE_DIR_RIGHT;
    }

    return TREE_DIR_NONE;
}

void acdb_tree_rotate_right(AcdbTreeNode *p_a, AcdbTreeNode *p_c)
{
    //Left heavy means right rotation
    //rotate right
    //    a
    //  b     =>  b
    //c         c   a

    AcdbTreeNode *p_b = p_c->parent;

    p_b->parent = p_a->parent;
    p_a->parent = p_b;

    if (!IsNull(p_b->right))
    {
        p_b->right->parent = p_a;
    }

    p_a->left = p_b->right;
    p_b->right = p_a;

    if (TREE_DIR_LEFT == acdb_tree_direction(p_b, p_b->parent))
    {
        p_b->parent->left = p_b;
    }
    else if (TREE_DIR_RIGHT == acdb_tree_direction(p_b, p_b->parent))
    {
        p_b->parent->right = p_b;
    }

    acdb_tree_update_depth(p_a);
    acdb_tree_update_depth(p_c);
}

void acdb_tree_rotate_left(AcdbTreeNode *p_a, AcdbTreeNode *p_c)
{
    //Right heavy means left rotation
    //rotate left
    //a
    //  b     =>     b
    //   c         a   c
    AcdbTreeNode *p_b = p_c->parent;

    p_b->parent = p_a->parent;
    p_a->parent = p_b;

    if (!IsNull(p_b->left))
    {
        p_b->left->parent = p_a;
    }

    p_a->right = p_b->left;
    p_b->left = p_a;

    if (TREE_DIR_LEFT == acdb_tree_direction(p_b, p_b->parent))
    {
        p_b->parent->left = p_b;
    }
    else if (TREE_DIR_RIGHT == acdb_tree_direction(p_b, p_b->parent))
    {
        p_b->parent->right = p_b;
    }

    acdb_tree_update_depth(p_a);
    acdb_tree_update_depth(p_c);
}

void acdb_tree_rotate(AcdbTreeNode *p_a, AcdbTreeNode *p_c, int32_t factor)
{
    //a - grand parent
    //b - parent
    //c - child
    AcdbTreeNode *p_b = p_c->parent;

    //Single Rotation (Left, Right)
    if (factor < -1 && TREE_DIR_LEFT == acdb_tree_direction(p_c, p_b))
    {
        acdb_tree_rotate_right(p_a, p_c);
    }
    else if (factor > 1 && TREE_DIR_RIGHT == acdb_tree_direction(p_c, p_b))
    {
        acdb_tree_rotate_left(p_a, p_c);
    }

    //Double Rotation (Left-Right, Right-Left)
    else if (factor < -1 && TREE_DIR_RIGHT == acdb_tree_direction(p_c, p_b))
    {
        //Left heavy means right rotation
        //Left-Right, rotate left, the rotate right
        //    a         a
        //  b     =>  c      =>    c
        //    c     b            b   a
        //rotate_left(p_b, p_c);

        p_c->parent = p_b->parent;
        p_b->parent = p_c;
        p_a->left = p_c;

        p_b->right = p_c->left;
        p_c->left = p_b;

        acdb_tree_rotate_right(p_a, p_b);
    }
    else if (factor > 1 && TREE_DIR_LEFT == acdb_tree_direction(p_c, p_b))
    {
        //Right heavy means left rotation
        //Right-Left, rotate right, the rotate left
        //a           a
        //  b     =>    c      =>    c
        //c               b        a   b
        //rotate_right(p_b, p_c);

        p_c->parent = p_b->parent;
        p_b->parent = p_c;
        p_a->right = p_c;

        p_b->left = p_c->right;
        p_c->right = p_b;

        acdb_tree_rotate_left(p_a, p_b);
    }
}

int32_t acdb_stack_push(LinkedList* stack, LinkedListNode* node)
{
    if (stack->length == 0)
    {
        stack->p_head = node;

        stack->p_tail = node;

        stack->length++;
    }
    else
    {
        //get what head is currently pointing to and point it to the inserted bin_node
        //stack->p_head->p_next = node;

        node->p_next = stack->p_head;
        //set the inserted bin_node to tail
        stack->p_head = node;

        stack->length++;
    }

    return 0;
}

int32_t acdb_stack_pop(LinkedList* stack, LinkedListNode** node)
{
    //(*node)->p_struct = stack->p_head->p_struct;
    *node = stack->p_head;

    if (!IsNull(stack->p_head->p_next))
    {
        stack->p_head = stack->p_head->p_next;
    }
    else
    {
        stack->p_head = NULL;
        stack->p_tail = NULL;
    }

    if (stack->length != 0)
    {
        stack->length--;
    }

    return 0;
}

KVSubgraphMapBin *acdb_heap_create_map_bin(void)
{
    KVSubgraphMapBin *bin = ACDB_MALLOC(KVSubgraphMapBin, 1);

    if (IsNull(bin))
        return NULL;

    bin->str_key_vector_size = 0;
    bin->str_key_vector = NULL;
    bin->map = NULL;

    return bin;
}

AcdbTreeNode *acdb_heap_create_tree_node(void *p_struct)
{
    AcdbTreeNode *bin_node = ACDB_MALLOC(AcdbTreeNode, 1);

    if (IsNull(bin_node))
        return NULL;

    bin_node->depth = 1;
    bin_node->left = NULL;
    bin_node->right = NULL;
    bin_node->parent = NULL;
    bin_node->p_struct = p_struct;

    return bin_node;
}

LinkedListNode *acdb_heap_create_list_node(void *p_struct)
{
    LinkedListNode *lnode = ACDB_MALLOC(LinkedListNode, 1);

    if (lnode == NULL) return NULL;

    lnode->p_next = NULL;
    lnode->p_struct = p_struct;

    return lnode;
}

void acdb_heap_free_persistance_data(
    AcdbDeltaPersistanceData *persistance_data)
{
    if (IsNull(persistance_data)) return;

    AcdbDeltaModuleCalData *p_cal_data = NULL;
    LinkedListNode *cur_node = persistance_data->cal_data_list.p_head;

    while (!(IsNull(cur_node)))
    {
        if (!IsNull(cur_node->p_struct))
        {
            p_cal_data = ((AcdbDeltaModuleCalData*)cur_node->p_struct);
            ACDB_FREE((uint8_t*)p_cal_data->param_payload);
            ACDB_FREE(p_cal_data);
        }

        cur_node = cur_node->p_next;
    }

    AcdbListClear(&persistance_data->cal_data_list);

    p_cal_data = NULL;
    cur_node = NULL;
}

void acdb_heap_free_key_vector_data(KeyVectorType key_vector_type,
    void* key_vector_data)
{
    AcdbKeyValuePair* kv_pair = NULL;
    if (IsNull(key_vector_data)) return;

    switch (key_vector_type)
    {
    case TAG_KEY_VECTOR:
        kv_pair = ((AcdbModuleTag*)
            key_vector_data)->tag_key_vector.graph_key_vector;

        if(!IsNull(kv_pair)) ACDB_FREE(kv_pair);

        break;
    case CAL_KEY_VECTOR:
        kv_pair = ((AcdbGraphKeyVector*)
            key_vector_data)->graph_key_vector;

        if (!IsNull(kv_pair)) ACDB_FREE(kv_pair);

        break;
    default:
        return;
    }

    ACDB_FREE(key_vector_data);
}

void acdb_heap_free_subgraph_data(AcdbDeltaSubgraphData* subgraph_data)
{
    if (IsNull(subgraph_data)) return;

    acdb_heap_free_persistance_data(&subgraph_data->non_global_data);
    acdb_heap_free_persistance_data(&subgraph_data->global_data);
    ACDB_FREE(subgraph_data);
}

void acdb_heap_free_map(acdb_delta_data_map_t *map)
{
    if (IsNull(map)) return;

    //AcdbDeltaModuleCalData *p_cal_data = NULL;
    LinkedListNode *sg_data_node = NULL;
    AcdbDeltaSubgraphData *sg_data = NULL;

    sg_data_node = map->subgraph_data_list.p_head;

    do
    {
        if (IsNull(sg_data_node)) break;

        sg_data = (AcdbDeltaSubgraphData*)sg_data_node->p_struct;
        acdb_heap_free_persistance_data(&sg_data->non_global_data);
        acdb_heap_free_persistance_data(&sg_data->global_data);
        ACDB_FREE(sg_data);

    } while (TRUE != AcdbListSetNext(&sg_data_node));

    AcdbListClear(&map->subgraph_data_list);

    acdb_heap_free_key_vector_data(map->key_vector_type, map->key_vector_data);
    ACDB_FREE(map);
}

void acdb_heap_free_bin(KVSubgraphMapBin **bin)
{
    acdb_heap_free_map((*bin)->map);
    ACDB_FREE((*bin)->str_key_vector);
    ACDB_FREE(*bin);
    *bin = NULL;
}

/**
* \breif acdb_heap_insert
*	Insert a node into the tree
*
* \return 0 on succes, non-zero on failure
*/
int32_t acdb_heap_insert(acdb_heap_handle_t handle, AcdbTreeNode *tnode)
{
    int32_t factor = 0;
    AcdbTreeNode *t = NULL;
    AcdbTreeNode *u = NULL;
    AcdbHeapInfo* db_heap = NULL;

    if (IsNull(handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle;
    t = db_heap->root;

    if (TRUE == acdb_tree_is_tree_empty(t))
    {
        db_heap->root = tnode;
        return 0;
    }

    while (TRUE)
    {
        if (TREE_DIR_LEFT == acdb_tree_direction(tnode, t))
        {
            if (t->left == NULL)
            {
                t->left = tnode;
                tnode->parent = t;
                acdb_tree_update_depth(t);
                break;
            }
            else
            {
                t = t->left;
            }
        }
        else if (TREE_DIR_RIGHT == acdb_tree_direction(tnode, t))
        {
            if (t->right == NULL)
            {
                t->right = tnode;
                tnode->parent = t;
                acdb_tree_update_depth(t);
                break;
            }
            else
            {
                t = t->right;
            }
        }
        else
        {
            break;
        }
    }

    //Check balance and rotate when nessesary. Set the new root
    u = tnode;
    while (t != NULL)
    {
        if (acdb_tree_is_balanced(t, &factor))
        {
            if (t->parent == NULL)
            {
                db_heap->root = t;
            }

            if (t->depth - u->depth >= 2)
            {
                u = u->parent;
            }

            t = t->parent;
        }
        else
        {
            //t - grandparent
            //  - parent
            //u - child
            acdb_tree_rotate(t, u, factor);
        }
    }

    return AR_EOK;
}

//int32_t acdb_heap_remove(TreeNode *tnode)
//{
//	int32_t status = AR_ENOTIMPL;
//	//the reverse of insert
//	//copy the same code but instead of inserting the node, ACDB_FREE the memory associated with the node
//	return status;
//}

int32_t acdb_heap_get_bin(acdb_heap_handle_t handle,
    size_t size_str_key_vector,
    char* str_key_vector, KVSubgraphMapBin **bin)
{
    int32_t status = AR_EOK;
    int32_t tree_dir = TREE_DIR_NONE;
    AcdbTreeNode *t = NULL;
    AcdbTreeNode tnode;
    KVSubgraphMapBin tmp_bin;
    AcdbHeapInfo* db_heap = NULL;

    if (IsNull(handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle;
    t = db_heap->root;

    if (TRUE == acdb_tree_is_tree_empty(t))
    {
        return AR_ENOTEXIST;
    }

    tmp_bin.str_key_vector = str_key_vector;
    tmp_bin.str_key_vector_size = (uint32_t)(size_str_key_vector);
    tnode.depth = 1;
    tnode.left = NULL;
    tnode.right = NULL;
    tnode.parent = NULL;
    tnode.p_struct = &tmp_bin;

    while (TRUE)
    {
        tree_dir = acdb_tree_direction(&tnode, t);

        switch (tree_dir)
        {
        case TREE_DIR_LEFT:
        {
            if (t->left == NULL)
            {
                status = AR_ENOTEXIST;
                break;
            }

            t = t->left;
            break;
        }
        case TREE_DIR_RIGHT:
        {
            if (t->right == NULL)
            {
                status = AR_ENOTEXIST;
                break;
            }

            t = t->right;
            break;
        }
        case TREE_DIR_NONE:
        {
            *bin = (KVSubgraphMapBin*)t->p_struct;
            break;
        }
        default:
            break;
        }

        if (TREE_DIR_NONE == tree_dir ||
            AR_EOK != status) break;
    }

    tmp_bin.str_key_vector = NULL;
    tmp_bin.str_key_vector_size = 0;
    t = NULL;

    return status;
}

/* ---------------------------------------------------------------------------
* IOCTL Command Functions
*--------------------------------------------------------------------------- */

int32_t acdb_heap_init(void)
{
    int32_t status = AR_EOK;

    if (!acdb_heap_context.heap_lock)
    {
        status = ar_osal_mutex_create(&acdb_heap_context.heap_lock);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: failed to create acdb client mutex",
                status);
        }
    }
    return status;
}

int32_t acdb_heap_add_database(uint32_t vm_id, acdb_heap_handle_t *handle)
{
    int32_t status = AR_EOK;
    int32_t index = 0;

    ACDB_MUTEX_LOCK(acdb_heap_context.heap_lock);

    /* find next avalible slot */
    for (index = 0; index < MAX_ACDB_FILE_COUNT; index++)
    {
        if (IsNull(acdb_heap_context.heap_info[index]))
            break;
    }

    if (MAX_ACDB_FILE_COUNT == index)
        index--;

    acdb_heap_context.heap_count++;
    acdb_heap_context.heap_info[index] = ACDB_MALLOC(AcdbHeapInfo, 1);

    ACDB_MUTEX_UNLOCK(acdb_heap_context.heap_lock);

    ar_mem_set(acdb_heap_context.heap_info[index], 0, sizeof(AcdbHeapInfo));

    acdb_heap_context.heap_info[index]->vm_id = vm_id;

    *handle = acdb_heap_context.heap_info[index];
    return status;
}

int32_t acdb_heap_remove_database(acdb_heap_handle_t *handle)
{
    int32_t status = AR_EOK;
    AcdbHeapInfo* db_heap = NULL;

    if (IsNull(handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle;

    if (IsNull(db_heap))
        return AR_EBADPARAM;

    status = acdb_heap_clear((acdb_heap_handle_t)db_heap);
    if (AR_FAILED(status))
    {
        ACDB_DBG("Error[%d]: Failed to clear heap for VM ID %d",
            status, db_heap->vm_id);
    }

    acdb_heap_context.heap_info[db_heap->database_index] = NULL;
    ACDB_FREE(db_heap);

    ACDB_MUTEX_LOCK(acdb_heap_context.heap_lock);

    if(acdb_heap_context.heap_count > 0)
        acdb_heap_context.heap_count--;

    ACDB_MUTEX_UNLOCK(acdb_heap_context.heap_lock);

    return status;
}

int32_t acdb_heap_add_delta_data_map(
    bool_t should_use_active_handle,
    acdb_heap_map_handle_info_t* info)
{
    int32_t status = AR_EOK;
    size_t size_str_key_vector = 0;
    char_t* str_key_vector = NULL;
    AcdbTreeNode* bin_node = NULL;
    KVSubgraphMapBin* bin = NULL;
    AcdbGraphKeyVector *map_key_vector = NULL;
    acdb_context_handle_t *ctx_handle = NULL;
    acdb_heap_handle_t heap_handle = NULL;

    if (IsNull(info))
        return AR_EBADPARAM;

    ctx_handle = acdb_ctx_man_get_active_handle();

    if (should_use_active_handle && IsNull(ctx_handle))
        return AR_EHANDLE;

    heap_handle = should_use_active_handle?
        ctx_handle->heap_handle: info->handle;

    if (IsNull(heap_handle))
        return AR_EHANDLE;

    map_key_vector = get_key_vector_from_map(info->map);

    if (IsNull(map_key_vector))
        return AR_EBADPARAM;

    str_key_vector = acdb_heap_key_vector_to_string(
        map_key_vector, &size_str_key_vector);

    /* Check to see if Tree has the appropriate bin
     * Locate bin and append to linked list */
    status = acdb_heap_get_bin(heap_handle,
        size_str_key_vector, str_key_vector, &bin);
    if (AR_SUCCEEDED(status))
    {
        goto end;
    }
    else
    {
        //Create new bin and insert into tree
        bin = acdb_heap_create_map_bin();
        if (IsNull(bin))
        {
            status = AR_ENOMEMORY;
            goto end;
        }

        bin_node = acdb_heap_create_tree_node(bin);
        if (IsNull(bin_node))
        {
            status = AR_ENOMEMORY;
            goto end;
        }

        bin->str_key_vector = str_key_vector;
        bin->str_key_vector_size = (uint32_t)(size_str_key_vector);
        bin->map = info->map;

        acdb_heap_insert(heap_handle, bin_node);
        status = AR_EOK;
    }

end:
    if (AR_FAILED(status))
    {
        ACDB_FREE(bin_node);
        ACDB_FREE(bin);
        ACDB_FREE(str_key_vector);
    }

    return status;
}

int32_t acdb_heap_get_ckv_subgraph_map(
    const AcdbGraphKeyVector *cal_key_vector,
    acdb_delta_data_map_t** map)
{
    int32_t status = AR_EOK;
    KVSubgraphMapBin *bin = NULL;
    AcdbGraphKeyVector *map_key_vector = NULL;
    acdb_delta_data_map_t *tmp_map = NULL;
    size_t size_str_key_vector = 0;
    acdb_context_handle_t* handle = NULL;
    char* str_key_vector = NULL;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle) || IsNull(handle->heap_handle))
        return AR_EHANDLE;

    str_key_vector = acdb_heap_key_vector_to_string(
        cal_key_vector, &size_str_key_vector);

    status = acdb_heap_get_bin(handle->heap_handle,
        size_str_key_vector, str_key_vector, &bin);

    if (AR_EOK != status)
    {
        //ACDB_ERR("Key Vector not found in heap");
        //LogKeyVector(cal_key_vector);
        goto end;
    }

    tmp_map = (acdb_delta_data_map_t*)bin->map;

    if (IsNull(tmp_map->key_vector_data))
    {
        if (!IsNull(str_key_vector))
            ACDB_DBG("Map key vector data is null for "
                "Key Vector<%s>", str_key_vector);
        status = AR_ENOTEXIST;
        goto end;
    }

    switch (tmp_map->key_vector_type)
    {
    case TAG_KEY_VECTOR:
        map_key_vector = &((AcdbModuleTag*)tmp_map->key_vector_data)->tag_key_vector;
        break;
    case CAL_KEY_VECTOR:
        map_key_vector = ((AcdbGraphKeyVector*)tmp_map->key_vector_data);
        break;
    default:
        if (!IsNull(str_key_vector))
            ACDB_DBG("Unable to determine Key Vector type "
                "for Key Vector<%s>", str_key_vector);
        status = AR_ENOTEXIST;
        goto end;
    }

    //Compare Sorted Key Vectors and values
    if (0 == ACDB_MEM_CMP(
        cal_key_vector->graph_key_vector,
        map_key_vector->graph_key_vector,
        map_key_vector->num_keys * sizeof(AcdbKeyValuePair)))
    {
        *map = tmp_map;
        tmp_map = NULL;
    }

    if (IsNull(*map))
    {
        if(!IsNull(str_key_vector))
            ACDB_DBG("KV Map does not exist for "
                "Key Vector<%s>", str_key_vector);
        status = AR_ENOTEXIST;
    }

    end:
    if (!IsNull(str_key_vector))
    {
        ACDB_FREE(str_key_vector);
        str_key_vector = NULL;
    }

    return status;
}

/**
* \brief  acdb_heap_get_map_list
*           Returns an aggregated list of all the maps in the tree using an
*			inoder tree traversal(Left, Root, Right). Each node in map_list must be freed by caller.
* \param[out] map_list: A linked list of CKV Bin linked lists
*
* \return
* 0 -- Success
* Nonzero -- Failure
*/
int32_t acdb_heap_get_map_list(LinkedList **map_list)
{
    int32_t status = AR_EOK;
    AcdbTreeNode *cur_node = NULL;
    LinkedListNode *item_node = NULL;
    LinkedList stack = { 0 };
    acdb_context_handle_t* handle = NULL;
    AcdbHeapInfo* db_heap = NULL;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle) || IsNull(handle->heap_handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle->heap_handle;
    cur_node = db_heap->root;

    if (IsNull(*map_list)) return AR_EBADPARAM;

    while (cur_node != NULL || stack.length != 0)
    {
        if (!IsNull(cur_node))
        {
            item_node = acdb_heap_create_list_node(cur_node);
            if (IsNull(item_node))
            {
                return AR_ENOMEMORY;
            }
            acdb_stack_push(&stack, item_node);
            cur_node = cur_node->left;
            continue;
        }

        if (IsNull(cur_node) && stack.length > 0)
        {
            acdb_stack_pop(&stack, &item_node);
            cur_node = (AcdbTreeNode*)item_node->p_struct;
            ACDB_FREE(item_node);

            //Collect Key Vector Subgraph Maps and add/append to list
            LinkedListNode *node = acdb_heap_create_list_node(
                ((KVSubgraphMapBin*)cur_node->p_struct)->map);
			if (IsNull(node))
			{
				return AR_ENOMEMORY;
			}
            AcdbListAppend(*map_list, node);
            cur_node = cur_node->right;
        }
    }

    return status;
}

/**
* \brief  acdb_heap_clear
*           Clears all heap data in an inoder fashion
* \return
* 0 -- Success
* Nonzero -- Failure
*/
int32_t acdb_heap_clear(acdb_heap_handle_t handle)
{
    AcdbTreeNode *cur_node = NULL;
    AcdbTreeNode *tmp_node = NULL;
    AcdbHeapInfo *db_heap = NULL;
    LinkedListNode *item_node = NULL;
    LinkedList stack = { 0 };

    if (IsNull(handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle;
    cur_node = db_heap->root;

    while (cur_node != NULL || stack.length != 0)
    {
        if (!IsNull(cur_node))
        {
            item_node = acdb_heap_create_list_node(cur_node);
            if (IsNull(item_node))
            {
                return AR_ENOMEMORY;
            }
            acdb_stack_push(&stack, item_node);
            cur_node = cur_node->left;
            continue;
        }

        if (IsNull(cur_node) && stack.length > 0)
        {
            acdb_stack_pop(&stack, &item_node);
            cur_node = (AcdbTreeNode*)item_node->p_struct;

            KVSubgraphMapBin **bin = (KVSubgraphMapBin**)(&(cur_node->p_struct));
            acdb_heap_free_bin(bin);
            //acdb_heap_free_bin(&(CkvSubgraphMapBin*)cur_node->p_struct);

            //Free stack nodes
            ACDB_FREE(item_node);

            //Free Tree nodes
            tmp_node = cur_node->right;
            ACDB_FREE(cur_node);
            cur_node = tmp_node;
        }
    }

    db_heap->root = NULL;

    return AR_EOK;
}

int32_t acdb_heap_reset(void)
{
    int32_t status = AR_EOK;
    AcdbHeapInfo *db_info = NULL;

    for (int32_t i = 0; i < ACDB_MAX_ACDB_FILES; i++)
    {
        db_info = ACDB_HEAP_DB_INFO_AT_INDEX(i);

        if (IsNull(db_info))
            continue;

        status = acdb_heap_remove_database((acdb_heap_handle_t)db_info);
        if (AR_FAILED(status))
        {
            ACDB_ERR("Error[%d]: Failed to remove database heap at index %d",
                status, i);
            status = AR_EFAILED;
        }
    }

    ar_osal_mutex_destroy(acdb_heap_context.heap_lock);
    ar_mem_set(&acdb_heap_context, 0, sizeof(AcdbHeapContext));
    acdb_heap_context.active_heap_index = -1;
    return status;
}

/**
* \brief  acdb_heap_get_heap_info
*           Performs an inorder traversal of the heap and collects information
            about each heap node in an. This includes:
*           1. Key Vector
*           2. Key Vector Type (CKV or TKV)
*           3. Calibration data size
* \return
* 0 -- Success
* Nonzero -- Failure
*/
int32_t acdb_heap_get_heap_info(AcdbBufferContext *rsp)
{
    int32_t status = AR_EOK;
    uint32_t offset = 0;
    uint32_t num_nodes = 0;
    AcdbTreeNode *cur_node = NULL;
    LinkedListNode* item_node = NULL;
    LinkedList stack = { 0 };
    acdb_context_handle_t* handle = NULL;
    AcdbHeapInfo* db_heap = NULL;

    handle = acdb_ctx_man_get_active_handle();

    if (IsNull(handle) || IsNull(handle->heap_handle))
        return AR_EHANDLE;

    db_heap = (AcdbHeapInfo*)handle->heap_handle;

    if (IsNull(db_heap))
        return AR_EHANDLE;

    cur_node = db_heap->root;

    //Make room to write number of heap nodes at the end of the function
    offset += sizeof(num_nodes);

    if (IsNull(rsp)) return AR_EBADPARAM;

    while (cur_node != NULL || stack.length != 0)
    {
        if (!IsNull(cur_node))
        {
            item_node = acdb_heap_create_list_node(cur_node);
			if (IsNull(item_node))
			{
				return AR_ENOMEMORY;
			}
            acdb_stack_push(&stack, item_node);
            cur_node = cur_node->left;
            continue;
        }

        if (IsNull(cur_node) && stack.length > 0)
        {
            acdb_stack_pop(&stack, &item_node);
            cur_node = (AcdbTreeNode*)item_node->p_struct;
            ACDB_FREE(item_node);

            KVSubgraphMapBin* bin = (KVSubgraphMapBin*)cur_node->p_struct;

            num_nodes++;

            char* next_int = bin->str_key_vector;
            char tmp[HEX_DIGITS + 1];
            uint32_t num_keys = 0;

            offset += sizeof(num_keys);//Make room to write number of keys
            /** Get Key Vector
             * This loop will write key followed by value for each key value pair.
             * The str_key_vector is in the form A0000000A0000001B0000000B0000001 where
             * key1.ID = A0000000 key1.Value = A0000001
             * key2.ID = B0000000 key2.Value = B0000001
             */
            while (*next_int != '\0')
            {
                ACDB_MEM_CPY_SAFE(&tmp[0], HEX_DIGITS, next_int, HEX_DIGITS);//8 bytes for 8 hex digits

                uint32_t key = 0;//(uint32_t)strtoul(&tmp[0], NULL, 16);

                ar_sscanf(&tmp[0], "%08x", &key);
                next_int += HEX_DIGITS;

                //write to rsp buf
                ACDB_MEM_CPY_SAFE(&rsp->buf[offset], sizeof(key), &key, sizeof(key));
                offset += sizeof(key);
                num_keys++;
            }

            next_int = NULL;
            num_keys = num_keys / 2;
            ACDB_MEM_CPY_SAFE(&rsp->buf[offset - (num_keys * sizeof(AcdbKeyValuePair) + sizeof(num_keys))],
                sizeof(num_keys), &num_keys, sizeof(num_keys));

            //Get Size of map
            acdb_delta_data_map_t *map =
                (acdb_delta_data_map_t*)bin->map;

            ACDB_MEM_CPY_SAFE(&rsp->buf[offset], sizeof(map->map_size), &map->map_size, sizeof(map->map_size));
            offset += sizeof(map->map_size);

            //Determine type of Key Vector
            uint32_t kv_type = map->key_vector_type;
            ACDB_MEM_CPY_SAFE(&rsp->buf[offset], sizeof(kv_type), &kv_type, sizeof(kv_type));
            offset += sizeof(kv_type);

            cur_node = cur_node->right;
        }
    }

    ACDB_MEM_CPY_SAFE(rsp->buf, sizeof(num_nodes), &num_nodes, sizeof(num_nodes));

    rsp->bytes_filled = offset;
    return status;
}
/**
*==============================================================================
*	Public functions
*==============================================================================
*/
int32_t acdb_heap_ioctl(uint32_t cmd_id,
    void *req, uint32_t req_size,
    void *rsp, uint32_t rsp_size)
{
    int32_t status = AR_EOK;

    switch (cmd_id)
    {
    case ACDB_HEAP_CMD_INIT:
    {
        status = acdb_heap_init();
        break;
    }
    case ACDB_HEAP_CMD_ADD_DATABASE:
        if (IsNull(req) || req_size < sizeof(uint32_t) ||
            IsNull(rsp) || rsp_size < sizeof(acdb_heap_handle_t))
            return AR_EBADPARAM;

        status = acdb_heap_add_database(
            *(uint32_t*)req, (acdb_heap_handle_t*)rsp);
        break;

    case ACDB_HEAP_CMD_REMOVE_DATABASE:
        if (IsNull(req) || req_size < sizeof(acdb_heap_handle_t))
            return AR_EBADPARAM;

        status = acdb_heap_remove_database((acdb_heap_handle_t*)req);
        break;
    case ACDB_HEAP_CMD_RESET:
        status = acdb_heap_reset();
        break;
    case ACDB_HEAP_CMD_CLEAR_DATABASE_HEAP:
    {
        if (IsNull(req) || req_size < sizeof(acdb_heap_handle_t))
            return AR_EBADPARAM;

        status = acdb_heap_clear((acdb_heap_handle_t)req);
        break;
    }
    case ACDB_HEAP_CMD_ADD_MAP:
    {
        if (IsNull(req) || req_size < sizeof(acdb_delta_data_map_t))
            return AR_EBADPARAM;

        acdb_heap_map_handle_info_t info =
        {
            NULL,
            (acdb_delta_data_map_t*)req
        };
        status = acdb_heap_add_delta_data_map(TRUE, &info);
        break;
    }
    case ACDB_HEAP_CMD_ADD_MAP_USING_HANDLE:
    {
        if (IsNull(req) || req_size < sizeof(acdb_heap_map_handle_info_t))
            return AR_EBADPARAM;

        status = acdb_heap_add_delta_data_map(FALSE,
            (acdb_heap_map_handle_info_t*)req);
        break;
    }
    case ACDB_HEAP_CMD_REMOVE_MAP:
    {
        //Similar to Get Map but frees the memory associated with the map
        break;
    }
    case ACDB_HEAP_CMD_GET_MAP:
    {
        if (IsNull(req) || req_size < sizeof(AcdbGraphKeyVector) ||
            IsNull(rsp) || rsp_size < sizeof(acdb_delta_data_map_t))
            return AR_EBADPARAM;

        status = acdb_heap_get_ckv_subgraph_map(
            (AcdbGraphKeyVector*)req,
            (acdb_delta_data_map_t**)rsp);

        break;
    }
    case ACDB_HEAP_CMD_GET_MAP_LIST:
    {
        if (IsNull(rsp) || rsp_size < sizeof(LinkedList))
            return AR_EBADPARAM;

        status = acdb_heap_get_map_list((LinkedList**)rsp);
        break;
    }

    case ACDB_HEAP_CMD_GET_HEAP_INFO:
    {
        if (IsNull(rsp) || rsp_size < sizeof(AcdbBufferContext))
            return AR_EBADPARAM;

        status = acdb_heap_get_heap_info((AcdbBufferContext*)rsp);
        break;
    }
    default:
        break;
    }
    return status;
}
