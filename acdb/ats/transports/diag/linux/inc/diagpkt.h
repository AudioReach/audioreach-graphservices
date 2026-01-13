#ifndef DIAGPKT_H
#define DIAGPKT_H
/**
*==============================================================================
* \file diagpkt.h
* \brief
*              D I A G N O S T I C  S Y S T E M  P A C K E T
*                       I N T E R F A C E  S T U B
*
*           This file is a stub version of the Diagnostic System Packet
*           Interface header. This file is used for compilation with the
*           Off-target Test Platform(OTTP).
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/
#include "ar_osal_types.h"
#define word uint32_t

/*--------------------------------------------------------------------------
* Type and Packet Definition Macros
*-------------------------------------------------------------------------*/
typedef uint8_t diagpkt_cmd_code_type;
typedef uint8_t diagpkt_subsys_id_type;
typedef uint16_t diagpkt_subsys_cmd_code_type;

/*--------------------------------------------------------------------------
* Function Definitions
*-------------------------------------------------------------------------*/
/* Packet Handler Types */

/* An array of this type is created by the client and registered with this
    service. It must be declared 'const' (preferrably 'static const').
    The function is called when an inbound packet matches subsystem ID and
    is within the command code range specified in the table. */
typedef struct
{
word cmd_code_lo;
word cmd_code_hi;
void *(*func_ptr) (void *req_pkt_ptr, uint16_t pkt_len);
}
diagpkt_user_table_entry_type;

/* Note: the following 2 items are used internally via the macro below. */

/* User table type */
typedef struct
{ uint16_t delay_flag;  /* 0 means no delay and 1 means with delay */
uint16_t cmd_code;
word subsysid;
word count;
uint16_t proc_id;
const diagpkt_user_table_entry_type *user_table;
} diagpkt_user_table_type;

void diagpkt_tbl_reg (const diagpkt_user_table_type * tbl_ptr);

/* Single processor or modem proc*/
#define DIAGPKT_DISPATCH_TABLE_REGISTER(xx_subsysid, xx_entry) \
do { \
    static const diagpkt_user_table_type xx_entry##_table = { \
    0, 0xFF, xx_subsysid, sizeof (xx_entry) / sizeof (xx_entry[0]), 0, xx_entry \
    }; \
    /*lint -save -e717 */ \
    diagpkt_tbl_reg (&xx_entry##_table); \
} while (0)
    /*lint -restore */

/*--------------------------------------------------------------------------
* Functions
*-------------------------------------------------------------------------*/

void *diagpkt_subsys_alloc (diagpkt_subsys_id_type id,
diagpkt_subsys_cmd_code_type code, unsigned int length);

void diagpkt_commit (void *ptr);

diagpkt_subsys_cmd_code_type diagpkt_subsys_get_cmd_code (void *ptr);

void *diagpkt_err_rsp (diagpkt_cmd_code_type code,
void *req_ptr, uint16_t req_len);


#endif              /* DIAGPKT_H  */
