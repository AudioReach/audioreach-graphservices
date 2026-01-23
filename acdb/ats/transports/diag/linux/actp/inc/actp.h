#ifndef ACTP_H
#define ACTP_H
/**
*==============================================================================
* \file actp.h
* \brief
*				A C T P   H E A D E R    F I L E
*
*	This header file contains all the definitions necessary for ACTP protocol
*	layer to initialize  ACTP diag dispatcher.
*   This actp works in both ARM9 and ARM11
*
* \copyright
*	  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*	  SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "acdb_utility.h"

/*------------------------------------------
* Macros
*------------------------------------------*/
/*ACTP subsystem command ID Range (inclusive)*/

/**< ACTP subsystem command code range start ID */
#define ACTP_CMD_ID_START 2051
/**< ACTP subsystem command code range end ID */
#define ACTP_CMD_ID_END 2100
#define PACKED

 /*------------------------------------------
 * External Functions
 *------------------------------------------*/
/**
* \brief
*		Registers the subsystem diag dispathcer with diag dispathcer.
*      Initializes the actp session.and give it a call-back function.
*  \depends
*      actp_diag_table[] must be initialized and should have the proper
*      sub-system command code range and pointer to the callback function.
*
* \param[in] request_callback: A callback that the dispatcher will use to
*            send/recieve messages to/from ATS
* \param[in/out] rsp: A data blob containg tag data
* \return 0 on success, and non-zero on failure
*/
extern int32_t actp_diag_init(
    void (*callback_function)(uint8_t*, uint32_t, uint8_t**, uint32_t*));

/**
* \brief
*		De-registers the subsystem diag dispathcer with diag dispathcer.
*
* \return n/a
*/
extern int32_t actp_diag_deinit(void);

/**
* \brief
*      This is the entry point to ACTP when seen from the PC. It is the
*      sub-system diag dispathcer for Audio Calibration manager. It receives
*      a diag packet ment for ACTP, passes it to the protocol layer, and
*      returns the response diag packet. In case of error, it returns diag
*      packet with error code DIAG_BAD_CMD_F
*
* \param[in] request_callback: A callback that the dispatcher will use to
*            send/recieve messages to/from ATS
* \param[in/out] rsp: A data blob containg tag data
* \return 0 on success, and non-zero on failure
*/
extern PACKED void * avsACTP_diag_cmd (PACKED void *request, uint16_t length);

#endif //ACTP_H

