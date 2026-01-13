#ifndef _ATS_SERVER_H_
#define _ATS_SERVER_H_
/**
*=============================================================================
* \file ats_server.h
* \brief
*                  A T S  S E R V E R  H E A D E R  F I L E
*
*   This file contains the TCP/IP server API definitions used to host 
*   connections to QACT.
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
* 
*=============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "ar_osal_mutex.h"
#include "ar_osal_error.h"
#include "ar_osal_thread.h"
#include "ats_common.h"
#include "acdb_utility.h"

//constants used by the server
#define SOCK_PATH "/vendor/app/GatewayServer/ats_sockets";
#define SOCK_PATH_SERVER "/vendor/app/GatewayServer/ats_sockets/unix_sock.server";
#define MAX_LENGTH_IP_ADDRESS 16
#define MAX_ATS_CLIENTS_ALLOWED 1
#define ATS_THREAD_LISTENER "ATS_THD_LISTENER"
#define ATS_THREAD_TRANSMIT "ATS_THD_TRANSMIT"
#define ATS_THD_STACK_SIZE 0xF4240 //1mb stack size

#define ATS_SERVER_ADDRESS "127.0.0.1" //local host
#define ATS_GATEWAY_PORT 5559

#define ATS_THREAD_PRIORITY_HIGH  0
#define ATS_THREAD_PRIORITY_LOW  1

/**< Read in sizes of 1024 to avoid allocating too much memory*/
#define ATS_RECIEVE_BUF_SIZE 1024

#define ATS_SERVER_CMD_QUIT "QUIT"

//const uint32_t maxsize = 0x200000;
//const uint32_t bufsize = 1024;

#ifdef __cplusplus
extern "C"{
#endif

    typedef struct ats_server_context {
        void(*ats_cb)(uint8_t* req, uint32_t req_len, uint8_t** resp, uint32_t* resp_len);
    } ats_server_context;

/**
*	\brief
*		Initializes the ATS TCP/IP server
*
*	\detdesc
*		Entry function to start ats_server threads
*		ats_server will start a listening thread on a local IP address on the
*		designated port.
*		ats communicates with the Gateway Server for any connection to external clients
*
*		Note: Only one client can be connected to this target at a time. The use of a mutex
*		ensures this.
*
*	\param [in] ats_cb: A callback to ats_exectue_command
*
*	\return
*		0 on success, non-zero on failure
*/
int32_t ats_server_init(void(*ats_cb)(uint8_t *buf, uint32_t buf_len, uint8_t **resp, uint32_t *resp_len));

/**
*   \brief
*		De-initializes the ATS TCP/IP server
*
*	\detdesc
*       Releases threading and memory resources aquired during ats_server_init
*
*		Note: Only one client can be connected to this target at a time. The use of a mutex
*		ensures this.
*
*	\return
*		0 on success, non-zero on failure
*/

/**
* \brief ats_server_deinit
*		Stops ats_server threads.
*
* \return 0 on success, non-zero on failure
*/
int32_t ats_server_deinit(void);

/**
	\brief
		Initializes the ATS TCP/IP server

	\detdesc
		Startup the server.
		Creates the listening socket on 5559 and accepts incoming connections.
		Upon accepting a new connection, a thread called recv_thread_proc is 
		created to handle transmitting(send/recieve) data to client.

	\dependencies
		None

	\param [in] thread_param: Parameters to be used within the thread routine
*/
void* ats_server_start_routine(void* thread_param);

/**
	\brief
		Thread for transmitting data between ATS and its client(s)

	\detdesc
		Thread process that is created to handle 2 way message sending between server and client

	\dependencies
		There must be a socket already accepted that is passed into this function.

	\param [in] client_socket_ptr: is a SOCKET pointer returned by the accept() 
		function in ats_svr_start_routine
*/
void* ats_server_transmit_routine(void* client_socket_ptr);

#ifdef __cplusplus
}
#endif
#endif /*_ATS_SERVER_H_*/

