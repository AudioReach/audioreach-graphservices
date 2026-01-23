#ifndef _TCPIP_DLS_SERVER_H_
#define _TCPIP_DLS_SERVER_H_
/**
*=============================================================================
*  \file tcpip_dls_server.h
*  \brief
*                      T C P I P  D L S  S E R V E R
*                           H E A D E R  F I L E
*
*    This file contains the TCP/IP server implementation to host connections
*    to QACT.
*    This file first sets up a listening socket on port 5558. Upon accepting
*    new connections, the server creates new receiving threads that handles
*    all ATS upcalls.
*
*     ATS_DATA_LOGGING must be defined in the build configuration to use
*     this feature
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/
#ifdef ATS_TRANSPORT_TCPIP
#ifdef ATS_DATA_LOGGING

#include <string>
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "ar_osal_thread.h"
#include "ar_osal_mutex.h"
#include "ar_osal_log.h"
#include "ar_sockets_api.h"
#include "tcpip_socket_util.h"

#define TCPIP_THREAD_PRIORITY_HIGH 0
#define TCPIP_THREAD_PRIORITY_LOW 1
#define TCPIP_THD_STACK_SIZE 0xF4240 //1mb stack size

#define TCPIP_DLS_SERVER_PORT 5561

class TcpipDlsServer
{
public:
	std::string address;
	uint16_t port;
private:
	uint8_t is_connected;
	bool_t should_close_server;
	ar_socket_t accept_socket;
	ar_osal_mutex_t connection_lock;
	ar_osal_thread_t thread;
public:
	TcpipDlsServer() = default;
	TcpipDlsServer(std::string thd_name);
	int32_t start();
	int32_t stop();

	void* connect_routine(void* args);

	/* \brief
	*	Sends DLS log buffers to the client
	*	param[in] buffer: a data buffer containing the DLS packet data
	*	param[in] buffer: The size of the buffer containing the DLS packet data
	*/
	int32_t send_dls_log_buffers(const char_t* buffer, uint32_t buffer_size);

private:
	int32_t set_connected_lock(uint8_t is_conn);

	static void connect(void* arg);
};

#endif /*ATS_DATA_LOGGING*/
#endif /*ATS_TRANSPORT_TCPIP*/
#endif /* _TCPIP_DLS_SERVER_H_ */
