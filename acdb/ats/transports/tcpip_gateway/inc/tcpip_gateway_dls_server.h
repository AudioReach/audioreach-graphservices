#ifndef _TCPIP_GATEWAY_DSL_SERVER_H_
#define _TCPIP_GATEWAY_DSL_SERVER_H_
/**
*==============================================================================
*  \file tcpip_gateway_dls_server.h
*  \brief
*                  T C P I P  G A T E W A Y  D L S  S E R V E R
*                             H E A D E R  F I L E
*
*         This file defines the class for the TCPIP Gateway Server as
*         well as types and defines used by the server. This server is
*         a proxy server that forwards request from server clients to the
*         TCPIP CMD Server.
*
*     ATS_DATA_LOGGING must be defined in the build configuration to use
*     this feature
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

#if defined(ATS_DATA_LOGGING)

/*-------------------------------------
 *             Includes
 *-----------------------------------*/
#include <string>
#include "ar_osal_mutex.h"
#include "ar_osal_error.h"
#include "ar_osal_thread.h"
#include "ar_osal_string.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_heap.h"
#include "ar_sockets_api.h"
#include "tcpip_gateway_cmds.h"
#include "tcpip_gateway_common.h"

#define TGWS_START_ROUTINE_THREAD "GWS_THD_START"
#define TGWS_TRANSMIT_THREAD "GWS_THD_TRANSMIT"
 /**< 1MB stack size used when creating threads */
#define TGWS_THD_STACK_SIZE  0xF4240 //
#define TGWS_THREAD_PRIORITY_HIGH 0
#define TGWS_THREAD_PRIORITY_LOW  1

#define TGWS_1_KB                           1024UL
#define TGWS_RECIEVE_BUFFER_SIZE            (TGWS_1_KB * 32UL)
#define TGWS_MIN_MESSAGE_BUFFER_SIZE        (TGWS_1_KB * 32UL)
#define TGWS_MAX_MESSAGE_BUFFER_SIZE        0x200000ul

 /**< The TCPIP Gateway DLS Servers default TCP/IP port when no port is specified at startup */
#define TCPIP_DEFAULT_DLS_SERVER_PORT 5560
 /**< Timeout in seconds */
#define TGWS_CONNECTION_TIMEOUT 30
 /**< The localhost address */

#define TCPIP_THREAD_PRIORITY_HIGH 0
#define TCPIP_THREAD_PRIORITY_LOW 1
#define TCPIP_THD_STACK_SIZE 0xF4240 //1mb stack size

#define TCPIP_DLS_SERVER_PORT 5560

class TcpipGatewayDlsServer
{
public:
	std::string address;
    std::string str_pc_port;//todo: might need this?
	uint16_t port;
private:
    buffer_t message_buffer;
    buffer_t recieve_buffer;
	bool_t is_connected;
	bool_t should_close_server;
	ar_socket_t accept_socket;
	ar_osal_mutex_t connection_lock;
	ar_osal_thread_t thread;
    ar_socket_t* server_socket_ptr;
    ar_socket_t *client_socket_ptr;
    ar_socket_t listen_socket;
    std::string str_ip_addr;
    ar_osal_mutex_t connected_mutex;
public:
	TcpipGatewayDlsServer();
	// TcpipGatewayDlsServer(std::string thd_name);
	int32_t start();
	int32_t stop();

	void* connect_routine(void* args);
	void* transmit_routine(void* args);
    void set_ip_address(std::string address);
private:
	int32_t set_connected_lock(bool_t is_conn);

	static void connect(void* arg);
    void static transmit(void* arg);

    /**
    * \brief
    *	  Forwards messages from the socket established between the ATS TCPIP CMD Server and the Gateway Server
    *     to the socket established between the Gateway Server and QACT
    *
    * \param [in] sender_socket_ptr: A pointer to the client socket. This is either the socket established with QACT or with the TCPIP CMD server
    * \param [in] receiver_socket_ptr: A pointer to the client socket. This is either the socket established with QACT or with the TCPIP CMD server
    * \param [in/out] gateway_message_buf: The buffer where the incomming message is written
    * \param [in/out] gateway_recv_buf: The buffer used for message boundry processing
    * \param [in] is_cmd_request: Indicates if a command request came from QACT
    * \param [out] status_code: A gateway status code that the caller can use to handle gateway server specific errors
    */
    void tcp_forward(
        ar_socket_t* sender_socket_ptr, ar_socket_t* receiver_socket_ptr,
        buffer_t* gateway_message_buf, buffer_t* gateway_recv_buf,
        bool_t is_cmd_request, tgws_status_codes_t &status_code);

    /**
    * \brief
    *	 Connects the Gateway DLS Server to the ATS TCPIP DLS Server
    */
    int32_t connect_to_target_server(
        ar_socket_t* server_socket);
};

#endif /*ATS_DATA_LOGGING*/
#endif /*_TCPIP_GATEWAY_DSL_SERVER_H_*/
