#ifndef _TCPIP_GATEWAY_CMD_SERVER_H_
#define _TCPIP_GATEWAY_CMD_SERVER_H_
/**
*==============================================================================
*  \file tcpip_gateway_cmd_server.h
*  \brief
*                  T C P I P  G A T E W A Y  C M D  S E R V E R
*                             H E A D E R  F I L E
*
*         This file defines the class for the TCPIP Gateway Server as
*         well as types and defines used by the server. This server is
*         a proxy server that forwards request from server clients to the
*         TCPIP CMD Server.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

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
#include "tcpip_gateway_dls_server.h"

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

 /**< The ATS Layers TCPIP CMD Server TCP/IP Port */
#define TCPIP_CMD_SERVER_PORT 5559
 /**< The TCPIP Gateway Servers default TCP/IP port when no port is specified at startup */
#define TGWS_DEFAULT_PORT 5558
 /**< Timeout in seconds */
#define TGWS_CONNECTION_TIMEOUT 30
 /**< The localhost address */
#define TGWS_DEFAULT_IP_ADDRESS "127.0.0.1"
 /**< 000.000.000.000 - 15 characteres plus null terminator */
#define MAX_LENGTH_IP_ADDRESS 16

class TcpipGatewayServer {
private:
    buffer_t message_buffer;
    buffer_t recieve_buffer;
    uint16_t pc_port;
    std::string str_ip_addr;
    std::string str_pc_port;
    tgws_config_t *config;
    ar_socket_t* server_socket_ptr;
    ar_socket_t *client_socket_ptr;
    ar_socket_t listen_socket;
    ar_osal_thread_t start_routine_thread;
    ar_osal_mutex_t connected_mutex;
    uint8_t is_connected;
    uint32_t option;

    #ifdef ATS_DATA_LOGGING
    TcpipGatewayDlsServer dls_server;
    #endif

public:
    TcpipGatewayServer(std::string ip_addr, std::string port, uint32_t option);
    ~TcpipGatewayServer();

    /**
    * \brief
    *	  Allocates recources and starts the gateway servers connection routine thread.
    */
    int32_t run();

    /**
    * \brief
    *	  Starts the TCP/IP connection routine and waits to accept clients.
    * \detdesc
    *     Waits to accept clients. When clients connect the Gateway Server establishes a connection to the TCPIP CMD Server
    */
    void* connect_routine(void* arg);

    /**
    * \brief
    *	  Recieves messages from the Gateway Server Client and forwads messages to the TCPIP CMD Server
    */
    void* transmit_routine(void* client_socket);

private:
    //We need to define these static fuinction in order to use the ar_osal_create_thread(...) API

    void static start(void* arg);
    void static transmit(void* arg);

    /**
    * \brief
    *	  Forwards messages between the socket established between QACT and the Gateway Server
    *     and the socket established between the Gateway Server and TCPIP CMD Server
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
    *	 Connects the Gateway Server to the TCPIP CMD Server
    */
    int32_t connect_to_target_server(
        ar_socket_t* server_socket);

    /**
    * \brief
    *	  Handles gateway server commands detected in the inbound message
    *
    * \param [in] service_cmd_id: The ATS Service + Command ID used to identify the service the command is part of and the command to execute
    * \param [in] sender_socket: The socket to send messages to
    * \param [in] service_cmd_id: The lemgth of the inbound message
    * \param [out] status_code: A gateway status code that the caller can use to handle gateway server specific errors
    *
    * \return AR_EOK on success, otherwise non-zero on failure
    */
    int32_t execute_server_command(
        uint32_t service_cmd_id, ar_socket_t sender_socket, uint32_t message_length, tgws_status_codes_t &status_code);

    /**
    * \brief
    *	  Starts the dls gateway server which alows gateway clients to recieve logging data from the ats dls server
    */
    void start_dls_server(void);
};

#endif /*_TCPIP_GATEWAY_CMD_SERVER_H_*/
