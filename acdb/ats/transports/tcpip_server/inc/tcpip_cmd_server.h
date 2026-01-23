#ifndef _TCPIP_CMD_SERVER_H_
#define _TCPIP_CMD_SERVER_H_
/**
*=============================================================================
*  \file tcpip_cmd_server.h
*  \brief
*                     T C P I P  C M D  S E R V E R
*                          H E A D E R  F I L E
*
*    This file contains the TCP/IP server implementation to host connections
*    to QACT.
*    This file first sets up a listening socket on port 5558. Upon accepting
*    new connections, the server creates new receiving threads that handles
*    all ATS upcalls.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/

#ifdef ATS_TRANSPORT_TCPIP

#include <string>
#include "ar_osal_mutex.h"
#include "ar_osal_error.h"
#include "ar_osal_thread.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

#include "ats_i.h"
#include "tcpip_dls_server.h"

//#if defined(__linux__)
//#include <unistd.h>
//#include <sys/socket.h>
//#include <netdb.h>
//#include <cutils/properties.h>
//#include <utils/Log.h>
//#include <sys/time.h>
//#include <sys/un.h>
//#include <arpa/inet.h>
//#endif

#define TCPIP_CMD_SERVER_RECV_BUFFER_SIZE         (ATS_1_KB * 32UL)
#define TCPIP_CMD_SERVER_MIN_MSG_BUFFER_SIZE      (ATS_1_KB * 32UL)
#define TCPIP_CMD_SERVER_MAX_MSG_BUFFER_SIZE      0x200000ul //2MB max size
#define TCPIP_CMD_SERVER_ADDRESS "127.0.0.1" //local host
#define TCPIP_CMD_SERVER_PORT 5559

typedef void(*ATS_EXECUTE_CALLBACK) (
    uint8_t* req, uint32_t req_len,
    uint8_t** resp, uint32_t* resp_len);

struct buffer_t {
    uint32_t buffer_size;
    char_t* buffer;
};

class TcpipServer;

class TcpipCmdServer
{
public:
    std::string thd_name;
    ar_osal_thread_t thd_connection_routine;
    ar_osal_thread_start_routine routine;
    uint16_t port;
    std::string address;
    ar_socket_t listen_socket;
    ar_socket_t accept_socket;
    ATS_EXECUTE_CALLBACK execute_command;

private:
    uint8_t is_connected;
    bool_t is_aborted;
    bool_t should_close_server;
    ar_osal_mutex_t connection_lock;
    buffer_t message_buffer;
    buffer_t recieve_buffer;

    /*------------------------- Server Commands -------------------------*/

    const std::string ATS_SERVER_CMD_QUIT = "QUIT";


#ifdef ATS_DATA_LOGGING
private:

    TcpipDlsServer _dls_server;
#endif

public:

    int32_t send_dls_log_buffers(const char_t* buffer, uint32_t buffer_size);

public:

    TcpipCmdServer(std::string thd_name);

    /**
    * \brief
    *       Starts the server by initializing locks and launches the connection routine thread
    *
    * \param [in] args: Optional arguments. Unused for now.
    *
    * \return Returns AR_EOK on success and non-zero on failure
    */
    int32_t start(void *args);

    /**
    * \brief
    *       Stops the server and releases all resources. This API is blocking since
    *       it needs to wait until the connection routine thread exists
    * \return Returns AR_EOK on success and non-zero on failure
    */
    int32_t stop();

    /**
    * \brief
    *	  Listens for incoming clients and starts the data transmission thread after a client connects
    *
    * \detdesc
    *     Creates the listening socket on 5559 and accepts incoming connections.
    *	  Upon accepting a new connection, a thread called recv_thread_proc is
    *	  created to handle transmitting(send/recieve) data to client.
    *
    * \dependencies
    *	  None
    *
    * \param [in] thread_param: Parameters to be used within the thread routine
    */
    void *connect_routine(void *args);

    /**
    * \brief
    *    Routine for transmitting data between ATS and its client(s)
    *
    * \detdesc
    *    Thread process that is created to handle 2 way message sending between server and client
    *
    * \param [in] args: This is unused
    */
    void *transmit_routine(void *args);

private:

    int32_t set_connected_lock(uint8_t is_conn);

    static void connect(void* arg);

    static void transmit(void* arg);

    int32_t recv_message_header(char_t *msgBuf, uint32_t msgbuflen,
        char_t *recvbuf, uint32_t recvbuflen, uint32_t &msg_len);

    int32_t recv_message(char_t *msgBuf, uint32_t msgbuflen,
        char_t *recvbuf, uint32_t recvbuflen, uint32_t msg_len);

    int32_t process_message(
        char_t *msgBuf, uint32_t msgbuflen, uint32_t msg_len,
        char_t **out_buf, uint32_t out_buf_len, uint32_t &resp_len);

    int32_t send_message(char_t *buf, uint32_t buf_len, uint32_t msg_len);

    int32_t execute_server_command(uint32_t service_cmd_id, uint32_t message_length);

    void start_dls_server();

    void stop_dls_server();
};

class TcpipServer
{
private:
    //Server Thread Properties

    const std::string THREAD_NAME_ATS_LISTENER = "ATS_THD_LISTENER";
    const std::string THREAD_NAME_ATS_DLS_LISTENER = "ATS_DLS_THD_LISTENER";
    const std::string THREAD_NAME_ATS_TRANSMIT = "ATS_THD_TRANSMIT";

    TcpipCmdServer cmd_server;

public:
    TcpipServer();

    ~TcpipServer();

    int32_t start(ATS_EXECUTE_CALLBACK cb);

    int32_t stop();

    int32_t send_dls_log_buffers(const uint8_t* buffer, uint32_t buffer_size);
};

#endif /*ATS_TRANSPORT_TCPIP*/

#endif /*_TCPIP_CMD_SERVER_H_*/

