/**
*=============================================================================
*  \file tcpip_dls_server.cpp
*  \brief
*                      T C P I P  D L S  S E R V E R
*                         S O U R C E  F I L E
*
*    This file contains the DLS TCPIP server implementation to host connections
*    to QACT.
*    This file first sets up a listening socket on port 5561. Upon accepting
*    new connections, the server sends DLS log packets to the connected client.
*
*     ATS_DATA_LOGGING must be defined in the build configuration to use
*     this feature
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/
#ifdef ATS_TRANSPORT_TCPIP
#ifdef ATS_DATA_LOGGING

#include "tcpip_dls_server.h"

#define TCPIP_THREAD_PRIORITY_HIGH 0
#define TCPIP_THREAD_PRIORITY_LOW 1
#define TCPIP_THD_STACK_SIZE 0xF4240 //1mb stack size

// #define TCPIP_DLS_SERVER_PORT 5561
#define MAX_TCPIP_CLIENTS_ALLOWED 1

/**< ATS TCPIP DLS Server(TDS) Log Tag */
#define TCPIP_DLS_SRV_LOG_TAG  "ATS-TDS"
#define TCPIP_DLS_ERR(...) AR_LOG_ERR(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)
#define TCPIP_DLS_DBG(...) AR_LOG_DEBUG(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)
#define TCPIP_DLS_INFO(...) AR_LOG_INFO(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)

typedef void* (TcpipDlsServer::* tcpip_dls_server_thread_callback)(void* args);
static tcpip_dls_server_thread_callback thd_cb_connect_routine = &TcpipDlsServer::connect_routine;

/*
============================================================================
                        DLS TCPIP Server Implementation
============================================================================
*/

TcpipDlsServer::TcpipDlsServer(std::string thd_name)
{
    port = TCPIP_DLS_SERVER_PORT;
}

int32_t TcpipDlsServer::start()
{
    int32_t status = AR_EOK;
    std::string thd_name = "DLS_TCPIP_SVR";

    status = ar_osal_mutex_create(&connection_lock);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to create mutex for %s thread", status, thd_name.c_str());
        return status;
    }

    ar_osal_thread_attr_t thd_attr =
    {
        (char_t*)thd_name.c_str(),
        TCPIP_THD_STACK_SIZE,
        TCPIP_THREAD_PRIORITY_HIGH,
    };

    ar_osal_thread_start_routine r = \
        (ar_osal_thread_start_routine)(connect);

    status = ar_osal_thread_create(&thread, &thd_attr, r, this);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to create thread %s", status, thd_name.c_str());
        return status;
    }

    return status;
}

int32_t TcpipDlsServer::stop()
{
    if (!is_connected)
        return AR_EOK;

    TCPIP_DLS_INFO("Closing tcpip dls server ...");
    int32_t status = ar_osal_thread_join_destroy(thread);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to destroy connection thread", status);
    }

    should_close_server = true;
    ar_socket_close(accept_socket);
    ar_osal_mutex_destroy(connection_lock);

    return AR_EOK;
}

int32_t TcpipDlsServer::set_connected_lock(uint8_t value)
{
    int32_t status = AR_EOK;

    status = ar_osal_mutex_lock(connection_lock);
    if (AR_FAILED(status))
    {
        return status;
    }

    is_connected = value;

    status = ar_osal_mutex_lock(connection_lock);
    if (AR_FAILED(status))
    {
        return status;
    }

    return status;
}

void TcpipDlsServer::connect(void* arg)
{
    TcpipDlsServer* thread = (TcpipDlsServer*)arg;
    (thread->*thd_cb_connect_routine)(NULL);
}

void* TcpipDlsServer::connect_routine(void* args)
{
    __UNREFERENCED_PARAM(args);

    TCPIP_DLS_INFO("Starting tcpip dls server thread.");
    int32_t status = AR_EOK;
    char_t* str_addr = (char_t*)address.c_str();
    ar_socket_t listen_socket;

    status = tcpip_socket_util_create_socket(TCPIP_SERVER_TYPE_DLS, AR_SOCKET_ADDRESS_FAMILY, str_addr, port, &listen_socket);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to create and bind to socket", status);
        return NULL;
    }

    //TCPIP_DLS_INFO("%s: Listening for connections...", thd_name.c_str());

    /* Clients will recieve a 'connection refused' error if the the
     * listening queue is full. The size of the queue is
     * MAX_TCPIP_CLIENTS_ALLOWED */
    status = ar_socket_listen(listen_socket, MAX_TCPIP_CLIENTS_ALLOWED);
    if (AR_SUCCEEDED(status))
    {
        TCPIP_DLS_INFO("Listening successful");
    }
    else
        return NULL;

    ar_osal_mutex_init(connection_lock);
    // status = set_connected_lock(false);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to set 'connected' lock", status);
        return 0;
    }

    while (true)
    {
        TCPIP_DLS_INFO("Waiting to accept clients for tcpip dls server...");

        status = tcpip_socket_util_accept_connections(AR_SOCKET_ADDRESS_FAMILY, listen_socket, &accept_socket);
        if (AR_FAILED(status))
        {
            ar_socket_close(accept_socket);
            if (AR_SOCKET_LAST_ERROR == EINTR) continue;

            continue;
        }

        ar_osal_mutex_lock(connection_lock);
        if (is_connected)
        {
            TCPIP_DLS_ERR("New connection request. Refusing...");
            ar_socket_close(accept_socket);
            ar_osal_mutex_unlock(connection_lock);
            continue;
        }
        ar_osal_mutex_unlock(connection_lock);

        TCPIP_DLS_INFO("Client connected to tcpip dls server...");
        break;
    }

    ar_socket_close(listen_socket);

    return 0;
}

int32_t TcpipDlsServer::send_dls_log_buffers(const char_t* buffer, uint32_t buffer_size)
{
    int32_t status = AR_EOK;
    int32_t bytes_sent = 0;

    if(ar_socket_is_invalid(accept_socket))
    {
        TCPIP_DLS_ERR("Unable to send log data. tcpip dls server isn't connected");
        return AR_EFAILED;
    }

    TCPIP_DLS_DBG("Preparing to send %d bytes", buffer_size);
    status = ar_socket_send(accept_socket, buffer, buffer_size, 0, &bytes_sent);
    if (AR_SUCCEEDED(status) && bytes_sent >= 0)
    {
        TCPIP_DLS_DBG("Successfully Sent %d bytes:", bytes_sent);
        return status;
    }

    return AR_EOK;
}

#endif /*ATS_DATA_LOGGING*/
#endif /*ATS_TRANSPORT_TCPIP*/
