/**
*=============================================================================
*  \file tcpip_cmd_server.cpp
*  \brief
*                   A T S  T C P I P  C M D  S E R V E R
*                            S O U R C E  F I L E
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
#include <thread>
#include <chrono>
#include "tcpip_socket_util.h"
#include "tcpip_dls_server.h"
#include "tcpip_server_api.h"
#include "tcpip_cmd_server.h"
#include "ar_osal_log.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_string.h"
#include "ar_osal_heap.h"
#include "ar_sockets_api.h"

/**< ATS TCPIP CMD Server(TCS) Log Tag */
#define TCPIP_CMD_SRV_LOG_TAG  "ATS-TCS"
#define TCPIP_CMD_SVR_ERR(...) AR_LOG_ERR(TCPIP_CMD_SRV_LOG_TAG, __VA_ARGS__)
#define TCPIP_CMD_SVR_DBG(...) AR_LOG_DEBUG(TCPIP_CMD_SRV_LOG_TAG, __VA_ARGS__)
#define TCPIP_CMD_SVR_INFO(...) AR_LOG_INFO(TCPIP_CMD_SRV_LOG_TAG, __VA_ARGS__)

/**< The maximum number of clients that can connect to the command server*/
#define MAX_TCPIP_CLIENTS_ALLOWED 1
/**< The name of the listening thread */
#define TCPIP_THREAD_LISTENER "ATS_THD_LISTENER"
/**< The name of the data transmission thread */
#define TCPIP_THREAD_TRANSMIT "ATS_THD_TRANSMIT"
/**< The size of the stack used by the threads created by the server */
#define TCPIP_THD_STACK_SIZE 0xF4240 //1mb stack size
/**< Indicates a high thread priority when creating a thread */
#define TCPIP_THREAD_PRIORITY_HIGH  0
/**< Indicates a low thread priority when creating a thread */
#define TCPIP_THREAD_PRIORITY_LOW  1

typedef void *(TcpipCmdServer::*cmd_server_thread_callback)(void* args);
static cmd_server_thread_callback thd_cb_connect_routine = &TcpipCmdServer::connect_routine;
static cmd_server_thread_callback thd_cb_transmit_routine = &TcpipCmdServer::transmit_routine;

/**< Instantiate a global static instance of the server for the duration of the appliation */
static TcpipServer server;

/*
============================================================================
                           Forward Declarations
============================================================================
*/

/**
* \brief
*   Helper function that retrieves the expected message length from the command request header
*
* \detdesc
*   The message_buffer must be in the following format:
* 		<--------- 4 bytes ----------->
* 		+-----------------------------+
* 		|  service id  |  command id  |
* 		+-----------------------------+
* 		|         data length         |
* 		+_____________________________+
* 		|                             |
* 		|            data             |
* 		|            ...              |
* 		+~.-~.-~.-~.-~.-~.-~.-~.-~.-~.+
*
*   Note: the data length referes to the size of the data section (not including header
*   size of 6 bytes)
*
* \dependencies
*   None
*
* \param [in] message_buffer: The buffer containing the command request sent by the client
* \param [in] msg_buffer_size: The length of the message buffer
* \param [in] data_length: The data length field in the command request header
*
* \return
*   TRUE if successfully parsed and FALSE otherwise
*/
static bool_t tcpip_cmd_server_get_ats_command_length(
    char_t* message_buffer, uint32_t message_buffer_size, uint32_t* data_length);

/**
* \brief
* Create a response error buffer with the specified error code
* and request command id.
*
* \detdesc
*	The response
* <-----------4bytes------------>
* +-----------------------------+
* |  service id  |  command id  |
* +-----------------------------+
* +-----------------------------+
* |         data length         |
* +-----------------------------+
* +-----------------------------+
* |            status           |
* +-----------------------------+
*
* \param[in] ar_status_code: The AR status code indicating the error
* \param[in/out] message_buffer: The message buffer where the message is written to
* \param[in] msg_buffer_size: The size of the message buffer
* \param[out] msg_length: The length of the message written to the message buffer
*
* \return none
*/
static void tcpip_cmd_server_create_error_resp(
    uint32_t service_cmd_id, uint32_t ar_status_code,
    char_t* message_buffer, uint32_t message_buffer_size,
    uint32_t& message_length);

/*
============================================================================
                            Public APIs
============================================================================
*/
int32_t tcpip_cmd_server_init(void(*ats_exec_callback)(uint8_t* req, uint32_t req_len,
    uint8_t** resp, uint32_t* resp_len))
{
    int32_t status = AR_EOK;

    status = server.start(ats_exec_callback);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to initialize ATS TCP/IP Server",
            status);
    }
    return status;
}

int32_t tcpip_cmd_server_deinit()
{
    int32_t status = AR_EOK;
    status = server.stop();
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to deinitialize ATS Tcpip Server",
            status);
    }
    return status;
}

int32_t tcpip_cmd_server_send_dls_log_data(const uint8_t * sendbuf, uint32_t payload_size)
{
    return server.send_dls_log_buffers(sendbuf, payload_size);
}
/*
============================================================================
                        TCPIP Server Implementation
============================================================================
*/
TcpipServer::TcpipServer()
    : cmd_server("CMD Thread")
{
}

TcpipServer::~TcpipServer()
{
}

int32_t TcpipServer::start(ATS_EXECUTE_CALLBACK cb)
{
    int32_t status = AR_EOK;
    TCPIP_CMD_SVR_INFO("Starting ATS server..");

    status = ar_socket_init();
    if (AR_FAILED(status))
        return status;

    cmd_server.execute_command = cb;
    cmd_server.start(NULL);
    return status;
}

int32_t TcpipServer::stop()
{
    int32_t status = AR_EOK;
    TCPIP_CMD_SVR_INFO("Stopping ATS server..");
    cmd_server.stop();

    status = ar_socket_deinit();
    return status;
}

int32_t TcpipServer::send_dls_log_buffers(const uint8_t* buffer, uint32_t buffer_size)
{
    return cmd_server.send_dls_log_buffers((const char_t*)buffer, buffer_size);
}

/*
============================================================================
                    TCPIP CMD/RSP Server Implementation
============================================================================
*/
TcpipCmdServer::TcpipCmdServer(std::string thd_name)
    : thd_name(thd_name)
{
}

int32_t TcpipCmdServer::start(void *args)
{
    __UNREFERENCED_PARAM(args);
    int32_t status = AR_EOK;

    this->address = TCPIP_CMD_SERVER_ADDRESS;
    this->port = TCPIP_CMD_SERVER_PORT;

    status = ar_osal_mutex_create(&connection_lock);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to create mutex for %s thread", status, thd_name.c_str());
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

    status = ar_osal_thread_create(&thd_connection_routine, &thd_attr, r, this);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to create thread %s", status, thd_name.c_str());
        return status;
    }

    return status;
}

int32_t TcpipCmdServer::stop()
{
    int32_t status = AR_EOK;

    TCPIP_CMD_SVR_INFO("Closing ATS CMD/RSP Server ...");
    is_aborted = true;
    should_close_server = true;

    stop_dls_server();

    ar_socket_close(listen_socket);
    ar_socket_close(accept_socket);
    ar_osal_mutex_unlock(connection_lock);

    TCPIP_CMD_SVR_DBG("Destroying listening thread...");
    status = ar_osal_thread_join_destroy(thd_connection_routine);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]:An error occured when waiting to close the listener thread.", status);
    }

    TCPIP_CMD_SVR_DBG("Destroying mutexes thread...");
    ar_osal_mutex_destroy(connection_lock);

    is_aborted = false;
    should_close_server = false;
    return status;
}


int32_t TcpipCmdServer::send_dls_log_buffers(const char_t* buffer, uint32_t buffer_size)
{
#ifdef ATS_DATA_LOGGING
    return _dls_server.send_dls_log_buffers(buffer, buffer_size);
#else
    __UNREFERENCED_PARAM(buffer);
    __UNREFERENCED_PARAM(buffer_size);
    return AR_EUNSUPPORTED;
#endif
}


int32_t TcpipCmdServer::set_connected_lock(uint8_t value)
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

void TcpipCmdServer::connect(void* arg)
{
    TcpipCmdServer *thread = (TcpipCmdServer*)arg;
    (thread->*thd_cb_connect_routine)(NULL);
}

void TcpipCmdServer::transmit(void* arg)
{
    TcpipCmdServer * thread = (TcpipCmdServer*)arg;
    (thread->*thd_cb_transmit_routine)(NULL);
}

void *TcpipCmdServer::connect_routine(void *args)
{
    __UNREFERENCED_PARAM(args);

    TCPIP_CMD_SVR_INFO("Starting TCP/IP server thread.");
    int32_t status = AR_EOK;
    ar_osal_thread_t thd_transmit = NULL;

    status = tcpip_socket_util_create_socket(TCPIP_SERVER_TYPE_CMD, AR_SOCKET_ADDRESS_FAMILY, address, port, &listen_socket);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to create and bind to socket", status);
        return NULL;
    }

    TCPIP_CMD_SVR_INFO("%s: Listening for connections...", thd_name.c_str());

    /* Clients will recieve a 'connection refused' error if the the
     * listening queue is full. The size of the queue is
     * MAX_TCPIP_CLIENTS_ALLOWED */
    status = ar_socket_listen(listen_socket, MAX_TCPIP_CLIENTS_ALLOWED);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_INFO("Error[%d]: Listen failed. Closing server...");
        ar_socket_close(listen_socket);
        return NULL;
    }

    TCPIP_CMD_SVR_INFO("Waiting to accept ATS TCP/IP Command-Response clients...");
    while (true)
    {
        if (should_close_server) break;

        status = tcpip_socket_util_accept_connections(AR_SOCKET_ADDRESS_FAMILY, listen_socket, &accept_socket);
        if (AR_FAILED(status))
        {
            ar_socket_close(accept_socket);

            if (AR_SOCKET_LAST_ERROR == EINTR) continue;

            continue;
        }

        //Start dls Server only after connecting to command server
        start_dls_server();

        TCPIP_CMD_SVR_INFO("Client connected to ATS TCPIP Command-Response Server");
        ar_osal_mutex_unlock(connection_lock);
        is_connected = true;

        //ar_osal_thread_t thd_transmit;
        ar_osal_thread_start_routine r = \
            (ar_osal_thread_start_routine)(transmit);

        std::string thd_transmit_name = "";
        ar_osal_thread_attr_t thd_attr = \
        {
            (char_t*)thd_transmit_name.c_str(),
                TCPIP_THD_STACK_SIZE,
                TCPIP_THREAD_PRIORITY_HIGH
        };

        status = ar_osal_thread_create(&thd_transmit, &thd_attr, r, this);
        if (AR_FAILED(status))
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Failed to create transmission thread", status);
        }


        /* Only one client is allowed to connect to the server for now.
         * Block until client calls QUIT on transmission thread.
         * Allow 200 msec sleep for thd_transmit to aquire connection_lock*/
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ar_osal_mutex_lock(connection_lock);

        status = ar_osal_thread_join_destroy(thd_transmit);
        if (AR_FAILED(status))
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Failed to destroy connection thread", status);
        }
    }

    ar_socket_close(listen_socket);
    ar_socket_close(accept_socket);
    //for (int j = 0; j < MAX_TCPIP_CLIENTS_ALLOWED; j++)
    //{
    //    status = ar_osal_thread_join_destroy(thd_transmit);
    //    if (AR_FAILED(status))
    //    {
    //        TCPIP_CMD_SVR_ERR("Error[%d]: Failed to destroy connection thread", status);
    //    }
    //}

    return 0;
}

void TcpipCmdServer::start_dls_server()
{
#ifdef ATS_DATA_LOGGING

    _dls_server.address = TCPIP_CMD_SERVER_ADDRESS;
    // _dls_server.port = TCPIP_DLS_SERVER_PORT;
    _dls_server.stop();
    if (AR_FAILED(_dls_server.start()))
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Unable to start the tcpip dls server. Skipping...");
    }

#endif
}

void TcpipCmdServer::stop_dls_server()
{
#ifdef ATS_DATA_LOGGING

    _dls_server.stop();

#endif
}

void *TcpipCmdServer::transmit_routine(void *args)
{
    __UNREFERENCED_PARAM(args);

    int32_t status = AR_EOK;
    const uint32_t maxsize = ATS_BUFFER_LENGTH;//TODO: We need to introduce a command to change this size. 2mb is too high
    char_t* outbuf = NULL;

    struct ar_heap_info_t heap_inf =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };

    ar_osal_mutex_lock(connection_lock);

    message_buffer.buffer_size = ATS_BUFFER_LENGTH;
    recieve_buffer.buffer_size = TCPIP_CMD_SERVER_RECV_BUFFER_SIZE;
    //Stores one message
    message_buffer.buffer = (char_t*)ar_heap_malloc(message_buffer.buffer_size, &heap_inf);
    if (NULL == message_buffer.buffer)
        return 0;

    recieve_buffer.buffer = (char_t*)ar_heap_malloc(recieve_buffer.buffer_size, &heap_inf);
    if (NULL == recieve_buffer.buffer) {
        ar_heap_free(message_buffer.buffer, &heap_inf);
        return 0;
    }

    outbuf = (char_t*)ar_heap_malloc(maxsize, &heap_inf);
    if (NULL == outbuf) {
        ar_heap_free(message_buffer.buffer, &heap_inf);
        ar_heap_free(recieve_buffer.buffer, &heap_inf);
        return 0;
    }
    ar_mem_set(outbuf, 0, 1);

    while (true)
    {
        uint32_t request_message_length = 0;
        uint32_t response_message_length = 0;

        /* This is for readability when analyzing the logs.We want to separate each command
         * sent by the client with a new line to understand all the operations that occur
         * during one command */
        TCPIP_CMD_SVR_DBG("\n");

        status = recv_message_header(
            message_buffer.buffer, message_buffer.buffer_size,
            recieve_buffer.buffer, recieve_buffer.buffer_size,
            request_message_length);
        if (AR_FAILED(status))
        {
            if (AR_ETERMINATED == status)
            {
                TCPIP_CMD_SVR_INFO("Ending data transmission...")
            }
            else
            {
                TCPIP_CMD_SVR_ERR("Error[%d]: Failed to read message header",
                    status);
            }
            break;
        }

        status = recv_message(
            message_buffer.buffer, message_buffer.buffer_size,
            recieve_buffer.buffer, recieve_buffer.buffer_size,
            request_message_length);
        if (AR_FAILED(status) && status != AR_ENEEDMORE)
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Failed to read message data", status);
            break;
        }

        status = process_message(
            message_buffer.buffer, message_buffer.buffer_size, request_message_length,
            (char_t**)&outbuf,
            maxsize, response_message_length);
        if (AR_FAILED(status))
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Failed to read message data", status);
            break;
        }

        status = send_message(outbuf, maxsize, response_message_length);
        if (AR_FAILED(status))
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Failed to send message", status);
            break;
        }
    }

    //Cleanup
    TCPIP_CMD_SVR_DBG("%s: closing thread", thd_name.c_str());

    ar_heap_free(message_buffer.buffer, &heap_inf);
    ar_heap_free(recieve_buffer.buffer, &heap_inf);

    is_connected = false;
    ar_osal_mutex_unlock(connection_lock);
    return 0;
}

int32_t TcpipCmdServer::recv_message_header(char_t *msgBuf, uint32_t msgbuflen,
    char_t *recvbuf, uint32_t recvbuflen, uint32_t &msg_len)
{
    int32_t status = AR_EOK;
    int32_t bytes_recieved = 0;
    int32_t headerBytesRead = 0;
    char svc_id_str[ATS_SEVICE_ID_STR_LEN] = { 0 };
    uint32_t svc_cmd_id = 0;

    while (true)
    {
        //receive full message header
        TCPIP_CMD_SVR_DBG("Waiting to recieve message...");

        if (ATS_HEADER_LENGTH - headerBytesRead > (int32_t)recvbuflen)
        {
            return AR_EBADPARAM;
        }
        status = ar_socket_recv(accept_socket, recvbuf, ATS_HEADER_LENGTH - headerBytesRead, 0, &bytes_recieved);

        if (bytes_recieved < 0)
        {
            if (AR_SOCKET_LAST_ERROR == EINTR) continue;

            TCPIP_CMD_SVR_ERR("Receive failed with error: %d\n", AR_SOCKET_LAST_ERROR);
            ar_socket_close(accept_socket);
            return AR_EFAILED;
        }
        else if (bytes_recieved == 0)
        {
            TCPIP_CMD_SVR_INFO("Client shutdown socket. Closing connection...");
            ar_socket_close(accept_socket);
            return AR_ETERMINATED;
        }

        TCPIP_CMD_SVR_DBG("Recieved %d bytes", bytes_recieved);

        /* The client sends "QUIT" to signal end of connection. The server will close
         * the socket and return */
        if (ar_strcmp(recvbuf, ATS_SERVER_CMD_QUIT.c_str(), 4) == 0)
        {
            TCPIP_CMD_SVR_INFO("Quitting...");
            ar_socket_close(accept_socket);
            return AR_ETERMINATED;
        }

        if (headerBytesRead > (int32_t)msgbuflen)
        {
            return AR_EBADPARAM;
        }
        ar_mem_cpy(msgBuf + headerBytesRead, bytes_recieved, recvbuf, bytes_recieved);
        headerBytesRead += bytes_recieved;

        //this determines how many bytes to expect (thus determining how many times to loop).
        if (tcpip_cmd_server_get_ats_command_length(msgBuf, bytes_recieved, &msg_len))
        {
            svc_cmd_id = 0;
            ar_mem_cpy(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
                msgBuf + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);

            ATS_SERVICE_ID_STR(svc_id_str, ATS_SEVICE_ID_STR_LEN, svc_cmd_id);
            TCPIP_CMD_SVR_DBG("Recieved Command[%s-%d] with length %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), msg_len);
            break;
        }
    }

    msg_len += ATS_HEADER_LENGTH;

    return status;
}

int32_t TcpipCmdServer::recv_message(char_t *msgBuf, uint32_t msgbuflen,
    char_t *recvbuf, uint32_t recvbuflen, uint32_t msg_len)
{
    __UNREFERENCED_PARAM(recvbuflen);
    int32_t status = AR_EOK;
    int32_t bytes_recieved = 0;
    uint32_t message_bytes_read = 0;
    uint32_t remaining_message_length = 0;
    uint32_t recv_len = 0;
    uint32_t data_length = msg_len;
    bool_t should_write_msg = TRUE;

    if (msg_len > msgbuflen)
    {
        /* We reject messages that are larger that what we can store in our message buffer */
        TCPIP_CMD_SVR_ERR("Error[%d]: Not enough memory to store incoming message of %d bytes. "
            "Use resize buffer command to update the max buffer size", AR_ENEEDMORE, msg_len);

        should_write_msg = FALSE;
        status =  AR_ENEEDMORE;
    }

    data_length -= ATS_HEADER_LENGTH;
    while (data_length > 0)
    {
        //receive rest of message
        if (message_bytes_read > data_length)
        {
            TCPIP_CMD_SVR_ERR("Error[%d]: Read more than message length. Exiting..",
                AR_ENEEDMORE);
            ar_socket_close(accept_socket);

            return AR_ENEEDMORE;
        }

        remaining_message_length = data_length - message_bytes_read;
        recv_len = remaining_message_length < TCPIP_CMD_SERVER_RECV_BUFFER_SIZE ?
            remaining_message_length : TCPIP_CMD_SERVER_RECV_BUFFER_SIZE;

        //will receive min(TCPIP_CMD_SERVER_RECV_BUFFER_SIZE, bytes left to receive to complete message)
        bytes_recieved = recv(accept_socket, recvbuf, recv_len, 0);

        if (bytes_recieved > 0)
        {
            TCPIP_CMD_SVR_DBG("Recieved %d bytes", bytes_recieved);

            if (should_write_msg)
            {
                if (ATS_HEADER_LENGTH + message_bytes_read > msgbuflen)
                {
                    TCPIP_CMD_SVR_ERR("Message bytes read + ATS Header %d bytes is greater "
                        "than message buffer length %d bytes",
                        ATS_HEADER_LENGTH + message_bytes_read, msgbuflen);
                    return AR_ENEEDMORE;
                }

                ar_mem_cpy(msgBuf + ATS_HEADER_LENGTH + message_bytes_read, bytes_recieved,
                    recvbuf, bytes_recieved);
            }

            message_bytes_read += bytes_recieved;
            if (message_bytes_read == data_length)
            {
                break;
            }
        }
        else if (bytes_recieved <= 0)
        {
            if (AR_SOCKET_LAST_ERROR == EINTR)
            {
                //TCPIP_CMD_SVR_DBG("Signal interruption detected. Continuing..");
                continue;
            }

            TCPIP_CMD_SVR_ERR("Receive failed with error: %d", AR_SOCKET_LAST_ERROR);
            ar_socket_close(accept_socket);
            return AR_EFAILED;
        }
    }

    return status;
}

int32_t TcpipCmdServer::process_message(
    char_t* msg_buffer, uint32_t msg_buffer_size, uint32_t msg_length,
    char_t** out_buf, uint32_t out_buf_len, uint32_t& resp_len)
{
    __UNREFERENCED_PARAM(out_buf_len);
    int32_t status = AR_EOK;
    //uint32_t recvlen_ptr = 0;
    uint32_t svc_cmd_id = 0;
    uint32_t data_length = 11;//TODO: Why is this hardcoded to 11?
    char svc_id_str[ATS_SEVICE_ID_STR_LEN] = { 0 };
    if (msg_length > msg_buffer_size)
    {
        /* We reject messages that are larger that what we can store in our message buffer */
        tcpip_cmd_server_create_error_resp(svc_cmd_id, AR_ENEEDMORE,
            *out_buf, out_buf_len, resp_len);
        goto process_message_end;
    }

    svc_cmd_id = 0;
    ar_mem_cpy(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
        msg_buffer + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);

    tcpip_cmd_server_get_ats_command_length(msg_buffer, msg_length, &data_length);
    ATS_SERVICE_ID_STR(svc_id_str, ATS_SEVICE_ID_STR_LEN, svc_cmd_id);
    TCPIP_CMD_SVR_DBG("Command[%s-%d]: Request data length is %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), data_length);

    //Handle server commands like RESIZE_BUFFER, etc..
    if (ATS_ONLINE_SERVICE_ID == ATS_GET_SERVICE_ID(svc_cmd_id))
    {
        status = execute_server_command(svc_cmd_id, msg_length);

        if (AR_FAILED(status))
        {
            tcpip_cmd_server_create_error_resp(svc_cmd_id, status,
                *out_buf, out_buf_len, resp_len);
            status = AR_EOK;
            goto process_message_end;
        }
    }

    //passing received data and blank output buffer to ats upcall
    execute_command((uint8_t *)message_buffer.buffer, (uint32_t)msg_length,
        (uint8_t**)out_buf, &resp_len);

    //resp_len = recvlen_ptr;

process_message_end:
    TCPIP_CMD_SVR_DBG("Outbound message of length %d bytes", resp_len);

    return status;
}

int32_t TcpipCmdServer::send_message(char_t* buf, uint32_t buf_len, uint32_t msg_len)
{
    int32_t status = AR_EOK;
    int32_t bytes_sent = 0;
    uint32_t data_length = 0;
    uint32_t svc_cmd_id = 0;
    char svc_id_str[ATS_SEVICE_ID_STR_LEN] = { 0 };

    if (buf == NULL)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: The send buffer is null", AR_EBADPARAM);
        return AR_EBADPARAM;
    }

    if (msg_len > buf_len)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: The message length %d bytes is >"
            " the send buffer length %d", AR_EBADPARAM, msg_len, buf_len);
        return AR_EBADPARAM;
    }

    tcpip_cmd_server_get_ats_command_length(buf, msg_len, &data_length);

    ar_mem_cpy(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
        buf + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);
    ATS_SERVICE_ID_STR(svc_id_str, ATS_SEVICE_ID_STR_LEN, svc_cmd_id);
    TCPIP_CMD_SVR_DBG("Command[%s-%d]: Sending response of %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), data_length);

    //Send response to client
    status = ar_socket_send(accept_socket, buf, msg_len, 0, &bytes_sent);
    if (AR_FAILED(status))
    {
        TCPIP_CMD_SVR_ERR("Unable to send message. Socket error: %d", AR_SOCKET_LAST_ERROR);
        ar_socket_close(accept_socket);
    }
    else
    {
        TCPIP_CMD_SVR_DBG("Message sent");
    }

    return status;
}

int32_t TcpipCmdServer::execute_server_command(uint32_t service_cmd_id, uint32_t message_length)
{
    switch (service_cmd_id)
    {
    case ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH:
    {
        uint32_t new_buffer_size = 0;
        uint32_t data_length = 0;
        uint32_t offset = 0;
        struct ar_heap_info_t heap_inf =
        {
            AR_HEAP_ALIGN_DEFAULT,
            AR_HEAP_POOL_DEFAULT,
            AR_HEAP_ID_DEFAULT,
            AR_HEAP_TAG_DEFAULT
        };

        if (message_length < sizeof(uint32_t))
        {
            return AR_ENEEDMORE;
        }

        ar_mem_cpy(&data_length, sizeof(uint32_t),
            this->message_buffer.buffer + ATS_DATA_LENGTH_POSITION, sizeof(uint32_t));
        ar_mem_cpy(&new_buffer_size, sizeof(uint32_t),
            this->message_buffer.buffer + ATS_ACDB_BUFFER_POSITION, sizeof(uint32_t));

        //The new buffer size needs to be between the required range to resize the message buffer:
        //range: AGWS_RECV_BUF_SIZE * 4 < new buffer size < GWS_MAX_BUFFER_SIZE
        //Largest buffer size is 2mb the GWS_MAX_BUFFER_SIZE
        //Smalleset buffer size is 4 * 1024 the recieve buffer size
        if ((new_buffer_size > this->message_buffer.buffer_size && new_buffer_size < TCPIP_CMD_SERVER_MAX_MSG_BUFFER_SIZE) ||
            (new_buffer_size < this->message_buffer.buffer_size && new_buffer_size > TCPIP_CMD_SERVER_MIN_MSG_BUFFER_SIZE)
            )
        {
            ar_heap_free(message_buffer.buffer, &heap_inf);

            message_buffer.buffer_size = new_buffer_size;
            message_buffer.buffer = (char_t*)ar_heap_malloc(message_buffer.buffer_size, &heap_inf);
            if (NULL == message_buffer.buffer)
            {
                TCPIP_CMD_SVR_ERR("Error[%d]: Failed to resize gateway message buffer", AR_ENOMEMORY);
                return AR_ENOMEMORY;
            }

            ar_mem_set(message_buffer.buffer, 0, message_buffer.buffer_size);

            /* Write the ATS command back to the resized message buffer so that the ATS Command
             * layer can resize its buffer.*/
            ar_mem_cpy(message_buffer.buffer, sizeof(uint32_t), &service_cmd_id, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            ar_mem_cpy(message_buffer.buffer + offset, sizeof(uint32_t), &data_length, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            ar_mem_cpy(message_buffer.buffer + offset, sizeof(uint32_t), &new_buffer_size, sizeof(uint32_t));
        }
    }
    break;
    default:
        break;
    }

    return AR_EOK;
}

/*
============================================================================
                   Helper Functions
============================================================================
*/

static bool_t tcpip_cmd_server_get_ats_command_length(
    char_t* message_buffer, uint32_t message_buffer_size, uint32_t* data_length)
{
    bool_t result = FALSE;
    if (NULL == message_buffer || NULL == data_length)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Input parameter is null", AR_EBADPARAM);
        return FALSE;
    }
    if (message_buffer_size < ATS_HEADER_LENGTH)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Message buffer is smaller than request header format length", AR_ENEEDMORE);
        result = FALSE;
    }
    else
    {
        /** copy data length*/
        ar_mem_cpy(data_length, ATS_DATA_LENGTH_LENGTH,
            message_buffer + ATS_DATA_LENGTH_POSITION, ATS_DATA_LENGTH_LENGTH);

        result = TRUE;
    }
    return result;
}

static void tcpip_cmd_server_create_error_resp(
    uint32_t service_cmd_id, uint32_t ar_status_code,
    char_t* message_buffer, uint32_t message_buffer_size,
    uint32_t& message_length
)
{
    /* The format of the command response message is:
     * <-----------4bytes------------>
     * +-----------------------------+
     * |  service id  |  command id  |
     * +-----------------------------+
     * +-----------------------------+
     * |         data length         |
     * +-----------------------------+
     * +-----------------------------+
     * |            status           |
     * +-----------------------------+ */
    uint32_t resp_data_length;

    if (NULL == message_buffer)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Response Buffer is not initialized", AR_EBADPARAM);
        message_length = 0;
        return;
    }

    if (message_buffer_size < ATS_ERROR_FRAME_LENGTH)
    {
        TCPIP_CMD_SVR_ERR("Error[%d]: Unable to create error response. "
            "The response buffer is less than %d bytes",
            AR_EBADPARAM, ATS_ERROR_FRAME_LENGTH);
        return;
    }

    message_length = ATS_ERROR_FRAME_LENGTH;
    resp_data_length = ATS_ERROR_FRAME_LENGTH - ATS_HEADER_LENGTH;

    //Service + Command ID
    ar_mem_cpy(message_buffer, ATS_SERVICE_COMMAND_ID_LENGTH,
        &service_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH);

    //Data Length
    ar_mem_cpy(message_buffer + ATS_SERVICE_COMMAND_ID_LENGTH, ATS_DATA_LENGTH_LENGTH,
        &resp_data_length,
        ATS_DATA_LENGTH_LENGTH);

    //Status
    ar_mem_cpy(message_buffer + ATS_HEADER_LENGTH, ATS_ERROR_CODE_LENGTH,
        &ar_status_code,
        ATS_ERROR_CODE_LENGTH);
}

#endif /*ATS_TRANSPORT_TCPIP*/
