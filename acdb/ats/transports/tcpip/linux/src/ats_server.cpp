/**
*=============================================================================
*  \file ats_server.cpp
*  \brief
*                   A T S  S E R V E R  S O U R C E  F I L E
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
*
*=============================================================================
*/

/*
-------------------------------
|Include Files                |
-------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <iostream>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>



#if defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/un.h>
#include <arpa/inet.h>
#ifdef AR_ATS_USE_CUTILS
#include <cutils/properties.h>
#endif
#elif defined(_WIN32)
//Windows
#include <winsock2.h>
#include <ws2tcpip.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
#endif

extern "C"
{
#include "ats.h"
#include "ats_i.h"
#include "ats_server.h"
#include "ar_osal_types.h"
}

#if defined(__linux__)
#define ADDRESS_FAMILY AF_UNIX
#define PROTOCOL 0
typedef int SOCKET;

#define ATS_INVALID_SOCKET(s) ((s) < 0)
#define atsclosesocket close
#elif defined(_WIN32)
#define ADDRESS_FAMILY AF_INET
#define PROTOCOL IPPROTO_TCP

#define ATS_INVALID_SOCKET(s) (s == INVALID_SOCKET)
#define atsclosesocket closesocket
#endif

/* ---------------------------------------------------------------------------
* Global Variables
*--------------------------------------------------------------------------- */
ar_osal_thread_t g_thd_ats_listener;
ar_osal_thread_t g_transmit_thread_holder[MAX_ATS_CLIENTS_ALLOWED];

ar_osal_mutex_t g_connected_mutex;//rename to connection lock
uint8_t g_is_connected; //used to ensure only one QACT client will be connected at one time

ats_server_context g_ats_server_context = { 0 };

AtsBufferManager *ats_buffer_manager = NULL;
bool_t g_should_close_server = FALSE;
SOCKET g_server_socket = NULL;

/* ---------------------------------------------------------------------------
* Helper Functions
*--------------------------------------------------------------------------- */
/**
	\brief
		Helper function that retrieves the expected message length from the message header

	\detdesc
		Passed in buffer must be in the following format:
			*-----------------------------------------------------*
			|  SERVICE ID |  CMD ID  |  CMD Size  |  CMD Payload  |
			|  2 bytes    |  2 bytes |  4 bytes   |  n byteS      |
			*-----------------------------------------------------*
		Note: the size referes to the n bytes of the payload (not including header
		size of 6 bytes)

	\dependencies
		None

	\param [in] rec_buf_ptr: Parameters to be used within the thread routine
	\param [in] req_buf_length: Parameters to be used within the thread routine
	\param [in] data_length: Parameters to be used within the thread routine

	\return
		TRUE if successfully parsed and FALSE otherwise
*/
static bool_t get_command_length_s(char_t* rec_buf_ptr, uint32_t req_buf_length, uint32_t* data_length);

#if defined(_WIN32)

/**
*	\brief
*		Initializes the Windsock DLL
*
*	\param [in] socket_descriptor: a pointer to an allocated socket object that
*                                  will be filled in
*	\return
*		0 on success, non-zero on failure
*/
int32_t init_winsock(void)
{
    int result = 0;
    WSADATA wsaData = { 0 };

    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != NO_ERROR)
    {
        ATS_ERR("Failed to initialize winsock. WSAStartup Error(%d)", result);
        return AR_EFAILED;
    }
    return result;
}

/**
*	\brief
*		Creates a windows based socket
*
*	\param [in] socket_descriptor: a pointer to an allocated socket object that
*                                  will be filled in
*	\return
*		0 on success, non-zero on failure
*/
int32_t create_socket_win(SOCKET *socket_descriptor)
{
    int32_t status = AR_EOK;
    SOCKET socketfd = NULL;

    status = init_winsock();
    if (AR_FAILED(status))
    {
        return status;
    }

    ATS_DBG("Setting up sockets...");
	//creates socket and references the socket using a file descriptor
	socketfd = socket(ADDRESS_FAMILY, SOCK_STREAM, PROTOCOL);
	ATS_DBG("sockfd: %d\n", socketfd);

	//Checks for errors from socket function
	if (ATS_INVALID_SOCKET(socketfd))
	{
		ATS_ERR("Error opening socket");
		perror("Error opening socket");

		//Prints out specific error in ADBLogcat
		ATS_ERR("socket error: %d - %s", errno, strerror(errno));
		return status;
	}

	//AtsSockAddr addr = { 0 };
	sockaddr_in addr = {0};
	addr.sin_family = ADDRESS_FAMILY;
	inet_pton(ADDRESS_FAMILY, ATS_SERVER_ADDRESS, &addr.sin_addr.s_addr);
	addr.sin_port = htons(ATS_GATEWAY_PORT);

	//binds socket to socket path
	status = bind(socketfd, (struct sockaddr*)&addr, sizeof(addr));
	//checks for errors when binding address and prints to ADBLogcat
	if (status < 0) {
		ATS_ERR("bind socket error: %d - %s", errno, strerror(errno));
		ATS_ERR("Bind to %s:%d", ATS_SERVER_ADDRESS, ATS_GATEWAY_PORT);
		status = AR_EFAILED;
		atsclosesocket(socketfd);
		return status;
	}
	else {
		ATS_ERR("Bind successful");
	}

	*socket_descriptor = socketfd;

	return status;
}
#endif
#if defined(__linux__)
/**
*	\brief
*		Creates a unix based socket
*
*	\param [in] socket_descriptor: a pointer to an allocated socket object that
*                                  will be filled in
*	\return
*		0 on success, non-zero on failure
*/
int32_t create_socket_unix(SOCKET *socket_descriptor)
{
    __UNREFERENCED_PARAM(socket_descriptor);

    int32_t status = AR_EOK;

    return status;
    /*
    ATS_DBG("Setting up sockets...");

    //creates socket and references the socket using a file descriptor
    SOCKET socketfd = socket(ADDRESS_FAMILY, SOCK_STREAM, PROTOCOL);
    ATS_DBG("sockfd: %d", socketfd);

    //Checks for errors from socket function
    if (ATS_INVALID_SOCKET(socketfd))
    {
        ATS_ERR("Error opening socket");
        perror("Error opening socket");

        //Prints out specific error in ADBLogcat
        ATS_ERR("socket error: %d - %s", errno, strerror(errno));
        return status;
    }

    //mode_t process_mask = umask(0);
    //700 is permission for -rwx------ (read/write/execute for only owner)
    char socket_path[] = SOCK_PATH;
    mode_t permissions = S_IRUSR | S_IWUSR | S_IXUSR;
    status = mkdir(socket_path, permissions);
    chmod(socket_path, permissions); //if already exists

    //umask(process_mask);
    struct sockaddr_un addr;
    ATS_DBG("Mode for directory and file is: %o", permissions);
    char socket_path_file[] = SOCK_PATH_SERVER;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = ADDRESS_FAMILY;
    AcdbStrCpy(addr.sun_path, sizeof(addr.sun_path), socket_path_file, strlen(socket_path_file));
    unlink(socket_path_file);

    //binds socket to socket path
    status = bind(socketfd, (struct sockaddr*)&addr, sizeof(addr));
    //checks for errors when binding address and prints to ADBLogcat
    if (status < 0) {
        ATS_ERR("bind socket error: %d - %s", errno, strerror(errno));
        ATS_ERR("Bind to %s:%d", ATS_SERVER_ADDRESS, ATS_GATEWAY_PORT);
        status = AR_EFAILED;
        return status;
    }
    else {
        ATS_ERR("Bind successful");
    }

    *socket_descriptor = socketfd;

    return status;
    */
}
#endif

/**
*	\brief
*		Creates a socket depending on the platform. Currently supports Unix and
*       windows based sockets
*
*	\param [in] socket_descriptor: a pointer to an allocated socket object that
*                                  will be filled in
*	\return
*		0 on success, non-zero on failure
*/
int32_t create_socket(SOCKET *sd)
{
    SOCKET socket_descriptor = 0;
    int32_t status = AR_EOK;

#if defined(__linux__)
    status = create_socket_unix(&socket_descriptor);
#elif defined(_WIN32)
    status = create_socket_win(&socket_descriptor);
#endif

    *sd = socket_descriptor;
    return status;
}

/**
*	\brief
*		Creates a server socket and listens for clients.
*
*	\detdesc
*       Once a client is connected, a transmission thread is created
*       for processing commands. Only client can be connected at a
*       time to perform operations on the ACDB and DSP.
*
*	\param [in] arg: This input parameter is unused
*
*	\return
*		0 on success, non-zero on failure
*/
void* ats_server_start_routine(void* arg)
{
    __UNREFERENCED_PARAM(arg);
    ATS_DBG("Starting TCP/IP server thread.");

    int32_t status = AR_EOK;
    char str_addr[MAX_LENGTH_IP_ADDRESS] = { 0 };
	SOCKET sockfd;
	status = create_socket(&sockfd);
	if (AR_FAILED(status))
	{
		ATS_ERR("Failed to create and bind to socket");
	}

    g_server_socket = sockfd;

    //fd_set socket_set;
    //socket_set.fd_count = 1;
    //socket_set.fd_array = &sockfd;
    //timeval tv;
    //tv.tv_sec = 1;
    //tv.tv_usec = 0;

    //int num_ready_sockets = select(0, NULL, &socket_set, NULL, &tv);

    ATS_ERR("Listening for connections...");

    //listen queue is of size 5
    status = listen(sockfd, 5);
	if (status < 0) {
            ATS_ERR("Error on listening");
            perror("Error on listen");
	}
    else {
           ATS_ERR("Listening successful");
    }

    //initializing mutex and setting up environment for threading
	ar_osal_mutex_init(g_connected_mutex);
	ar_osal_mutex_lock(g_connected_mutex);
    g_is_connected = 0;
	ar_osal_mutex_unlock(g_connected_mutex);

    int i = 0;


    //uint8_t connected = 0;

    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t addr_size = sizeof(client_addr);
        SOCKET *gateway_socket_ptr = (SOCKET*)malloc(sizeof(SOCKET));
		if (IsNull(gateway_socket_ptr))
		{
			ATS_ERR("Insufficient memory to create socket");
			g_server_socket = NULL;
			atsclosesocket(sockfd);
			return 0;
		}
		memset(&client_addr, 0, addr_size);

        *gateway_socket_ptr = accept(sockfd, (struct sockaddr*)&client_addr, &addr_size);

        if (g_should_close_server)
        {
            atsclosesocket(*gateway_socket_ptr);
            ACDB_FREE(gateway_socket_ptr);
            break;
        }

        if (ATS_INVALID_SOCKET(*gateway_socket_ptr))
		{
			atsclosesocket(*gateway_socket_ptr);
			ACDB_FREE(gateway_socket_ptr);

            if (errno == EINTR) continue;

            inet_ntop(ADDRESS_FAMILY, &client_addr.sin_addr, str_addr, MAX_LENGTH_IP_ADDRESS);
	        ATS_ERR("Accept error: %s",  strerror(errno));
            ATS_ERR("Attempted Connection from: %s", str_addr);
        }
		else
		{
            if (g_is_connected) {
                ATS_ERR("New connection request. Refusing...");
				atsclosesocket(*gateway_socket_ptr);
				ACDB_FREE(gateway_socket_ptr);
                continue;
            }

            //Lock - Do not create more threads if already connected.
            ar_osal_mutex_lock(g_connected_mutex);

            inet_ntop(ADDRESS_FAMILY, &client_addr.sin_addr, str_addr, MAX_LENGTH_IP_ADDRESS);
            ATS_INFO("Accept successful to Gateway Service");
            ATS_INFO("Connection from: %s", str_addr);
            ATS_INFO("Starting transmission thread...");

			ar_osal_thread_t thd_ats_transmit;
			ar_osal_thread_start_routine routine = \
				(ar_osal_thread_start_routine)ats_server_transmit_routine;

			char threadName[32];
            ACDB_STR_CPY_SAFE(threadName, 32, ATS_THREAD_TRANSMIT, strlen(ATS_THREAD_TRANSMIT));
			ar_osal_thread_attr_t thd_attr = \
			{
				threadName,
					ATS_THD_STACK_SIZE,
					ATS_THREAD_PRIORITY_HIGH
			};

			status = ar_osal_thread_create(&thd_ats_transmit, &thd_attr,
                routine, gateway_socket_ptr);
            if (AR_FAILED(status))
			{
				ATS_ERR("Error[%d]: Failed to create transmission thread #%d.\n", status, i);
            }
			else
			{
				ATS_INFO("Created transmission thread #%d...", i);
                g_transmit_thread_holder[i] = thd_ats_transmit;
                g_is_connected = 1;
                i++;
                i %= MAX_ATS_CLIENTS_ALLOWED;
            }

			//Unlock
            ar_osal_mutex_unlock(g_connected_mutex);

			//TODO: move this cleanup work to a separate thread so that we can still refuse
			//new connection requests
			for (int thd = 0; thd < MAX_ATS_CLIENTS_ALLOWED; thd++)
			{
				ar_osal_thread_join_destroy(g_transmit_thread_holder[thd]);
				ACDB_FREE(gateway_socket_ptr);
			}
		}
	}

	atsclosesocket(sockfd);
	g_server_socket = NULL;

    return 0;
}

/**
*	\brief
*		Handles processing commands sent by clients and returns the
*       appropriate response.
*
*	\detdesc
*       This function allocates a message and recieve buffer that are
*       each ATS_BUFFER_LENGTH bytes. The message buffer holds the
*       request sent by the client and is read from the recieve buffer.
*       The recieve buffer is the socket buffer and holds data sent by clients.
*
*	\param [in] client_socket_ptr: the client socket used for
*                                  sending/recieving messages
*
*	\return
*		0 on success, non-zero on failure
*/
void* ats_server_transmit_routine(void* client_socket_ptr)
{
    SOCKET client_socket = *((SOCKET*)client_socket_ptr);
	//current maxsize of any expected message is 'ATS_BUFFER_LENGTH'
	const uint32_t maxsize = ATS_BUFFER_LENGTH;
    char svc_id_str[ATS_SEVICE_ID_STR_LEN] = { 0 };

    //Service Command ID 2 Byte Service ID + 2 Byte Command ID
    uint32_t svc_cmd_id = 0;

	//Stores one message
	char* msgBuf = (char*)ACDB_MALLOC(char, maxsize);
	if (NULL == msgBuf) {
		return 0;
	}
	char* recvbuf = (char*)ACDB_MALLOC(char, maxsize);
	if (NULL == recvbuf) {
		ACDB_FREE(msgBuf);
		return 0;
	}

	char* outbuf = (char*)ACDB_MALLOC(char, 1);  // An array of 5 haracters (including terminator)
	if (NULL == outbuf) {
		ACDB_FREE(msgBuf);
		ACDB_FREE(recvbuf);
		return 0;
	}
	char* holder = outbuf;
	memset(outbuf, 0, 1);

    /*
    This loop will run once per ENTIRE message received.
    Conditions that will exit this loop:
        1. An unexpected error occured that requires the thread to close
        2. A 'QUIT' command is sent by the client
    */
	while (true)
	{
		//keep listening for whole incoming messages
		int32_t bytes_recieved = 0;
		uint32_t headerBytesRead = 0;
		uint32_t msg_len = 0;
		//---------------------------
		memset(msgBuf, 0, maxsize);
		memset(recvbuf, 0, ATS_RECIEVE_BUF_SIZE);
		//memset(outbuf, 0, maxsize);

		//This loop will run as many times as to receive full message header (should be just once)
		while (true)
		{
			//receive full message header
			ATS_ERR("Waiting to recieve message...");
			bytes_recieved = recv(client_socket, recvbuf, ATS_HEADER_LENGTH - headerBytesRead, 0);

			//client sends "QUIT" to signal end of connection. At that point, close socket and return.
			if (strncmp(recvbuf, ATS_SERVER_CMD_QUIT, 4) == 0)
			{
				ATS_DBG("Quitting...");

				atsclosesocket(client_socket);
				goto threaddone;
			}

			if (bytes_recieved > 0)
			{
				ATS_DBG("Recieved %d bytes", bytes_recieved);
				ACDB_MEM_CPY_SAFE(msgBuf + headerBytesRead, bytes_recieved, recvbuf, bytes_recieved);
				headerBytesRead += bytes_recieved;

				//this determines how many bytes to expect (thus determining how many times to loop).
				if (get_command_length_s(msgBuf, bytes_recieved, &msg_len))
				{
					svc_cmd_id = 0;
					ACDB_MEM_CPY_SAFE(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
						msgBuf + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);

                    ATS_SERVICE_ID_STR(svc_id_str, ATS_SEVICE_ID_STR_LEN, svc_cmd_id);
					ATS_ERR("Recieved Command[%s-%d] with length %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), msg_len);
					break;
				}
			}
			else if (bytes_recieved <= 0)
			{
				if (errno == EINTR) continue;

				ATS_ERR("Receive failed with error: %s\n", strerror(errno));
				atsclosesocket(client_socket);
				goto threaddone;
			}
		}

		uint32_t payload_bytes_read = 0;

		//this loop will receive maxbufsize bytes each iteration, looping until it receives a full message
		while (msg_len != 0)
		{
			//receive rest of message
			if (payload_bytes_read > msg_len) {
				ATS_ERR("Read more than message length...corruption\n");
				atsclosesocket(client_socket);
				goto threaddone;
			}

			uint32_t remaining_recv_len = msg_len - payload_bytes_read;
			uint32_t recv_len = remaining_recv_len > ATS_RECIEVE_BUF_SIZE ? remaining_recv_len : ATS_RECIEVE_BUF_SIZE;

			//will receive min(ATS_RECIEVE_BUF_SIZE, bytes left to receive to complete message)
			bytes_recieved = recv(client_socket, recvbuf, recv_len, 0);

			if (bytes_recieved > 0) {
				ATS_ERR("Recieved %d bytes", bytes_recieved);
				ACDB_MEM_CPY_SAFE(msgBuf + ATS_HEADER_LENGTH + payload_bytes_read, bytes_recieved, recvbuf, bytes_recieved);
				payload_bytes_read += bytes_recieved;
				if (payload_bytes_read == msg_len) {
					break;
				}
			}
			else if (bytes_recieved <= 0) {
                if (errno == EINTR) {
                    ATS_ERR("Signal interrupt. Continuing...");
                    continue;
                }
				ATS_ERR("Receive failed with error: %s", strerror(errno));
				atsclosesocket(client_socket);
				goto threaddone;
			}
		}

		ATS_ERR("Full message received from client");
		//handle message handling - calls to ATS/ACDB
		uint32_t* recvlen_ptr = (uint32_t*)ACDB_MALLOC(uint32_t, 1);
		if (recvlen_ptr == NULL) {
			atsclosesocket(client_socket);
			goto threaddone;
		}

		memset(recvlen_ptr, 0, sizeof(uint32_t));
		msg_len += ATS_HEADER_LENGTH;
		svc_cmd_id = 0;
		ACDB_MEM_CPY_SAFE(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
            msgBuf + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);

		uint32_t msgBufCheck = 11;//TODO: Why is this hardcoded to 11?
		get_command_length_s(msgBuf, msg_len, &msgBufCheck);
		ATS_ERR("Command[%s-%d]: Request data length is %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), msgBufCheck);

		//passing received data and blank output buffer to ats upcall
		g_ats_server_context.ats_cb((uint8_t *)msgBuf, (uint32_t)msg_len, (uint8_t**)&outbuf, recvlen_ptr);

		ATS_ERR("Outbound message of length %d bytes", *recvlen_ptr);
		uint32_t outlen = 0;
        svc_cmd_id = 0;
		get_command_length_s(outbuf, *recvlen_ptr, &outlen);

		ACDB_MEM_CPY_SAFE(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
            outbuf + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);

		ATS_ERR("Command[%s-%d]: Sending response of %d bytes", svc_id_str, ATS_GET_COMMAND_ID(svc_cmd_id), outlen);

        int32_t send_result = 0;

        /* GATEWAY HEADER
        Only send accros the bytes nessesary (not MAX_SIZE bytes)
        <-----------4bytes------------>
        +-----------------------------+
        |         msg length          |
        +-----------------------------+
        +-----------------------------+
        |                             |
        |       msg(msg length)       |
        |                             |
        +-.-.-.-.-.-.-.-.-.-.-.-.-.-.-+ */

        //char* gatewayMessage = (char*)malloc(sizeof(uint32_t) + *recvlen_ptr);
        //memcpy(gatewayMessage, recvlen_ptr, sizeof(uint32_t));
        //memcpy(gatewayMessage + sizeof(uint32_t), outbuf, *recvlen_ptr);
        //
        //send_result = ::send(client_socket, gatewayMessage, sizeof(uint32_t) + *recvlen_ptr, 0);
        //ACDB_FREE(gatewayMessage);

        //No Gateway Header (for debugging purposes)
        send_result = ::send(client_socket, outbuf, *recvlen_ptr, 0);
		ACDB_FREE(recvlen_ptr);

		if (send_result < 0) {
			ATS_ERR("Send failed with error: %s\n", strerror(errno));
			atsclosesocket(client_socket);
			goto threaddone;
		}
        ATS_ERR("Message sent\n");
	}

threaddone:
	ACDB_FREE(msgBuf);
	ACDB_FREE(recvbuf);
	ACDB_FREE(holder);
	//ACDB_FREE(outbuf);

	ATS_INFO("Transmission thread closed...\n");

    ar_osal_mutex_lock(g_connected_mutex);
    g_is_connected = 0;
    ar_osal_mutex_unlock(g_connected_mutex);
    ACDB_FREE(client_socket_ptr);
	return 0;
}

static bool_t get_command_length_s(char_t* rec_buf_ptr, uint32_t req_buf_length, uint32_t* data_length) {
	bool_t result = FALSE;
	if (IsNull(rec_buf_ptr) || IsNull(data_length))
	{
		ATS_ERR("Input parameter is null");
		return FALSE;
	}
	if (req_buf_length < ATS_HEADER_LENGTH)
	{
		ATS_ERR("There is no data length information");
		result = FALSE;
	}
	else
	{
		/** copy data length*/
		ACDB_MEM_CPY_SAFE(data_length, ATS_DATA_LENGTH_LENGTH,
			rec_buf_ptr + ATS_DATA_LENGTH_POSITION, ATS_DATA_LENGTH_LENGTH);

		result = TRUE;
	}
	return result;
}

int32_t ats_server_init(void(*ats_cb)(uint8_t *buf, uint32_t buf_len, uint8_t **resp, uint32_t *resp_len)) {
    int32_t status = AR_EOK;

//#ifdef _WIN32
//    status = init_winsock();
//    if (AR_FAILED(status))
//    {
//        return status;
//    }
//#endif

    status = ar_osal_mutex_create(&g_connected_mutex);
    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to create mutex.\n");
        return status;
    }

    ATS_DBG("Creating server thread.");
    g_ats_server_context.ats_cb = ats_cb;

    char threadName[32];
    ACDB_STR_CPY_SAFE(threadName, 32, ATS_THREAD_LISTENER, strlen(ATS_THREAD_LISTENER));

    ar_osal_thread_attr_t thd_attr =
    {
        threadName,
        ATS_THD_STACK_SIZE,
        ATS_THREAD_PRIORITY_HIGH
    };

    ar_osal_thread_start_routine routine = \
        (ar_osal_thread_start_routine)ats_server_start_routine;

    status = ar_osal_thread_create(&g_thd_ats_listener, &thd_attr, routine, NULL);

    if (AR_FAILED(status))
    {
        ATS_ERR("Failed to create server thread.\n");
        return status;
    }

    return status;
}

int32_t ats_server_deinit()
{
    ATS_INFO("Shutting down server...");

    int32_t status = AR_EOK;

    g_should_close_server = TRUE;

    if (!IsNull(g_server_socket))
        atsclosesocket(g_server_socket);

	status = ar_osal_thread_join_destroy(g_thd_ats_listener);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]:An error occured when waiting to "
			"close the listener thread.", status);
		return status;
	}

	status = ar_osal_mutex_destroy(g_connected_mutex);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]:An error occured while "
			"destroying the mutex.", status);
		return status;
	}

	ATS_INFO("Status[%d]: ATS server shut down successfully.", status);
	return status;
}

