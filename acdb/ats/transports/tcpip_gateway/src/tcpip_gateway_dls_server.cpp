/**
*=============================================================================
*  \file tcpip_gateway_dls_server.cpp
*  \brief
*              T C P I P  G A T E W A Y  D L S  S E R V E R
*                         S O U R C E  F I L E
*
*    This file contains the TCPIP Gateway DLS Server implementation.
*
*    This server listens for clients on on port 5560 and allows one
*    connection per session. After establishing a connection the server will
*    send dls messages containing log data to the client. The client must
*    register log codeds to recievce log data.
*
*     ATS_DATA_LOGGING must be defined in the build configuration to use
*     this feature
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/
#if defined(ATS_DATA_LOGGING)

#include "tcpip_gateway_dls_server.h"
#include "tcpip_gateway_socket_util.h"
#include <thread>
#include <chrono>

#define IS_NULL(ptr) (ptr == NULL)

#define TCPIP_THREAD_PRIORITY_HIGH 0
#define TCPIP_THREAD_PRIORITY_LOW 1
#define TCPIP_THD_STACK_SIZE 0xF4240 //1mb stack size

#define TCPIP_DLS_SERVER_PORT 5560
#define TCPIP_ATS_DLS_SERVER_PORT 5561
#define MAX_TCPIP_CLIENTS_ALLOWED 1

/**< ATS TCPIP DLS Server(TRS) Log Tag */
#define TCPIP_DLS_SRV_LOG_TAG  "ATS-GTD"
#define TCPIP_DLS_ERR(...) AR_LOG_ERR(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)
#define TCPIP_DLS_DBG(...) AR_LOG_INFO(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)//AR_LOG_DEBUG
#define TCPIP_DLS_INFO(...) AR_LOG_INFO(TCPIP_DLS_SRV_LOG_TAG, __VA_ARGS__)


/* The name of the unix abstract domain socket used by the
 * ATS Server to communicate with the gateway server */
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS "#AtsDlsServer"
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS "#AtsGwDlsServer"

 /* The character length of the unix domain socket string
  * including the null-terminating character */
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS_LENGTH 13
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS_LENGTH 16

/* The byte position of the total log data size field in the DLS log data message packet */
#define DLS_LOG_DATA_FIELD_TOTAL_SIZE_POSITION 8
/* The byte size of the total log data size field in the DLS log data message packet */
#define DLS_LOG_DATA_FIELD_TOTAL_SIZE_LENGTH 4

#define DLS_LOG_DATA_HEADER_LENGTH 12

typedef void* (TcpipGatewayDlsServer::* tcpip_dls_server_thread_callback)(void* args);
static tcpip_dls_server_thread_callback thd_cb_gw_dls_connect_routine = &TcpipGatewayDlsServer::connect_routine;
static tcpip_dls_server_thread_callback thd_cb_gw_dls_transmit_routine = &TcpipGatewayDlsServer::transmit_routine;

/**
* \brief
*   Helper function that retrieves the expected message length from the command request header
*
* \detdesc
*   The message_buffer must be in the following format:
*   The DLS log buffers are bundled to gether and sent to the ATS client in the format below:
*
*                .+--   +================================+
*                |      |          'A''R''T''M'          |  bytes: 4
*                |      |  ----------------------------  |
*       Header-->|      |  Version                       |  bytes: 2
*                |      |  # Log Packets                 |  bytes: 2
*                .+--   |  Log Data Size                 |  bytes: 4
*                .+--   .--------------------------------.
*                |      |          Log Packet #1         |
*                |      |  ----------------------------  |
*                |      |  Packet Size                   |  bytes: 4
*                |      |  Packet Data [packet size]     |  bytes: Packet Size bytes
*                |      |--------------------------------|
*    Log Data--> |      :              ...               :
*                |      |--------------------------------|
*                |      |          Log Packet #n         |
*                |      |  ----------------------------  |
*                |      |  Packet Size                   |  bytes: 4
*                |      |  Packet Data [packet size]     |  bytes: Packet Size bytes
*                .+--   +.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~+
*
*   Note: the Log Data Size referes to the size of the data section (not including header
*   size of 12 bytes)
*
* \dependencies
*   None
*
* \param [in] message_buffer: The buffer containing the command request sent by the client
* \param [in] message_buffer_size: The length of the message buffer
* \param [in] data_length: The data length field in the command request header
*
* \return
*   TRUE if successfully parsed and FALSE otherwise
*/
static bool_t tgws_get_dls_log_data_length(
	char_t* message_buffer, uint32_t message_buffer_size, uint32_t* data_length);

void tgws_dls_get_client_address(uint16_t port, ar_socket_addr_storage_t* client_sock_addr);
void tgws_dls_get_server_address(uint16_t port, ar_socket_addr_storage_t* server_sock_addr);

/*
============================================================================
                        DLS TCPIP Server Implementation
============================================================================
*/

TcpipGatewayDlsServer::TcpipGatewayDlsServer()
	:is_connected{FALSE}
{
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};

	//todo: do we want to set this as part of the gateway config?
    str_pc_port =  "5560";
    // ats_gateway IP CMD_PORT DLS_PORT

	server_socket_ptr = (ar_socket_t*)ar_heap_malloc(sizeof(ar_socket_t), &heap_inf);
	client_socket_ptr = (ar_socket_t*)ar_heap_malloc(sizeof(ar_socket_t), &heap_inf);
	ar_mem_set(server_socket_ptr, 0, sizeof(ar_socket_t));
	ar_mem_set(client_socket_ptr, 0, sizeof(ar_socket_t));

	int32_t status = ar_osal_mutex_create(&connected_mutex);
	if (AR_FAILED(status))
	{
		TCPIP_DLS_ERR("Error[%d]: Failed to create mutex.", status);
	}
}

void TcpipGatewayDlsServer::set_ip_address(std::string address)
{
    str_ip_addr = address;
}

int32_t TcpipGatewayDlsServer::start()
{
    int32_t status = AR_EOK;
    std::string thd_name = "DLS_TCPIP_SVR";
	is_connected = FALSE;
	TCPIP_DLS_INFO("Starting gateway dls tcpip server");

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

int32_t TcpipGatewayDlsServer::stop()
{
	TCPIP_DLS_INFO("Is connected? value:%d 1= true, 0 = false", is_connected);
    if (!is_connected)
        return AR_EOK;

    //todo: add ar_socket_shutdown  and call it here
    //ar_socket_shutdown(accept_socket);

    TCPIP_DLS_INFO("Closing DLS TCPIP Server ...");
    int32_t status = ar_osal_thread_join_destroy(thread);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Failed to destroy connection thread", status);
    }

	is_connected = FALSE;
    should_close_server = true;
    ar_socket_close(accept_socket);
    ar_osal_mutex_destroy(connection_lock);

    return AR_EOK;
}

int32_t TcpipGatewayDlsServer::set_connected_lock(bool_t value)
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

void TcpipGatewayDlsServer::transmit(void* arg)
{
	TCPIP_DLS_ERR("Transmit routine callback...");
	TcpipGatewayDlsServer* gws = (TcpipGatewayDlsServer*)arg;
	(gws->*thd_cb_gw_dls_transmit_routine)(NULL);
}

void TcpipGatewayDlsServer::connect(void* arg)
{
    TcpipGatewayDlsServer* thread = (TcpipGatewayDlsServer*)arg;
    (thread->*thd_cb_gw_dls_connect_routine)(NULL);
}

void* TcpipGatewayDlsServer::connect_routine(void* arg)
{
	__UNREFERENCED_PARAM(arg);

	TCPIP_DLS_INFO("Starting gateway dls tcpip server");
	int status = 0;
	int32_t thd_index = 0;
	struct timeval timeout = { 0 };
	struct addrinfo socket_hints;
	struct addrinfo* connected_devices_addr_info = NULL;

	// getaddrinfo() requires all fields in the addrinfo struct to be zeroed out
	ar_mem_set(&socket_hints, 0, sizeof(socket_hints));

	//sets hints to look for addresses that IPv4 and used for TCP/IP
	socket_hints.ai_family = AF_INET;	// IPv4
	socket_hints.ai_socktype = SOCK_STREAM;	// TCP
	socket_hints.ai_flags = AI_PASSIVE;	//IP Wildcard

	//gets addrinfo structure for devices on port 5560

	TCPIP_DLS_INFO("my address:%s:%s",str_ip_addr.c_str(), str_pc_port.c_str());

	//set up USB listening thread on localhost
    status = ar_socket_get_addr_info(str_ip_addr.c_str(),
        str_pc_port.c_str(),
        &socket_hints,
        &connected_devices_addr_info);


	//checks for errors getting the IP address
	if (AR_FAILED(status) || connected_devices_addr_info == NULL)
	{
		return NULL;
	}

	TCPIP_DLS_DBG("Host Info AI_FLAGS: %d", connected_devices_addr_info->ai_flags);
	TCPIP_DLS_DBG("Host Info AI_FAMILY: %d", connected_devices_addr_info->ai_family);
	TCPIP_DLS_DBG("Host Info AI_SOCKTYPE: %d", connected_devices_addr_info->ai_socktype);
	TCPIP_DLS_DBG("Host Info AI_PROTOCOL: %d", connected_devices_addr_info->ai_protocol);
	TCPIP_DLS_DBG("Host Info ADDRLEM: %u", connected_devices_addr_info->ai_addrlen);
	TCPIP_DLS_DBG("Host Info AI_CANONNAME: %s", connected_devices_addr_info->ai_canonname);

	TCPIP_DLS_INFO("Setting up server...");
	//ar_socket_t listen_socket;

	//creates socket and references the socket using a file descriptor
	status = ar_socket_tcp(&listen_socket);

	//Sets socket options allowing sockets to bind to a certain address
	int32_t yes = 1;
	status = ar_socket_set_options(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char_t*)&yes, sizeof(int32_t));
	if (status < 0)
	{
		TCPIP_DLS_ERR("Error[%d]: Unable to set socket options", status);
		return 0;
	}

	// timeout.tv_sec = TGWS_CONNECTION_TIMEOUT;
	// ar_socket_set_options(listen_socket, SOL_SOCKET, SO_RCVTIMEO, (char_t*)&timeout, sizeof(struct timeval));

	//binds IP address to socket
	status = ar_socket_bind(listen_socket,
		connected_devices_addr_info->ai_addr,
		(int)connected_devices_addr_info->ai_addrlen);

	TCPIP_DLS_ERR("Listening for connections...");

	//listens queue is of size 1
	status = ar_socket_listen(listen_socket, 1);
    if (AR_FAILED(status))
    {
        TCPIP_DLS_ERR("Error[%d]: Listen failed. Closing server...");
        ar_socket_close(listen_socket);
        return NULL;
    }
	TCPIP_DLS_ERR("after invoking ar_socket_listen");

	//initializing mutex and setting up environment for threading
	ar_osal_mutex_init(connected_mutex);
    // set_connected_lock(FALSE);

	TCPIP_DLS_ERR("after invoking ar_osal_mutex_init");
	while (TRUE)
	{
		ar_socket_addr_storage_t their_addr;
		socklen_t addr_size = sizeof(their_addr);
		ar_socket_t client_socket_temp;

		TCPIP_DLS_ERR("Waiting to accept connections...");
		status = ar_socket_accept(listen_socket, (struct sockaddr*)&their_addr, &addr_size, &client_socket_temp);

		if (AR_FAILED(status))
		{
			if (errno == EINTR) continue;

			ar_socket_addr_in_t* sin = (ar_socket_addr_in_t*)&their_addr;
			//Converts binary to IPv4 string
			char_t ip_addr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(sin->sin_addr), ip_addr, INET_ADDRSTRLEN);
			//TCPIP_DLS_ERR("Attempted Connection from: %s", ip_addr);
		}
		else
		{
			//do not create more threads if already connected.
			ar_osal_mutex_lock(connected_mutex);
			if (is_connected)
			{
				ar_osal_mutex_unlock(connected_mutex);
				TCPIP_DLS_ERR("Detected a new connection request. Refusing...");
				ar_socket_close(client_socket_temp);
				continue;
			}

			is_connected = TRUE;
			TCPIP_DLS_INFO("Accept successful to Gateway DLS Service: Client Socket %d", client_socket_temp);
			// ar_osal_mutex_unlock(connected_mutex);

			timeout.tv_sec = TGWS_CONNECTION_TIMEOUT;
			ar_socket_set_options(client_socket_temp, SOL_SOCKET, SO_RCVTIMEO, (char_t*)&timeout, sizeof(struct timeval));

			*client_socket_ptr = client_socket_temp;
			ar_socket_addr_in_t* sin = (ar_socket_addr_in_t*)&their_addr;

			//Converts binary to IPv4 string
			char_t str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(sin->sin_addr), str, INET_ADDRSTRLEN);
			// TCPIP_DLS_INFO("Connection from: %s:%d", str, pc_port);

			//ar_socket_close(listen_socket);
			status = connect_to_target_server(server_socket_ptr);
			if (AR_FAILED(status))
			{
				TCPIP_DLS_ERR("Unable to connect to intended server. Refusing client...");
				ar_socket_close(client_socket_temp);
				continue;
			}

			ar_osal_thread_t thd_transmit;
			ar_osal_thread_start_routine routine = \
				(ar_osal_thread_start_routine)(transmit);

			std::string thd_name_tmp = "GWD_THD_" + std::to_string(thd_index);
			char_t thd_name[21];
			ar_strcpy(thd_name, 21, thd_name_tmp.c_str(), thd_name_tmp.length() + 1);
			ar_osal_thread_attr_t thd_attr = \
			{
				thd_name,
					TGWS_THD_STACK_SIZE,
					TGWS_THREAD_PRIORITY_HIGH
			};

			status = ar_osal_thread_create(&thd_transmit, &thd_attr, routine, this);
			if (AR_FAILED(status))
			{
				TCPIP_DLS_ERR("Failed to create data transmission thread.");
				break;
			}


			/* Only one client is allowed to connect to the server for now.
			 * Block until client calls QUIT on transmission thread.
			 * Allow 200 msec sleep for thd_transmit to aquire connection_lock*/
			 //Sleep(200);
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
			ar_osal_mutex_lock(connected_mutex);

			TCPIP_DLS_DBG("Error[%d]: Waiting for thread %s to complete", status, thd_name);
			status = ar_osal_thread_join_destroy(thd_transmit);
			if (AR_FAILED(status))
			{
				TCPIP_DLS_ERR("Error[%d]: Failed to join usb thread", status);
			}
			TCPIP_DLS_DBG("Error[%d]: Thread %s destroyed", status, thd_name);
		}
	}

	TCPIP_DLS_INFO("Ending connect routine.");
	ar_socket_close(*client_socket_ptr);
	ar_socket_close(*server_socket_ptr);
	return 0;
}

void* TcpipGatewayDlsServer::transmit_routine(void* arg)
{
	__UNREFERENCED_PARAM(arg);
	// ar_osal_mutex_lock(connected_mutex);
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};

	TCPIP_DLS_DBG("Begin message forwarding");

	/*todo: Note on Supporting multiple connections
	 * If we decide to support multiple device connections, the buffers need to be added
	 * to an array and each thread needs to pick its associated buffer we can do this
	 * after testing with 1 connection
	 */
	message_buffer.buffer_size = TGWS_MAX_MESSAGE_BUFFER_SIZE;
	recieve_buffer.buffer_size = TGWS_RECIEVE_BUFFER_SIZE;

	message_buffer.buffer = (char_t*)ar_heap_malloc(message_buffer.buffer_size, &heap_inf);
	if (NULL == message_buffer.buffer)
	{
		TCPIP_DLS_ERR("Error[%d]: Failed to allocate memory for message buffer", AR_ENOMEMORY);
		return NULL;
	}

	recieve_buffer.buffer = (char_t*)ar_heap_malloc(recieve_buffer.buffer_size, &heap_inf);
	if (NULL == recieve_buffer.buffer)
	{
		ar_heap_free(message_buffer.buffer, &heap_inf);
		TCPIP_DLS_ERR("Error[%d]: Failed to allocate memory for recieve buffer", AR_ENOMEMORY);
		return NULL;
	}

	/* this loop will run once per ENTIRE message received.
	 * keep listening for whole incoming messages
	 */
	while (true)
	{
		tgws_status_codes_t status_code = TGWS_E_SUCCESS;

		/* Forward responses from CMD Server to Gateway Client */
		tcp_forward(
			/* from server */ server_socket_ptr,
			/* to client   */ client_socket_ptr,
			&message_buffer, &recieve_buffer, false, status_code);
		if (TGWS_E_END_MSG_FWD == status_code)
			break;
	}

	ar_socket_close(*client_socket_ptr);
	ar_socket_close(*server_socket_ptr);
	ar_heap_free(message_buffer.buffer, &heap_inf);
	ar_heap_free(recieve_buffer.buffer, &heap_inf);

	TCPIP_DLS_DBG("End message forwarding");

	is_connected = FALSE;
	// ar_osal_mutex_unlock(connected_mutex);
	return NULL;
}

void TcpipGatewayDlsServer::tcp_forward(
	ar_socket_t* sender_socket_ptr, ar_socket_t* receiver_socket_ptr,
	buffer_t* gateway_message_buf, buffer_t* gateway_recv_buf,
	bool_t is_cmd_request, tgws_status_codes_t& agws_status_code)
{
	int32_t status = AR_EOK;
	ar_socket_t sender_socket = *sender_socket_ptr;
	ar_socket_t receiver_socket = *receiver_socket_ptr;
	uint32_t header_bytes_read = 0;
	uint32_t message_length = 0;
	uint32_t msg_offset = 0;
	int32_t bytes_sent = 0;
	int32_t bytes_read = 0;

	ar_mem_set(gateway_message_buf->buffer, 0, gateway_message_buf->buffer_size);
	ar_mem_set(gateway_recv_buf->buffer, 0, gateway_recv_buf->buffer_size);

	//This loop will run as many times as to receive full message header (should be just once)
	while (TRUE)
	{
		bytes_read = 0;
		bytes_sent = 0;
		status = AR_EOK;

		TCPIP_DLS_DBG("Receiving...");

		status = ar_socket_recv(
			sender_socket,
			gateway_recv_buf->buffer,
			DLS_LOG_DATA_HEADER_LENGTH - header_bytes_read,
			0, &bytes_read);
		if (AR_FAILED(status))
		{
			TCPIP_DLS_ERR("Recieve failed. Data of %d bytes received.", bytes_read);
		}

		//client sends "QUIT" to signal end of connection. At that point, close socket and return.
		if (ar_strcmp(gateway_recv_buf->buffer, "QUIT", 4) == 0)
		{
			ar_socket_send(receiver_socket, "QUIT", 4, 0, &bytes_sent);
			TCPIP_DLS_ERR("Quitting");
			ar_socket_close(receiver_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		if (bytes_read <= 0)
		{
			/*recv(...) returned -1 or 0
			 * -1 - indicates an error so we need to check errno (error number)
			 *	0 - the client sent 0 or the connection was closed. Check
			 *		recv(...) documentation for addition info
			 */
			if (AR_SOCKET_LAST_ERROR == EINTR) continue;

			TCPIP_DLS_INFO("Failed to recieve data from client");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}
		else if (bytes_read == 0)
		{
			TCPIP_DLS_INFO("Client shutdown socket. Closing connection...");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		TCPIP_DLS_ERR("Data of %d bytes received.", bytes_read);
		header_bytes_read += bytes_read;

		//this determines how many bytes to expect (thus determining how many times to loop).
		if (tgws_get_dls_log_data_length(gateway_recv_buf->buffer, header_bytes_read, &message_length))
		{
			TCPIP_DLS_DBG("Message with length: %d received.", message_length);
			ar_mem_cpy(
				gateway_message_buf->buffer, DLS_LOG_DATA_HEADER_LENGTH,
				gateway_recv_buf->buffer, DLS_LOG_DATA_HEADER_LENGTH);
			msg_offset += DLS_LOG_DATA_HEADER_LENGTH;
			break;
		}
	}

	if (message_length > message_buffer.buffer_size)
	{
		/* We reject messages that are larger that what we can store in our message buffer */
		TCPIP_DLS_DBG("Error[%d]: Not enough memory to store incoming message of %d bytes. "
			"Use resize buffer command update the max buffer size", AR_ENEEDMORE, message_length);
		status = AR_ENEEDMORE;
		agws_status_code = TGWS_E_IGNORE_MSG_FWD;
		goto tcp_forward_end;
	}

	//this loop will receive max bufsize bytes each iteration, looping until it receives full message
	msg_offset = 0;
	while (message_length != 0)
	{
		if (msg_offset > message_length)
		{
			TCPIP_DLS_ERR("read more than message length...corruption");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		//will receive min(bufsize, bytes left to receive to complete message)
		uint32_t recv_buf_size = gateway_recv_buf->buffer_size;//AGWS_RECV_BUF_SIZE;
		int32_t bytes_read = 0;

		int32_t bytes_remaining = message_length - msg_offset < recv_buf_size ? message_length - msg_offset : recv_buf_size;
		ar_socket_recv(
			sender_socket,
			gateway_recv_buf->buffer,
			bytes_remaining,
			0, &bytes_read);

		if (bytes_read <= 0)
		{
			if (AR_SOCKET_LAST_ERROR == EINTR)
			{
				TCPIP_DLS_ERR("Signal Interrupt. Continuing...");
				continue;
			}
			TCPIP_DLS_ERR("failed to recieve data from client");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		TCPIP_DLS_ERR("msg offset: %d bytes", msg_offset);
		ar_mem_cpy(
			gateway_message_buf->buffer + DLS_LOG_DATA_HEADER_LENGTH + msg_offset, bytes_read,
			gateway_recv_buf->buffer, bytes_read);
		msg_offset += bytes_read;

		if (msg_offset == message_length)
			break;
	}

	//The total message length is DLS Log Data Header + Total Log Data Size
	message_length += DLS_LOG_DATA_HEADER_LENGTH;
	TCPIP_DLS_DBG("*** Full message received [%d bytes]***", message_length);
	TCPIP_DLS_DBG("message offset = %d", msg_offset);
	TCPIP_DLS_DBG("message buffer [0-8] = \n%08x %08x %08x %08x\n%08x %08x %08x %08x",
		*((uint32_t*)gateway_message_buf->buffer + 0),
		*((uint32_t*)gateway_message_buf->buffer + 1),
		*((uint32_t*)gateway_message_buf->buffer + 2),
		*((uint32_t*)gateway_message_buf->buffer + 3),
		*((uint32_t*)gateway_message_buf->buffer + 4),
		*((uint32_t*)gateway_message_buf->buffer + 5),
		*((uint32_t*)gateway_message_buf->buffer + 6),
		*((uint32_t*)gateway_message_buf->buffer + 7)
	);

tcp_forward_end:

	if (agws_status_code == TGWS_E_IGNORE_MSG_FWD)
	{
		if (message_length == 0)
		{
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}
		TCPIP_DLS_DBG("Returning err message of length: %d to client", message_length);
	}

	status = ar_socket_send(
		receiver_socket,
		gateway_message_buf->buffer,
		message_length, 0, &bytes_sent);
	if (AR_FAILED(status))
	{
		TCPIP_DLS_ERR("Error[%d]: Failed to send message to client");
		ar_socket_close(receiver_socket);
		agws_status_code = TGWS_E_END_MSG_FWD;
	}
}


int32_t TcpipGatewayDlsServer::connect_to_target_server(ar_socket_t* server_socket)
{
	int32_t status = AR_EOK;
	uint32_t client_addr_length = 0;
	uint32_t server_addr_length = 0;
	ar_socket_addr_storage_t client_sockaddr = { 0 };
	ar_socket_addr_storage_t server_sockaddr = { 0 };

// #if defined (__linux__)
// 	if (AR_FAILED(ar_socket_unix(server_socket)))
// 		return AR_EFAILED;
// 	client_addr_length = ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS_LENGTH
// 		+ sizeof(uint16_t);
// 	server_addr_length = ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS_LENGTH
// 		+ sizeof(uint16_t);
// #elif defined (_WIN32)
// 	if (AR_FAILED(ar_socket_tcp(server_socket)))
// 		return AR_EFAILED;
// 	client_addr_length = sizeof(ar_socket_addr_in_t);
// 	server_addr_length = sizeof(ar_socket_addr_in_t);
// #endif
	// ar_socket_addr_storage_t client_sockaddr = { 0 };
	// ar_socket_addr_storage_t server_sockaddr = { 0 };
	// tgws_dls_get_client_address(TCPIP_DLS_SERVER_PORT /*pc_port*/, &client_sockaddr);
	// tgws_dls_get_server_address(TCPIP_ATS_DLS_SERVER_PORT, &server_sockaddr);

	tgws_util_create_socket(server_socket);

	//Get Client address and address length (this gateway dls server)
	tgws_util_get_socket_address(TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN, ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS, TCPIP_DLS_SERVER_PORT, &client_sockaddr);
	client_addr_length = tgws_util_get_socket_address_length(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS);

	//Get ATS Service address and address length
	server_addr_length = tgws_util_get_socket_address_length(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS);
	tgws_util_get_socket_address(TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN, ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS, TCPIP_ATS_DLS_SERVER_PORT, &server_sockaddr);

	/* Bind to client address to the Gateway Server socket */
	client_addr_length = sizeof(ar_socket_addr_in_t);
	status = ar_socket_bind(
		*server_socket,
		(ar_socket_addr_t*)&client_sockaddr,
		client_addr_length);// This is size of ar_socket_addr_un_t::sun_family
	if (AR_FAILED(status))
	{
		TCPIP_DLS_DBG("Unable to bind client address to gateway dls server socket");
		ar_socket_close(*server_socket);
		return AR_EFAILED;
	}

	/* Connect dls gateway server to dls server socket */
	TCPIP_DLS_DBG("Attempting to connect to dls gateway server...");
	client_addr_length = sizeof(server_sockaddr);
	status = ar_socket_connect(
		*server_socket,
		(ar_socket_addr_t*)&server_sockaddr,
		server_addr_length); // This is size of ar_socket_addr_un_t::sun_family
	if (AR_FAILED(status))
	{
		TCPIP_DLS_ERR("Error[%d]: Failed to connect to dls server");
		ar_socket_close(*server_socket);
		return AR_EFAILED;
	}

	TCPIP_DLS_INFO("Connected to dls server");
	return status;
}

/*
============================================================================
				   Helper Functions
============================================================================
*/

static bool_t tgws_get_dls_log_data_length(
	char_t* message_buffer, uint32_t message_buffer_size, uint32_t* data_length)
{
	if (IS_NULL(message_buffer) || IS_NULL(data_length))
	{
		TCPIP_DLS_ERR("Error[%d]: Input parameter is null", AR_EBADPARAM);
		return FALSE;
	}

	if (message_buffer_size < DLS_LOG_DATA_HEADER_LENGTH)
	{
		TCPIP_DLS_ERR("Error[%d]: Message buffer is smaller than request header format length", AR_ENEEDMORE);
		return FALSE;
	}

	/** copy data length*/
	tgws_mem_cpy(
		data_length, DLS_LOG_DATA_FIELD_TOTAL_SIZE_LENGTH,
		message_buffer + DLS_LOG_DATA_FIELD_TOTAL_SIZE_POSITION, DLS_LOG_DATA_FIELD_TOTAL_SIZE_LENGTH);

	return TRUE;
}

#endif /*ATS_DATA_LOGGING*/
