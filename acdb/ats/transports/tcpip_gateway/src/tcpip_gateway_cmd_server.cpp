/**
*==============================================================================
*  \file tcpip_gateway_cmd_server.cpp
*  \brief
*                  T C P I P  G A T E W A Y  C M D  S E R V E R
*                             S O U R C E  F I L E
*
*         Contains the implementation for the ATS TCPIP Gateway Command Server.
*         This Command server is the middle man between ATS TCPIP Command
*         Server and QACT and handles forwarding messages between the two.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

/**
* Preprocessor Macro Notes
*------------------------------------------------------------------------------
* ATS_DATA_LOGGING | define this macro in your build configuration to enable
*                  | recieving log packet data from SPF
*/

#include "tcpip_gateway_cmd_server.h"
#include "tcpip_gateway_socket_util.h"
#include <thread>
#include <chrono>

#define IS_NULL(ptr) (ptr == NULL)

/* The name of the unix abstract domain socket used by the
 * ATS Server to communicate with the gateway server */
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_CMD "#AtsCmdServer"
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_DLS "#AtsDlsServer"
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_CMD "#AtsGwCmdServer"
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_DLS "#AtsGwDlsServer"

 /* The character length of the unix domain socket string
  * including the null-terminating character */
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_CMD_LENGTH 13
#define ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_CMD_LENGTH 16

typedef enum ats_server_id_t
{
	ATS_CMD_SERVER = 0,
	ATS_DLS_SERVER = 1
}ats_server_id_t;
/*
============================================================================
					Prototypes / Typedefs / Callbacks
============================================================================
*/

typedef void* (TcpipGatewayServer::* thread_callback)(void* args);
thread_callback thd_cb_start_routine = &TcpipGatewayServer::connect_routine;
thread_callback thd_cb_transmit_routine = &TcpipGatewayServer::transmit_routine;

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
* \param [in] message_buffer_size: The length of the message buffer
* \param [in] data_length: The data length field in the command request header
*
* \return
*   TRUE if successfully parsed and FALSE otherwise
*/
static bool_t tgws_get_ats_command_length(
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
* \param[in] message_buffer_size: The size of the message buffer
* \param[out] message_length: The length of the message written to the message buffer
*
* \return none
*/
static void tgws_create_error_resp(
	uint32_t service_cmd_id, uint32_t ar_status_code,
	char_t* rsp_msg_buffer, uint32_t rsp_msg_buffer_size,
	uint32_t& rsp_msg_legnth
);

/*
============================================================================
				   TCPIP Gateway Server Implementation
============================================================================
*/

TcpipGatewayServer::TcpipGatewayServer(std::string ip_addr, std::string port, uint32_t option)
	: str_ip_addr { ip_addr }, str_pc_port{ port },
	option{ option }
{
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};
	size_t index = 0;
	pc_port = (uint16_t)std::stoi(port, &index);

	server_socket_ptr = (ar_socket_t*)ar_heap_malloc(sizeof(ar_socket_t), &heap_inf);
	client_socket_ptr = (ar_socket_t*)ar_heap_malloc(sizeof(ar_socket_t), &heap_inf);
	ar_mem_set(server_socket_ptr, 0, sizeof(ar_socket_t));
	ar_mem_set(client_socket_ptr, 0, sizeof(ar_socket_t));

	int32_t status = ar_osal_mutex_create(&connected_mutex);
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]: Failed to create mutex.", status);
	}
}

TcpipGatewayServer::~TcpipGatewayServer()
{
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};
	//Cleanup resources
	ar_heap_free(server_socket_ptr, &heap_inf);
	ar_heap_free(client_socket_ptr, &heap_inf);

	int32_t status = ar_osal_mutex_destroy(connected_mutex);
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]:An error occured while destroying the mutex.", status);
	}
}

int32_t TcpipGatewayServer::connect_to_target_server(ar_socket_t* server_socket)
{
	int32_t status = AR_EOK;
	uint32_t client_addr_length = 0;
	uint32_t server_addr_length = 0;
	ar_socket_addr_storage_t client_sockaddr = { 0 };
	ar_socket_addr_storage_t server_sockaddr = { 0 };

// #if defined (__linux__)
// 	if (AR_FAILED(ar_socket_unix(server_socket)))
// 		return AR_EFAILED;
// 	client_addr_length = ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_CMD_LENGTH
// 		+ sizeof(uint16_t);
// 	server_addr_length = ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_CMD_LENGTH
// 		+ sizeof(uint16_t);
// #elif defined (_WIN32)
// 	if (AR_FAILED(ar_socket_tcp(server_socket)))
// 		return AR_EFAILED;
// 	/*client_addr_length = sizeof(ar_socket_addr_storage_t);*/
// 	client_addr_length = sizeof(ar_socket_addr_in_t);
// 	server_addr_length = sizeof(ar_socket_addr_in_t);
// #endif

// 	ar_socket_addr_storage_t client_sockaddr = { 0 };
// 	tgws_get_client_address(pc_port, &client_sockaddr);
// 	ar_socket_addr_storage_t server_sockaddr = { 0 };
// 	tgws_get_server_address(TCPIP_CMD_SERVER_PORT, &server_sockaddr);

	tgws_util_create_socket(server_socket);

	//Get Client address and address length (this gateway dls server)
	tgws_util_get_socket_address(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_CMD, pc_port, &client_sockaddr);
	client_addr_length = tgws_util_get_socket_address_length(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_GATEWAY_CMD);

	//Get ATS Service address and address length
	server_addr_length = tgws_util_get_socket_address_length(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_CMD);
	tgws_util_get_socket_address(tgws_get_address_type(), ATS_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_ATS_CMD, TCPIP_CMD_SERVER_PORT, &server_sockaddr);

	/* Bind to client address to the Gateway Server socket */
	client_addr_length = sizeof(ar_socket_addr_in_t);
	status = ar_socket_bind(
		*server_socket,
		(ar_socket_addr_t*)&client_sockaddr,
		client_addr_length);// This is size of ar_socket_addr_un_t::sun_family
	if (AR_FAILED(status))
	{
		GATEWAY_DBG("Unable to bind client address to gateway cmd server socket");
		ar_socket_close(*server_socket);
		return AR_EFAILED;
	}

	GATEWAY_DBG("Attempting to connect to ats command server socket...");
	client_addr_length = sizeof(server_sockaddr);
	/* Connect Gateway to the CMD Server socket */
	status = ar_socket_connect(
		*server_socket,
		(ar_socket_addr_t*)&server_sockaddr,
		server_addr_length); // This is size of ar_socket_addr_un_t::sun_family
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]: Failed to connect to ats command server.");
		ar_socket_close(*server_socket);
		return AR_EFAILED;
	}

	GATEWAY_INFO("Connected to ats command server.");
	return status;
}

void* TcpipGatewayServer::connect_routine(void* arg)
{
	__UNREFERENCED_PARAM(arg);

	GATEWAY_DBG("Starting gateway command server thread.");
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

	//gets addrinfo structure for devices on port 5558

	//set up USB listening thread on localhost
	switch (option)
	{
	case TGWS_CONNECTION_OPTION_USB:
		GATEWAY_INFO("Connecting to gateway over usb");

		status = ar_socket_get_addr_info(str_ip_addr.c_str(),
			config->port_str,
			&socket_hints,
			&connected_devices_addr_info);
		break;
	case TGWS_CONNECTION_OPTION_WIFI:
	{
		GATEWAY_INFO("Connecting to gateway over wifi");
		//int fd;
		//struct ifreq ifr;
		//fd = socket(AF_INET, SOCK_DGRAM, 0);
		//ifr.ifr_addr.sa_family = AF_INET;
		//strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
		//ioctl(fd, SIOCGIFADDR, &ifr);
		//ar_socket_close(fd);
		//GATEWAY_ERR("IP Addr.: %s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		//status = getaddrinfo(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), PORT_NUMBER_PC.c_str(), &hints, &results);
		status = ar_socket_get_addr_info(NULL, str_pc_port.c_str(), &socket_hints, &connected_devices_addr_info);
	}
	break;
	default:
		break;
	}

	//checks for errors getting the IP address
	if (AR_FAILED(status) || connected_devices_addr_info == NULL)
	{
		return NULL;
	}

	GATEWAY_DBG("Host Info AI_FLAGS: %d", connected_devices_addr_info->ai_flags);
	GATEWAY_DBG("Host Info AI_FAMILY: %d", connected_devices_addr_info->ai_family);
	GATEWAY_DBG("Host Info AI_SOCKTYPE: %d", connected_devices_addr_info->ai_socktype);
	GATEWAY_DBG("Host Info AI_PROTOCOL: %d", connected_devices_addr_info->ai_protocol);
	GATEWAY_DBG("Host Info ADDRLEM: %u", connected_devices_addr_info->ai_addrlen);
	GATEWAY_DBG("Host Info AI_CANONNAME: %s", connected_devices_addr_info->ai_canonname);

	GATEWAY_ERR("Setting up sockets...");
	//ar_socket_t listen_socket;

	//creates socket and references the socket using a file descriptor
	status = ar_socket_tcp(&listen_socket);

	//Sets socket options allowing sockets to bind to a certain address
	int32_t yes = 1;
	status = ar_socket_set_options(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char_t*)&yes, sizeof(int32_t));
	if (status < 0)
	{
		GATEWAY_ERR("Error[%d]: Unable to set socket options", status);
		return 0;
	}

	// timeout.tv_sec = TGWS_CONNECTION_TIMEOUT;
	// ar_socket_set_options(listen_socket, SOL_SOCKET, SO_RCVTIMEO, (char_t*)&timeout, sizeof(struct timeval));

	//binds IP address to socket
	status = ar_socket_bind(listen_socket,
		connected_devices_addr_info->ai_addr,
		(int)connected_devices_addr_info->ai_addrlen);

	GATEWAY_INFO("Listening for connections...");

	//listens queue is of size 1
	status = ar_socket_listen(listen_socket, 1);

	//initializing mutex and setting up environment for threading
	ar_osal_mutex_init(connected_mutex);
	ar_osal_mutex_lock(connected_mutex);
	is_connected = 0;
	ar_osal_mutex_unlock(connected_mutex);

	while (TRUE)
	{
		ar_socket_addr_storage_t their_addr;
		socklen_t addr_size = sizeof(their_addr);
		ar_socket_t client_socket_temp;

		//GATEWAY_ERR("Waiting to accept connections...");
		status = ar_socket_accept(listen_socket, (struct sockaddr*)&their_addr, &addr_size, &client_socket_temp);

		if (AR_FAILED(status))
		{
			if (errno == EINTR) continue;

			ar_socket_addr_in_t* sin = (ar_socket_addr_in_t*)&their_addr;
			//Converts binary to IPv4 string
			char_t ip_addr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(sin->sin_addr), ip_addr, INET_ADDRSTRLEN);
			//GATEWAY_ERR("Attempted Connection from: %s", ip_addr);
		}
		else
		{
			//do not create more threads if already connected.
			//ar_osal_mutex_lock(connected_mutex);
			//if (is_connected)
			//{
			//	ar_osal_mutex_unlock(connected_mutex);
			//	GATEWAY_ERR("Detected a new connection request. Refusing...");
			//	ar_socket_close(client_socket_temp);
			//	continue;
			//}

			GATEWAY_DBG("Accept successful to gateway command server: Client Socket %d", client_socket_temp);
			ar_osal_mutex_unlock(connected_mutex);

			timeout.tv_sec = TGWS_CONNECTION_TIMEOUT;
			ar_socket_set_options(client_socket_temp, SOL_SOCKET, SO_RCVTIMEO, (char_t*)&timeout, sizeof(struct timeval));

			*client_socket_ptr = client_socket_temp;
			ar_socket_addr_in_t* sin = (ar_socket_addr_in_t*)&their_addr;

			//Converts binary to IPv4 string
			char_t str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(sin->sin_addr), str, INET_ADDRSTRLEN);
			GATEWAY_INFO("Connection from: %s:%d", str, pc_port);

			//ar_socket_close(listen_socket);
			status = connect_to_target_server(server_socket_ptr);
			if (AR_FAILED(status))
			{
				GATEWAY_ERR("Unable to connect to intended server. Refusing client...");
				ar_socket_close(client_socket_temp);
				continue;
			}

			ar_osal_thread_t thd_transmit;
			ar_osal_thread_start_routine routine = \
				(ar_osal_thread_start_routine)(transmit);

			std::string thd_name_tmp = "GW_THD_" + std::to_string(thd_index);
			char_t thd_name[20];
			ar_strcpy(thd_name, 20, thd_name_tmp.c_str(), thd_name_tmp.length() + 1);
			ar_osal_thread_attr_t thd_attr = \
			{
				thd_name,
					TGWS_THD_STACK_SIZE,
					TGWS_THREAD_PRIORITY_HIGH
			};

			status = ar_osal_thread_create(&thd_transmit, &thd_attr, routine, this);
			if (AR_FAILED(status))
			{
				GATEWAY_ERR("Failed to create data transmission thread.");
				break;
			}

			start_dls_server();

			/* Only one client is allowed to connect to the server for now.
			 * Block until client calls QUIT on transmission thread.
			 * Allow 200 msec sleep for thd_transmit to aquire connection_lock*/
			 //Sleep(200);
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
			ar_osal_mutex_lock(connected_mutex);

			GATEWAY_DBG("Error[%d]: Waiting for thread %s to complete", status, thd_name);
			status = ar_osal_thread_join_destroy(thd_transmit);
			if (AR_FAILED(status))
			{
				GATEWAY_ERR("Error[%d]: Failed to join usb thread", status);
			}
			GATEWAY_DBG("Error[%d]: Thread %s destroyed", status, thd_name);
		}
	}

	GATEWAY_INFO("Ending connect routine.");
	ar_socket_close(*client_socket_ptr);
	ar_socket_close(*server_socket_ptr);
	return 0;
}

void* TcpipGatewayServer::transmit_routine(void* arg)
{
	__UNREFERENCED_PARAM(arg);
	ar_osal_mutex_lock(connected_mutex);
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};

	GATEWAY_DBG("Begin message forwarding");

	//todo: If we decide to support multiple device connections, the buffers need to be added to an array and each thread needs to pick its associated buffer we can do this after testing with 1 connection
	message_buffer.buffer_size = TGWS_MAX_MESSAGE_BUFFER_SIZE;
	recieve_buffer.buffer_size = TGWS_RECIEVE_BUFFER_SIZE;

	message_buffer.buffer = (char_t*)ar_heap_malloc(message_buffer.buffer_size, &heap_inf);
	if (NULL == message_buffer.buffer)
	{
		GATEWAY_ERR("Error[%d]: Failed to allocate memory for message buffer", AR_ENOMEMORY);
		return NULL;
	}

	recieve_buffer.buffer = (char_t*)ar_heap_malloc(recieve_buffer.buffer_size, &heap_inf);
	if (NULL == recieve_buffer.buffer)
	{
		ar_heap_free(message_buffer.buffer, &heap_inf);
		GATEWAY_ERR("Error[%d]: Failed to allocate memory for recieve buffer", AR_ENOMEMORY);
		return NULL;
	}

	/* this loop will run once per ENTIRE message received.
	 * keep listening for whole incoming messages
	 */
	while (true)
	{
		tgws_status_codes_t status_code = TGWS_E_SUCCESS;

		/* Forward requests from Gateway Client to CMD Server */
		tcp_forward(
			/* from client */ client_socket_ptr,
			/* to server   */ server_socket_ptr,//server_socket_ptr,
			&message_buffer, &recieve_buffer, true, status_code);

		switch (status_code)
		{
		case TGWS_E_END_MSG_FWD:
			goto threaddone;
		case TGWS_E_IGNORE_MSG_FWD:
			/* Return error response was returned to Gateway
			 * Client so dont forward messages to CMD Server*/
			continue;
		default:
			break;
		}

		/* Forward responses from CMD Server to Gateway Client */
		tcp_forward(
			/* from server */ server_socket_ptr,
			/* to client   */ client_socket_ptr,
			&message_buffer, &recieve_buffer, false, status_code);
		if (TGWS_E_END_MSG_FWD == status_code)
			break;
	}
threaddone:
	ar_socket_close(*client_socket_ptr);
	ar_socket_close(*server_socket_ptr);
	ar_heap_free(message_buffer.buffer, &heap_inf);
	ar_heap_free(recieve_buffer.buffer, &heap_inf);

	GATEWAY_DBG("End message forwarding");

	is_connected = 0;
	ar_osal_mutex_unlock(connected_mutex);
	return NULL;
}

int32_t TcpipGatewayServer::execute_server_command(
	uint32_t service_cmd_id, ar_socket_t sender_socket, uint32_t message_length,
	tgws_status_codes_t& status_code)
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

		ar_mem_cpy(&new_buffer_size, sizeof(uint32_t), this->message_buffer.buffer, message_length);

		GATEWAY_DBG("Setting max buffer length to %d bytes", new_buffer_size);

		//The new buffer size needs to be between the required range to resize the message buffer:
		//range: AGWS_RECV_BUF_SIZE * 4 < new buffer size < GWS_MAX_BUFFER_SIZE
		//Largest buffer size is 2mb the GWS_MAX_BUFFER_SIZE
		//Smalleset buffer size is 4 * 1024 the recieve buffer size
		if ((new_buffer_size > this->message_buffer.buffer_size && new_buffer_size < TGWS_MIN_MESSAGE_BUFFER_SIZE) ||
			(new_buffer_size < this->message_buffer.buffer_size && new_buffer_size > TGWS_MAX_MESSAGE_BUFFER_SIZE)
			)
		{
			ar_heap_free(message_buffer.buffer, &heap_inf);

			message_buffer.buffer_size = new_buffer_size;
			message_buffer.buffer = (char_t*)ar_heap_malloc(message_buffer.buffer_size, &heap_inf);
			if (NULL == message_buffer.buffer)
			{
				GATEWAY_ERR("Error[%d]: Failed to resize gateway message buffer", AR_ENOMEMORY);
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

	return TGWS_E_SUCCESS;
}

void TcpipGatewayServer::tcp_forward(
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
	uint32_t svc_cmd_id = 0;

	ar_mem_set(gateway_message_buf->buffer, 0, gateway_message_buf->buffer_size);
	ar_mem_set(gateway_recv_buf->buffer, 0, gateway_recv_buf->buffer_size);

	//This loop will run as many times as to receive full message header (should be just once)
	while (TRUE)
	{
		bytes_read = 0;
		bytes_sent = 0;
		status = AR_EOK;

		GATEWAY_DBG("Receiving...");

		status = ar_socket_recv(
			sender_socket,
			gateway_recv_buf->buffer,
			ATS_HEADER_LENGTH - header_bytes_read,
			0, &bytes_read);
		if (AR_FAILED(status))
		{
			GATEWAY_ERR("Recieve failed. Data of %d bytes received.", bytes_read);
		}

		//client sends "QUIT" to signal end of connection. At that point, close socket and return.
		if (ar_strcmp(gateway_recv_buf->buffer, "QUIT", 4) == 0)
		{
			ar_socket_send(receiver_socket, "QUIT", 4, 0, &bytes_sent);
			GATEWAY_ERR("Quitting");
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

			GATEWAY_INFO("Failed to recieve data from client");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}
		else if (bytes_read == 0)
		{
			GATEWAY_INFO("Client shutdown socket. Closing connection...");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		GATEWAY_ERR("Data of %d bytes received.", bytes_read);
		header_bytes_read += bytes_read;

		//this determines how many bytes to expect (thus determining how many times to loop).
		if (tgws_get_ats_command_length(gateway_recv_buf->buffer, header_bytes_read, &message_length))
		{
			GATEWAY_DBG("Message with length: %d received.", message_length);
			ar_mem_cpy(
				gateway_message_buf->buffer, ATS_HEADER_LENGTH,
				gateway_recv_buf->buffer, ATS_HEADER_LENGTH);
			msg_offset += ATS_HEADER_LENGTH;
			break;
		}
	}


	if (message_length > message_buffer.buffer_size)
	{
		/* We reject messages that are larger that what we can store in our message buffer */
		GATEWAY_DBG("Error[%d]: Not enough memory to store incoming message of %d bytes. "
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
			GATEWAY_ERR("read more than message length...corruption");
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
				GATEWAY_ERR("Signal Interrupt. Continuing...");
				continue;
			}
			GATEWAY_ERR("failed to recieve data from client");
			ar_socket_close(sender_socket);
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}

		GATEWAY_ERR("msg offset: %d bytes", msg_offset);
		ar_mem_cpy(
			gateway_message_buf->buffer + ATS_HEADER_LENGTH + msg_offset, bytes_read,
			gateway_recv_buf->buffer, bytes_read);
		msg_offset += bytes_read;

		if (msg_offset == message_length)
			break;
	}

	//The total message length is ATS Header  + CMD Length
	message_length += ATS_HEADER_LENGTH;
	GATEWAY_DBG("*** Full message received [%d bytes]***", message_length);


	GATEWAY_DBG("message offset = %d", msg_offset);
	GATEWAY_DBG("message buffer [0-8] = \n%08x %08x %08x %08x\n%08x %08x %08x %08x",
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

	ar_mem_cpy(&svc_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
		gateway_message_buf->buffer + ATS_SERVICE_COMMAND_ID_POSITION, ATS_SERVICE_COMMAND_ID_LENGTH);
	GATEWAY_DBG("Service Command ID: 0x%x", svc_cmd_id);

	if (ATS_ONLINE_SERVICE_ID == ATS_GET_SERVICE_ID(svc_cmd_id) && is_cmd_request)
	{
		//process gateway command
		status = execute_server_command(svc_cmd_id, sender_socket, message_length, agws_status_code);
	}

	if (agws_status_code == TGWS_E_IGNORE_MSG_FWD)
	{
		//create error response
		tgws_create_error_resp(svc_cmd_id, status,
			gateway_message_buf->buffer, gateway_message_buf->buffer_size, message_length);
		receiver_socket = sender_socket;

		if (message_length == 0)
		{
			agws_status_code = TGWS_E_END_MSG_FWD;
			return;
		}
		GATEWAY_DBG("Returning err message of length: %d to client", message_length);
	}

	status = ar_socket_send(
		receiver_socket,
		gateway_message_buf->buffer,
		message_length, 0, &bytes_sent);
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]: Failed to send data to client");
		ar_socket_close(receiver_socket);
		agws_status_code = TGWS_E_END_MSG_FWD;
	}
}

void TcpipGatewayServer::start(void* arg)
{
	GATEWAY_ERR("Start routine callback...");
	TcpipGatewayServer* gws = (TcpipGatewayServer*)arg;
	(gws->*thd_cb_start_routine)(NULL);
}

void TcpipGatewayServer::transmit(void* arg)
{
	GATEWAY_ERR("Transmit routine callback...");
	TcpipGatewayServer* gws = (TcpipGatewayServer*)arg;
	(gws->*thd_cb_transmit_routine)(NULL);
}

int32_t TcpipGatewayServer::run()
{
	int32_t status = AR_EOK;
	struct ar_heap_info_t heap_inf =
	{
		AR_HEAP_ALIGN_DEFAULT,
		AR_HEAP_POOL_DEFAULT,
		AR_HEAP_ID_DEFAULT,
		AR_HEAP_TAG_DEFAULT
	};

	status = ar_socket_init();
	if (AR_FAILED(status))
	{
		return status;
	}

	config = (tgws_config_t*)ar_heap_malloc(sizeof(tgws_config_t), &heap_inf);
	config->option = this->option;// TGWS_CONNECTION_OPTION_USB;
	config->port = pc_port;
	// config->port_str = str_pc_port.c_str();

	str_pc_port.copy(config->port_str, str_pc_port.size() + 1, 0);
	config->port_str[4] = 0;
	GATEWAY_DBG("Port Str: %s | Port: %d", config->port_str, config->port);

	char thd_name_usb[] = TGWS_START_ROUTINE_THREAD;
	ar_osal_thread_attr_t thd_attr_usb = \
	{
		thd_name_usb,
			TGWS_THD_STACK_SIZE,
			TGWS_THREAD_PRIORITY_HIGH
	};

	ar_osal_thread_start_routine routine = \
		(ar_osal_thread_start_routine)(start);
	status = ar_osal_thread_create(&start_routine_thread, &thd_attr_usb, routine, this);
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]: Failed to create USB listening thread", status);
		goto main_cleanup;
	}

	GATEWAY_ERR("waiting for usb thread to end...");
	status = ar_osal_thread_join_destroy(start_routine_thread);
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Failed to join usb thread");
		goto main_cleanup;
	}

main_cleanup:
	GATEWAY_ERR("END..");
	ar_heap_free(server_socket_ptr, &heap_inf);
	ar_heap_free(client_socket_ptr, &heap_inf);
	return status;
}

void TcpipGatewayServer::start_dls_server()
{
	#if defined(ATS_DATA_LOGGING)

	GATEWAY_INFO("starting gateway dls server");
	//Start the DLS client server after successfully connecting to the CMD server
	dls_server.set_ip_address(str_ip_addr);
	dls_server.stop();

	//wait for arts tcpip dls server to be ready
	std::this_thread::sleep_for(std::chrono::milliseconds(200));

	uint32_t status = dls_server.start();
	if (AR_FAILED(status))
	{
		GATEWAY_ERR("Error[%d]: Unable to start gateway dls server. Client won't be able to recieve log packets. Skipping...");
	}

	#endif
}

/*
============================================================================
				   Helper Functions
============================================================================
*/

static bool_t tgws_get_ats_command_length(
	char_t* message_buffer, uint32_t message_buffer_size, uint32_t* data_length)
{
	bool_t result = FALSE;
	if (IS_NULL(message_buffer) || IS_NULL(data_length))
	{
		GATEWAY_ERR("Error[%d]: Input parameter is null", AR_EBADPARAM);
		return FALSE;
	}
	if (message_buffer_size < ATS_HEADER_LENGTH)
	{
		GATEWAY_ERR("Error[%d]: Message buffer is smaller than request header format length", AR_ENEEDMORE);
		result = FALSE;
	}
	else
	{
		/** copy data length*/
		tgws_mem_cpy(data_length, ATS_DATA_LENGTH_LENGTH,
			message_buffer + ATS_DATA_LENGTH_POSITION, ATS_DATA_LENGTH_LENGTH);

		result = TRUE;
	}
	return result;
}

static void tgws_create_error_resp(
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
		GATEWAY_ERR("Error[%d]: Response Buffer is not initialized", AR_EBADPARAM);
		message_length = 0;
		return;
	}

	if (message_buffer_size < ATS_ERROR_FRAME_LENGTH)
	{
		GATEWAY_ERR("Error[%d]: TUnable to create error response. "
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