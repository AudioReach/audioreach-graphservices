#ifndef _TCPIP_SOCKET_UTIL_H_
#define _TCPIP_SOCKET_UTIL_H_
/**
*=============================================================================
* \file tcpip_socket_util.h
* \brief
*                  T C P I P  S O C K E T  U T I L I T Y
*                          H E A D E R  F I L E
*
*   This a utility class that encapsulates socket creation and socket connection
*   for the ATS tcpip server
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#ifdef ATS_TRANSPORT_TCPIP
/*------------------------------------------
* Includes
*------------------------------------------*/
#include "ar_osal_error.h"
#include "ats_common.h"
#include "ar_sockets_api.h"
#include <string>

/**< The path containing the socket file on a linux file system */
//#define SOCK_PATH "/vendor/app/GatewayServer/ats_sockets";
/**< The socket file used for restricting access to the socket. Permissions
 * must be enabled for the socket file to allow the TCPIP Gateway to establish
 * a connection with the Tcpip CMD/RSP Server.
 * Commented out for now if required later.
 */
//#define SOCK_PATH_SERVER "/vendor/app/GatewayServer/ats_sockets/unix_sock.server";

#ifdef __cplusplus
extern "C"{
#endif

typedef enum tcpip_server_type_t
{
    /**< Command Response Server Type */
    TCPIP_SERVER_TYPE_CMD = 0,
    /**< Data Logging Service Server Type */
    TCPIP_SERVER_TYPE_DLS = 1,
}tcpip_server_type_t;

/**
*	\brief
*		Creates a server listening socket based on the address family.
*
*	\detdesc
*   Setting the address familty to AF_INET will create a TCPIP socket using an IP address
*   Setting the address family to AF_UNIX will create and abstract domain socket to communicate with the Gateway Server (only on linux)
*
*	\param [in] server_type: The type of server to create a socket for
*	\param [in] address_family: AF_INET or AF_UNIX
*	\param [in] address_string: an IP string when using AF_INET or a Unix Domain Socket name starting with # when using AF_UNIX
*	\param [in] gateway_port: The port to connect to. Only used with AF_INET
*	\param [out] listen_socket: The socket used to listen for clients
*
*	\return
*		0 on success and populates listen_socket, non-zero on failure
*/
int32_t tcpip_socket_util_create_socket(
    tcpip_server_type_t server_type,
    ar_address_family_t address_family,
    std::string address,
    uint16_t gateway_port,
    ar_socket_t* listen_socket);

/**
*	\brief
*		Creates an accept socket after successfully listening and accepting a new client connection
*
*	\detdesc
*   Setting the address familty to AF_INET will create a TCPIP socket using an IP address
*   Setting the address family to AF_UNIX will create and abstract domain socket to communicate with the Gateway Server (only on linux)
*
*	\param [in] address_family: AF_INET or AF_UNIX
*	\param [in] listen_socket: The socket used to listen for clients
*	\param [out] accept_socket: The a socket used to listen for clients
*
*	\return
*		0 on success and populates accept_socket, non-zero on failure
*/
int32_t tcpip_socket_util_accept_connections(
    ar_address_family_t address_family,
    ar_socket_t listen_socket,
    ar_socket_t* accept_socket);

#ifdef __cplusplus
}
#endif

#endif /*ATS_TRANSPORT_TCPIP*/
#endif /*_TCPIP_SOCKET_UTIL_H_*/

