/**
*=============================================================================
*  \file tcpip_socket_util.cpp
*  \brief
*                   A T S  S E R V E R  S O U R C E  F I L E
*
*    Contains socket creation functions to simplify socket creation in the 
*    server sources files
*
*  \cond
*      Copyright (c) Qualcomm Innovation Center, Inc. All rights reserved.
*      SPDX-License-Identifier: BSD-3-Clause
*  \endcond
*=============================================================================
*/
#ifdef ATS_TRANSPORT_TCPIP

#include "tcpip_socket_util.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_heap.h"
#include "ar_osal_string.h"

/**< TCPIP Socket Utility(TSU) Log Tag */
#define LOG_TAG  "ATS-TSU"
#define TCPIP_SOCKET_UTIL_ERR(...) AR_LOG_ERR(LOG_TAG, __VA_ARGS__)
#define TCPIP_SOCKET_UTIL_DBG(...) AR_LOG_DEBUG(LOG_TAG, __VA_ARGS__)
#define TCPIP_SOCKET_UTIL_INFO(...) AR_LOG_INFO(LOG_TAG, __VA_ARGS__)

/* The name of the unix abstract domain socket used by the 
 * ATS Server to communicate with the gateway server */
#define SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME "#AtsServer"

/* The character length of the unix domain socket string 
 * including the null-terminating character */
#define SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_LENGTH 11

int32_t create_socket_inet(
    ar_address_family_t address_family, 
    char_t* address_string, 
    uint16_t gateway_port, 
    ar_socket_t* listen_socket)
{
    int32_t status = AR_EOK;

    TCPIP_SOCKET_UTIL_DBG("Setting up sockets...");
    //creates socket and references the socket using a file descriptor
    status = ar_socket_tcp(listen_socket);

    //Checks for errors from socket function
    if (ar_socket_is_invalid(*listen_socket))
    {
        TCPIP_SOCKET_UTIL_ERR("Error opening socket");
        return status;
    }

    ar_socket_addr_in_t addr = { 0 };
    addr.sin_family = address_family;
    ar_socket_inet_pton(address_family, address_string, &addr.sin_addr.s_addr);
    addr.sin_port = ar_socket_htons(gateway_port);

    //binds socket to socket path
    status = ar_socket_bind(*listen_socket, (struct sockaddr*)&addr, sizeof(addr));
    if (AR_FAILED(status))
    {
        return status;
    }

    TCPIP_SOCKET_UTIL_DBG("Bind successful");
    
    return status;
}

// void create_unix_socket_path()
// {
// #if defined(__linux__)
//     //Create the sockets path and give full permisions to the path
//     char_t socket_path[] = SOCK_PATH;
//     //700 is permission for -rwx------ (read/write/execute for only owner)
//     mode_t permissions = S_IRWXU;//S_IRWXU
//     status = mkdir(socket_path, permissions);
//     chmod(socket_path, permissions); //if already exists
// #endif
// }

int32_t create_socket_unix(
    ar_socket_t* listen_socket)
{
    int32_t status = AR_EOK;
    
    //creates socket and references the socket using a file descriptor
    status = ar_socket_unix(listen_socket);

    //Checks for errors from socket function
    if (ar_socket_is_invalid(*listen_socket))
    {
        TCPIP_SOCKET_UTIL_ERR("Error opening socket");
        return status;
    }

    //create_unix_socket_path();

    //Create Abstract domain socket
    ar_socket_addr_un_t addr = { 0 };
    ar_mem_set(&addr, 0, sizeof(ar_socket_addr_un_t));
    addr.sun_family = AF_UNIX;

    ar_strcpy(addr.sun_path, 
        AR_UNIX_PATH_MAX, 
        SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME, 
        SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_LENGTH);
    addr.sun_path[0] = 0;

    ar_socketlen_t length = SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_LENGTH
        + sizeof(addr.sun_family);

    //binds socket to socket path
    TCPIP_SOCKET_UTIL_DBG("Binding Abstract Domain Socket. Socket Path: %s Length: %d", 
        &addr.sun_path[0], 
        SERVER_UNIX_SOCKET_ABSTRACT_DOMAIN_NAME_LENGTH);

    status = ar_socket_bind(*listen_socket, (struct sockaddr*)&addr, length);
    if (AR_FAILED(status))
    {
        return status;
    }

    TCPIP_SOCKET_UTIL_DBG("Bind successful");

    return status;
}

int32_t tcpip_socket_util_create_socket(
    ar_address_family_t address_family, 
    char_t* address_string, 
    uint16_t gateway_port, 
    ar_socket_t* listen_socket)
{
    int32_t status = AR_EOK;

    switch (address_family)
    {
    case AF_UNIX:
        status = create_socket_unix(listen_socket);
        break;
    case AF_INET:
    case AF_INET6:
        status = create_socket_inet(
            address_family, address_string, gateway_port, listen_socket);
        break;

    default:
        break;
    }

    return status;
}

int32_t tcpip_socket_util_accept_unix_socket_connection(
    ar_socket_t listen_socket, 
    ar_socket_t* accept_socket)
{
    int32_t status = AR_EOK;
    ar_sockaddr_un_t client_addr;
    struct ar_heap_info_t heap_inf =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };
    socklen_t addr_size = sizeof(client_addr);
    ar_mem_set(&client_addr, 0, addr_size);

    TCPIP_SOCKET_UTIL_DBG("Waiting to accept clients...");
    status = ar_socket_accept(
        listen_socket, (struct sockaddr*)&client_addr, &addr_size, accept_socket);

    return status;
}

int32_t tcpip_socket_util_accept_inet_socket_connection(
    ar_socket_t listen_socket, 
    ar_socket_t *accept_socket)
{
    int32_t status = AR_EOK;
    ar_socket_addr_in_t client_addr;
    struct ar_heap_info_t heap_inf =
    {
        AR_HEAP_ALIGN_DEFAULT,
        AR_HEAP_POOL_DEFAULT,
        AR_HEAP_ID_DEFAULT,
        AR_HEAP_TAG_DEFAULT
    };
    ar_socketlen_t addr_size = sizeof(client_addr);
    ar_mem_set(&client_addr, 0, addr_size);

    TCPIP_SOCKET_UTIL_DBG("Waiting to accept clients...");
    status = ar_socket_accept(
        listen_socket, (struct sockaddr*)&client_addr, &addr_size, accept_socket);

    return status;
}

int32_t tcpip_socket_util_accept_connections(
    ar_address_family_t address_family, 
    ar_socket_t listen_socket, 
    ar_socket_t* accept_socket)
{
    int32_t status = AR_EOK;

    switch (address_family)
    {
    case AF_UNIX:
        status = tcpip_socket_util_accept_unix_socket_connection(listen_socket, accept_socket);
        break;
    case AF_INET:
    case AF_INET6:
        status = tcpip_socket_util_accept_inet_socket_connection(listen_socket, accept_socket);
        break;

    default:
        status = AR_EUNSUPPORTED;
        break;
    }

    return status;
}

int32_t tcpip_socket_util_get_client_name(
    ar_address_family_t address_family, 
    ar_socket_t accept_socket)
{
    int32_t status = AR_EOK;
    ar_socketlen_t addr_length = 0;
    switch (address_family)
    {
    case AF_UNIX:
    {
        ar_sockaddr_un_t client_addr;
        status = ar_socket_get_peer_name(accept_socket, (ar_socket_addr_t*)&client_addr, &addr_length);
    }
        break;
    case AF_INET:
    case AF_INET6:
    {
        ar_socket_addr_in_t client_addr;
        status = ar_socket_get_peer_name(accept_socket, (ar_socket_addr_t*)&client_addr, &addr_length);

        //client_addr.sin_addr
    }
        break;
    default:
        status = AR_EUNSUPPORTED;
        break;
    }
    
    return status;
}

#endif /*ATS_TRANSPORT_TCPIP*/