/**
*==============================================================================
*  \file ar_sockets.cpp
*  \brief
*                    A u d i o R e a c h  S O C K E T S
*                          S O U R C E  F I L E
*
*         This file contains the socket implementation AR libraries.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "ar_sockets_api.h"

bool_t ar_socket_is_invalid(
    ar_socket_t socket)
{
    return socket == INVALID_SOCKET;
}

int32_t ar_socket_last_error()
{
    return errno;
}

char_t *ar_socket_last_error_str(int32_t error_number)
{
    __UNREFERENCED_PARAM(error_number);
    //return strerror(error_number);//for linux
    //char_t empty_str[2] = {' ','\0'};
    return NULL;
}

int32_t ar_socket_init()
{
    int32_t status = AR_EOK;
    return status;
}

int32_t ar_socket_deinit()
{
    return AR_EOK;
}

int32_t ar_socket_close(ar_socket_t socket)
{
    if (0 > close(socket))
    {
        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_connect(ar_socket_t socket, ar_socket_addr_t *addr, uint32_t addr_len)
{
    if (0 != connect(socket, addr, addr_len))
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while connecting to socket."
            " Socket Error: %d: %s", AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_bind(ar_socket_t socket, ar_socket_addr_t *addr, uint32_t addr_len)
{
    int32_t status = bind(socket, addr, addr_len);
    if ( 0 > status)
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while binding socket. bind returned %d."
            " Socket Error: %d: %s", status, AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_listen(ar_socket_t socket, int32_t backlog)
{
    int32_t status = listen(socket, backlog);
    if (0 > status)
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while listening. listen retruend %d"
            " Socket Error: %d: %s", status, AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_accept(ar_socket_t socket, ar_socket_addr_t *addr, ar_socketlen_t *addr_len, ar_socket_t *new_socket)
{
    *new_socket = accept(socket, addr, addr_len);
    if (ar_socket_is_invalid(*new_socket))
    {
        *new_socket = 0;

        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while accepting socket connection."
            " Socket Error: %d: %s",
            AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));
        return AR_EFAILED;
    }

    return AR_EOK;
}

int32_t ar_socket_send(ar_socket_t socket, const char_t* buf, int32_t len, int32_t flags, int32_t *bytes_sent)
{
    if (0 > (*bytes_sent = send(socket, (char*)buf, len, flags)))
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while sending data over socket."
            " Socket Error: %d: %s", AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_recv(ar_socket_t socket, char_t* buf, int32_t len, int32_t flags, int32_t *bytes_read)
{
    if (0 > (*bytes_read = recv(socket, (char*)buf, len, flags)))
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while recieving data over socket."
            " Socket Error: %d: %s", AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_get_options(ar_socket_t socket, int32_t level, int32_t opt_name, char_t* opt_val, ar_socketlen_t *opt_val_len)
{
    ar_socketlen_t tmp_opt_val_len = 0;
    if (0 > getsockopt(socket, level, opt_name, opt_val, &tmp_opt_val_len))
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while setting socket options."
            " Socket Error: %d: %s", AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }

    *opt_val_len = tmp_opt_val_len;
    return AR_EOK;
}

int32_t ar_socket_set_options(ar_socket_t socket, int32_t level, int32_t opt_name, const char_t* opt_val, int32_t opt_val_len)
{
    if (0 > setsockopt(socket, level, opt_name, opt_val, opt_val_len))
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while setting socket options."
            " Socket Error: %d: %s", AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));

        return AR_EFAILED;
    }
    return AR_EOK;
}

int32_t ar_socket_tcp(ar_socket_t *s)
{
    *s = socket(AF_INET, SOCK_STREAM, TCP_PROTOCOL);
    if (ar_socket_is_invalid(*s))
    {
        *s = 0;

        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while opening TCP socket."
            " Socket Error: %d: %s",
            AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));
        return AR_EFAILED;
    }

    return AR_EOK;
}

int32_t ar_socket_unix(ar_socket_t *s)
{
    *s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ar_socket_is_invalid(*s))
    {
        *s = 0;

        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while opening TCP socket."
            " Socket Error: %d: %s",
            AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));
        return AR_EFAILED;
    }

    return AR_EOK;
}

int32_t ar_socket_inet_ntop(
    int32_t family,
    void* addr,
    char_t* addr_string,
    size_t addr_string_length)
{
    const char_t* out = inet_ntop(family, addr, addr_string, addr_string_length);
    if (out == NULL)
    {
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error converting binary address to string."
            " Socket Error: %d: %s",
            AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));
        return AR_EFAILED;
    }

    return AR_EOK;
}

uint16_t ar_socket_htons(uint16_t port)
{
    return htons(port);
}

int32_t ar_socket_inet_pton(
    int32_t family,
    char_t* addr_string,
    void* addr_struct)
{
    return inet_pton(family, addr_string, addr_struct);
}

int32_t ar_socket_get_peer_name(
    ar_socket_t socket,
    ar_socket_addr_t *socket_addr,
    ar_socketlen_t *addr_length)
{
    if (0 == getpeername(socket, socket_addr, addr_length))
        return AR_EOK;

    AR_SOCKET_ERR(
        "Error[%d]: Encounter error while retrieving peer name."
        " Socket Error: %d: %s",
        AR_EFAILED, AR_SOCKET_LAST_ERROR, ar_socket_last_error_str(AR_SOCKET_LAST_ERROR));
    return AR_EFAILED;
}

int32_t ar_socket_get_addr_info(
    const char_t* node,
    const char_t* service,
    const ar_socket_addr_info_t* hints,
    ar_socket_addr_info_t** addr_results)
{
    int32_t status = getaddrinfo(node, service, hints, addr_results);
    if (0 == status)
        return AR_EOK;
    else
        AR_SOCKET_ERR(
            "Error[%d]: Encounter error while retrieving address info."
            " Socket Error: %d: %s",
            AR_EFAILED, status, gai_strerror(status));
    return AR_EFAILED;
}

void ar_socket_free_addr_info(
    ar_socket_addr_info_t* addr_info)
{
    freeaddrinfo(addr_info);
}
