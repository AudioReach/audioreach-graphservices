/**
*==============================================================================
*  \file tcpip_gateway_socket_util.cpp
*  \brief
*               T C P I P  G A T E W A Y  S O C K E T  U T I L I T Y
*                             H E A D E R  F I L E
*
*    Contains utility functions to simplify socket creation in the
*    server sources files
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/
#include "ar_osal_mem_op.h"
#include "tcpip_gateway_socket_util.h"

tgws_util_address_type_t tgws_get_address_type()
{
#if defined (__linux__)
	return TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN;
#elif defined (_WIN32)
	return TGWS_ADDRESS_TCPIP;
#endif
}

uint32_t tgws_util_get_socket_address_length(tgws_util_address_type_t address_type, std::string address)
{
    uint32_t address_length = 0;
    switch(address_type)
    {
        case TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN:
        {
            //see ar_sockaddr_un_t
            address_length = sizeof(uint16_t) + address.length();
            break;
        }
        case TGWS_ADDRESS_TCPIP:
        {
            address_length = sizeof(ar_socket_addr_in_t);
            break;
        }
    }

    return address_length;
}

uint32_t tgws_util_create_socket(ar_socket_t* socket)
{
#if defined (__linux__)
	if (AR_FAILED(ar_socket_unix(socket)))
		return AR_EFAILED;
#elif defined (_WIN32)
	if (AR_FAILED(ar_socket_tcp(socket)))
		return AR_EFAILED;
#endif
    return AR_EOK;
}

void tgws_util_get_socket_address(tgws_util_address_type_t address_type, std::string address, uint16_t port, ar_socket_addr_storage_t* socket_address)
{
    switch(address_type)
    {
        case TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN:
        {
            #if defined(__linux__)
            //Create Abstract Domain Address
            ar_socket_addr_un_t* un_abstract_sock_addr =
                (ar_socket_addr_un_t*)socket_address;
            ar_strcpy(un_abstract_sock_addr->sun_path, AR_UNIX_PATH_MAX, address.c_str(), address.length());
            un_abstract_sock_addr->sun_family = AF_UNIX;
            un_abstract_sock_addr->sun_path[0] = 0;
            #endif
            break;
        }
        case TGWS_ADDRESS_TCPIP:
        {
            ar_socket_addr_in_t ip_sock_addr = { 0 };
            ip_sock_addr.sin_family = AF_INET;
            ip_sock_addr.sin_port = htons(port);
            inet_pton(AF_INET, address.c_str(), &ip_sock_addr.sin_addr.s_addr);
            ar_mem_cpy(socket_address, sizeof(ar_socket_addr_storage_t), &ip_sock_addr, sizeof(ar_socket_addr_in_t));
            break;
        }
    }
}
