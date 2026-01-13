#ifndef _TCPIP_GATEWAY_SOCKET_UTIL_H_
#define _TCPIP_GATEWAY_SOCKET_UTIL_H_
/**
*==============================================================================
*  \file tcpip_gateway_socket_util.h
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
#include "ar_osal_types.h"
#include "ar_osal_log.h"
#include "ar_osal_string.h"
#include "ar_sockets_api.h"
#include <string>

typedef enum tgws_util_address_type_t{
    TGWS_ADDRESS_TCPIP = 0,
    TGWS_ADDRESS_UNIX_ABSTRACT_DOMAIN = 1,
}tgws_util_address_type_t;

tgws_util_address_type_t tgws_get_address_type();

uint32_t tgws_util_get_socket_address_length(tgws_util_address_type_t address_type, std::string address);

uint32_t tgws_util_create_socket(ar_socket_t* socket);

void tgws_util_get_socket_address(tgws_util_address_type_t address_type, std::string address, uint16_t port, ar_socket_addr_storage_t* socket_address);

#endif /*_TCPIP_GATEWAY_SOCKET_UTIL_H_*/
