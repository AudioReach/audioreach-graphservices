#ifndef _TCPIP_GATEWAY_COMMON_H_
#define _TCPIP_GATEWAY_COMMON_H_
/**
*=============================================================================
* \file tcpip_gateway_common.h
*
*                      T C P I P  G A T E W A Y  C O M M O N
*                             H E A D E R  F I L E
*
* \brief
*      Common header file used by GATEWAY modules.
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries. 
*  SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/

#include "ar_osal_types.h"
#include "ar_osal_log.h"
#include "ar_osal_mem_op.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define GATEWAY_LOG_TAG  "GATEWAY"
#define GATEWAY_ERR(...)  AR_LOG_ERR(GATEWAY_LOG_TAG, __VA_ARGS__)
#define GATEWAY_DBG(...)  AR_LOG_DEBUG(GATEWAY_LOG_TAG, __VA_ARGS__)
#define GATEWAY_INFO(...)  AR_LOG_INFO(GATEWAY_LOG_TAG, __VA_ARGS__)

struct tgws_config_t
{
    uint16_t option;
    uint16_t port;
    char port_str[5];
};

struct buffer_t{
    uint32_t buffer_size;
    char_t* buffer;
};

/**< Defines options for connecting to the gateway server */
typedef enum tgws_connection_options_t
{
    TGWS_CONNECTION_OPTION_USB      = 0,
    TGWS_CONNECTION_OPTION_WIFI     = 1
}tgws_connection_options_t;

/**< Defines error codes specific to the gateway server */
typedef enum tgws_status_codes_t
{
    /**< General Success */
    TGWS_E_SUCCESS           = 0,
    /**< End message forwarding */
    TGWS_E_END_MSG_FWD       = 1,
    /**< Ignore message forwarding */
    TGWS_E_IGNORE_MSG_FWD    = 2
}tgws_status_codes_t;

inline int32_t tgws_mem_cpy(void* dest, size_t sz_dest, void* src, size_t sz_src)
{
	int32_t result = AR_EOK;

	if (dest == NULL || src == NULL) return result;
	if (sz_src <= sz_dest)
	{
		ar_mem_cpy((int8_t*)dest, sz_dest, (int8_t*)src, sz_src);

		if (sz_dest - sz_src != 0)
		{
			ar_mem_set((int8_t*)dest + sz_src, 0, sz_dest - sz_src);
		}
		result = 0;
	}

	return result;
}
#endif /*_TCPIP_GATEWAY_COMMON_H_*/
