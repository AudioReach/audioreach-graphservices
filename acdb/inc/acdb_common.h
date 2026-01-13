#ifndef ACDB_COMMON_H
#define ACDB_COMMON_H
/**
*=============================================================================
* \file acdb_common.h
*
* \brief
*      Common header file used by ACDB modules.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#include "ar_osal_types.h"
#include "ar_osal_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_TAG  "ACDB"
#define ACDB_ERR(...)  AR_LOG_ERR(LOG_TAG, __VA_ARGS__)
#define ACDB_DBG(...)  AR_LOG_DEBUG(LOG_TAG, __VA_ARGS__)
#define ACDB_INFO(...) AR_LOG_INFO(LOG_TAG, __VA_ARGS__)
#define ACDB_VERBOSE(...) AR_LOG_VERBOSE(LOG_TAG, __VA_ARGS__)

/* Error/Debug Message Format 2
* @param msg: Brief message describing the error
* @param err_code: Error code to be logged
* @param variadic: any parameter to fill in %d %x %s characters in msg
*/
#define ACDB_ERR_MSG_2(status, msg, ...) \
ACDB_ERR("Status[%d]:"##msg, status, __VA_ARGS__)
#define ACDB_DBG_MSG_2(status, msg, ...) \
ACDB_DBG("Status[%d]:"##msg, status, __VA_ARGS__)

/* Error/Debug Message Format 1
* @param msg: Brief message describing the error
* @param err_code: Error code to be logged
*/
#define ACDB_ERR_MSG_1(msg, err_code) ACDB_ERR("Error[%d]: %s", err_code, msg)
#define ACDB_DBG_MSG_1(msg, err_code) ACDB_DBG("Error[%d]: %s", err_code, msg)

/**< Macro for obtaining a mutex. The lock must already be initialized
 * through ar_osal_mutex_create before calling this macro. */
#define ACDB_MUTEX_LOCK(lock)\
do{\
	if (lock){\
		uint32_t __status = ar_osal_mutex_lock(lock);\
		if (AR_FAILED(__status)){\
			ACDB_DBG("Error[%d]: Failed to obtain lock", __status);\
		}\
	}\
	break;\
} while (1);

 /**< Macro for releasing a mutex. The lock must already be initialized
  * through ar_osal_mutex_create before calling this macro. */
#define ACDB_MUTEX_UNLOCK(lock)\
do{\
	if (lock){\
		uint32_t __status = ar_osal_mutex_unlock(lock);\
		if (AR_FAILED(__status)){\
			ACDB_DBG("Error[%d]: Failed to release lock", __status);\
		}\
	}\
	break;\
} while (1);

//#define ACDB_DEBUG_ENABLE

#ifdef ACDB_DEBUG_ENABLE
extern ar_fhandle *acdb_pkt_log_fd;

#define ACDB_PKT_LOG_INIT() \
do {\
if (acdb_pkt_log_fd == NULL)\
acdb_pkt_log_fd = (ar_fhandle*)malloc(sizeof(ar_fhandle));\
ar_fopen(acdb_pkt_log_fd, "acdb_log.bin", AR_FOPEN_READ_WRITE);\
} while (0)

#define ACDB_PKT_LOG_DEINIT() \
do{\
ar_fclose(*acdb_pkt_log_fd);\
ACDB_FREE(acdb_pkt_log_fd); \
acdb_pkt_log_fd = NULL;\
} while (0)

/*
* @param DST_FD File descriptor where logs will be logged to
* @param ID_STR MUST be exactly 8 chars, string that will be placed in the log
*					  before BUFF to help in parsing
*
*/
#define ACDB_PKT_LOG_TO_FILE(DST_FD, ID_STR, BUFF, SIZE)\
do {\
char *acdb_log_str = "acdb_log_";\
size_t bytes_written = 0;\
ar_fwrite(*DST_FD, acdb_log_str, strlen(acdb_log_str), &bytes_written);\
ar_fwrite(*DST_FD, __FUNCTION__, strlen(__FUNCTION__), &bytes_written);\
ar_fwrite(*DST_FD, "_", strlen("_"), &bytes_written);\
ar_fwrite(*DST_FD, ID_STR, strlen(ID_STR), &bytes_written);\
ar_fwrite(*DST_FD, BUFF, SIZE, &bytes_written);\
ar_fwrite(*DST_FD, "\n", sizeof(char), &bytes_written);\
} while (0)

#define ACDB_PKT_LOG_DATA(ID_STR, BUFF, SIZE)\
ACDB_PKT_LOG_TO_FILE(acdb_pkt_log_fd, ID_STR, BUFF, SIZE)

#else
#define ACDB_PKT_LOG_INIT()
#define ACDB_PKT_LOG_DEINIT()
#define ACDB_PKT_LOG_DATA(ID_STR, BUFF, SIZE)
#endif // ACDB_DEBUG_ENABLE

#endif
