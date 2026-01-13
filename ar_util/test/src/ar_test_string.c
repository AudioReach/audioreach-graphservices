/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include "ar_osal_test.h"
#include "ar_osal_string.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"

void ar_test_string_main()
{
	int32_t status = AR_EOK;
	char_t pStr[] = "test 0 string ";
	char_t pStr1[29] = "test 1 string ";
	char_t pStr2[24] = "test 2 string ";
	char_t pStr3[] = "test string ";
	char_t* pStrTemp = NULL;
	char_t pStr4[40] = { 0 };
	char_t pStr5[40] = { 0 };


	AR_LOG_DEBUG(LOG_TAG, "ar_strlen(%d), pStr:size(%d) String:%s", ar_strlen(pStr,sizeof(pStr)), sizeof(pStr), pStr);
	AR_LOG_DEBUG(LOG_TAG, "ar_strcat(%d), pStr1:size(%d) String:%s", ar_strcat(pStr1, sizeof(pStr1), pStr, sizeof(pStr)), sizeof(pStr1), pStr1);
	AR_LOG_DEBUG(LOG_TAG, "ar_strcat(%d), pStr2:size(%d) String:%s", ar_strcat(pStr2, sizeof(pStr2), pStr, sizeof(pStr)), sizeof(pStr2), pStr2);
	AR_LOG_DEBUG(LOG_TAG, "ar_strcpy(%d), pStr2:size(%d) String:%s", ar_strcpy(pStr2, sizeof(pStr2), pStr, sizeof(pStr)), sizeof(pStr2), pStr2);
	AR_LOG_DEBUG(LOG_TAG, "ar_strcpy(%d), pStr3:size(%d) String:%s", ar_strcpy(pStr3, sizeof(pStr3), pStr, sizeof(pStr)), sizeof(pStr3), pStr3);
	pStrTemp = ar_strstr(pStr1, "1");
	AR_LOG_DEBUG(LOG_TAG, "ar_strstr(), pStrTemp:size(%d) String:%s",  sizeof(pStrTemp), pStrTemp);

	ar_sprintf(pStr4, sizeof(pStr4), "%s", "test 4 string ");
	AR_LOG_DEBUG(LOG_TAG, "ar_sprintf(), pStr4:size(%d) String:%s", sizeof(pStr4), pStr4);

	ar_sscanf(pStr4, "%14c", pStr5, (unsigned int)sizeof(pStr5));
	AR_LOG_DEBUG(LOG_TAG, "ar_sscanf(), pStr5:size(%d) String:%s", sizeof(pStr5), pStr5);

	return;
}
