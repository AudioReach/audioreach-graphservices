/**
 *==============================================================================
 * \file ats_dls.c
 * \brief
 *                             A T S  D L S
 *                         S O U R C E  F I L E
 *
 *	Contains the implemnentation of the ats dls service. This service is used by
 *  the ats tuning client for registering log codes to recieve binary log packetg
 *  data which is used for realtime monitoring.
 *
 * \copyright
 *	  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *	  SPDX-License-Identifier: BSD-3-Clause
 *==============================================================================
 */

/* Notes
 *    size_t is used in calculating the size of the gsl structure headers
 *    becaause the last element in those structures is a pointer. The size
 *    of a pointer may very between x86 and x64 architectures
 */

#include "ats.h"
#include "ats_i.h"
#include "ats_dls.h"
#include "ats_common.h"
#include "ar_osal_mutex.h"
#include "ar_osal_thread.h"
#include "acdb_utility.h"
#include "acdb_common.h"

/*The version number of the ATS DLS get log packet header */
#define ATS_DLS_HEADER_VERSION 1
/*ARTM Tag in ASCII*/
#define ATS_DLS_HEADER_TAG 0x4D545241
/**< The byte size of one DLS buffer. A DLS buffer contains one log packet */
#define ATS_DEFAULT_DLS_BUFFER_SIZE 5120
/**< The number of DLS buffers in shared memory */
#define ATS_DEFAULT_DLS_BUFFER_COUNT 30

/* The dls buffer pool configuration */
struct gsl_dls_buffer_pool_config_t buffer_pool_config;
//buffer that stores binary log packets before sending to tcpip dls server
AtsBuffer dls_data_send_buffer;
ar_osal_mutex_t buffer_ready_lock;
ATS_DSL_TCPIP_SEND_CALLBACK ats_dls_tcpip_send_callback;
ar_osal_thread_t thd_ready_buffer_routine;

#if defined(_DEVICE_SIM)
int32_t gsl_dls_client_is_feature_supported()
{
	return AR_EOK;
}
int32_t gsl_dls_client_init(struct gsl_dls_buffer_pool_config_t* gbuffer_pool_config, GSL_DLS_CLIENT_BUFFER_READY_CALLBACK callback)
{
	__UNREFERENCED_PARAM(gbuffer_pool_config);
	__UNREFERENCED_PARAM(callback);
	return AR_EOK;
}
int32_t gsl_dls_client_deinit()
{
	return AR_EOK;
}
int32_t gsl_dls_client_create_buffer_pool(struct gsl_dls_buffer_pool_config_t* gbuffer_pool_config)
{
	__UNREFERENCED_PARAM(gbuffer_pool_config);
	return AR_EOK;
}
void gsl_dls_client_get_ready_dls_buffer_list(struct gsl_dls_ready_buffer_index_list_t* buffer_ready_list)
{
	__UNREFERENCED_PARAM(buffer_ready_list);
}
int32_t gsl_dls_client_get_log_buffer(uint32_t log_buffer_index, struct gls_dls_buffer_t* dls_log_buffer)
{
	__UNREFERENCED_PARAM(log_buffer_index);
	__UNREFERENCED_PARAM(dls_log_buffer);
	return AR_EOK;
}
int32_t gsl_dls_client_return_used_buffers(struct gsl_dls_ready_buffer_index_list_t* buffer_index_list)
{
	__UNREFERENCED_PARAM(buffer_index_list);
	return AR_EOK;
}
int32_t gsl_dls_client_register_deregister_log_code(uint32_t log_code, bool_t is_log_code_enabled)
{
	__UNREFERENCED_PARAM(log_code);
	__UNREFERENCED_PARAM(is_log_code_enabled);
	return AR_EOK;
}
#endif

int32_t ats_dls_buffer_ready_callback(void);

int32_t ats_dls_register_log_code(
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled)
{
	__UNREFERENCED_PARAM(rsp_buf);
	__UNREFERENCED_PARAM(rsp_buf_size);

	uint32_t status = AR_EOK;
	uint32_t log_code = 0;
	uint32_t offset = 0;

	if (cmd_buf_size != sizeof(uint16_t))
		return AR_EBADPARAM;

	ATS_READ_SEEK_UI16(log_code, cmd_buf, offset);

	status = gsl_dls_client_register_deregister_log_code(log_code, TRUE);

	*rsp_buf_bytes_filled = 0;
	return status;
}

int32_t ats_dls_deregister_log_code(
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled)
{
	__UNREFERENCED_PARAM(rsp_buf);
	__UNREFERENCED_PARAM(rsp_buf_size);

	__UNREFERENCED_PARAM(rsp_buf);
	__UNREFERENCED_PARAM(rsp_buf_size);

	uint32_t status = AR_EOK;
	uint32_t log_code = 0;
	uint32_t offset = 0;

	if (cmd_buf_size != sizeof(uint16_t))
		return AR_EBADPARAM;

	ATS_READ_SEEK_UI16(log_code, cmd_buf, offset);

	status = gsl_dls_client_register_deregister_log_code(log_code, FALSE);

	*rsp_buf_bytes_filled = 0;
	return status;
}

int32_t ats_dls_set_buffer_config(
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled)
{
	__UNREFERENCED_PARAM(rsp_buf);
	__UNREFERENCED_PARAM(rsp_buf_size);

	int32_t status = AR_EOK;

	if (cmd_buf_size < sizeof(struct gsl_dls_buffer_pool_config_t))
		return AR_EBADPARAM;

	ATS_MEM_CPY_SAFE(&buffer_pool_config, cmd_buf_size, cmd_buf, cmd_buf_size);

	status = gsl_dls_client_create_buffer_pool(&buffer_pool_config);
	if(AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to create dls buffer pool.", status, 0);
	}

	*rsp_buf_bytes_filled = 0;
	return status;
}
/**
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
 */
int32_t ats_dls_get_log_data(
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled)
{

	__UNREFERENCED_PARAM(cmd_buf);
	__UNREFERENCED_PARAM(cmd_buf_size);
	__UNREFERENCED_PARAM(rsp_buf_size);

	int32_t status = AR_EOK;
	uint32_t offset = 0;
	uint32_t dls_log_data_rsp_header_size = 12;
	struct gsl_dls_ready_buffer_index_list_t ready_buffer_index_list;
	struct gls_dls_buffer_t log_buffer;
	AtsDlsLogDataHeader rsp = {0};

	*rsp_buf_bytes_filled = 0;

	gsl_dls_client_get_ready_dls_buffer_list(&ready_buffer_index_list);

	if (ready_buffer_index_list.buffer_count == 0)
		return status;

	/* skip the header and write it later
	 * the header isn't 4-byte aligned so subtract 4 bytes due to struct alignment
	 */
	offset += dls_log_data_rsp_header_size;

	ATS_DBG("#dls ready buffers %d", ready_buffer_index_list.buffer_count);

	for (uint16_t index = 0; index < ready_buffer_index_list.buffer_count; index++)
	{
		status = gsl_dls_client_get_log_buffer(ready_buffer_index_list.buffer_index_list[index], &log_buffer);
		if(AR_FAILED(status))
		{
			continue;
		}

		ATS_DBG("Buffer size received from dls client is %d bytes", log_buffer.size);

		ATS_MEM_CPY_SAFE(rsp_buf + offset, sizeof(uint32_t), &log_buffer.size, sizeof(uint32_t));
		offset += sizeof(uint32_t);

		ATS_MEM_CPY_SAFE(rsp_buf + offset, log_buffer.size, log_buffer.buffer, log_buffer.size);
		offset += log_buffer.size;

		//include log buffer size filed and data in the total size
		rsp.total_log_data_size += sizeof(uint32_t) + log_buffer.size;
	}

	//Write header
	ATS_DBG("writing header");
	rsp.header_id = ATS_DLS_HEADER_TAG;
	rsp.header_version = ATS_DLS_HEADER_VERSION;
	rsp.log_buffer_count = ready_buffer_index_list.buffer_count;
	status = AR_EOK;

	offset = 0;
	ATS_MEM_CPY_SAFE(rsp_buf + offset, sizeof(uint32_t), &rsp.header_id, sizeof(uint32_t));
	offset += sizeof(uint32_t);
	ATS_MEM_CPY_SAFE(rsp_buf + offset, sizeof(uint16_t), &rsp.header_version, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	ATS_MEM_CPY_SAFE(rsp_buf + offset, sizeof(uint16_t), &rsp.log_buffer_count, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	ATS_MEM_CPY_SAFE(rsp_buf + offset, sizeof(uint32_t), &rsp.total_log_data_size, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	// ATS_MEM_CPY_SAFE(rsp_buf, sizeof(uint32_t), &rsp, sizeof(AtsDlsLogDataHeader));
	*rsp_buf_bytes_filled += sizeof(AtsDlsLogDataHeader) + rsp.total_log_data_size;

	ATS_DBG("set used buffers to gsl");
	gsl_dls_client_set_used_buffers(&ready_buffer_index_list);
	ATS_DBG("done returning buffers to spf");

	return status;
}

void ats_dls_ready_buffer_thd(void* params){

	while(true)
	{
		//wait for signal and release ready buffers to dsp

		//get ready buffers from gsl

		ATS_DBG("return buffers to spf");
		gsl_dls_client_return_used_buffers(NULL);
		ATS_DBG("done returning buffers to spf");
	}
}

int32_t ats_dls_create_ready_buffer_thread()
{
	int32_t status = AR_EOK;
	char_t* thd_name = "ATS_DLS_RDY_THD";
	ar_osal_thread_attr_t thd_attr =
    {
        thd_name,
        0xF4240,
        0,
    };

    ar_osal_thread_start_routine r = \
        (ar_osal_thread_start_routine)(ats_dls_ready_buffer_thd);

    status = ar_osal_thread_create(&thd_ready_buffer_routine, &thd_attr, r, NULL);
    if (AR_FAILED(status))
    {
        ATS_ERR("Error[%d]: Failed to create thread %s", status, thd_name);
        return status;
    }

	return status;
}

int32_t ats_dls_ioctl(
	uint32_t svc_cmd_id,
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled
)
{
	int32_t status = AR_EOK;

	int32_t(*func_cb)(
		uint8_t *cmd_buf,
		uint32_t cmd_buf_size,
		uint8_t *rsp_buf,
		uint32_t rsp_buf_size,
		uint32_t *rsp_buf_bytes_filled
		) = NULL;

	switch (svc_cmd_id)
	{
	case ATS_CMD_DLS_START:
		func_cb = ats_dls_register_log_code;
		break;
	case ATS_CMD_DLS_STOP:
		func_cb = ats_dls_deregister_log_code;
		break;
	/*Online get service returns version of DLS service as well*/
	/*case ATS_CMD_DLS_GET_VERSION:
		func_cb = get_dls_version;
		break;*/
	case ATS_CMD_DLS_CONFIGURE:
		func_cb = ats_dls_set_buffer_config;
		break;
	case ATS_CMD_DLS_GET_LOG_DATA:
		func_cb = ats_dls_get_log_data;
		break;
	default:
		ATS_ERR("Command[%x] is not supported", svc_cmd_id);
		status = AR_EUNSUPPORTED;
		break;
	}

	if (!AR_FAILED(status))
	{
		status = func_cb(cmd_buf, cmd_buf_size, rsp_buf, rsp_buf_size, rsp_buf_bytes_filled);
	}

	return status;
}


int32_t ats_dls_init(ATS_DSL_TCPIP_SEND_CALLBACK callback)
{
	int32_t status = AR_EOK;

	status = gsl_dls_client_is_feature_supported();
	if (AR_FAILED(status))
	{
		ATS_DBG("dls support is not enabled in this build");
		return status;
	}

	// ar_set_log_level(AR_CRITICAL|AR_ERROR|AR_INFO|AR_DEBUG);

	ATS_DBG("Registering ATS Relatime Monitoring Service...");

	status = ar_osal_mutex_create(&buffer_ready_lock);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to create buffer ready lock", status);
		return status;
	}

	status = ats_register_service(ATS_DLS_SERVICE_ID, ats_dls_ioctl);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to register the ATS Data Logging Service.", status);
		goto destroy_lock;
	}

	buffer_pool_config.buffer_size = ATS_DEFAULT_DLS_BUFFER_SIZE;
	buffer_pool_config.buffer_count = ATS_DEFAULT_DLS_BUFFER_COUNT;

	status = gsl_dls_client_init(&buffer_pool_config, ats_dls_buffer_ready_callback);
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed initialize dls client", status);
	}
	//allocate buffer for storing dls log buffer

	dls_data_send_buffer.buffer_size = buffer_pool_config.buffer_count *buffer_pool_config.buffer_size;
	dls_data_send_buffer.buffer = ACDB_MALLOC(uint8_t, dls_data_send_buffer.buffer_size);

	ats_dls_tcpip_send_callback = callback;

	//start ready buffer thread
	ats_dls_create_ready_buffer_thread();
destroy_lock:
	if(AR_FAILED(status))
	{
		ar_osal_thread_join_destroy(thd_ready_buffer_routine);
		ar_osal_mutex_destroy(buffer_ready_lock);
	}

	return status;
}

int32_t ats_dls_deinit(void)
{
	int32_t status = AR_EOK;

	status = gsl_dls_client_is_feature_supported();
	if (AR_FAILED(status))
	{
		ATS_DBG("dls support is not enabled in this build");
		return status;
	}

	ATS_DBG("Deregistering ATS Data Logging Service...");

	status = gsl_dls_client_deinit();
	if (status != AR_EOK)
	{
		ATS_DBG("Error[%d]: Failed to deinitialize gsl dls client", status, 0);
	}

	status = ats_deregister_service(ATS_DLS_SERVICE_ID);
	if (status != AR_EOK)
	{
		ATS_DBG("Error[%d]: Failed to deregister ATS Data Logging Service.", status, 0);
	}

	ar_osal_mutex_destroy(buffer_ready_lock);
	ar_osal_thread_join_destroy(thd_ready_buffer_routine);
	//free ats dls send buffer

	return status;
}

int32_t ats_dls_buffer_ready_callback(void)
{
	int32_t status = AR_EOK;
	uint32_t bytes_written = 0;

	ACDB_MUTEX_LOCK(buffer_ready_lock);

	ar_mem_set(dls_data_send_buffer.buffer, 0, dls_data_send_buffer.buffer_size);

	status = ats_dls_get_log_data(NULL, 0,
		dls_data_send_buffer.buffer,
		dls_data_send_buffer.buffer_size,
		&bytes_written);

	ATS_DBG("calling ats dls tcpip send callback. sending %d bytes", bytes_written);
	ats_dls_tcpip_send_callback(dls_data_send_buffer.buffer, bytes_written);

	ACDB_MUTEX_UNLOCK(buffer_ready_lock);

	return status;
}
