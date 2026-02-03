/**
*==============================================================================
* \file ats.h
* \brief
*                  A T S  H E A D E R  F I L E
*
*     This header file contains all the definitions necessary for the QACT
*     Tuning Service to handle request buffer and operate ACDB
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*------------------------------------------
* Notes
*------------------------------------------*/
/* Platform Agnostic Services
*
* The Online and FTS service are cross-platform. This means that these two
* services are fully functional in the device simulator and dont require
* retrieving packets from the *.bin file. All other services have
* dependecies on the platform or other ar componets. For simulation
* MCS/ADIE/RTC are stubbed out for compilation with the device simulator
*/

/*------------------------------------------
* Includes
*------------------------------------------*/

#include "ats.h"
#include "ats_i.h"
#include "ats_online.h"
#include "ats_rtc.h"
#include "ats_dls.h"
#include "ats_fts.h"
#include "ats_mcs.h"
#include "ats_adie_rtc.h"
#include "ats_common.h"
#include "acdb_utility.h"
#include "ats_transport_api.h"

/* ---------------------------------------------------------------------------
 * Type Declarations
 *--------------------------------------------------------------------------- */

typedef struct ats_service_node_t {
	uint32_t service_id;
	ATS_CALLBACK service_callback;
	struct ats_service_node_t *p_next;
}AtsServiceNode;

typedef struct ats_registry_table_t {
	AtsServiceNode *p_head;
	AtsServiceNode *p_tail;
}AtsRegistryTable;

/* ---------------------------------------------------------------------------
 * Global Variables
 *--------------------------------------------------------------------------- */
AtsBuffer ats_main_buffer					= {0};
ATS_SIM_CALLBACK ats_simulation_callback    = NULL;
bool_t simulation_enabled                   = FALSE;
static AtsRegistryTable *g_ats_reg_tbl      = NULL;
static uint32_t ats_init_count              = 0;

/* ---------------------------------------------------------------------------
* External Functions and Forward Declarations
*--------------------------------------------------------------------------- */
extern int32_t actp_diag_init(
    void(*callback_function)(uint8_t*, uint32_t, uint8_t**, uint32_t*)
);

extern int32_t actp_diag_deinit(void);

void ats_execute_command(
    uint8_t *req_buf_ptr,
	uint32_t req_buf_length,
	uint8_t **resp_buf_ptr,
	uint32_t *resp_buf_length
);

static bool_t get_command_length(
    uint8_t *req_buf_ptr,
    uint32_t req_buf_length,
    uint32_t *data_length
);

static void ats_create_error_resp(
    uint32_t error_code,
    uint8_t *req_buf_ptr,
    uint8_t *resp_buf_ptr,
    uint32_t *resp_buf_length
);

static void ats_create_suc_resp(
    uint32_t error_code,
    uint32_t data_length,
    uint8_t *req_buf_ptr,
    uint8_t *resp_buf_ptr,
    uint32_t *resp_buf_length
);

static bool_t is_service_registered(uint32_t service_id);

void ats_register_simulation(ATS_SIM_CALLBACK sim_callback);

void ats_simulation_switch(void);

/*-----------------------------------------------------------------------------
* Public Functions
*----------------------------------------------------------------------------*/

/**
 * \brief
 *    Initilizes ATS including all services (RTC, RTM, MCS, ADIE, Online)
 *    and Data transports (Diag USB, TCPIP)
 *
 * \return AR_EOK when success, AR_EFAILED otherwise
 */
int32_t ats_init(void)
{
	int32_t status = AR_EOK;
	int32_t service_status = AR_EOK;

	if (ats_init_count)
	{
		ATS_ERR("Error[%d]: ATS is already initialized.",
			AR_EALREADY);
		return status;
	}

	/*-----------------------------------------------------
	 *				Initialize ATS Transports
	 *---------------------------------------------------*/
	status = ats_transport_init(ats_execute_command);
	if (AR_FAILED(status))
	{
		/* Dont initialize any of the services if any of
		 * the transports fail to initialize since the ATS
		 * client wont be able to communicate with ATS */
		goto end;
	}

	if (NULL == ats_main_buffer.buffer)
	{
		ats_main_buffer.buffer_size = ATS_ACDB_BUFFER_POSITION + ATS_BUFFER_LENGTH;
		ats_main_buffer.buffer = (uint8_t*)ACDB_MALLOC(
			uint8_t, ats_main_buffer.buffer_size);
		g_ats_reg_tbl = (AtsRegistryTable*)ACDB_MALLOC(AtsRegistryTable, 1);

		if (NULL == ats_main_buffer.buffer || NULL == g_ats_reg_tbl)
		{
			status = AR_ENOMEMORY;
			ATS_ERR("Error[%d]: Failed to allocate memory for "
				"ATS resources",
				status);
		}
		else
		{
			g_ats_reg_tbl->p_head = NULL;
			g_ats_reg_tbl->p_tail = NULL;
		}
	}

	if (AR_FAILED(status))
	{
		goto release_resources;
	}

	/*-----------------------------------------------------
	 *				Initialize ATS Services
	 *---------------------------------------------------*/

	/* At minimum the Online and File Transfer services must
	 * be registered. If these two services fail to register,
	 * then ats_init should fail.*/

	status = ats_online_init();
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"Online service", status);
		goto release_resources;
	}

	status = ats_fts_init();
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"File Transfer service", status);
		goto online_deinit;
	}

	service_status = ats_rtc_init();
	if (AR_FAILED(service_status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"Realtime Calibration service", service_status);
		goto core_service_deinit;
	}

	service_status = ats_dls_init(ats_transport_dls_send_callback);
	if (AR_FAILED(service_status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"Data Logging Service", service_status);
		ats_dls_deinit();
	}

	service_status = ats_mcs_init();
	if (AR_FAILED(service_status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"Media Control service", service_status);
		ats_mcs_deinit();
	}

	service_status = ats_adie_rtc_init();
	if (AR_FAILED(service_status))
	{
		ATS_ERR("Error[%d]: Failed to initialize "
			"Codec Realtime Calibration service", service_status);
		ats_adie_rtc_deinit();
	}

	ats_simulation_switch();

	ats_init_count++;
	goto end;

core_service_deinit:
	ats_rtc_deinit();
	ats_fts_deinit();
online_deinit:
	ats_online_deinit();
release_resources:
	if (NULL != ats_main_buffer.buffer)
	{
		ACDB_FREE(ats_main_buffer.buffer);
		ats_main_buffer.buffer = NULL;
	}
	if (NULL != g_ats_reg_tbl)
	{
		ACDB_FREE(g_ats_reg_tbl);
		g_ats_reg_tbl = NULL;
	}
end:
	if (AR_FAILED(status))
	{
		ATS_ERR("Error[%d]: Failed to initialize ATS", status);
	}
	else
	{
		ATS_ERR("Error[%d]: Successfully initialized ATS", status);
	}

	return status;
}

/**
 * \brief
 *    Deinitilizes ATS and releases resources aquired during ats_init. This
 *    includes all services and data transports
 *
 * \return AR_EOK when success, AR_EFAILED otherwise
 */
int32_t ats_deinit(void)
{
	int32_t status = AR_EOK;

	ATS_DBG("Deinitializing ATS");
	if (!ats_init_count)
	{
		return status;
	}

	if (NULL != ats_main_buffer.buffer)
	{
		ACDB_FREE(ats_main_buffer.buffer);
		ats_main_buffer.buffer = NULL;
	}

	{
		if (g_ats_reg_tbl != NULL && g_ats_reg_tbl->p_head != NULL)
		{
			int32_t count = 0;
			AtsServiceNode *cur_node = g_ats_reg_tbl->p_head;
			ATS_DBG("g_ats_reg_tbl is not NULL, g_ats_reg_tbl->p_head is not NULL\n");

			while (cur_node)
			{
				count++;
				ATS_DBG("Node%d is not empty, address[%p]\n", count, cur_node);
				cur_node = cur_node->p_next;
			}
			if (g_ats_reg_tbl->p_tail != NULL)
			{
				ATS_DBG("g_ats_reg_tbl->p_tail is not NULL, address[%p]\n", g_ats_reg_tbl->p_tail);
			}
		}
	}

	// Deinitializes services
    (void)ats_online_deinit();
    (void)ats_rtc_deinit();
    (void)ats_fts_deinit();
    (void)ats_mcs_deinit();
    (void)ats_adie_rtc_deinit();

	// Deinitializes transport(s)
	(void)ats_transport_deinit();

	if (NULL != g_ats_reg_tbl)
	{
		if (g_ats_reg_tbl->p_head != NULL)
		{
			AtsServiceNode *cur_node = g_ats_reg_tbl->p_head->p_next;
			while (cur_node)
			{
				g_ats_reg_tbl->p_head->p_next = cur_node->p_next;
				ACDB_FREE(cur_node);
				cur_node = g_ats_reg_tbl->p_head->p_next;
			}
			ACDB_FREE(g_ats_reg_tbl->p_head);
		}
		ACDB_FREE(g_ats_reg_tbl);
		g_ats_reg_tbl = NULL;
	}
	ats_init_count = 0;

	return status;
}

/*-----------------------------------------------------------------------------
* Private Functions
*----------------------------------------------------------------------------*/

/**
 * \brief Interpret request and operate ACDB correspondingly, respond with
 * the result.
 *
 * \depends ACDB needs to be initialized before this function is called
 *
 * \param[in/out] req_buf_ptr - pointer to request buffer
 * \param[in/out] req_buf_length - length of the request buffer
 * \param[in/out] resp_buf_ptr - pointer to response buffer
 * \param[in/out] resp_buf_length - length of the response buffer
 *
 * \return none
 */
void ats_execute_command(uint8_t *req_buf_ptr,
	uint32_t req_buf_length,
	uint8_t **resp_buf_ptr,
	uint32_t *resp_buf_length
)
{
	uint32_t data_length;
	int32_t status = AR_EFAILED;
    uint32_t service_id = 0;
    uint32_t service_cmd_id = 0;
	uint8_t *temp_resp_buf = NULL;
	ATS_CALLBACK ats_cb_req_op = NULL;
	uint32_t resp_buf_size = ATS_BUFFER_LENGTH
		- ATS_ACDB_BUFFER_POSITION - sizeof(status);

	if (!ats_main_buffer.buffer)
	{
		*resp_buf_ptr = NULL;
		*resp_buf_length = 0;
		return;
	}

	*resp_buf_ptr = ats_main_buffer.buffer;
	temp_resp_buf = ats_main_buffer.buffer + ATS_ACDB_BUFFER_POSITION;
    char svc_id_str[ATS_SEVICE_ID_STR_LEN] = { 0 };
	if (FALSE == get_command_length(req_buf_ptr, req_buf_length, &data_length))
	{
		/**return error response: ERR_LENGTH_NOT_MATCH */
		ats_create_error_resp(AR_EBADPARAM, req_buf_ptr, *resp_buf_ptr, resp_buf_length);
		return;
	}

	//Copy 2byte service id + 2byte command id
	ATS_MEM_CPY_SAFE((void*)&service_cmd_id, ATS_SERVICE_COMMAND_ID_LENGTH,
		(void*)(req_buf_ptr + ATS_SERVICE_COMMAND_ID_POSITION),
		ATS_SERVICE_COMMAND_ID_LENGTH);

    service_id = ATS_GET_SERVICE_ID(service_cmd_id);
    ATS_SERVICE_ID_STR(svc_id_str, ATS_SEVICE_ID_STR_LEN, service_cmd_id);

    switch (service_id)
    {
    case ATS_RTC_SERVICE_ID:
    case ATS_DLS_SERVICE_ID:
    case ATS_FTS_SERVICE_ID:
    case ATS_MCS_SERVICE_ID:
    case ATS_CODEC_RTC_SERVICE_ID:
    case ATS_ONLINE_SERVICE_ID:
        break;
    default:
        ATS_ERR("The command id provided does not belong to any service category [%x]\n", service_cmd_id);
        ats_create_error_resp(AR_EUNSUPPORTED, req_buf_ptr, *resp_buf_ptr, resp_buf_length);
        return;
    }

	if (g_ats_reg_tbl != NULL)
	{
		AtsServiceNode *pCur = g_ats_reg_tbl->p_head;
		while (pCur)
		{
			if (pCur->service_id == service_id)
			{
				uint32_t temp_req_buf_len = req_buf_length - ATS_HEADER_LENGTH;
				ats_cb_req_op = pCur->service_callback;

                // See note at top on Platform Agnostic Services
                if (simulation_enabled &&
                    (service_id != ATS_ONLINE_SERVICE_ID &&
                        service_id != ATS_FTS_SERVICE_ID &&
                        service_id != ATS_CODEC_RTC_SERVICE_ID))
                {
                    status = ats_simulation_callback(req_buf_length, req_buf_ptr,
                        resp_buf_length, ats_main_buffer.buffer);

                    /* The recorded packet response already contains the status
                     * so there is no need to call ats_create_suc_resp.
                     * If the response buffer associated with the request buffer
                     * cannot be found call ats_create_suc_resp
                     */
                    if(AR_SUCCEEDED(status)) return;
                    else break;
                }

				if (temp_req_buf_len == 0)
				{
					status = ats_cb_req_op(service_cmd_id,
                        NULL, temp_req_buf_len,
                        temp_resp_buf, resp_buf_size, resp_buf_length);
				}
				else
				{
					status = ats_cb_req_op(service_cmd_id,
                        req_buf_ptr + ATS_HEADER_LENGTH, temp_req_buf_len,
                        temp_resp_buf, resp_buf_size, resp_buf_length);
				}
				break;
			}
			else
			{
				pCur = pCur->p_next;
			}
		}

		if (AR_FAILED(status))
		{
            ATS_ERR("Error[%d]: Error occured while executing Command[%s-%d]", status, svc_id_str, ATS_GET_COMMAND_ID(service_cmd_id));
			//ats_create_error_resp(status, req_buf_ptr, *resp_buf_ptr, resp_buf_length);
			ats_create_suc_resp(status, *resp_buf_length, req_buf_ptr, *resp_buf_ptr, resp_buf_length);
		}
		else
		{
			ats_create_suc_resp(status, *resp_buf_length, req_buf_ptr, *resp_buf_ptr, resp_buf_length);
		}
	}
	else
	{
        ATS_ERR("ATS registry table is not initialized. ats_init must be called prior to executing commands");
		status = AR_EFAILED;
	}
}

/**
 * \brief
 * register command id into ATS registry table
 *
 * \depends
 * get_command_length is supposed to be called before this function,
 * which will check the command length and ensures that the
 * service + command id is present.
 *
 * \param[in] service_id - corresponding to command id to the function name,
 *                 client must use this commandId to de-resiger the command
 *  \param[in] service_callback - a function callback
 *
 * \return AR_EOK if the register with function pointer success;
 *                AR_EFAILED otherwise.
 */
int32_t ats_register_service(uint32_t service_id,
    ATS_CALLBACK service_callback
)
{
	int32_t result = AR_EOK;

	if ((service_id != ATS_RTC_SERVICE_ID) &&
		(service_id != ATS_DLS_SERVICE_ID) &&
		(service_id != ATS_FTS_SERVICE_ID) &&
		(service_id != ATS_MCS_SERVICE_ID) &&
        (service_id != ATS_CODEC_RTC_SERVICE_ID)&&
        (service_id != ATS_ONLINE_SERVICE_ID))
	{
		ATS_DBG("[ATS]->Invalid service id Received for ATS registration - %x\n", service_id);
		return AR_EHANDLE;
	}

	//ATS_DBG("[ATS]->registering the command - %x\n", nService_id);

	if (g_ats_reg_tbl == NULL)
	{
		ATS_DBG("[ATS ERROR]->ATS_execute_command->ATS registry table was not initialized\n");
		result = AR_EFAILED;
		return result;
	}

	if (is_service_registered(service_id))
	{
		ATS_DBG("[ATS]->Requested service already registered - %x\n", service_id);
		return AR_EFAILED;
	}

	if (g_ats_reg_tbl->p_tail != NULL)
	{
		AtsServiceNode* pCur = g_ats_reg_tbl->p_tail;
		pCur->p_next = (AtsServiceNode*)ACDB_MALLOC(AtsServiceNode, 1);
		if (pCur->p_next != NULL)
		{
			pCur->p_next->service_id = service_id;
            pCur->p_next->service_callback = service_callback;
			pCur->p_next->p_next = NULL;
			g_ats_reg_tbl->p_tail = pCur->p_next;
		}
		else
		{
			ATS_DBG("[ATS ERROR]->ATS_register_command->fail to ACDB_MALLOC memory\n");
			result = AR_EFAILED;
		}
	}
	else
	{
		/* register with cmdId and function pointer */
		g_ats_reg_tbl->p_head = (AtsServiceNode*)ACDB_MALLOC(AtsServiceNode, 1);
		if (g_ats_reg_tbl->p_head != NULL)
		{
			g_ats_reg_tbl->p_head->service_id = service_id;
            g_ats_reg_tbl->p_head->service_callback = service_callback;
			g_ats_reg_tbl->p_head->p_next = NULL;
			g_ats_reg_tbl->p_tail = g_ats_reg_tbl->p_head;
		}
		else
		{
			ATS_DBG("[ATS ERROR]->ATS_register_command->fail to ACDB_MALLOC memory\n");
			result = AR_EFAILED;
		}
	}

	if (AR_SUCCEEDED(result))
	{
		switch (service_id)
		{
		case ATS_ONLINE_SERVICE_ID:
			ATS_INFO("Online service registered with ATS");
			break;
		case ATS_CODEC_RTC_SERVICE_ID:
            ATS_INFO("ADIE Realtime Calibration Service registered with ATS");
			break;
		case ATS_MCS_SERVICE_ID:
            ATS_INFO("Media Control Service registered with ATS");
			break;
		case ATS_FTS_SERVICE_ID:
            ATS_INFO("File Transfer Service registered with ATS");
			break;
        case ATS_RTC_SERVICE_ID:
            ATS_INFO("Realtime Calibration service registered with ATS");
            break;
        case ATS_DLS_SERVICE_ID:
            ATS_INFO("Data Logging service registered with ATS");
            break;
		default:
            ATS_INFO("Unknown service registered with ATS");
			break;
		}
	}

	return result;
}

/**
 * \brief deregister command into ATS registry table
 *
 * \depends
 * get_command_length is supposed to be called before this function,
 * which will check the command length and ensures that the
 * service + command id is present.
 *
 * \param[in] service_id - corresponding to command id to the function
 *                         name, it is dynamically created and client
                           must use this commandId to de-resiger the command
 *
 * \return AR_EOK if the register with function pointer success;
 *                AR_EFAILED otherwise.
 *
 * SIDE EFFECTS : None
 */
int32_t ats_deregister_service(uint32_t service_id
)
{
	int32_t result = AR_EFAILED;

	if (g_ats_reg_tbl != NULL && g_ats_reg_tbl->p_head != NULL)
	{
		AtsServiceNode* pCur = g_ats_reg_tbl->p_head;
		AtsServiceNode* pPrev = g_ats_reg_tbl->p_head;
		//first Node
		if (pCur->service_id == service_id)
		{
			if (pCur == g_ats_reg_tbl->p_tail)
			{
				ACDB_FREE(pCur);
				g_ats_reg_tbl->p_head = NULL;
				g_ats_reg_tbl->p_tail = g_ats_reg_tbl->p_head;
			}
			else
			{
				g_ats_reg_tbl->p_head = pCur->p_next;
				ATS_DBG("Free first node, p_head[%p],pCur[%p],p_next[%p]\n",
					g_ats_reg_tbl->p_head, pCur, pCur->p_next);
				ACDB_FREE(pCur);
			}

			result = AR_EOK;
		}
		else
		{
			pCur = pCur->p_next;

			//2nd or ... Node
			while (pCur)
			{
				if (pCur->service_id == service_id)
				{
					if (pCur == g_ats_reg_tbl->p_tail)
					{
						g_ats_reg_tbl->p_tail = pPrev;
					}
					pPrev->p_next = pCur->p_next;
					ACDB_FREE(pCur);
					result = AR_EOK;
					break;
				}
				else
				{
					pPrev = pPrev->p_next;
					pCur = pCur->p_next;
				}
			}
		}
		if (AR_FAILED(result))
		{
			ATS_DBG("The provided Service ID was not found in the registry\n");
		}
	}
	else
	{
		ATS_DBG("ATS registry table was not initialized\n");
		result = AR_EFAILED;
	}

	if (AR_SUCCEEDED(result))
	{
        switch (service_id)
        {
        case ATS_ONLINE_SERVICE_ID:
            ATS_DBG("Deregistering Online service");
            break;
        case ATS_CODEC_RTC_SERVICE_ID:
            ATS_DBG("Deregistering ADIE Realtime Calibration Service");
            break;
        case ATS_MCS_SERVICE_ID:
            ATS_DBG("Deregistering Media Control Service");
            break;
        case ATS_FTS_SERVICE_ID:
            ATS_DBG("Deregistering File Transfer Service");
            break;
        case ATS_RTC_SERVICE_ID:
            ATS_DBG("Deregistering Realtime Calibration service");
            break;
        case ATS_DLS_SERVICE_ID:
            ATS_DBG("Deregistering Data Logging service");
            break;
        default:
            ATS_DBG("Deregistering unknown service");
            break;
        }
	}

	return result;
}

int32_t ats_get_service_info(AtsCmdGetServiceInfoRsp *svc_info_rsp, uint32_t rsp_buf_len)
{
    int32_t status = AR_EOK;

    if (rsp_buf_len < sizeof(AtsCmdGetServiceInfoRsp))
    {
        ATS_ERR("Response buffer is too small")
        return AR_EBADPARAM;
    }

    //if (ACDB_SOFTWARE_VERSION_MAJOR == 1 && ACDB_SOFTWARE_VERSION_MINOR == 0)
    //{

    //}
    AtsServiceInfo svc_info = { 0 };
    AtsServiceNode *cur_node = g_ats_reg_tbl->p_head;
    uint32_t found = FALSE;

    while (!IsNull(cur_node))
    {
        svc_info.service_id = cur_node->service_id;

        switch (cur_node->service_id)
        {
        case ATS_RTC_SERVICE_ID:
        {
            svc_info.major = ATS_RTC_MAJOR_VERSION;
            svc_info.minor = ATS_RTC_MINOR_VERSION;
            found = TRUE;
            break;
        }
        case ATS_DLS_SERVICE_ID:
        {
            svc_info.major = ATS_DLS_MAJOR_VERSION;
            svc_info.minor = ATS_DLS_MINOR_VERSION;
            found = TRUE;
            break;
        }
        case ATS_FTS_SERVICE_ID:
        {
            svc_info.major = ATS_FTS_MAJOR_VERSION;
            svc_info.minor = ATS_FTS_MINOR_VERSION;
            found = TRUE;
            break;
        }
        case ATS_MCS_SERVICE_ID:
        {
            ats_mcs_get_version(
                &svc_info.major, &svc_info.minor);
            found = TRUE;
            break;
        }
        case ATS_CODEC_RTC_SERVICE_ID:
        {
            ats_adie_rtc_get_version(
                &svc_info.major, &svc_info.minor);
            found = TRUE;
            break;
        }
        case ATS_ONLINE_SERVICE_ID:
        {
            svc_info.major = ATS_ONC_MAJOR_VERSION;
            svc_info.minor = ATS_ONC_MINOR_VERSION;
            found = TRUE;
            break;
        }
        default:
            found = FALSE;
            break;
        }

        if (found)
        {
            ATS_MEM_CPY_SAFE(&svc_info_rsp->services_info[svc_info_rsp->service_count],
                sizeof(AtsServiceInfo), &svc_info, sizeof(AtsServiceInfo));
            svc_info_rsp->service_count++;
        }

        cur_node = cur_node->p_next;
    }

	svc_info.service_id = 0xACDB0000;
	svc_info.major = ACDB_SOFTWARE_VERSION_MAJOR << 16 | ACDB_SOFTWARE_VERSION_MINOR;
	svc_info.minor = ACDB_SOFTWARE_VERSION_REVISION << 16 | ACDB_SOFTWARE_VERSION_CPLINFO;

	ATS_MEM_CPY_SAFE(&svc_info_rsp->services_info[svc_info_rsp->service_count],
		sizeof(AtsServiceInfo), &svc_info, sizeof(AtsServiceInfo));
	svc_info_rsp->service_count++;

    if (0 == svc_info_rsp->service_count)
    {
        ATS_ERR("No registered services were found");
        status = AR_EFAILED;
    }

    return status;
}

/**
* \brief
* Get request data length from a request buffer
*
* \depends
* the address of a uint32_t variable need to be passed in to
* contain the data length
*
* \param[in] req_buf_ptr: pointer to request buffer
* \param[in] req_buf_length: length of the request buffer
* \param[in] data_length: pointer to the length of data
*
* \return
* Return false if the there is no data length information or the data length
* read from the request buffer is not consistent with the total buffer
* length. Return true otherwise and data length is returned in the last parameter.
*/
static bool_t get_command_length(uint8_t *req_buf_ptr,
    uint32_t req_buf_length,
    uint32_t *data_length
)
{
    bool_t status = FALSE;
    if (req_buf_length < ATS_HEADER_LENGTH)
    {
        /**there is no data length information*/
        status = FALSE;
    }
    else
    {
        /** copy data length*/
        ATS_MEM_CPY_SAFE(data_length, ATS_DATA_LENGTH_LENGTH,
            req_buf_ptr + ATS_DATA_LENGTH_POSITION,
            ATS_DATA_LENGTH_LENGTH);

        if (req_buf_length - ATS_HEADER_LENGTH == *data_length)
        {
            status = TRUE;
        }
        else
        {
            /**the data length read from the request buffer is not consistent
            with the total buffer length.*/
            status = FALSE;
        }
    }
    return status;
}

/**
* \brief
* Create a response error buffer with the specified error code
* and request command id.
*
* \param[in] error_code - response error code
* \param[in/out] req_buf_ptr - pointer to request buffer
* \param[in/out] resp_buf_ptr - pointer to response buffer
* \param[in/out] resp_buf_length - length of the response buffer
*
* \return none
*/
static void ats_create_error_resp(uint32_t error_code,
    uint8_t *req_buf_ptr,
    uint8_t *resp_buf_ptr,
    uint32_t *resp_buf_length
)
{
    /* The format of the output is:
    <-----------4bytes------------>
    +-----------------------------+
    |  service id  |  command id  |
    +-----------------------------+
    +-----------------------------+
    |         data length         |
    +-----------------------------+
    +-----------------------------+
    |            status           |
    +-----------------------------+ */
    uint32_t resp_data_length;

    if (IsNull(resp_buf_ptr))
    {
        ATS_DBG("Response Buffer is not initialized");
        *resp_buf_length = 0;
        return;
    }

    *resp_buf_length = ATS_ERROR_FRAME_LENGTH;
    resp_data_length = ATS_ERROR_FRAME_LENGTH - ATS_HEADER_LENGTH;

    //Service + Command ID
    ATS_MEM_CPY_SAFE(resp_buf_ptr, ATS_SERVICE_COMMAND_ID_LENGTH,
        req_buf_ptr, ATS_SERVICE_COMMAND_ID_LENGTH);

    //Data Length
    ATS_MEM_CPY_SAFE(resp_buf_ptr + ATS_SERVICE_COMMAND_ID_LENGTH, ATS_DATA_LENGTH_LENGTH,
        &resp_data_length,
        ATS_DATA_LENGTH_LENGTH);

    //Status
    ATS_MEM_CPY_SAFE(resp_buf_ptr + ATS_HEADER_LENGTH, ATS_ERROR_CODE_LENGTH,
        &error_code,
        ATS_ERROR_CODE_LENGTH);
}

/**
* \brief
* Create a response buffer with the specified response data
* and request command id.
*
* \param[in] error_code - response error code
* \param[in/out] req_buf_ptr - pointer to request buffer
* \param[in/out] resp_buf_ptr - pointer to response buffer
* \param[in/out] resp_buf_length - length of the response buffer
*
* \return none
*/
static void ats_create_suc_resp(uint32_t error_code, uint32_t data_length,
    uint8_t *req_buf_ptr,
    uint8_t *resp_buf_ptr,
    uint32_t *resp_buf_length
)
{
    /* The format of the output is:
    <-----------4bytes------------>
    +-----------------------------+
    |  service id  |  command id  |
    +-----------------------------+
    +-----------------------------+
    |         data length         |
    +-----------------------------+
    +-----------------------------+
    |            status           |
    +-----------------------------+
    +-----------------------------+
    |                             |
    |    data(response length)    |
    |                             |
    +-.-.-.-.-.-.-.-.-.-.-.-.-.-.-+ */

    uint32_t resp_data_length;

    if (IsNull(resp_buf_ptr))
    {
        ATS_DBG("Response Buffer is not initialized");
        *resp_buf_length = 0;
        return;
    }

    *resp_buf_length = ATS_HEADER_LENGTH + data_length + sizeof(error_code);
    resp_data_length = sizeof(error_code) + data_length;

    //Service + Command ID
    ATS_MEM_CPY_SAFE(resp_buf_ptr, ATS_SERVICE_COMMAND_ID_LENGTH, req_buf_ptr, ATS_SERVICE_COMMAND_ID_LENGTH);

    //Data length
    ATS_MEM_CPY_SAFE(resp_buf_ptr + ATS_SERVICE_COMMAND_ID_LENGTH, ATS_DATA_LENGTH_LENGTH,
        &resp_data_length, ATS_DATA_LENGTH_LENGTH);

    //Status
    ar_mem_move(resp_buf_ptr + ATS_HEADER_LENGTH + ATS_ERROR_CODE_LENGTH, data_length,
        resp_buf_ptr + ATS_HEADER_LENGTH, data_length);

    ATS_MEM_CPY_SAFE(resp_buf_ptr + ATS_HEADER_LENGTH, sizeof(error_code),
        &error_code, sizeof(error_code));
}

/**
* \brief
* Checks if the given service is already registered.
*
* PARAMS:
* \param[in] service_id - Service ID
*
* \return returns true or false.
*/
static bool_t is_service_registered(uint32_t service_id)
{
    if (g_ats_reg_tbl != NULL)
    {
        AtsServiceNode *cur_node = g_ats_reg_tbl->p_head;
        while (cur_node)
        {
            if (cur_node->service_id == service_id)
            {
                return TRUE;
            }

            cur_node = cur_node->p_next;
        }
    }

    return FALSE;
}

/**
* \brief
* Toggles simulation mode on/off depending on whether _DEVICE_SIM is defined
*
* \depends
* The _DEVICE_SIM preprocessor definition must be defined
*/
void ats_simulation_switch()
{
#if defined(_DEVICE_SIM)
    simulation_enabled = TRUE;
#else
    simulation_enabled = FALSE;
#endif
}

void ats_register_simulation(ATS_SIM_CALLBACK sim_callback)
{
    __UNREFERENCED_PARAM(sim_callback);
#if defined(_DEVICE_SIM)
    ats_simulation_callback = sim_callback;
#endif
}

