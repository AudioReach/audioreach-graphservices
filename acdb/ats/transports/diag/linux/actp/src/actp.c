/**
*==============================================================================
* \file actp.c
* \brief
*                    A U D I O   C A L I B R A T I O N
*                 T R A N S P O R T E R   P R O T O C O L
*                          S O U R C E  F I L E
*
*     This file contains the implementation of ACTP diag dispatcher.
*
*     INITIALIZATION REQUIREMENTS:
*     actp_diag_init must be called to initialise ACTP module.
*     actp_diag_init must be called ~AFTER~ initialization of SOUND TASK
*     A pointer to a call-back function with the following format needs
*     to be passed in:
*       func(char_t*, uint32_t, char_t**, uint32_t*)
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

/*------------------------------------------
* Includes
*------------------------------------------*/
#include "audtp.h"
#include "actp.h"

#ifdef __INTEGRITY
#include "Diag_LSM.h"
#else
#include "diag_lsm.h"
#endif

#include "ats_common.h"

//Defing diag functions for compilation on ottp
#if defined(ATS_OTTP) || defined(_DEVICE_SIM) || defined(ATS_USES_DUMMY_DIAG)
void diagpkt_commit(void *ptr) { __UNREFERENCED_PARAM(ptr); }
diagpkt_subsys_cmd_code_type diagpkt_subsys_get_cmd_code(void *ptr) { __UNREFERENCED_PARAM(ptr); return 0; }

void *diagpkt_err_rsp(diagpkt_cmd_code_type code,
    void *req_ptr, uint16_t req_len)
{
    __UNREFERENCED_PARAM(code);
    __UNREFERENCED_PARAM(req_ptr);
    __UNREFERENCED_PARAM(req_len);
    return NULL;
}
void diagpkt_tbl_reg(const diagpkt_user_table_type * tbl_ptr) { __UNREFERENCED_PARAM(tbl_ptr); };

void *diagpkt_subsys_alloc(diagpkt_subsys_id_type id,
    diagpkt_subsys_cmd_code_type code, unsigned int length) {
    __UNREFERENCED_PARAM(id);
    __UNREFERENCED_PARAM(code);
    __UNREFERENCED_PARAM(length);
    return NULL;
}
#endif

/*------------------------------------------
* Static Variable Definitions
*------------------------------------------*/

/**< The actp diag dispatch table that needs to be
 * registered with the diag dispathcer to route the diag
 * packets sent from PC to the actp diag dispatcher.
 */
static const diagpkt_user_table_entry_type  actp_diag_table[] =
{
    {
        ACTP_CMD_ID_START,
        ACTP_CMD_ID_END,
        avsACTP_diag_cmd
    }
};


/** ACTP session*/
static atp_phone_context_struct actp_phone_context;

/*------------------------------------------
* External Functions
*------------------------------------------*/

int32_t actp_diag_init(
        void (*request_callback)(uint8_t*, uint32_t, uint8_t**, uint32_t*)
        )
{
    if (Diag_LSM_Init(NULL))
    {
        /**Register command range and diag subsystem dispatcher*/
        DIAGPKT_DISPATCH_TABLE_REGISTER(DIAG_SUBSYS_AUDIO_SETTINGS,
            actp_diag_table);
        memset(&actp_phone_context, 0, sizeof(atp_phone_context_struct));
        /** Set the pointer to the application callback function which receives the
        request buffer and provides a response*/
        actp_phone_context.receive_req_buffer_ptr = request_callback;
        return AR_EOK;
    }

    ATS_INFO("Error[%d]: Failed to initialize DIAG", AR_EFAILED);
    return AR_EFAILED;
}

int32_t actp_diag_deinit(void)
{
    if (Diag_LSM_DeInit())
    {
        return AR_EOK;
    }

    ATS_INFO("Error[%d]: Failed to de-initialize DIAG", AR_EFAILED);
    return AR_EFAILED;
}

PACKED void * avsACTP_diag_cmd(
        PACKED void *req_ptr,
        uint16_t pkt_len
        )
{
    diag_pkt_resp_struct *rsp_diag_pkt_ptr  = NULL;
    diag_pkt_resp_struct *actp_rsp_ptr = NULL;
    diag_pkt_req_struct request;
    uint16_t actp_rsp_pkt_len = 0;
    /** Initialize subsystem command code*/
    uint16_t command_code = ACTP_CMD_ID_START;
    if (NULL != req_ptr)
    {
        /**Create an unpacked version of diag packet*/
        ATS_MEM_CPY_SAFE((void *)&request,sizeof(diag_pkt_req_struct), (void *)req_ptr,pkt_len);
        /**Get command code*/
        command_code = (uint16_t) diagpkt_subsys_get_cmd_code((void *) &request);
        /** Verify is the command code valid */
        if (command_code < ACTP_CMD_ID_START || command_code > ACTP_CMD_ID_END)
        {
            /**If not in the range return error*/
            rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_err_rsp(DIAG_BAD_CMD_F, req_ptr, pkt_len);
        }
        else
        {
            /**Send diag packet to protocol layer*/

            /**Call ATP to process the packet*/
            atp_receive_diag_pkt(&request, &actp_rsp_ptr, &actp_phone_context);
            /**If we have not received response frame from protocol layer return error*/
            if(NULL == actp_rsp_ptr)
            {
                rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_err_rsp(DIAG_BAD_CMD_F, req_ptr, pkt_len);
            }
            else
            {
                actp_rsp_pkt_len = DIAG_RES_PKT_SIZE + sizeof(diag_pkt_header_struct);
                /**
                  Create a diag packet using diag api . It automatically delets the
                  packet after we commit the packet.
                  */
                rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_subsys_alloc (
                        DIAG_SUBSYS_AUDIO_SETTINGS,(uint16_t) command_code, actp_rsp_pkt_len);
                //Klocwork fix: check rsp_diag_pkt_ptr if it is a null ptr.
                if (rsp_diag_pkt_ptr == NULL)
                {
                   rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_err_rsp(DIAG_BAD_CMD_F, req_ptr, pkt_len);
                   if (actp_rsp_ptr != NULL)
                   {
                      ACDB_FREE(actp_rsp_ptr);
                   }
                   return (rsp_diag_pkt_ptr);
                }
                ATS_MEM_CPY_SAFE(rsp_diag_pkt_ptr,actp_rsp_pkt_len,actp_rsp_ptr,actp_rsp_pkt_len);
                /**Send the diag packet .This will be received on PC side as response
                  packet*/
                if (rsp_diag_pkt_ptr == NULL)
                //Klocwork fix: check rsp_diag_pkt_ptr if it is a null ptr.
                {
                    rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_err_rsp(DIAG_BAD_CMD_F, req_ptr, pkt_len);
                    return (rsp_diag_pkt_ptr);
                }
                diagpkt_commit(rsp_diag_pkt_ptr);
                rsp_diag_pkt_ptr = NULL;
                /**Free the response packet we received from protocol layer*/
                ACDB_FREE(actp_rsp_ptr);
            }
        }
    }
    else
    {
        rsp_diag_pkt_ptr = (diag_pkt_resp_struct*) diagpkt_err_rsp(DIAG_BAD_CMD_F, req_ptr, pkt_len);
    }
    return (rsp_diag_pkt_ptr);
}
