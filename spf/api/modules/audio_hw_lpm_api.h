#ifndef _AUDIO_HW_LPM_API_H_
#define _AUDIO_HW_LPM_API_H_
/**
 * \file audio_hw_lpm_api.h
 * \brief 
 *  	 This file contains lpm api for requesting/releasing LPM memory resources for remote client
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

/**
   Param ID for lpass core
   This ID should only be used under PRM module instance
*/
#define PARAM_ID_RSC_LOW_PWR_MEM 0x080010CD

/* When LPM resources are successfully allocated and requested:
    - The status field indicates a success
    - The message payload contains the LPM resources response payload
    - Data in the payload contains the physical address (lower 32 bits and higher 32 bits) of the LPM that was allocated by
      the aDSP.

    For example, if 4 KB of LPM was requested and it is
    successfully allocated, the data in the payload contains a valid physical address.

    If requested resources were not allocated successfully, the payload is
    invalid. */

#include "spf_begin_pack.h"
/** Struct for response for LPM memory request by HLOS  */
struct lpm_rsc_request_t
{
   uint32_t lpm_type;
   /**< LPM memory type
     @values #LPAIF_CORE_LPM */
   uint32_t size_in_bytes;
   /**< Amount of LPM needed in bytes */
}
#include "spf_end_pack.h"
;

typedef struct lpm_rsc_request_t lpm_rsc_request_t;

#include "spf_begin_pack.h"
/** Struct for response for LPM memory request response by HLOS  */
/* This payload is for PRM_CMD_RSP_REQUEST_HW_RSC,
    when the LPM resources are requested.
   When the request is for LPM resources, this structure immediately
    follows apm_module_param_data_t.
*/
struct lpm_rsp_rsc_request_t
{
   uint32_t lpm_type;
   /**< LPM memory type
     @values #LPAIF_CORE_LPM */
   uint32_t size_in_bytes;
   /**< Amount of LPM allocated in bytes */
   uint32_t phy_addr_lsw;
   /**< LSW of allocated LPM physical address */
   uint32_t phy_addr_msw;
   /**< MSW of allocated LPM physical address */
}
#include "spf_end_pack.h"
;

typedef struct lpm_rsp_rsc_request_t lpm_rsp_rsc_request_t;

#include "spf_begin_pack.h"
/** Struct for LPM memory release by HLOS  */
struct lpm_rsc_release_t
{
   uint32_t lpm_type;
   /**< LPM memory type
     @values #LPAIF_CORE_LPM*/
   uint32_t size_in_bytes;
   /**< Amount of LPM to release in bytes */
   uint32_t phy_addr_lsw;
   /**< LSW of LPM physical address to release */
   uint32_t phy_addr_msw;
   /**< MSW of LPM physical address to release */
}
#include "spf_end_pack.h"
;

typedef struct lpm_rsc_release_t lpm_rsc_release_t;

/* Note: There is no response other than the prm error code for releasing from LPM */

#endif /* _AUDIO_HW_LPM_API_H_ */
