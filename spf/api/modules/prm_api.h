#ifndef _PRM_API_H_
#define _PRM_API_H_
/**
 * \file prm_api.h
 * \brief 
 *  	 This file contains Proxy Resource Manager module interface
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

/**
  Instance ID of the Proxy Resource Manager module

  This module instance supports the following command IDs:
  - #PRM_CMD_REQUEST_HW_RSC
  - #PRM_CMD_RELEASE_HW_RSC
  - #PRM_CMD_RSP_REQUEST_HW_RSC
  - #PRM_CMD_RSP_RELEASE_HW_RSC

  @calibration_hdr_field
  module_id -- PRM_MODULE_INSTANCE_ID
 */
#define PRM_MODULE_INSTANCE_ID 0x00000002

/** @ingroup EVENT_ID_MBHC_INTR_DETECTION
  - EVENT_ID_MBHC_INTR_DETECTION is sent when a mbhc interrupt has been received to notify the client
  - This event has no payload attached
  - This event is registered using the APM_CMD_REGISTER_MODULE_EVENTS command sent against the PRM module static
    instance ID, and deregistered the
    same way. The payload for the reg/dereg is apm_module_register_events_t, using the PRM as the module ID

  @gpr_hdr_fields
  Opcode -- EVENT_ID_MBHC_INTR_DETECTION

  @return
  None
 */
#define EVENT_ID_MBHC_INTR_DETECTION 0x0800115E

/** @ingroup prm_cmd_request_hw_rsc
  - This API is used by client for requesting the single h/w resource ID
  - Command payload depends upon the resource ID and it may vary for
  different resource types
  - A single resource ID may encompass multiple instances of that resource
  - From client perspective, it is possible to request multiple such instances
  using a single command
  - Multiple resources ID request cannot be clubbed together in a single command.
  Individual command must be sent for requesting each individual resource ID
  - Depending upon resource type, a resource ID may be requested multiple number
  of times as long as the resource configuration is not changed. This is possible
  if there are multiple unique clients on HLOS side requesting for the same resource ID
  - Multiple request for same resource ID may not be supported for all resources
  - PRM module keeps track of reference counter for each such request

  @gpr_hdr_fields
  Opcode -- PRM_CMD_REQUEST_HW_RSC

  @structure
  apm_cmd_header_t
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any, but not mandatory>

  @return
  Opcode -- PRM_CMD_RSP_REQUEST_HW_RSC

 */
#define PRM_CMD_REQUEST_HW_RSC 0x0100100F

/** @ingroup prm_cmd_release_hw_rsc
  - This API is used by client for releasing the h/w resource requested
  using the PRM_CMD_REQUEST_HW_RSC command
  - This command results in failure if command issued for releasing a
  resource which was not previously requested
  - Number of release commands for a given resource ID must match with
  the number of request commands
  - If the number of release is lesser than number of request, it may result
  in h/w resource to remain ON
  - For resources with multiple instances, release command need not be symmetric
  to release request. For example, client may request 3 clock ID's under a single
  REQUEST command but release maybe be done across 2 or more commands

  @gpr_hdr_fields
  Opcode -- PRM_CMD_RELEASE_HW_RSC

  @structure
  apm_cmd_header_t
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any, but not mandatory>

  @return
  Opcode --  PRM_CMD_RSP_RELEASE_HW_RSC

 */
#define PRM_CMD_RELEASE_HW_RSC 0x01001010

/** @ingroup prm_cmd_rsp_request_hw_rsc
  - PRM_CMD_RSP_REQUEST_HW_RSC is sent in response to PRM_CMD_REQUEST_HW_RSC
  - The response payload depends upon the resource type and it varies for
  different resource ID's

  @gpr_hdr_fields
  Opcode -- PRM_CMD_RSP_REQUEST_HW_RSC

  @structure
  - prm_cmd_rsp_hw_rsc_cfg_t

  @return
  None
 */
#define PRM_CMD_RSP_REQUEST_HW_RSC 0x02001002

/** @ingroup prm_cmd_rsp_release_hw_rsc
  - PRM_CMD_RSP_RELEASE_HW_RSC is sent in response to PRM_CMD_RELEASE_HW_RSC
  - The response payload depends upon the resource type and it varies for
  different resource ID's

  @gpr_hdr_fields
  Opcode -- PRM_CMD_RSP_RELEASE_HW_RSC

  @structure
  - prm_cmd_rsp_hw_rsc_cfg_t

  @return
  None
 */
#define PRM_CMD_RSP_RELEASE_HW_RSC 0x02001003

/**
   This structure is the common payload structure used by
   resource request and release response API's.
   If there are no failures, only the success code is returned
   back to the client.
   In case of partial or complete failure, the response payload
   may contain more information depending upon the resource ID.

   Immediately following this structure is a variable length
   array of structure objects corresponding to each status of
   resource requested. Length of the array is determined by
   number of resources being requested
 */

#include "spf_begin_pack.h"

struct prm_cmd_rsp_hw_rsc_cfg_t
{
   uint32_t param_id;
   /**< @ PARAM_ID_RSC_LPASS_CORE
    *   @ PARAM_ID_RSC_AUDIO_HW_CLK
    */

   uint32_t status;
   /**< Status representing of request/release cmd
    * @ 0 - Success
    * @ Non-Zero - Failure
    * */
}

#include "spf_end_pack.h"
;

typedef struct prm_cmd_rsp_hw_rsc_cfg_t prm_cmd_rsp_hw_rsc_cfg_t;

#ifdef CSMD_COSIM
/* These are private commands used in the OTTP CSMD simulator setup to
to perform cosim reset.
OPEN is used to write 1 to the RESET register and CLOSE is used to write 0.
The sequence is - CLOSE -> Write to dma_io_dynamic.cfg -> OPEN --> usecase*/

#define PRM_PVT_CMD_COSIM_OPEN 0x01001024
#define PRM_PVT_CMD_COSIM_CLOSE 0x01001025

#endif // CSMD_COSIM

#endif /* _PRM_API_H_ */
