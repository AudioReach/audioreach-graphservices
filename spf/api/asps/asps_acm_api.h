#ifndef _ASPS_ACM_API_H_
#define _ASPS_ACM_API_H_
/**
 * \file asps_api.h
 * \brief
 *    This file contains Audio-Sensor Proxy Service Commands Data Structures
 *
 *    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *    SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

/*------------------------------------------------------------------------------
 *  Usecase ID API includes
 *----------------------------------------------------------------------------*/
#include "asps_acd_usecase_api.h"
#include "asps_upd_usecase_api.h"
#include "asps_ads_usecase_api.h"
#include "asps_us_rendering_usecase_api.h"
#include "asps_sdz_usecase_api.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/


/*------------------------------------------------------------------------------
 *  API Definitions
 *----------------------------------------------------------------------------*/

/*ASPS module instance ID. Used for GPR communication */
#define ASPS_MODULE_INSTANCE_ID  0x00000007

/*------------------------------------------------------------------------------
 *  EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST
 *----------------------------------------------------------------------------*/

/**
  Event raised by ASPS to setup a given usecase for a given sensor instance.

  The event has a variable payload which is specific to usecase id. For example,
  ACD usecase will contain list of context ids.

  @Payload struct
     apm_cmd_header_t
     apm_module_event_t
     event_id_asps_sensor_register_request_t
     <usecase specific payload if any>
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_MODULE_EVENT_TO_CLIENT

  @return
  Error code -- #PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 */
#define EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST               0x080012EB

/**
   Payload of the  EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST data structure. This
   structure is preceeded by apm_module_event_t structure and followed by
   usecase specific payload if any.
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_id_asps_sensor_register_request_t
{
   uint32_t see_sensor_iid;
   /**< Unique identifier for the audio sensor instance in SEE framework.
        Valid non-zero value. */

   uint32_t usecase_id;
   /**< Indicates the usecase which a given sensor instance is trying to
        register.

        Supported usecase ids:
          1. ASPS_USECASE_ID_ACD
          2. ASPS_USECASE_ID_UPD
          3. ASPS_USECASE_ID_PCM_DATA
          4. ASPS_USECASE_ID_ULTRASOUND_RENDERING
          5. ASPS_USECASE_ID_SDZ      */

   uint32_t payload_size;
   /**< Size of the "usecase_id" specific payload if any. */

   uint32_t payload[0];
   /**< Points to "usecase_id" specific paylod if any.
          1. ASPS_USECASE_ID_ACD - Payload required - struct asps_acd_usecase_register_request_payload_t
          2. ASPS_USECASE_ID_UPD - Payload not required.
          3. ASPS_USECASE_ID_PCM_DATA - Payload required - struct asps_pcm_data_usecase_register_payload_t  */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_id_asps_sensor_register_request_t event_id_asps_sensor_register_request_t;

/*------------------------------------------------------------------------------
 *  PARAM_ID_ASPS_SENSOR_REGISTER_ACK
 *----------------------------------------------------------------------------*/

/**
  This parameter is set as an ACK to the event EVENT_ID_ASPS_SENSOR_REGISTER_REQUEST.
  It contains the

  @Payload struct
     apm_cmd_header_t
     apm_module_param_data_t
     param_id_asps_sensor_register_ack_t
     <Usecase specific payload if any>
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_CMD_SET_CFG

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

 */
#define PARAM_ID_ASPS_SENSOR_REGISTER_ACK                             0x080012ED

/**
   Payload of the  PARAM_ID_ASPS_SENSOR_REGISTER_ACK data structure. This
   structure is preceeded by  apm_module_param_data_t structure.
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_asps_sensor_register_ack_t
{
   uint32_t see_sensor_iid;
   /**< Sensor instance iid which was passed as part of the ASPS event. */

   uint32_t usecase_id;
   /**< Indicates the usecase which a given sensor instance is trying to
        register.

        Supported usecase ids:
          1. ASPS_USECASE_ID_ACD
          2. ASPS_USECASE_ID_UPD
          3. ASPS_USECASE_ID_PCM_DATA      */

   uint32_t payload_size;
   /**< Size of the usecase_id specific ACK payload following this structure.

       In case of ACD usecase, the ACK payload contains list of context ids for
       each of the ACD module instance IDs that. */

   uint32_t payload[0];
   /**< Points to "usecase_id" specific paylod if any.

          1. ASPS_USECASE_ID_ACD - Payload struct asps_acd_usecase_register_ack_payload_t
             This can be a cascaded payload, if there are multiple ACD module instance ids.
               < acd_sensor_register_ack_payload_t > list of context ids for module instance 1
               < acd_sensor_register_ack_payload_t > list of context ids for module instance 2

          2. ASPS_USECASE_ID_UPD - Payload  struct asps_upd_usecase_register_ack_payload_t

          3. ASPS_USECASE_ID_PCM_DATA - Payload  struct asps_audio_data_usecase_register_ack_payload_t   */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct param_id_asps_sensor_register_ack_t param_id_asps_sensor_register_ack_t;

/*------------------------------------------------------------------------------
 *  EVENT_ID_ASPS_SENSOR_DEREGISTER_REQUEST
 *----------------------------------------------------------------------------*/

/**
  De-registers request event ID. This is the sensor de-register request event.

  @Payload struct
     apm_cmd_header_t
     apm_module_event_t
     event_id_asps_sensor_deregister_request_t
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_MODULE_EVENT_TO_CLIENT

  @return
  Error code -- #PARAM_ID_ASPS_BASIC_ACK

 */
#define EVENT_ID_ASPS_SENSOR_DEREGISTER_REQUEST             0x080012EC

/**
   Payload of the EVENT_ID_ASPS_SENSOR_DEREGISTER_REQUEST data structure. This
   structure is preceeded by apm_module_event_t structure.
*/
#include "spf_begin_pack.h"

struct event_id_asps_sensor_deregister_request_t
{
   uint32_t see_sensor_iid;
   /**< Unique identifier for the audio sensor instance in SEE framework.
        Valid non-zero value. */

   uint32_t usecase_id;
   /**< Module event ID for which sensor instance wants to de-register from.
        Valid non-zero value.

        Supported usecase ids:
          1. ASPS_USECASE_ID_ACD  
          2. ASPS_USECASE_ID_UPD
          3. ASPS_USECASE_ID_PCM_DATA      */
}
#include "spf_end_pack.h"
;

typedef struct event_id_asps_sensor_deregister_request_t event_id_asps_sensor_deregister_request_t;

/*------------------------------------------------------------------------------
 *  EVENT_ID_ASPS_GET_SUPPORTED_CONTEXT_IDS
 *----------------------------------------------------------------------------*/

/**
  Event raised by ASPS to get list of supported instance IDS.

  @Payload struct
     apm_cmd_header_t
     apm_module_event_t
     event_id_asps_get_supported_context_ids_t
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_MODULE_EVENT_TO_CLIENT

  @return
  Response set config -- #PARAM_ID_ASPS_SUPPORTED_CONTEXT_IDS

 */
#define EVENT_ID_ASPS_GET_SUPPORTED_CONTEXT_IDS           0x08001302

/**
   Payload of the  EVENT_ID_ASPS_GET_SUPPORTED_CONTEXT_IDS data structure. This
   structure is preceded by apm_module_event_t structure.
*/
#include "spf_begin_pack.h"

struct event_id_asps_get_supported_context_ids_t
{
   uint32_t see_sensor_iid;
   /**< Unique identifier for the audio sensor instance in SEE framework thats
        requesting for the list of supported context ids.

        Valid non-zero value. */
}
#include "spf_end_pack.h"
;

typedef struct event_id_asps_get_supported_context_ids_t event_id_asps_get_supported_context_ids_t;

/*------------------------------------------------------------------------------
 *  PARAM_ID_ASPS_SUPPORTED_CONTEXT_IDS
 *----------------------------------------------------------------------------*/

/**
  Set param to inform list of supported context ids to ASPS.
  This param is through APM_CMD_SET_CFG.

  sizeof of the param payload = sizeof(param_id_asps_supported_context_ids_t)
                                 + (num_supported_context * sizeof(uint32_t) );

  @Payload struct
     apm_cmd_header_t
     apm_module_param_data_t
     param_id_asps_supported_context_ids_t
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_CMD_SET_CFG

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

 */
#define PARAM_ID_ASPS_SUPPORTED_CONTEXT_IDS                 0x08001303

/**
   Payload of the  PARAM_ID_ASPS_SUPPORTED_CONTEXT_IDS data structure. This
   structure is preceeded by  apm_module_param_data_t structure.
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_asps_supported_context_ids_t
{
   uint32_t see_sensor_iid;
   /**< Unique identifier for the audio sensor instance in SEE framework that
        requested for the list of supported context ids.
        Valid non-zero value. */

   uint32_t num_supported_contexts;
   /**< Number of supported context ids */

   uint32_t supported_context_ids[0];
   /**< Variable length array of supported context ids.
        Length of the array is "num_supported_context" */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_asps_supported_context_ids_t param_id_asps_supported_context_ids_t;

/*------------------------------------------------------------------------------
 *  EVENT_ID_ASPS_CLOSE_ALL
 *----------------------------------------------------------------------------*/

/**
  Event raised by ASPS to close all the sessions corresponding to earlier register
  requests.

  There is no payload for this event.

  @Payload struct
     apm_cmd_header_t
     apm_module_event_t
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_MODULE_EVENT_TO_CLIENT

  @return
  ACK is not required.

 */
#define EVENT_ID_ASPS_CLOSE_ALL                       0x0800133E


/*------------------------------------------------------------------------------
 *  PARAM_ID_ASPS_BASIC_ACK
 *----------------------------------------------------------------------------*/

/**
  Sets the error code corresponding to the request event raised by ASPS.
  This param is through APM_CMD_SET_CFG.

  @Payload struct
     apm_cmd_header_t
     apm_module_param_data_t
     param_id_asps_basic_ack_t
     <8 byte alignment if any, but not mandatory at the end>

  @gpr_hdr_fields
  Opcode -- APM_CMD_SET_CFG

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

 */
#define PARAM_ID_ASPS_BASIC_ACK                         0x08001304

/**
   Payload of the  PARAM_ID_ASPS_BASIC_ACK data structure. This
   structure is preceeded by  apm_module_param_data_t structure.
*/
#include "spf_begin_pack.h"

struct param_id_asps_basic_ack_t
{
   uint32_t error_code;
   /**< Audio reach error code. */

   uint32_t asps_event_id;
   /**< ASPS event ID to which this response is being returned. */

   uint32_t see_sensor_iid;
   /**< Sensor instance iid which was passed as part of the ASPS event. */

   uint32_t usecase_id;
   /**<  Usecase ID for which the response is being returned.*/
}
#include "spf_end_pack.h"
;
typedef struct param_id_asps_basic_ack_t param_id_asps_basic_ack_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif //_ASPS_API_H_
