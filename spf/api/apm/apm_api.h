#ifndef _APM_API_H_
#define _APM_API_H_
/**
 * \file apm_api.h
 * \brief 
 *  	 This file contains Audio Processing Manager Commands Data Structures
 * 
 * \copyright
 *    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *    SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

/*------------------------------------------------------------------------------
 *  Module ID Definitions
 *----------------------------------------------------------------------------*/


#include "spf_begin_pack.h"

/**
    In-band :
         This structure is followed by an in-band payload of type,
         apm_module_param_data_t
    Out-of-band :
         Out of band payload can be extracted from the mem_map_handle,
         payload_address_lsw and payload_address_msw using the
         posal api posal_memorymap_get_virtual_addr_from_shmm_handle.
         Out of band payload of apm_cmd_header_t can be of 2 types.
         1. apm_module_param_data_t
         2. apm_module_param_shared_data_t - This payload should only be used 
            for the following apm commands
               a. APM_CMD_REGISTER_SHARED_CFG
               b. APM_CMD_DEREGISTER_SHARED_CFG
 */
struct apm_cmd_header_t
{
   uint32_t payload_address_lsw;
   /**< Lower 32 bits of the payload address. */

   uint32_t payload_address_msw;
   /**< Upper 32 bits of the payload address.

         The 64-bit number formed by payload_address_lsw and
         payload_address_msw must be aligned to a 32-byte boundary and be in
         contiguous memory.

         @values
         - For a 32-bit shared memory address, this field must be set to 0.
         - For a 36-bit shared memory address, bits 31 to 4 of this field must
           be set to 0. @tablebulletend */

   uint32_t mem_map_handle;
   /**< Unique identifier for a shared memory address.

        @values
        - NULL -- The message is in the payload (in-band).
        - Non-NULL -- The parameter data payload begins at the address
          specified by a pointer to the physical address of the payload in
          shared memory (out-of-band).

        @contcell
        The aDSP returns this memory map handle through
        #apm_CMD_SHARED_MEM_MAP_REGIONS.

        An optional field is available if parameter data is in-band:
        %afe_port_param_data_v2_t param_data[...].
        See <b>Parameter data variable payload</b>. */

   uint32_t payload_size;
   /**< Actual size of the variable payload accompanying the message or in
        shared memory. This field is used for parsing both in-band and
        out-of-band data.

        @values > 0 bytes, in multiples of 4 bytes */
}
#include "spf_end_pack.h"
;

typedef struct apm_cmd_header_t apm_cmd_header_t;

/** 
   Payload of the module parameter data structure. 
   Immediately following this structure are param_size bytes of 
   calibration data. The structure and size depend on the 
   module_instace_id/param_id combination. 
*/


#include "spf_begin_pack.h"

struct apm_module_param_data_t
{
   uint32_t module_instance_id;
   /**< Valid instance ID of module
        @values  */

   uint32_t param_id;
   /**< Valid ID of the parameter.

        @values See Chapter */

   uint32_t param_size;
   /**< Size of the parameter data based upon the
        module_instance_id/param_id combination.
        @values > 0 bytes, in multiples of
        4 bytes at least */

   uint32_t error_code;
   /**< Error code populated by the entity hosting the  module. 
     Applicable only for out-of-band command mode  */
}
#include "spf_end_pack.h"
;

typedef struct apm_module_param_data_t apm_module_param_data_t;


/** 
   Payload of the shared persistent module parameter data structure.
   Immediately following this structure are param_size bytes of
   calibration data. The structure and size depend on the param_id.
*/


#include "spf_begin_pack.h"

struct apm_module_param_shared_data_t
{
   uint32_t param_id;
   /**< Valid ID of the parameter.

        @values See Chapter */

   uint32_t param_size;
   /**< Size of the parameter data based upon the
        module_instance_id/param_id combination.
        @values > 0 bytes, in multiples of
        4 bytes at least */
}
#include "spf_end_pack.h"
;

typedef struct apm_module_param_shared_data_t apm_module_param_shared_data_t;


/**
   Payload of the property data structure. This 
   structure applies to container, sub-graph and module 
   properties. Immediately following this structure are 
   prop_size bytes of property data. 
   Property payload size must be at least 4 bytes.
*/

#include "spf_begin_pack.h"

struct apm_prop_data_t
{
   uint32_t prop_id;
   /**< Property ID
        @values  */

   uint32_t prop_size;
   /**< Size of the property ID structure */

}
#include "spf_end_pack.h"
;

typedef struct apm_prop_data_t apm_prop_data_t;


/**
   Payload of the register events data structure. This
   structure is preceded by apm_cmd_header_t structure
*/

#include "spf_begin_pack.h"

struct apm_module_register_events_t
{
   uint32_t module_instance_id;
   /**< Valid instance ID of module */

   uint32_t event_id;
   /**< Valid event ID of the module */

   uint32_t is_register;
   /**< 1 - to register the event
    *   0 - to de-register the event
    */

   uint32_t error_code;
   /**< Error code populated by the entity hosting the  module.
     Applicable only for out-of-band command mode  */

   uint32_t event_config_payload_size;
   /**< Size of the event config data based upon the
        module_instance_id/event_id combination.
        @values > 0 bytes, in multiples of
        4 bytes at least */

   uint32_t reserved;
   /**< reserved must be set to zero.
   For 8 byte alignment */
}
#include "spf_end_pack.h"
;
typedef struct apm_module_register_events_t apm_module_register_events_t;

/**
   Payload of the module event data structure. This
   structure is preceeded by apm_cmd_header_t structure
   and followed by event payload
*/

#include "spf_begin_pack.h"

struct apm_module_event_t
{
   uint32_t event_id;
   /**< Valid event ID of the module */

   uint32_t event_payload_size;
   /**< Size of the event data based upon the
        module_instance_id/eveny_id combination.
        @values > 0 bytes, in multiples of
        4 bytes at least */
}
#include "spf_end_pack.h"
;

typedef struct apm_module_event_t apm_module_event_t;

/**
  Instance ID of the Audio Processing Manager module

  This module instance supports the following parameter IDs:
  - #APM_PARAM_ID_SUB_GRAPH_CFG
  - #APM_PARAM_ID_CONTAINER_CFG
  - #APM_PARAM_ID_MODULES_LIST
  - #APM_PARAM_ID_MODULE_PROP
  - #APM_PARAM_ID_MODULE_CONN 
  - #APM_PARAM_ID_MODULE_CTRL_LINK_CFG 
  
  @calibration_hdr_field
  module_id -- APM_MODULE_INSTANCE_ID
*/

/**
    h2xml_title1          {Audio Processing Manager (APM) Module API}
    h2xml_title_agile_rev {Audio Processing Manager (APM) Module API}
    h2xml_title_date      {June 27, 2019}
 */
#define APM_MODULE_INSTANCE_ID                    0x00000001

/** h2xmlm_module       {"APM_MODULE_INSTANCE_ID",APM_MODULE_INSTANCE_ID}
    h2xmlm_displayName  {"Audio Processing Manager"}
    h2xmlm_description  {Audio Processing Manager (APM).\n

    This module supports the following parameter IDs: \n
      - #APM_PARAM_ID_SUB_GRAPH_CONFIG \n
      - #APM_PARAM_ID_CONTAINER_CONFIG \n
      - #APM_PARAM_ID_MODULES_LIST \n
      - #APM_PARAM_ID_MODULE_PROP \n
      - #APM_PARAM_ID_MODULE_CONN \n
      - #APM_PARAM_ID_MODULE_CTRL_LINK_CFG \n
      - #APM_PARAM_ID_IMCL_PEER_DOMAIN_INFO \n
      - #APM_PARAM_ID_PATH_DELAY \n
      - #APM_PARAM_ID_SUB_GRAPH_LIST \n

}
    h2xmlm_dataMaxInputPorts    {0}
    h2xmlm_dataMaxOutputPorts   {0}
    h2xmlm_stackSize            {0}
    h2xmlm_ToolPolicy           {Calibration}
    @{                   <-- Start of the Module -->*/

/** @}                   <-- End of the Module --> */










/** @ingroup apm_cmd_graph_open
  Opens a list of one or more sub-graphs. Graph open command is
  issued against APM module instance iD. Graph open command 
  consists of following parameter ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_CFG
  - #APM_PARAM_ID_CONTAINER_CFG
  - #APM_PARAM_ID_MODULES_LIST
  - #APM_PARAM_ID_MODULE_PROP
  - #APM_PARAM_ID_MODULE_CONN
  - #APM_PARAM_ID_MODULE_CTRL_LINK_CFG
   
  In the overall graph open command payload, parameter ID 
  #APM_PARAM_ID_SUB_GRAPH_CFG and #APM_PARAM_ID_CONTAINER_CFG 
  should be populated first before any other parameter ID's. The 
  sub-graph and container ID's need to be configured first 
  before configuring the rest of the parameter ID's. 
   
  Parameter ID #APM_PARAM_ID_MODULES_LIST must be configured 
  after configuring the #APM_PARAM_ID_SUB_GRAPH_CFG and 
  #APM_PARAM_ID_CONTAINER_CFG. 
   
  Parameter ID #APM_PARAM_ID_MODULE_PROP,  
  #APM_PARAM_ID_MODULE_CONN and #APM_PARAM_ID_MODULE_CTRL_LINK_CFG,
  must be configured after configuring the
  #APM_PARAM_ID_MODULES_LIST. 
   
  Overall payload for this command is of variable length. 
  Payload length depends upon the number of sub-graphs, 
  container, modules being configured as part of this command. 

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_OPEN 
   
  Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_cfg_t (Contains number of sub-graphs)
      (List of structures below is repeated for each sub-graph ID
       being configured)
      apm_sub_graph_cfg_t 
      apm_prop_data_t
      apm_sg_prop_id_perf_mode_t
      apm_prop_data_t
      apm_sg_prop_id_direction_t
      apm_prop_data_t
      apm_sg_prop_id_scenario_id_t
   <8 byte alignment if any>
   
    apm_module_param_data_t
    apm_param_id_container_cfg_t (Contains number of containers)
      (List of structures below is repeated for each container ID
       being configured)
      apm_container_cfg_t
      apm_prop_data_t
      apm_cont_prop_id_type_t
      apm_container_type_t
      apm_prop_data_t
      apm_cont_prop_id_graph_pos_t
      apm_prop_data_t
      apm_cont_prop_id_stack_size_t
      apm_prop_data_t
      apm_cont_prop_id_proc_domain_t
      apm_prop_data_t
      apm_cont_prop_id_parent_container_t
   <8 byte alignment if any>

   apm_module_param_data_t   
   apm_param_id_modules_list_t (Contains number of module lists)
      (List of structures below is repeated for each module list per
       sub-graph / container ID pair being configured
       being configured)
      apm_modules_list_t (Number of modules in the list)
      (Structure below is repeated for each module instance
      being configured)
      apm_module_cfg_t
   <8 byte alignment if any>

   apm_module_param_data_t
   apm_param_id_module_prop_t (Contains number of module property object)
      (List of structures below is repeated for each module
       property configuration object)
      apm_module_prop_cfg_t (Contains number of properties per module instance)
      (Structure below is repeated for each module instance
      property being configured)
      apm_prop_data_t
      apm_module_prop_id_port_info_t

   <8 byte alignment if any>
   apm_module_param_data_t
   apm_param_id_module_conn_t (Contains number of data connections)
      (Structure below is repeated for each data link being configured)
      apm_module_conn_cfg_t

   <8 byte alignment if any>
   apm_module_param_data_t
   apm_param_id_module_ctrl_link_cfg_t (Contains number of control links)
   (Structure below is repeated for each control link being configured)
      apm_module_ctrl_link_cfg_t (Contains number of control link intents)
      (List of structure below is repeated for each control link properties)
      apm_prop_data_t
      apm_module_ctrl_link_prop_id_intent_list_t

   (any non-APM module calibration payloads follow below)
   <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID payload <>
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
  None.
 */
#define APM_CMD_GRAPH_OPEN                        0x01001000

/** @ingroup apm_cmd_graph_prepare
  Prepares one or more sub-graph ID's that have been configured 
  Graph prepare command is issued against APM module instance 
  iD. Graph prepare command consists of following parameter 
  ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST 
   
  This command may be issued after the following commands: 
  - #APM_CMD_GRAPH_OPEN  
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_PREPARE 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's)

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GRAPH_PREPARE                     0x01001001

/** @ingroup apm_cmd_graph_start
  Starts one or more sub-graph ID's that have been configured 
  using the #APM_CMD_GRAPH_OPEN. 
  Graph start command is issued against APM module instance 
  iD. Graph start command consists of following parameter 
  ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST 
   
  This command may be issued after the following commands: 
  - #APM_CMD_GRAPH_OPEN 
  - #APM_CMD_GRAPH_PREPARE
  - #APM_CMD_GRAPH_STOP  
  - #APM_CMD_GRAPH_SUSPEND
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_START 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's) 

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GRAPH_START                       0x01001002

/** @ingroup apm_cmd_graph_stop
  Stops one or more sub-graph ID's that have been configured 
  using the #APM_CMD_GRAPH_OPEN. 
  Graph stop command is issued against APM module instance iD. 
  Graph start command consists of following parameter ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST 
   
  This command may be issued after the following commands: 
  - #APM_CMD_GRAPH_START  
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_STOP 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's)  

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GRAPH_STOP                        0x01001003

/** @ingroup apm_cmd_graph_close
  Closes one or more sub-graph ID's, data and control links that
  have been configured using the #APM_CMD_GRAPH_OPEN command.
  Graph close command is issued against APM module instance iD.
  Graph close command consists of following parameter ID's.
  Any combination of below parameter ID's can be sent as part of
  the close command.
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST
  - #APM_PARAM_ID_MODULE_CONN 
  - #APM_PARAM_ID_MODULE_CTRL_LINK_CFG  
   
  This command may be issued after the following commands: 
  - #APM_CMD_GRAPH_OPEN 
  - #APM_CMD_GRAPH_PREPARE
  - #APM_CMD_GRAPH_START 
  - #APM_CMD_GRAPH_STOP  
  - #APM_CMD_GRAPH_FLUSH  
  - #APM_CMD_GRAPH_SUSPEND 
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph. 

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_CLOSE 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's)
   <8 byte alignment if any>
   
  apm_module_param_data_t
   apm_param_id_module_conn_t (Contains number of data connections)
      (Structure below is repeated for each data link being configured)
      apm_module_conn_cfg_t
   <8 byte alignment if any>

  apm_module_param_data_t
  apm_param_id_module_ctrl_link_cfg_t (Contains number of control links)
   (Structure below is repeated for each control link being configured)
      apm_module_ctrl_link_cfg_t (Contains number of control link intents)
      (List of structure below is repeated for each control link properties)
      apm_prop_data_t
      apm_module_ctrl_link_prop_id_intent_list_t  
   <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GRAPH_CLOSE                       0x01001004

/** @ingroup apm_cmd_close_all
 * This command is used by the client for cleaning up all the
 * allocated resources within the framework including
 * - Closing all the opened sub-graphs, containers and modules.
 * Sub-graphs will be closed regardless of state.
 * - For multi DSP framework, this includes
 * sub-graphs/containers/modules on all the satellites
 * processors.
 * - All the mapped memories for master and satellite processor
 * at the time of receiving this command are unmapped.
 * - Modules registered and loaded via AMDB API's are unloaded
 * and de-registered.
 * One or more resources listed above at the time of receiving this
 * command will be de-allocated. Client need not send the list of
 * all those resources explicitly.

  @gpr_hdr_fields
  Opcode -- APM_CMD_CLOSE_ALL

  @Payload struct
  None

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

 */
#define APM_CMD_CLOSE_ALL                       0x01001013

/** @ingroup apm_cmd_graph_flush
  Flushes one or more sub-graph ID's that have been configured 
  Graph flush command is issued against APM module instance 
  iD. Graph flush command consists of following parameter 
  ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST 
   
  This command can be issued for the sub-graphs which have been 
  started at least once and are in pause state. Pause state is 
  configured using #APM_CMD_SET_CFG on a specific module within 
  a sub-graph. 
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_FLUSH 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's)

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GRAPH_FLUSH                       0x01001005

/** @ingroup apm_cmd_set_cfg
  Configures one or more parameter ID's for one more module 
  instances present in the graph. Module instances may include 
  APM module instance or any other data and control processing 
  module present within the graph. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the 
  #APM_CMD_GRAPH_OPEN 
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_SET_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of structures below is repeated for each module
    instance parameter ID )
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID payload <>
    <8 byte alignment if any>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_SET_CFG                           0x01001006

/** @ingroup apm_cmd_get_cfg
  This parameter is used for querying one or more
  configuration/calibration parameter ID corresponding to any 
  module instance ID. Module instances may any control 
  processing module present within the graph. This command is 
  currently not supported for APM module instance parameter 
  ID's. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the #APM_CMD_GRAPH_OPEN 
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_GET_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_data_t
    <>Param ID empty payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID empty payload <>
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Response code -- #APM_CMD_RSP_GET_CFG

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_GET_CFG                           0x01001007

/** @ingroup apm_cmd_rsp_get_cfg
  The response code returned as an acknowledgment for the
  #APM_CMD_GET_CFG command. 
   
  The response payload starts with status field which indicates 
  the overall status of the #APM_CMD_GET_CFG command. 
   
  Immediately following the status field is variable length 
  payload consisting the parameter data for the module ID's 
  which are queried as part of the #APM_CMD_GET_CFG command. 
  Each PID data uses the header structure 
  #apm_module_param_data_t followed by the actual param ID data. 
   
  Client is responsible for specifying sufficiently large 
  payload size to accommodate configuration/calibration data
  corresponding to each parameter ID data being queried. 
   
  Status field is populated with success code (#AR_EOK) if all
  the parameter ID's being queried returns success code. 
   
  Status field is populated with failure code (#AR_EFAILED) if 
  at least one param ID results failure error code.
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_RSP_GET_CFG 
   
  @Payload struct 
   
  apm_cmd_rsp_get_cfg_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_data_t
    <>Param ID  payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID  payload <> 
    <8 byte alignment if any, but not mandatory at the end>

  @return
  None

  @dependencies
   None
   
 */
#define APM_CMD_RSP_GET_CFG                       0x02001000

#include "spf_begin_pack.h"

struct apm_cmd_rsp_get_cfg_t
{
   uint32_t    status;
}
#include "spf_end_pack.h"
;

typedef struct apm_cmd_rsp_get_cfg_t apm_cmd_rsp_get_cfg_t;


/** @ingroup apm_cmd_register_cfg
  This command is used for registering persistent 
  calibration/configuration data corresponding to one or more 
  parameter ID's for one ore more data/control processing
  modules. This command is applicable for the module instances 
  supporting persistent calibration/configuration data. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the #APM_CMD_GRAPH_OPEN 
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_REGISTER_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID payload <> 
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_REGISTER_CFG                      0x01001008

/** @ingroup apm_cmd_deregister_cfg
  This command is used for de-registering persistent 
  calibration/configuration data corresponding to one or more 
  parameter ID's for one or more data/control processing
  modules. This command is applicable for the module instances 
  supporting persistent calibration/configuration data. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the #APM_CMD_GRAPH_OPEN 
   
  This command may be issued after the following commands: 
  - #APM_CMD_REGISTER_CFG   
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_DEREGISTER_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_data_t
    <>Param ID payload<>
    <8 byte alignment if any>
    apm_module_param_data_t
    <>Param ID payload <>  
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   The de-register command must be sent for the parameter ID's
   after issuing successful register command.
   
 */
#define APM_CMD_DEREGISTER_CFG                    0x01001009

/** @ingroup apm_cmd_register_shared_cfg
  This command is used for registering shared persistent 
  calibration/configuration data corresponding to one  
  parameter ID's for any data/control processing modules. This
  command is applicable for the module instances supporting 
  shared persistent calibration/configuration data. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the #APM_CMD_GRAPH_OPEN
  payload struct -- apm_cmd_header_t, which in turn has
  apm_module_param_shared_data_t as out of band payload
   
  @gpr_hdr_fields
  Opcode -- APM_CMD_REGISTER_SHARED_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_shared_data_t
    <>Param ID payload<>
    <8 byte alignment if any>
    apm_module_param_shared_data_t
    <>Param ID payload<>
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   
 */
#define APM_CMD_REGISTER_SHARED_CFG               0x0100100A

/** @ingroup apm_cmd_deregister_shared_cfg
  This command is used for registering shared persistent 
  calibration/configuration data corresponding to one  
  parameter ID's for any data/control processing modules. This
  command is applicable for the module instances supporting 
  shared persistent calibration/configuration data. 
   
  This command can be issued for all the module instance ID that 
  have been configured at least once using the #APM_CMD_GRAPH_OPEN 
 
  payload struct -- apm_cmd_header_t, which in turn has
  apm_module_param_shared_data_t as out of band payload
    
  This command may be issued after the following commands: 
  - #APM_CMD_REGISTER_SHARED_CFG  
     

  @gpr_hdr_fields
  Opcode -- APM_CMD_DEREGISTER_SHARED_CFG 
   
  @Payload struct 
   
  apm_cmd_header_t 
    (List of strucures below is repeated for each module
    instance parameter ID )
    apm_module_param_shared_data_t
    <>Param ID payload<>   
    <8 byte alignment if any>
    apm_module_param_shared_data_t
    <>Param ID payload<>
    <8 byte alignment if any, but not mandatory at the end>

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.
   The de-register command must be sent for the parameter ID's
   only after issuing successful register command.
   
 */
#define APM_CMD_DEREGISTER_SHARED_CFG             0x0100100B

/** @ingroup APM_CMD_REGISTER_MODULE_EVENTS
  Registers/de-registers one or more event ID's for one or more
  module instances present in the graph. This command can be only sent
  to modules present in an opened graph. This command
  cannot be sent to APM_MODULE_INSTANCE_ID.

  This command can be issued for all the module instance ID that
  have been configured at least once using the
  #APM_CMD_GRAPH_OPEN

  @Payload struct 
     apm_cmd_header_t
     apm_module_register_events_t
     <event config payload if any>
     <8 byte alignment if any>
     apm_module_register_events_t
     <event config payload if any>
     <8 byte alignment if any, but not mandatory at the end>

  When there are multiple events different
  apm_module_register_events_t must be 8 byte aligned.

  @gpr_hdr_fields
  Opcode -- APM_CMD_REGISTER_MODULE_EVENTS

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Module ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command or else and
   error code is returned by APM.

 */
#define APM_CMD_REGISTER_MODULE_EVENTS            0x0100100E


/** @ingroup apm_cmd_get_spf_status_t
  This parameter is used for querying SPF status. If the
  command can reach the APM, means that SPF is ready.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GET_SPF_STATE

  @return
  Response code -- #APM_CMD_RSP_GET_SPF_STATE

  @dependencies
   None

 */
#define APM_CMD_GET_SPF_STATE                   0x01001021


/** Definition for the spf Not-Ready State */
#define APM_SPF_STATE_NOT_READY                 0

/** Definition for the spf Ready State */
#define APM_SPF_STATE_READY                     1


/** @ingroup apm_cmd_rsp_get_spf_status_t
  The response code returned as an acknowledgment for the
  #APM_CMD_GET_SPF_STATE command.

  The response payload starts with status field which indicates
  the overall status of the #APM_CMD_GET_SPF_STATE command.

  @gpr_hdr_fields
  Opcode -- APM_CMD_RSP_GET_SPF_STATE

  @return
  None

  @dependencies
   None

 */
#define APM_CMD_RSP_GET_SPF_STATE                0x02001007

#include "spf_begin_pack.h"

struct apm_cmd_rsp_get_spf_status_t
{
   uint32_t    status;
   /**< spf status.

        @values
        - #APM_SPF_STATE_NOT_READY
        - #APM_SPF_STATE_READY
        @tablebulletend */
}

#include "spf_end_pack.h"
;

typedef struct apm_cmd_rsp_get_spf_status_t apm_cmd_rsp_get_spf_status_t;


/** @ingroup APM_EVENT_MODULE_TO_CLIENT
  Event raised by module to client, if the event is registered
  by the client

  This event can be raised by all module instances that
  have been configured at least once using the
  #APM_CMD_GRAPH_OPEN

  Payload struct -- apm_module_event_t

  @gpr_hdr_fields
  Opcode -- APM_EVENT_MODULE_TO_CLIENT

  @return
  Error code -- #GPR_BASIC_RSP_RESULT
 */
#define APM_EVENT_MODULE_TO_CLIENT                0x03001000

/**
 * Parameter ID for getting path delay from APM
 *
 * The graphs corresponding to the modules mentioned in the
 * payload of this command must be opened using #APM_CMD_GRAPH_OPEN
 *
 * This param is used with APM_CMD_GET_CFG.
 * Usually APM_CMD_GET_CFG doesn't carry any parameter specific payload, however,
 * this command contains payload to specify the path.
 *
 * For the delay to be accurate calibration should already be done for the path.
 * Media format must have been propagated. Typically, all subgraphs must be in PREPARE state.
 *
 * Maximum possible delay from source to destination is returned.
 * In some cases, delay may not be exactly same as returned. For example, in FTRT paths, or
 * processing time is smaller than expected. Also, delay can be obtained only for PCM or packetized data paths.
 * If raw compressed data is involved, then delay cannot be known correctly for the portion that's compressed.
 * Query however, won't fail as delay of the rest of the path (if any) can be determined.
 *
 * Under split-merge scenarios, if there are multiple paths from source to destination,
 * first path will be chosen arbitrarily.
 *
 * If path is not complete, error is returned.
 * Delay is >= 0.
 *
 * Client can leave the port-ids zeros to be autofilled by spf.
 * When port-ids are zero src and dst module's delay may or may not be included as explained below
 *
 *  -  If src has only outputs and max input ports = 0, then it's delay is included.
 *       Since src has no input ports, this is the only way to account for its delay.
 *  -  If dst has only input ports and max output ports = 0, then it's delay is included.
 *       Since dst has no output ports, this is the only way to account for its delay.
 *  -  For all other cases, delay is from the output port of src to output port of dst.
 *       This way of defining helps in concatenation. E.g.,  A -> B -> C can be obtained as A to B + B to C
 *       and delay of B is not considered twice.
 *       When dst has multiple outputs, an output will be selected arbitrarily.
 *
 * Payload struct -- apm_module_event_t
 *
 */
#define APM_PARAM_ID_PATH_DELAY                 0x08001119

#include "spf_begin_pack.h"
/**
 * This struct defines the start and end of path for which delay is queried.
 *
 */
struct apm_path_defn_for_delay_t
{
   uint32_t    src_module_instance_id;
      /**< Source module instance ID
       * input parameter. */
   uint32_t    src_port_id;
      /**< Source port-ID. Set to zero if port-id is not known.
       * Knowing port-id helps reduce the complexity of graph search.
       * Also, if specific path delays are needed in split-merge scenarios, port-id helps
       * (E.g. module A's port 1 & 2 ends up in port 1 & 2 of end point B. Since there are 2 paths from A to B
       * having port-id helps).
       *
       *
       * If port-id is zero at the time of query, it will be populated with proper port-id when APM responds.
       * This is an input & output parameter. */
   uint32_t    dst_module_instance_id;
      /**< Destination module instance ID.
       * This is an input parameter. */
   uint32_t    dst_port_id;
      /**< Destination port-ID. Set to zero if port-id is not known.
       * If port-id is zero at the time of query, it will be populated with proper port-id when APM responds.
       * This is an input & output parameter. */
   uint32_t    delay_us;
      /**< Microsecond delay
       * This is an output parameter.*/
}
#include "spf_end_pack.h"
;


typedef struct apm_path_defn_for_delay_t apm_path_defn_for_delay_t;

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"

/**
 * defines the main payload for the APM_PARAM_ID_PATH_DELAY query
 */
struct apm_param_id_path_delay_t
{
   uint32_t                   num_paths;
   /** number of paths to be queried */

   apm_path_defn_for_delay_t  paths[0];
   /** definition of each path */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct apm_param_id_path_delay_t apm_param_id_path_delay_t;

/* @ingroup apm_cmd_graph_suspend
  Suspends one or more sub-graph ID's that have been configured 
  Graph suspend command is issued against APM module instance 
  iD. Graph suspend command consists of following parameter 
  ID's. 
   
  - #APM_PARAM_ID_SUB_GRAPH_LIST 
   
  This command can be issued for the sub-graphs which have been 
  started at least once.
   
  If this command is issued to more than 1 sub-graph ID's, the 
  command is executed in a sequential manner for each sub-graph.

  @gpr_hdr_fields
  Opcode -- APM_CMD_GRAPH_SUSPEND 
   
  @Payload struct 
   
  apm_cmd_header_t
    apm_module_param_data_t
    apm_param_id_sub_graph_list_t (Contains number of sub-graph
    ID)
    apm_sub_graph_id_t (array of sub-graph ID's)

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   Sub-graph ID's listed as part of this command must be
   configured using the #APM_CMD_GRAPH_OPEN command and
   started using the #APM_CMD_GRAPH_START.
   For the sub-graphs in STOPPED or PREPARED state suspend
   command is not applied.
   
 */
#define APM_CMD_GRAPH_SUSPEND                       0x01001043

/** @ingroup apm_param_id_satellite_pd_info_t
  This parameter is used for setting
  satellite proc domain info to the master APM.

  This param is used with APM_CMD_SET_CFG.

  @return
  Error code -- #GPR_BASIC_RSP_RESULT

  @dependencies
   None

*/
#define APM_PARAM_ID_SATELLITE_PD_INFO                 0x08001251

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct apm_param_id_satellite_pd_info_t
{
   uint32_t num_proc_domain_ids;
   /**< Number of satellite proc domain ids */


   uint32_t proc_domain_id_list[0];
   /**< List of atellite proc domain IDs.
        @values { "DONT_CARE"=0xFFFFFFFF,
                  "MDSP"=#APM_PROC_DOMAIN_ID_MDSP,
                  "ADSP"=#APM_PROC_DOMAIN_ID_ADSP,
                  "SDSP"=#APM_PROC_DOMAIN_ID_SDSP,
                  "CDSP"=#APM_PROC_DOMAIN_ID_CDSP}
         Number of elements = num_proc_domain_ids */

}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct apm_param_id_satellite_pd_info_t apm_param_id_satellite_pd_info_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/


#endif /* _APM_API_H_ */
