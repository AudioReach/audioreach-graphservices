#ifndef _APM_MODULE_API_H_
#define _APM_MODULE_API_H_
/**
 * \file apm_module_api.h
 * \brief 
 *  	This file contains APM module related commands and events structures definitions
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_PARAM_ID_MODULES_LIST                 0x08001002
/** h2xmlp_parameter   {"APM_PARAM_ID_MODULES_LIST", APM_PARAM_ID_MODULES_LIST}
    h2xmlp_description { ID of the parameter to configure the modules list for a given \n
                         combination of sub-graph and container ID's. \n }
    h2xmlp_toolPolicy  {RTC; Calibration}*/

/* Immediately following this structure is a variable length array apm_modules_list_t */
#include "spf_begin_pack.h"
struct apm_param_id_modules_list_t
{
   uint32_t num_modules_list;
   /**< h2xmle_description   {Number of sub-graphs being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_modules_list_t apm_param_id_modules_list_t;


/* Immediately following this structure is a variable length array  apm_modules_list_t */

#include "spf_begin_pack.h"
struct apm_modules_list_t
{
   uint32_t sub_graph_id;
   /**< h2xmle_description   {Sub-graph ID being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t container_id;
   /**< h2xmle_description   {Container ID being configured }
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t num_modules;
   /**< h2xmle_description   {Number of modules being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_modules_list_t apm_modules_list_t;


#include "spf_begin_pack.h"
struct apm_module_cfg_t
{
   uint32_t module_id;
   /**< h2xmle_description   {Valid ID of the module}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t instance_id;
   /**< h2xmle_description   {Instance ID for this module}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_module_cfg_t  apm_module_cfg_t;


/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_PARAM_ID_MODULE_PROP                  0x08001003
/** h2xmlp_parameter   {"APM_PARAM_ID_SUB_GRAPH_CONFIG", APM_PARAM_ID_SUB_GRAPH_CONFIG}
    h2xmlp_description {ID of the parameter to configure the module properties. }
    h2xmlp_toolPolicy  {RTC; Calibration} */

#include "spf_begin_pack.h"
struct apm_param_id_module_prop_t
{
   uint32_t num_module_prop_cfg;
   /**< h2xmle_description   {Number of module property configuration objects}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_module_prop_t apm_param_id_module_prop_t;

/* Immediately following this structure is a variable length
   array of structure objects corresponding to each module
   properties. Length of the array is determined by number of
   module properties being configured. */

#include "spf_begin_pack.h"
struct apm_module_prop_cfg_t
{
   uint32_t instance_id;
   /**< h2xmle_description   {Valid ID of the module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t num_props;
   /**< h2xmle_description   {Number of properties for the module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;

typedef struct apm_module_prop_cfg_t apm_module_prop_cfg_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_MODULE_PROP_ID_PORT_INFO              0x08001015
/** h2xmlp_parameter   {"APM_MODULE_PROP_ID_PORT_INFO", APM_MODULE_PROP_ID_PORT_INFO}
    h2xmlp_description {Enumeration for module property ID Port Info. }
    h2xmlp_toolPolicy  {RTC; Calibration} */

#include "spf_begin_pack.h"
struct apm_module_prop_id_port_info_t
{
   uint32_t max_ip_port;
   /**< h2xmle_description   {Max number of input ports.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t max_op_port;
   /**< h2xmle_description   {Max number of output ports.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_module_prop_id_port_info_t apm_module_prop_id_port_info_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_PARAM_ID_MODULE_CONN                  0x08001004
/** h2xmlp_parameter   {"APM_PARAM_ID_MODULE_CONN", APM_PARAM_ID_MODULE_CONN}
    h2xmlp_description { ID of the parameter to configure the connection between module ports.\n
                         This parameter ID must be used under command APM_CMD_GRAPH_OPEN. \n

                         Configure connection links between each of the input and \n
                         output ports of modules present in the sub-graph. \n
                         Connection between source and destination module ports is \n
                         1:1 i.e. the source module's output cannot be routed to \n
                         multiple input ports of 1 or more destination modules.  \n
                         Similarly, destination module's input port cannot accept \n
                         data from more than 1 output ports of one or more source \n
                         modules. Any such connection is treated as invalid \n
                         configuration and will be flagged as error to the client. \n }
    h2xmlp_toolPolicy  {RTC; Calibration} */

/* Immediately following this structure is a variable length array of connection objects.
   Length of the array is determined using the number of connections configuration parameter. */
#include "spf_begin_pack.h"
struct apm_param_id_module_conn_t
{
   uint32_t num_connections;
   /**< h2xmle_description   {Number of connections.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_module_conn_t  apm_param_id_module_conn_t;


#include "spf_begin_pack.h"
struct apm_module_conn_cfg_t
{
   uint32_t src_mod_inst_id;
   /**< h2xmle_description   {Source module instance ID.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t src_mod_op_port_id;
   /**< h2xmle_description   {Source module output port ID.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t dst_mod_inst_id;
   /**< h2xmle_description   {Destination module instance ID.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t dst_mod_ip_port_id;
   /**< h2xmle_description   {Destination module input port ID.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_module_conn_cfg_t  apm_module_conn_cfg_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_PARAM_ID_MODULE_CTRL_LINK_CFG         0x08001061
/** h2xmlp_parameter   {"APM_PARAM_ID_MODULE_CTRL_LINK_CFG", APM_PARAM_ID_MODULE_CTRL_LINK_CFG}
    h2xmlp_description {ID of the parameter to configure the list of control links across module control ports. }
    h2xmlp_toolPolicy  {RTC; Calibration} */

/* Immediately following this structure is a variable length array of structure objects corresponding to module control
   port link configuration. Length of the array is determined by number of control links being configured. */
#include "spf_begin_pack.h"
struct apm_param_id_module_ctrl_link_cfg_t
{
   uint32_t num_ctrl_link_cfg;
   /**< h2xmle_description   {Number of module control link configuration objects.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_module_ctrl_link_cfg_t apm_param_id_module_ctrl_link_cfg_t;


/* Immediately following this structure is a variable length array of structure objects corresponding to each module
   control link properties. Length of the array is determined by number of module properties being configured. */
#include "spf_begin_pack.h"
struct apm_module_ctrl_link_cfg_t
{
   uint32_t peer_1_mod_iid;
   /**< h2xmle_description   {Module instance ID for first peer module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t peer_1_mod_ctrl_port_id;
   /**< h2xmle_description   {Control port ID for the first peer module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t peer_2_mod_iid;
   /**< h2xmle_description   {Module instance ID for second peer module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t peer_2_mod_ctrl_port_id;
   /**< h2xmle_description   {Control port ID for the second peer module.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t num_props;
   /**< h2xmle_description   {Number of link properties.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_module_ctrl_link_cfg_t apm_module_ctrl_link_cfg_t;


/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_MODULE_PROP_ID_CTRL_LINK_INTENT_LIST              0x08001062
/** h2xmlp_parameter   {"APM_MODULE_PROP_ID_CTRL_LINK_INTENT_LIST", APM_MODULE_PROP_ID_CTRL_LINK_INTENT_LIST}
    h2xmlp_description {Enumeration for control link property ID Port Info. }
    h2xmlp_toolPolicy  {RTC; Calibration} */

/* Immediately following this structure is a variable length array of control link intent id list for each control link.
   Length of the array is determined by number of control link properties being configured. */
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct apm_module_ctrl_link_prop_id_intent_list_t
{
   uint32_t  num_intents;
   /**< h2xmle_description   {Number of intents associated with a control link.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t intent_id_list[0];
   /**< h2xmle_description   {Number of intents associated with a control link.}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct apm_module_ctrl_link_prop_id_intent_list_t apm_module_ctrl_link_prop_id_intent_list_t;

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* _APM_MODULE_API_H_ */
