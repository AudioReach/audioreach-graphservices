#ifndef _APM_CONTAINER_API_H_
#define _APM_CONTAINER_API_H_
/**
 * \file apm_container_api.h
 * \brief 
 *  	This file contains APM container commands and events structures definitions.
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "apm_graph_properties.h"

#ifdef __cplusplus
extern "C"
{
#endif /*__cplusplus*/

/*====================================================================================================================*/
/*====================================================================================================================*/

#define APM_PARAM_ID_CONTAINER_CONFIG             0x08001000
/** h2xmlp_parameter   {"Container Configuration", APM_PARAM_ID_CONTAINER_CONFIG}
    h2xmlp_description {ID of the parameter to configure the container properties.\n }
    h2xmlp_toolPolicy  {RTC; Calibration}*/


/* Immediately following this structure is a variable length array of structure objects corresponding to each container
   configuration and properties. Length of the array is determined by number of containers being configured */ 
#include "spf_begin_pack.h"
struct apm_param_id_container_cfg_t
{
   uint32_t num_container;
   /**< h2xmle_description   {Number of containers being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_container_cfg_t apm_param_id_container_cfg_t;

/* Immediately following this structure is a variable length array of container property structure. Length of the array
   is determined by number of properties being configured */
#include "spf_begin_pack.h"
struct apm_container_cfg_t
{
   uint32_t container_id;
   /**< h2xmle_description   {Valid ID of the container}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t num_prop;
   /**< h2xmle_description   {Number of properties for this sub-graph}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_container_cfg_t apm_container_cfg_t;



#include "spf_begin_pack.h"
struct apm_container_type_t
{
   uint32_t type;
   /**< @h2xmle_rangeEnum {containerCap} 
        @h2xmle_default {APM_PROP_ID_INVALID}
        @h2xmle_description {Container type} */
}
#include "spf_end_pack.h"
;
typedef struct apm_container_type_t apm_container_type_t;

/** h2xmlgp_configType {"CONT_CFG"}
    @h2xmlgp_config {"CONT_CFG", "APM_PARAM_ID_CONTAINER_CONFIG", APM_PARAM_ID_CONTAINER_CONFIG}
    @h2xmlgp_description {ID of the parameter to configure the container properties}
    @{ <-- Start of container_cfg --> */
/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_CONTAINER_PROP_ID_CONTAINER_TYPE     0x08001011
/** @h2xmlp_property {"Container Type", APM_CONTAINER_PROP_ID_CONTAINER_TYPE}
    @h2xmlp_description {Container type} */

/**
    @h2xmlp_insertSubStruct{apm_container_type_t}
*/

/* Immediately following this structure is the container type struct (only once). */
#include "spf_begin_pack.h"
struct apm_cont_prop_id_type_t
{
   uint32_t version;
   /**< @h2xmle_range {1..0xFFFFFFFF}
        @h2xmle_default {1}
		version can never be incremented to 2 because it will change below var length array.
        @h2xmle_description {Version number} */

   apm_container_type_t type_id;
   /**< @h2xmle_range {0..0xFFFFFFFF}
        @h2xmle_default {APM_PROP_ID_INVALID}
        @h2xmle_description {Container type}
		This is not meant to be a variable size array, but due to backward compatibility 
		with previous struct, which based based on container capability ID, we had to do this.
		@h2xmle_variableArraySize {version}*/
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_type_t apm_cont_prop_id_type_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_CONTAINER_PROP_ID_GRAPH_POS           0x08001012
/** @h2xmlp_property {"Graph Position", APM_CONTAINER_PROP_ID_GRAPH_POS}
    @h2xmlp_description {Container property ID for Graph Position} */
/**< Enumeration for container graph position Stream */
#define APM_CONT_GRAPH_POS_STREAM                 0x1

/**< Enumeration for container graph position Per Stream Per Device*/
#define APM_CONT_GRAPH_POS_PER_STR_PER_DEV        0x2

/**< Enumeration for container graph position Stream-Device */
#define APM_CONT_GRAPH_POS_STR_DEV                0x3

/**< Enumeration for container graph position Global Device */
#define APM_CONT_GRAPH_POS_GLOBAL_DEV             0x4

#include "spf_begin_pack.h"
struct apm_cont_prop_id_graph_pos_t
{
   uint32_t graph_pos;
   /**< @h2xmle_rangeList {"DONT_CARE"=0xFFFFFFFF,
                           "STREAM"=APM_CONT_GRAPH_POS_STREAM,
                           "PSPD"=APM_CONT_GRAPH_POS_PER_STR_PER_DEV,
                           "STR_DEV"=APM_CONT_GRAPH_POS_STR_DEV,
                           "GLOBAL DEV"=APM_CONT_GRAPH_POS_GLOBAL_DEV}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {Container position in the graph.} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_graph_pos_t apm_cont_prop_id_graph_pos_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_CONTAINER_PROP_ID_STACK_SIZE          0x08001013
/** @h2xmlp_property {"Stack Size", APM_CONTAINER_PROP_ID_STACK_SIZE}
    @h2xmlp_description {Container property ID for Stack Size } */

#include "spf_begin_pack.h"
struct apm_cont_prop_id_stack_size_t
{
   uint32_t stack_size;
   /**< @h2xmle_range {0..0xFFFFFFFF}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {Stack size for this container.} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_stack_size_t apm_cont_prop_id_stack_size_t;


/*--------------------------------------------------------------------------------------------------------------------*/
/**< Enumeration for container property ID Processor Domain */
#define APM_CONTAINER_PROP_ID_PROC_DOMAIN         0x08001014
/** @h2xmlp_property {"Proc Domain", APM_CONTAINER_PROP_ID_PROC_DOMAIN}
    @h2xmlp_description {Container property ID for Processor Domain } */

#include "spf_begin_pack.h"
struct apm_cont_prop_id_proc_domain_t
{
   uint32_t proc_domain;
   /**< @h2xmle_rangeList {"DONT_CARE"=0xFFFFFFFF,
                           "MDSP"=APM_PROC_DOMAIN_ID_MDSP,
                           "ADSP"=APM_PROC_DOMAIN_ID_ADSP,
                           "SDSP"=APM_PROC_DOMAIN_ID_SDSP,
                           "CDSP"=APM_PROC_DOMAIN_ID_CDSP}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {Container processor domain.} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_proc_domain_t apm_cont_prop_id_proc_domain_t;
/*--------------------------------------------------------------------------------------------------------------------*/
/**< Enumeration for parent container property ID  */
#define APM_CONTAINER_PROP_ID_PARENT_CONTAINER_ID    0x080010CB
/** @h2xmlp_property {"Parent Container ID", APM_CONTAINER_PROP_ID_PARENT_CONTAINER_ID}
    @h2xmlp_description {Container property ID for parent container property ID} */

#include "spf_begin_pack.h"
struct apm_cont_prop_id_parent_container_t
{
   uint32_t parent_container_id;
   /**< @h2xmle_range {0..0xFFFFFFFF}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {ID of the Offload Container in Master DSP to which
                             the containers in the Satellite DSP are associated.} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_parent_container_t apm_cont_prop_id_parent_container_t;

/*--------------------------------------------------------------------------------------------------------------------*/
/**< Enumeration for container property Heap ID  */
#define APM_CONTAINER_PROP_ID_HEAP_ID                  0x08001174
/** @h2xmlp_property {"Container Heap", APM_CONTAINER_PROP_ID_HEAP_ID}
    @h2xmlp_description {Container property ID for the Heap ID} */
/**< Enumeration for container Default Heap ID */
#define APM_CONT_HEAP_DEFAULT                     0x1

/**< Enumeration for container Low Power Island (LPI) Heap ID */
#define APM_CONT_HEAP_LOW_POWER                   0x2

#include "spf_begin_pack.h"
struct apm_cont_prop_id_heap_id_t
{
   uint32_t heap_id;
   /**< @h2xmle_rangeList {"Default"=APM_CONT_HEAP_DEFAULT,
                           "Low Power"=APM_CONT_HEAP_LOW_POWER}
        @h2xmle_default {APM_CONT_HEAP_DEFAULT}
        @h2xmle_description {Informs the container about the heap it needs to use.
                             The container re-maps this id to the actual heap id} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_heap_id_t apm_cont_prop_id_heap_id_t;

/**< Enumeration for container property Peer-Heap ID  */
#define APM_CONTAINER_PROP_ID_PEER_HEAP_ID             0x0800124D

#include "spf_begin_pack.h"
struct apm_cont_prop_id_peer_heap_id_t
{
   uint32_t heap_id;
   /**< @h2xmle_rangeList {"Default"=APM_CONT_HEAP_DEFAULT,
                           "Low Power"=APM_CONT_HEAP_LOW_POWER}
        @h2xmle_default {APM_CONT_HEAP_DEFAULT}
        @h2xmle_description {Informs the container about its peer container's heap id.} */
}
#include "spf_end_pack.h"
;
typedef struct apm_cont_prop_id_peer_heap_id_t apm_cont_prop_id_peer_heap_id_t;
/*--------------------------------------------------------------------------------------------------------------------*/
/** @} <-- End of container_cfg -->*/
/*====================================================================================================================*/
/*====================================================================================================================*/

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* _APM_CONTAINER_API_H_ */
