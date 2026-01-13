#ifndef _APM_SUB_GRAPH_API_H_
#define _APM_SUB_GRAPH_API_H_
/**
 * \file apm_sub_graph_api.h
 * \brief 
 *     This file contains APM sub-graph related commands and events data structures definitions
 *  
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
#define APM_PARAM_ID_SUB_GRAPH_CONFIG             0x08001001
/** h2xmlp_parameter   {"Sub Graph Config", APM_PARAM_ID_SUB_GRAPH_CONFIG}
    h2xmlp_description {  ID of the parameter to configure the sub-graph properties.\n
                           This parameter ID must be used under command APM_CMD_GRAPH_OPEN \n }
    h2xmlp_toolPolicy  {RTC; Calibration} */

/* Immediately following this structure is a variable length array of structure objects corresponding to each sub-graph
   configuration and properties. Length of the array is determined by number of sub-graphs being configured  */
#include "spf_begin_pack.h"
struct apm_param_id_sub_graph_cfg_t
{
   uint32_t num_sub_graphs;
   /**< h2xmle_description   {Number of sub-graphs being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_sub_graph_cfg_t apm_param_id_sub_graph_cfg_t;


/* Immediately following this structure is a variable length array of sub-graph property structure.
   Length of the array is determined by number of properties being configured */
#include "spf_begin_pack.h"
struct apm_sub_graph_cfg_t
{
   uint32_t sub_graph_id;
   /**< h2xmle_description   {Valid ID of the sub-graph}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */

   uint32_t num_sub_graph_prop;
   /**< h2xmle_description   {Number of properties for this sub-graph }
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sub_graph_cfg_t apm_sub_graph_cfg_t;

/** @h2xmlgp_config {"SG_CFG", "APM_PARAM_ID_SUB_GRAPH_CONFIG", APM_PARAM_ID_SUB_GRAPH_CONFIG}
    @h2xmlgp_description {Properties supported by APM_PARAM_ID_SUB_GRAPH_CONFIG}
    @{ <-- Start of subgraph_cfg --> */
/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_SUB_GRAPH_PROP_ID_PERF_MODE           0x0800100E
/** @h2xmlp_property {"Performance Mode", APM_SUB_GRAPH_PROP_ID_PERF_MODE}
    @h2xmlp_description {Sub-graph property ID Performance Mode} */
/**< Enumeration for low power performance mode of subgraph */
#define APM_SG_PERF_MODE_LOW_POWER                0x1

/**< Enumeration for low latency performance mode of subgraph */
#define APM_SG_PERF_MODE_LOW_LATENCY              0x2

#include "spf_begin_pack.h"
struct apm_sg_prop_id_perf_mode_t
{
   uint32_t perf_mode;
   /**< @h2xmle_rangeList {"Low Power"=APM_SG_PERF_MODE_LOW_POWER,
                           "Low Latency"=APM_SG_PERF_MODE_LOW_LATENCY}
         @h2xmle_default {APM_SG_PERF_MODE_LOW_POWER}
         @h2xmle_description {Performance Mode} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sg_prop_id_perf_mode_t apm_sg_prop_id_perf_mode_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_SUB_GRAPH_PROP_ID_DIRECTION           0x0800100F
/** @h2xmlp_property {"SG Direction", APM_SUB_GRAPH_PROP_ID_DIRECTION}
    @h2xmlp_description {Sub-graph property ID Direction} */
/**< Enumeration for sub-graph direction Tx */
#define APM_SUB_GRAPH_DIRECTION_TX                0x1

/**< Enumeration for sub-graph direction Rx */
#define APM_SUB_GRAPH_DIRECTION_RX                0x2

#include "spf_begin_pack.h"
struct apm_sg_prop_id_direction_t
{
   uint32_t direction;
   /**< @h2xmle_rangeList {"DONT_CARE"=0xFFFFFFFF,
                           "TX"=APM_SUB_GRAPH_DIRECTION_TX,
                           "RX"=APM_SUB_GRAPH_DIRECTION_RX}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {Data flow direction for this sub-graph} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sg_prop_id_direction_t apm_sg_prop_id_direction_t;

/*--------------------------------------------------------------------------------------------------------------------*/
#define APM_SUB_GRAPH_PROP_ID_SCENARIO_ID         0x08001010
/** @h2xmlp_property {"Scenario ID", APM_SUB_GRAPH_PROP_ID_SCENARIO_ID}
    @h2xmlp_description {Sub-graph property ID Scenario ID} */

/**< Enumeration for Scenario ID Audio Playback */
#define APM_SUB_GRAPH_SID_AUDIO_PLAYBACK          0x1

/**< Enumeration for Scenario ID Audio Record */
#define APM_SUB_GRAPH_SID_AUDIO_RECORD            0x2

/**< Enumeration for Scenario ID Voice call. */
#define APM_SUB_GRAPH_SID_VOICE_CALL              0x3

#include "spf_begin_pack.h"
struct apm_sg_prop_id_scenario_id_t
{
   uint32_t scenario_id;
   /**< @h2xmle_rangeList {"DONT_CARE"=0xFFFFFFFF,
                           "Audio Playback"=APM_SUB_GRAPH_SID_AUDIO_PLAYBACK,
                           "Audio Record"=APM_SUB_GRAPH_SID_AUDIO_RECORD,
                           "Voice Call"=APM_SUB_GRAPH_SID_VOICE_CALL}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {Scenario ID for this sub-grpah} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sg_prop_id_scenario_id_t apm_sg_prop_id_scenario_id_t;

/*--------------------------------------------------------------------------------------------------------------------*/

#define APM_SUB_GRAPH_PROP_ID_VSID                0x080010CC
/** @h2xmlp_property {"PROP_ID_VSID", APM_SUB_GRAPH_PROP_ID_VSID}
 *  @h2xmlp_description {Sub-graph property ID VSID}
 *  @h2xmlp_isVoice (true) */

/**< Enumeration for VSID Voice call with Subscription 1 and VSID 0x11C05000 */
#define APM_SUB_GRAPH_VSID_SUB1                   AR_NON_GUID(0x11C05000)

/**< Enumeration for VSID Voice call with Subscription 2 and VSID 0x11DC5000 */
#define APM_SUB_GRAPH_VSID_SUB2                   AR_NON_GUID(0x11DC5000)

/** Apps only mode with vocoder loopback on SUB1 */
#define APM_SUB_GRAPH_VSID_VOC_LB_SUB1            AR_NON_GUID(0x12006000)

/** Apps only mode with vocoder loopback on SUB2 */
#define APM_SUB_GRAPH_VSID_VOC_LB_SUB2            AR_NON_GUID(0x121C6000)

/**< Dont care value for VSID, which shall be enumerated by HLOS client at a later time. */
#define APM_SUB_GRAPH_VSID_DONT_CARE              AR_NON_GUID(0xFFFFFFFF)

#include "spf_begin_pack.h"
struct apm_sg_prop_id_vsid_t
{
   uint32_t vsid;
   /**< @h2xmle_rangeList {"VSID_DONT_CARE"=0xFFFFFFFF,
                           "VSID_SUB1"=0x11C05000;
                           "VSID_SUB2"=0x11DC5000}
        @h2xmle_default {0xFFFFFFFF}
        @h2xmle_description {VSID for this sub-grpah} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sg_prop_id_vsid_t apm_sg_prop_id_vsid_t;

/*--------------------------------------------------------------------------------------------------------------------*/
/** @} <-- End of subgraph_cfg -->*/

/*====================================================================================================================*/
/*====================================================================================================================*/
#define APM_PARAM_ID_SUB_GRAPH_LIST             0x08001005
/** h2xmlp_parameter   {"Sub Graph List", APM_PARAM_ID_SUB_GRAPH_LIST}
    h2xmlp_description {IID of the parameter to configure the sub-graph list. \n
                        This parameter ID must be used under command APM_CMD_GRAPH_OPEN \n }
    h2xmlp_toolPolicy  {RTC; Calibration} */

/** 
   Immediately following this structure is a variable length array of structure objects corresponding to each sub-graph
   configuration and properties. Length of the array is determined by number of sub-graphs being configured
*/
#include "spf_begin_pack.h"
struct apm_param_id_sub_graph_list_t
{
   uint32_t num_sub_graphs;
   /**< h2xmle_description   {Number of sub-graphs being configured}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_param_id_sub_graph_list_t apm_param_id_sub_graph_list_t;


#include "spf_begin_pack.h"
struct apm_sub_graph_id_t
{
   uint32_t sub_graph_id;
   /**< h2xmle_description   {Sub-graph ID}
        h2xmle_range         {0..0xFFFFFFFF}
        h2xmle_default       {0} */
}
#include "spf_end_pack.h"
;
typedef struct apm_sub_graph_id_t apm_sub_graph_id_t;

/*====================================================================================================================*/
/*====================================================================================================================*/

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* _APM_SUB_GRAPH_API_H_ */
