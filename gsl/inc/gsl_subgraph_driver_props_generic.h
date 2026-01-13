#ifndef GSL_SUBGRAPH_DRIVER_PROPS_GENERIC_H
#define GSL_SUBGRAPH_DRIVER_PROPS_GENERIC_H

/**
 * \file gsl_subgraph_driver_props.h
 *
 * \brief
 *      Represents GSL subgraph driver properties - generic

 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *	@h2xml_title_date {08/01/2018}
 */

#include "ar_osal_types.h"

#define SUB_GRAPH_PROP_ID_GENERIC 0x08000001
#define ROUTING_ID_MDSP 0x1
#define ROUTING_ID_ADSP 0x2
#define ROUTING_ID_APPS 0x3
#define ROUTING_ID_SDSP 0x4
#define ROUTING_ID_CDSP 0x5
#define FLUSHABLE_FALSE 0x0
#define FLUSHABLE_TRUE 0x1

typedef struct sg_generic_t sg_generic_t;

/**
 *	@h2xmlp_property {"SUB_GRAPH_PROP", SUB_GRAPH_PROP_ID_GENERIC}
 *	@h2xmlp_description {}
 */
struct sg_generic_t {
	uint32_t routing_id;
	/**<
	 *	@h2xmle_rangeList {"ROUTING_ID_MDSP"=1; "ROUTING_ID_ADSP"=2;
	 *		"ROUTING_ID_APPS"=3; "ROUTING_ID_SDSP"=4; "ROUTING_ID_CDSP"=5}
	 *	@h2xmle_default {2}
	 *	@h2xmle_description {}
	 */
	uint32_t is_flushable;
	/**<
	 * @h2xmle_rangeList {"FLUSHABLE_FALSE"=0; "FLUSHABLE_TRUE"=1}
	 * @h2xmle_default {1}
	 * @h2xmle_description {}
	 */
};

#endif
