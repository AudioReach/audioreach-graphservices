#ifndef GSL_SUBGRAPH_DRIVER_PROPS_H
#define GSL_SUBGRAPH_DRIVER_PROPS_H

/**
 * \file gsl_subgraph_driver_props.h
 *
 * \brief
 *      Represents GSL subgraph driver properties
 *

 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *	@h2xml_title_date {08/01/2018}
 */

#include "ar_osal_types.h"

#define SUB_GRAPH_PROP_ID_SG_TYPE 0x08000010
#define SUB_GRAPH_TYPE_STREAM 0x1
#define SUB_GRAPH_TYPE_DEVICE 0x2
#define SUB_GRAPH_TYPE_STREAM_DEVICE 0x3
#define SUB_GRAPH_TYPE_STREAM_PP 0x4
#define SUB_GRAPH_TYPE_DEVCICE_PP 0x5

typedef struct sg_type_t sg_type_t;

/**
 * @h2xmlp_property {"SUB_GRAPH_TYPE", SUB_GRAPH_PROP_ID_SG_TYPE}
 * @h2xmlp_description {}
 */
struct sg_type_t {
	uint32_t sg_type;
	/**<
	 * @h2xmle_rangeList {"SUB_GRAPH_TYPE_STREAM"=1;
	 *                   "SUB_GRAPH_TYPE_DEVCICE"=2;
	 *                   "SUB_GRAPH_TYPE_STREAM_DEVICE"=3;
	 *                   "SUB_GRAPH_TYPE_STREAM_PP"=4;
	 *                   "SUB_GRAPH_TYPE_DEVCICE_PP"=5}
	 * @h2xmle_default {1}
	 * @h2xmle_description {}
	 */
};

#endif
