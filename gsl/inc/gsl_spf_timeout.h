#ifndef GSL_SPF_TIMEOUTS_H
#define GSL_SPF_TIMEOUTS_H
/**
 * \file gsl_spf_timeouts.h
 *
 * \brief
 *       Represents GSL SPF timeouts
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */


 /**
  * @h2xml_title_date {09/25/2025}
  */
 #include "ar_osal_types.h"

#define GSL_SPF_TIMEOUTS 0x2006

 /**
  * @h2xmlm_module  {"GSL_SPF_TIMEOUTS", GSL_SPF_TIMEOUTS}
  * @h2xmlm_displayName  {"GSL_SPF_TIMEOUTS"}
  * @h2xmlm_description  {Timeout configuration groups associated with the Graph \n}
  *
  * -  This module supports the following parameter IDs: \n
  * - #SPF_TIMEOUTS_INFO \n
  *
  * @{                   <-- Start of the Module -->
  */
#define PARAM_ID_SPF_TIMEOUTS 0x0001

/** @h2xmle_description {Timeout configuration groups}
 * @h2xmlp_subStruct
 */

extern uint32_t GSL_SPF_TIMEOUT_MS;
extern uint32_t GSL_GRAPH_OPEN_TIMEOUT_MS;
extern uint32_t GSL_GRAPH_PREPARE_TIMEOUT_MS;
extern uint32_t GSL_GRAPH_START_STOP_TIMEOUT_MS;
extern uint32_t GSL_SPF_READ_WRITE_TIMEOUT_MS;
extern uint32_t GSL_AMDB_LOAD_MODULES_TIMEOUT_MS;

#if !defined(__GSL_GPR_STUB__) && (defined(_WIN32) || defined(_WIN64)) \
	&& !defined(_KERNEL_MODE) && defined(ARSPF_WIN_PORTING)
	/** WIN32/64 - SPF PORTING Timeout can be less than COSIM mode */
#define GSL_SPF_TIMEOUT_MS_DEFAULT ((3)*(1000))
#define GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT ((3)*(1000))
#define GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT  (0)
#define GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT (0)
#define GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT ((3)*(1000))
#define GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT ((3)*(1000))
#elif !defined(__GSL_GPR_STUB__) && (defined(_WIN32) || defined(_WIN64)) \
	&& !defined(_KERNEL_MODE)
/** WIN32/64 COSIM Mode requires longer delays(30 min) */
#define GSL_SPF_TIMEOUT_MS_DEFAULT ((1800)*(1000))
#define GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT ((1800)*(1000))
#define GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT  (0)
#define GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT (0)
#define GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT ((3600)*(1000))
#define GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT ((1800)*(1000))
#elif defined(__GSL_GPR_STUB__)
/**
 * unit-testing with GPR stub we increase the timeout due to APM sim globally
 * serializeng all SPF commands which causes more delays in multi-session tests
 */
#define GSL_SPF_TIMEOUT_MS_DEFAULT  (2000)
#define GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT  (2000)
#define GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT  (2000)
#define GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT  (5500)
#define GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT  (60000LL) /* 1 min */
#define GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT (2000)
#else
#define GSL_SPF_TIMEOUT_MS_DEFAULT  (1000)
#define GSL_GRAPH_OPEN_TIMEOUT_MS_DEFAULT  (4000)
#define GSL_GRAPH_PREPARE_TIMEOUT_MS_DEFAULT  (2000)
#define GSL_GRAPH_START_STOP_TIMEOUT_MS_DEFAULT  (5500)
#define GSL_SPF_READ_WRITE_TIMEOUT_MS_DEFAULT  (1000)
#define GSL_AMDB_LOAD_MODULES_TIMEOUT_MS_DEFAULT (5000)
#endif

/**
 * @h2xmlp_parameter   {"PARAM_ID_SPF_TIMEOUTS",
 *   PARAM_ID_SPF_TIMEOUTS}
 * @h2xmlp_description {Contains timeouts used for setting max wait
 * 	 times for responses or operations between GSL and SPF}
 */
struct spf_timeouts_value {
	/** @h2xmle_description {Max wait time for SPF response, excluding the graph open command}
	 * @h2xmle_default      {0x3e8}
	 */
	uint32_t spf_timeout;
	/** @h2xmle_description {Max wait time for SPF response to the graph open command}
	 * @h2xmle_default      {0xfa0}
	 */
	uint32_t graph_open_timeout;
    /** @h2xmle_description {Max wait time for SPF response to the graph prepare command}
	 * @h2xmle_default      {0x7d0}
	 */
	uint32_t graph_prepare_timeout;
    /** @h2xmle_description {Max wait time for start/stop operation completion}
	 * @h2xmle_default      {0x157c}
	 */
	uint32_t graph_start_stop_timeout;
    /** @h2xmle_description {Max wait time for read/write operation completion}
	 * @h2xmle_default      {0x3e8}
	 */
	uint32_t spf_read_write_timeout;
	/** @h2xmle_description {Max wait time for AMDB load modules operation completion}
	 * @h2xmle_default      {0x1388}
	 */
	uint32_t amdb_load_modules_timeout;
};

/**
 * @}
 */

/*
 * \brief get spf timeouts from acdb
 *
 */
int32_t gsl_spf_timeouts_get_timeouts_from_acdb(void);

/*
 * \brief initialize SPF timeouts, internally queries ACDB to get supported info
 *
 */
int32_t gsl_spf_timeouts_init(void);

#endif
