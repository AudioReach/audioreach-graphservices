#ifndef _TEST_MODULE_API_H_
#define _TEST_MODULE_API_H_
/**
 *   \file test_module_api.h
 * \brief
 *  	 This file contains test module APIs. The test module is implemented
 *  	 to be used in CSIM tests for nonstandard capi behavior like threshold,
 *  	 partial processing, duration change, etc. For production this module will
 *    	 be stubbed
 *
 * \copyright
 *    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *    SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"
#include "module_cmn_api.h"
/*==============================================================================
   Defines
==============================================================================*/
/** Module IDs for testing custom stub modules in AMDB tests */
#define MODULE_ID_GAIN_CUSTOM          0x07001025
#define MODULE_ID_AAC_DEC_CUSTOM       0x07001026
#define MODULE_ID_AAC_ENC_CUSTOM       0x07001027

/*==============================================================================
   API definitions
==============================================================================*/
/* ID of the parameter used to configure as a threshold module */
#define PARAM_ID_TEST_THRESHOLD_CFG           0x0800100D

/** Configures whether to act as a threshold module. The threshold can be configured
                         to be hard or soft. A hard threshold means that the module will raise a port threshold
                         event, and will error out from the process() call if there is not enough data in the input
                         or space in the output to process the entire threshold. A soft threshold means that the module
                         will not raise a port threshold event. During process(), the module will process at MOST the
                         threshold amount of data. If less data than the threshold is provided, all data will be processed. */

#include "spf_begin_pack.h"
/* Payload for parameter param_id_test_threshold_cfg_t */
struct param_id_test_threshold_cfg_t
{
     uint32_t threshold_us;
  /**< Threshold duration. 0 means disabled.
       range        0..1000000
       default      0 */

     uint16_t is_input;
  /**< description Whether the threshold applies to the input port or output port.
      rangeList        "Output Port" = 0;
                       "Input Port"  = 1
      default      0 */

     uint16_t is_hard_thresh;
  /**< description Whether the threshold is a hard threshold or soft threshold.
       rangeList   "Hard Threshold" = 0;
                   "Soft Threshold" = 1
       default      0 */
}
#include "spf_end_pack.h"
;

typedef struct param_id_test_threshold_cfg_t param_id_test_threshold_cfg_t;

/* ID of the parameter used to configure busy-waiting during process. */
#define PARAM_ID_TEST_BUSY_WAIT_CFG           0x0800106D

/** Configures the threshold module to busy-wait at the end of process. The module will not busy wait
    if this is not configured. Even when busy waiting is enabled, the test module will still do all
    normal processing before busy waiting. Busy waiting is implemented as an assembly loop full of nops. */

#include "spf_begin_pack.h"
/* Payload for parameter param_id_busy_wait_cfg_t */
struct param_id_busy_wait_cfg_t
{
     uint32_t enable;
  /**< description  {Enable/disable busy waiting.}
       rangeList    {"Disable" = 0;
                             "Enable"  = 1}
       default      {0} */
     uint32_t busy_wait_cycles;
  /**< description  {How many cycles the module should busy wait.
                             TODO(claguna) Estimates of cycle-to-duration:
                             MSM8998: 1ms = X cycles, 5ms = X cycles, 10ms = X cycles}
       range        {0..0xFFFFFFFF}
       default      {0} */

     uint16_t period;
  /**< description {The module will only busy-wait every <period> process calls.}
       range        {0..65535}
       default      {0} */

     uint16_t duty_cycle;
  /**< description {How many consecutive process calls the module should busy-wait for.
                            If larger than the period, then the module will busy wait every
                            process cycle.}
      range        {0..65535}
      default      {0} */

}
#include "spf_end_pack.h"
;

typedef struct param_id_busy_wait_cfg_t param_id_busy_wait_cfg_t;

/* ID of the parameter used to configure algorithmic delay. Currently the actual delay is 0;
 * this only configures the reported delay. */
#define PARAM_ID_TEST_ALGO_DELAY_CFG           0x080010F7

/** Configures the threshold module to busy-wait at the end of process. The module will not busy wait
                         if this is not configured. Even when busy waiting is enabled, the test module will still do all
                         normal processing before busy waiting. Busy waiting is implemented as an assembly loop full of nops. */

#include "spf_begin_pack.h"
/* Payload for parameter param_id_algo_delay_cfg_t */
struct param_id_algo_delay_cfg_t
{
     uint32_t delay_in_us;
  /**< description  {Reported delay in microseconds.}
       range        {0..0xFFFFFFFF}
       default      {0} */

}
#include "spf_end_pack.h"
;

typedef struct param_id_algo_delay_cfg_t param_id_algo_delay_cfg_t;

/* ID of the parameter used to configure hw accelerator delay. */
#define PARAM_ID_TEST_HW_ACCL_PROC_DELAY           0x0800130F

#include "spf_begin_pack.h"
/* Payload for parameter PARAM_ID_TEST_HW_ACCL_PROC_DELAY */
struct param_id_hw_acc_proc_delay_cfg_t
{
     uint32_t delay_in_us;
  /**< description  {Reported delay in microseconds.}
       range        {0..0xFFFFFFFF}
       default      {0} */

}
#include "spf_end_pack.h"
;

typedef struct param_id_hw_acc_proc_delay_cfg_t param_id_hw_acc_proc_delay_cfg_t;


/* ID used to configure DTMF and send metadata for DTMF configuration */
#define PARAM_ID_TEST_DTMF_GEN_MD_CFG                   0x08001147
/** Sends configuration as DTMF Gen metadata. */


/* ID used to add TTR delay to TTR metadata attached to buffers */
#define PARAM_ID_TEST_SET_TTR_DELAY 0x0800101D
/** Creates ttr metadata with delay */

#include "spf_begin_pack.h"
struct param_id_set_ttr_delay_t
{
	uint32_t ttr_delay_in_us;
  /**< description  {delay in microseconds.}
       range        {0..0xFFFFFFFF}
       default      {0} */
}
#include "spf_end_pack.h"
;
typedef struct param_id_set_ttr_delay_t param_id_set_ttr_delay_t;
/* ID of the parameter used to configure timestamp offset. All timestamps are offset by this amount - this is
   used to simulate timestamp discontinuities. */
#define PARAM_ID_TEST_TIMESTAMP_OFFSET           0x080010F8

/** Configures the timestamp offset - all timestamps are adjust by algo delay + this amount. */

#include "spf_begin_pack.h"
/* Payload for parameter param_id_timestamp_offset_t */
struct param_id_timestamp_offset_t
{
     int32_t offset_us;
  /**< description  {Timestamp offset in microseconds.}
       range        {0..0xFFFFFFFF}
       default      {0} */

     int32_t delay_num_proc_calls;
  /** description  {Don't apply the offset until this many process calls have happened.}
       range        {0..0xFFFFFFFF}
       default      {0} */
}
#include "spf_end_pack.h"
;

typedef struct param_id_timestamp_offset_t param_id_timestamp_offset_t;

#define PARAM_ID_TEST_PERIODIC_MD_GEN_CFG 0x0800125C

typedef enum periodicity_mode_t
{
   FRAME_PERIODIC,
   /*MD gets generated every n frames (process calls)*/
}periodicity_mode_t;

typedef struct test_module_periodicity_t
{
   periodicity_mode_t mode;
   /**< description  {mode of periodicity - default - frame periodic}
       range        {0..0xFFFFFFFF}
       default      {0} */
   uint32_t           period;
   /**< description  {period}
       range        {0..0xFFFFFFFF}
       default      {10} */
}test_module_periodicity_t;


#include "spf_begin_pack.h"
/* Payload for parameter param_id_test_periodic_md_gen_cfg_t */
struct param_id_test_periodic_md_gen_cfg_t
{
     uint32_t gen_enable;
  /**< description  {enable generation}
       range        {0..0xFFFFFFFF}
       default      {0} */

     uint32_t md_id;
  /** description  {metadata_to_generate. relevant cfg needs to have been received - if reqd}
       range        {0..0xFFFFFFFF}
       default      {0} */

     test_module_periodicity_t periodicity;
     /** description  {by default, periodic md is generated once every 10 frames}
       range        {0..0xFFFFFFFF}
       default      {0} */
}
#include "spf_end_pack.h"
;

typedef struct param_id_test_periodic_md_gen_cfg_t param_id_test_periodic_md_gen_cfg_t;

#define PARAM_ID_TEST_MD_TRACKING_CFG                 0x080012EA

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
/* Payload for parameter param_id_test_md_tracking_cfg_t */
struct param_id_test_md_tracking_cfg_t
{
     uint32_t tracking_enable;
  /**< description  {enable tracking md}
       range        {0..0xFFFFFFFF}
       default      {0} */

     uint32_t md_id;
     /** description  {MD ID for which to enable tracking - module expects separate md cfg as necessary} */

     uint8_t  tracking_info[0];
     /** description  {tracking info. Module will parse the size of module_cmn_md_tracking_t}
       range        {0..0xFFFFFFFF}
       default      {0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

typedef struct param_id_test_md_tracking_cfg_t param_id_test_md_tracking_cfg_t;


/* ID of the parameter used to configure algorithmic delay. Currently the actual delay is 0;
 * this only configures the reported delay. */
#define PARAM_ID_TEST_FORCE_OUTPUT_SAMPLES_CFG           0x08001318

/** Configures the test module to force it to output a certain number of samples per channel for a single process call. */

#include "spf_begin_pack.h"
/* Payload for parameter param_id_test_force_output_samples_cfg_t */
struct param_id_test_force_output_samples_cfg_t
{
     uint32_t samples_per_channel;
  /**< description  {Samples per channel to output for a single process call. If larger than current frame,
                     size is cropped to actual frame size.}
       range        {0..0xFFFFFFFF}
       default      {0} */

}
#include "spf_end_pack.h"
;

typedef struct param_id_test_force_output_samples_cfg_t param_id_test_force_output_samples_cfg_t;

/** Module ID for test module  */
#define MODULE_ID_TEST_MODULE      0x07001021

#endif //_TEST_MODULE_API_H_
