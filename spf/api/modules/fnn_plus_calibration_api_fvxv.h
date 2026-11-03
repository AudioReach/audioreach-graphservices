/*=======================================================================
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
All rights reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=========================================================================*/

#ifndef __FNN_PLUS_CALIBRATION_API_FVXV__
#define __FNN_PLUS_CALIBRATION_API_FVXV__

#include "module_cmn_api.h"

#define PARAM_ID_FNN_PLUS_DOA_ESTIMATE_MONITOR_WITH_TIMESTAMP 0x08001B97

typedef struct fnn_plus_doa_estimate_monitor_param_with_ts_t fnn_plus_doa_estimate_monitor_param_with_ts_t;
/** @h2xmlp_parameter    {"PARAM_ID_FNN_PLUS_DOA_ESTIMATE_MONITOR_WITH_TIMESTAMP",
   PARAM_ID_FNN_PLUS_DOA_ESTIMATE_MONITOR_WITH_TIMESTAMP}
    @h2xmlp_description  {DOA Estimate Monitor with timestamp parameters}
    @h2xmle_readOnly     {true}
    @h2xmlp_toolPolicy   {RTM}
*/
#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct fnn_plus_doa_estimate_monitor_param_with_ts_t
{
   int16_t speech_probability_q15;

   uint16_t reserved;

   int16_t current_talker_doa[2];

   uint16_t polar_activity_axis0_length;

   uint16_t polar_activity_axis1_length;

   int16_t polar_activity_axis0[0];

   int16_t angle_mapping_axis0[0];

   int16_t polar_activity_axis1[0];

   int16_t angle_mapping_axis1[0];

   uint32_t session_time_lsw;

   uint32_t session_time_msw;
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

#endif /* __FNN_PLUS_CALIBRATION_API_FVXV__ */
