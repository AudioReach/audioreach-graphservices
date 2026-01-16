#ifndef FLUENCE_FFV_COMMON_CALIBRATION_H
#define FLUENCE_FFV_COMMON_CALIBRATION_H

/*==============================================================================
  @file fluence_ffv_common_calibration.h
  @brief This file contains audio rtm logging parameters.

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause

==============================================================================*/

#include "ar_defs.h"

/*==============================================================================
   Param ID
==============================================================================*/

#define PARAM_ID_FLUENCE_SEC_CMN_ECPP                    0x08001086

/*==============================================================================
   Param structure defintions
==============================================================================*/

/** @h2xmlp_parameter    {"PARAM_ID_FLUENCE_SEC_CMN_ECPP", PARAM_ID_FLUENCE_SEC_CMN_ECPP}
    @h2xmlp_description  { SEC Common Post Filtering configuration.}
    @h2xmlp_toolPolicy   { Calibration, RTC } */
#include "spf_begin_pack.h"
struct sec_cmn_ecpp_param_t
{
    int16_t ec_vad_thresh_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD threshold}
    @h2xmle_default     {0x4000}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x6666"}

    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_thresh2_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD threshold-II}
    @h2xmle_default     {0x4000}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x4000"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x6666"}

    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_pwr_scale_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD noise power scale factor}
    @h2xmle_default     {0x0100}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_hangover_max_l16;
    /**< @h2xmle_description {EC_CNI near-end VAD hangover duration}
    @h2xmle_default     {0x1E}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x1E"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x1E"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x1E"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x0F"}

    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_alpha_snr_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD probability estimation smoothing factor (higher value means more smoothing)}
    @h2xmle_default     {0x0CCE}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_avar_scale_l16q13;
    /**< @h2xmle_description {EC_CNI near-end VAD noise variance scaling factor}
    @h2xmle_default     {0x2000}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_sub_nc_l16;
    /**< @h2xmle_description {EC_CNI near-end VAD noise floor tracking window length}
    @h2xmle_default     {0x19}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_snr_diff_max_l16q8;
    /**< @h2xmle_description {EC_CNI near-end VAD SNR difference max threshold}
    @h2xmle_default     {0x0C00}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_snr_diff_min_l16q8;
    /**< @h2xmle_description {EC_CNI near-end VAD SNR difference min threshold}
    @h2xmle_default     {0x0A00}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_init_length_l16;
    /**< @h2xmle_description {EC_CNI near-end VAD initial frames length for power initialization}
    @h2xmle_default     {0x64}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_max_val_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD max bound on noise estimate}
    @h2xmle_default     {0x0288}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_init_bound_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD initial bound for noise estimation}
    @h2xmle_default     {0x64}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_reset_bound_l16q15;
    /**< @h2xmle_description {EC_CNI near-end VAD reset bound for noise estimation}
    @h2xmle_default     {0x0122}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t ec_vad_spow_min_l16q15;
    /**< @h2xmle_description {EC_CNI near-end minimum bound for VAD speech power estimate}
    @h2xmle_default     {0x019A}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_saec_pathchange_factor_l16q15;
    /**< @h2xmle_description {Path change factor for extra gain clipping in EC}
    @h2xmle_default     {0x7FFF}
    @h2xmle_range       {0x8000..0x7FFF}

    @h2xmle_group     {Echo_PCD}
    @h2xmle_subgroup  {PCD_Aggressiveness}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_num_spectral_bands_l16;
    /**< @h2xmle_description {Number of spectral bands for EC PF}
    @h2xmle_default     {0x20}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x20"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x20"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x20"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x14"}

    @h2xmle_range       {8..513}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_lin_log_freq_l16;
    /**< @h2xmle_description {Linear-log boundary frequency for Mel scale in EC PF processing}
    @h2xmle_default     {0x02BC}
    @h2xmle_range       {0x02BC..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_pc_add_agg_q_l16;
    /**< @h2xmle_description {Additional Q-factor for EC PF aggressiveness during path change}
    @h2xmle_default     {0x03}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x03"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x03"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x03"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x01"}

    @h2xmle_group     {Echo_PCD}
    @h2xmle_subgroup  {PCD_Aggressiveness}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_gain_floor_l16q15[32];
    /**< @h2xmle_description {Minimum EC PF gain for each band}
    @h2xmle_default     {0x02}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x62"}

   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {Aggressiveness}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_nlp_st_agg_l16q15;
    /**< @h2xmle_description {EC PF aggressiveness during single talk (far-end alone)}
    @h2xmle_default     {0x7D00}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x7D00"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x7D00"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x7D00"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x4800"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Aggressiveness}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_nlp_dt_agg_l16q15;
    /**< @h2xmle_description {EC PF aggressiveness during double talk}
    @h2xmle_default     {0x7530}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x7530"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x7530"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x7530"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x4800"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Aggressiveness}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_agg_q_l16;
    /**< @h2xmle_description {Q-factor for EC PF aggressiveness}
    @h2xmle_default     {0x06}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x06"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x06"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x06"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x02"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Aggressiveness}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_nlp_boost_l16q12;
    /**< @h2xmle_description {Slope Boost factor for the non-linear EC PF processing}
    @h2xmle_default     {0x1000}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Aggressiveness}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_rx_ec_factor_l16q13;
    /**< @h2xmle_description {Factor for applying Rx energy to estimated echo energy}
    @h2xmle_default     {0x2000}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x2000"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x2000"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x2000"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x1000"}

    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_energy_t_factor_l16q15[32];
    /**< @h2xmle_description {EC PF energy factor to apply for spectral band 1}
    @h2xmle_default     {0x0320}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x0320"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x0320"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x0320"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x0333"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Aggressiveness}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_salph_l16q15;
    /**< @h2xmle_description {Smoothing factor for the Mic energy input in EC PF  (Higher value means less smoothing)}
    @h2xmle_default     {0x7332}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x7332"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x7332"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x7332"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x7EB8"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Smoothing}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_salph_edown_l16q15;
    /**< @h2xmle_description {Smoothing factor for the echo energy input in EC PF  (Higher value means less smoothing)}
    @h2xmle_default     {0x2666}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x2666"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x2666"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x2666"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x6000"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Smoothing}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_galph_l16q15;
    /**< @h2xmle_description {Smoothing factor for the EC PF gain (Higher value means less smoothing)}
    @h2xmle_default     {0x7F1C}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x7F1C"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x7F1C"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x7F1C"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x6666"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Smoothing}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_lin_log_l16q13;
    /**< @h2xmle_description {Normalized transition frequency in EC PF}
    @h2xmle_default     {0x02BC}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x02BC"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x02BC"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x02BC"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x02CC"}

    @h2xmle_range       {0x02BC..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_mela_l16q8;
    /**< @h2xmle_description {Multiplication factor in EC PF}
    @h2xmle_default     {0x0A00}
    @h2xmle_range       {0x0280..0x1400}
    @h2xmle_policy      {Basic} */


    int16_t aec_pf_clip_saec_clip_factor2_l16q15;
    /**< @h2xmle_description {EC PF gain clip factor to be applied during initial duration after call start}
    @h2xmle_default     {0x0147}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x0147"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x0147"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x0147"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x0CCD"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Initial_Aggressiveness}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_clip_sinit_frames_l16;
    /**< @h2xmle_description {Initial duration for applying the EC PF gain clip factor}
    @h2xmle_default     {0xC8}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0xC8"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0xC8"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0xC8"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x64"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Initial_Aggressiveness}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_pf_clip_saec_clip_factor_l16q15;
    /**< @h2xmle_description {EC PF gain clip factor to be applied in normal cases}
    @h2xmle_default     {0x0CCD}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_group       {Post_Filtering}
    @h2xmle_subgroup    {EC_Clipper}
    @h2xmle_policy      {Basic} */

    int16_t aec_cn_norm_const_l16q15;
    /**< @h2xmle_description {EC_CNI scaling factor}
    @h2xmle_default     {0x6000}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x6000"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x6000"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x6000"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x4666"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {EC_CNI}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_cn_norm_const_q_l16;
    /**< @h2xmle_description {EC_CNI estimate Q factor}
    @h2xmle_default     {0x02}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x02"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x03"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {EC_CNI}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_cn_salph_l16q15;
    /**< @h2xmle_description {Smoothing factor for the EC_CNI noise estimate estimate (Higher value means less smoothing)}
    @h2xmle_default     {0x3333}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_cn_ms_frames_l16;
    /**< @h2xmle_description {EC_CNI noise floor estimation window length}
    @h2xmle_default     {0xC8}
    @h2xmle_range       {0x0001..0x03E8}
    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {EC_CNI}
    @h2xmle_policy      {Advanced} */

    int16_t aec_cn_ms_num_blk_l16;
    /**< @h2xmle_description {EC_CNI minimum statistics bulk size}
    @h2xmle_default     {0x0A}
    @h2xmle_range       {0x0001..0x03E8}
    @h2xmle_policy      {Basic} */

    int16_t aec_pf_rx_echo_shift;
    /**< @h2xmle_description {Rx energy echo shift factor for EC PP}
    @h2xmle_default     {0xFFF8}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0xFFFC"}

    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t abf_echo_shift;
    /**< @h2xmle_description {Q0 shift factor for scaling echo energy computed from Rx signal}
    @h2xmle_default     {0xFFF8}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0xFFFC"}

    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aeccfg_abf_echo_shift;
    /**< @h2xmle_description {Q0 shift factor for scaling echo energy computed from Rx signal}
    @h2xmle_default     {0xFFF8}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0xFFF8"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0xFFFC"}

    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aeccfg_farendvadpfcfg_shangovermax;
    /**< @h2xmle_description {EC Postprocesing far-end VAD hangover in number of frames}
    @h2xmle_default     {0x04}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x04"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x04"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x04"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x05"}

    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {Far_end_VAD}
    @h2xmle_range       {0x0000..0x7FFF}
    @h2xmle_policy      {Advanced} */

    int16_t aec_lb_clipflag_al_bitshift;
    /**< @h2xmle_description {Q0 shift factor for smoothing Mic1 clipper detection likelihood}
    @h2xmle_default     {0x01}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {EC_Clipper}
    @h2xmle_policy      {Advanced} */

    int16_t aec_hb_clipflag_al_bitshift;
    /**< @h2xmle_description {Q0 shift factor for smoothing Mic1 high band clipper detection threshold}
    @h2xmle_default     {0x01}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_group     {Post_Filtering}
    @h2xmle_subgroup  {EC_Clipper}
    @h2xmle_policy      {Advanced} */

    int16_t aec_clip_flag_lb_frac_l16q15;
    /**< @h2xmle_description {Threshold for the low band NLMS output error to mic ratio for applying extra clipping}
    @h2xmle_default     {0x2710}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x0444"}

    @h2xmle_group       {Post_Filtering}
    @h2xmle_subgroup    {EC_Clipper}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_clip_flag_hb_frac_l16q15;
    /**< @h2xmle_description {Threshold for the high band NLMS output error to mic ratio for applying extra clipping}
    @h2xmle_default     {0x2710}

    @h2xmle_defaultDependency  { Samplerate = "8000" ,  default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "16000" , default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "32000" , default = "0x2710"}
    @h2xmle_defaultDependency  { Samplerate = "48000" , default = "0x0444"}

    @h2xmle_group       {Post_Filtering}
    @h2xmle_subgroup    {EC_Clipper}
    @h2xmle_range       {0x8000..0x7FFF}
    @h2xmle_policy      {Basic} */

    int16_t aec_f_vad_shangover_max_pf_nb;           // fbCfg.aecCfg.farEndVadCfg.sHangoverMaxPF
   /**< @h2xmle_description {Far-end VAD for EC post-filtering hangover duration (frames) for low band}
   @h2xmle_default     {10}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {Far_end_VAD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_f_vad_shangover_max_pf_hb;           // fbCfg.aecCfg.farEndVadCfg.sHangoverMaxPF
   /**< @h2xmle_description {Far-end VAD for EC post-filtering hangover duration (frames)  for high band}
   @h2xmle_default     {10}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {Far_end_VAD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_fvad_nb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine far-end activity (0-4kHz)}
   @h2xmle_default     {5}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {Far_end_VAD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_fvad_hb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine far-end activity (>4kHz)}
   @h2xmle_default     {2}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {Far_end_VAD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_dtd_nb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine double-talk activity (0-4kHz)}
   @h2xmle_default     {5}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {DTD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_dtd_hb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine double-talk activity (>4kHz)}
   @h2xmle_default     {5}
   @h2xmle_group      {Post_Filtering}
   @h2xmle_subgroup   {DTD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_clip_nb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine clipping (0-4kHz)}
   @h2xmle_default     {20}
   @h2xmle_group       {Post_Filtering}
   @h2xmle_subgroup    {EC_Clipper}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_clip_hb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine clipping (>4kHz)}
   @h2xmle_default     {20}
   @h2xmle_group       {Post_Filtering}
   @h2xmle_subgroup    {EC_Clipper}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_pcd_nb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine path change activity (0-4kHz)}
   @h2xmle_default     {16}
   @h2xmle_group       {Echo_PCD}
   @h2xmle_subgroup    {PCD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */

   int16_t aec_glb_flag_pcd_hb_cnt;
   /**< @h2xmle_description {minimum number of active subbands to determine path change activity (>4kHz)}
   @h2xmle_default     {16}
   @h2xmle_group       {Echo_PCD}
   @h2xmle_subgroup    {PCD}
   @h2xmle_range       {0..0x7FFF}
   @h2xmle_policy      {Advanced} */
}
#include "spf_end_pack.h"
;
/* Type definition for the above structure. */
typedef struct sec_cmn_ecpp_param_t sec_cmn_ecpp_param_t;

/**
    Param ID to support dynamic enablement/disablement of Audio effects.
    This PID will be common for all audio effects and will be shared accross multiple module IDs.
    HLOS will use regular set/get param interface to set/get effects to/from DSP. This PID will not be visible in ARCT.
    Each module will generally use 0th bit to set effect. If a module supports more than one effect than subsequent LSB bits can be used.

    payload size -- 4 bytes
*/
#define PARAM_ID_FLUENCE_CMN_GLOBAL_EFFECT               0x080010BB

/* Structure for setting/Querying  Audio module effects. */

/** @h2xmlp_parameter   {"PARAM_ID_FLUENCE_CMN_GLOBAL_EFFECT", PARAM_ID_FLUENCE_CMN_GLOBAL_EFFECT}
    @h2xmlp_description {To dynamically enable/disable Audio effects.}
    @h2xmlp_toolPolicy  {Calibration}*/

#include "spf_begin_pack.h"
struct qcmn_global_effect_param_t
{
   int32_t ecns_effect_mode;
        /**< @h2xmle_description {ecns_effect_mode -1:NO EFFECT, 0:EC and NS disabled, 1:EC enabled, 2:NS enabled, 3: EC and NS enabled}
          @h2xmle_default     {0xFFFFFFFF}
          @h2xmle_range       {0xFFFFFFFF..0x00000003}
          @h2xmle_policy      {Advanced}*/
}
#include "spf_end_pack.h"
;
/* Type definition for the above structure.*/
typedef struct qcmn_global_effect_param_t qcmn_global_effect_param_t;

#endif
