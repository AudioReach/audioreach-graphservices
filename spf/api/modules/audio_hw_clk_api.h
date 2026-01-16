#ifndef _AUDIO_HW_CLK_API_H_
#define _AUDIO_HW_CLK_API_H_
/**
 * \file audio_hw_clk_api.h
 * \brief
 *  	 This file contains audio hw clock APIs
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

/**
   Param ID for audio hardware clocks
   This ID should only be used under PRM module instance
   Eg: Bit clocks for audio h/w interface like MI2S, PCM, TDM
   Mclks for audio codec (internal / external) operation
*/
#define PARAM_ID_RSC_AUDIO_HW_CLK 0x0800102C

/** Start of the range of MI2S clock IDs. */
#define CLOCK_ID_MI2S_RANGE_START 0x100

/** Clock ID of the primary MI2S internal bit clock (IBIT). */
#define CLOCK_ID_PRI_MI2S_IBIT 0x100

/** Clock ID of the primary MI2S external bit clock (EBIT). */
#define CLOCK_ID_PRI_MI2S_EBIT 0x101

/** Clock ID of the secondary MI2S IBIT. */
#define CLOCK_ID_SEC_MI2S_IBIT 0x102

/** Clock ID of the secondary MI2S EBIT. */
#define CLOCK_ID_SEC_MI2S_EBIT 0x103

/** Clock ID of the tertiary MI2S IBIT. */
#define CLOCK_ID_TER_MI2S_IBIT 0x104

/** Clock ID of the tertiary MI2S EBIT. */
#define CLOCK_ID_TER_MI2S_EBIT 0x105

/** Clock ID of the quaternary MI2S IBIT. */
#define CLOCK_ID_QUAD_MI2S_IBIT 0x106

/** Clock ID of the quaternary MI2S EBIT. */
#define CLOCK_ID_QUAD_MI2S_EBIT 0x107

/** Clock ID of the quinary MI2S IBIT. */
#define CLOCK_ID_QUI_MI2S_IBIT 0x108

/** Clock ID of the quinary MI2S EBIT. */
#define CLOCK_ID_QUI_MI2S_EBIT 0x109

/** Clock ID of the quinary MI2S OSR. */
#define CLOCK_ID_QUI_MI2S_OSR 0x10A

/** Clock ID of the senary MI2S IBIT. */
#define CLOCK_ID_SEN_MI2S_IBIT 0x10B

/** Clock ID of the senary MI2S EBIT. */
#define CLOCK_ID_SEN_MI2S_EBIT 0x10C

/** Clock ID of the septenary MI2S IBIT. */
#define CLOCK_ID_SEP_MI2S_IBIT 0x10D

/** Clock ID of the sepetnary MI2S EBIT. */
#define CLOCK_ID_SEP_MI2S_EBIT 0x10E

/** Clock ID of the High speed  I2S interface 0 IBIT. */
#define CLOCK_ID_HS_I2S_IF0_IBIT 0x10F

/** Clock ID of the high speed I2S interface 0 EBIT. */
#define CLOCK_ID_HS_I2S_IF0_EBIT 0x110

/** Clock ID of the High speed  interface 1 IBIT. */
#define CLOCK_ID_HS_I2S_IF1_IBIT 0x111

/** Clock ID of the high speed interface 1 EBIT. */
#define CLOCK_ID_HS_I2S_IF1_EBIT 0x112

/** Clock ID of the High speed  interface 2 IBIT. */
#define CLOCK_ID_HS_I2S_IF2_IBIT 0x113

/** Clock ID of the high speed interface 2 EBIT. */
#define CLOCK_ID_HS_I2S_IF2_EBIT 0x114

/** Clock ID of the High speed  interface 3 IBIT. */
#define CLOCK_ID_HS_I2S_IF3_IBIT 0x115

/** Clock ID of the high speed interface 3 EBIT. */
#define CLOCK_ID_HS_I2S_IF3_EBIT 0x116

/** Clock ID of the High speed  interface 4 IBIT. */
#define CLOCK_ID_HS_I2S_IF4_IBIT 0x117

/** Clock ID of the high speed interface 4 EBIT. */
#define CLOCK_ID_HS_I2S_IF4_EBIT 0x118

/** End of the range of MI2S clock IDs. */
#define CLOCK_ID_MI2S_RANGE_END 0x118

/** Start of the range of PCM clock IDs. */
#define CLOCK_ID_PCM_RANGE_START 0x200

/** Clock ID of the primary PCM IBIT. */
#define CLOCK_ID_PRI_PCM_IBIT 0x200

/** Clock ID of the primary PCM EBIT. */
#define CLOCK_ID_PRI_PCM_EBIT 0x201

/** Clock ID of the secondary PCM IBIT. */
#define CLOCK_ID_SEC_PCM_IBIT 0x202

/** Clock ID of the secondary PCM EBIT. */
#define CLOCK_ID_SEC_PCM_EBIT 0x203

/** Clock ID of the tertiary PCM IBIT. */
#define CLOCK_ID_TER_PCM_IBIT 0x204

/** Clock ID of the tertiary PCM EBIT. */
#define CLOCK_ID_TER_PCM_EBIT 0x205

/** Clock ID of the quaternary PCM IBIT. */
#define CLOCK_ID_QUAD_PCM_IBIT 0x206

/** Clock ID of the quaternary PCM EBIT. */
#define CLOCK_ID_QUAD_PCM_EBIT 0x207

/** Clock ID of the quinary PCM IBIT. */
#define CLOCK_ID_QUI_PCM_IBIT 0x208

/** Clock ID of the quinary PCM EBIT. */
#define CLOCK_ID_QUI_PCM_EBIT 0x209

/** Clock ID of the quinary PCM OSR. */
#define CLOCK_ID_QUI_PCM_OSR 0x20A

/** Clock ID of the senary PCM IBIT. */
#define CLOCK_ID_SEN_PCM_IBIT 0x20B

/** Clock ID of the senary PCM EBIT. */
#define CLOCK_ID_SEN_PCM_EBIT 0x20C

/** Clock ID of the septenary PCM IBIT. */
#define CLOCK_ID_SEP_PCM_IBIT 0x20D

/** Clock ID of the septenary PCM EBIT. */
#define CLOCK_ID_SEP_PCM_EBIT 0x20E

/** Clock ID of the High speed  PCM interface 0 IBIT. */
#define CLOCK_ID_HS_PCM_IF0_IBIT 0x20F

/** Clock ID of the high speed PCM interface 0 EBIT. */
#define CLOCK_ID_HS_PCM_IF0_EBIT 0x210

/** Clock ID of the High speed  PCM interface 1 IBIT. */
#define CLOCK_ID_HS_PCM_IF1_IBIT 0x211

/** Clock ID of the high speed PCM interface 1 EBIT. */
#define CLOCK_ID_HS_PCM_IF1_EBIT 0x212

/** Clock ID of the High speed  PCM interface 2 IBIT. */
#define CLOCK_ID_HS_PCM_IF2_IBIT 0x213

/** Clock ID of the high speed PCM interface 2 EBIT. */
#define CLOCK_ID_HS_PCM_IF2_EBIT 0x214

/** Clock ID of the High speed  PCM interface 3 IBIT. */
#define CLOCK_ID_HS_PCM_IF3_IBIT 0x215

/** Clock ID of the high speed PCM interface 3 EBIT. */
#define CLOCK_ID_HS_PCM_IF3_EBIT 0x216

/** Clock ID of the High speed  PCM interface 4 IBIT. */
#define CLOCK_ID_HS_PCM_IF4_IBIT 0x217

/** Clock ID of the high speed PCM interface 4 EBIT. */
#define CLOCK_ID_HS_PCM_IF4_EBIT 0x218

/** End of of the range of PCM clock IDs. */
#define CLOCK_ID_PCM_RANGE_END 0x218

/** Start of the TDM clock ID group. */
#define CLOCK_ID_TDM_RANGE_START 0x200

/** Clock ID for the primary TDM IBIT. */
#define CLOCK_ID_PRI_TDM_IBIT 0x200

/** Clock ID for the primary TDM EBIT. */
#define CLOCK_ID_PRI_TDM_EBIT 0x201

/** Clock ID for the secondary TDM IBIT. */
#define CLOCK_ID_SEC_TDM_IBIT 0x202

/** Clock ID for the secondary TDM EBIT. */
#define CLOCK_ID_SEC_TDM_EBIT 0x203

/** Clock ID for the tertiary TDM IBIT. */
#define CLOCK_ID_TER_TDM_IBIT 0x204

/** Clock ID for the tertiary TDM EBIT. */
#define CLOCK_ID_TER_TDM_EBIT 0x205

/** Clock ID for the quaternary TDM IBIT. */
#define CLOCK_ID_QUAD_TDM_IBIT 0x206

/** Clock ID for the quaternary TDM EBIT. */
#define CLOCK_ID_QUAD_TDM_EBIT 0x207

/** Clock ID for the quinary TDM IBIT. */
#define CLOCK_ID_QUI_TDM_IBIT 0x208

/** Clock ID for the quinary TDM EBIT. */
#define CLOCK_ID_QUI_TDM_EBIT 0x209

/** Clock ID for the quinary TDM OSR. */
#define CLOCK_ID_QUI_TDM_OSR 0x20A

/** Clock ID for the senary TDM IBIT. */
#define CLOCK_ID_SEN_TDM_IBIT 0x20B

/** Clock ID for the senary TDM EBIT. */
#define CLOCK_ID_SEN_TDM_EBIT 0x20C

/** Clock ID of the septenary TDM IBIT. */
#define CLOCK_ID_SEP_TDM_IBIT 0x20D

/** Clock ID of the septenary TDM EBIT. */
#define CLOCK_ID_SEP_TDM_EBIT 0x20E

/** Clock ID of the High speed  TDM interface 0 IBIT. */
#define CLOCK_ID_HS_TDM_IF0_IBIT 0x20F

/** Clock ID of the high speed TDM interface 0 EBIT. */
#define CLOCK_ID_HS_TDM_IF0_EBIT 0x210

/** Clock ID of the High speed  TDM interface 1 IBIT. */
#define CLOCK_ID_HS_TDM_IF1_IBIT 0x211

/** Clock ID of the high speed TDM interface 1 EBIT. */
#define CLOCK_ID_HS_TDM_IF1_EBIT 0x212

/** Clock ID of the High speed  TDM interface 2 IBIT. */
#define CLOCK_ID_HS_TDM_IF2_IBIT 0x213

/** Clock ID of the high speed TDM interface 2 EBIT. */
#define CLOCK_ID_HS_TDM_IF2_EBIT 0x214

/** Clock ID of the High speed  TDM interface 3 IBIT. */
#define CLOCK_ID_HS_TDM_IF3_IBIT 0x215

/** Clock ID of the high speed TDM interface 3 EBIT. */
#define CLOCK_ID_HS_TDM_IF3_EBIT 0x216

/** Clock ID of the High speed  TDM interface 4 IBIT. */
#define CLOCK_ID_HS_TDM_IF4_IBIT 0x217

/** Clock ID of the high speed TDM interface 4 EBIT. */
#define CLOCK_ID_HS_TDM_IF4_EBIT 0x218

/** End of the TDM clock ID group. */
#define CLOCK_ID_TDM_RANGE_END 0x218

/** Start of the range of MCLK clock IDs. */
#define CLOCK_ID_MCLK_RANGE_START 0x300

/** Clock ID for MCLK 1. */
#define CLOCK_ID_MCLK_1 0x300

/** Clock ID for MCLK 2. */
#define CLOCK_ID_MCLK_2 0x301

/** Clock ID for MCLK 3. */
#define CLOCK_ID_MCLK_3 0x302

/** Clock ID for MCLK 4. */
#define CLOCK_ID_MCLK_4 0x303

/** Clock ID for MCLK 5. */
#define CLOCK_ID_MCLK_5 0x304

/** Clock ID for MCLK for WSA core */
#define CLOCK_ID_WSA_CORE_MCLK 0x305

/** Clock ID for NPL MCLK for WSA core */
#define CLOCK_ID_WSA_CORE_NPL_MCLK 0x306

/** Clock ID for 2X WSA MCLK (2X MCLK or NPL MCLK, both are same) */
#define CLOCK_ID_WSA_CORE_2X_MCLK CLOCK_ID_WSA_CORE_NPL_MCLK

/** Clock ID for MCLK for VA core */
#define CLOCK_ID_VA_CORE_MCLK 0x307

/** Clock ID for 2X VA MCLK (2X MCLK) */
#define CLOCK_ID_VA_CORE_2X_MCLK 0x308

/** Clock ID for MCLK for TX */
#define CLOCK_ID_TX_CORE_MCLK 0x30C

/** Clock ID for NPL MCLK for TX */
#define CLOCK_ID_TX_CORE_NPL_MCLK  0x30D

/** Clock ID for TX CORE 2X MCLK (2X MCLK or NPL MCLK, both are same) */
#define CLOCK_ID_TX_CORE_2X_MCLK CLOCK_ID_TX_CORE_NPL_MCLK

/** Clock ID for MCLK for RX */
#define CLOCK_ID_RX_CORE_MCLK 0x30E

/** Clock ID for NPL MCLK for RX */
#define CLOCK_ID_RX_CORE_NPL_MCLK  0x30F

/** Clock ID for RX CORE 2X MCLK (2X MCLK or NPL MCLK, both are same) */
#define CLOCK_ID_RX_CORE_2X_MCLK CLOCK_ID_RX_CORE_NPL_MCLK

/** Clock ID for MCLK for WSA2 core */
#define CLOCK_ID_WSA2_CORE_MCLK 0x310

/** Clock ID for NPL MCLK for WSA2 core */
#define CLOCK_ID_WSA2_CORE_2X_MCLK 0x311

/** Clock ID for RX Core TX MCLK */
#define CLOCK_ID_RX_CORE_TX_MCLK 0x312

/** Clock ID for RX CORE TX 2X MCLK */
#define CLOCK_ID_RX_CORE_TX_2X_MCLK 0x313

/** Clock ID for WSA core TX MCLK */
#define CLOCK_ID_WSA_CORE_TX_MCLK 0x314

/** Clock ID for WSA core TX 2X MCLK */
#define CLOCK_ID_WSA_CORE_TX_2X_MCLK 0x315

/** Clock ID for WSA2 core TX MCLK */
#define CLOCK_ID_WSA2_CORE_TX_MCLK 0x316

/** Clock ID for WSA2 core TX 2X MCLK */
#define CLOCK_ID_WSA2_CORE_TX_2X_MCLK 0x317

/** Clock ID for RX CORE MCLK2 2X  MCLK */
#define CLOCK_ID_RX_CORE_MCLK2_2X_MCLK 0x318

/** End of the range of MCLK clock IDs. */
#define CLOCK_ID_MCLK_RANGE_END 0x318

/** Start of the range of SPDIF clock IDs. */
#define CLOCK_ID_SPDIF_RANGE_START 0x400

/** Clock ID for the primary SPDIF output core. */
#define CLOCK_ID_PRI_SPDIF_OUTPUT_CORE 0x400

/** Clock ID for the secondary SPDIF output core. */
#define CLOCK_ID_SEC_SPDIF_OUTPUT_CORE 0x401

/** Clock ID for the primary SPDIF input core. */
#define CLOCK_ID_PRI_SPDIF_INPUT_CORE 0x402

/** Clock ID for the secondary SPDIF input core. */
#define CLOCK_ID_SEC_SPDIF_INPUT_CORE 0x403

/** Clock ID for the secondary SPDIF output NPL clk. */
#define CLOCK_ID_PRI_SPDIF_OUTPUT_NPL 0x404

/** Clock ID for the primary SPDIF output NPL clk. */
#define CLOCK_ID_SEC_SPDIF_OUTPUT_NPL 0x405

/** End of the range of SPDIF clock IDs. */
#define CLOCK_ID_SPDIF_RANGE_END 0x405

/** Max number of clock ids that can be requested/released at a command */
#define MAX_AUD_HW_CLK_NUM_REQ 5

/**
   Immediately following this structure is a variable length
   array of audio_hw_clk_cfg_t or clock ID structure. Length
   of array is determined by number of clock ID's being configured
*/

#include "spf_begin_pack.h"

struct audio_hw_clk_cfg_req_param_t
{
   uint32_t num_clock_id;
   /**< Number of clock ID's being configured */
}

#include "spf_end_pack.h"
;

typedef struct audio_hw_clk_cfg_req_param_t audio_hw_clk_cfg_req_param_t;

/** Clock attribute is invalid (reserved for internal use). */
#define CLOCK_ATTRIBUTE_INVALID 0x0

/** Clock attribute for no coupled clocks. */
#define CLOCK_ATTRIBUTE_COUPLE_NO 0x1

/** Clock attribute for the dividend of the coupled clocks. */
#define CLOCK_ATTRIBUTE_COUPLE_DIVIDEND 0x2

/** Clock attribute for the divisor of the coupled clocks. */
#define CLOCK_ATTRIBUTE_COUPLE_DIVISOR 0x3

/** Clock attribute for the invert-and-no-couple case. */
#define CLOCK_ATTRIBUTE_INVERT_COUPLE_NO 0x4

/* Default clock id used as dont care when requesting clock by client */
#define HW_INTF_CLK_ID_DEFAULT 0x0

/* Default clock frequency used as dont care when requesting clock by client */
#define HW_INTF_CLK_FREQ_DEFAULT 0x0

/* Default clock attribute used as dont care when requesting clock by client */
#define HW_INTF_CLK_ATTRI_DEFAULT 0x0

/** Default root clock source. */
#define CLOCK_ROOT_DEFAULT 0x0

#include "spf_begin_pack.h"

struct audio_hw_clk_cfg_t
{
   uint32_t clock_id;
   /**< Unique Clock ID of the clock being requested */

   uint32_t clock_freq;
   /**< Clock frequency in Hz to set. */

   uint32_t clock_attri;
   /**< Divider for two clocks that are coupled, if necessary:
        divider = A/B, where A is the dividend and B is the divisor.
        @values
        - #_CLOCK_ATTRIBUTE_COUPLE_NO -- For no divider-related clocks
        - #_CLOCK_ATTRIBUTE_COUPLE_DIVIDEND
        - #_CLOCK_ATTRIBUTE_COUPLE_DIVISOR
        - #_CLOCK_ATTRIBUTE_INVERT_COUPLE_NO */

   uint32_t clock_root;
   /**< Root clock source.
        @values #_CLOCK_ROOT_DEFAULT
        Currently, only _CLOCK_ROOT_DEFAULT is valid. */
}

#include "spf_end_pack.h"
;

typedef struct audio_hw_clk_cfg_t audio_hw_clk_cfg_t;

#include "spf_begin_pack.h"

struct audio_hw_clk_rel_cfg_t
{
   uint32_t clock_id;
   /**< Unique Clock ID of the clock being released */
}

#include "spf_end_pack.h"
;

typedef struct audio_hw_clk_rel_cfg_t audio_hw_clk_rel_cfg_t;

/**
   Immediately following this structure is a variable length
   array of audio_hw_clk_status_cfg_t structure. Length of the array
   is determined by number of clock ID's being configured which failed
*/

#include "spf_begin_pack.h"

struct audio_hw_clk_rsp_cfg_t
{
   uint32_t num_failures;
   /**< Number of failures while requesting for 1 or more clock ID's */
}

#include "spf_end_pack.h"
;

typedef struct audio_hw_clk_rsp_cfg_t audio_hw_clk_rsp_cfg_t;


#include "spf_begin_pack.h"

struct audio_hw_clk_status_cfg_t
{
   uint32_t clock_id;
   /**< Unique Clock ID of the clock which failed to be requested/released */

   uint32_t status;
   /**< Status representing why clock id request/release failed
    * @ Non-Zero - Failure
    * */
}

#include "spf_end_pack.h"
;

typedef struct audio_hw_clk_status_cfg_t audio_hw_clk_status_cfg_t;

/** Default clock source. */
#define CLOCK_ROOT_SRC_DEFAULT 0x0 

/** Xo Clock source. */
#define CLOCK_ROOT_SRC_XO 0x1

/** RCO Clock source. */
#define CLOCK_ROOT_SRC_RCO 0x2

/** maximum clock sources. */
#define CLOCK_ROOT_SRC_MAX CLOCK_ROOT_SRC_RCO + 1

#endif /* _AUDIO_HW_CLK_API_H_ */
