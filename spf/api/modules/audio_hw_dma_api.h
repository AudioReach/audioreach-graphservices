#ifndef _AUDIO_HW_DMA_API_H_
#define _AUDIO_HW_DMA_API_H_
/**
 * \file audio_hw_dma_api.h
 * \brief 
 *  	 This file contains dma api
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_defs.h"

/**
   Param ID for dma
   This ID should only be used under PRM module instance
*/
#define PARAM_ID_RSC_DMA_READ_CHANNEL 0x080010CE
#define PARAM_ID_RSC_DMA_WRITE_CHANNEL 0x080010CF

#include "spf_begin_pack.h"
/** Struct for DMA channel memory request/release/request response by HLOS */
struct dma_rsc_t
{
   uint32_t dma_type;
   /**< DMA channel type
    @values #LPAIF_CORE_DMA */
   uint32_t num_dma_channels;
   /**< Number of DMA channels
    @values >= 0 */
}
#include "spf_end_pack.h"
;

typedef struct dma_rsc_t dma_rsc_t;
/* Immediately following this struct is a variable length payload that contains the DMA channel indices that were
   reserved.
   example:
< DMA resources payload >
  dma_cfg_rsc_t
     dma_type = LPAIF_CORE_DMA
     num_dma_channels
< variable data payload >
     num_dma_channels indices as 4 bytes each; contains the DMA index
     */

#endif /* _AUDIO_HW_DMA_API_H_ */
