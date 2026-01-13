#ifndef HW_INTF_CMN_API
#define HW_INTF_CMN_API
/**
 * \file hw_intf_cmn_api.h
 * \brief 
 *  	
 * 
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "module_cmn_api.h"
#include "audio_hw_clk_api.h"
#include "imcl_fwk_intent_api.h"
/*------------------------------------------------------------------------------
   Parameters
------------------------------------------------------------------------------*/
/*==============================================================================
  Constants
==============================================================================*/
/* Frame size in milliseconds (inclusive) */
#define FRAME_SIZE_FACTOR_1                                 1
#define FRAME_SIZE_MIN_MS                                   1
#define FRAME_SIZE_MAX_MS                                   40

typedef enum lpaif_type_t
{
  LPAIF             = 0,     // Default type
  LPAIF_RXTX        = 1,
  LPAIF_WSA         = 2,
  LPAIF_VA          = 3,
  LPAIF_AXI         = 4,
  LPAIF_AUD         = 5,
  LPAIF_SDR         = 6,
  LPAIF_WSA2        = 7,
  LPAIF_RXTX_SDCA   = 8,
  LPAIF_RXTX_WSA    = 9,
  LPAIF_QAIF_AUD    = 10,
  LPAIF_QAIF_VA     = 11,
  MAX_NUM_LPAIF_TYPES,
  LPAIF_BLK_INVALID = 0x7FFFFFFF
} lpaif_type_t;


typedef enum qaif_type_t
{
  QAIF_AUD      = 0,     // Default type
  QAIF_VA        = 1,
  MAX_NUM_QAIF_TYPES,
  QAIF_BLK_INVALID = 0x7FFFFFFF
}qaif_type_t;


/*==============================================================================
   Type definitions
==============================================================================*/

/** Parameter used to configure the Silence detection for the CODEC DMA Interface 
		To be notified of the detection status, client can register with the codec dma source module using EVENT_ID_SILENCE_DETECTION.
*/
#define PARAM_ID_SILENCE_DETECTION								0x08001AC2

/** @h2xmlp_parameter   {"PARAM_ID_SILENCE_DETECTION",
                          PARAM_ID_SILENCE_DETECTION}
    @h2xmlp_description {Configures the Silence detection param for the CODEC DMA Interface.
	To be notified of the detection status, client can register with the codec dma source module using EVENT_ID_SILENCE_DETECTION. }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_SILENCE_DETECTION */
struct param_id_silence_detection_t
{
	uint32_t enable_detection;
	/**< @h2xmle_description {Indicates if Silence detection is enabled/disabled}
	       @h2xmle_range       {0,1}
	       @h2xmle_default     {0} */

	uint32_t detection_duration_ms;
	/**< @h2xmle_description {Continuous silence duration of mic signal that is required to confirm silence detection}
	       @h2xmle_range       {1000..30000}
	       @h2xmle_default     {3000} */
}
#include "spf_end_pack.h"
;
typedef struct param_id_silence_detection_t param_id_silence_detection_t;


/**
 Payload for silence detection status.
*/
#include "spf_begin_pack.h"
struct event_cfg_silence_detection_status_t
{
   uint32_t status_ch_mask;
   /**< Current silence detection status mask for groups of 32 channels */

   /*#< @h2xmle_description       {Current silence detection status mask for groups of 
                                   32 channels based on num_32_channel_group.
								   Here nth channel status will be present at n-1 th bit.
                                   If num_32_channel_group = 1, the status includes channels 1-32
                                   If num_32_channel_group = 2, the status includes channels 33-64 etc.}
        @h2xmle_policy            {Basic} */
}
#include "spf_end_pack.h"
;

typedef struct event_cfg_silence_detection_status_t event_cfg_silence_detection_status_t;


/** Identifier of the silence detection event from CODEC DMA module.
    Payload of the configuration that the client is to register with the module
    through APM_CMD_REGISTER_MODULE_EVENTS
    event_cfg_silence_detection_t
	The events are raised based on the configuration provided using PARAM_ID_SILENCE_DETECTION
 */
#define EVENT_ID_SILENCE_DETECTION 								0x08001AC3
/** @h2xmlp_parameter   {"EVENT_ID_SILENCE_DETECTION",
                          EVENT_ID_SILENCE_DETECTION}
    @h2xmlp_description {ID of the event raised by codec DMA module based on configuration provided using PARAM_ID_SILENCE_DETECTION. }
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

/** Payload of the #EVENT_ID_SILENCE_DETECTION event.
*/

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct event_cfg_silence_detection_t
{
   uint32_t num_32_channel_group;
   /**< Number of silence detection 32 channel groups. 
		If num_32_channel_group=1 then status contain information of 32 channels.
		If num_32_channel_group=2 then status contain information of 64 channels etc.
		*/

   /*#< @h2xmle_description {Number of silence detection 32 channel groups. 
							 If num_32_channel_group=1 then then status contain information of 32 channels.
							 If num_32_channel_group=2 then status contain information of 64 channels etc.}
        @h2xmle_default     {0}
        @h2xmle_range       {0..0xFFFFFFFF}
        @h2xmle_policy      {Basic} */

   event_cfg_silence_detection_status_t detections[0];
   /**< Array of silence detection status of size num_32_channel_group. */
   /*#< @h2xmle_description       {Array of silence detection status of size
                                   num_32_channel_group.}
        @h2xmle_variableArraySize {num_32_channel_group}
        @h2xmle_policy            {Basic} */
   
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct event_cfg_silence_detection_t event_cfg_silence_detection_t;
/** ID of the parameter used to configure the HW endpoint media format */
#define PARAM_ID_HW_EP_MF_CFG                               0x08001017

/** @h2xmlp_parameter   {"PARAM_ID_HW_EP_MF_CFG",
                         PARAM_ID_HW_EP_MF_CFG}
    @h2xmlp_description {Configures the media format of the HW endpoint interface.} 
    @h2xmlp_toolPolicy   {Calibration}
*/

#include "spf_begin_pack.h"
struct param_id_hw_ep_mf_t
{
   uint32_t sample_rate;
   /**< @h2xmle_description {Defines sample rate of the interface.}
        @h2xmle_rangeList   {"8 kHz"=8000;
                             "11.025 kHz"=11025;
                             "12 kHz"=12000;
                             "16 kHz"=16000;
                             "22.05 kHz"=22050;
                             "24 kHz"=24000;
                             "32 kHz"=32000;
                             "44.1 kHz"=44100;
                             "48 kHz"=48000;
                             "88.2 kHz"=88200;
                             "96 kHz"=96000;
                             "176.4 kHz"=176400;
                             "192 kHz"=192000;
                             "352.8 kHz"=352800;
                             "384 kHz"=384000}
        @h2xmle_default     {48000}
   */
    uint16_t bit_width;
   /**< @h2xmle_description {Bit width in bits per sample.}
        @h2xmle_rangeList   {"16-bit"=16;
                             "24-bit"=24;
                             "32-bit"=32}
        @h2xmle_default     {16}
   */
   uint16_t num_channels;
   /**< @h2xmle_description {Number of channels.}
        @h2xmle_range       {1..32}
        @h2xmle_default     {1}
   */
   uint32_t data_format;
   /**< @h2xmle_description {Format of the data}
        @h2xmle_rangeList   {"DATA_FORMAT_FIXED_POINT"=1;
                            "DATA_FORMAT_IEC61937_PACKETIZED"=2;
                            "DATA_FORMAT_IEC60958_PACKETIZED"=3;
                            "DATA_FORMAT_IEC60958_PACKETIZED_NON_LINEAR"= 8;
                            "DATA_FORMAT_DSD_OVER_PCM"=4;
                            "DATA_FORMAT_GENERIC_COMPRESSED"=5;
                            "DATA_FORMAT_RAW_COMPRESSED"=6;
                            "DATA_FORMAT_COMPR_OVER_PCM_PACKETIZED"= 7}
        @h2xmle_default     {1}
   */
}
#include "spf_end_pack.h"
;
/* Structure type def for above payload. */
typedef struct param_id_hw_ep_mf_t param_id_hw_ep_mf_t;


/** ID of the parameter used to configure the operating frame size */
#define PARAM_ID_HW_EP_FRAME_SIZE_FACTOR                    0x08001018

/** @h2xmlp_parameter   {"PARAM_ID_HW_EP_FRAME_SIZE_FACTOR",
                         PARAM_ID_HW_EP_FRAME_SIZE_FACTOR}
    @h2xmlp_description {Configures the operating frame size} 
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
struct param_id_frame_size_factor_t
{
   uint32_t frame_size_factor;
   /**< @h2xmle_description {Frame size factor used to derive operating frame size in number of samples per channel.}
        @h2xmle_range       {1..40}
        @h2xmle_default     {1}
   */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_frame_size_factor_t param_id_frame_size_factor_t;


/* ID of the paramter used to configure or enable HW clocks */
#define PARAM_ID_HW_INTF_CLK_CFG                            0x0800113C

/** @h2xmlp_parameter   {"PARAM_ID_HW_INTF_CLK_CFG",
                         PARAM_ID_HW_INTF_CLK_CFG}
    @h2xmlp_description {Configures or enables HW clocks} 
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
struct param_id_hw_intf_clk_cfg_t
{
   uint32_t clock_id;
   /**< @h2xmle_description {Unique Clock ID of the clock being requested.}
        @h2xmle_default     {HW_INTF_CLK_ID_DEFAULT}
        @h2xmle_rangeList   {"HW_INTF_CLK_ID_DEFAULT"=HW_INTF_CLK_ID_DEFAULT} */

   uint32_t clock_freq;
   /**< @h2xmle_description {Clock frequency in Hz to set.}
        @h2xmle_default     {HW_INTF_CLK_FREQ_DEFAULT} */

   uint32_t clock_attri;
   /**< @h2xmle_description {Configures clock attributes.}
        @h2xmle_default     {HW_INTF_CLK_ATTRI_DEFAULT}
        @h2xmle_rangeList   {"HW_INTF_CLK_ATTRI_DEFAULT"=HW_INTF_CLK_ATTRI_DEFAULT;
                             "CLOCK_ATTRIBUTE_INVERT_COUPLE_NO"=CLOCK_ATTRIBUTE_INVERT_COUPLE_NO} */

   uint32_t clock_root;
   /**< @h2xmle_description {Root clock source.}
        @h2xmle_default     {CLOCK_ROOT_DEFAULT}
        @h2xmle_rangeList   {"CLOCK_ROOT_DEFAULT"=CLOCK_ROOT_DEFAULT}  */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_hw_intf_clk_cfg_t param_id_hw_intf_clk_cfg_t;

/* ID of the paramter used to configure or enable HW clocks */
#define PARAM_ID_HW_EP_POWER_MODE_CFG                       0x08001176

#define POWER_MODE_0             0 //default
#define POWER_MODE_1             1 //XO shutdown allowed
#define POWER_MODE_2             2 //XO shutdown disallowed
#define HW_EP_POWER_MODE_MAX     POWER_MODE_2
/** @h2xmlp_parameter   {"PARAM_ID_HW_EP_POWER_MODE_CFG",
                         PARAM_ID_HW_EP_POWER_MODE_CFG}
    @h2xmlp_description {Configures the power mode (XO Shutdown).} 
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
struct param_id_hw_ep_power_mode_cfg_t
{
   uint32_t power_mode;
   /**< @h2xmle_description {Power mode - indicates the sleep latency XO mode vote 
                             in a low power scenario; \n
                             -# POWER_MODE_0 -> EP is not in LPI - Default Mode; \n
                             -# POWER_MODE_1 -> XO shutdown is allowed (deep sleep)\n
                             -# POWER_MODE_2 -> XO shutdown is NOT allowed}
        @h2xmle_default     {POWER_MODE_0}
        @h2xmle_rangeList   {"POWER_MODE_0"=POWER_MODE_0;
                             "POWER_MODE_1"=POWER_MODE_1;
                             "POWER_MODE_2"=POWER_MODE_2} */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_hw_ep_power_mode_cfg_t param_id_hw_ep_power_mode_cfg_t;

/*********************************** HW EP Source Custom Channel Map ******************************/
/**
 * Param ID used to configure hw ep source custom channel maps
 */
#define PARAM_ID_HW_EP_SRC_CHANNEL_MAP                 0x0800108A

/** @h2xmlp_parameter   {"PARAM_ID_HW_EP_SRC_CHANNEL_MAP", PARAM_ID_HW_EP_SRC_CHANNEL_MAP}
    @h2xmlp_description {Param ID used to configure hw ep source custom channel maps. }
    @h2xmlp_toolPolicy  {Calibration} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct param_id_hw_ep_src_channel_map_t
{
   uint16_t num_channels;
   /**< @h2xmle_description {Number of channels}
        @h2xmle_default     {0}
        @h2xmle_range       { 0..16 }
        @h2xmle_policy      {Basic} */
#if defined(__H2XML__)
   uint16_t channel_mapping[0];
    /**< @h2xmle_description {Channel mapping array whose size is num_channels defined above.
                              Each element i of the channel_mapping[i] array, describes the channel i inside
                              the buffer where i is less than num_channels.  An unused channel is set to 0.
                              Each used channel should be between the values 48 and 63}
         @h2xmle_rangeList         {"PCM_CUSTOM_CHANNEL_MAP_1" = PCM_CUSTOM_CHANNEL_MAP_1,
                                    "PCM_CUSTOM_CHANNEL_MAP_2" = PCM_CUSTOM_CHANNEL_MAP_2,
                                    "PCM_CUSTOM_CHANNEL_MAP_3" = PCM_CUSTOM_CHANNEL_MAP_3,
                                    "PCM_CUSTOM_CHANNEL_MAP_4" = PCM_CUSTOM_CHANNEL_MAP_4,
                                    "PCM_CUSTOM_CHANNEL_MAP_5" = PCM_CUSTOM_CHANNEL_MAP_5,
                                    "PCM_CUSTOM_CHANNEL_MAP_6" = PCM_CUSTOM_CHANNEL_MAP_6,
                                    "PCM_CUSTOM_CHANNEL_MAP_7" = PCM_CUSTOM_CHANNEL_MAP_7,
                                    "PCM_CUSTOM_CHANNEL_MAP_8" = PCM_CUSTOM_CHANNEL_MAP_8,
                                    "PCM_CUSTOM_CHANNEL_MAP_9" = PCM_CUSTOM_CHANNEL_MAP_9,
                                    "PCM_CUSTOM_CHANNEL_MAP_10" = PCM_CUSTOM_CHANNEL_MAP_10,
                                    "PCM_CUSTOM_CHANNEL_MAP_11" = PCM_CUSTOM_CHANNEL_MAP_11,
                                    "PCM_CUSTOM_CHANNEL_MAP_12" = PCM_CUSTOM_CHANNEL_MAP_12,
                                    "PCM_CUSTOM_CHANNEL_MAP_13" = PCM_CUSTOM_CHANNEL_MAP_13,
                                    "PCM_CUSTOM_CHANNEL_MAP_14" = PCM_CUSTOM_CHANNEL_MAP_14,
                                    "PCM_CUSTOM_CHANNEL_MAP_15" = PCM_CUSTOM_CHANNEL_MAP_15,
                                    "PCM_CUSTOM_CHANNEL_MAP_16" = PCM_CUSTOM_CHANNEL_MAP_16}
         @h2xmle_default           {PCM_CUSTOM_CHANNEL_MAP_1}
         @h2xmle_variableArraySize {"num_channels"}
         @h2xmle_policy            {Basic} */
#endif
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
typedef struct param_id_hw_ep_src_channel_map_t param_id_hw_ep_src_channel_map_t;

/** Parameter used to configure DMA data alignment for Codec DMA interface  */

#define PARAM_ID_HW_EP_DMA_DATA_ALIGN                          0x08001233

#define DMA_DATA_ALIGN_MSB                                     0   // DMA data is MSB aligned
#define DMA_DATA_ALIGN_LSB                                     1   // DMA data is LSB aligned

/** @h2xmlp_parameter   {"PARAM_ID_HW_EP_DMA_DATA_ALIGN",
                         PARAM_ID_HW_EP_DMA_DATA_ALIGN}
    @h2xmlp_description {Configures DMA data alignment.}
    @h2xmlp_toolPolicy   {Calibration} */

#include "spf_begin_pack.h"
/** Payload for parameter PARAM_ID_HW_EP_DMA_DATA_ALIGN */
struct param_id_hw_ep_dma_data_align_t
{
       uint32_t                dma_data_align;
       /**< @h2xmle_description {DMA data alignment.\n
                                 Indicates the data alignment in DMA buffer. \n

                                 # DMA_DATA_ALIGN_MSB - DMA data aligned towards MSB \n
                                 # DMA_DATA_ALIGN_LSB - DMA data aligned towrads LSB}
            @h2xmle_rangeList   {"DMA_DATA_ALIGN_MSB"=0;
                                 "DMA_DATA_ALIGN_LSB"=1}
          @h2xmle_default     {0}
     */
}
#include "spf_end_pack.h"
;

/* Structure type def for above payload. */
typedef struct param_id_hw_ep_dma_data_align_t param_id_hw_ep_dma_data_align_t;

#endif /* HW_INTF_CMN_API */
