#ifndef API_SOUND_DOSE_H
#define API_SOUND_DOSE_H
/*==============================================================================
  @file sounddose_api.h
  @brief This file contains SOUND DOSE API
==============================================================================*/

/*=======================================================================
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
=========================================================================*/
/*========================================================================
 Edit History

 when       	who     what, where, why
 --------   	---     -------------------------------------------------------
 22/08/2024    sreegr     Created File.
 ========================================================================== */

 /*------------------------------------------------------------------------
 * Include files
 * -----------------------------------------------------------------------*/
#include "module_cmn_api.h"
/*==============================================================================
   Constants
==============================================================================*/
#define CAPI_SOUND_DOSE_STACK_SIZE    2048
#define MODULE_ID_SOUND_DOSE 0x17030FFF
/**
     @h2xml_title1          {Sound Dose API}
     @h2xml_title_agile_rev {Sound Dose API}
     @h2xml_title_date      {August 01 , 2024}
  */

/**
    @h2xmlm_module       {"MODULE_ID_SOUND_DOSE",
                          MODULE_ID_SOUND_DOSE}
  @h2xmlm_displayName  {"Sound Dose"}
    @h2xmlm_toolPolicy   {Calibration}
    @h2xmlm_description  {Mel Value calculation from the audio input to control the sound pressure exposure\n
* - This module supports the following parameter IDs:  \n
*      - #PARAM_ID_SOUND_DOSE_MEL_EVENTS_CONFIG \n
*      - #PARAM_ID_SOUND_DOSE_RS2_UPPER_BOUND \n
*      - #PARAM_ID_SOUND_DOSE_MEL_TIMESTAMP_INFO \n
*
* Supported Input Media Format:\n
*  - Data Format          : FIXED_POINT\n
*  - fmt_id               : Don't care\n
*  - Sample Rates         : 44100,48000\n
*  - Number of channels   : 1 , 2 \n
*  - Channel type         : 1 to 63\n
*  - Bits per sample      : 16, 32\n
*  - Q format             : 15, 27, 31\n
*  - Interleaving         : de-interleaved unpacked\n
*  - Signed/unsigned      : Signed }

    @h2xmlm_dataMaxInputPorts    {1}
    @h2xmlm_dataInputPorts       {IN=2}
    @h2xmlm_dataMaxOutputPorts   {0}
    @h2xmlm_supportedContTypes  {APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
    @h2xmlm_isOffloadable        {false}
    @h2xmlm_stackSize            {CAPI_SOUND_DOSE_STACK_SIZE}
    @h2xmlm_ToolPolicy              {Calibration}
    @{                   <-- Start of the Module -->
*/

/** Param ID of the time interval in which mel values to be raised to client */
#define PARAM_ID_SOUND_DOSE_MEL_EVENTS_CONFIG 0x18030FFA
/** @h2xmlp_parameter   {"PARAM_ID_SOUND_DOSE_MEL_EVENTS_CONFIG",
                         PARAM_ID_SOUND_DOSE_MEL_EVENTS_CONFIG}
    @h2xmlp_description {This parameter used to configure the time interval
                         in which event to be raised to client.}
    @h2xmlp_toolPolicy  {CALIBRATION}*/


typedef struct param_id_sounddose_mel_events_config{
  uint32_t mel_event_interval_in_sec;
  /**< @h2xmle_description  {The period in which the new MEL values will be communicated to the client.
                               }
      @h2xmle_default        {0xA}
      @h2xmle_range          {0x1..0xA} */
}param_id_sounddose_mel_events_config;

/** Param ID of RS2 Upper bound used for momentary exposure detection */
#define PARAM_ID_SOUND_DOSE_RS2_UPPER_BOUND 0x18030FFB
/** @h2xmlp_parameter   {"PARAM_ID_SOUND_DOSE_RS2_UPPER_BOUND",
                         PARAM_ID_SOUND_DOSE_RS2_UPPER_BOUND}
    @h2xmlp_description {parameter used to configure the RS2 upper bound for momentary exposure.}
    @h2xmlp_toolPolicy  {CALIBRATION,RTC}*/

typedef struct param_id_sounddose_rs2_upper_bound{
  uint32_t rs2_upper_bound;
  /**< @h2xmle_description  {RS2 upper bound value above which the momentary exposure warning to be raised }
       @h2xmle_dataFormat  {Q22}
       @h2xmle_default        {0x19000000} */
}param_id_sounddose_rs2_upper_bound;

/** Param ID related to the timestamp info attached to the mel values */
#define PARAM_ID_SOUND_DOSE_MEL_TIMESTAMP_INFO 0x18030FFC
/** @h2xmlp_parameter   {"PARAM_ID_SOUND_DOSE_MEL_TIMESTAMP_INFO",
                         PARAM_ID_SOUND_DOSE_MEL_TIMESTAMP_INFO}
    @h2xmlp_description {parameter used to configure the timestamp info attached to event.
                         Absolute TS is used when the module is in the real time section of the graph and
                         Relative TS is to be used if the module is kept in the non RT section}
    @h2xmlp_toolPolicy  {CALIBRATION}*/
	
typedef struct param_id_sounddose_mel_timestamp_info{
  uint32_t timestamp_info;
  /**< @h2xmle_description  {This field is regarding the timestamp value
   * attached to the mel values. The client can communicate whether it is expecting
   * absolute or relative timestamp.
                                 }
        @h2xmle_rangeList  { "Absolute TS" = 0 ; "Relative TS " = 1}
        @h2xmle_default        {0x0} */
}param_id_sounddose_mel_timestamp_info;


/** Event ID of the  events raised to client for momentary exposure or new mel values*/
#define EVENT_ID_SOUND_DOSE_MEL_VALUES 0x18030FFE
/** @h2xmlp_parameter   {"EVENT_ID_SOUND_DOSE_MEL_VALUES",
                         EVENT_ID_SOUND_DOSE_MEL_VALUES}
    @h2xmlp_description {New Mel Values or Momentary exposure event raised by sound dose module}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/
	
#include "spf_begin_pragma.h"
typedef struct event_id_sound_dose_mel_values{
  uint32_t is_momentary_exposure_raised;
  /**< @h2xmle_description  {Flag to indicate whether the event is related to momentary exposure or new mel values
                            1 means the event is related to momentary exposure and 0 indicates the event is related to new mel values}
  */

  uint32_t num_mel_values;
    /**< @h2xmle_description  {The number of mel values  included in the event raised to HLOS
                                 }
        @h2xmle_default        {0xA} */

  float mel_value[0];
    /**< @h2xmle_description  {The mel values calculated in the ADSP is kept in this section}
     *   @h2xmle_variableArraySize {max_num_mel_values}
     */

  uint32_t timestamp_mel_value[0];
  /**< @h2xmle_description  {The timestamp associated with mel value are kept in this section
   * The timestamp at which each mel value is generated is captured.
   * The 64 bit timestamp value is split into two 32 bit values and stored consecutively.
   * For example, the first item in this section is the LSB of the 64 bit timestamp associated with first mel value
   * The second item is the MSB of the 64 bit timestamp associated with first mel value.
   * Timestamp for the other mel values will be in the same order}
   *   @h2xmle_variableArraySize {max_num_mel_values}
   */
}event_id_sound_dose_mel_values;
#include "spf_end_pragma.h"


#define PARAM_ID_SOUND_DOSE_FLUSH_MEL_VALUES 0x18030FFD
/** @h2xmlp_parameter   {"PARAM_ID_SOUND_DOSE_FLUSH_MEL_VALUES",
                         PARAM_ID_SOUND_DOSE_FLUSH_MEL_VALUES}
    @h2xmlp_description {This get param is used to get the accumulated mel values at the end of the use case}
    @h2xmlp_toolPolicy  {NO_SUPPORT}*/
#include "spf_begin_pragma.h"
typedef struct param_id_sounddose_flush_mel_values{
	uint32_t num_mel_values;
	    /**< @h2xmle_description  {The number of mel values  included in the get param
	                                 }
	        @h2xmle_default        {0xA} */

	  float mel_value[0];
	 /**< @h2xmle_description  {The mel values accumulated in the ADSP
	  * after the last event has been raised}
	     *   @h2xmle_variableArraySize {num_mel_values}
	     */

	  uint32_t timestamp_mel_value[0];
	/**< @h2xmle_description  {The timestamp associated with mel value are kept in this section
	   * The timestamp at which each mel value is generated is captured.
	   * The 64 bit timestamp value is split into two 32 bit values and stored consecutively.
	   * For example, the first item in this section is the LSB of the 64 bit timestamp associated with first mel value
	   * The second item is the MSB of the 64 bit timestamp associated with first mel value.
	   * Timestamp for the other mel values will be in the same order}
	   *   @h2xmle_variableArraySize {num_mel_values}
	   */
}param_id_sounddose_flush_mel_values;
#include "spf_end_pragma.h"


/**
	@h2xml_Select					{param_id_module_enable_t}
   @h2xmlm_InsertParameter
*/
/**
	@h2xml_Select					{param_id_sounddose_mel_events_config}
   @h2xmlm_InsertParameter
*/

/**
	@h2xml_Select					{param_id_sounddose_rs2_upper_bound}
   @h2xmlm_InsertParameter
*/

/**
	@h2xml_Select					{param_id_sounddose_mel_timestamp_info}
   @h2xmlm_InsertParameter
*/

/**
	@h2xml_Select					{param_id_sounddose_flush_mel_values}
   @h2xmlm_InsertParameter
*/

/** @}                   <-- End of the Module -->*/
#endif //API_SOUND_DOSE_H
