/* =========================================================================
    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
    SPDX-License-Identifier: BSD-3-Clause
   ========================================================================= */

#ifndef QUASAR_MODULE_API_H
#define QUASAR_MODULE_API_H

/** @h2xml_title1           {Qualcomm Spatial Audio Renderer (QUASAR_Module)}
    @h2xml_title_agile_rev  {Qualcomm Spatial Audio Renderer (QUASAR_Module)}
    @h2xml_title_date       {August 05, 2025} */

#include "module_cmn_api.h"
#include "imcl_spm_intent_api.h"
#include "imcl_fwk_intent_api.h"


#define MODULE_ID_QUASAR        0x07001186
#define VERSION_MAJOR           0x00000004
#define VERSION_MINOR           0x00000001

/**
   @h2xmlm_module               {"MODULE_ID_QUASAR",
                                 MODULE_ID_QUASAR}
   @h2xmlm_displayName          {"Qualcomm Spatial Audio Renderer"}
   @h2xmlm_modSearchKeys        {Audio}
   @h2xmlm_description          {- ID of the QUASAR module.\n
                                 - This module dynamically registers for HDT data via IMCL.\n
                                 - It can register for either:\n
                                 - INTENT_ID_SA_HDT_ORIENTATION_DATA (preferred - pre-processed)\n
                                 - INTENT_ID_SA_HDT_RAW_DATA (fallback - requires conversion)\n
                                 - This module supports the following parameter IDs:\n
                                 - PARAM_ID_QUASAR_MODULE_DYNAMICS_CONFIG\n
                                 - PARAM_ID_QUASAR_MODULE_REVERB_CONFIG\n
                                 - PARAM_ID_QUASAR_MODULE_REFLECTIONS_CONFIG\n
                                 - PARAM_ID_QUASAR_MODULE_USER_POSITION\n
                                 - PARAM_ID_QUASAR_MODULE_N_SOURCES_METADATA\n
                                 - PARAM_ID_QUASAR_MODULE_RESET\n
                                 - PARAM_ID_QUASAR_MODULE_OBJ_BINAURALIZER_CONFIG\n
                                 - PARAM_ID_QUASAR_MODULE_OUTPUT_MODE\n
                                 - PARAM_ID_QUASAR_MODULE_VERSION\n
                                 - Supported Input Media Format:\n
                                 - Data Format          : FIXED_POINT\n
                                 - fmt_id               : MEDIA_FMT_ID_PCM\n
                                 - Sample Rates         : 48000\n
                                 - Number of channels   : 12\n
                                 - Channel type         : Supported channel mapping based on number of channels\n
                                 - Bits per sample      : 16\n
                                 - Q format             : Q15 for bps = 16\n
                                 - Interleaving         : Deinterleaved Unpacked\n
                                 - Signed/unsigned      : Signed\n
                                 - Supported Input Channel Mapping:\n
                                 - TBD: Channel default order as per Android framework is supported. Final supported channel map and order will be updated later.}
   @h2xmlm_dataMaxInputPorts    {1}
   @h2xmlm_dataMaxOutputPorts   {1}
   @h2xmlm_dataInputPorts       {IN = 2}
   @h2xmlm_dataOutputPorts      {OUT = 1}
   @h2xmlm_ctrlDynamicPortIntent  { "HDT Raw Data In" = INTENT_ID_SA_HDT_RAW_DATA,
                                    maxPorts= 1 }
   @h2xmlm_ctrlDynamicPortIntent  { "HDT Orientation Data In" = INTENT_ID_SA_HDT_ORIENTATION_DATA,
                                    maxPorts= 1 }
   @h2xmlm_supportedContTypes   {APM_CONTAINER_TYPE_SC, APM_CONTAINER_TYPE_GC}
   @h2xmlm_isOffloadable        {true}
   @h2xmlm_stackSize            {4096}
   @h2xmlm_toolPolicy           {Calibration}

   @{                           <-- Start of the Module --> **/


#define PARAM_ID_QUASAR_MODULE_DYNAMICS_CONFIG 0x08001BB5

typedef struct dynamics_config_t dynamics_config_t;
/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_DYNAMICS_CONFIG",
                          PARAM_ID_QUASAR_MODULE_DYNAMICS_CONFIG}
    @h2xmlp_description {Configures QuaSAR's dynamics sub-module}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct dynamics_config_t
{
    uint32_t enable;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Dynamics enable/disable}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableDynamics=0;enableDynamics=1} */
    uint32_t comp_enable;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Compressor enable/disable}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableCompressor=0;enableCompressor=1} */
    float comp_gain;
    /** < @h2xmle_default       {6.0}
          @h2xmle_description   {Make-up gain applied in dB applied by compressor}
          @h2xmle_range         {-12.0,12.0}  */
    float comp_threshold;
    /** < @h2xmle_default       {-18.0}
          @h2xmle_description   {Threshold for compression in dB(FS)}
          @h2xmle_range         {-60.0,0.0} */
    float comp_ratio;
    /** < @h2xmle_default       {1.3}
          @h2xmle_description   {Compression ratio applied above threshold}
          @h2xmle_range         {1.0,10.0} */
    uint32_t os_enable;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Overshoot control enable/disable}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableOS=0;enableOS=1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*   @h2xml_Select					{dynamics_config_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_REVERB_CONFIG 0x08001BB6

typedef struct reverb_config_t reverb_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_REVERB_CONFIG",
                         PARAM_ID_QUASAR_MODULE_REVERB_CONFIG}
    @h2xmlp_description {Configures QuaSAR's late reverb sub-module}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct reverb_config_t
{
    uint32_t enable;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Reverb enable/disable}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableReverb=0;enableReverb=1} */
    float duration;
    /** < @h2xmle_default       {0.165}
          @h2xmle_description   {Duration of reverb tail in seconds}
          @h2xmle_range         {0.001,0.165} */
    uint32_t pulse_period;
    /** < @h2xmle_default       {15}
          @h2xmle_description   {Density of reverb tail pulses (lower = more dense)}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_range         {2,6000} */
    float scale;
    /** < @h2xmle_default       {0.09}
          @h2xmle_description   {Scale factor applied to reverb tail}
          @h2xmle_range         {0.0,1.0} */
    uint32_t predelay;
    /** < @h2xmle_default       {15}
          @h2xmle_description   {Pre-delay between direct path and reverb start in miliseconds}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_range         {0,100} */
    uint32_t stereo;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Enable stereo decorrelation of reverb}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableStereo=0;enableStereo=1} */
    uint32_t tone_enable;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Enable reverb tone control}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableTone=0;enableTone=1} */
    uint32_t tone_cutoff;
    /** < @h2xmle_default       {10000}
          @h2xmle_description   {Cutoff frequency of tone control high-shelf in Hz}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_range         {100,12000} */
    float tone_balance;
    /** < @h2xmle_default       {0.5}
          @h2xmle_description   {Relative level high shelf (-1.0 = -12 dB, 1.0 = 0 dB)}
          @h2xmle_range         {-1.0,1.0} */
    float tone_slope;
    /** < @h2xmle_default       {1.0}
          @h2xmle_description   {Slope of shelving filter (higher value = steeper slope)}
          @h2xmle_range         {0.1,1.0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*   @h2xml_Select					{reverb_config_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_REFLECTIONS_CONFIG 0x08001BB7

typedef struct reflections_config_t reflections_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_REFLECTIONS_CONFIG",
                          PARAM_ID_QUASAR_MODULE_REFLECTIONS_CONFIG}
    @h2xmlp_description {Configures QuaSAR's early reflections sub-module}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct reflections_config_t
{
    uint32_t mode;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Early reflections processing mode}
          @h2xmle_range         {0,6} */
    float room_l;
    /** < @h2xmle_default       {5.0}
          @h2xmle_description   {Room length}
          @h2xmle_range         {1.0,14.0} */
    float room_w;
    /** < @h2xmle_default       {4.0}
          @h2xmle_description   {Room width}
          @h2xmle_range         {1.0,14.0} */
    float room_h;
    /** < @h2xmle_default       {3.0}
          @h2xmle_description   {Room height}
          @h2xmle_range         {1.0,14.0} */
    uint32_t use_materials;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Flag to use materials (1) or absorption coefficients (0)}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {useAbsCoeff=0;useMaterial=1} */
    float abs_front;
    /** < @h2xmle_default       {0.2}
          @h2xmle_description   {Absorption coefficient of front wall}
          @h2xmle_range         {0.0,1.0} */
    float abs_back;
    /** < @h2xmle_default       {0.2}
          @h2xmle_description   {Absorption coefficient of back wall}
          @h2xmle_range         {0.0,1.0} */
    float abs_left;
    /** < @h2xmle_default       {0.2}
          @h2xmle_description   {Absorption coefficient of left wall}
          @h2xmle_range         {0.0,1.0} */
    float abs_right;
    /** < @h2xmle_default       {0.2}
          @h2xmle_description   {Absorption coefficient of right wall}
          @h2xmle_range         {0.0,1.0} */
    float abs_ceiling;
    /** < @h2xmle_default       {0.11}
          @h2xmle_description   {Absorption coefficient of ceiling}
          @h2xmle_range         {0.0,1.0} */
    float abs_floor;
    /** < @h2xmle_default       {0.63}
          @h2xmle_description   {Absorption coefficient of floor}
          @h2xmle_range         {0.0,1.0} */
    uint32_t material_front;
    /** < @h2xmle_default       {2}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    uint32_t material_back;
    /** < @h2xmle_default       {2}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    uint32_t material_left;
    /** < @h2xmle_default       {2}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    uint32_t material_right;
    /** < @h2xmle_default       {2}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    uint32_t material_ceiling;
    /** < @h2xmle_default       {27}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    uint32_t material_floor;
    /** < @h2xmle_default       {25}
          @h2xmle_description   {Front wall material}
          @h2xmle_range         {1,27} */
    float user_x;
    /** < @h2xmle_default       {0.0}
          @h2xmle_description   {User X position (front-back) in meters}
          @h2xmle_range         {-7.0,7.0} */
    float user_y;
    /** < @h2xmle_default       {0.0}
          @h2xmle_description   {User Y position (left-right) in meters}
          @h2xmle_range         {-7.0,7.0} */
    float user_height;
    /** < @h2xmle_default       {1.6}
          @h2xmle_description   {User height in meters}
          @h2xmle_range         {0.1,14.0} */
    uint32_t auto_reverb;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Flag to use automatic late reverb (1) or manual reverb parameters (0)}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableAutoreverb=0,enableAutoreverb=1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{reflections_config_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_SCREEN_ORIENTATION 0x08001BB8

typedef struct screen_orientation_t screen_orientation_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_SCREEN_ORIENTATION",
                          PARAM_ID_QUASAR_MODULE_SCREEN_ORIENTATION}
    @h2xmlp_description {Set QuaSAR screen orientation}
    @h2xmlp_toolPolicy  {RTC; CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct screen_orientation_t {
      /* h2xml does not support enum, so use int32_t when h2xml is defined */
      uint32_t rotation_mode;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Rotation mode}
          @h2xmle_range         {0,2} */

    float orientation[3];
    /** < @h2xmle_defaultList   {0.0,0.0,1.0}
          @h2xmle_description   {User orientation 3 vector}
          @h2xmle_range         {-360.0,360.0} */
    int64_t timestamp;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Current screen orientation timestamp}
          @h2xmle_range         {0..1000000000000000} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{screen_orientation_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_USER_POSITION 0x08001BB9

typedef struct user_position_t user_position_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_USER_POSITION",
                          PARAM_ID_QUASAR_MODULE_USER_POSITION}
    @h2xmlp_description {Set QuaSAR user position}
    @h2xmlp_toolPolicy  {RTC; CALIBRATION} */

/**
User position is defined using the following right-handed cartesian coordinate system:
    position[0] (X-axis): Positive forwards, negative backwards
    position[1] (Y-axis): Positive left, negative right
    position[2] (Z-axis): Positive up, negative down */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct user_position_t {
    float position[3];
    /** < @h2xmle_defaultList   {0.0,0.0,0.0}
          @h2xmle_description   {User position 3 vector}
          @h2xmle_range         {-100.0,100.0} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{user_position_t}
     @h2xmlm_InsertParameter */

typedef struct source_metadata_t source_metadata_t;
/** 
    @h2xmlp_subStruct
    @h2xmlp_description {Set QuaSAR source metadata} */

/**
Source position is defined using the following right-handed cartesian coordinate system:
    position[0] (X-axis): Positive forwards, negative backwards
    position[1] (Y-axis): Positive left, negative right
    position[2] (Z-axis): Positive up, negative down */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct source_metadata_t {
    uint16_t index;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Source index}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_range         {0,63} */
    float position[3];
    /** < @h2xmle_defaultList   {0.0,0.0,0.0}
          @h2xmle_description   {Source position 3 vector}
          @h2xmle_range         {-100.0,100.0} */
    uint32_t type;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {Rotation mode}
          @h2xmle_range         {0,4} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;


#define PARAM_ID_QUASAR_MODULE_N_SOURCES_METADATA 0x08001BBB

typedef struct n_sources_metadata_t n_sources_metadata_t;
/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_N_SOURCES_METADATA",
                          PARAM_ID_QUASAR_MODULE_N_SOURCES_METADATA}
    @h2xmlp_description {Set QuaSAR source metadata for N sources}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct n_sources_metadata_t {
    uint32_t n_sources;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Number of sources}
          @h2xmle_range         {1,64} */
    source_metadata_t source_metadata[];
    /** < @h2xmle_variableArraySize {n_sources}
          @h2xmle_default           {0}
          @h2xmle_description       {Source metadata} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{n_sources_metadata_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_RESET 0x08001BBC
/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_RESET",
                          PARAM_ID_QUASAR_MODULE_RESET}
    @h2xmlp_description {Resets QuaSAR library}
    @h2xmlp_toolPolicy  {NO_SUPPORT} */

// DOES NOT REQUIRE ANY PARAM STRUCTURE PTR / SIZE

#define PARAM_ID_QUASAR_MODULE_OUTPUT_MODE 0x08001BBD

typedef struct output_mode_t output_mode_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_OUTPUT_MODE",
                          PARAM_ID_QUASAR_MODULE_OUTPUT_MODE}
    @h2xmlp_description {Set QuaSAR output mode}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct output_mode_t {
    uint32_t output_mode;
    /** < @h2xmle_default       {0}
          @h2xmle_description   {QuaSAR output mode}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {twoSided=0;oneSidedLeft=1;oneSidedRight=2} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;
/*   @h2xml_Select					{output_mode_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_OBJ_BINAURALIZER_CONFIG 0x08001BBE

typedef struct obj_binauralizer_config_t obj_binauralizer_config_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_OBJ_BINAURALIZER_CONFIG",
                          PARAM_ID_QUASAR_MODULE_OBJ_BINAURALIZER_CONFIG}
    @h2xmlp_description {Configuration params for QUASAR_MODULE_OBJECT_BINAURALIZE render mode}
    @h2xmlp_toolPolicy  {CALIBRATION} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct obj_binauralizer_config_t {
    uint32_t activity_detect;
    /** < @h2xmle_default       {1}
          @h2xmle_description   {Enable / disable activity detector}
          @h2xmle_dataFormat    {Q0}
          @h2xmle_rangeList     {disableActivityDetect=0;enableActivityDetect=1} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{obj_binauralizer_config_t}
     @h2xmlm_InsertParameter */

#define PARAM_ID_QUASAR_MODULE_VERSION 0x08001BBF 	

typedef struct quasar_module_version_t quasar_module_version_t;

/** @h2xmlp_parameter   {"PARAM_ID_QUASAR_MODULE_VERSION",
                          PARAM_ID_QUASAR_MODULE_VERSION}
    @h2xmlp_description {Structure to get the current library version.}
    @h2xmlp_toolPolicy  {RTC_READONLY} */

#include "spf_begin_pack.h"
#include "spf_begin_pragma.h"
struct quasar_module_version_t
{
    uint32_t version_major;
    /**<    @h2xmle_description {Lower 32 bits of the 64-bit library version number}
            @h2xmle_default     {VERSION_MAJOR} */
    uint32_t version_minor;
    /**<    @h2xmle_description {Higher 32 bits of the 64-bit library version number}
            @h2xmle_default     {VERSION_MINOR} */
}
#include "spf_end_pragma.h"
#include "spf_end_pack.h"
;

/*   @h2xml_Select					{QUASAR_MODULE_module_version_t}
     @h2xmlm_InsertParameter */


/*==============================================================================
   Insert Common parameters
==============================================================================*/

/**
    @h2xml_Select                    {param_id_module_enable_t}
    @h2xmlm_InsertParameter

   @}                   <-- End of the Module -->*/

#endif
