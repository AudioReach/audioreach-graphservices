/**
*==============================================================================
* \file adie_rtc_api.h
* \brief
*                   A D I E  R T C  A P I  H E A D E R  F I L E
*
*      This header defines the APIs nessesary to operate on codec registers.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

#ifndef ADIE_RTC_API_H
#define ADIE_RTC_API_H

#include "ar_osal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum adie_rtc_api_major_version_t
{
    ADIE_RTC_API_MAJOR_VERSION_1 = 0x1,
}adie_rtc_api_major_version_t;

typedef enum adie_rtc_api_minor_version_t
{
    /**< Initial version */
    ADIE_RTC_API_MINOR_VERSION_0 = 0x0,
    /**< Introduces bug fixes */
    ADIE_RTC_API_MINOR_VERSION_1 = 0x1,
    /**<
    * Update to adie_rtc_codec_handle_v2 to include codec revison number
    * Update to adie_rtc_codec_info_v2 to include structure version
    * Added adie_rtc_get_codec_info_v2 api
    */
    ADIE_RTC_API_MINOR_VERSION_2 = 0x2,
}adie_rtc_api_minor_version_t;

typedef enum adie_chipset_id_t
{
    MSM8X52 = 1,
    WCD9335 = 2,
    WSA881X_ANALOG = 3,
    WSA881X_SOUNDWIRE = 4,
    WSA881X = 5,
    MSM8909 = 6,
    WCD9330 = 7,
    WCD9326 = 8,
    WCD9320 = 9,
    WCD9310 = 10,
    WCD9306 = 11,
    WCD9302 = 12,
    MSM8X16 = 13,
    MSM8X10 = 14,
    RESERVED_1 = 15,
    WCD9340 = 16,
    WCD9341 = 17,
    RESERVED_2 = 18,
    RESERVED_3 = 19,
    RESERVED_4 = 20,
    WHS9410 = 21,
    WHS9420 = 22,
    RESERVED_5 = 23,
    WCD9360 = 24,
    AQT1000 = 25,
    BOLERO = 26,
    WCD937X = 27,   //Tanguu
    WCD938X = 28,   //Traverso
    ROULER = 29,
    WSA883X = 30,
    WSA884X = 31,
    SLATE = 32,
    BESBEV = 33,
    WCD939X = 34,
    WCD9378 = 35,
    CODEC_UNDEFINED = ((uint16_t)-1)
}adie_chipset_id_t;

struct adie_rtc_codec_handle {
    uint32_t handle;
    uint32_t chipset_id;
    uint32_t chipset_major_version;
    uint32_t chipset_minor_version;
};

#define CODEC_INFO_STRUCT_VERSION_V2 2

struct adie_rtc_codec_handle_v2 {
	uint32_t handle;
	uint32_t chipset_id;
	uint32_t chipset_major_version;
	uint32_t chipset_minor_version;
	uint32_t chipset_revision;
};

struct adie_rtc_codec_info {
    uint32_t num_of_entries;                /**< number of codec entries */
    struct adie_rtc_codec_handle handle[0]; /**< codec entry list (in-band). */

};

struct adie_rtc_codec_info_v2 {
	uint32_t version;
	uint32_t num_of_entries;                /**< number of codec entries */
	uint8_t handle[0];			/**< codec entry list (in-band). */

};

struct adie_rtc_register {
    uint32_t register_id;
    uint32_t register_mask;
    uint32_t value;
    /**< value is output in get_register and acts as input in set_register */
};


struct adie_rtc_register_req {
    uint32_t codec_handle;          /**< The codec handle */
    struct adie_rtc_register reg;   /**< The codec register */
};

struct adie_rtc_multi_register_req {
    uint32_t codec_handle;      /**< The codec to set registers for */
    uint32_t num_registers;     /**< the number of registers being set */
    struct adie_rtc_register
        register_list[0];       /**< the list of registers to set */
};

struct adie_rtc_version
{
    /**< Major version for changes that break backward compatibility */
    uint32_t major;
    /**< Major version for changes that do not break backward compatibility */
    uint32_t minor;
};

/**
* \brief
*		Initializes the platforms ADIE RTC layer
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_init(void);

/**
* \brief
*		Deinitializes the platforms ADIE RTC layer
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_deinit(void);

/**
* \brief
*		Retrieves the ADIE RTC version being used. The version can be specified
*       using the enumations defined in adie_api_major_version_t and
*       adie_api_minor_version_t
*
* \params[in/out] api_version: The api version used by the platform
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_get_api_version(struct adie_rtc_version *api_version);

/**
* \brief
*		Retreives codec information for the list of chipset(s) specified
*       in the adie_rtc_codec_info::handle array.
*
* \params[in/out] codec_info: The chipsets to get information for
* \params[in] size: The size of the info structure in bytes
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_get_codec_info(struct adie_rtc_codec_info *codec_info, uint32_t size);

/**
* \brief
*		Retreives codec information for the list of chipset(s) specified
*       in the adie_rtc_codec_info_v2::handle array.
*
* \params[in/out] codec_info: The chipsets to get information for
* \params[in] size: The size of the info structure in bytes
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_get_codec_info_v2(struct adie_rtc_codec_info_v2 *codec_info, uint32_t size);

/**
* \brief
*		Get data for a register from the specified codec.
*
* \params[in/out] req: The register to get data for
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_get_register(struct adie_rtc_register_req *req);

/**
* \brief
*		Set data to a register for the specified codec.
*
* \params[in/out] req: The register to set data to
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_set_register(struct adie_rtc_register_req *req);

/**
* \brief
*		Get data for multiple registers from the specified codec.
*
* \params[in/out] req: The registers to get data for
* \params[in] size: The size of the request structure in bytes
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_set_multiple_registers(struct adie_rtc_multi_register_req *req, uint32_t size);

/**
* \brief
*		Set data to multiple registers for the specified codec.
*
* \params[in/out] req: The registers to set data for
* \params[in] size: The size of the request structure in bytes
*
* \return 0 on success, non-zero otherwise
*/
int32_t adie_rtc_get_multiple_registers(struct adie_rtc_multi_register_req *req, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* ADIE_RTC_API_H */

