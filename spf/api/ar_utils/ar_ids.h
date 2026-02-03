#ifndef AR_IDS_H_
#define AR_IDS_H_
/**
 * \file ar_ids.h
 * \brief
 *      GUID interpretation
 *
 *
 * \copyright
 *    Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *    SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_guids.h"
/**
 * Zero is an invalid instance ID.
 *
 * It cannot be used for a container, subgraph or a module-instance.
 */
#define AR_INVALID_INSTANCE_ID                           0

/**
 * spf static instance ID range is from 1-0x2000 (including both ends)
 * E.g. 1 is APM_MODULE_INSTANCE_ID
 *
 *
 * Module instance ID, container (instance) ID, subgraph (instance) ID must all be unique.
 * i.e. a number used for module-instance-ID cannot be used for container-ID and so on.
 *
 * The below ranges are applicable for module-instance-ID, subgraph ID, and container ID.
 *
 */
#define AR_SPF_STATIC_INSTANCE_ID_RANGE_BEGIN             1
#define AR_SPF_STATIC_INSTANCE_ID_RANGE_END               AR_NON_GUID(0x2000)

/**
 * Static instance ID range for platform driver 0x2001-0x4000 (including both ends)
 */
#define AR_PLATFORM_DRIVER_STATIC_INSTANCE_ID_RANGE_BEGIN   AR_NON_GUID(0x2001)
#define AR_PLATFORM_DRIVER_STATIC_INSTANCE_ID_RANGE_END     AR_NON_GUID(0x4000)

/**
 * Dynamic instance IDs starts from 0x4001. ARCT uses this range to assign instance IDs.
 * The range includes this number.
 *
 */
#define AR_DYNAMIC_INSTANCE_ID_RANGE_BEGIN                  AR_NON_GUID(0x4001)


/**
 * Following masks apply to Port-IDs
 *
 * Port-ID has to be unique for the module.
 * Two modules can have same port-ID
 *
 * Port-ID cannot be zero.
 */

#define AR_PORT_ID_INVALID                      0
/**
 * Control ports have MSB set. Data ports have MSB clear.
 * Static Control Ports have 2 Most significant bits set
 */
#define AR_PORT_DATA_TYPE_MASK                       AR_NON_GUID(0x80000000)
#define AR_PORT_DATA_TYPE_SHIFT                      31
#define AR_PORT_DATA_TYPE_DATA                       0
#define AR_PORT_DATA_TYPE_CONTROL                    1

#define AR_CONTROL_PORT_TYPE_MASK                    AR_NON_GUID(0x40000000)
#define AR_CONTROL_PORT_TYPE_SHIFT                   30
#define AR_CONTROL_PORT_TYPE_STATIC                  1      
#define AR_CONTROL_PORT_TYPE_DYNAMIC                 0

/**
 * LSB determines if a port id input (0) or output (1)
 * input - even
 * output - odd
 */
#define AR_PORT_DIR_TYPE_MASK                       AR_NON_GUID(0x00000001)
#define AR_PORT_DIR_TYPE_SHIFT                      0
#define AR_PORT_DIR_TYPE_INPUT                      0
#define AR_PORT_DIR_TYPE_OUTPUT                     1

#endif /* AR_IDS_H_ */

