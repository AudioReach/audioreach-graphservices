/**
*=============================================================================
* \file acdb_end_pack.h
*
* \brief
*      This file defines pack attributes for different compilers to be used to
*      pack aDSP API data structures.
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

/** @addtogroup acph_api_pack
@{ */

#if defined( __qdsp6__ )
/* No packing atrributes for Q6 compiler; all structs manually packed */
#elif defined( __GNUC__ ) && !defined( __INTEGRITY )
#ifndef ARSDK
__attribute__((packed, aligned(1)));
#endif
#elif defined( __INTEGRITY )
#elif defined( ACDB_WP_PACK )
#pragma pack( pop )
#pragma warning(pop)
#elif defined( __arm__ )
#elif defined( _MSC_VER ) && !defined(_KERNEL_MODE)
#pragma pack( pop )
#pragma warning(pop)
#elif defined(_KERNEL_MODE)
#else
#error "Unsupported compiler."
#endif /* __GNUC__ */

/** @} */  /* end_ addtogroup acph_api_pack */
