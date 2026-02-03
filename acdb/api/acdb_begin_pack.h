/**
*=============================================================================
* \file acdb_begin_pack.h
*
* \brief
*      This file defines pack attributes for different compilers to be used to
*      pack ACPH API data structures.
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
#elif defined( __INTEGRITY )
#elif defined( ACDB_WP_PACK )
#pragma warning( disable:4103 )  /* Another header changing "pack". */
#pragma pack( push, 1 )
#pragma warning(push)
#pragma warning(disable: 4200)
#elif defined( __arm__ )
#elif defined( _MSC_VER ) && !defined(_KERNEL_MODE)
#pragma warning( disable:4103 )  /* Another header changing "pack". */
#pragma pack( push, 1 )
#pragma warning(push)
#pragma warning(disable: 4200)
#elif defined(_KERNEL_MODE)
#pragma warning(disable: 4200)
#else
#error "Unsupported compiler."
#endif /* __GNUC__ */

/** @} */ /* end_addtogroup acph_api_pack */
