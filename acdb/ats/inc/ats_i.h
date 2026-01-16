#ifndef __ATS_H_I__
#define __ATS_H_I__
/**
*=============================================================================
* \file ats.h
* \brief
*                          A T S  I N T E R N A L
*                           H E A D E R  F I L E
*
*     This header file contains all the definitions necessary for the Audio
*     Tuning Service to handle request buffer and operate ACDB
*
* \copyright
*     Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*     SPDX-License-Identifier: BSD-3-Clause
*
*=============================================================================
*/

#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "acdb.h"

#ifdef __cplusplus
extern "C" {
#endif

/*-----------------------------------------------------------------------------
** flag, page size, and buffer length definition for ats_main_buffer
*----------------------------------------------------------------------------*/
#define ATS_1_KB                            1024UL
#define ATS_BUFFER_LENGTH                   0x200000
#define ATS_MIN_BUFFER_LENGTH               ATS_1_KB * 32UL
#define ATS_HEADER_LENGTH                   8

#define ATS_SERVICE_COMMAND_ID_LENGTH       4
#define ATS_DATA_LENGTH_LENGTH              4
#define ATS_ERROR_CODE_LENGTH               4
#define ATS_ERROR_FRAME_LENGTH              12

#define ATS_SERVICE_COMMAND_ID_POSITION     0
#define ATS_DATA_LENGTH_POSITION            4
#define ATS_ACDB_BUFFER_POSITION            8

/*-----------------------------------------------------------------------------
* Macros for ATS Services
*----------------------------------------------------------------------------*/

/**< Extract the service id from the MSW of the 4byte service command id x*/
#define ATS_GET_SERVICE_ID(x) ((0xFFFF0000 & x))

#define ATS_SERVICE_ID_INITIALIZER(x){ (char)(x >> 24), (char)(x >> 16), 0}
#define ATS_SEVICE_ID_STR_LEN (3)
/**< Set the 'x'(the service command id) to the arr to create a service command id string x.
* arr must be initialized with 3 bytes
*/
#define ATS_SERVICE_ID_STR(arr, sz, x) \
do {\
int svc_str_len = ATS_SEVICE_ID_STR_LEN; \
if(sz == svc_str_len)\
{ \
arr[0] = (char)(x >> 24); \
arr[1] = (char)(x >> 16); \
arr[2] = 0; \
}\
break; \
}while(0)

#define ATS_READ_SEEK_I(value, buf, offset, type)\
do {\
value = *(uint32_t*)&buf[offset]; \
offset += sizeof(type); \
break; \
}while(0)

#define ATS_READ_SEEK_I_ANY(value, buf, offset, type)\
do {\
value = *(type*)&buf[offset]; \
offset += sizeof(type); \
break; \
}while(0)

#define ATS_READ_SEEK_UI32(value, buf, offset) \
    ATS_READ_SEEK_I(value, buf, offset, uint32_t)

#define ATS_READ_SEEK_I32(value, buf, offset) \
    ATS_READ_SEEK_I(value, buf, offset, int32_t)

#define ATS_READ_SEEK_UI16(value, buf, offset) \
    ATS_READ_SEEK_I_ANY(value, buf, offset, uint16_t)

/**< Extract the command id from the LSW of the 4byte service command id x*/
#define ATS_GET_COMMAND_ID(x) ((0x0000FFFFul & x))

/**< Defines command IDs for the Online Calibration service */
#define ATS_ONLINE_CMD_ID(x) ((0x4F4Eul << 16) | (0xFFFFul & x))
#define ATS_ONLINE_SERVICE_ID (0x4F4Eul << 16)

/**< Defines command IDs for the Real Time Tuning service */
#define ATS_RTC_SERVICE_ID (0x5254ul << 16)
#define ATS_RTC_CMD_ID(x) ((0x5254ul << 16) | (0xFFFFul & x))

/**< Defines command IDs for the Data logging service */
#define ATS_DLS_SERVICE_ID (0x524dul << 16)
#define ATS_DLS_CMD_ID(x) ((0x524dul << 16) | (0xFFFFul & x))

/**< Defines command IDs for the File Transfer service */
#define ATS_FTS_CMD_ID(x) ((0x4654ul << 16) | (0xFFFFul & x))
#define ATS_FTS_SERVICE_ID (0x4654ul << 16)

/**< Defines command IDs for the Media Control Service */
#define ATS_MCS_CMD_ID(x) ((0x4D43ul << 16) | (0xFFFFul & x))
#define ATS_MCS_SERVICE_ID (0x4D43ul << 16)

/**< Defines command IDs for the Adie Codec RTC service */
#define ATS_CODEC_RTC_CMD_ID(x) ((0x4152ul << 16) | (0xFFFFul & x))
#define ATS_CODEC_RTC_SERVICE_ID (0x4152ul << 16)

#define ATS_MAX_FILENAME_LENGTH 256

/*-----------------------------------------------------------------------------
* Common Types
*----------------------------------------------------------------------------*/

typedef struct _ats_buffer_t AtsBuffer;
struct _ats_buffer_t
{
    uint32_t buffer_size;
    uint8_t *buffer;
};

typedef struct _ats_buffer_man_t AtsBufferManager;
struct _ats_buffer_man_t
{
    /**< Main ATS buffer used for storing the response of commands*/
    AtsBuffer main_buffer;
    /**< Main ATS Server message buffer used for storing complete messages recieved from TCP/IP clients*/
    AtsBuffer msg_buffer;
    /**< Main ATS Server recieve buffer used for storing messages recieved from TCP/IP clients*/
    AtsBuffer recieve_buffer;
};

extern AtsBufferManager *ats_buffer_manager;
extern AtsBuffer ats_main_buffer;

//TODO: Move to bottom of file
//void GetBufferManager(AtsBufferManager** buffer_man)
//{
//    *buffer_man = ats_buffer_manager;
//}

/**< Holds the version information*/
typedef struct _ats_version_t AtsVersion;
#include "acdb_begin_pack.h"
struct _ats_version_t
{
    /**< Major version*/
    uint32_t major;
    /**< Minor version*/
    uint32_t minor;
}
#include "acdb_end_pack.h"
;
/*-----------------------------------------------------------------------------
* ATS Commands
*----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_VERSION Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_VERSION
\{ */

/**
	Queries for the ATS Real Time Calibration service version.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_GET_VERSION.
	\param[in] cmd
		There is no input structure; set this to NULL.
	\param[in] cmd_size
		There is no input structure; set this to 0.
	\param[out] rsp
		Pointer to AtsVersion
	\param[in] rsp_size
		Size of AtsVersion

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_GET_VERSION ATS_RTC_CMD_ID(1)
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_VERSION */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_ACTIVE_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_ACTIVE_INFO
\{ */

/**
	Queries ATS for the active usecase information. The active usecase is
	provided by GSL.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_GET_ACTIVE_INFO.
	\param[in] cmd
		Pointer to AtsActiveUsecaseInfo.
	\param[in] cmd_size
		Size of AtsActiveUsecaseInfo.
	\param[out] rsp
		Pointer to AtsCmdRtGetActiveInfoRsp
	\param[in] rsp_size
		Size of AtsCmdRtGetActiveInfoRsp

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_GET_ACTIVE_INFO ATS_RTC_CMD_ID(2)
/**< Holds the active usecase information provided by GSL*/
typedef struct ats_cmd_rt_active_usecase_info_t AtsActiveUsecaseInfo;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_active_usecase_info_t
{
	/**< Handle to a usecase(collection of graphs) provided by gsl_open*/
	uint32_t usecase_handle;
	/**< Number of active graphs*/
	uint32_t num_graphs;
	/**< List of Graph Key vectors for each graph*/
	AcdbGraphKeyVector *graph_key_vector;
	/**< Number of Calibration Key vectors. There is one for each Graph Key Vector*/
	uint32_t num_cal_key_vectors;
	/**< Calibration key vector*/
	AcdbGraphKeyVector *cal_key_vector;
}
#include "acdb_end_pack.h"
;

/**< The response structure for ATS_CMD_RT_GET_ACTIVE_INFO*/
typedef struct ats_cmd_rt_get_active_info_rsp_t AtsCmdRtGetActiveInfoRsp;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_active_info_rsp_t
{
	/**< Total size of the active usecase information*/
	uint32_t size;
	/**< Number of active usecases*/
	uint32_t num_usecases;
	/**< List of currently active usecases*/
	AtsActiveUsecaseInfo *active_usecases;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_ACTIVE_INFO */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT
\{ */

/**
	Queries ATS for the non-persistent calibration data for all SPF modules
	instances for a given subgraph.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT.
	\param[in] cmd
		Pointer to AtsCmdRtGetCalDataNonPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtGetCalDataNonPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT ATS_RTC_CMD_ID(3)
/**< The request structure for ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT*/
typedef struct ats_cmd_rt_get_cal_data_non_persist_req_t AtsCmdRtGetCalDataNonPersistentReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_cal_data_non_persist_req_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
	uint32_t subgraph_id;
	/**< Size of the subgraph calibration data*/
	uint32_t data_size;
	/**< [in/out] Subgraph calibration data. Format:
	[module_id, param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *subgraph_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_CAL_DATA_NON_PERSISTENT */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_CAL_DATA_PERSISTENT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_CAL_DATA_PERSISTENT
\{ */

/**
	Queries ATS for the persistent calibration data for all SPF modules
	instances for a given subgraph.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_GET_CAL_DATA_PERSISTENT.
	\param[in] cmd
		Pointer to AtsCmdRtGetCalDataPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtGetCalDataPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_GET_CAL_DATA_PERSISTENT ATS_RTC_CMD_ID(4)
/**< The request structure for ATS_CMD_RT_GET_CAL_DATA_PERSISTENT*/
typedef struct ats_cmd_rt_get_cal_data_persist_req_t AtsCmdRtGetCalDataPersistentReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_cal_data_persist_req_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
	uint32_t subgraph_id;
	/**< Size of the subgraph calibration data*/
	uint32_t data_size;
	/**< [in/out] Subgraph calibration data. Format:
	[module_id, param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *subgraph_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_CAL_DATA_PERSISTENT */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT
\{ */

/**
	Queries ATS for the globally-persisent calibration data for a signle
	PID of a module instance from GSL.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT.
	\param[in] cmd
		Pointer to AtsCmdRtGetCalDataGblPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtGetCalDataGblPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT ATS_RTC_CMD_ID(5)
/**< The request structure for ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT*/
typedef struct ats_cmd_rt_get_cal_data_global_persist_req_t AtsCmdRtGetCalDataGblPersistentReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_cal_data_global_persist_req_t
{
	/**< Calibration identifier*/
	uint32_t cal_id;
	/**< Size of the parameter calibration data*/
	uint32_t data_size;
	/**< [in/out] Parameter calibration data. Format:
	[param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *param_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_CAL_DATA_GBL_PERSISTENT */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT
\{ */

/**
	Set non-persistent subgraph calibration data to SPF.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT.
	\param[in] cmd
		Pointer to AtsCmdRtSetCalDataNonPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtSetCalDataNonPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT ATS_RTC_CMD_ID(6)
/**< The request structure for ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT*/
typedef struct ats_cmd_rt_set_cal_data_non_persist_req_t AtsCmdRtSetCalDataNonPersistentReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_set_cal_data_non_persist_req_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
	uint32_t subgraph_id;
	/**< Size of the subgraph calibration data*/
	uint32_t data_size;
	/**< [out] Subgraph calibration data. Format:
	[module_id, param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *subgraph_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_SET_CAL_DATA_NON_PERSISTENT */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_SET_CAL_DATA_PERSISTENT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_SET_CAL_DATA_PERSISTENT
\{ */

/**
	Set persistent subgraph calibration data to SPF.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_SET_CAL_DATA_PERSISTENT.
	\param[in] cmd
		Pointer to AtsCmdRtSetCalDataPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtSetCalDataPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_SET_CAL_DATA_PERSISTENT ATS_RTC_CMD_ID(7)
/**< The request structure for ATS_CMD_RT_SET_CAL_DATA_PERSISTENT*/
typedef struct ats_cmd_rt_set_cal_data_persist_req_t AtsCmdRtSetCalDataPersistentReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_set_cal_data_persist_req_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
	uint32_t subgraph_id;
	/**< Size of the subgraph calibration data*/
	uint32_t data_size;
	/**< [out] Subgraph calibration data. Format:
	[module_id, param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *subgraph_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_SET_CAL_DATA_PERSISTENT */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH
 \{ */

/**
    Notifies GSL about graph modifications that are going to take place.

    \param[in] cmd_id
    Command ID is ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH.
    \param[in] cmd
    Pointer to AtsCmdRtGmUpdateDataReq.
    \param[in] cmd_size
    Size of AtsCmdRtGmUpdateDataReq.
    \param[out] rsp
    There is no output structure; set this to NULL.
    \param[in] rsp_size
    There is no output structure; set this to 0.

    \return
    - AR_EOK -- Command executed successfully.
    - AR_EBADPARAM -- Invalid input parameters were provided.
    - AR_EFAILED -- Command execution failed.

    \sa none
*/
#define ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH ATS_RTC_CMD_ID(8)

typedef struct _ats_list_t AtsList;
#include "acdb_begin_pack.h"
struct _ats_list_t
{
    /**< Number of items in list */
    uint32_t count;
    /**< list of items */
    void *list;
}
#include "acdb_end_pack.h"
;

/**< The request structure for ATS_CMD_RT_GM_UPDATE_DATA*/
typedef struct ats_cmd_rt_gm_prep_change_graph_req_t AtsCmdRtGmPrepChangeGraphReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_gm_prep_change_graph_req_t
{
    /**< Handle to a graph provided by gsl_open */
    uint32_t graph_handle;
    /**< The old graph keys for the updated/new usecase */
    AcdbGraphKeyVector old_graph_key_vector;
    /**< The new graph keys for the updated/new usecase */
    AcdbGraphKeyVector new_graph_key_vector;
    /**< The updated calibration keys for the updated/new usecase */
    AcdbGraphKeyVector new_cal_key_vector;
    /**< List of subgraph after modifications */
    AtsList post_modification_subgraph_list;
    /**< List of subgraph modified at run-time */
    AtsList modified_subgraph_list;
    /**< List of subgraph <src, dst> pairs */
    AtsList subgraph_conn_list;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GM_CHANGE_GRAPH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GM_UPDATE_DATA
 \{ */

/**
    Notifies GSL about graphs that have been prepared using ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH

    \param[in] cmd_id
    Command ID is ATS_CMD_RT_GM_CHANGE_GRAPH.
    \param[in] cmd
    Pointer to AtsCmdRtGmUpdateDataReq.
    \param[in] cmd_size
    Size of AtsCmdRtGmUpdateDataReq.
    \param[out] rsp
    There is no output structure; set this to NULL.
    \param[in] rsp_size
    There is no output structure; set this to 0.

    \return
    - AR_EOK -- Command executed successfully.
    - AR_EBADPARAM -- Invalid input parameters were provided.
    - AR_EFAILED -- Command execution failed.

    \sa none
*/
#define ATS_CMD_RT_GM_CHANGE_GRAPH ATS_RTC_CMD_ID(9)

/**< The request structure for ATS_CMD_RT_GM_CHANGE_GRAPH*/
typedef struct ats_cmd_rt_gm_change_graph_req_t AtsCmdRtGmChangeGraphReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_gm_change_graph_req_t
{
    /**< Handle to a graph provided by gsl_open */
    uint32_t graph_handle;
    /**< The old graph keys for the updated/new usecase */
    AcdbGraphKeyVector old_graph_key_vector;
    /**< The new graph keys for the updated/new usecase */
    AcdbGraphKeyVector new_graph_key_vector;
    /**< The updated calibration keys for the updated/new usecase */
    AcdbGraphKeyVector new_cal_key_vector;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GM_UPDATE_DATA */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_OPEN_GRAPH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_OPEN_GRAPH
 \{ */

/**
    Opens a graph on GSL and returns a graph handle for the opened graph

    \param[in] cmd_id
    Command ID is ATS_CMD_RT_GM_CHANGE_GRAPH.
    \param[in] cmd
    Pointer to AtsCmdRtGmUpdateDataReq.
    \param[in] cmd_size
    Size of AtsCmdRtGmUpdateDataReq.
    \param[out] rsp
    A uint32_t graph handle
    \param[in] rsp_size
    Size of a uint32_t

    \return
    - CASA_EOK -- Command executed successfully.
    - CASA_EBADPARAM -- Invalid input parameters were provided.
    - CASA_EFAILED -- Command execution failed.
    - CASA_EHANDLE -- Graph handle is invalid.

    \sa
    ATS_CMD_RT_CLOSE_GRAPH
*/
#define ATS_CMD_RT_OPEN_GRAPH ATS_RTC_CMD_ID(10)

/**< The request structure for ATS_CMD_RT_OPEN_GRAPH*/
typedef struct ats_cmd_rt_graph_open_req_t AtsCmdRtGraphOpenReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_graph_open_req_t
{
    /**< The new graph keys for the updated/new usecase */
    AcdbGraphKeyVector graph_key_vector;
    /**< The updated calibration keys for the updated/new usecase */
    AcdbGraphKeyVector cal_key_vector;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_OPEN_GRAPH */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_OPEN_GRAPH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_CLOSE_GRAPH
 \{ */

/**
    Closes an open graph on GSL

    \param[in] cmd_id
    Command ID is ATS_CMD_RT_CLOSE_GRAPH.
    \param[in] cmd
    Pointer to AtsCmdRtGraphClose.
    \param[in] cmd_size
    Size of AtsCmdRtGraphClose.
    \param[out] rsp
    There is no output structure; set this to NULL.
    \param[in] rsp_size
    There is no output structure; set this to 0.
    Size of AtsCmdRtGraphClose.

    \return
    - CASA_EOK -- Command executed successfully.
    - CASA_EBADPARAM -- Invalid input parameters were provided.
    - CASA_EFAILED -- Command execution failed.
    - CASA_EHANDLE -- Graph handle is invalid.

    \sa
    ATS_CMD_RT_OPEN_GRAPH
*/
#define ATS_CMD_RT_CLOSE_GRAPH ATS_RTC_CMD_ID(11)

/**< The request structure for ATS_CMD_RT_CLOSE_GRAPH*/
typedef struct ats_cmd_rt_graph_close_req_t AtsCmdRtGraphCloseReq;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_graph_close_req_t
{
    /**< Handle to a graph provided by gsl_open */
    uint32_t graph_handle;
}
#include "acdb_end_pack.h"
;

/** \} */ /* end_addtogroup ATS_CMD_RT_CLOSE_GRAPH */


/* ---------------------------------------------------------------------------
* ATS_CMD_RT_NOTIFY_CONNECTION_STATE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_NOTIFY_CONNECTION_STATE
 \{ */

/**
*     Notifies the Audio Driver about the ATS client's connection state.
*
*     NOTE: This API must be called before performing any RTGM operations with
*     ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH and ATS_CMD_RT_GM_CHANGE_GRAPH
*
*     \param[in] cmd_id
*       Command ID is ATS_CMD_RT_GM_SET_SESSION_STATE.
*     \param[in] cmd
*       Pointer to AtsCmdRtSetSessionState.
*     \param[in] cmd_size
*       Size of AtsCmdRtSetSessionState.
*     \param[out] rsp
*       There is no output structure; set this to NULL.
*     \param[in] rsp_size
*       There is no output structure; set this to 0.
*       Size of AtsCmdRtGraphClose.
*
*     \return
*     - CASA_EOK -- Command executed successfully.
*     - CASA_EBADPARAM -- Invalid input parameters were provided.
*     - CASA_EFAILED -- Command execution failed.
*     - CASA_EHANDLE -- Graph handle is invalid.
*
*     \sa
*     ATS_CMD_RT_GM_PREPARE_CHANGE_GRAPH
*     ATS_CMD_RT_GM_CHANGE_GRAPH
*/
#define ATS_CMD_RT_NOTIFY_CONNECTION_STATE ATS_RTC_CMD_ID(12)

 /**< The request structure for ATS_CMD_RT_CLOSE_GRAPH*/
typedef struct ats_cmd_rt_notify_connection_state_t AtsCmdRtNotifyConnectionState;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_notify_connection_state_t
{
    /**< Handle to a graph provided by gsl_open */
    uint32_t graph_handle;
}
#include "acdb_end_pack.h"
;

/** \} */ /* end_addtogroup ATS_CMD_RT_NOTIFY_CONNECTION_STATE */

/* ---------------------------------------------------------------------------
* ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2
\{ */

/**
*	Retrieves persistent calibration for a subgraph from the shared memory
*   managed by GSL. Calibration is returned for a persistent PIDs that
*   have the tool policies:
*       1. RTC_READ_ONLY
*       2. RTC_CALIBRATION
*
*   The format of the response blob is:
*
*           *------------------------------------------*
*           |               Buffer Size                |
*           *------------------------------------------*
*           | <IID, PID, Size, Error Code, Data[Size]> |
*           *------------------------------------------*
*           |                 ...                      |
*           *------------------------------------------*
*           | <IID, PID, Size, Error Code, Data[Size]> |
*           *------------------------------------------*
*
*	\param[in] cmd_id
*		Command ID is ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2.
*	\param[in] cmd
*		Pointer to AtsCmdRtGetCalDataPersistentReq.
*	\param[in] cmd_size
*		Size of AtsCmdRtGetCalDataPersistentReq.
*	\param[out] rsp
*		Pointer to AcdbBlob
*	\param[in] rsp_size
*		Size of AcdbBlob
*
*	\return
*		- AR_EOK -- Command executed successfully.
*		- AR_EBADPARAM -- Invalid input parameters were provided.
*		- AR_EFAILED -- Command execution failed.
*
*	\sa TODO
*/
#define ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2 ATS_RTC_CMD_ID(13)

typedef enum ats_calibration_type_t
{
    ATS_CAL_TYPE_AUDIO      = 0x0,
    ATS_CAL_TYPE_VOICE      = 0x1,
}AtsCalibrationType;

typedef struct ats_uint_list_za_t AtsUintList;
#include "acdb_begin_pack.h"
struct ats_uint_list_za_t
{
    uint32_t count;
    uint32_t list[0];
}
#include "acdb_end_pack.h"
;

/**< The request structure for ATS_CMD_RT_GET_CAL_DATA_PERSISTENT*/
typedef struct ats_cmd_rt_get_cal_data_persist_req_v2_t AtsCmdRtGetCalDataPersistV2Req;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_cal_data_persist_req_v2_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
    uint32_t subgraph_id;
    /**< The ID of the processor the sugraph is running on */
    uint32_t proc_id;
    /**< The type of subgraph cal data: voice, audio, etc.. */
    uint32_t cal_type;
	/**< Size of [iid, pid] pair list */
	uint32_t list_size;
	/**< List of IID, PIDs to get persistent cal for */
    AtsUintList iid_pid_pair_list;
}
#include "acdb_end_pack.h"
;

/**< The response structure for ATS_CMD_RT_GET_CAL_DATA_PERSISTENT*/
typedef struct ats_cmd_rt_get_cal_data_persist_v2_rsp_t AtsCmdRtGetCalDataPersistV2Rsp;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_get_cal_data_persist_v2_rsp_t
{
    /**< Handle to a graph provided by gsl_open*/
    uint32_t graph_handle;
    /**< Subgraph ID*/
    uint32_t subgraph_id;
    /**< Size of the subgraph calibration data*/
    uint32_t data_size;
    uint32_t sg_cal_type;
    /**< [in/out] Subgraph calibration data. Format:
    [module_id, param_id, param_size, err_code, payload[param_size]]
    */
    uint32_t count;
    uint32_t *iid_pid_list;
    AcdbUintList param_list;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_GET_CAL_DATA_PERSISTENT_V2 */


/* ---------------------------------------------------------------------------
* ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2
\{ */

/**
	Set persistent subgraph calibration data to SPF.

	\param[in] cmd_id
		Command ID is ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2.
	\param[in] cmd
		Pointer to AtsCmdRtSetCalDataPersistentReq.
	\param[in] cmd_size
		Size of AtsCmdRtSetCalDataPersistentReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2 ATS_RTC_CMD_ID(14)
/**< The request structure for ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2*/
typedef struct ats_cmd_rt_set_cal_data_persist_req_v2_t AtsCmdRtSetCalDataPersistentReqV2;
#include "acdb_begin_pack.h"
struct ats_cmd_rt_set_cal_data_persist_req_v2_t
{
	/**< Handle to a graph provided by gsl_open*/
	uint32_t graph_handle;
	/**< Subgraph ID*/
	uint32_t subgraph_id;
    /**< Processor ID*/
    uint32_t proc_id;
	/**< Size of the subgraph calibration data*/
	uint32_t data_size;
	/**< [out] Subgraph calibration data. Format:
	[module_id, param_id, param_size, err_code, payload[param_size]]
	*/
	uint8_t *subgraph_cal_data;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_RT_SET_CAL_DATA_PERSISTENT_V2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_PLAY Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_PLAY
\{ */

/**
	Start a playback session with the provided usecase, calibration, and
	audio file.

	\param[in] cmd_id
		Command ID is ATS_CMD_MCS_PLAY.
	\param[in] cmd
		Pointer to AtsCmdMcsPlayReq.
	\param[in] cmd_size
		Size of AtsCmdMcsPlayReq.
	\param[out] rsp
		There is no ouput structure; set this to NULL.
	\param[in] rsp_size
		There is no ouput structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_MCS_PLAY ATS_MCS_CMD_ID(1)

/**< Specifies the set of playback modes used in the ATS_CMD_MCS_PLAY request*/
typedef enum ATS_MCS_PLAYBACK_MODE
{
    ATS_PLAYBACK_REGULAR,
    ATS_PLAYBACK_ANC_S_PATH,
    ATS_PLAYBACK_ANC_E_PATH,
    ATS_PLAYBACK_RAS,
} AtsMcsPlaybackMode;

/**< Media properties for a device or stream*/
typedef struct ats_mcs_properties_t McsProperties;
#include "acdb_begin_pack.h"
struct ats_mcs_properties_t
{
    /**< The device/stream sample rate*/
    uint32_t sample_rate;
    /**< The bit width of each sample*/
    uint16_t bit_width;
    /**< Indicates the alignment of bits_per_sample in sample_word_size.Relevant only when bits_per_sample is 24 and word_size is 32*/
    uint16_t alignment;
    /**< Bits needed to store one sample*/
    uint16_t bits_per_sample;
    /**< Q factor of the PCM data*/
    uint16_t q_factor;
    /**< Indicates whether PCM samples are stored in little endian or big endian format.*/
    uint16_t endianness;
    /**< Number of channels*/
    uint16_t num_channels;
    /**< Determines what channels are used. Up to 32 channels are supported. If not supported set to 0*/
    uint8_t *channel_mapping;
}
#include "acdb_end_pack.h"
;

/**< The request structure for ATS_CMD_MCS_PLAY*/
typedef struct ats_cmd_mcs_play_req_t AtsCmdMcsPlayReq;
#include "acdb_begin_pack.h"
struct ats_cmd_mcs_play_req_t
{
    /**< playback device properties*/
    McsProperties device_properties;
    /**< playback stream properties*/
    McsProperties stream_properties;
    /**< Graph Key Vector representing the playback usecase*/
    AcdbGraphKeyVector graph_key_vector;
    /**< Type of playback: 0(regular), 1(anc_spath), 2(anc_epath), 3(ras)*/
    AtsMcsPlaybackMode playback_mode;
    /**< Playback duration in seconds*/
    int32_t playback_duration_sec;
    /**< Length of the file name/path*/
    int32_t filename_len;
    /**< Name of/path to file to save recording to*/
    char filename[ATS_MAX_FILENAME_LENGTH];
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_MCS_PLAY */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_RECORD Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_RECORD
\{ */

/**
	Start a record session and save the output to the specified file using
	the provided record usecase, duration, and calibration.

	\param[in] cmd_id
		Command ID is ATS_CMD_MCS_RECORD.
	\param[in] cmd
		Pointer to AtsCmdMcsRecordReq.
	\param[in] cmd_size
		Size of AtsCmdMcsRecordReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_MCS_RECORD ATS_MCS_CMD_ID(2)

/**< Specifies the set of recording modes used in the ATS_CMD_MCS_RECORD request*/
typedef enum ATS_MCS_RECORD_MODE
{
    ATS_RECORD_REGULAR,
    ATS_RECORD_ANC_P_PATH,
    ATS_RECORD_ANC_S_PATH,
    ATS_RECORD_ANC_E_PATH
} AtsMcsRecordMode;

/**< The request structure for ATS_CMD_MCS_RECORD*/
typedef struct ats_cmd_mcs_record_req_t AtsCmdMcsRecordReq;
#include "acdb_begin_pack.h"
struct ats_cmd_mcs_record_req_t
{
    /**< record device properties*/
    McsProperties device_properties;
    /**< record stream properties*/
    McsProperties stream_properties;
    /**< Graph Key Vector representing the record usecase*/
    AcdbGraphKeyVector graph_key_vector;
    /**< Type of record: 0(regular), 1(aanc_path), 2(aanc_spath), 3(aanc_epath)*/
    AtsMcsRecordMode record_mode;
    /**< Save recording to file: 0 (ignore write), 1 (write data)*/
    uint32_t write_to_file;
    /**< Record duration in seconds*/
    int32_t record_duration_sec;
    /**< Length of the file name/path*/
    int32_t filename_len;
    /**< Name of/path to file to save recording to*/
    char filename[ATS_MAX_FILENAME_LENGTH];
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_MCS_RECORD */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_PLAY_RECORD Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_PLAY_RECORD
\{ */

/**
	Start playback and record simultaneously.

	\param[in] cmd_id
		Command ID is ATS_CMD_MCS_PLAY_RECORD.
	\param[in] cmd
		Pointer to AtsCmdMcsPlayRecordReq.
	\param[in] cmd_size
		Size of AtsCmdMcsPlayRecordReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa
		- AtsCmdMcsPlayReq
		- AtsCmdMcsRecordReq
*/
#define ATS_CMD_MCS_PLAY_RECORD ATS_MCS_CMD_ID(3)
/**< The request structure for ATS_CMD_MCS_PLAY_RECORD*/
typedef struct ats_cmd_mcs_play_record_req_t AtsCmdMcsPlayRecordReq;
#include "acdb_begin_pack.h"
struct ats_cmd_mcs_play_record_req_t
{
	AtsCmdMcsPlayReq playback_session;
	AtsCmdMcsRecordReq record_session;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_MCS_PLAY_RECORD */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_STOP Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_STOP
\{ */

/**
	Stop the active playback, record, or playback-record session. Releases all
	resources allocated to MCS.

	\param[in] cmd_id
		Command ID is ATS_CMD_MCS_STOP.
	\param[in] cmd
		There is no intput structure; set this to NULL.
	\param[in] cmd_size
		There is no intput structure; set this to 0.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.
	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_MCS_STOP ATS_MCS_CMD_ID(4)
/** \} */ /* end_addtogroup ATS_CMD_MCS_STOP */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_PLAY_2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_PLAY_2
\{ */

/**
    Start a playback session with the provided usecase, calibration, and
    audio file. This provides the same functionality as ATS_CMD_MCS_PLAY
    except that it allows the client to apply calibration, tag config, and
    tag custom config data before starting the usecase.

    See MCS_CMD_PLAY_2 in mcs_api.h for command/response input and output

    \sa ATS_CMD_MCS_PLAY
*/
#define ATS_CMD_MCS_PLAY_2 ATS_MCS_CMD_ID(5)
/** \} */ /* end_addtogroup ATS_CMD_MCS_PLAY_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_RECORD_2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_RECORD_2
\{ */

/**
    Start a record session and save the output to the specified file using
	the provided record usecase, duration, and calibration. This provides the
    same functionality as ATS_CMD_MCS_RECORD except that it allows the client
    to apply calibration, tag config, and tag custom config data before

    See MCS_CMD_REC_2 in mcs_api.h for command/response input and output

    \sa ATS_CMD_MCS_RECORD
*/
#define ATS_CMD_MCS_RECORD_2 ATS_MCS_CMD_ID(6)
/** \} */ /* end_addtogroup ATS_CMD_MCS_RECORD_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_MULTI_PLAY_REC Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_MULTI_PLAY_REC
\{ */

/**
    Start the active playback, record, or playback-record session. Releases all
    resources allocated to MCS.

   See MCS_CMD_MULTI_PLAY_REC in mcs_api.h for command/response input and output

    \sa ATS_CMD_MCS_PLAY_REC
*/
#define ATS_CMD_MCS_MULTI_PLAY_REC ATS_MCS_CMD_ID(7)
/** \} */ /* end_addtogroup ATS_CMD_MCS_MULTI_PLAY_REC */

/* ---------------------------------------------------------------------------
* ATS_CMD_MCS_STOP_2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_MCS_STOP_2
\{ */

/**
    Stop the active playback, record, or playback-record session. Releases all
    resources allocated to MCS.

    See MCS_CMD_STOP_2 mcs_api.h for command/response input and output

    \sa ATS_CMD_MCS_STOP
*/
#define ATS_CMD_MCS_STOP_2 ATS_MCS_CMD_ID(8)
/** \} */ /* end_addtogroup ATS_CMD_MCS_STOP_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_FTS_OPEN_FILE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_FTS_OPEN_FILE
\{ */

/**
	Open or create a file on the file system with write permissions.

	\param[in] cmd_id
		Command ID is ATS_CMD_FTS_OPEN_FILE.
	\param[in] cmd
		Pointer to AtsCmdFtsOpenFileReq.
	\param[in] cmd_size
		Size of AtsCmdFtsOpenFileReq.
	\param[out] rsp
		4 byte file index
	\param[in] rsp_size
		Size of uint32_t

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_FTS_OPEN_FILE ATS_FTS_CMD_ID(1)
/**< The request structure for ATS_CMD_FTS_OPEN_FILE*/
typedef struct ats_cmd_fts_open_file_req_t AtsCmdFtsOpenFileReq;
#include "acdb_begin_pack.h"
struct ats_cmd_fts_open_file_req_t
{
    /**< File path length*/
    uint32_t file_path_length;
	/**< File path*/
	char *file_path;
	/**< AR file access flag*/
	uint32_t access;
}
#include "acdb_end_pack.h"
;

/** \} */ /* end_addtogroup ATS_CMD_FTS_OPEN_FILE */

/* ---------------------------------------------------------------------------
* ATS_CMD_FTS_WRITE_FILE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_FTS_WRITE_FILE
\{ */

/**
	Writes data to a file using the provided file handle.

	\param[in] cmd_id
		Command ID is ATS_CMD_FTS_WRITE_FILE.
	\param[in] cmd
		Pointer to AtsCmdFtsWriteFileReq.
	\param[in] cmd_size
		Size of AtsCmdFtsWriteFileReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa
		- ATS_CMD_FTS_OPEN_FILE
*/
#define ATS_CMD_FTS_WRITE_FILE ATS_FTS_CMD_ID(2)
/**< The request structure for ATS_CMD_FTS_WRITE_FILE*/
typedef struct ats_cmd_fts_write_file_req_t AtsCmdFtsWriteFileReq;
#include "acdb_begin_pack.h"
struct ats_cmd_fts_write_file_req_t
{
	/**< File index for a file to write to*/
	uint32_t findex;
    /**< [in] Size of the data to write*/
    uint32_t write_size;
	/**< Pointer to the data to be written*/
	void *buf_ptr;
	/**< [out] Number of bytes that are written*/
	uint32_t *bytes_writen;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_FTS_WRITE_FILE */

/* ---------------------------------------------------------------------------
* ATS_CMD_FTS_CLOSE_FILE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_FTS_CLOSE_FILE
\{ */

/**
	Closes a file using the provided file handle.

	\param[in] cmd_id
		Command ID is ATS_CMD_FTS_CLOSE_FILE.
	\param[in] cmd
		Pointer to AtsCmdFtsCloseFileReq.
	\param[in] cmd_size
		Size of AtsCmdFtsCloseFileReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa
		- ATS_CMD_FTS_OPEN_FILE
*/
#define ATS_CMD_FTS_CLOSE_FILE ATS_FTS_CMD_ID(3)
/**< The request structure for ATS_CMD_FTS_CLOSE_FILE*/
typedef struct ats_cmd_fts_close_file_req_t AtsCmdFtsCloseFileReq;
#include "acdb_begin_pack.h"
struct ats_cmd_fts_close_file_req_t
{
	/**< File index for a file to close*/
	uint32_t findex;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_FTS_CLOSE_FILE */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_GET_VERSION Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_GET_VERSION
\{ */

/**
	Queries ATS for the ADIE(Codec) Service version.

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_GET_VERSION.
	\param[in] cmd
		There is no input structure; set this to NULL.
	\param[in] cmd_size
		There is no input structure; set this to 0.
	\param[out] rsp
		Pointer to AtsVersion
	\param[in] rsp_size
		Size of AtsVersion

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
//#define ATS_CMD_ADIE_GET_VERSION ATS_CODEC_RTC_CMD_ID(1)
/** \} */ /* end_addtogroup ATS_CMD_ADIE_GET_VERSION */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_GET_CODEC_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_GET_CODEC_INFO
\{ */

/**
	Queries ATS for the Real Time Tuning service version.

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_GET_CODEC_INFO.
	\param[in] cmd
		There is no input structure; set this to NULL.
	\param[in] cmd_size
		There is no input structure; set this to 0.
	\param[out] rsp
		Pointer to AtsCmdAdieGetCodecInfoRsp
	\param[in] rsp_size
		Size of AtsCmdAdieGetCodecInfoRsp

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_ADIE_GET_CODEC_INFO ATS_CODEC_RTC_CMD_ID(1)
/**< Holds the chipset ID and version information for a codec*/
typedef struct codec_properties_t CodecProperties;
#include "acdb_begin_pack.h"
struct codec_properties_t
{
	/**< Codec handle*/
	uint32_t handle;
	/**< ID of the codec chipset*/
	uint32_t chipset_id;
	/**< Major version of the chipset*/
	uint32_t chipset_major;
	/**< Minor version of the chipset*/
	uint32_t chipset_minor;
}
#include "acdb_end_pack.h"
;

/**< The response structure for ATS_CMD_ADIE_GET_CODEC_INFO.*/
typedef struct ats_cmd_adie_get_codec_info_rsp_t AtsCmdAdieGetCodecInfoRsp;
#include "acdb_begin_pack.h"
struct ats_cmd_adie_get_codec_info_rsp_t
{
	/**< Number of codec properties*/
	uint32_t property_count;
	/**< List of codec properties*/
	CodecProperties *codec_properties;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ADIE_GET_CODEC_INFO */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_GET_REGISTER Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_GET_REGISTER
\{ */

/**
	Queries ATS for the register value for a given register.

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_GET_REGISTER.
	\param[in] cmd
		Pointer to AtsCmdAdieGetRegisterReq.
	\param[in] cmd_size
		Size of AtsCmdAdieGetRegisterReq.
	\param[out] rsp
		Pointer to AtsCmdAdieGetRegisterRsp.
	\param[in] rsp_size
		Size of AtsCmdAdieGetRegisterRsp.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_ADIE_GET_REGISTER ATS_CODEC_RTC_CMD_ID(2)
/**< The request structure for ATS_CMD_ADIE_GET_REGISTER.*/
typedef struct ats_cmd_adie_get_register_req_t AtsCmdAdieGetRegisterReq;
#include "acdb_begin_pack.h"
struct ats_cmd_adie_get_register_req_t
{
	/**< Codec handle*/
	uint32_t codec_handle;
	/**< ID of the register*/
	uint32_t register_id;
	/**< The bit-mask for the register*/
	uint32_t register_mask;
}
#include "acdb_end_pack.h"
;

/**< The response structure for ATS_CMD_ADIE_GET_REGISTER.*/
typedef struct ats_cmd_adie_get_register_rsp_t AtsCmdAdieGetRegisterRsp;
#include "acdb_begin_pack.h"
struct ats_cmd_adie_get_register_rsp_t
{
	/**< The register value*/
	uint32_t register_value;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ADIE_GET_REGISTER */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_GET_MULTIPLE_REGISTER Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_GET_MULTIPLE_REGISTER
\{ */

/**
	Calls ATS_CMD_ADIE_GET_REGISTER for each ADIE register

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_GET_MULTIPLE_REGISTER.
	\param[in] cmd
		There is no input structure; set this to NULL.
	\param[in] cmd_size
		There is no input structure; set this to 0.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa
		- ATS_CMD_ADIE_GET_REGISTER
*/
#define ATS_CMD_ADIE_GET_MULTIPLE_REGISTER ATS_CODEC_RTC_CMD_ID(3)
/** \} */ /* end_addtogroup ATS_CMD_ADIE_GET_MULTIPLE_REGISTER */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_SET_REGISTER Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_SET_REGISTER
\{ */

/**
	Set the register value for the given ADIE register.

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_SET_REGISTER.
	\param[in] cmd
		Pointer to AtsCmdAdieSetRegisterReq.
	\param[in] cmd_size
		Size of AtsCmdAdieSetRegisterReq.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa
		- TODO
*/
#define ATS_CMD_ADIE_SET_REGISTER ATS_CODEC_RTC_CMD_ID(4)
/**< The request structure for ATS_CMD_ADIE_SET_REGISTER.*/
typedef struct ats_cmd_adie_set_register_req_t AtsCmdAdieSetRegisterReq;
#include "acdb_begin_pack.h"
struct ats_cmd_adie_set_register_req_t
{
	/**< Codec handle*/
	uint32_t codec_handle;
	/**< ID of the register*/
	uint32_t register_id;
	/**< The bit-mask for the register*/
	uint32_t register_mask;
	/**< The value stored in the register*/
	uint32_t register_value;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ADIE_SET_REGISTER */

/* ---------------------------------------------------------------------------
* ATS_CMD_ADIE_SET_MULTIPLE_REGISTER Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ADIE_SET_MULTIPLE_REGISTER
\{ */

/**
	Calls ATS_CMD_ADIE_SET_REGISTER for each ADIE register

	\param[in] cmd_id
		Command ID is ATS_CMD_ADIE_SET_MULTIPLE_REGISTER.
	\param[in] cmd
		There is no input structure; set this to NULL.
	\param[in] cmd_size
		There is no input structure; set this to 0.
	\param[out] rsp
		There is no output structure; set this to NULL.
	\param[in] rsp_size
		There is no output structure; set this to 0.

	\return
		- AR_EOK -- Command executed successfully.
		- AR_EBADPARAM -- Invalid input parameters were provided.
		- AR_EFAILED -- Command execution failed.

	\sa TODO
*/
#define ATS_CMD_ADIE_SET_MULTIPLE_REGISTER ATS_CODEC_RTC_CMD_ID(5)
/** \} */ /* end_addtogroup ATS_CMD_ADIE_SET_MULTIPLE_REGISTER */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_SERVICE_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_SERVICE_INFO
\{ */

/**
    Queries the Online Calibration Service Version

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_SERVICE_INFO.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to AtsCmdGetServiceInfoRsp
    \param[in] rsp_size
        There is the size of AtsCmdGetServiceInfoRsp

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa TODO
*/
#define ATS_CMD_ONC_GET_SERVICE_INFO ATS_ONLINE_CMD_ID(1)
/**< Holds the service information of a service*/
typedef struct ats_service_info_t AtsServiceInfo;
#include "acdb_begin_pack.h"
struct ats_service_info_t
{
    /**< Service ID*/
    uint32_t service_id;
    /**< Major version*/
    uint32_t major;
    /**< Minor version*/
    uint32_t minor;
}
#include "acdb_end_pack.h"
;

/**< The response structure for retrieving information about the registered services*/
typedef struct ats_cmd_get_service_info_rsp_t AtsCmdGetServiceInfoRsp;
#include "acdb_begin_pack.h"
struct ats_cmd_get_service_info_rsp_t
{
    /**< Number of ATS services*/
    uint32_t service_count;
    /**< Array of service information*/
    AtsServiceInfo *services_info;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_SERVICE_INFO */

/*----------------------------------------------------------------------------
* ATS_CMD_ONC_CHECK_CONNECTION Declarations and Documentation
*---------------------------------------------------------------------------*/

/** \addtogroup ATS_CMD_ONC_CHECK_CONNECTION
\{ */

/**
    Checks to see if a connection between ATS and its client can be
    established or is still active.

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_CHECK_CONNECTION.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to a uint32_t
    \param[in] rsp_size
        This is the size of a uint32_t

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_CHECK_CONNECTION ATS_ONLINE_CMD_ID(2)
/** \} */ /* end_addtogroup ATS_CMD_ONC_CHECK_CONNECTION */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_MAX_BUFFER_LENGTH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_MAX_BUFFER_LENGTH
\{ */

/**
    Queries ATS for its maximum buffer length.

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_MAX_BUFFER_LENGTH.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to a uint32_t
    \param[in] rsp_size
        This is the size of a uint32_t

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_MAX_BUFFER_LENGTH ATS_ONLINE_CMD_ID(3)
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_MAX_BUFFER_LENGTH */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH
\{ */

/**
    Set the maximum buffer size to be used by ATS

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        There is no output structure; set this to NULL.
    \param[in] rsp_size
        There is no output structure; set this to 0.

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH ATS_ONLINE_CMD_ID(4)
/** \} */ /* end_addtogroup ATS_CMD_ONC_SET_MAX_BUFFER_LENGTH */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_ACDB_FILES_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_ACDB_FILES_INFO
\{ */

/**
    Queries ATS for ACDB file information for all ACDB files loaded into RAM.
    File info includes the ACDB file name and file size for each ACDB file.

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_ACDB_FILES_INFO.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to AtsCmdGetAcdbFileInfoRsp
    \param[in] rsp_size
        This is the size of AtsCmdGetAcdbFileInfoRsp

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_ACDB_FILES_INFO ATS_ONLINE_CMD_ID(5)

/**< Holds basic Acdb file information */
typedef struct ats_get_acdb_file_info_t AtsGetAcdbFileInfo;
#include "acdb_begin_pack.h"
struct ats_get_acdb_file_info_t
{
    /**< Acdb file size*/
    uint32_t file_size;
    /**< Acdb file name length*/
    uint32_t file_name_len;
    /**< Acdb file name*/
    char* file_name;
}
#include "acdb_end_pack.h"
;

/**< The response structure for retrieving information about the Acdb files loaded in memory*/
typedef struct ats_cmd_get_acdb_file_info_rsp_t AtsCmdGetAcdbFileInfoRsp;
#include "acdb_begin_pack.h"
struct ats_cmd_get_acdb_file_info_rsp_t
{
    /**< Number of acdb files*/
    uint32_t file_count;
    /**< Array of acdb file info*/
    AtsGetAcdbFileInfo *files_info;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_ACDB_FILES_INFO */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_ACDB_FILE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_ACDB_FILE
\{ */

/**
    Downloads the requested ACDB data and delta data file(s) from the target
    to the client. The client retrieves the file name from
    ATS_CMD_ONC_GET_ACDB_FILES_INFO

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_ACDB_FILE.
    \param[in] cmd
        There is a pointer to AtsOcsGetAcdbFile
    \param[in] cmd_size
        There is the size of AtsOcsGetAcdbFile
    \param[out] rsp
        This is a pointer to AcdbBlob
    \param[in] rsp_size
        This is the size of AcdbBlob

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa
    ats_online_ioctl
    ATS_CMD_ONC_GET_ACDB_FILES_INFO
*/
#define ATS_CMD_ONC_GET_ACDB_FILE ATS_ONLINE_CMD_ID(6)

typedef struct _ats_ocs_get_acdb_file_req_t AtsOcsGetAcdbFile;
#include "acdb_begin_pack.h"
struct _ats_ocs_get_acdb_file_req_t
{
    /**<File offset to start reading from*/
    uint32_t file_offset;
    /**<The size of the file read*/
    uint32_t file_read_size;
    /**<The length of the file name*/
    uint32_t file_name_len;
    /**<The name of the file to retrieve data for*/
    uint8_t* file_name;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_ACDB_FILE */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_HEAP_ENTRY_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_HEAP_ENTRY_INFO
\{ */

/**
    Get information about the entries on the ACDB heap

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_HEAP_ENTRY_INFO.
    \param[in] cmd
        There is a pointer to
    \param[in] cmd_size
        There is the size of
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa
    ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_HEAP_ENTRY_INFO ATS_ONLINE_CMD_ID(7)
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_HEAP_ENTRY_INFO */

/* ---------------------------------------------------------------------------
* #define ATS_CMD_ONC_GET_HEAP_ENTRY_DATA ATS_ONLINE_CMD_ID(8)
 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup #define ATS_CMD_ONC_GET_HEAP_ENTRY_DATA ATS_ONLINE_CMD_ID(8)

\{ */

/**
    Queries for the requested heap entries from the ACDB heap.

    \param[in] cmd_id
        Command ID is #define ATS_CMD_ONC_GET_HEAP_ENTRY_DATA ATS_ONLINE_CMD_ID(8)
.
    \param[in] cmd
        There is a pointer to AtsOcsGetAcdbFile
    \param[in] cmd_size
        There is the size of AtsOcsGetAcdbFile
    \param[out] rsp
        This is a pointer to AcdbBlob
    \param[in] rsp_size
        This is the size of AcdbBlob

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa
    ats_online_ioctl
    ATS_CMD_ONC_GET_HEAP_ENTRY_INFO
*/
#define ATS_CMD_ONC_GET_HEAP_ENTRY_DATA ATS_ONLINE_CMD_ID(8)
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_HEAP_ENTRY_DATA */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_CAL_DATA_NON_PERSIST Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_CAL_DATA_NON_PERSIST
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_GET_CAL_DATA_NON_PERSIST
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_CAL_DATA_NON_PERSIST ATS_ONLINE_CMD_ID(9)

typedef struct _ats_get_subgraph_cal_data_req_t AtsGetSubgraphCalDataReq;
#include "acdb_begin_pack.h"
struct _ats_get_subgraph_cal_data_req_t {
    uint32_t subgraph_id;
    uint32_t module_iid;
    uint32_t param_id;
    AcdbGraphKeyVector cal_key_vector;
}
#include "acdb_end_pack.h"
;

typedef struct _ats_set_subgraph_cal_data_req_t AtsSetSubgraphCalDataReq;
#include "acdb_begin_pack.h"
struct _ats_set_subgraph_cal_data_req_t {
    uint32_t subgraph_id;
    uint32_t module_iid;
    uint32_t param_id;
    AcdbGraphKeyVector cal_key_vector;
    AcdbBlob payload;
}
#include "acdb_end_pack.h"
;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_CAL_DATA_NON_PERSIST */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST ATS_ONLINE_CMD_ID(10)
/** \} */ /* end_addtogroup ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_CAL_DATA_PERSIST Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_CAL_DATA_PERSIST
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_GET_CAL_DATA_PERSIST
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_CAL_DATA_PERSIST ATS_ONLINE_CMD_ID(11)
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_CAL_DATA_PERSIST */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_CAL_DATA_PERSIST Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SET_CAL_DATA_PERSIST
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_SET_CAL_DATA_PERSIST
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SET_CAL_DATA_PERSIST ATS_ONLINE_CMD_ID(12)
/** \} */ /* end_addtogroup ATS_CMD_ONC_SET_CAL_DATA_PERSIST */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_TAG_DATA Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_TAG_DATA
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_GET_TAG_DATA
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_TAG_DATA ATS_ONLINE_CMD_ID(13)

typedef struct _ats_get_subgraph_tag_data_req_t AtsGetSubgraphTagDataReq;
#include "acdb_begin_pack.h"
struct _ats_get_subgraph_tag_data_req_t {
    uint32_t subgraph_id;
    uint32_t tag_id;
    uint32_t module_iid;
    uint32_t param_id;
    AcdbGraphKeyVector tag_key_vector;
}
#include "acdb_end_pack.h"
;

typedef struct _ats_set_subgraph_tag_data_req_t AtsSetSubgraphTagDataReq;
#include "acdb_begin_pack.h"
struct _ats_set_subgraph_tag_data_req_t {
    uint32_t subgraph_id;
    uint32_t tag_id;
    uint32_t module_iid;
    uint32_t param_id;
    AcdbGraphKeyVector cal_key_vector;
    AcdbBlob payload;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_TAG_DATA */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_TAG_DATA Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SET_TAG_DATA
\{ */

/**
    TBD

    \param[in] cmd_id ATS_CMD_ONC_SET_TAG_DATA
        Command ID is
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to
    \param[in] rsp_size
        This is the size of

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SET_TAG_DATA ATS_ONLINE_CMD_ID(14)
/** \} */ /* end_addtogroup ATS_CMD_ONC_SET_TAG_DATA */
/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_DELETE_DELTA_FILES Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_DELETE_DELTA_FILES
\{ */

/**
    Removes the *.acdbdelta files from the targets file system

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_DELETE_DELTA_FILES.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is no output structure; set this to NULL.
    \param[in] rsp_size
        This is no output structure; set this to 0.

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_DELETE_DELTA_FILES ATS_ONLINE_CMD_ID(15)
/** \} */ /* end_addtogroup ATS_CMD_ONC_DELETE_DELTA_FILES */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_IS_DELTA_DATA_SUPPORTED Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_IS_DELTA_DATA_SUPPORTED
\{ */

/**
    Determines whether the target has ACDB Delta data persistence enabled or
    disabled.

    Is persistance supported? Zero for supported and non-zero for unsupported.

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_IS_DELTA_DATA_SUPPORTED.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        There is no input structure; set this to 0.
    \param[out] rsp
        This is a pointer to a uint32_t
    \param[in] rsp_size
        This is the size of AtsCmdGetAcdbFileInfoRsp

    \return
        - AR_EOK -- Command executed successfully.
        - AR_EBADPARAM -- Invalid input parameters were provided.
        - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_IS_DELTA_DATA_SUPPORTED ATS_ONLINE_CMD_ID(16)

/** \} */ /* end_addtogroup ATS_CMD_ONC_IS_DELTA_DATA_SUPPORTED */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_TEMP_PATH Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_TEMP_PATH
\{ */

/**
    Get the writable path that can be used for pushing files to the file system

    \param[in] cmd_id
        Command ID is ATS_CMD_ONC_GET_TEMP_PATH.
    \param[in] cmd
        There is no input structure; set this to NULL.
    \param[in] cmd_size
        Set this to zero
    \param[out] rsp
        This is a pointer to AtsGetTempPath
    \param[in] rsp_size
        This is the size of AtsGetTempPath

    \return
    - AR_EOK -- Command executed successfully.
    - AR_EBADPARAM -- Invalid input parameters were provided.
    - AR_EFAILED -- Command execution failed.
    - AR_ENOTEXIST -- No writable path was found.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_TEMP_PATH ATS_ONLINE_CMD_ID(17)

/**< Holds temporary file path information */
typedef struct ats_get_temp_path_t AtsGetTempPath;
#include "acdb_begin_pack.h"
struct ats_get_temp_path_t
{
    /**< The string length of the path */
    uint32_t path_len;
    /**< A writable path on the file system */
    char* path;
}
#include "acdb_end_pack.h"
;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_TEMP_PATH */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_ACDB_REINIT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_ACDB_REINIT
\{ */

/**
    Reinitializes ACDB Software with the provided ACDB and Delta Data files
    paths

    \param[in] cmd_id
    Command ID is ATS_CMD_ONC_ACDB_REINIT.
    \param[in] cmd
    There is no input structure; set this to NULL.
    \param[in] cmd_size
    There is the size of AtsAcdbReinitReq.
    \param[out] rsp
    This is a pointer to a uint32_t
    \param[in] rsp_size
    This is the size of AtsCmdGetAcdbFileInfoRsp

    \return
    - AR_EOK -- Command executed successfully.
    - AR_EBADPARAM -- Invalid input parameters were provided.
    - AR_EFAILED -- Command execution failed.

    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_ACDB_REINIT ATS_ONLINE_CMD_ID(18)

typedef struct _ats_acdb_reinit_req_t AtsAcdbReinitReq;
#include "acdb_begin_pack.h"
struct _ats_acdb_reinit_req_t {
    /**< List of Acdb file paths */
    AcdbDataFiles acdb_files;
    /**< Flag to enable/disable delta support data  */
    uint32_t is_delta_data_supported;
    /**< Delta Data file path */
    AcdbFile delta_file_path;
}
#include "acdb_end_pack.h"
;
/** \} */ /* end_addtogroup ATS_CMD_ONC_ACDB_REINIT */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_ALL_DB_FILE_SETS Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_ALL_DB_FILE_SETS
\{ */

/**
*    Retrieves all the database files sets managed by AML.
*
*    A file set contains all the files related to one client database
*    and can contain the following:
*       1. *.acdb  file path
*       2. *.workspace file path
*       3. writable path

*    The format of the response is:
*    +-------------------------------------+
*    |             #files sets             |
*    +-------------------------------------+
*    +-------------------------------------+
*    |             acdb handle             | _
*    +-------------------------------------+  |
*    +-------------------------------------+  |
*    |               # files               |  |
*    +-------------------------------------+  |
*    +-------------------------------------+  | File Set #1
*    | path type | fsize | path len | path |  |
*    +-------------------------------------+  |
*    |                    ...                 |
*    +-------------------------------------+  |
*    | path type | fsize | path len | path | _|
*    +-------------------------------------+
*                       ..
*                       ..  more file set(s)
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_GET_ALL_DB_FILE_SETS.
*    \param[in] cmd
*    There is no input structure; set this to NULL.
*    \param[in] cmd_size
*    There is no input structure; set this to 0.
*    \param[out] rsp
*    This is a pointer to ats_cmd_get_all_db_file_sets_rsp_t
*    \param[in] rsp_size
*    This is the size of ats_cmd_get_all_db_file_sets_rsp_t
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_ALL_DB_FILE_SETS ATS_ONLINE_CMD_ID(19)

typedef struct ats_db_path_info_t
{
    /**< The handle for the database */
    uint32_t acdb_handle;
    /**< Acdb path type*/
    uint32_t path_type;
    /**< Acdb file size*/
    uint32_t file_size;
    /**< Acdb file name length*/
    uint32_t file_name_len;
    /**< Acdb file name*/
    char_t* file_name;
}ats_db_path_info_t;

typedef struct ats_cmd_get_all_db_file_sets_rsp_t
{
    /**< The handle for the database files */
    uint32_t acdb_handle;
    /**< The number of directories/files in the file set */
    uint32_t num_files;
    /**< The list of directories/file paths */
    ats_db_path_info_t file_set[0];
}ats_cmd_get_all_db_file_sets_rsp_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_ALL_DB_FILE_SETS */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_FILE Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_FILE
\{ */

/**
*    Retrieves the specified database file (*.acdb or *.qwsp or etc..) for the
*    given acdb handle.
*
*    The file is retrieved in pieces if its larger than the ATS buffer.
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_FILE.
*    \param[in] cmd
*    This is a pointer to ats_cmd_get_all_db_file_sets_rsp_t
*    \param[in] cmd_size
*    This is the size of ats_cmd_get_all_db_file_sets_rsp_t
*    \param[out] rsp
*    This is a pointer to ats_blob_t
*    \param[in] rsp_size
*    This is the size of ats_blob_t
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_FILE ATS_ONLINE_CMD_ID(20)

typedef struct ats_cmd_get_selected_client_db_file_req_t
{
    /**< The handle for the selected database */
    uint32_t acdb_handle;
    /**< File offset to start reading from */
    uint32_t file_offset;
    /**< The number of bytes to read */
    uint32_t file_read_size;
    /**< The length of the file name */
    uint32_t file_name_len;
    /**< The name of the file to retrieve data for */
    uint8_t* file_name;
}ats_cmd_get_selected_client_db_file_req_t;

//typedef struct ats_blob_t
//{
//    /**< The byte size of the data */
//    uint32_t size;
//    /**< A blob of data */
//    uint8_t data[0];
//}ats_blob_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_FILE */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO
\{ */

/**
*    Retrieves database heap info for the given acdb handle.
*
*    This API is used in conjunction with
*    ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA to get all heap data
*    for a database.
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO.
*    \param[in] cmd
*    This is a pointer to ats_cmd_get_selected_client_db_heap_info_req_t
*    \param[in] cmd_size
*    This is the size of ats_cmd_get_selected_client_db_heap_info_req_t
*    \param[out] rsp
*    This is a pointer to ats_cmd_get_selected_client_db_heap_info_rsp_t
*    \param[in] rsp_size
*    This is the size of ats_cmd_get_selected_client_db_heap_info_rsp_t
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO ATS_ONLINE_CMD_ID(21)

typedef struct ats_cmd_get_selected_client_db_heap_info_req_t
{
    /**< The handle for the selected database */
    uint32_t acdb_handle;
}ats_cmd_get_selected_client_db_heap_info_req_t;

typedef struct ats_cmd_get_selected_client_db_heap_info_rsp_t
{
    /**<The key vector*/
    AcdbGraphKeyVector key_vector;
    /**<The type of key vector*/
    uint32_t key_vector_type;
    /**<Size of the heap entry*/
    uint32_t map_size;
}ats_cmd_get_selected_client_db_heap_info_rsp_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA
\{ */

/**
*    Retrieves database heap data for the given acdb handle.
*
*    This API is used in conjunction with
*    ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_INFO to get all heap data
*    for a database.
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA.
*    \param[in] cmd
*    This is a pointer to ats_cmd_get_selected_client_db_heap_data_req_t
*    \param[in] cmd_size
*    This is the size of ats_cmd_get_selected_client_db_heap_data_req_t
*    \param[out] rsp
*    This is a pointer to ats_cmd_get_selected_client_db_heap_data_rsp_t
*    \param[in] rsp_size
*    This is the size of ats_cmd_get_selected_client_db_heap_data_rsp_t
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA ATS_ONLINE_CMD_ID(22)

typedef struct ats_cmd_get_selected_client_db_heap_data_req_t
{
    /**< The handle for the selected database */
    uint32_t acdb_handle;
    /**< The number of key vectors to get heap data for */
    uint32_t num_key_vectors;
    /**< A list of key vectors (ckv/tkv/..) to get heap data for */
    AcdbGraphKeyVector *key_vector_list;
}ats_cmd_get_selected_client_db_heap_data_req_t;

typedef struct ats_parameter_t
{
    /**< The module instance id */
    uint32_t instance_id;
    /**< The parameter id */
    uint32_t parameter_id;
    /**< The non-padded size of the parameter payload */
    uint32_t size;
    /**< The parameter payload (with no padding) */
    uint8_t payload[0];
}ats_parameter_t;

typedef struct ats_heap_param_data_t
{
    /**< The size of the parameter data */
    uint32_t data_size;
    /**< Number of regular and shared parameters */
    uint32_t parameter_count;
    /**< A list of both regular and shared parameters */
    ats_parameter_t* parameter_data;
}ats_heap_param_data_t;

typedef struct ats_heap_subgraph_t
{
    /**< The subgraph id */
    uint32_t subgraph_id;
    /**< The total size of the subgraph data. This is
    * non_global_data_size + global_data_size */
    uint32_t subgraph_data_size;
    /**< Regular and shared parameters */
    ats_heap_param_data_t *non_global_parameter_data;
    /**< Globally-shared parameters */
    ats_heap_param_data_t *global_parameter_data;
}ats_heap_subgraph_t;

typedef struct ats_heap_data_instance_t
{
    /**< The key vector (ckv/tkv/etc..) */
    AcdbGraphKeyVector key_vector;
    /**< The size of the heap entry */
    uint32_t map_size;
    /**< The number of subgraph in the data instance */
    uint32_t num_subgraphs;
    /**< A list of subgraph heap objects containing parameter data */
    ats_heap_subgraph_t* subgraph;
}ats_heap_data_instance_t;

typedef struct ats_cmd_get_selected_client_db_heap_data_rsp_t
{
    /**< The number of keyvectors found */
    uint32_t num_key_vectors_found;
    /**< The heap data for all key vectors found */
    ats_heap_data_instance_t *heap_data;
}ats_cmd_get_selected_client_db_heap_data_rsp_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_GET_SELECTED_CLIENT_DB_HEAP_DATA */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_CHECK_SELECTED_CLIENT_CONNECTION Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_CHECK_SELECTED_CLIENT_CONNECTION
\{ */

/**
*    Checks if the database associated with the given acdb handle is
*    still connected.
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_CHECK_SELECTED_CLIENT_CONNECTION.
*    \param[in] cmd
*    This is a pointer to ats_cmd_check_selcted_client_connection_req_t
*    \param[in] cmd_size
*    This is the size of ats_cmd_check_selcted_client_connection_req_t
*    \param[out] rsp
*    There is no input structure; set this to NULL.
*    \param[in] rsp_size
*    There is no input structure; set this to 0.
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_CHECK_SELECTED_CLIENT_CONNECTION ATS_ONLINE_CMD_ID(23)

typedef struct ats_cmd_check_selcted_client_connection_req_t {
    /**< The handle for the selected database */
    uint32_t acdb_handle;
}ats_cmd_check_selcted_client_connection_req_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_CHECK_SELECTED_CLIENT_CONNECTION */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SELECTED_CLIENT_DB_REINIT Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SELECTED_CLIENT_DB_REINIT
\{ */

/**
*    Reinitializes the database associated with the acdb handle
*
*    \param[in] cmd_id
*    Command ID is ATS_CMD_ONC_SELECTED_CLIENT_DB_REINIT.
*    \param[in] cmd
*    This is a pointer to ats_cmd_selected_client_db_reinit_req_t
*    \param[in] cmd_size
*    This is the size of ats_cmd_selected_client_db_reinit_req_t
*    \param[out] rsp
*    There is no input structure; set this to NULL.
*    \param[in] rsp_size
*    There is no input structure; set this to 0.
*
*    \return
*    - AR_EOK -- Command executed successfully.
*    - AR_EBADPARAM -- Invalid input parameters were provided.
*    - AR_EFAILED -- Command execution failed.
*
*    \sa ats_online_ioctl
*/
#define ATS_CMD_ONC_SELECTED_CLIENT_DB_REINIT ATS_ONLINE_CMD_ID(24)

typedef struct ats_cmd_selected_client_db_reinit_req_t {
    /**< The handle for the selected database */
    uint32_t acdb_handle;
    /**< List of Acdb file paths */
    AcdbDatabaseFiles acdb_files;
}ats_cmd_selected_client_db_reinit_req_t;

/** \} */ /* end_addtogroup ATS_CMD_ONC_SELECTED_CLIENT_DB_REINIT */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST_2 Declarations and Documentation
*-------------------------------------------------------------------------- */

/** \addtogroup ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST_2
\{ */

/**
 *    Sets non-persistent cal data to the AML heap. This overrides calibration data
 *    retrieved from the acdb file when GSL querries for calibration data.
 *
 *    This data can also be persisted to the delta file by setting the
 *    persist flag to true.
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST_2
 *    \param[in] cmd
 *        This is a pointer to AtsSetCalDataNonPersistReq
 *    \param[in] cmd_size
 *        This is the size of AtsSetCalDataNonPersistReq
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to 0.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_online_ioctl
 */
#define ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST_2 ATS_ONLINE_CMD_ID(25)

typedef struct _ats_set_cal_data_non_persist_req_t AtsSetCalDataNonPersistReq;
#include "acdb_begin_pack.h"
struct _ats_set_cal_data_non_persist_req_t {
    uint32_t should_persist;
    uint32_t num_subgraphs;
    uint32_t* subgraph_list;
    AcdbGraphKeyVector cal_key_vector;
}
#include "acdb_end_pack.h"
;

/** @} */ /* end_addtogroup ATS_CMD_ONC_SET_CAL_DATA_NON_PERSIST_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_CAL_DATA_PERSIST_2 Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_ONC_SET_CAL_DATA_PERSIST_2
\{ */

/**
 *    Sets persistent cal data to the AML heap. This overrides calibration data
 *    retrieved from the acdb file when GSL querries for calibration data.
 *
 *    This data can also be persisted to the delta file by setting the
 *    persist flag to true.
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_ONC_SET_CAL_DATA_PERSIST_2
 *    \param[in] cmd
 *        This is a pointer to AtsSetCalDataPersistReq
 *    \param[in] cmd_size
 *        This is the size of AtsSetCalDataPersistReq
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_online_ioctl
 */
#define ATS_CMD_ONC_SET_CAL_DATA_PERSIST_2 ATS_ONLINE_CMD_ID(26)

typedef struct _ats_set_cal_data_persist_req_t AtsSetCalDataPersistReq;
#include "acdb_begin_pack.h"
struct _ats_set_cal_data_persist_req_t {
    uint32_t should_persist;
    uint32_t num_subgraphs;
    uint32_t* subgraph_list;
    AcdbGraphKeyVector cal_key_vector;
}
#include "acdb_end_pack.h"
;

/** @} */ /* end_addtogroup ATS_CMD_ONC_SET_CAL_DATA_PERSIST_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_ONC_SET_TAG_DATA_2 Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_ONC_SET_TAG_DATA_2
\{ */

/**
 *    Sets tag data to the AML heap. This overrides tag data
 *    retrieved from the acdb file when GSL querries for tag data.
 *
 *    This data can also be persisted to the delta file by setting the
 *    persist flag to true.
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_ONC_SET_TAG_DATA_2
 *    \param[in] cmd
 *        This is a pointer to AtsSetTagDataReq
 *    \param[in] cmd_size
 *        This is the size of AtsSetTagDataReq
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_online_ioctl
 */
#define ATS_CMD_ONC_SET_TAG_DATA_2 ATS_ONLINE_CMD_ID(27)

typedef struct _ats_set_tag_data_req_t AtsSetTagDataReq;
#include "acdb_begin_pack.h"
struct _ats_set_tag_data_req_t {
    uint32_t should_persist;
    uint32_t num_subgraphs;
    uint32_t* subgraph_list;
    uint32_t tag_id;
    AcdbGraphKeyVector tag_key_vector;
}
#include "acdb_end_pack.h"
;

/** @} */ /* end_addtogroup ATS_CMD_ONC_SET_TAG_DATA_2 */

/* ---------------------------------------------------------------------------
* ATS_CMD_DLS_START Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_DLS_START
\{ */

/**
 *    Registers a single log code and begins logging data for the log code.
 *    on SPF
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_DLS_START
 *    \param[in] cmd
 *        This is a pointer to AtsDlsLogCode
 *    \param[in] cmd_size
 *        This is the size of uint16_t
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_dls_ioctl
 */
#define ATS_CMD_DLS_START ATS_DLS_CMD_ID(1)

typedef struct _ats_dls_log_code_t AtsDlsLogCode;
#include "acdb_begin_pack.h"
struct _ats_dls_log_code_t {
    uint16_t log_code;
}
#include "acdb_end_pack.h"
;
/** @} */ /* end_addtogroup ATS_CMD_DLS_START */

/* ---------------------------------------------------------------------------
* ATS_CMD_DLS_STOP Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_DLS_STOP
\{ */
/**
 *    De-egisters a single log code and stops logging data for the log code
 *    on SPF
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_DLS_STOP
 *    \param[in] cmd
 *        This is a pointer to AtsDlsLogCode
 *    \param[in] cmd_size
 *        This is the size of uint16_t
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_dls_ioctl
 */
#define ATS_CMD_DLS_STOP ATS_DLS_CMD_ID(2)
/** @} */ /* end_addtogroup ATS_CMD_DLS_STOP */

/* ---------------------------------------------------------------------------
* ATS_CMD_DLS_CONFIGURE Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_DLS_CONFIGURE
\{ */
/**
 *    Configures the size of the shared memory buffer pool. The buffer
 *    pool is where all the dls buffers are stored/updated/retrieved.
 *
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_DLS_CONFIGURE
 *    \param[in] cmd
 *        This is a pointer to AtsDlsBufferPoolConfig
 *    \param[in] cmd_size
 *        This is the size of AtsDlsBufferPoolConfig
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_dls_ioctl
 */
#define ATS_CMD_DLS_CONFIGURE ATS_DLS_CMD_ID(3)

typedef struct _ats_dls_buffer_pool_config_t AtsDlsBufferPoolConfig;
#include "acdb_begin_pack.h"
struct _ats_dls_buffer_pool_config_t {
    /**< The size of a single binary log packet buffer */
	uint32_t buffer_size;
    /**< The number of binary log buffers */
	uint32_t buffer_count;
}
#include "acdb_end_pack.h"
;
/** @} */ /* end_addtogroup ATS_CMD_DLS_CONFIGURE */

/* ---------------------------------------------------------------------------
* ATS_CMD_DLS_GET_LOG_DATA Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_DLS_GET_LOG_DATA
\{ */
/**
*    The log data containing log packets for each registered log code. Each
*    registerd log code can have multiple packets within the log data buffer.
*
*    For example, we can have 2 log codes 0x1234 and 0x5678 where
*       1. LC 0x1234 may have 2 packets in the log data buffer and
*       2. LC 0x5678 may have 3 log packets in the log data buffer
*
*      Log Data Buffer Format:
*
*                .+--   +================================+
*                |      |          'A''R''T''M'          |  bytes: 4
*                |      |  ----------------------------  |
*       Header-->|      |  Version                       |  bytes: 2
*                |      |  # Log Packets                 |  bytes: 2
*                .+--   |  Log Data Size                 |  bytes: 4
*                .+--   .--------------------------------.
*                |      |          Log Packet #1         |
*                |      |  ----------------------------  |
*                |      |  Packet Size                   |  bytes: 4
*                |      |  Packet Data [packet size]     |  bytes: Packet Size bytes
*                |      |--------------------------------|
*    Log Data--> |      :              ...               :
*                |      |--------------------------------|
*                |      |          Log Packet #n         |
*                |      |  ----------------------------  |
*                |      |  Packet Size                   |  bytes: 4
*                |      |  Packet Data [packet size]     |  bytes: Packet Size bytes
*                .+--   +.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~+
*
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_DLS_GET_LOG_DATA
 *    \param[in] cmd
 *        There is no input structure; set this to NULL.
 *    \param[in] cmd_size
 *        There is no input structure; set this to 0.
 *    \param[out] rsp
 *        TThis is a pointer to AtsDlsLogDataHeader
 *    \param[in] rsp_size
 *        This is the size of AtsDlsLogDataHeader
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_dls_ioctl
 */
#define ATS_CMD_DLS_GET_LOG_DATA ATS_DLS_CMD_ID(4)

typedef struct _ats_dls_get_dls_log_data_header_t AtsDlsLogDataHeader;
#include "acdb_begin_pack.h"
struct _ats_dls_get_dls_log_data_header_t {
	/**<'A''R''T''M'*/
	uint32_t header_id;
	/**< command version*/
	uint16_t header_version;
	/**< the number of log buffers to send*/
	uint16_t log_buffer_count;
	/**< the total size of all the log buffers*/
	uint32_t total_log_data_size;
	/* Following this header is a list of log buffers:
     AtsBuffer log_data[];
	 */
}
#include "acdb_end_pack.h"
;
/** @} */ /* end_addtogroup ATS_CMD_DLS_GET_LOG_DATA */

/* ---------------------------------------------------------------------------
* ATS_CMD_DLS_GET_VERSION Declarations and Documentation
*-------------------------------------------------------------------------- */
/** \addtogroup ATS_CMD_DLS_GET_VERSION
\{ */
/**
 *    Retrieves the DLS service Version. This is actually handled
 *    by ATS_CMD_ONC_GET_SERVICE_INFO
 *    \param[in] cmd_id
 *        Command ID is ATS_CMD_DLS_GET_VERSION
 *    \param[in] cmd
 *        This is a pointer to ...
 *    \param[in] cmd_size
 *        This is the size of ...
 *    \param[out] rsp
 *        There is no input structure; set this to NULL.
 *    \param[in] rsp_size
 *        There is no input structure; set this to NULL.
 *
 *    \return
 *        - AR_EOK -- Command executed successfully.
 *        - AR_EBADPARAM -- Invalid input parameters were provided.
 *        - AR_EFAILED -- Command execution failed.
 *
 *    \sa ats_dls_ioctl
 */
#define ATS_CMD_DLS_GET_VERSION ATS_DLS_CMD_ID(5)
/** @} */ /* end_addtogroup ATS_CMD_DLS_GET_VERSION */

/* ---------------------------------------------------------------------------
* API Definitions
*-------------------------------------------------------------------------- */

/**
* \brief ATS_CALLBACK
*		A function callback for used for various ATS services
* \param [in] svc_cmd_id: The service command to be issued. Contains the 2 byte
        service id and 2byte command id
* \param [in/out] cmd_buf: Pointer to the command structure.
* \param [in] cmd_buf_size:
* \param [out] rsp_buf: The response structre
* \param [in] rsp_buf_size: The size of the response
* \param [out] rsp_buf_bytes_filled: Number of bytes written to the response buffer
* \return 0 on success, non-zero on failure
*/
typedef int32_t(*ATS_CALLBACK)(
	uint32_t svc_cmd_id,
	uint8_t *cmd_buf,
	uint32_t cmd_buf_size,
	uint8_t *rsp_buf,
	uint32_t rsp_buf_size,
	uint32_t *rsp_buf_bytes_filled);

typedef int32_t(*ATS_VERSION_CALLBACK)(
    AtsServiceInfo *service_info);

typedef struct _ats_callback_table_t AtsCallbackTable;
struct _ats_callback_table_t
{
    ATS_CALLBACK *service_callback;
    ATS_VERSION_CALLBACK *version_callback;
};

#if defined(ATS_OTTP) || defined(_DEVICE_SIM)
typedef int(__stdcall *ATS_SIM_CALLBACK)(
    uint32_t sz_request, uint8_t* request,
    uint32_t *sz_response, uint8_t* response);
#else
typedef int(*ATS_SIM_CALLBACK)(
    uint32_t sz_request, uint8_t* request,
    uint32_t *sz_response, uint8_t* response);
#endif



/**
* \brief
*		Sets the simulation callback for ATS to retrieve response buffers from
*       the Communication capture *.bin
*
* \return 0 on success, non-zero on failure
*/
void ats_register_simulation(ATS_SIM_CALLBACK sim_callback);

/**
* \brief ats_register_service
*		Registers the specified service.
* \param [in] servie_id: The service ID of a ATS service
* \param [in] service_callback: The callback used to execute commands for the service.
* \return 0 on success, non-zero on failure
*/
int32_t ats_register_service(uint32_t service_id, ATS_CALLBACK service_callback);

/**
* \brief ats_deregister_service
*		Deregisters the specified service.
* \param [in] servie_id: The service ID of a ATS service
* \return 0 on success, non-zero on failure
*/
int32_t ats_deregister_service(uint32_t servie_id);

/**
* \brief ats_get_service_info
*		Get service information for each service registered
* \param [in] servie_id: The service ID of a ATS service
* \return 0 on success, non-zero on failure
*/
int32_t ats_get_service_info(AtsCmdGetServiceInfoRsp *svc_info_rsp, uint32_t rsp_buf_len);


#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /*__ATS_H_I__*/
