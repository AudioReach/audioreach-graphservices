/**
*==============================================================================
*  \file adie_rtc_api.h
*  \brief
*                      M C S  A P I  H E A D E R  F I L E
*
*      This header defines the APIs nessesary to control basic audio media
*      services such as playback and record
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*
*==============================================================================
*/

#ifndef MCS_API_H
#define MCS_API_H

#include "ar_osal_types.h"
#include "ar_osal_error.h"

#define MCS_MAX_FILENAME_LENGTH 256

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
** Structure Definitions and Enums
** ----------------------------------------------------------------------- */

typedef enum mcs_api_major_version_t
{
    MCS_API_MAJOR_VERSION_1 = 0x1,
}mcs_api_major_version_t;

typedef enum mcs_api_minor_version_t
{
    /**< Initial version */
    MCS_API_MINOR_VERSION_0 = 0x0,
    /**< Added support for MCS v2 APIs:
    1. MCS_CMD_PLAY_2
    2. MCS_CMD_REC_2
    3. MCS_CMD_MULTI_PLAY_REC
    4. MCS_CMD_STOP_2 */
    MCS_API_MINOR_VERSION_1 = 0x1,
}mcs_api_minor_version_t;

/**< Media control commands */
typedef enum mcs_command_t
{
    MCS_CMD_UNKNOWN                 = 0x00,

    /**<
    * The command for triggering a playback usecase with a path to the playback
    * file for a specified duration.
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_play_t
    * \param[in] cmd_buf_size:  size of mcs_play_t
    * \param[out] rsp:          There is no output structure; set this to NULL.
    * \param[in] rsp_size:      There is no output structure; set this to 0.
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_PLAY                    = 0x01,
    /**<
    * The command for triggering a capture usecase with a path to the file
    * to write to for a specified duration.
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_rec_t
    * \param[in] cmd_buf_size:  size of mcs_rec_t
    * \param[out] rsp:          There is no output structure; set this to NULL.
    * \param[in] rsp_size:      There is no output structure; set this to 0.
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_REC                     = 0x02,
    /**<
    * The command for triggering a simultaneous playback + record session.
    * This command combines the structures used in MCS_CMD_PLAY and
    * MCS_CMD_REC.
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_play_rec_t
    * \param[in] cmd_buf_size:  size of mcs_play_rec_t
    * \param[out] rsp:          There is no output structure; set this to NULL.
    * \param[in] rsp_size:      There is no output structure; set this to 0.
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_PLAY_REC                = 0x03,
    /**<
    * The command for stopping an audio session
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       There is no output structure; set this to NULL.
    * \param[in] cmd_buf_size:  There is no output structure; set this to 0.
    * \param[out] rsp:          There is no output structure; set this to NULL.
    * \param[in] rsp_size:      There is no output structure; set this to 0.
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_STOP                    = 0x04,
    /**<
    * The command for triggering a playback usecase with a path to the playback
    * file for a specified duration.
    * Calibration and tag data can be configured here unlike MCS_CMD_PLAY
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_play_2_t
    * \param[in] cmd_buf_size:  size of mcs_play_2_t
    * \param[out] rsp:          A pointer to mcs_session_handles_t
    * \param[in] rsp_size:      size of mcs_session_handles_t
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_PLAY_2                  = 0x05,
    /**<
    * The command for triggering a capture usecase with a path to the file
    * to write to for a specified duration.
    * Calibration and tag data can be configured here unlike MCS_CMD_REC
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_record_2_t.
    * \param[in] cmd_buf_size:  size of mcs_record_2_t.
    * \param[out] rsp:          A pointer to mcs_session_handles_t
    * \param[in] rsp_size:      size of mcs_session_handles_t
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_REC_2                   = 0x06,
    /**<
    * The command for stopping one or more audio sessions given one or more session handles
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_session_handles_t.
    * \param[in] cmd_buf_size:  size of mcs_session_handles_t.
    * \param[out] rsp:          There is no output structure; set this to NULL.
    * \param[in] rsp_size:      There is no output structure; set this to 0.
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_STOP_2                  = 0x07,
    /**<
    * The command for triggering multiple simultaneous playback + record
    * sessions.
    * This command combines the structures used in MCS_CMD_PLAY_2 and
    * MCS_CMD_REC_2 and contains arrays of playback and record usecases.
    *
    * \param[in] cmd:           this command ID
    * \param[in] cmd_buf:       A pointer to mcs_multi_play_rec_t
    * \param[in] cmd_buf_size:  size of mcs_multi_play_rec_t
    * \param[out] rsp:          A pointer to mcs_multi_play_rec_handle_list_t
    * \param[in] rsp_size:      size of mcs_multi_play_rec_handle_list_t
    *
    * \sa mcs_stream_cmd
    */
    MCS_CMD_MULTI_PLAY_REC          = 0x08,
} mcs_command_t;

/**< Specifies the set of playback modes used in mcs_play_t */
typedef enum mcs_playback_mode_t
{
    MCS_PLAYBACK_REGULAR,
    MCS_PLAYBACK_ANC_S_PATH,
    MCS_PLAYBACK_ANC_E_PATH,
    MCS_PLAYBACK_RAS,
} mcs_playback_mode_t;

/**< Specifies the set of recording modes used in the ATS_CMD_MCS_RECORD request*/
typedef enum mcs_record_mode_t
{
    MCS_RECORD_REGULAR,
    MCS_RECORD_ANC_P_PATH,
    MCS_RECORD_ANC_S_PATH,
    MCS_RECORD_ANC_E_PATH
} mcs_record_mode_t;

/**< A <key,value> pair */
typedef struct mcs_key_value_pair_t
{
    uint32_t key;
    uint32_t value;

}mcs_key_value_pair_t;

/**< Maintains a list of key value pairs */
typedef struct mcs_key_vector_t
{
    /**< number of key-value pairs */
    uint32_t num_kvps;
    /**< key-value pairs */
    mcs_key_value_pair_t *kvp;
}mcs_key_vector_t;

/**< Maintains a list of key value pairs */
typedef struct mcs_tag_key_vector_t
{
    /**< Module tag ID*/
    uint32_t tag_id;
    /**< Tag key vector */
    mcs_key_vector_t tag_key_vector;
}mcs_tag_key_vector_t;

/**< Media properties for a device or stream*/
typedef struct mcs_properties_t
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
}mcs_properties_t;

/**< An array of audio session handles for active session */
typedef struct mcs_session_handles_t
{
    /**< The number of handles for active audio sessions */
    uint32_t num_handles;
    /**< A pointer to an array of handles for active audio sessions */
    uint32_t* handles;
}mcs_session_handles_t;

/**< Contains properties for controlling audio playback */
typedef struct mcs_play_t
{
    /**< playback device properties*/
    mcs_properties_t device_properties;
    /**< playback stream properties*/
    mcs_properties_t stream_properties;
    /**< Graph Key Vector representing the playback usecase*/
    mcs_key_vector_t graph_key_vector;
    /**< Type of playback: 0(regular), 1(anc_spath), 2(anc_epath), 3(ras)*/
    mcs_playback_mode_t playback_mode;
    /**< Playback duration in seconds*/
    int32_t playback_duration_sec;
    /**< Length of the file name/path*/
    int32_t filename_len;
    /**< Name of/path to file to save recording to*/
    char filename[MCS_MAX_FILENAME_LENGTH];
}mcs_play_t;


/**< Contains properties for controlling audio record */
typedef struct mcs_record_t
{
    /**< record device properties*/
    mcs_properties_t device_properties;
    /**< record stream properties*/
    mcs_properties_t stream_properties;
    /**< Graph Key Vector representing the record usecase*/
    mcs_key_vector_t graph_key_vector;
    /**< Type of record: 0(regular), 1(aanc_path), 2(aanc_spath), 3(aanc_epath)*/
    mcs_record_mode_t record_mode;
    /**< Save recording to file: 0 (ignore write), 1 (write data)*/
    uint32_t write_to_file;
    /**< Record duration in seconds*/
    int32_t record_duration_sec;
    /**< Length of the file name/path*/
    int32_t filename_len;
    /**< Name of/path to file to save recording to*/
    char filename[MCS_MAX_FILENAME_LENGTH];
}mcs_record_t;

/**< Contains properties for controlling audio playback and record simultaneously */
typedef struct mcs_play_rec_t
{
    mcs_play_t playback_session;
    mcs_record_t record_session;
}mcs_play_rec_t;

typedef struct mcs_version
{
    /**< Major version for changes that break backward compatibility */
    uint32_t major;
    /**< Major version for changes that do not break backward compatibility */
    uint32_t minor;
}mcs_version_t;

/**< Contains the session config information for triggering an
 * audio playback usecase. Unlike the mcs_play_t structure, this structure
 * allows the client to apply specific calibration/config before starting
 * the usecase. The client can:
 *     1. select specific calibraiton data using the ckv
 *     2. select data base defined tag data using TKVs
 *     3. provide custom tag data (this is not stored in the database)
 */
typedef struct mcs_play_2_t
{
    /**< playback device properties */
    mcs_properties_t device_properties;
    /**< playback stream properties */
    mcs_properties_t stream_properties;
    /**< Graph Key Vector representing the playback usecase */
    mcs_key_vector_t graph_key_vector;
    /**< The usecase calibration key vector for selecting specific calibraion
    to apply before starting a usecase */
    mcs_key_vector_t cal_key_vector;
    /**< The number of tag key vectors. Setting this to zero indicates
    that tkvs are unused */
    uint32_t num_tag_key_vectors;
    /**< length of the tkv list */
    uint32_t tkv_list_size;
    /**< An array of all the tag key vectors within a usecase. Used for
    applying a specific configuration stored in the *.acdb before the
    starting a useecase */
    mcs_tag_key_vector_t* tag_key_vectors;
    /**< Type of playback:
    0(regular), 1(anc_spath), 2(anc_epath), 3(ras) */
    mcs_playback_mode_t playback_mode;
    /**< Playback duration in seconds */
    int32_t playback_duration_sec;
    /**< Length of the file name/path */
    int32_t filename_len;
    /**< Name of/path to file to save recording to */
    char filename[MCS_MAX_FILENAME_LENGTH];
    /**< Size of tag data blob. Set to 0 to indicate none included */
    uint32_t tag_data_size;
    /**< A pointer to the custom tag data blob. The format of this data is
    [IID, Parameter ID, Data Size, Payload[Data Size], 8 Byte Aligned Padding]
    ...
    [IID, Parameter ID, Data Size, Payload[Data Size], 8 Byte Aligned Padding] */
    uint8_t* tag_data;
}mcs_play_2_t;

/**< Contains the session config information for triggering an
 * audio capture usecase. Unlike the mcs_record_t structure, this structure
 * allows the client to apply specific calibration/config before starting
 * the usecase. The client can:
 *     1. select specific calibraiton data using the ckv
 *     2. select data base defined tag data using TKVs
 *     3. provide custom tag data (this is not stored in the database)
 */
typedef struct mcs_record_2_t
{
    /**< record device properties*/
    mcs_properties_t device_properties;
    /**< record stream properties*/
    mcs_properties_t stream_properties;
    /**< Graph Key Vector representing the record usecase*/
    mcs_key_vector_t graph_key_vector;
    /**< The usecase calibration key vector for selecting specific calibraion
    to apply before starting a usecase */
    mcs_key_vector_t cal_key_vector;
    /**< The number of tag key vectors. Setting this to zero indicates
    that tkvs are unused */
    uint32_t num_tag_key_vectors;
    /**< length of the tkv list */
    uint32_t tkv_list_size;
    /**< An array of all the tag key vectors within a usecase. Used for
    applying a specific configuration stored in the *.acdb before the
    starting a useecase */
    mcs_tag_key_vector_t* tag_key_vectors;
    /**< Type of record: 0(regular), 1(aanc_path), 2(aanc_spath), 3(aanc_epath)*/
    mcs_record_mode_t record_mode;
    /**< Save recording to file: 0 (ignore write), 1 (write data)*/
    uint32_t write_to_file;
    /**< Record duration in seconds*/
    int32_t record_duration_sec;
    /**< Length of the file name/path*/
    int32_t filename_len;
    /**< Name of/path to file to save recording to*/
    char filename[MCS_MAX_FILENAME_LENGTH];
    /**< Size of tag data blob. Set to 0 to indicate none included */
    uint32_t tag_data_size;
    /**< A pointer to the custom tag data blob. The format of this data is
    [IID, Parameter ID, Data Size, Payload[Data Size], 8 Byte Aligned Padding]
    ...
    [IID, Parameter ID, Data Size, Payload[Data Size], 8 Byte Aligned Padding] */
    uint8_t* tag_data;
}mcs_record_2_t;

/**< Holds pointers to a playback and record session configurations. The
* pointers can be null to indicate no configuration is provided. */
typedef struct mcs_multi_play_rec_session_t
{
    /**< A pointer to a playback session request. Set to null if not provided */
    mcs_play_2_t* playback;
    /**< A pointer to a record session request. Set to null if not provided */
    mcs_record_2_t* record;
}mcs_multi_play_rec_session_t;

/**< The request structure for MCS_CMD_MULTI_PLAY_REC */
typedef struct mcs_multi_play_rec_t
{
    /**< The number of playback + record sessions */
    uint32_t num_sessions;
    /**< An array of playback + record sessions */
    mcs_multi_play_rec_session_t* sessions;
}mcs_multi_play_rec_t;

/**< Handles to a playback and/or record session. Handles can be zero to signify no handle is set. */
typedef struct mcs_multi_play_rec_handle_t
{
    /**< The handle for the playback session. Set this to zero if no handle is provided */
    uint32_t playback_handle;
    /**< The handle for the record session. Set this to zero if no handle is provided */
    uint32_t record_handle;
}mcs_multi_play_rec_handle_t;

/**< The response structure for MCS_CMD_MULTI_PLAY_REC */
typedef struct mcs_multi_play_rec_handle_list_t
{
    /**< The number of playback + record sessions */
    uint32_t num_sessions;
    /**< An array of playback + record session handles*/
    mcs_multi_play_rec_handle_t* handles;
}mcs_multi_play_rec_handle_list_t;

/****************************************************************************
** Functions
*****************************************************************************/

int32_t mcs_init(void);

int32_t mcs_deinit(void);

int32_t mcs_get_api_version(mcs_version_t* api_version);

int32_t mcs_stream_cmd(
    uint32_t    cmd,
    uint8_t     *cmd_buf,
    uint32_t    cmd_buf_size,
    uint8_t     *rsp_buf,
    uint32_t    rsp_buf_size,
    uint32_t    *rsp_buf_bytes_filled);

#ifdef __cplusplus
}
#endif

#endif /* MCS_API_H */

