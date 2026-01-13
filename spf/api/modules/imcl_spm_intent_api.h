/**========================================================================
 @file imcl_spm_intent_api.h

 @brief This file contains all the public intent names
 the intent related structs are defined in internal header files

 Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 SPDX-License-Identifier: BSD-3-Clause

 ====================================================================== */

#ifndef _IMCL_SPM_INTENT_API_H_
#define _IMCL_SPM_INTENT_API_H_

/*------------------------------------------------------------------------------
 *  Header Includes
 *----------------------------------------------------------------------------*/

#include "ar_defs.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/** -----------------------------------------------------------------------
 ** Type Declarations
 ** ----------------------------------------------------------------------- */

/* clang-format off */

/*==============================================================================
  Intent ID
==============================================================================*/
/**< Intent defines the payload structure of the IMCL message.
SVA and Dam modules supports the following functionalities â€“
1. Channel resizing â€“ This as an input intent ID exposed by Dam module, which allows resizing the channel buffers based
on SVA moduleâ€™s buffering requirement.
2. Output port data flow control - This as an input intent ID exposed by Dam module. This intent is used to open/close
the Dam output ports gates by SVA module.
3. Best channel output â€“ This intent allows detection engines to send the best channel indices to Dam module. Upon
receiving the best channel indices, Dam module outputs only the best channels from the given output port.
4. FTRT data availably info - This as an output intent ID exposed by Dam module. This intent is used by Dam module to
send the unread data length [FTRT data] length present in the channel buffers to the SVA module. */

#define INTENT_ID_AUDIO_DAM_DETECTION_ENGINE_CTRL    0x08001064

/*==============================================================================
  Intent ID
==============================================================================*/
// Intent ID for the control link between FFECNS and detection engine.
#define INTENT_ID_FFECNS_SVA_FREEZE                  0x080010BA

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID for the control link between AVC Tx and Rx module.

The AVC module automatically adjusts the loudness of the Rx voice in
response to the near-end noise level on the Tx path. This adjustment
improves the intelligibility of the receive path voice signal.
*/
#define INTENT_ID_AVC                                0x080010DB

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID to send DRC parameters over control link.
e.g.
Control link between Rx DRC and Tx AVC modules in voice path.
*/
#define INTENT_ID_DRC_CONFIG                         0x080010F3

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID for the control link to send gain information.
This intent can be used by a module to send its gain to another module.

e.g.
Soft Volume Control sends the target gain to AVC-TX module in voice path.
*/
#define INTENT_ID_GAIN_INFO                          0x080010F5

/*==============================================================================
  Intent ID
==============================================================================*/
// Intent ID for the control link between Soft Vol and Popless Equalizer.
#define INTENT_ID_P_EQ_VOL_HEADROOM                  0x08001118

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID for the control link between RVE Tx and Rx module.

The RVE module automatically adjusts the loudness of the Rx voice in
response to the near-end noise level on the Tx path. This adjustment
improves the intelligibility of the receive path voice signal.
*/
#define INTENT_ID_RVE                                0x080010DD

/*==============================================================================
  Intent ID
==============================================================================*/
/** IMCL intent ID for sending sideband data to the encoder
 * This intent id supports two param ids:
 * 1. IMCL_PARAM_ID_BT_SIDEBAND_ENCODER_FEEDBACK
 * 2. IMCL_PARAM_ID_BIT_RATE_LEVEL_ENCODER_FEEDBACK */
#define INTENT_ID_BT_ENCODER_FEEDBACK                0x080010D7

/*==============================================================================
  Intent ID
==============================================================================*/
/** IMCL intent ID for sending the notification to the packetizer v1
 * to send sideband ack to BT that the primer sideband has been
 * received by the RX RAT module */
#define INTENT_ID_PACKETIZER_V1_FEEDBACK             0x08001148

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID for the control link between CTM Tx and Rx module.
*/
#define INTENT_ID_CTM_TTY                            0x08001191

/*==============================================================================
  Intent ID
==============================================================================*/
/**<
Intent ID for the control link between TTY module(1x/CTM/LTE_TTY in Rx path) and soft volume module(in Tx path).
TTY module communicates with the soft volume module to indicate whether to
mute or unmute the stream in the Tx path. The parameter - PARAM_ID_IMCL_MUTE
is used for this communication.

*/
#define INTENT_ID_MUTE                               0x08001195

/* clang-format on */

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* _IMCL_SPM_INTENT_API_H_ */
