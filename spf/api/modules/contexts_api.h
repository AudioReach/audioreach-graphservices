#ifndef _CONTEXTS_API_H_
#define _CONTEXTS_API_H_

/*==============================================================================
  @file contexts_api.h
  @brief This file contains Public Context IDs that can be used by clients to configure the ACD module

  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  SPDX-License-Identifier: BSD-3-Clause
==============================================================================*/

/** Environment*/
#define MODULE_CMN_CONTEXT_ID_ENV_HOME              0x08001324
#define MODULE_CMN_CONTEXT_ID_ENV_OFFICE            0x08001325
#define MODULE_CMN_CONTEXT_ID_ENV_RESTAURANT        0x08001326
#define MODULE_CMN_CONTEXT_ID_ENV_INDOOR            0x08001327
#define MODULE_CMN_CONTEXT_ID_ENV_INSTREET          0x08001328
#define MODULE_CMN_CONTEXT_ID_ENV_OUTDOOR           0x08001329
#define MODULE_CMN_CONTEXT_ID_ENV_INCAR             0x0800132A
#define MODULE_CMN_CONTEXT_ID_ENV_INTRAIN           0x0800132B
#define MODULE_CMN_CONTEXT_ID_ENV_UNKNOWN           0x0800132C


/** Event*/
#define MODULE_CMN_CONTEXT_ID_EVENT_ALARM           0x0800132D
#define MODULE_CMN_CONTEXT_ID_EVENT_BABYCRYING      0x0800132E
#define MODULE_CMN_CONTEXT_ID_EVENT_DOGBARKING      0x0800132F
#define MODULE_CMN_CONTEXT_ID_EVENT_DOORBELL        0x08001330
#define MODULE_CMN_CONTEXT_ID_EVENT_DOOROPENCLOSE   0x08001331
#define MODULE_CMN_CONTEXT_ID_EVENT_CRASH           0x08001332
#define MODULE_CMN_CONTEXT_ID_EVENT_GLASSBREAKING   0x08001333
#define MODULE_CMN_CONTEXT_ID_EVENT_SIREN           0x08001334

/** Ambience*/
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_SPEECH       0x08001335
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_MUSIC        0x08001336
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SPL    0x08001337
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SPL   0x08001338
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_NOISY_SFLUX  0x08001339
#define MODULE_CMN_CONTEXT_ID_AMBIENCE_SILENT_SFLUX 0x0800133A

#endif //_CONTEXTS_API_H_