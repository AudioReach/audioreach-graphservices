 /*
* mcs.c
*
*This file has implementation of mcs for LX platform
*
* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
* SPDX-License-Identifier: BSD-3-Clause
*/

#include "mcs_api.h"
#include "ats_common.h"

#ifdef MCS_ENABLED
typedef int32_t(*mcs_stream_cmd_t)(
    uint32_t cmd,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t*rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled);

typedef int32_t(*mcs_init_t)(void);
typedef int32_t(*mcs_deinit_t)(void);
mcs_init_t pal_mcs_init;
mcs_deinit_t pal_mcs_deinit;
mcs_stream_cmd_t pal_mcs_stream_cmd;

/*------------------------------------------
* MCS Dynamic loading
*------------------------------------------*/

#include <dlfcn.h>
#define MCS_LIB  "libmcs.so"
void* mcsLibHandle = NULL;

/**
* \brief
* Dynamically load mcs.so
*
* \return 0 on success, non-zero on failure
*/

int32_t load_mcs_lib()
{
    int32_t status = AR_EOK;
    ATS_DBG("Enter.");
    if (!mcsLibHandle) {
         mcsLibHandle = dlopen(MCS_LIB, RTLD_NOW);
         if (NULL == mcsLibHandle) {
             const char *err_str = dlerror();
             ATS_ERR("DLOPEN failed for %s, %s",
             MCS_LIB, err_str ? err_str : "unknown");
             status = AR_EFAILED;
             return status;
          }
     }


     /*Loading the mcs function symbols*/
    pal_mcs_stream_cmd = (mcs_stream_cmd_t)dlsym(mcsLibHandle, "mcs_stream_cmd");
    if (!pal_mcs_stream_cmd) {
         ATS_ERR("dlsym error %s for mcs_stream_cmd", dlerror());
         status = AR_EFAILED;
         dlclose(mcsLibHandle);
         mcsLibHandle = NULL;
         return status;
     }

    pal_mcs_init = (mcs_init_t)dlsym(mcsLibHandle, "mcs_init");
    if (!pal_mcs_init) {
          ATS_ERR("dlsym error %s for mcs_init", dlerror());
          status = AR_EFAILED;
          dlclose(mcsLibHandle);
          mcsLibHandle = NULL;
          return status;
    }

    pal_mcs_deinit = (mcs_deinit_t)dlsym(mcsLibHandle, "ats_mcs_deinit");
    if (!pal_mcs_deinit) {
          ATS_ERR("dlsym error %s for pal_mcs_deinit", dlerror());
          status = AR_EFAILED;
          dlclose(mcsLibHandle);
          mcsLibHandle = NULL;
    }
     return status;
}

int32_t mcs_init(void)
{
    int32_t status = AR_EOK;

    status = load_mcs_lib();
    if(AR_FAILED(status)) {
        ATS_ERR("Error[%d]: Failed to load mcs lib", status);
        return status;
    }

    status = pal_mcs_init();
    if(AR_FAILED(status)) {
        ATS_ERR("Error[%d]: libmcs init failed", status);
        return status;
    }

    return status;
}

int32_t mcs_stream_cmd(
    uint32_t cmd,
    uint8_t *cmd_buf,
    uint32_t cmd_buf_size,
    uint8_t*rsp_buf,
    uint32_t rsp_buf_size,
    uint32_t *rsp_buf_bytes_filled)
{
    return pal_mcs_stream_cmd(cmd,
    cmd_buf, cmd_buf_size,
    rsp_buf, rsp_buf_size,
    rsp_buf_bytes_filled);
}

int32_t mcs_get_api_version(mcs_version_t* api_version)
{
    if (!api_version)
        return 0;

    api_version->major = MCS_API_MAJOR_VERSION_1;
    api_version->minor = MCS_API_MINOR_VERSION_0;
    return 0;
}

int32_t mcs_deinit(void)
{
    int32_t status = AR_EOK;

    status = pal_mcs_deinit ? pal_mcs_deinit() : AR_EFAILED;
    if (mcsLibHandle != NULL) {
        dlclose(mcsLibHandle);
        mcsLibHandle = NULL;
    }
    pal_mcs_init = NULL;
    pal_mcs_deinit = NULL;
    return status;
}
#else
int32_t mcs_get_api_version(mcs_version_t* api_version __attribute__((unused)))
{
    return AR_ENOTIMPL;
}

int32_t mcs_init(void)
{
    return AR_ENOTIMPL;
}

int32_t mcs_stream_cmd(
    uint32_t cmd __attribute__((unused)),
    uint8_t *cmd_buf __attribute__((unused)),
    uint32_t cmd_buf_size __attribute__((unused)),
    uint8_t*rsp_buf __attribute__((unused)),
    uint32_t rsp_buf_size __attribute__((unused)),
    uint32_t *rsp_buf_bytes_filled __attribute__((unused)))
{
    return AR_ENOTIMPL;
}

int32_t mcs_deinit(void)
{
    return AR_ENOTIMPL;
}
#endif

