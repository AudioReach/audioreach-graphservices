/*
 * adie_rtc.c
 *
 * This file has implementation of adie rtc for LX platform
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "adie_rtc_api.h"
#include "ar_osal_error.h"
#include "ar_osal_file_io.h"
#include "ar_osal_log.h"

#define CDC_REG_DIG_BASE_READ    0x200
#define CDC_REG_DIG_OFFSET    0x000
#define CDC_REG_DIG_BASE_WRITE    0x200
#define FILE_NAME_LENGTH    200
#define MAX_NUMBER_OF_CODECS    20
#define CODEC_INFO_PATH "/proc/asound/card0/codecs/"
#define READ_STEP_SIZE 4000
#define WCD939X_I2C_REG_MAX 0x4FF
#define WCD939X_I2C_REG_MIN 0
#define IS_I2C_REG(reg) (((reg) >= WCD939X_I2C_REG_MIN) && ((reg) <= WCD939X_I2C_REG_MAX))

#define LOG_TAG "ADIE_RTC"

struct chipset_id_info {
    char    *name;
    enum adie_chipset_id_t id;
};

static struct chipset_id_info codec_chipset[] = {
    {"BOLERO", BOLERO},
    {"LPASS", BOLERO},
    {"LPASS-CDC", BOLERO},
    {"WCD939X", WCD939X},
    {"WCD938X", WCD938X},
    {"WCD937X", WCD937X},
    {"WCD9378", WCD9378},
    {"WCD9360", WCD9360},
    {"AQT1000", AQT1000},
    {"WCD9341", WCD9341},
    {"WCD9340", WCD9340},
    {"MSM8X52", MSM8X52},
    {"WHS9410", WHS9410},
    {"WHS9420", WHS9420},
    {"WCD9335", WCD9335},
    {"WSA881X-ANALOG", WSA881X_ANALOG},
    {"WSA881X-SOUNDWIRE", WSA881X_SOUNDWIRE},
    {"WSA881X", WSA881X},
    {"WSA883X", WSA883X},
    {"WSA884X", WSA884X},
    {"MSM8909", MSM8909},
    {"WCD9330", WCD9330},
    {"WCD9326", WCD9326},
    {"WCD9320", WCD9320},
    {"WCD9310", WCD9310},
    {"WCD9306", WCD9306},
    {"WCD9302", WCD9302},
    {"MSM8X16", MSM8X16},
    {"MSM8X10", MSM8X10},
    {"CODEC_UNDEFINED", CODEC_UNDEFINED}
};

struct codec_info {
    uint32_t    handle;
    uint32_t    chipset_id;
    uint32_t    major_version;
    uint32_t    minor_version;
    char        codec_name[FILE_NAME_LENGTH];
    char        reg_path[FILE_NAME_LENGTH];
    char        address_path[FILE_NAME_LENGTH]; /* regmap/codec_name/address */
    char        data_path[FILE_NAME_LENGTH]; /* regmap/codec_name/path */
    int         is_address_data_paths_available;
 };

struct wcd939x_i2c_reg_info {
    char        reg_path[FILE_NAME_LENGTH];
    char        address_path[FILE_NAME_LENGTH]; /* regmap/codec_name/address */
    char        data_path[FILE_NAME_LENGTH]; /* regmap/codec_name/path */
} wcd939x_i2c_info;

static struct codec_info *codec_info;
static uint32_t found_codec_path;
static uint32_t number_of_codecs;
static uint32_t register_length = 4;

static int lnx_to_ar(int lx_err)
{
    switch(lx_err) {
        case -EINVAL:
            return AR_EBADPARAM;
        case -ENODEV:
            return AR_ENORESOURCE;
        case -ENOMEM:
            return AR_ENOMEMORY;
        case 0:
            return AR_EOK;
        default:
            return AR_EFAILED;
    }
}

static int find_codec_index(uint32_t handle)
 {
    int i;
    for (i=0; i < (int)number_of_codecs; i++)
        if (codec_info[i].handle == handle)
            goto done;
    AR_LOG_ERR(LOG_TAG,"%s->could not find codec with handle %d\n", __func__, handle);
    i = -EINVAL;
 done:
    return i;
 }


static int get_chipset_id(char *chipset_name)
{
    int ret = 0;
    unsigned int i;
    if(chipset_name == NULL){
        AR_LOG_ERR(LOG_TAG,"chipset_name is null");
        ret = -EINVAL;
        goto done;
    }

    for (i = 0; i < sizeof(codec_chipset)/sizeof(codec_chipset[0]);i++) {
        if (!strncmp(chipset_name, codec_chipset[i].name, strlen(chipset_name)+1)) {
            codec_info[number_of_codecs].chipset_id = codec_chipset[i].id;
            goto done;
        }
    }
    ret = -EINVAL;
 done:
    return ret;
}

static int read_version_file(char *version_path)
{
    int ret = 0;
    ar_fhandle file_handle;
    int fd;
    char    *token;
    char    *token2;
    char    *save;
    size_t  num_read;
    char    version_entry[FILE_NAME_LENGTH];
    if(version_path == NULL) {
        AR_LOG_ERR(LOG_TAG,"version_path is null");
        ret = -EINVAL;
        goto done;
    }

    fd = ar_fopen(&file_handle, version_path, AR_FOPEN_READ_ONLY);
    if (fd != 0) {
        AR_LOG_ERR(LOG_TAG,"%s: file open failed for path %s\n", __func__, version_path);
        ret = -ENODEV;
        goto done;
    }

    fd = ar_fread(file_handle, version_entry, sizeof(version_entry)-1, &num_read);
    version_entry[FILE_NAME_LENGTH-1]='\0';
    if (fd != 0) {
        AR_LOG_ERR(LOG_TAG,"%s: file read failed for path %s\n", __func__);
        ret = -ENODEV;
        goto done;
    }

    token = strtok_r(version_entry, "_", &save);
    if (token == NULL) {
        AR_LOG_ERR(LOG_TAG,"%s: strtok failed to get chipset name\n", __func__);
        ret = -EINVAL;
        goto close;
    }

    ret = get_chipset_id(token);
    if (ret < 0) {
        AR_LOG_ERR(LOG_TAG,"%s: get_chipset_id failed error %d\n", __func__, ret);
        ret = -EINVAL;
        goto close;
    }

    token = strtok_r(NULL, "_", &save);
    if (token == NULL) {
        AR_LOG_ERR(LOG_TAG,"%s: strtok failed to get chipset major version\n", __func__);
        ret = -EINVAL;
        goto close;
    }

    token2 = strtok_r(NULL, "\n", &save);
    if (token2 == NULL) {
        AR_LOG_ERR(LOG_TAG,"%s: strtok failed to get chipset minor version\n", __func__);
        ret = -EINVAL;
        goto close;
    }

    codec_info[number_of_codecs].major_version = atoi(token);
    codec_info[number_of_codecs].minor_version = atoi(token2);

 close:
    fclose(file_handle);
 done:
    return ret;
}

static int get_address_path(char **match_strings, int array_size)
{
    DIR *dir;
    int i;
    int ret = -EINVAL;
    struct dirent *dirent;
    char path[FILE_NAME_LENGTH] = "/sys/kernel/debug";

    if(*match_strings == NULL){
        ret = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"Empty array of string");
    }

    for(i = 0; i <  array_size; i++) {
        dir = opendir(path);
        if (dir == NULL) {
            AR_LOG_INFO(LOG_TAG,"%d (%s) opendir %s failed\n", errno, strerror(errno), path);
            return -EINVAL;
        }

        while (NULL != (dirent = readdir(dir))) {
            if (strstr(dirent->d_name, match_strings[i]))
            {
                strlcat(path, "/", sizeof(path));
                strlcat(path, dirent->d_name, sizeof(path));

                /* If "reg" found don't search anymore */
                if (i ==  array_size - 1) {
                    strlcpy(codec_info[number_of_codecs].address_path, path,
                        sizeof(codec_info[number_of_codecs].address_path));
                    ret = 0;
                    closedir(dir);
                    goto done;
                }
            }
        }
        closedir(dir);
    }
 done:
    return ret;
}

static int get_data_path(char **match_strings, int array_size)
{
    DIR *dir;
    int i;
    int ret = -EINVAL;
    struct dirent *dirent;
    char path[FILE_NAME_LENGTH] = "/sys/kernel/debug";

    if(*match_strings == NULL){
        ret = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"Empty array of string");
    }

    for(i = 0; i <  array_size; i++) {
        dir = opendir(path);
        if (dir == NULL) {
            AR_LOG_INFO(LOG_TAG,"%d (%s) opendir %s failed\n", errno, strerror(errno), path);
            return -EINVAL;
        }

        while (NULL != (dirent = readdir(dir))) {
            if (strstr(dirent->d_name, match_strings[i]))
            {
                strlcat(path, "/", sizeof(path));
                strlcat(path, dirent->d_name, sizeof(path));

                /* If "reg" found don't search anymore */
                if (i ==  array_size - 1) {
                    strlcpy(codec_info[number_of_codecs].data_path, path,
                        sizeof(codec_info[number_of_codecs].data_path));
                    ret = 0;
                    closedir(dir);
                    goto done;
                }
            }
        }
        closedir(dir);
    }
 done:
    return ret;
}

static int get_reg_path(char **match_strings, int array_size)
{
    DIR *dir;
    int i;
    int ret = -EINVAL;
    struct dirent *dirent;
    char path[FILE_NAME_LENGTH] = "/sys/kernel/debug";

    if(*match_strings == NULL){
        ret = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"Empty array of string");
    }

    for(i = 0; i <  array_size; i++) {
        dir = opendir(path);
        if (dir == NULL) {
            AR_LOG_INFO(LOG_TAG,"%d (%s) opendir %s failed\n", errno, strerror(errno), path);
            return -EINVAL;
        }

        while (NULL != (dirent = readdir(dir))) {
            if (strstr(dirent->d_name, match_strings[i]))
            {
                strlcat(path, "/", sizeof(path));
                strlcat(path, dirent->d_name, sizeof(path));

                /* If "reg" found don't search anymore */
                if (i ==  array_size - 1) {
                    strlcpy(codec_info[number_of_codecs].reg_path, path,
                        sizeof(codec_info[number_of_codecs].reg_path));
                    found_codec_path = 1;
                    ret = 0;
                    closedir(dir);
                    goto done;
                }
            }
        }
        closedir(dir);
    }
 done:
    return ret;
}

enum {
    REG_PATH,
    ADDRESS_PATH,
    DATA_PATH,
};

static int set_i2c_path(char **match_strings, int array_size, int path_id)
{
    DIR *dir;
    int i;
    int ret = -EINVAL;
    struct dirent *dirent;
    char path[FILE_NAME_LENGTH] = "/sys/kernel/debug";

    if(*match_strings == NULL){
        ret = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"Empty array of string");
    }

    for(i = 0; i <  array_size; i++) {
        dir = opendir(path);
        if (dir == NULL) {
            AR_LOG_INFO(LOG_TAG,"%d (%s) opendir %s failed\n", errno, strerror(errno), path);
            return -EINVAL;
        }

        while (NULL != (dirent = readdir(dir))) {
            if (strstr(dirent->d_name, match_strings[i]))
            {
                strlcat(path, "/", sizeof(path));
                strlcat(path, dirent->d_name, sizeof(path));

                /* If "reg" found don't search anymore */
                if (i ==  array_size - 1) {
                    if (path_id == REG_PATH)
                        strlcpy(wcd939x_i2c_info.reg_path, path,
                                sizeof(wcd939x_i2c_info.reg_path));

                    if (path_id == ADDRESS_PATH)
                        strlcpy(wcd939x_i2c_info.address_path, path,
                                sizeof(wcd939x_i2c_info.address_path));

                    if (path_id == DATA_PATH)
                        strlcpy(wcd939x_i2c_info.data_path, path,
                                sizeof(wcd939x_i2c_info.data_path));
                    ret = 0;
                    closedir(dir);
                    goto done;
                }
            }
        }
        closedir(dir);
    }
 done:
    return ret;
}

static int populate_wcd939x_i2c_info(void)
{
    int ret = 0;
    char *match_strings[] = {"regmap", "-000e", "registers"};
    char *match_strings1[] = {"regmap", "-000e", "address"};
    char *match_strings2[] = {"regmap", "-000e", "data"};

    ret = set_i2c_path(match_strings, sizeof(match_strings)/sizeof(char *), REG_PATH);
    if (ret) {
        AR_LOG_ERR(LOG_TAG,"%s: set_i2c_reg_path failed, err %d\n", __func__, ret);
    } else {
        AR_LOG_INFO(LOG_TAG,"%s: reg path : %s\n", __func__, wcd939x_i2c_info.reg_path);
    }

    ret = set_i2c_path(match_strings1, sizeof(match_strings1)/sizeof(char *), ADDRESS_PATH);
    if (ret) {
        AR_LOG_ERR(LOG_TAG,"%s: set_i2c_address_path failed, err %d\n", __func__, ret);
    } else {
        AR_LOG_INFO(LOG_TAG,"%s: address path : %s\n", __func__, wcd939x_i2c_info.address_path);
    }
    ret = set_i2c_path(match_strings2, sizeof(match_strings2)/sizeof(char *), DATA_PATH);
    if (ret) {
        AR_LOG_ERR(LOG_TAG,"%s: set_i2c_data_path failed, err %d\n", __func__, ret);
    } else {
        AR_LOG_INFO(LOG_TAG,"%s: data path : %s\n", __func__, wcd939x_i2c_info.data_path);
    }


    return ret;
}

static int find_codecs_info(void)
{
    DIR     *dir;
    struct dirent   *dentry;
    int ret = 0, ret1 = 0, ret2 = 0;
    char version_path[FILE_NAME_LENGTH] = CODEC_INFO_PATH;

    dir = opendir(version_path);
    if (dir == NULL) {
        AR_LOG_ERR(LOG_TAG,"%s: %d (%s) opendir %s failed\n", __func__, errno, strerror(errno), CODEC_INFO_PATH);
        ret = -ENODEV;
        goto done;
    }

    while ((dentry = readdir(dir)) != NULL) {
        if (!strncmp(dentry->d_name, ".", 1))
            continue;
        ret = snprintf(codec_info[number_of_codecs].codec_name,
            sizeof(codec_info[number_of_codecs].codec_name), "%s", dentry->d_name);
        if (ret < 0) {
            AR_LOG_ERR(LOG_TAG,"%s: snprintf failed: %s in %s, err %d\n",
                __func__, dentry->d_name, CODEC_INFO_PATH, ret);
            continue;
        }
        ret = snprintf(version_path, sizeof(version_path),
            "%s%s/version", CODEC_INFO_PATH, dentry->d_name);
        if (ret < 0) {
            AR_LOG_ERR(LOG_TAG,"%s: snprintf failed: %s in %s, err %d\n",
                __func__, dentry->d_name, CODEC_INFO_PATH, ret);
            continue;
        }
        ret = read_version_file(version_path);
        if (ret < 0) {
            AR_LOG_ERR(LOG_TAG,"%s: read_version_file failed, err %d path %s\n",
                __func__, ret, version_path);
            continue;
        }
        char *match_strings[] = {"regmap", codec_info[number_of_codecs].codec_name, "registers"};
        ret = get_reg_path(match_strings, sizeof(match_strings)/sizeof(char *));
        if (ret < 0) {
            AR_LOG_ERR(LOG_TAG,"%s: get_reg_path failed, err %d, path %s\n",
                __func__, ret, version_path);
            continue;
        }
        char *match_strings1[] = {"regmap", codec_info[number_of_codecs].codec_name, "address"};
        ret1 = get_address_path(match_strings1, sizeof(match_strings1)/sizeof(char *));
        if (ret1 < 0) {
            AR_LOG_DEBUG(LOG_TAG,"%s: get_address_path failed, err %d, path %s\n",
                __func__, ret1, version_path);
        }
        char *match_strings2[] = {"regmap", codec_info[number_of_codecs].codec_name, "data"};
        ret2 = get_data_path(match_strings2, sizeof(match_strings2)/sizeof(char *));
        if (ret2 < 0) {
            AR_LOG_DEBUG(LOG_TAG,"%s: get_data_path failed, err %d, path %s\n",
                __func__, ret2, version_path);
        }
        codec_info->is_address_data_paths_available = 0;
        if (ret1 == 0 && ret2 == 0) {
            codec_info->is_address_data_paths_available = 1;
            AR_LOG_INFO(LOG_TAG,"%s: address path : %s\n", __func__,
                    codec_info[number_of_codecs].address_path);
            AR_LOG_INFO(LOG_TAG,"%s: data path : %s\n", __func__,
                    codec_info[number_of_codecs].data_path);
        }
        codec_info[number_of_codecs].handle = number_of_codecs + 1;
        number_of_codecs++;
    }
    closedir(dir);
 done:
    return ret;
}

static int find_codecs(void)
{
    int ret = 0;
    unsigned int i;
    char *old_match_strings[] = {"regmap", "-000d", "registers"};

    number_of_codecs = 0;
    ret = find_codecs_info();
    if (number_of_codecs == 0) {
        ret = get_reg_path(old_match_strings, sizeof(old_match_strings)/sizeof(char *));
        if (ret < 0) {
            AR_LOG_ERR(LOG_TAG,"%s: get_reg_path failed, err %d\n",__func__, ret);
            goto done;
        }

        codec_info[number_of_codecs].handle = number_of_codecs+1;
        number_of_codecs++;
    }
    for (i=0; i < number_of_codecs; i++)
        AR_LOG_VERBOSE(LOG_TAG,"%s: codec %s: handle %d, chipset id %d, major %d, minor %d, reg path %s\n",
            __func__, codec_info[i].codec_name, codec_info[i].handle, codec_info[i].chipset_id,
            codec_info[i].major_version, codec_info[i].minor_version, codec_info[i].reg_path);
 done:
    return ret;
}

static int parse_codec_reg_file(char_t **rtc_io_buf_base, int32_t *rtc_io_buf_size,
                int fd, int32_t codec_idx)
{
    char_t *rtc_io_buf = NULL;
    char_t *temp;
    int32_t buf_size = 0, rc = 0;
    int32_t numBytes;

    if (fd < 0)
    {
        rc = -EINVAL;
        *rtc_io_buf_base = NULL;
        AR_LOG_ERR(LOG_TAG,"Invalid fd");
        goto done;
    }

    while (1)
    {
        temp = realloc(*rtc_io_buf_base, buf_size + READ_STEP_SIZE);
        if (!temp)
        {
            rc = -ENOMEM;
            free(*rtc_io_buf_base);
            *rtc_io_buf_base = NULL;
            buf_size = 0;
            AR_LOG_ERR(LOG_TAG,"cannot allocate memory: %d, path: %s",
                    READ_STEP_SIZE, codec_info[codec_idx].reg_path);
            goto done;
        }
        *rtc_io_buf_base = temp;
        rtc_io_buf = *rtc_io_buf_base + buf_size;
        numBytes = read(fd, rtc_io_buf, READ_STEP_SIZE);
        if (numBytes <= 0)
            break;

        buf_size += numBytes;
    }
done:
    *rtc_io_buf_size = buf_size;

    return rc;
}

int32_t adie_rtc_get_api_version(struct adie_rtc_version *api_version)
{
    if (!api_version)
        return 0;

    api_version->major = ADIE_RTC_API_MAJOR_VERSION_1;
    api_version->minor = ADIE_RTC_API_MINOR_VERSION_1;

    return 0;
}

int32_t adie_rtc_init(void)
{
    int ret = 0, i = 0;

    codec_info = (struct codec_info *) calloc(1, MAX_NUMBER_OF_CODECS *
                sizeof(struct codec_info));
    if (codec_info == NULL) {
        ret = -ENOMEM;
        AR_LOG_ERR(LOG_TAG, "malloc failed\n");
        goto done;
    }
    if (!found_codec_path) {
        if (find_codecs() < 0) {
            ret = -EINVAL;
            AR_LOG_ERR(LOG_TAG, "failed to get register paths \n");
        }

        for(i = 0; i < number_of_codecs; ++i) {
            if (codec_info[i].chipset_id != WCD939X)
                continue;
            populate_wcd939x_i2c_info();
            break;
        }
    }

 done:
    if (ret) {
        free(codec_info);
        codec_info = NULL;
    }
    return lnx_to_ar(ret);
}

int32_t adie_rtc_deinit(void)
{
    free(codec_info);
    codec_info = NULL;

    return AR_EOK;
}

//TODO: Stubbing this function for now to avoid compilation.
//Need to add support when required to enable adie rtc via v2 function.
int32_t adie_rtc_get_codec_info_v2(struct adie_rtc_codec_info_v2 *codec_info, uint32_t size)
{
	 if (!codec_info || (size == 0)) {
        AR_LOG_ERR(LOG_TAG, "adie_rtc_get_codec_info_v2 failed");
        return AR_EBADPARAM;
    }

	AR_LOG_ERR(LOG_TAG, "adie_rtc_get_codec_info_v2 not supported");
	return AR_ENOTIMPL;
}

int32_t adie_rtc_get_codec_info(struct adie_rtc_codec_info *cdc_info, uint32_t size)
{
    int i, ret = 0, j = 0;

    if (!cdc_info || (size == 0)) {
        AR_LOG_ERR(LOG_TAG, "get codec info failed");
        return AR_EBADPARAM;
    }

    if (size == sizeof(struct adie_rtc_codec_info)) {
        cdc_info->num_of_entries = number_of_codecs;
        for(i = 0, j = 0; i < number_of_codecs; ++i) {
            if (codec_info[i].chipset_id == BOLERO)
                continue;
            ++j;
        }
        cdc_info->num_of_entries = j;
        AR_LOG_DEBUG(LOG_TAG, "num codec entries: %d", cdc_info->num_of_entries);
    } else {
        if (size < (sizeof(uint32_t) + (number_of_codecs - 1) *
                    sizeof(struct adie_rtc_codec_handle))) {
            AR_LOG_ERR(LOG_TAG, "insufficient memory");
            ret = AR_ENEEDMORE;
            goto done;
        }

        for(i = 0, j = 0; i < number_of_codecs; ++i) {
            if (codec_info[i].chipset_id == BOLERO)
                continue;
            cdc_info->handle[j].handle = codec_info[i].handle;
            cdc_info->handle[j].chipset_id = codec_info[i].chipset_id;
            cdc_info->handle[j].chipset_major_version = codec_info[i].major_version;
            cdc_info->handle[j].chipset_minor_version = codec_info[i].minor_version;
            ++j;
        }
    }
 done:
    return ret;
}

int32_t adie_rtc_get_register(struct adie_rtc_register_req *req)
{
    int res = 0;
    int result = 0;
    int fd = -1;
    char_t *rtc_io_buf = NULL;
    char_t *rtc_io_buf_base = NULL;
    int found = 0;
    uint32_t ultempRegAddr = 0;
    int32_t lRegValue = 0;
    uint32_t handle = req->codec_handle;
    int32_t codec_idx = 0;
    uint32_t regAddr = req->reg.register_id;
    uint32_t regMask = req->reg.register_mask;
    size_t numBytes = 0;
    char_t *pCurInputBuf = NULL;
    int32_t rtc_io_buf_size = 0;
    char_t reg[5], val[3];
    reg[4] = '\0', val[2] = '\0';
    uint32_t offset = 0;
    int reg_len, i2c_file_open = 0;
    char *save;
    char *token;

    codec_idx = find_codec_index(handle);
    if (codec_idx < 0) {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"could not find codec index for handle %d", handle);
        goto done;
    } else if (strlen(codec_info[codec_idx].reg_path) == 0) {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"codec path is empty\n %d", handle);
        goto done;
    }
    //AR_LOG_INFO(LOG_TAG,"reg path= %s",codec_info[codec_idx].reg_path);
    if (codec_info[codec_idx].chipset_id == WCD939X) {
        if (IS_I2C_REG(regAddr)) {
           if (strlen(wcd939x_i2c_info.reg_path) == 0) {
               result = -EINVAL;
               AR_LOG_ERR(LOG_TAG,"codec (i2c reg) path is empty\n %d", handle);
               goto done;
           }
           fd = open(wcd939x_i2c_info.reg_path, O_RDWR);
           i2c_file_open = 1;
        } else {
            fd = open(codec_info[codec_idx].reg_path, O_RDWR);
        }
    } else {
        fd = open(codec_info[codec_idx].reg_path, O_RDWR);
    }
    if(fd < 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"cannot open adie peek error: %d, path: %s",
                fd, codec_info[codec_idx].reg_path);
        goto done;
    }
    result = parse_codec_reg_file(&rtc_io_buf_base, &rtc_io_buf_size, fd, codec_idx);
    if (rtc_io_buf_base == NULL || result < 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"cannot allocate memory: %d, path: %s",
                READ_STEP_SIZE, codec_info[codec_idx].reg_path);
            goto close_fd;
    }
    if (rtc_io_buf_size <= 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"length of written bytes does not match expected value %d", rtc_io_buf_size);
        goto close_fd;
    }
    numBytes = rtc_io_buf_size;
    rtc_io_buf = rtc_io_buf_base;
    memcpy((void*)reg, (void*)(rtc_io_buf+offset), sizeof(uint32_t));
    token = strtok_r(reg, ":", &save);
    if (token == NULL) {
        AR_LOG_ERR(LOG_TAG,"%s: strtok failed to find register length : delimiter!\n", __func__);
        result = -EINVAL;
        goto done;
    }
    reg_len = strlen(token);
    if (reg_len <= 0) {
        AR_LOG_ERR(LOG_TAG,"%s: register length is %d!\n", __func__, reg_len);
        result = -EINVAL;
        goto done;
    }
    register_length = reg_len;
    AR_LOG_DEBUG(LOG_TAG,"%s: valid register length is %d\n", __func__, register_length);
    while(numBytes>offset)
    {
        memcpy((void*)reg, (void*)(rtc_io_buf+offset), sizeof(uint32_t));
        offset += register_length;
        ultempRegAddr = strtoul(reg, NULL, 16);
        offset += 2;
        memcpy((void*)val, (void*)(rtc_io_buf+offset), sizeof(uint16_t));
        lRegValue = strtol(val, NULL, 16);
        offset += 3;
        if (ultempRegAddr >= CDC_REG_DIG_BASE_READ)
            ultempRegAddr -= CDC_REG_DIG_OFFSET;
        if(ultempRegAddr == regAddr)
        {
            found = 1;
            AR_LOG_DEBUG(LOG_TAG,"register[%08X] found from the file!\n",regAddr);
            break;
        }
    }
    if (found == 0)
    {
        result = -EINVAL;
        if (i2c_file_open) {
            AR_LOG_ERR(LOG_TAG,"get adie register[0x%x] failed Peek(%s) Poke(%s)",
                    regAddr, wcd939x_i2c_info.reg_path, wcd939x_i2c_info.reg_path);
        } else {
            AR_LOG_ERR(LOG_TAG,"get adie register[0x%x] failed Peek(%s) Poke(%s)",
                    regAddr, codec_info[codec_idx].reg_path, codec_info[codec_idx].reg_path);
        }
        goto close_fd;
    }
    else
    {
        AR_LOG_ERR(LOG_TAG,"Found the value for register = 0x%X, value = 0x%X\n",regAddr,lRegValue);
    }
    /* return a masked value */
    lRegValue &= regMask;
    req->reg.value = lRegValue;/* output value*/

close_fd:
    close(fd);
done:
    free(rtc_io_buf_base);
    return lnx_to_ar(result);
}

int32_t _adie_rtc_set_register(int32_t codec_idx, uint32_t regAddr, uint32_t ulRegValue)
{
    int result = 0;
    int fd = -1, fd1 = -1;
    size_t numBytes1 = 0, val_numBytes1 = 0;
    size_t numBytes2 = 0, val_numBytes2 = 0;
    char *temp = NULL;
    char *val_temp = NULL;

    numBytes1 = asprintf(&temp, "0x%x", regAddr);
    if (codec_info[codec_idx].chipset_id == WCD939X) {
        if (IS_I2C_REG(regAddr)) {
           if (strlen(wcd939x_i2c_info.address_path) == 0) {
               result = -EINVAL;
               AR_LOG_ERR(LOG_TAG,"codec (i2c address) path is empty\n %d", codec_idx);
               if (temp != NULL)
               {
                   free(temp);
                   temp = NULL;
               }
               goto done;
           }
           fd = open(wcd939x_i2c_info.address_path, O_RDWR);
        } else {
            fd = open(codec_info[codec_idx].address_path, O_RDWR);
        }
    } else {
        fd = open(codec_info[codec_idx].address_path, O_RDWR);
    }
    if(fd < 0) {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"ERROR! cannot open adie address path error: %d, path: %s",
                fd, codec_info[codec_idx].address_path);
        if (temp != NULL)
        {
            free(temp);
            temp = NULL;
        }
        goto done;
    }
    val_numBytes1 = asprintf(&val_temp, "0x%x", ulRegValue);
    if (codec_info[codec_idx].chipset_id == WCD939X) {
        if (IS_I2C_REG(regAddr)) {
           if (strlen(wcd939x_i2c_info.data_path) == 0) {
               result = -EINVAL;
               AR_LOG_ERR(LOG_TAG,"codec (i2c data) path is empty\n %d", codec_idx);
               if (val_temp != NULL)
               {
                   free(val_temp);
                   val_temp = NULL;
               }
               close(fd);
               if (temp != NULL)
               {
                   free(temp);
                   temp = NULL;
               }
               goto done;
           }
           fd1 = open(wcd939x_i2c_info.data_path, O_RDWR);
        } else {
            fd1 = open(codec_info[codec_idx].data_path, O_RDWR);
        }
    } else {
        fd1 = open(codec_info[codec_idx].data_path, O_RDWR);
    }
    if(fd1 < 0) {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"ERROR! cannot open adie data path error: %d, path: %s",
                fd1, codec_info[codec_idx].data_path);
        if (val_temp != NULL)
        {
            free(val_temp);
            val_temp = NULL;
        }
        close(fd);
        if (temp != NULL)
        {
            free(temp);
            temp = NULL;
        }
        goto done;
    }
    numBytes2 = write(fd, temp, numBytes1);
    val_numBytes2 = write(fd1, val_temp, val_numBytes1);
    if (temp != NULL) {
        free(temp);
        temp = NULL;
    }
    if (val_temp != NULL) {
        free(val_temp);
        val_temp = NULL;
    }
    close(fd);
    close(fd1);
    /* make sure the write is successful */
    if (numBytes1 != numBytes2) {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"set adie register failed for Register[0x%X], addressBytes[%zu], valBytes[%zu]",
                regAddr ,numBytes1, val_numBytes1);
    }
done:
    return result;
}

int32_t adie_rtc_set_register(struct adie_rtc_register_req *req)
{
    int result = 0;
    int fd = -1;
    uint32_t ulRegValue = req->reg.value;
    uint32_t handle = req->codec_handle;
    int32_t codec_idx = 0;
    uint32_t regAddr = req->reg.register_id;
    uint32_t regMask = req->reg.register_mask;
    size_t numBytes1 = 0;
    size_t numBytes2 = 0;
    char *temp = NULL;

    codec_idx = find_codec_index(handle);
    if (codec_idx < 0) {
        AR_LOG_ERR(LOG_TAG,"could not find codec index for handle\n %d", handle);
        goto done;
    } else if (strlen(codec_info[codec_idx].reg_path) == 0) {
        AR_LOG_ERR(LOG_TAG,"codec path is empty\n %d", handle);
        goto done;
    }

    /* set the value as masked one*/
    ulRegValue &= regMask;

    if (regAddr >= CDC_REG_DIG_BASE_WRITE)
        regAddr += CDC_REG_DIG_OFFSET;

    AR_LOG_DEBUG(LOG_TAG,"set register request received for ==> reg[%X], val[%X], bytes[%zu]\n",
            regAddr, ulRegValue, numBytes1);
    if (codec_info->is_address_data_paths_available) {
        result = _adie_rtc_set_register(codec_idx, regAddr, ulRegValue);
    } else {
        numBytes1 = asprintf(&temp, "0x%x 0x%x", regAddr, ulRegValue);
        fd = open(codec_info[codec_idx].reg_path, O_RDWR);
        if(fd < 0) {
            result = -EINVAL;
            AR_LOG_ERR(LOG_TAG,"ERROR! cannot open adie poke error: %d, path: %s",
                    fd, codec_info[codec_idx].reg_path);
            if (temp != NULL)
            {
                free(temp);
                temp = NULL;
            }

            goto done;
        }
        numBytes2 = write(fd, temp, numBytes1);
        AR_LOG_DEBUG(LOG_TAG,"set register ==> actual bytes written[%zu]\n", numBytes2);
        if (temp != NULL) {
            free(temp);
            temp = NULL;
        }
        close(fd);
        /* make sure the write is successful */
        if (numBytes1 != numBytes2) {
            result = -EINVAL;
            AR_LOG_ERR(LOG_TAG,"set adie register failed for Register[0x%X], numBytes[%zu]",regAddr ,numBytes1);
            goto done;
        }
    }
    //*resp_buf_bytes_filled = 0;
    if (result == 0)
        AR_LOG_INFO(LOG_TAG,"Set Register Success\n");
 done:
    return lnx_to_ar(result);
}

int32_t adie_rtc_set_multiple_registers(struct adie_rtc_multi_register_req *req, uint32_t size)
{
    struct adie_rtc_register_req  sreq;
    uint32_t i = 0, regAddr = 0, regMask = 0;
    size_t numBytes1 = 0;
    size_t numBytes2 = 0;
    uint32_t ulRegValue = 0;
    char *temp = NULL;
    int32_t result = 0;
    uint32_t handle;
    int32_t codec_idx = 0;
    int fd = -1;

    if (!req || (size == 0))
        return lnx_to_ar(-EINVAL);

    if (req->num_registers == 0)
        return lnx_to_ar(-EINVAL);

    handle = req->codec_handle;
    codec_idx = find_codec_index(handle);
    if (codec_idx < 0) {
        AR_LOG_ERR(LOG_TAG, "could not find codec index for handle %d",
                handle);
        result = -EINVAL;
        goto done;
    } else if (strlen(codec_info[codec_idx].reg_path) == 0) {
        AR_LOG_ERR(LOG_TAG, "codec path is empty %d", handle);
        result = -EINVAL;
        goto done;
    }
    for (i = 0; i < req->num_registers; ++i) {
        temp = NULL;
        regAddr = req->register_list[i].register_id;
        regMask = req->register_list[i].register_mask;
        ulRegValue = req->register_list[i].value;
        ulRegValue &= regMask;

        if (regAddr >= CDC_REG_DIG_BASE_WRITE)
            regAddr += CDC_REG_DIG_OFFSET;


        if (codec_info->is_address_data_paths_available) {
            result = _adie_rtc_set_register(codec_idx, regAddr, ulRegValue);
            if (result)
                goto done;
        } else {
            numBytes1 = asprintf(&temp, "0x%x 0x%x", regAddr, ulRegValue);

            fd = open(codec_info[codec_idx].reg_path, O_RDWR);
            if (fd < 0) {
                AR_LOG_ERR(LOG_TAG, "ERROR! cannot open adie poke error: %d, path: %s",
                        fd, codec_info[codec_idx].reg_path);
                result = -EINVAL;
                if (temp != NULL) {
                    free(temp);
                    temp = NULL;
                }
                goto done;
            }
            numBytes2 = write(fd, temp, numBytes1);
            if (temp != NULL) {
                free(temp);
                temp = NULL;
            }
            close(fd);

            if (numBytes1 != numBytes2) {
                AR_LOG_ERR(LOG_TAG, "set multi registers failed, numBytes1[%zu], numBytes2[%zu]",
                        numBytes1, numBytes2);
                result = -EINVAL;
                goto done;
            }
        }
        usleep(30);
    }

done:
    return lnx_to_ar(result);
}

int32_t adie_rtc_get_multiple_registers(struct adie_rtc_multi_register_req *req, uint32_t size)
{
    struct adie_rtc_register_req  sreq;
    uint32_t i = 0;
    uint32_t handle;
    int32_t codec_idx = 0;
    int fd = -1;
    int result = -EINVAL;
    int found = 0;
    uint32_t ultempRegAddr = 0;
    int32_t lRegValue = 0;
    char_t *rtc_io_buf_base = NULL;
    char_t *rtc_io_buf = NULL;
    int32_t rtc_io_buf_size = 0;
    size_t numBytes = 0;
    uint32_t regAddr, regMask;
    char_t reg[5], val[3];
    char *save;
    char *token;
    int reg_len;
    uint32_t count = 0;
    uint32_t offset = 0;

    if (!req || (size == 0))
        return lnx_to_ar(-EINVAL);

    if (req->num_registers == 0)
        return lnx_to_ar(-EINVAL);

    handle = req->codec_handle;
    codec_idx = find_codec_index(handle);
    if (codec_idx < 0) {
        AR_LOG_ERR(LOG_TAG, "could not find codec index for handle %d",
                handle);
        goto done;
    } else if (strlen(codec_info[codec_idx].reg_path) == 0) {
        AR_LOG_ERR(LOG_TAG, "codec path is empty %d", handle);
        goto done;
    }
    regAddr = req->register_list[0].register_id; //read first reg
    if (codec_info[codec_idx].chipset_id == WCD939X) {
        if (IS_I2C_REG(regAddr)) {
           if (strlen(wcd939x_i2c_info.reg_path) == 0) {
               result = -EINVAL;
               AR_LOG_ERR(LOG_TAG,"codec (i2c reg) path is empty\n %d", handle);
               goto done;
           }
           fd = open(wcd939x_i2c_info.reg_path, O_RDWR);
        } else {
            fd = open(codec_info[codec_idx].reg_path, O_RDWR);
        }
    } else {
        fd = open(codec_info[codec_idx].reg_path, O_RDWR);
    }
    if(fd < 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"cannot open adie peek error: %d, path: %s",
                fd, codec_info[codec_idx].reg_path);
        goto done;
    }
    result = parse_codec_reg_file(&rtc_io_buf_base, &rtc_io_buf_size, fd, codec_idx);
    if (rtc_io_buf_base == NULL || result < 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"cannot allocate memory: %d, path: %s",
                READ_STEP_SIZE, codec_info[codec_idx].reg_path);
        goto close_fd;
    }
    if (rtc_io_buf_size <= 0)
    {
        result = -EINVAL;
        AR_LOG_ERR(LOG_TAG,"length of written bytes does not match expected value %d", rtc_io_buf_size);
        goto close_fd;
    }
    numBytes = rtc_io_buf_size;
    rtc_io_buf = rtc_io_buf_base;

    reg[4] = '\0', val[2] = '\0';
    for (i = 0; i < req->num_registers; ++i) {
        regAddr = req->register_list[i].register_id;
        regMask = req->register_list[i].register_mask;

        found = 0;
        offset = 0;
        if (rtc_io_buf == NULL) {
            AR_LOG_ERR(LOG_TAG, "rtc_io_buf is NULL");
            result = -EINVAL;
            goto close_fd;
        }
        memcpy((void*)reg, (void*)(rtc_io_buf+offset), sizeof(uint32_t));
        token = strtok_r(reg, ":", &save);
        if (token == NULL) {
            AR_LOG_ERR(LOG_TAG,"%s: strtok failed to find register length : delimiter!\n", __func__);
            result = -EINVAL;
            goto close_fd;
        }
        reg_len = strlen(token);
        if (reg_len <= 0) {
            AR_LOG_ERR(LOG_TAG,"%s: register length is %d!\n", __func__, reg_len);
            result = -EINVAL;
            goto done;
        }
        register_length = reg_len;
        AR_LOG_DEBUG(LOG_TAG,"%s: valid register length is %d\n", __func__, register_length);
        while(numBytes > offset) {
            memcpy((void*)reg, (void*)(rtc_io_buf+offset), sizeof(uint32_t));
            offset += register_length;
            ultempRegAddr = strtoul(reg, NULL, 16);
            offset += 2;
            memcpy((void*)val, (void*)(rtc_io_buf+offset), sizeof(uint16_t));
            lRegValue = strtol(val, NULL, 16);
            offset += 3;
            if (ultempRegAddr >= CDC_REG_DIG_BASE_READ)
                ultempRegAddr -= CDC_REG_DIG_OFFSET;

            if(ultempRegAddr == regAddr)
            {
                count++;
                found = 1;
                /* return a masked value */
                lRegValue &= regMask;
                req->register_list[i].value = lRegValue;
                usleep(30);
                AR_LOG_DEBUG(LOG_TAG, "reg[%08X],val[%08X], count[%d]\n",
                        ultempRegAddr, lRegValue,count);
                break;
            }
        }
    }
    if (found == 0) {
        AR_LOG_ERR(LOG_TAG, "GetMultipleAdieReg failed because reg[%08x] is not found\n", regAddr);
        result = -EINVAL;
        goto close_fd;
    }

    if (result == 0 && req->num_registers != count) {
        AR_LOG_ERR(LOG_TAG, "Error in lengths of input or output buffers or total registers");
        result = 0;
        goto close_fd;
    }

close_fd:
    if (fd != -1)
        close(fd);

done:
    if(rtc_io_buf_base)
        free(rtc_io_buf_base);

    return lnx_to_ar(result);
}

