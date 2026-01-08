LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := liblx-ar_util
LOCAL_MODULE_OWNER := qti
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

LOCAL_SRC_FILES := \
    src/ar_util_list.c \
    src/ar_util_data_log.c \
    src/ar_util_err_detection.c

LOCAL_SHARED_LIBRARIES := \
    liblog \
    liblx-osal

LOCAL_CFLAGS := -D_ANDROID_
LOCAL_HEADER_LIBRARIES := libspf-headers
LOCAL_C_INCLUDES := $(LOCAL_PATH)/api \
                    $(LOCAL_PATH)/inc

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/api

include $(BUILD_SHARED_LIBRARY)

# Build test library.
include $(CLEAR_VARS)

LOCAL_MODULE        := ar_util_in_test_example
LOCAL_VENDOR_MODULE := true

LOCAL_SRC_FILES := \
    test/src/ar_osal_mutex_thread.c \
    test/src/ar_osal_signal_thread.c \
    test/src/ar_osal_test.c \
    test/src/ar_osal_test_service.c \
    test/src/ar_test_file_io.c \
    test/src/ar_test_heap.c \
    test/src/ar_test_list.c \
    test/src/ar_test_mem_op.c \
    test/src/ar_test_shmem.c \
    test/src/ar_test_sleep.c \
    test/src/ar_test_string.c\
    test/src/ar_test_data_log.c \
    test/src/ar_test_log_pkt_op.c

LOCAL_SHARED_LIBRARIES := \
    liblog \
    liblx-ar_util \
    liblx-osal

LOCAL_C_INCLUDES := $(LOCAL_PATH)/api \
                    $(LOCAL_PATH)/test/inc \
                    $(LOCAL_PATH)/inc

include $(BUILD_EXECUTABLE)
