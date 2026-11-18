pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ar_util.pc
EXTRA_DIST = $(pkgconfig_DATA)

AM_CFLAGS = -Werror -Wall -Wno-error=unused-variable

AM_CFLAGS += -I$(srcdir)/inc
AM_CFLAGS += -I$(srcdir)/api
AM_CFLAGS += -I$(top_srcdir)/ar_osal/api -I$(top_srcdir)/spf/api/apm -I$(top_srcdir)/spf/api/ar_utils

util_sources = ./api/ar_util_data_log_codes.h \
               ./api/ar_util_data_log.h \
               ./api/ar_util_list.h

lib_includedir = $(includedir)
lib_include_HEADERS = $(util_sources)

util_c_sources = src/ar_util_data_log.c \
                 src/ar_util_err_detection.c \
                 src/ar_util_list.c

lib_LTLIBRARIES = libaudioreach-util.la
libaudioreach_util_la_CC = @CC@
libaudioreach_util_la_SOURCES = $(util_c_sources)
libaudioreach_util_la_CFLAGS = $(AM_CFLAGS)
libaudioreach_util_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@
