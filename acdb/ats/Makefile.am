pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ats.pc
EXTRA_DIST = $(pkgconfig_DATA)

ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall \
            -Wundef \
            -O2
AM_CFLAGS += @GLIB_CFLAGS@ -include glib.h

if USE_G_STR_FUNC
AM_CFLAGS += -Dstrlcpy=g_strlcpy -Dstrlcat=g_strlcat
endif

AM_CFLAGS += -I$(top_srcdir)/ar_osal/api \
             -I$(top_srcdir)/acdb/api \
             -I$(top_srcdir)/acdb/inc \
             -I$(top_srcdir)/gsl/api \
             -I$(top_srcdir)/gsl/rtc_api \
             -I$(top_srcdir)/gsl/dls_client_api


AM_CFLAGS += -I ${srcdir}/inc \
             -I ${srcdir}/api \
             -I ${srcdir}/transports/diag/linux/actp/inc \
             -I ${srcdir}/transports/diag/linux/audtp/inc \
             -I ${srcdir}/online/common/inc \
             -I ${srcdir}/rtc/common/inc \
             -I ${srcdir}/fts/common/inc \
             -I ${srcdir}/mcs/common/inc \
             -I ${srcdir}/mcs/common/api \
             -I ${srcdir}/adie/common/inc \
             -I ${srcdir}/adie/common/api \
             -I ${srcdir}/sockets/common/api/ \
             -I ${srcdir}/transports/common/api/ \
             -I ${srcdir}/transports/common/inc/ \
             -I ${srcdir}/transports/tcpip_server/inc/ \
             -I ${srcdir}/transports/tcpip_server/api/ \
             -I ${srcdir}/dls/common/inc

AM_CPPFLAGS = $(AM_CFLAGS)

ats_headers = ./api/ats.h

ats_c_sources = ./src/ats.c \
                ./src/ats_command.c \
                ./adie/common/src/ats_adie_rtc.c \
                ./adie/linux/adie_rtc.c \
                ./transports/diag/linux/actp/src/actp.c \
                ./transports/diag/linux/audtp/src/audtp.c \
                ./fts/common/src/ats_fts.c \
                ./mcs/common/src/ats_mcs.c \
                ./mcs/linux/mcs.c \
                ./online/common/src/ats_online.c \
                ./rtc/common/src/ats_rtc.c \
                ./sockets/linux/src/ar_sockets.cpp \
                ./transports/common/src/ats_transport.c \
                ./transports/tcpip_server/src/tcpip_cmd_server.cpp \
                ./transports/tcpip_server/src/tcpip_dls_server.cpp \
                ./transports/tcpip_server/src/tcpip_socket_util.cpp \
                ./dls/common/src/ats_dls.c

#Includes
lib_includedir = $(includedir)
lib_include_HEADERS = $(ats_headers)
requiredlibs = -lrt

lib_LTLIBRARIES = libar-ats.la
libar_ats_la_CC = @CC@
libar_ats_la_LIBADD = -lar-osal -L$(top_builddir)/ar_osal
libar_ats_la_LIBADD += -lar-acdb -L$(top_builddir)/acdb
if CUTILS_SUPPORTED
libar_ats_la_LIBADD += -lcutils
AM_CFLAGS += -DAR_ATS_USE_CUTILS
endif

if USE_DUMMY_DIAG
AM_CFLAGS += -DATS_USES_DUMMY_DIAG \
             -I ${srcdir}/transports/diag/linux/inc
else
AM_CFLAGS += @DIAG_CFLAGS@
AM_CPPFLAGS += -DFEATURE_LE_DIAG
requiredlibs += @DIAG_LIBS@
libar_ats_la_LIBADD += @DIAG_LIBS@
endif

libar_ats_la_SOURCES = $(ats_c_sources)
libar_ats_la_CFLAGS = $(AM_CFLAGS)
libar_ats_la_CPPFLAGS = $(AM_CPPFLAGS)
if USES_ATS_TRANSPORT_TCPIP
libar_ats_la_CFLAGS += -DATS_TRANSPORT_TCPIP
libar_ats_la_CPPFLAGS += -DATS_TRANSPORT_TCPIP
endif

if USES_ATS_DATA_LOGGING
libar_ats_la_CFLAGS += -DATS_DATA_LOGGING
libar_ats_la_CPPFLAGS += -DATS_DATA_LOGGING
endif

libar_ats_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@

AM_CPPFLAGS += -DSOCK_PATH='"/usr/bin/gateway/ats_sockets"' \
        -DSOCK_PATH_SERVER='"/usr/bin/gateway/ats_sockets/unix_sock.server"' \
        -DSOCK_PATH_GATEWAY='"/usr/bin/gateway/ats_sockets/unix_sock.gateway"'

AM_CPPFLAGS += -I$(srcdir)/transports/tcpip_gateway/inc
AM_CPPFLAGS += -I$(top_srcdir)/ar_osal/api
AM_CPPFLAGS += -I$(top_srcdir)/acdb/ats/sockets/common/api/

AM_CPPFLAGS += @GLIB_CFLAGS@ -include glib.h

if USE_G_STR_FUNC
AM_CPPFLAGS += -Dstrlcpy=g_strlcpy -Dstrlcat=g_strlcat
endif

gateway_sources = ./transports/tcpip_gateway/src/tcpip_gateway_main.cpp \
                  ./transports/tcpip_gateway/src/tcpip_gateway_cmd_server.cpp \
                  ./transports/tcpip_gateway/src/tcpip_gateway_dls_server.cpp \
                  ./transports/tcpip_gateway/src/tcpip_gateway_socket_util.cpp \
                  ./sockets/linux/src/ar_sockets.cpp

bin_PROGRAMS = ats_gateway
ats_gateway_CC = @CC@
ats_gateway_SOURCES = $(gateway_sources)
ats_gateway_LDADD = $(top_builddir)/ar_osal/libar-osal.la
ats_gateway_CPPFLAGS = $(AM_CPPFLAGS)

if USES_ATS_DATA_LOGGING
ats_gateway_CFLAGS = -DATS_DATA_LOGGING
ats_gateway_CPPFLAGS += -DATS_DATA_LOGGING
endif
