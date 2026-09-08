pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gpr.pc
EXTRA_DIST = $(pkgconfig_DATA)

AM_CFLAGS = -Wall

AM_CFLAGS += -I$(srcdir)/api
AM_CFLAGS += -I$(srcdir)/api/private
AM_CFLAGS += -I$(srcdir)/core/inc
AM_CFLAGS += -I$(srcdir)/core/inc/ar_utils/generic
AM_CFLAGS += -I$(srcdir)/core/src
AM_CFLAGS += -I$(srcdir)/datalinks/gpr_lx/inc
AM_CFLAGS += -I$(srcdir)/ext/logging/inc
AM_CFLAGS += -I$(srcdir)/ext/dynamic_allocation/inc
AM_CFLAGS += -I$(top_srcdir)/ar_osal/api
AM_CFLAGS += -I$(top_srcdir)/ar_util/api
AM_CFLAGS += -I$(top_srcdir)/gpr/api
AM_CFLAGS += -I$(top_srcdir)/acdb/api
AM_CFLAGS += -I$(top_srcdir)/spf/api/ar_utils -I$(top_srcdir)/spf/api/apm -I$(top_srcdir)/spf/api/modules

AM_CFLAGS += -DSESSION_ARRAY_SIZE=200
AM_CFLAGS += -D_GNU_SOURCE

gpr_sources =  ./api/gpr_api.h \
               ./api/gpr_api_inline.h \
               ./api/gpr_comdef.h \
               ./api/gpr_ids_domains.h \
               ./api/gpr_msg_if.h \
               ./api/gpr_pack_begin.h \
               ./api/gpr_pack_end.h \
               ./api/gpr_packet.h \
               ./api/ipc_dl_api.h \
               ./api/ar_guids.h \
               ./api/ar_types.h \
               ./core/inc/gpr_api_i.h \
               ./core/inc/gpr_list.h \
               ./core/src/gpr_memq.h \
               ./datalinks/gpr_lx/inc/gpr_lx.h

gpr_c_sources =  ./core/src/gpr_drv.c \
                 ./core/src/gpr_list.c \
                 ./core/src/gpr_main.c \
                 ./core/src/gpr_memq.c \
                 ./core/src/gpr_drv_island.c \
                 ./core/src/gpr_list_island.c \
                 ./core/src/gpr_memq_island.c \
                 ./core/src/hash_based/gpr_session.c \
                 ./core/src/hash_based/gpr_session_island.c \
                 ./ext/dynamic_allocation/src/gpr_dynamic_allocation.c \
                 ./ext/logging/src/gpr_log_generic.c \
                 ./ext/logging/stub_src/gpr_log_diag_stub.c \
                 ./datalinks/gpr_lx/src/gpr_lx.c \
                 ./platform/linux/gpr_init_lx_wrapper.c

lib_includedir = $(includedir)
lib_include_HEADERS = $(gpr_sources)

lib_LTLIBRARIES = libaudioreach-gpr.la
libaudioreach_gpr_la_CC = @CC@
libaudioreach_gpr_la_LIBADD = -lpthread $(top_builddir)/ar_osal/libaudioreach-osal.la
if USE_GLIB
libaudioreach_gpr_la_LIBADD += -lglib-2.0
AM_CFLAGS += $(GLIB_CFLAGS) -include glib.h
endif

if USE_G_STR_FUNC
AM_CFLAGS += -Dstrlcpy=g_strlcpy
endif

if CUTILS_SUPPORTED
libaudioreach_gpr_la_LIBADD += -lcutils
AM_CFLAGS += -DGPR_USE_CUTILS
endif

if USE_ARE_ON_APPS
AM_CFLAGS += -DARE_ON_APPS
endif

libaudioreach_gpr_la_SOURCES = $(gpr_c_sources)
libaudioreach_gpr_la_CFLAGS = $(AM_CFLAGS)
libaudioreach_gpr_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@
