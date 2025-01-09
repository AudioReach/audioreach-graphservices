pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gsl.pc
EXTRA_DIST = $(pkgconfig_DATA)

AM_CFLAGS = -I$(srcdir)/inc
AM_CFLAGS += -I$(srcdir)/api
AM_CFLAGS += -I$(srcdir)/rtc_api
AM_CFLAGS += -I$(srcdir)/hw_rsc_api
AM_CFLAGS += -I$(srcdir)/dls_client_api

AM_CFLAGS += -I$(top_srcdir)/ar_osal/api
AM_CFLAGS += -I$(top_srcdir)/ar_util/api
AM_CFLAGS += -I$(top_srcdir)/gpr/api
AM_CFLAGS += -I$(top_srcdir)/acdb/api
AM_CFLAGS += -I$(top_srcdir)/spf/api/ar_utils -I$(top_srcdir)/spf/api/apm -I$(top_srcdir)/spf/api/modules

gsl_sources = ./inc/gsl_common.h \
              ./inc/gsl_graph.h \
              ./inc/gsl_main.h \
              ./inc/gsl_shmem_mgr.h \
              ./inc/gsl_subgraph.h \
              ./inc/gsl_subgraph_pool.h \
              ./inc/gsl_spf_ss_state.h \
              ./inc/gsl_rtc.h \
              ./inc/gsl_rtc_main.h \
              ./api/gsl_intf.h \
              ./inc/gsl_dynamic_module_mgr.h \
              ./rtc_api/gsl_rtc_intf.h \
              ./hw_rsc_api/gsl_hw_rsc_intf.h \
              ./inc/gsl_subgraph_driver_props_generic.h \
              ./api/gsl_subgraph_driver_props.h \
              ./inc/gsl_mdf_utils.h \
              ./inc/gsl_spf_timeout.h \
              ./inc/gsl_global_persist_cal.h \
              ./dls_client_api/gsl_dls_client_intf.h \
              ./inc/gsl_dls_client.h \
              ./inc/gsl_cshm_mgr.h

gsl_c_sources = ./src/gsl_graph.c \
                ./src/gsl_main.c \
                ./src/gsl_mdf_utils.c \
                ./src/gsl_spf_timeout.c \
                ./src/gsl_shmem_mgr.c \
                ./src/gsl_subgraph.c \
                ./src/gsl_subgraph_pool.c \
                ./src/gsl_common.c \
                ./src/gsl_datapath.c \
                ./src/gsl_dynamic_module_mgr.c \
                ./src/gsl_spf_ss_state.c \
                ./src/gsl_rtc.c \
                ./src/gsl_rtc_main.c \
                ./src/gsl_hw_rsc_mgr.c \
                ./src/gsl_msg_builder.c \
                ./src/gsl_global_persist_cal.c \
                ./src/gsl_dls_client.c \
                ./src/gsl_cshm_mgr.c

lib_includedir = $(includedir)
lib_include_HEADERS = $(gsl_sources)

lib_LTLIBRARIES = libar-gsl.la
libar_gsl_la_CC = @CC@
libar_gsl_la_LIBADD = $(top_builddir)/acdb/libar-acdb.la $(top_builddir)/ar_osal/libar-osal.la $(top_builddir)/ar_util/libar-util.la $(top_builddir)/spf/libar-spfhdrs.la $(top_builddir)/gpr/libar-gpr.la
libar_gsl_la_SOURCES = $(gsl_c_sources)
libar_gsl_la_CFLAGS = $(AM_CFLAGS)
libar_gsl_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@

if USES_ATS_DATA_LOGGING
libar_gsl_la_CFLAGS += -DATS_DATA_LOGGING
libar_gsl_la_CPPFLAGS = -DATS_DATA_LOGGING
endif
