pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = acdb.pc
EXTRA_DIST = $(pkgconfig_DATA)

AM_CFLAGS = -Wall -Wno-unknown-pragmas -Wno-error=comment -Wno-error=discarded-qualifiers \
            -Wno-error=address-of-packed-member -Wno-error=unused-but-set-variable \
           -Wno-error=incompatible-pointer-types

AM_CFLAGS += -I$(srcdir)/inc
AM_CFLAGS += -I$(srcdir)/api
AM_CFLAGS += -I$(top_srcdir)/ar_osal/api

acdb_sources = ./inc/acdb_command.h \
               ./inc/acdb_common.h \
               ./inc/acdb_context_mgr.h \
               ./inc/acdb_delta_file_mgr.h \
               ./inc/acdb_delta_parser.h \
               ./inc/acdb_file_mgr.h \
               ./inc/acdb_init.h \
               ./inc/acdb_init_utility.h \
               ./inc/acdb_parser.h \
               ./inc/acdb_types.h \
               ./inc/acdb_utility.h \
               ./inc/acdb_data_proc.h \
               ./inc/acdb_heap.h\
               ./api/acdb.h \
               ./api/acdb_begin_pack.h \
               ./api/acdb_end_pack.h

acdb_c_sources = ./src/acdb.c \
                 ./src/acdb_command.c \
                 ./src/acdb_context_mgr.c \
                 ./src/acdb_delta_file_mgr.c \
                 ./src/acdb_delta_parser.c \
                 ./src/acdb_file_mgr.c \
                 ./src/acdb_init.c \
                 ./src/acdb_init_utility.c \
                 ./src/acdb_parser.c \
                 ./src/acdb_utility.c \
                 ./src/acdb_data_proc.c \
                 ./src/acdb_heap.c

lib_includedir = $(includedir)
lib_include_HEADERS = $(acdb_sources)

lib_LTLIBRARIES = libar-acdb.la
libar_acdb_la_CC = @CC@
libar_acdb_la_LIBADD = -lar-osal -L$(top_builddir)/ar_osal
libar_acdb_la_SOURCES = $(acdb_c_sources)
libar_acdb_la_CFLAGS = $(AM_CFLAGS)
libar_acdb_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@
