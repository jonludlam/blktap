
AM_CFLAGS  = -Wall
AM_CFLAGS += -Werror

AM_CPPFLAGS  = -D_GNU_SOURCE
AM_CPPFLAGS += -D_FILE_OFFSET_BITS=64
AM_CPPFLAGS += -I$(top_srcdir)/include
AM_CPPFLAGS += -I$(top_srcdir)/xenio
AM_CPPFLAGS += -I$(top_srcdir)/control

lib_LTLIBRARIES = libxenio.la

libxenio_la_SOURCES  = xenio.h
libxenio_la_SOURCES += xenio-private.h
libxenio_la_SOURCES += xenio-ctx.c
libxenio_la_SOURCES += xenio-blkif.c
libxenio_la_SOURCES += gntdev.h

libxenio_la_LIBADD = -lxenctrl -lpthread

libxenio_la_LDFLAGS = -version-info 0:1:0

sbin_PROGRAMS = blkback
blkback_LDADD = libxenio.la -lxenctrl -lxenstore ../control/libblktapctl.la

