
CC        = gcc

CFLAGS    = -O2 -Wall -Werror -g
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS      = .*.d

CPPFLAGS  = -I.
CPPFLAGS += -D_GNU_SOURCE
CPPFLAGS += -D_LARGEFILE64_SOURCE

XENIO-OBJS  = xenio-ctx.o
XENIO-OBJS += xenio-blkif.o

all: libxenio.a

libxenio.a: libxenio.a($(XENIO-OBJS))

clean:
	rm -f libxenio.a
	rm -f $(XENIO-OBJS)
	rm -f $(DEPS)
	rm -f *~

-include $(DEPS)
