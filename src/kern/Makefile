#
# Standalone NPF makefile: the kernel component as a library.
# This file is in the Public Domain.
#

CFLAGS=		-std=gnu99 -O3 -Wall -Wextra -Werror
CFLAGS+=	-flto
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-I stand -D_NPF_STANDALONE #-DUSE_JUDY
CFLAGS+=	-D__RCSID\(x\)=

CFLAGS+=	-Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
CFLAGS+=	-Wno-unused

# !! don't forget to uncomment CPPFLAGS defines
#CFLAGS+=	-DALEXK_DEBUG
#CFLAGS+=	-DALEXK_DEBUG2
#CFLAGS+=	-DALEXK_DEBUG3
#CFLAGS+=       -DNPF_DEBUG_COUNTERS
#CFLAGS+=       -DNPF_SPINLOCK
#CFLAGS+=       -DNPF_DEBUG_DONT_TRACK_TCP_WINDOW
#CFLAGS+=	-DMEMPOOL_DEBUG
#CFLAGS+=	-DNPF_LOG_DEBUG
#CFLAGS+=	-DCONN_STATE_DEBUG_CHECK
#CFLAGS+=	-DNPF_CONN_DEBUG

SYSNAME:=	$(shell uname -s)

#
# WARNING: All symbols must be hidden by default to not conflict with
# the libnpf(3) library.  The debug version would, however, conflict.
#
ifeq ($(DEBUG),1)
CFLAGS+=	-O1 -DDEBUG -fno-omit-frame-pointer
CFLAGS+=	-D_NPF_TESTING
else
CFLAGS+=	-fvisibility=hidden
#CFLAGS+=	-DNDEBUG
LDFLAGS=	-flto
# debug
#CFLAGS+=	-fno-omit-frame-pointer
CFLAGS+=	-g
endif

LDFLAGS+=	-lpthread -lpcap -lqsbr -lcdb -lprop -lbpfjit
ifeq ($(SYSNAME),Linux)
LDFLAGS+=	-ljemalloc #-lJudy
endif

#
# System specific flags
#

ifeq ($(SYSNAME),Linux)
CFLAGS+=	-D_POSIX_C_SOURCE=200809L
CFLAGS+=	-D_DEFAULT_SOURCE
endif

###
### CPP
###
CPPFLAGS=	-std=c++11 -O3 -Wall -Wextra -Werror
CPPFLAGS+=	-flto
CPPFLAGS+=	-Wpointer-arith
CPPFLAGS+=	-I stand -D_NPF_STANDALONE #-DUSE_JUDY
CPPFLAGS+=	-D__RCSID\(x\)=

CPPFLAGS+=	-Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
CPPFLAGS+=	-Wno-unused

# debug information
#CPPFLAGS+=	-g
#CPPFLAGS+=	-fno-omit-frame-pointer
#LDFLAGS+=	-g

#CPPFLAGS+=	-DALEXK_DEBUG
#CPPFLAGS+=	-DALEXK_DEBUG2
#CPPFLAGS+=	-DALEXK_DEBUG3
#CPPFLAGS+=	-DNPF_CONN_DEBUG
#CPPFLAGS+=	-DNPF_LOG_DEBUG

#
# WARNING: All symbols must be hidden by default to not conflict with
# the libnpf(3) library.  The debug version would, however, conflict.
#
ifeq ($(DEBUG),1)
CPPFLAGS+=	-O1 -DDEBUG -fno-omit-frame-pointer
CPPFLAGS+=	-D_NPF_TESTING
else
CPPFLAGS+=	-fvisibility=hidden
CPPFLAGS+=	-DNDEBUG
endif
ifeq ($(SYSNAME),Linux)
endif

#
# System specific flags
#

ifeq ($(SYSNAME),Linux)
CPPFLAGS+=	-D_POSIX_C_SOURCE=200809L
CPPFLAGS+=	-D_DEFAULT_SOURCE
endif

### end CPP

#
# Objects to compile
#

OBJS=		$(shell grep ^file files.npf | cut -f2 | \
		    sed 's/\(.*\)net\/npf\/\(.*\).c/\2.o/g' | \
		    grep -v npf_os | grep -v npf_alg_ | \
		    grep -v npf_ext_ | \
		    grep -v if_npflog)

OBJS+=		npf_alg_icmp.o
OBJS+=		stand/bpf_filter.o

OBJS+=		stand/rb.o stand/ptree.o
OBJS+=		stand/murmurhash.o stand/subr_hash.o
OBJS+=		stand/mempool.o stand/tls_pth.o
OBJS+=		npf_portmap.o
OBJS+=		npf_conn_map.o npf_conn_map_ipv6.o npf_city_hasher.o
OBJS+=		npf_conn_debug.o
#
# Flags for the library target
#

LIB=		libnpfkern
ifeq ($(DEBUG),1)
LIB=		libnpfkern-dbg
endif

INCS=		npf.h npfkern.h
MANS=		npfkern.3

$(LIB).la:	LDFLAGS+=	-rpath $(LIBDIR)
install/%.la:	ILIBDIR=	$(DESTDIR)/$(LIBDIR)
install:	IINCDIR=	$(DESTDIR)/$(INCDIR)
install:	IMANDIR=	$(DESTDIR)/$(MANDIR)/man3/

CPP = g++

PORTMAP_STRESS_OBJ=	npf_portmap.o npf_portmap_test.o npf_city_hasher.o
PORTMAP_STRESS_OBJ+=	MersenneTwister.o
#
# Targets
#

lib: $(LIB).la

%.lo: %.c
	libtool --mode=compile --tag CC $(CC) $(CFLAGS) -c $<

%.lo: %.cpp
	libtool --mode=compile --tag CC $(CPP) $(CPPFLAGS) -c $<

$(LIB).la: $(shell echo $(OBJS) | sed 's/\.o/\.lo/g')
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) -o $@ $(notdir $^)

install/%.la: %.la
	mkdir -p $(ILIBDIR)
	libtool --mode=install install -c $(notdir $@) $(ILIBDIR)/$(notdir $@)

install: $(addprefix install/,$(LIB).la)
	libtool --mode=finish $(LIBDIR)
	mkdir -p $(IINCDIR)/net && install -c $(INCS) $(IINCDIR)/net
	mkdir -p $(IMANDIR) && install -c $(MANS) $(IMANDIR)

clean:
	libtool --mode=clean rm
	rm -rf .libs *.o *.lo *.la stand/*.{l,}o stand/*.la

%.o: %.c
	libtool --mode=compile --tag CC $(CC) $(CFLAGS) -c $<

%.o: %.cpp
	libtool --mode=compile --tag CC $(CPP) $(CPPFLAGS) -c $<
	
portmap_stress: $(PORTMAP_STRESS_OBJ)
	$(CPP) $(CPPFLAGS) $^ -o npf_portmap_test -lpthread -lcityhash

.PHONY: all lib install clean
