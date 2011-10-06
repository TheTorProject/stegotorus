# Makefile for obfsproxy
# Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
# See LICENSE for other credits and copying information

ACLOCAL_AMFLAGS = -I m4
WARNINGS = -Wall -Wextra -pedantic -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wno-unused-parameter -Wno-overlength-strings -Werror
AM_CPPFLAGS = -I. -I$(srcdir)/src
AM_CFLAGS = $(WARNINGS) @libevent_CFLAGS@ @libcrypto_CFLAGS@
LDADD = libobfsproxy.a @libevent_LIBS@ @libcrypto_LIBS@ @ws32_LIBS@

bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests tltester

PROTOCOLS = \
	src/protocols/dummy.c \
	src/protocols/obfs2.c \
	src/protocols/x_dsteg.c

STEGANOGRAPHERS = \
	src/steg/x_http.c

libobfsproxy_a_SOURCES = \
	src/connections.c \
	src/container.c \
	src/crypt.c \
	src/network.c \
	src/protocol.c \
	src/socks.c \
	src/steg.c \
	src/util.c \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

nodist_libobfsproxy_a_SOURCES = protolist.c steglist.c

if NEED_SHA256
libobfsproxy_a_SOURCES += src/sha256.c
endif

obfsproxy_SOURCES = \
	src/main.c

UTGROUPS = \
	src/test/unittest_container.c \
	src/test/unittest_crypt.c \
	src/test/unittest_socks.c \
	src/test/unittest_obfs2.c \
	src/test/unittest_config.c \
	src/test/unittest_transfer.c

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	$(UTGROUPS)

nodist_unittests_SOURCES = unitgrplist.c

tltester_SOURCES = src/test/tltester.c

noinst_HEADERS = \
	src/connections.h \
	src/container.h \
	src/crypt.h \
	src/ht.h \
	src/listener.h \
	src/main.h \
	src/protocol.h \
	src/rng.h \
	src/sha256.h \
	src/socks.h \
	src/steg.h \
	src/util.h \
	src/protocols/obfs2.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h \
	src/test/unittest.h

dist_noinst_SCRIPTS = \
	src/genmodtable.sh \
	src/test/genunitgrps.sh

EXTRA_DIST = doc \
	src/protocols/roundrobin.c \
	src/test/obfstestlib.py \
	src/test/test_endtoend.py \
	src/test/test_socks.py

# Generated source files
CLEANFILES = protolist.c steglist.c unitgrplist.c \
	stamp-protolist stamp-steglist stamp-unitgrplist

GMOD  = $(SHELL) $(srcdir)/src/genmodtable.sh
GUNIT = $(SHELL) $(srcdir)/src/test/genunitgrps.sh

AM_V_gs   = $(AM_V_gs_$(V))
AM_V_gs_  = $(AM_V_gs_$(AM_DEFAULT_VERBOSITY))
AM_V_gs_0 = @echo "  GEN   " $(patsubst stamp-%,%.c,$@);

protolist.c: stamp-protolist ;
stamp-protolist: $(PROTOCOLS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) protolist.c $(filter %.c, $^)
	$(AM_V_at) touch stamp-protolist

steglist.c: stamp-steglist ;
stamp-steglist: $(STEGANOGRAPHERS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) steglist.c $(filter %.c, $^)
	$(AM_V_at) touch stamp-steglist

unitgrplist.c: stamp-unitgrplist ;
stamp-unitgrplist: $(UTGROUPS) Makefile src/test/genunitgrps.sh
	$(AM_V_gs) $(GUNIT) unitgrplist.c $(filter %.c, $^)
	$(AM_V_at) touch stamp-unitgrplist

# Testing
check-local:
	@echo --- Unit tests ---
	$(AM_V_at) ./unittests
if INTEGRATION_TESTS
	@echo --- Integration tests ---
	$(AM_V_at) $(PYTHON) -m unittest discover -s $(srcdir)/src/test -p 'test_*.py' -v
else
	@echo !!! Integration tests skipped !!!
endif
