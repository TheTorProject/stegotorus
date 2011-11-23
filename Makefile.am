# Makefile for stegotorus
# Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
# See LICENSE for other credits and copying information

ACLOCAL_AMFLAGS = -I m4 --install

WARNINGS  = -Werror -Wall -Wextra -Wformat=2 \
 -Wno-unused-parameter -Wno-overlength-strings -Wno-long-long
CWARNINGS = -pedantic -Wwrite-strings -Wdeclaration-after-statement \
 -Wstrict-prototypes -Wmissing-prototypes

AM_CFLAGS   = -std=gnu99 $(WARNINGS) $(CWARNINGS)
AM_CXXFLAGS = -std=gnu++98 $(WARNINGS)

AM_CPPFLAGS = -I. -I$(srcdir)/src -D_FORTIFY_SOURCE=2 $(lib_CPPFLAGS)
LDADD       = libstegotorus.a

noinst_LIBRARIES = libstegotorus.a
noinst_PROGRAMS  = unittests tltester
bin_PROGRAMS     = stegotorus

PROTOCOLS = \
	src/protocol/chop.cc \
	src/protocol/x_null.cc

STEGANOGRAPHERS = \
	src/steg/x_http.cc

libstegotorus_a_SOURCES = \
	src/connections.cc \
	src/container.c \
	src/crypt.cc \
	src/network.cc \
	src/protocol.cc \
	src/socks.cc \
	src/steg.cc \
	src/util.cc \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

nodist_libstegotorus_a_SOURCES = protolist.c steglist.c

stegotorus_SOURCES = \
	src/main.cc

UTGROUPS = \
	src/test/unittest_container.c \
	src/test/unittest_crypt.c \
	src/test/unittest_socks.c \
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
	src/socks.h \
	src/steg.h \
	src/util.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h \
	src/test/unittest.h

dist_noinst_SCRIPTS = \
	src/genmodtable.sh \
	src/test/genunitgrps.sh

EXTRA_DIST = doc \
	src/test/itestlib.py \
	src/test/test_socks.py \
	src/test/test_tl.py

# Automake does not realize that because libstegotorus.a contains
# a C++ source file, every program that has it in LDADD must be
# linked with the C++ compiler.  Persuade it to do so anyway.
# The file forcecxxlink.cc need not, and does not, exist.
nodist_EXTRA_tltester_SOURCES  = forcecxxlink.cc
nodist_EXTRA_unittests_SOURCES = forcecxxlink.cc

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
	$(AM_V_gs) $(GMOD) protolist.c $(filter %.cc, $^)
	$(AM_V_at) touch stamp-protolist

steglist.c: stamp-steglist ;
stamp-steglist: $(STEGANOGRAPHERS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) steglist.c $(filter %.cc, $^)
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
