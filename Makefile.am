# Makefile for stegotorus
# Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
# See LICENSE for other credits and copying information

ACLOCAL_AMFLAGS = -I m4 --install

WARNINGS    = -Werror -Wall -Wextra -Wformat=2

AM_CXXFLAGS = -std=c++98 $(WARNINGS)
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
	src/crypt.cc \
	src/network.cc \
	src/protocol.cc \
	src/rng.cc \
	src/socks.cc \
	src/steg.cc \
	src/util.cc \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

nodist_libstegotorus_a_SOURCES = protolist.cc steglist.cc

stegotorus_SOURCES = \
	src/main.cc

UTGROUPS = \
	src/test/unittest_crypt.cc \
	src/test/unittest_socks.cc \
	src/test/unittest_config.cc \
	src/test/unittest_transfer.cc

unittests_SOURCES = \
	src/test/tinytest.cc \
	src/test/unittest.cc \
	$(UTGROUPS)

nodist_unittests_SOURCES = unitgrplist.cc

tltester_SOURCES = src/test/tltester.cc

noinst_HEADERS = \
	src/connections.h \
	src/crypt.h \
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

# Generated source files
CLEANFILES = protolist.cc steglist.cc unitgrplist.cc \
	stamp-protolist stamp-steglist stamp-unitgrplist

GMOD  = $(SHELL) $(srcdir)/src/genmodtable.sh
GUNIT = $(SHELL) $(srcdir)/src/test/genunitgrps.sh

AM_V_gs   = $(AM_V_gs_$(V))
AM_V_gs_  = $(AM_V_gs_$(AM_DEFAULT_VERBOSITY))
AM_V_gs_0 = @echo "  GEN   " $(patsubst stamp-%,%.c,$@);

protolist.cc: stamp-protolist ;
stamp-protolist: $(PROTOCOLS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) protolist.cc $(filter %.cc, $^)
	$(AM_V_at) touch stamp-protolist

steglist.cc: stamp-steglist ;
stamp-steglist: $(STEGANOGRAPHERS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) steglist.cc $(filter %.cc, $^)
	$(AM_V_at) touch stamp-steglist

unitgrplist.cc: stamp-unitgrplist ;
stamp-unitgrplist: $(UTGROUPS) Makefile src/test/genunitgrps.sh
	$(AM_V_gs) $(GUNIT) unitgrplist.cc $(filter %.cc, $^)
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
