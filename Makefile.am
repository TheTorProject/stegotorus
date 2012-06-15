# Copyright 2011 Nick Mathewson, George Kadianakis
# Copyright 2011, 2012 SRI International
# See LICENSE for other credits and copying information

ACLOCAL_AMFLAGS = -I config-aux --install

AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2
AM_CPPFLAGS = -I. -I$(srcdir)/src -D_FORTIFY_SOURCE=2 $(lib_CPPFLAGS)
LDADD       = libstegotorus.a

noinst_LIBRARIES = libstegotorus.a
noinst_PROGRAMS  = unittests tltester
bin_PROGRAMS     = stegotorus

PROTOCOLS = \
	src/protocol/chop.cc \
	src/protocol/null.cc

STEGANOGRAPHERS = \
	src/steg/b64cookies.cc \
	src/steg/cookies.cc \
	src/steg/embed.cc \
	src/steg/http.cc \
	src/steg/jsSteg.cc \
	src/steg/nosteg.cc \
	src/steg/nosteg_rr.cc \
	src/steg/payloads.cc \
	src/steg/pdfSteg.cc \
	src/steg/swfSteg.cc

libstegotorus_a_SOURCES = \
	src/base64.cc \
	src/compression.cc \
	src/connections.cc \
	src/crypt.cc \
	src/mkem.cc \
	src/network.cc \
	src/protocol.cc \
	src/rng.cc \
	src/socks.cc \
	src/steg.cc \
	src/util.cc \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

if WINDOWS
libstegotorus_a_SOURCES += src/subprocess-windows.cc
else
libstegotorus_a_SOURCES += src/subprocess-unix.cc
endif

nodist_libstegotorus_a_SOURCES = protolist.cc steglist.cc

stegotorus_SOURCES = \
	src/main.cc

UTGROUPS = \
	src/test/unittest_base64.cc \
	src/test/unittest_compression.cc \
	src/test/unittest_config.cc \
	src/test/unittest_crypt.cc \
	src/test/unittest_pdfsteg.cc \
	src/test/unittest_socks.cc \
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
	src/audit-globals.sh \
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
AGLOB = $(SHELL) $(srcdir)/src/audit-globals.sh

AM_V_gs   = $(AM_V_gs_$(V))
AM_V_gs_  = $(AM_V_gs_$(AM_DEFAULT_VERBOSITY))
AM_V_gs_0 = @echo "  GEN   " $(patsubst stamp-%,%.cc,$@);

AM_V_ag   = $(AM_V_ag_$(V))
AM_V_ag_  = $(AM_V_ag_$(AM_DEFAULT_VERBOSITY))
AM_V_ag_0 = @echo "  AGLOB ";

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

stamp-audit-globals: src/audit-globals.sh Makefile \
  $(libstegotorus_a_OBJECTS) $(stegotorus_OBJECTS)
	$(AM_V_ag) $(AGLOB) $(libstegotorus_a_OBJECTS) $(stegotorus_OBJECTS)
	$(AM_V_at) touch stamp-audit-globals

# prevent stegotorus from being linked if s-a-g fails
EXTRA_stegotorus_DEPENDENCIES = stamp-audit-globals

# Testing
check-local:
	@echo --- Unit tests ---
	$(AM_V_at) ./unittests
if INTEGRATION_TESTS
	@echo --- Integration tests ---
	[ -e traces ] || ln -s $(srcdir)/traces .
	$(AM_V_at) $(PYTHON) -m unittest discover -s $(srcdir)/src/test -p 'test_*.py' -v
else
	@echo !!! Integration tests skipped !!!
endif
