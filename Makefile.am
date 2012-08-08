# Copyright 2011 Nick Mathewson, George Kadianakis
# Copyright 2011, 2012 SRI International
# See LICENSE for other credits and copying information

ACLOCAL_AMFLAGS = -I config-aux --install

AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2
AM_CPPFLAGS = -I. -I$(srcdir)/src -D_FORTIFY_SOURCE=2 $(lib_CPPFLAGS)

noinst_LIBRARIES = libstegotorus.a
noinst_PROGRAMS  = unittests tltester
bin_PROGRAMS     = stegotorus

PROTOCOLS = \
	src/protocol/chop.cc \
	src/protocol/chop_blk.cc \
	src/protocol/null.cc

STEGANOGRAPHERS = \
	src/steg/b64cookies.cc \
	src/steg/cookies.cc \
	src/steg/embed.cc \
	src/steg/http.cc \
	src/steg/http_apache.cc \
	src/steg/jsSteg.cc \
	src/steg/nosteg.cc \
	src/steg/nosteg_rr.cc \
	src/steg/payload_server.cc \
	src/steg/trace_payload_server.cc \
	src/steg/apache_payload_server.cc \
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
	src/util-net.cc \
	src/curl_util.cc \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

if WINDOWS
libstegotorus_a_SOURCES += src/subprocess-windows.cc
else
libstegotorus_a_SOURCES += src/subprocess-unix.cc
endif

nodist_libstegotorus_a_SOURCES = protolist.cc steglist.cc

stegotorus_SOURCES = \
	src/main.cc

stegotorus_LDADD = libstegotorus.a $(lib_LIBS)

# prevent stegotorus from being linked if s-a-g fails
# it is known that $(lib_LIBS) contains nothing that needs to be depended upon
stegotorus_DEPENDENCIES = libstegotorus.a stamp-audit-globals

## payload trace generators

bin_PROGRAMS += pgen_fake
pgen_fake_SOURCES = \
	src/pgen_fake.cc \
	src/util.cc \
	src/rng.cc \
	src/base64.cc

pgen_fake_LDADD = $(libcrypto_LIBS)

# pgen_pcap is only built if we have libpcap
if HAVE_PCAP
bin_PROGRAMS += pgen_pcap

pgen_pcap_SOURCES = \
	src/pgen_pcap.cc \
	src/compression.cc \
	src/util.cc

pgen_pcap_LDADD = $(pcap_LIBS) $(libz_LIBS)
endif

UTGROUPS = \
	src/test/unittest_base64.cc \
	src/test/unittest_compression.cc \
	src/test/unittest_crypt.cc \
	src/test/unittest_pdfsteg.cc \
	src/test/unittest_socks.cc

unittests_SOURCES = \
	src/test/tinytest.cc \
	src/test/unittest.cc \
	$(UTGROUPS)

nodist_unittests_SOURCES = unitgrplist.cc

unittests_LDADD = libstegotorus.a $(lib_LIBS)

tltester_SOURCES = src/test/tltester.cc src/util.cc src/util-net.cc
tltester_LDADD   = $(libevent_LIBS)

noinst_HEADERS = \
	src/base64.h \
	src/compression.h \
	src/connections.h \
	src/crypt.h \
	src/listener.h \
	src/mkem.h \
	src/pgen.h \
	src/protocol.h \
	src/rng.h \
	src/socks.h \
	src/subprocess.h \
	src/steg.h \
	src/util.h \
	src/protocol/chop_blk.h \
	src/steg/b64cookies.h \
	src/steg/cookies.h \
	src/steg/jsSteg.h \
	src/steg/payloads.h \
	src/steg/pdfSteg.h \
	src/steg/swfSteg.h \
	src/steg/http.h \
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
	stamp-protolist stamp-steglist stamp-unitgrplist \
	stamp-audit-globals

GMOD  = $(SHELL) $(srcdir)/src/genmodtable.sh
GUNIT = $(SHELL) $(srcdir)/src/test/genunitgrps.sh
AGLOB = $(SHELL) $(srcdir)/src/audit-globals.sh

AM_V_gs   = $(AM_V_gs_$(V))
AM_V_gs_  = $(AM_V_gs_$(AM_DEFAULT_VERBOSITY))
AM_V_gs_0 = @echo "  GEN     " $(patsubst stamp-%,%.cc,$@);

AM_V_ag   = $(AM_V_ag_$(V))
AM_V_ag_  = $(AM_V_ag_$(AM_DEFAULT_VERBOSITY))
AM_V_ag_0 = @echo "  AGLOB";

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

# Testing
check-local:
	@echo --- Unit tests ---
	$(AM_V_at) ./unittests
if INTEGRATION_TESTS
	@echo --- Integration tests ---
	@set -ex; if [ ! -e traces ]; then \
	  if [ -e $(srcdir)/../steg-traces ]; then \
	    ln -s $(srcdir)/../steg-traces traces; \
	  elif [ -e $(srcdir)/traces ]; then \
	    ln -s $(srcdir)/traces traces; \
	  else \
	    mkdir traces && touch traces/.faked && ./pgen_fake; \
	  fi; \
	fi
	$(AM_V_at) $(PYTHON) -m unittest discover -s $(srcdir)/src/test -p 'test_*.py' -v
else
	@echo !!! Integration tests skipped !!!
endif

if INTEGRATION_TESTS
clean-local:
	[ ! -f traces/.faked ] || rm -r traces
endif
