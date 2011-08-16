
ACLOCAL_AMFLAGS = -I m4
WARNINGS = -Wall -Wwrite-strings -Werror
AM_CPPFLAGS = -I. -I$(srcdir)/src
AM_CFLAGS = $(WARNINGS) @libevent_CFLAGS@ @libcrypto_CFLAGS@
LDADD = libobfsproxy.a @libevent_LIBS@ @libcrypto_LIBS@ @ws32_LIBS@

bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests

libobfsproxy_a_SOURCES = \
	src/connections.c \
	src/container.c \
	src/crypt.c \
	src/network.c \
	src/protocol.c \
	src/socks.c \
	src/steg.c \
	src/util.c \
	src/protocols/dummy.c \
	src/protocols/x_dsteg.c \
	src/steg/x_http.c
if NEED_SHA256
libobfsproxy_a_SOURCES += src/sha256.c
endif

obfsproxy_SOURCES = \
	src/main.c

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	src/test/unittest_container.c \
	src/test/unittest_crypt.c \
	src/test/unittest_socks.c \
	src/test/unittest_dummy.c \
	src/test/unittest_steg_x_http.c

noinst_HEADERS = \
	src/connections.h \
	src/container.h \
	src/crypt.h \
	src/ht.h \
	src/main.h \
	src/network.h \
	src/protocol.h \
	src/rng.h \
	src/sha256.h \
	src/socks.h \
	src/steg.h \
	src/util.h \
	src/protocols/dummy.h \
	src/protocols/obfs2.h \
	src/protocols/x_dsteg.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h

EXTRA_DIST = doc/protocol-spec.txt \
	src/protocols/obfs2.c \
	src/test/unittest_obfs2.c \
	src/test/tester.py

check-local:
	@echo --- Unit tests ---
	./unittests
if HAVE_PYTHON
	@echo --- Integration tests ---
	$(PYTHON) $(srcdir)/src/test/tester.py --verbose
endif
