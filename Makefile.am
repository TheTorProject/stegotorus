
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -DDEBUG -Wall -Werror @libevent_CFLAGS@ @openssl_CFLAGS@
LDADD = libobfsproxy.a @libevent_LIBS@ @openssl_LIBS@ @ws32_LIBS@

bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests

libobfsproxy_a_SOURCES = \
	src/crypt.c \
	src/network.c \
	src/protocol.c \
	src/socks.c \
	src/util.c \
	src/protocols/dummy.c \
	src/protocols/obfs2.c
if NEED_SHA256
libobfsproxy_a_SOURCES += src/sha256.c
endif

obfsproxy_SOURCES = \
	src/main.c

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	src/test/unittest_crypt.c \
	src/test/unittest_obfs2.c \
	src/test/unittest_socks.c

noinst_HEADERS = \
	src/crypt.h \
	src/network.h \
	src/protocol.h \
	src/sha256.h \
	src/socks.h \
	src/util.h \
	src/protocols/dummy.h \
	src/protocols/obfs2.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h

EXTRA_DIST = doc/protocol-spec.txt

TESTS = unittests
