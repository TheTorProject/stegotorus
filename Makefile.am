
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -DDEBUG -Wall -Werror @libevent_CFLAGS@ @openssl_CFLAGS@
LDADD = libobfsproxy.a @libevent_LIBS@ @openssl_LIBS@ @ws32_LIBS@

bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests

libobfsproxy_a_SOURCES = \
	src/network.c \
	src/protocol.c \
	src/socks.c  \
	src/util.c   \
	src/protocols/obfs2.c \
	src/protocols/obfs2_crypt.c \
	src/protocols/dummy.c

obfsproxy_SOURCES = \
	src/main.c

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	src/test/unittest_obfs2.c \
	src/test/unittest_crypt.c \
	src/test/unittest_socks.c

noinst_HEADERS = \
	src/network.h \
	src/protocol.h \
	src/socks.h \
	src/util.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h \
	src/protocols/obfs2.h \
	src/protocols/obfs2_crypt.h \
	src/protocols/dummy.h

EXTRA_DIST = doc/protocol-spec.txt src/sha256.c

TESTS = unittests
