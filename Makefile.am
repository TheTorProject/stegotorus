AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
CFLAGS = -DDEBUG -g -Wall -O2 -Werror @libevent_CFLAGS@ @openssl_CFLAGS@


bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests

libobfsproxy_a_SOURCES = \
	src/network.c \
	src/protocol.c \
	src/socks.c  \
	src/util.c   \
	src/plugins/obfs2.c \
	src/plugins/obfs2_crypt.c \
	src/plugins/dummy.c

obfsproxy_SOURCES = \
	src/main.c
obfsproxy_LDADD = @libevent_LIBS@ @openssl_LIBS@ libobfsproxy.a

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	src/test/unittest_protocol.c \
	src/test/unittest_crypt.c \
	src/test/unittest_socks.c
unittests_LDADD = @libevent_LIBS@ @openssl_LIBS@ libobfsproxy.a

noinst_HEADERS = \
	src/network.h \
	src/protocol.h \
	src/socks.h \
	src/util.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h \
	src/plugins/obfs2.h \
	src/plugins/obfs2_crypt.h \
	src/plugins/dummy.h

EXTRA_DIST = doc/protocol-spec.txt src/sha256.c

TESTS = unittests
