AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
CFLAGS = -g -Wall -O2 -Werror

bin_PROGRAMS = obfsproxy
noinst_LIBRARIES = libobfsproxy.a
noinst_PROGRAMS = unittests

libobfsproxy_a_SOURCES = \
	src/crypt.c \
	src/crypt_protocol.c
libobfsproxy_a_CFLAGS = @libevent_CFLAGS@ @openssl_CFLAGS@

obfsproxy_SOURCES = \
	src/main.c
obfsproxy_LDADD = @libevent_LIBS@ @openssl_LIBS@ libobfsproxy.a

unittests_SOURCES = \
	src/test/tinytest.c \
	src/test/unittest.c \
	src/test/unittest_protocol.c \
	src/test/unittest_crypt.c
unittests_CFLAGS = @libevent_CFLAGS@ @openssl_CFLAGS@
unittests_LDADD = @libevent_LIBS@ @openssl_LIBS@ libobfsproxy.a

noinst_HEADERS = \
	src/crypt_protocol.h \
	src/crypt.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h

EXTRA_DIST = doc/protocol-spec.txt src/sha256.c

TESTS = unittests
