AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = obfsproxy

obfsproxy_SOURCES = \
	src/crypt_protocol.c
	src/proxy_main.c
obfsproxy_CFLAGS = @libevent_CFLAGS@ @openssl_CFLAGS@
obfsproxy_LDFLAGS = @libevent_LDFLAGS@ @openssl_LDFLAGS@
obfsproxy_LIBS = @libevent_LIBSS@ @openssl_LIBS@

noinst_HEADERS = \
	src/crypt_protocol.h \
	src/crypt.h

EXTRA_DIST = doc/protocol-spec.txt

