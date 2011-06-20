AC_INIT
AM_INIT_AUTOMAKE(obsproxy, 0.0)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_HOST

AC_PROG_GCC_TRADITIONAL
AC_PROG_SED
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

AC_CHECK_HEADERS(stdint.h unistd.h fcntl.h)

PKG_CHECK_MODULES([libevent], [libevent >= 2.0])
PKG_CHECK_MODULES([openssl], [openssl >= 0.9.7])

# We don't need -lssl, only -lcrypto
openssl_LIBS=`echo "$openssl_LIBS" | $SED -e 's/-lssl//'`

AC_CHECK_HEADERS([winsock2.h], HAVE_WINSOCK2_H=yes)
AM_CONDITIONAL(HAVE_WINSOCK2_H, test "x$HAVE_WINSOCK2_H" = "xyes")
if test "x$HAVE_WINSOCK2_H" = "xyes"; then
  LIB_WS32=-lws2_32
else
  LIB_WS32=
fi
AC_SUBST(LIB_WS32)

AC_CHECK_SIZEOF(size_t)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

