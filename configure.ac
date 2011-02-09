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

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

