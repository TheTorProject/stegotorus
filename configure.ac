AC_PREREQ([2.61])dnl Possibly earlier will do, but this is what I have
AC_INIT([obsproxy], [0.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign])

dnl The stock definition of AC_INCLUDES_DEFAULT performs a whole bunch
dnl of completely unnecessary checks *even if* you override its
dnl mostly-useless default header list at invocation time.
dnl Replace it with a version that does nothing unless requested.
m4_pushdef([AC_INCLUDES_DEFAULT], [$1])

### Programs ###

AC_PROG_CC
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

### Libraries ###

PKG_CHECK_MODULES([libevent], [libevent >= 2.0])
# Presently no need for libssl, only libcrypto.
PKG_CHECK_MODULES([libcrypto], [libcrypto >= 0.9.7])

# We permit the use of openssl 0.9.7, which doesn't have sha256.
# Check whether a replacement is required.
save_LIBS="$LIBS"
LIBS="$libcrypto_LIBS"
AC_CHECK_FUNC(SHA256_Init, [:], [:])
LIBS="$save_LIBS"
AM_CONDITIONAL(NEED_SHA256, [test x$ac_cv_func_SHA256_Init = xno])

# ntohl and a bunch of related functions require a special library on Windows.
# It is possible that libevent or libcrypto has hooked us up already.
# This can't be done with AC_SEARCH_LIBS -- see m4/winsock.m4 for gory details.
save_LIBS="$LIBS"
LIBS="$libevent_LIBS $libcrypto_LIBS"
AX_LIB_WINSOCK2
LIBS="$save_LIBS"

### C features ###

AC_C_INLINE
AC_CHECK_SIZEOF(int)

### Output ###

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
