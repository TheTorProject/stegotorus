AC_PREREQ([2.61])dnl Possibly earlier will do, but this is what I have
AC_INIT([obfsproxy], [0.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign nostdinc silent-rules subdir-objects])

dnl The stock definition of AC_INCLUDES_DEFAULT performs a whole bunch
dnl of completely unnecessary checks *even if* you override its
dnl mostly-useless default header list at invocation time.
dnl Replace it with a version that does nothing unless requested.
m4_pushdef([AC_INCLUDES_DEFAULT], [$1])

### Programs ###

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

# We need python 2.7 for TestLoader.discover().
# The unit tests presently only work on POSIX systems.
AM_PATH_PYTHON([2.7],, [:])
if test "$PYTHON" = ":"; then
  AC_MSG_WARN([Python interpreter not found; integration tests disabled.])
  PYOS=none
else
  PYOS=`$PYTHON -c 'import os; print os.name'`
  if test "$PYOS" != "posix"; then
    AC_MSG_WARN([Not a POSIX platform; integration tests disabled.])
  fi
fi
AM_CONDITIONAL([INTEGRATION_TESTS], [test "$PYOS" = "posix"])

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
AC_CHECK_HEADERS([execinfo.h],,, [AC_INCLUDES_DEFAULT()])

### Output ###

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_COMMANDS_PRE([DEFS=])dnl Suppress pointless -DHAVE_CONFIG_H.
AC_OUTPUT
