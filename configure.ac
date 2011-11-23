AC_PREREQ([2.61])dnl Possibly earlier will do, but this is what I have
AC_INIT([stegotorus], [0.0])
AC_CONFIG_SRCDIR([src/main.cc])
AC_LANG([C++])
AM_INIT_AUTOMAKE([foreign nostdinc silent-rules subdir-objects])
AM_MAINTAINER_MODE([enable])

dnl The stock definition of AC_INCLUDES_DEFAULT performs a whole bunch
dnl of completely unnecessary checks *even if* you override its
dnl mostly-useless default header list at invocation time.
dnl Replace it with a version that does nothing unless requested.
m4_pushdef([AC_INCLUDES_DEFAULT], [$1])

### Programs ###

AC_PROG_CXX
AX_PROG_CXX_C_O
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

# We need python 2.7 for TestLoader.discover().
# The unit tests presently only work on POSIX systems,
# and are flaky enough that we let them be configured off.
AC_ARG_ENABLE(integration-tests,
  [AS_HELP_STRING([--disable-integration-tests],
    [Disable tests of the complete program])],
  [], [enable_integration_tests=yes])
if test x$enable_integration_tests != xyes; then
  AC_MSG_WARN([Integration tests disabled by configure option.])
  PYOS=none
else
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
fi
AM_CONDITIONAL([INTEGRATION_TESTS], [test "$PYOS" = "posix"])

### Libraries ###

PKG_CHECK_MODULES([libevent], [libevent >= 2.0])
# libcrypto++ 5.6.0 is the earliest version with GCM support.
PKG_CHECK_MODULES([libcryptopp], [libcrypto++ >= 5.6.0])

LIBS="$libevent_LIBS $libcryptopp_LIBS"
lib_CPPFLAGS="$libevent_CFLAGS $libcryptopp_CFLAGS"
AC_SUBST(lib_CPPFLAGS)

# ntohl and a bunch of related functions require a special library on Windows.
# It is possible that libevent or libcrypto has hooked us up already.
# This can't be done with AC_SEARCH_LIBS -- see m4/winsock.m4 for gory details.
AX_LIB_WINSOCK2
LIBS="$LIBS $ws32_LIBS"

### Language features ###

AC_CHECK_HEADERS([execinfo.h],,, [AC_INCLUDES_DEFAULT()])

### Output ###

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_COMMANDS_PRE([DEFS=])dnl Suppress pointless -DHAVE_CONFIG_H.
AC_OUTPUT
