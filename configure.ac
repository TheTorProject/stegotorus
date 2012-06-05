dnl Copyright 2011 Nick Mathewson, George Kadianakis
dnl Copyright 2011, 2012 SRI International
dnl See LICENSE for other credits and copying information
dnl
AC_PREREQ([2.61])dnl Possibly earlier will do, but this is what I have
AC_INIT([stegotorus], [0.0])
AC_CONFIG_SRCDIR([src/main.cc])
AC_CONFIG_AUX_DIR([config-aux])
AC_LANG([C++])
AM_INIT_AUTOMAKE([foreign nostdinc silent-rules subdir-objects])
AM_MAINTAINER_MODE([enable])

### Compiler and language features ###

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CXXCPP

AX_SYS_EXTENSIONS
AC_SYS_LARGEFILE

AX_CXXFLAGS_STDCXX_11([ext])
AX_CXX_DELETE_METHOD
AX_CXX_STATIC_ASSERT

### Programs ###

AX_PROG_RANLIB
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

# Presently no need for libssl, only libcrypto.
# We require version 1.0.1 for GCM support.
PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.1])
# libevent 2.0 radically changed the API
PKG_CHECK_MODULES([libevent], [libevent >= 2.0])
# there's no good reason not to require the latest zlib, which is
# from 2009
PKG_CHECK_MODULES([libz], [zlib >= 1.2.3.4])

LIBS="$libevent_LIBS $libcrypto_LIBS $libz_LIBS"
lib_CPPFLAGS="$libevent_CFLAGS $libcrypto_CFLAGS $libz_CFLAGS"
AC_SUBST(lib_CPPFLAGS)

# ntohl and a bunch of related functions require a special library on Windows.
# It is possible that libevent or libcrypto has hooked us up already.
# This can't be done with AC_SEARCH_LIBS -- see m4/winsock.m4 for gory details.
AX_LIB_WINSOCK2
LIBS="$LIBS $ws32_LIBS"

### System features ###

AC_CHECK_HEADERS([execinfo.h paths.h],,,[/**/])
AC_CHECK_FUNCS([closefrom execvpe])

### Output ###

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_COMMANDS_PRE([DEFS=])dnl Suppress pointless -DHAVE_CONFIG_H.
AC_OUTPUT
