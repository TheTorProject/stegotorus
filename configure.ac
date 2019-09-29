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
AC_PROG_RANLIB

AC_CONFIG_MACRO_DIR([config-aux])
dnl This script deliberately does not check for a bunch of things
dnl that 'autoscan' thinks we ought to check for.  Here is the list,
dnl with a rationale for each:
dnl
dnl Defined by C89, therefore unnecessary to check for nowadays:
dnl
dnl   AC_CHECK_FUNCS([memset strcasecmp strchr strerror strrchr strstr strtoul])
dnl   AC_CHECK_HEADERS([limits.h stddef.h stdlib.h string.h])
dnl   AC_CHECK_TYPES([ptrdiff_t])
dnl   AC_TYPE_SIZE_T
dnl
dnl Dealt with by our 'xmalloc' and 'xrealloc' wrappers:
dnl
dnl   AC_FUNC_MALLOC
dnl   AC_FUNC_REALLOC
dnl
dnl Defined by C++ since cfront, therefore unnecessary to check for
dnl in a C++ program:
dnl
dnl   AC_C_INLINE
dnl   AC_HEADER_STDBOOL # 'bool', 'true', and 'false', not the header
dnl
dnl Defined by Unix98, therefore adequately handled by #ifdef _WIN32
dnl (FIXME: Windows has not been tested in some time and is likely to
dnl be broken):
dnl
dnl   AC_CHECK_HEADERS([fcntl.h unistd.h arpa/inet.h netinet/in.h
dnl                     sys/types.h sys/stat.h sys/un.h sys/wait.h])
dnl   AC_CHECK_FUNCS([gettimeofday])
dnl   AC_FUNC_FORK
dnl   AC_TYPE_PID_T
dnl
dnl libevent handles for us (FIXME: we probably shouldn't rely on this):
dnl
dnl   AC_CHECK_HEADERS([stdint.h])
dnl   AC_CHECK_FUNCS([socket])
dnl   AC_TYPE_SSIZE_T
dnl   AC_TYPE_UINT8_T
dnl   AC_TYPE_UINT16_T
dnl   AC_TYPE_UINT32_T
dnl   AC_TYPE_UINT64_T
dnl
dnl The fallback is inappropriate for our use case (it would copy
dnl several enormous files), it is only required for 'make check'
dnl in an out-of-tree build, and it's slated to go away RSN anyway:
dnl
dnl   AC_PROG_LN_S

### Compiler and language features ###

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CXXCPP

# Make a conditional for whether we're on Windows or not, so we can
# select the right version of certain files.
AC_CACHE_CHECK([for Windows], ac_cv_system_windows,
  [AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
    /* _WIN32 is defined for both Win32 and Win64 */
    #ifndef _WIN32
    #error "this is not Windows"
    #endif
  ]])],
  [ac_cv_system_windows=yes],
  [ac_cv_system_windows=no])])
AM_CONDITIONAL(WINDOWS, test $ac_cv_system_windows = yes)

# Similary conditional for android so we link to correct
# libraries
AC_CACHE_CHECK([for Android], ac_cv_system_android,
  [AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
    /* __ANDROID__ is defined for android */
    #ifndef __ANDROID__
    #error "this is not android"
    #endif
  ]])],
  [ac_cv_system_android=yes],
  [ac_cv_system_android=no])])
AM_CONDITIONAL(ANDROID, test $ac_cv_system_android = yes)

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
m4_define_default([_AM_PYTHON_INTERPRETER_LIST],[python2 python2.7])

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
# libcurl for htt_apache steg module
PKG_CHECK_MODULES([libcurl], [libcurl >= 7.22.0])
# configuration reader
PKG_CHECK_MODULES([libyaml], [yaml-cpp >= 0.5.0])
# configuration libssl
# PKG_CHECK_MODULES([libssl], [libssl >= 1.1.1])

# the portable c++ library for manipulating filesystem (only server needs boost)
AC_ARG_WITH(boost,
[  --without-boost         do not use libboost (disables integrating with local http server)])
if test "x${with_boost}" != "xno"; then
       AX_BOOST_BASE([1.46.0],
       [
       AC_DEFINE(HAVE_BOOST, 1)
       ],
       [AC_MSG_ERROR([we needs Boost, but it was not found in your system])
        AC_DEFINE(HAVE_BOOST, 0)])
       AX_BOOST_SYSTEM
       AX_BOOST_FILESYSTEM
       # PKG_CHECK_MODULES([libboost], [libboost >= 1.46.0])
else
       AC_DEFINE(HAVE_BOOST, 0)
fi

# libraries needed for tester proxy
#PKG_CHECK_MODULES([libevent_openssl], [libevent_openssl >= 2.0])

LIBS="$libevent_LIBS $libcrypto_LIBS $libz_LIBS $libcurl_LIBS $libyaml_LIBS "
# $libssl_LIBS"

lib_CPPFLAGS="$libevent_CFLAGS $libcrypto_CFLAGS $libz_CFLAGS"
AC_SUBST(lib_CPPFLAGS)

# ntohl and a bunch of related functions require a special library on Windows.
# It is possible that libevent or libcrypto has hooked us up already.
# This can't be done with AC_SEARCH_LIBS -- see m4/winsock.m4 for gory details.
# disable this for android compiling for now.
AX_LIB_WINSOCK2
LIBS="$LIBS $ws32_LIBS"

# We might need to explicitly link -lm for floor().
dnl AC_SEARCH_LIBS([floor], [m], [], [
dnl   AC_MSG_ERROR([unable to find 'floor'])
dnl ])

lib_LIBS="$LIBS"
lib_CPPFLAGS="$libevent_CFLAGS $libcrypto_CFLAGS $libz_CFLAGS"
LIBS=
AC_SUBST(lib_LIBS)
AC_SUBST(lib_CPPFLAGS)

# pgen_pcap needs libpcap.
pcap_LIBS=
HAVE_PCAP=no
AC_SEARCH_LIBS([pcap_open_offline], [pcap],
  [AC_CACHE_CHECK([whether libpcap is usable], ac_cv_libpcap_usable,
    [AC_LINK_IFELSE([AC_LANG_PROGRAM(
      [[#include <pcap/pcap.h>]],
      [[char f;
        pcap_t *p = pcap_open_offline("",&f);]])],
      [ac_cv_libpcap_usable=yes], [ac_cv_libpcap_usable=no])])
   if test $ac_cv_libpcap_usable = yes; then
     HAVE_PCAP=yes
     pcap_LIBS="$LIBS"
   fi],
   [])
LIBS=
AC_SUBST(pcap_LIBS)
AM_CONDITIONAL(HAVE_PCAP, test $HAVE_PCAP = yes)

### System features ###

AC_CHECK_HEADERS([execinfo.h paths.h],,,[/**/])
AC_CHECK_FUNCS([closefrom execvpe])

### Output ###

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_COMMANDS_PRE([DEFS=])dnl Suppress pointless -DHAVE_CONFIG_H.
AC_OUTPUT
