AC_PREREQ([2.67])dnl Possibly earlier will do, but this is what I have
AC_INIT([obsproxy], [0.0])
AC_CONFIG_SRCDIR([src/main.c])

AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([libevent], [libevent >= 2.0])
PKG_CHECK_MODULES([openssl], [openssl >= 0.9.7])

AC_CACHE_CHECK([for winsock], [ac_cv_lib_winsock],
  [AC_PREPROC_IFELSE(
    [#ifndef _WIN32
    #error "not windows"
    #endif
    ],
    [ac_cv_lib_winsock=yes], [ac_cv_lib_winsock=no])
])
AS_IF([test "x$ac_cv_lib_winsock" = xyes],
  [ws32_LIBS=-lws2_32],
  [ws32_LIBS=])
AC_SUBST(ws32_LIBS)

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
