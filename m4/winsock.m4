# Copyright © 2011 Zack Weinberg <zackw@panix.com>
#
# Copying and distribution of this software, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This software is offered as-is,
# without any warranty.

# The socket API requires a special library on Windows, but
# AC_SEARCH_LIBS cannot be used to find it, because it will
# mis-declare 'ntohl' on windows and cause the link to fail.
#
# This macro sets the substitution @ws2_LIBS@ to "-lws2_32"
# if you need that, and "" otherwise.  It does not provide
# any #defines for the differences in socket headers between
# Windows and Unix -- just use #ifdef _WIN32.
#
# Implementation note: we use the same _cv_ variable that
# AC_SEARCH_LIBS would, because the test is what AC_SEARCH_LIBS
# *should* have done in this situation.
AC_DEFUN([AX_LIB_WINSOCK2],
  [AC_CACHE_CHECK([for library containing ntohl], [ac_cv_search_ntohl],
    [AC_LANG_CONFTEST([AC_LANG_PROGRAM([
      #ifdef _WIN32
      #include <winsock2.h>
      #else
      #include <arpa/inet.h>
      #endif
    ], [
      return (int)ntohl(42);])
    ])

    ax_lib_winsock2_save_LIBS="$LIBS"
    for ac_lib in '' -lws2_32; do
      if test -z "$ac_lib"; then
        ac_res="none required"
      else
        ac_res=$ac_lib
      fi
      LIBS="$ac_lib $ax_lib_winsock2_save_LIBS"
      AC_LINK_IFELSE([], [AS_VAR_SET([ac_cv_search_ntohl], [$ac_res])])
      AS_VAR_SET_IF([ac_cv_search_ntohl], [break])
    done
    AS_VAR_SET_IF([ac_cv_search_ntohl], ,
                  [AS_VAR_SET([ac_cv_search_ntohl], [no])])
    rm conftest.$ac_ext
    LIBS="$ax_lib_winsock2_save_LIBS"
  ])

  ws32_LIBS=
  if test "x$ac_cv_search_ntohl" == "xno"; then
    AC_MSG_ERROR([could not find ntohl])
  elif test "x$ac_cv_search_ntohl" != "xnone required"; then
    ws32_LIBS="$ac_cv_search_ntohl"
  fi
  AC_SUBST(ws32_LIBS)
])
