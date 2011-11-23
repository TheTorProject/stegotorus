##                                                          -*- Autoconf -*-
# Copyright (C) 1999, 2000, 2001, 2003, 2004, 2005, 2008, 2011
# Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# serial 1

# AX_PROG_CXX_C_O
# --------------
# Like AC_PROG_CC_C_O, but tests the C++ compiler instead of the C
# compiler, does not bother testing the generic 'cc'-equivalent, and
# only does the output setting that Automake cares about (i.e. does
# _not_ define CXX_NO_MINUS_C_MINUS_O).

AC_DEFUN([AX_PROG_CXX_C_O],
[AC_REQUIRE([AC_PROG_CXX])dnl
AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
AC_REQUIRE_AUX_FILE([compile])dnl
AC_MSG_CHECKING([whether $CXX understands -c and -o together])
set dummy $CXX; am_cxx=`AS_ECHO(["$[2]"]) |
                        sed ['s/[^a-zA-Z0-9_]/_/g;s/^[0-9]/_/']`
AC_CACHE_VAL(ac_cv_prog_cxx_${am_cxx}_c_o,
[AC_LANG_ASSERT([C++])
AC_LANG_CONFTEST([AC_LANG_PROGRAM([])])
# We do the test twice because some compilers refuse to overwrite an
# existing .o file with -o, though they will create one.
ac_try='$CXX -c conftest.$ac_ext -o conftest2.$ac_objext >&AS_MESSAGE_LOG_FD'
rm -f conftest2.*
if _AC_DO_VAR(ac_try) &&
   test -f conftest2.$ac_objext && _AC_DO_VAR(ac_try)
then
  eval ac_cv_prog_cc_${am_cxx}_c_o=yes
else
  eval ac_cv_prog_cc_${am_cxx}_c_o=no
fi
rm -f core conftest*
])dnl
if eval test \$ac_cv_prog_cc_${am_cxx}_c_o = yes; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
  # Losing compiler, so override with the script.
  # FIXME: It is wrong to rewrite CXX.
  # But if we don't then we get into trouble of one sort or another.
  # A longer-term fix would be to have automake use am__CC in this case,
  # and then we could set am__CXX="\$(top_srcdir)/compile \$(CXX)"
  CXX="$am_aux_dir/compile $CXX"
fi
dnl Make sure AC_PROG_CXX is never called again, or it will override our
dnl setting of CXX.
m4_define([AC_PROG_CXX],
          [m4_fatal([AC_PROG_CXX cannot be called after AX_PROG_CXX_C_O])])
])
