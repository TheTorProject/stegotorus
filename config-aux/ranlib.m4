# SYNOPSIS
#
#   AX_PROG_RANLIB
#
# DESCRIPTION
#
#   In addition to everything AC_PROG_RANLIB does, determine whether it is
#   _necessary_ to run 'ranlib' after 'ar'.  If it is unnecessary (which is
#   the case on most modern systems), reset the RANLIB variable to ':'.
#
# LICENSE
#
#   Same as Autoconf proper.

# serial 1

# 'ranlib' may be needed to make it possible for objects that occur
# later in an archive library to refer to symbols defined by objects
# earlier in the archive.  Therefore, the testing strategy is to
# compile three small files where A refers to B refers to C, put C and
# B in an archive *in that order*, and then see if we can link A
# against the archive.

AC_DEFUN([AX_PROG_RANLIB],
[AC_CHECK_TOOL([AR], [ar])
AC_CHECK_TOOL([RANLIB], [ranlib], [:])
if test x$RANLIB != x:; then
  AC_CACHE_CHECK([whether ranlib is necessary], [ac_cv_prog_RANLIB_necessary],
    [AC_LANG_PUSH([C])

     AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
       extern int B(void);
       int main(void) { return B(); }
     ]])],
     [cp conftest.$ac_objext conftA.$ac_objext],
     [AC_MSG_ERROR([failed to compile test file A])])

     AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
       extern int C(void);
       int B(void) { return C(); }
     ]])],
     [cp conftest.$ac_objext conftB.$ac_objext],
     [AC_MSG_ERROR([failed to compile test file B])])

     AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
       int C(void) { return 0; }
     ]])],
     [cp conftest.$ac_objext conftC.$ac_objext],
     [AC_MSG_ERROR([failed to compile test file C])])

     dnl  There is no standard macro for creating an archive.
     _AC_DO([$AR cru conftest.a conftC.$ac_objext conftB.$ac_objext]) ||
       AC_MSG_ERROR([failed to create test archive])

     dnl  There's no good way to make AC_LINK_IFELSE do what we need.
     AS_IF([_AC_DO([$CC -o conftest$ac_exeext $CFLAGS $CPPFLAGS $LDFLAGS conftA.$ac_objext conftest.a >&AS_MESSAGE_LOG_FD])],
       [ac_cv_prog_RANLIB_necessary=no],
       [AS_IF([_AC_DO([$RANLIB conftest.a && $CC -o conftest$ac_exeext $CFLAGS $CPPFLAGS $LDFLAGS conftA.$ac_objext conftest.a >&AS_MESSAGE_LOG_FD])],
          [ac_cv_prog_RANLIB_necessary=yes],
          [AC_MSG_ERROR([test link failed with and without ranlib])])])

     rm -f conftest$ac_exeext conft[ABC].$ac_objext conftest.a
     AC_LANG_POP([C])
  ])
  if test $ac_cv_prog_RANLIB_necessary = no; then
    RANLIB=:
  fi
fi
])
