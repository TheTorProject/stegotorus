# SYNOPSIS
#
#   AX_CXX_STATIC_ASSERT
#
# DESCRIPTION
#
#   Detect whether the C++ compiler, in its present operating mode,
#   supports the C++11 'static_assert' construct.  If it doesn't,
#   define 'static_assert' as a preprocessor macro which provides
#   more-or-less the same functionality.
#
# LICENSE
#
#   Copyright (c) 2012 Zack Weinberg <zackw@panix.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([AX_CXX_STATIC_ASSERT], [dnl
  AC_LANG_ASSERT([C++])dnl
  AC_CACHE_CHECK(whether $CXX accepts static_assert, ax_cv_cxx_static_assert,
    [AC_COMPILE_IFELSE([AC_LANG_SOURCE([dnl
         template <typename T>
         struct check
         { static_assert(sizeof(int) <= sizeof(T), "not big enough"); };
         check<int> ok;])],
       [ax_cv_cxx_static_assert=yes], [ax_cv_cxx_static_assert=no])])
  if test x$ax_cv_cxx_static_assert = xyes; then
   AC_CACHE_CHECK(whether $CXX enforces static_assert, ax_cv_cxx_static_assert_e,
    [AC_COMPILE_IFELSE([AC_LANG_SOURCE([dnl
         template <typename T>
         struct check
         { static_assert(sizeof(char[2]) <= sizeof(T), "not big enough"); };
         check<char> bad;])],
       [ax_cv_cxx_static_assert_e=no], [ax_cv_cxx_static_assert_e=yes])])
  fi
  if test x$ax_cv_cxx_static_assert = xyes &&
     test x$ax_cv_cxx_static_assert_e = xyes; then
    AC_DEFINE(HAVE_STATIC_ASSERT, 1,
              [Define to 1 if the C++ compiler supports static_assert.])
  fi
  AH_VERBATIM([HAVE_STATIC_ASSERT_],
[#ifndef HAVE_STATIC_ASSERT
# define static_assert(expr, msg) typedef char static_assert_id[(expr)?1:-1]
# ifdef __COUNTER__
#  define static_assert_id static_assert_paste(static_assert_, __COUNTER__)
# else
#  define static_assert_id static_assert_paste(static_assert_, __LINE__)
# endif
# define static_assert_paste(a,b) static_assert_paste_(a,b)
# define static_assert_paste_(a,b) a##b
#endif])
])
