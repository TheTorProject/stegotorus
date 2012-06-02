# SYNOPSIS
#
#   AX_SYS_EXTENSIONS
#
# DESCRIPTION
#
#   Functionally equivalent to the stock AC_USE_SYSTEM_EXTENSIONS, but:
#   does not trigger AC_CHECK_HEADER's backward compatibility mode;
#   does not make use of AC_INCLUDES_DEFAULT;
#   does not define _MINIX.
#
# LICENSE
#
#   Same as Autoconf proper.

# serial 1

# Enable extensions on systems that normally disable them,
# typically due to standards-conformance issues.
#
# Remember that #undef in AH_VERBATIM gets replaced with #define by
# AC_DEFINE.  The goal here is to define all known feature-enabling
# macros, then, if reports of conflicts are made, disable macros that
# cause problems on some platforms (such as __EXTENSIONS__).
AC_DEFUN_ONCE([AX_SYS_EXTENSIONS],
[AC_BEFORE([$0], [AC_COMPILE_IFELSE])dnl
AC_BEFORE([$0], [AC_RUN_IFELSE])dnl
AC_PROVIDE([AC_USE_SYSTEM_EXTENSIONS])dnl Suppress the stock macro if used.

  AC_CHECK_HEADER([minix/config.h], [MINIX=yes], [MINIX=], [/**/])
  if test "$MINIX" = yes; then
    AC_DEFINE([_POSIX_SOURCE], [1],
      [Define to 1 if you need to in order for `stat' and other
       things to work.])
    AC_DEFINE([_POSIX_1_SOURCE], [2],
      [Define to 2 if the system does not provide POSIX.1 features
       except with this defined.])
  fi

dnl Use a different key than __EXTENSIONS__, as that name broke existing
dnl configure.ac when using autoheader 2.62.
  AH_VERBATIM([USE_SYSTEM_EXTENSIONS],
[/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# undef _ALL_SOURCE
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# undef _POSIX_PTHREAD_SEMANTICS
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# undef _TANDEM_SOURCE
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# undef __EXTENSIONS__
#endif
])
  AC_CACHE_CHECK([whether it is safe to define __EXTENSIONS__],
    [ac_cv_safe_to_define___extensions__],
    [AC_COMPILE_IFELSE(
      dnl  http://lists.gnu.org/archive/html/bug-gnulib/2006-02/msg00002.html
      dnl  implies that testing <stdlib.h> is adequate.
      [AC_LANG_PROGRAM([[
#       define __EXTENSIONS__ 1
#       include <stdlib.h>
      ]])],
      [ac_cv_safe_to_define___extensions__=yes],
      [ac_cv_safe_to_define___extensions__=no])])
  test $ac_cv_safe_to_define___extensions__ = yes &&
    AC_DEFINE([__EXTENSIONS__])
  AC_DEFINE([_ALL_SOURCE])
  AC_DEFINE([_GNU_SOURCE])
  AC_DEFINE([_POSIX_PTHREAD_SEMANTICS])
  AC_DEFINE([_TANDEM_SOURCE])
])# AX_SYS_EXTENSIONS
