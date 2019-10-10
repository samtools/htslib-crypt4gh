# Configure script for hfile-crypt4gh, HTSlib crypt4gh plug-in
#
#    Copyright (C) 2019 Genome Research Ltd.
#
#    Author: Rob Davies <rmd@sanger.ac.uk>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

dnl Process this file with autoconf to produce a configure script
AC_INIT([hfile-crypt4gh], m4_esyscmd_s([./version.sh 2>/dev/null]),
        [samtools-help@lists.sourceforge.net], [], [http://www.htslib.org/])
AC_PREREQ([2.63])  dnl This version introduced 4-argument AC_CHECK_HEADER
AC_CONFIG_SRCDIR([plugin/hfile_crypt4gh.c])
AC_CONFIG_HEADERS([config.h])

m4_include([m4/hts_prog_cc_warnings.m4])
m4_include([m4/ax_with_htslib.m4])

dnl Copyright notice to be copied into the generated configure script
AC_COPYRIGHT([Portions copyright (C) 2019 Genome Research Ltd.

This configure script is free software: you are free to change and
redistribute it.  There is NO WARRANTY, to the extent permitted by law.])

AC_ARG_WITH([plugin-dir],
  [AS_HELP_STRING([--with-plugin-dir=DIR],
                  [plugin installation location [LIBEXECDIR/htslib]])],
  [case $withval in
     yes|no) AC_MSG_ERROR([no directory specified for --with-plugin-dir]) ;;
   esac],
   [with_plugin_dir='$(libexecdir)/htslib'])
AC_SUBST([plugindir], $with_plugin_dir)

AC_PROG_CC

dnl Turn on compiler warnings, if possible
HTS_PROG_CC_WARNINGS
dnl Flags to treat warnings as errors.  These need to be applied to CFLAGS
dnl later as they can interfere with some of the tests (notably AC_SEARCH_LIBS)
HTS_PROG_CC_WERROR(hts_late_cflags)

AC_SYS_LARGEFILE

AX_WITH_HTSLIB
if test "$ax_cv_htslib" != yes; then
  AC_MSG_ERROR([HTSlib development files not found

Building hfile-crypt4gh requires either an unpacked HTSlib source tree (which
will be built in conjunction with hfile-crypt4gh) or a previously-installed
HTSlib.  In either case you may need to configure --with-htslib=DIR to locate
the appropriate HTSlib.

FAILED.  You must supply an HTSlib in order to build samtools successfully.])
fi

if test "$ax_cv_htslib_which" = source; then
  Hsource=
  Hinstall='#'
else
  Hsource='#'
  Hinstall=
fi
AC_SUBST([Hsource])
AC_SUBST([Hinstall])

dnl Force POSIX mode on Windows/Mingw
test -n "$host_alias" || host_alias=unknown-`uname -s`
case $host_alias in
  *-msys* | *-MSYS* | *-mingw* | *-MINGW*)
    host_result="MSYS dll"
    PLATFORM=MSYS
    PLUGIN_EXT=.dll
    # This also sets __USE_MINGW_ANSI_STDIO which in turn makes PRId64,
    # %lld and %z printf formats work.  It also enforces the snprintf to
    # be C99 compliant so it returns the correct values (in kstring.c).
    CPPFLAGS="$CPPCFLAGS -D_XOPEN_SOURCE=600"
    ;;
esac

libsodium_devel=ok
AC_CHECK_HEADER([sodium.h], [], [libsodium_devel=missing], [;])
AC_SEARCH_LIBS([sodium_version_string], [sodium],
  [AC_DEFINE([HAVE_LIBSODIUM], 1, [Define if libsodium is present])
   AS_IF([test "$ac_cv_search_sodium_version_string" != "none required"],
         HFILE_CRYPT4GH_LIBS=$ac_cv_search_sodium_version_string)],
  [libsodium_devel=missing])
AS_IF([test $libsodium_devel != ok], [dnl
  AC_MSG_ERROR([Libsodium development files not found.

hfile_crypt4gh requires libsodium <https://download.libsodium.org/doc/>.
Building hfile_crypt4gh requires libsodium development files to be installed
on the build machine; you may need to ensure a package such as libsodium-dev
(on Debian or Ubuntu Linux) or libsodium-devel (on RPM-based Linux
distributions or Cygwin) is installed.

Libsodium can also be obtained from
https://download.libsodium.org/libsodium/releases/
  ])
])


dnl Apply value from HTS_PROG_CC_WERROR (if set)
AS_IF([test "x$hts_late_cflags" != x],[CFLAGS="$CFLAGS $hts_late_cflags"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
