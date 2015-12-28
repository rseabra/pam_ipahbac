# Initialize autoconf.
AC_COPYRIGHT([
See the included file: COPYING for copyright information.
])
AC_INIT([pam_ipahbac], [0.0.3], [rms@1407.org],
        [pam_ipahbac], [https://github.com/rseabra/pam_ipahbac/])
# Force autoconf to be at least this version number:
AC_PREREQ([2.68])
# Safety check - list a source file that wouldn't be in other directories:
AC_CONFIG_SRCDIR([src/pam_ipahbac.c])
# Put configuration results here, so we can easily #include them:
AC_CONFIG_HEADERS([config.h])
# Put autotools auxiliary files in subdirectories to reduce clutter:
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE

# Checks for programs, e.g., AC_PROG_CC
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB(pam, pam_start)
AC_SEARCH_LIBS([ldap_bind_s], [ldap], , AC_MSG_ERROR([Unable to find OpenLDAP libs]))

# Checks for header files.
AC_CHECK_HEADERS([ldap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Choose what to build
AC_ARG_ENABLE([pamdir], [AS_HELP_STRING([--enable-pamdir],
              [Location to install the pam module ($libdir/security)])],
              [pamdir=$enableval], [pamdir=$libdir/security])
AC_SUBST(pamdir)


case "$host_os" in
	*solaris*)
		LIBS="$LIBS -lresolv"
		AC_SUBST(pammisc,[])
		AC_SUBST(WARNINGS,["-Wall"])
		AC_SUBST(STACKPROT,["-fstack-protector"])
		AC_DEFINE([SOLARIS_BUILD], [1], [Whether to build against Solaris])
		AC_SUBST(XLCFLAGS,[""])
	;;
	*aix*)
		AC_SUBST(pammisc,[])
		AC_DEFINE([AIX_BUILD], [1], [Whether to build against Solaris])

		AC_SUBST(WARNINGS,[""])
		AC_SUBST(XLCFLAGS,["-q64"])
	;;
	*)
		AC_SUBST(WARNINGS,["-Wall"])
		AC_SUBST(STACKPROT,["-fstack-protector-strong"])
		AC_SUBST(XLCFLAGS,[""])
		AC_DEFINE([GNULINUX_BUILD], [1], [Whether to build against a GNU/Linux system [default]])
	;;
esac

AC_ARG_ENABLE([hbaccfg], [AS_HELP_STRING([--enable-hbaccfg],
              [Location to install the pam module ($sysconfdir/ipa-hbac.conf)])],
              [hbaccfg=$enableval], [hbaccfg=$sysconfdir/ipa-hbac.conf])
AC_SUBST(hbaccfg)

LIBDIR=`eval echo $LIBDIR`
AC_SUBST([LIBDIR])

AC_SUBST([VERSION])

# Do final output.
AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT
