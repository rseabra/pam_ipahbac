# Initialize autoconf.
AC_INIT([pam_ipahbac], [0.0.1], [rms@1407.org],
        [pam_ipahbac], [https://github.com/rseabra/pam_ipahbac/])
# Force autoconf to be at least this version number:
AC_PREREQ([2.68])
# Safety check - list a source file that wouldn't be in other directories:
AC_CONFIG_SRCDIR([src/pam_ipahbac.c])
# Put configuration results here, so we can easily #include them:
AC_CONFIG_HEADERS([config.h])
# Put autotools auxiliary files in subdirectories to reduce clutter:
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile])

# Checks for programs, e.g., AC_PROG_CC

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Do final output.
AC_OUTPUT([
Makefile
src/Makefile
])
