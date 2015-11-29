MAINTAINERCLEANFILES = Makefile.in

bin_PROGRAMS: test

test_SOURCES = test.c
test_LDFLAGS = -lpam -lpam_misc

pamlibdir = $(PAM_DEST_DIR)
pamlib_LTLIBRARIES = pam_ipahbac.la

pam_ipahbac_la_SOURCES = pam_ipahbac.c pam_ipahbac.h
pam_ipahbac_la_CFLAGS = -fPIC -fno-stack-protector -Wall
pam_ipahbac_la_LDFLAGS = -module -avoid-version -shared -export-dynamic -ltspi -lpam --as-needed --disable-static --shared

EXTRA_DIST = pam_libhbac.h
