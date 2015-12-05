MAINTAINERCLEANFILES = Makefile.in

bin_PROGRAMS = ipahbac_test

ipahbac_test_SOURCES = test.c
ipahbac_test_LDFLAGS = -lpam -lpam_misc


moduledir = @pamdir@

module_LTLIBRARIES = pam_ipahbac.la

pam_ipahbac_la_SOURCES = pam_ipahbac.c pam_ipahbac.h
pam_ipahbac_la_CFLAGS = -fPIC -fno-stack-protector -Wall -D HBAC_CONFIG=@hbaccfg@
pam_ipahbac_la_LDFLAGS = -module -avoid-version -shared -export-dynamic -lpam --as-needed --disable-static --shared

install-data-hook:
	rm -f $(DESTDIR)$(pamdir)/pam_ipahback.la
	libtool --finish $(DESTDIR)$(pamdir)
	${INSTALL} -d $(DESTDIR)$(docdir)
	${INSTALL} -m 644 sample.pam $(DESTDIR)$(docdir)

EXTRA_DIST = sample.pam
