.PHONY: aix solaris

aix: pam_ipahbac.o
	gcc -fPIC -fno-stack-protector -D AIX_BUILD -c pam_ipahbac.c

aixinstall: aix /lib64/security/pam_ipahbac.so
	ld -x --shared -o /lib64/security/pam_ipahbac.so pam_ipahbac.o

test: test.c
	gcc -o test test.c -lpam -lpam_misc

clean:
	rm -f pam_ipahbac.o test
