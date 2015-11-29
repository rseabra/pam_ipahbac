.PHONY: aix solaris

aix: pam_ipahbac.o
	gcc -fPIC -fno-stack-protector -D AIX_BUILD -c pam_ipahbac.c

aixinstall: aix /lib64/security/pam_ipahbac.so
	sudo ld -x --shared -o /lib64/security/pam_ipahbac.so pam_ipahbac.o

clean:
	rm pam_ipahbac.o
