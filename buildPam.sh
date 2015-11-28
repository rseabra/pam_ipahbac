#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/pam_ipahbac.c

sudo ld -x --shared -o /lib/security/pam_ipahbac.so pam_ipahbac.o

rm pam_ipahbac.o
