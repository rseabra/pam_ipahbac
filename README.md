Intro
=====

This is just a simple PAM module to implement FreeIPA HBAC for systems that don't support it, like AIX and Solaris.

To build, either use the build scripts or use these commands:

**Build the PAM module**

`gcc -fPIC -fno-stack-protector -c src/pam_ipahbac.c`

`sudo ld -x --shared -o /lib/security/pam_ipahbac.so pam_ipahbac.o`

The first command builds the object file in the current directory and the second links it with PAM.
Since it's a shared library, PAM can use it on the fly without having to restart.

**Build Test**

`gcc -o pam_test src/test.c -lpam -lpam_misc`

Simple Usage
------------

The build scripts will take care of putting your module where it needs to be, `/lib/security`, so the next thing to do is edit config files.

The config files are located in `/etc/pam.d/` and the one I edited was `/etc/pam.d/common-auth`.

The test application tests auth and account functionality (although account isn't very interesting). At the top of the pam file (or anywhere), put these lines:

	auth sufficient pam_ipahbac.so
	account sufficient pam_ipahbac.so

I think the account part should technically go in `/etc/pam.d/common-account`, but I put mine in the same place so I'd remember to take them out later.

To run the test program, just do: `pam_test backdoor` and you should get some messages saying that you're authenticated! Maybe this is how Sam Flynn 'hacked' his father's computer in TRON Legacy =D.

Resources
=========

Beat Gammit's Simple PAM
------------------------

I forked Beat Gammit's simple example as basis for start. You can find it here: https://github.com/beatgammit/simple-pam

I found these resources especially helpful:

O'Reilly Guides:
----------------

These guides give brief overviews about PAM and how to write modules.  This is useful if you already have a little knowledge.

* [Writing PAM Modules, Part One](http://linuxdevcenter.com/pub/a/linux/2002/05/02/pam_modules.html)
* [Writing PAM Modules, Part Two](http://linuxdevcenter.com/pub/a/linux/2002/05/23/pam_modules.html)
* [Writing PAM Modules, Part Three](http://linuxdevcenter.com/pub/a/linux/2002/05/30/pam_modules.html)

Others
------

Good example for simple authentication.  I adapted this one in my simple PAM module.

[2-factor authentication & writing PAM modules](http://ben.akrin.com/?p=1068)

License
=======

The whole project is licensed under the GNU GPL version 2 or later. Portions may be in MIT if some of the original code of simple-pam remains. If none remains after sometime, this alert will be removed.

Aditionally, you're allowed to link with Solaris and AIX's PAM libraries.
