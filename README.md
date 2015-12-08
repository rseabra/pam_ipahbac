![FreeIPA logo](https://www.freeipa.org/images/freeipa/freeipa-logo-small.png)

Intro
=====

This is just a simple PAM module to implement FreeIPA HBAC for systems that don't support it, like AIX and Solaris.

To build, either use the build scripts or use these commands:

**Building the PAM module**

	./configure --prefix=/usr
	make
	sudo make install

**Testing**

You can check sample.pam included for more details about configuring the module, but it's a bit like this:

	cat <<EOF > /etc/pam.d/ipahbac_test
	auth       required     pam_ipahbac.so blameGetOpt -u YourSysAccount -b dc=your,dc=domain -p thePassw0rd -l ldaps://ldap1/,ldaps://ldap2/..
	account    required     pam_ipahbac.so blameGetOpt -u YourSysAccount -b dc=your,dc=domain -p thePassw0rd -l ldaps://ldap1/,ldaps://ldap2/..
	EOF

Simple Usage
------------

Take a look at Testing above, apply to the commands you want.

Known Issues
------------

Although it's oriented towards Solaris, AIX and non SSSD GNU/Linux systems or commands, so far it has only been tested in :
* Fedora 23
* Solaris 11.3

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

The whole project is licensed under the GNU GPL version 2 or later. test.c is licensed under MIT since most of it's original code remains. If none remains after sometime, this alert will be removed.

Aditionally, you're allowed to link with Solaris and AIX's PAM libraries.
