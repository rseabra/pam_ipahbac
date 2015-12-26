![IPA HBAC logo](ipahbac.png)

Intro
=====

AIX supports it's own two LDAP attributes, per user: one which lists hosts where the user is allowed to login, and another of hosts where he is forbidden to.

Solaris has just one, for allowed hosts.

Both are unmaintanable messes per user, not the elegancy of FreeIPA's HBAC controls, they both _miss_ the concept of flexible control of user access to hosts and services.

This is just a simple PAM module that aims to implement FreeIPA's HBAC for systems that don't support it, like AIX and Solaris, or for systems that want to support it without a full FreeIPA client stack.

The logo is a play with the concept of _plugging in the missing piece_.

**Building the PAM module**

To build, either use the build scripts or use these commands:

	./configure --prefix=/usr
	make
	sudo make install

**Testing**

You can check sample.pam included for more details about configuring the module, but it's a bit like this:

	cat <<EOF > /etc/pam.d/ipahbac_test
	auth       required     pam_ipahbac.so blameGetOpt -u YourSysAccount -b dc=your,dc=domain -P /etc/ldap.secret -l ldaps://ldap1/,ldaps://ldap2/..
	account    required     pam_ipahbac.so blameGetOpt -u YourSysAccount -b dc=your,dc=domain -P /etc/ldap.secret -l ldaps://ldap1/,ldaps://ldap2/..
	EOF

Options
-------
* blameGetOpt is only needed in GNU/Linux, getopt expects argv[0] to be the command. Not needed in Solaris, it works differently there. (Why use getopt?... well... why have the trouble of parsing options myself?)
* `-b BASE` is mandatory, the IPA domain base
* `-u USER` is mandatory, an IPA sysaccount but only the uid value is needed, the rest is derived from the base
* `-p PASS` or `-P path` is mandatory, as you'll need the sysaccount's password. The second form reads the whole first line of bytes as the password, including newline if present
* `-l LDAPSERVERS` is mandatory, and comprised of a comma separated list of LDAP servers. Use URI's in GNU/Linux, host:port in Solaris. TLS is **expected and required**.
* `-k path` is mandatory **in Solaris**; it's the path to the NSSDB that OpenLDAP is using.
* `-x path` is an optional file with a line separated list of users who will be immediately accepted (useful for root and application accounts).

Known Issues
------------

Although it's oriented towards Solaris, AIX and non SSSD GNU/Linux systems or commands, so far it has only been tested in :
* Fedora 23
* Solaris 11.3
* AIX 7.1 (not really, yet, it's in the works)

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
