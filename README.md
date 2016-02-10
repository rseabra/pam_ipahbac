Intro
=====

<img src='ipahbac.png' align='right' width='30%' height='30%' alt="PAM IPA HBAC logo"/>

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

Status
------

| OS  | Status | Observations |
| --- |:------:| ------------ |
| Fedora 23 | Done | |
| Solaris 11.3 | Done | Remember to compile in 64 and 32 bits... |
| AIX 6.1/7.1 | Compiles | Being seriously tested. Compiles but there are issues (eg, -lldap is missing from the linker, which might have been fixed by recent changes), working on it. I decided to not care about IDSLDAP and just use OpenLDAP, which is sort of a requirement for sudo with LDAP support anyway, so it will be there for sure |

Resources
=========

I found these resources especially helpful.

Beat Gammit's Simple PAM
------------------------

I forked Beat Gammit's simple example as basis for start. You can find it here: https://github.com/beatgammit/simple-pam

Guides
------

These guides give brief overviews about PAM and how to write modules.  This is useful if you already have a little knowledge.

* Oreilly's _Writing PAM Modules_, parts [One](http://linuxdevcenter.com/pub/a/linux/2002/05/02/pam_modules.html) * [Two](http://linuxdevcenter.com/pub/a/linux/2002/05/23/pam_modules.html) and [Three](http://linuxdevcenter.com/pub/a/linux/2002/05/30/pam_modules.html)
* [2-factor authentication & writing PAM modules](http://ben.akrin.com/?p=1068)

License
=======

The whole project is licensed under the GNU GPL version 2 or later. test.c is licensed under MIT since most of it's original code remains. If none remains after sometime, this alert will be removed.

Aditionally, you're allowed to link with Solaris and AIX's PAM libraries.
