Intro
=====

<img src='ipahbac.png' align='right' width='30%' height='30%' alt="PAM IPA HBAC logo"/>

AIX supports it's own two LDAP attributes, per user: one which lists hosts where the user is allowed to login, and another of hosts where he is forbidden to.

Solaris has just one, for allowed hosts.

Both are unmaintanable messes per user, not the elegancy of FreeIPA's HBAC controls, they both _miss_ the concept of flexible control of user access to hosts and services.

This is just a simple PAM module that aims to implement FreeIPA's HBAC for systems that don't support it, like [AIX](https://github.com/rseabra/pam_ipahbac/wiki/AIX) and Solaris, or for systems that want to support it without a full FreeIPA client stack.

The logo is a play with the concept of _plugging in the missing piece_.

**Building the PAM module**

To build, either use the build scripts or use these commands:

	./configure --prefix=/usr
	make
	sudo make install

Building in AIX is a very long story, [checkout the rpm SPEC](https://github.com/rseabra/pam_ipahbac/releases/download/0.0.7/pam_ipahbac.spec). One used to need to build a lot of dependencies before it could work, but the usual source of RPMS for AIX seems to have had some recent love fixing most of the issues.

**Testing**

You can check sample.pam included for more details about configuring the module, but it's a bit like this:

	cat <<EOF > /etc/pam.d/ipahbac_test
	account    required     pam_ipahbac.so blameGetOpt -u YourSysAccount -b dc=your,dc=domain -P /etc/ldap.secret -l ldaps://ldap1/,ldaps://ldap2/..
	EOF

Options
-------
* blameGetOpt is only needed in GNU/Linux and AIX as getopt is expecting argv[0] to be the command. Not needed in Solaris, it works differently there. (Why use getopt?... well... why have the trouble of parsing options myself?)
* `-d level` is optional, the debug level (use a value greater than zero, although currently only has one debug level)
* `-D domain` is optional, and used to create the FQDN if the hostname is the short version (eg, a.b.c).
* `-b BASE` is mandatory, the IPA domain base (eg dc=a,dc=b,dc=c)
* `-u USER` **or** `-U USER` is mandatory, the first form derives to an IPA **sysaccount** while the second one to a normal user, thus only the uid value is needed, the rest is derived from the base
* `-p PASS` or `-P path` is mandatory, as you'll need the sysaccount's password. The second form reads the whole first line of bytes as the password, including newline if present
* `-l LDAPSERVERS` is mandatory, and comprised of a comma separated list of LDAP servers. Use URI's in GNU/Linux and AIX, **host:port in Solaris**. TLS is **expected and required**.
* `-k path` is mandatory in **Solaris and AIX**; it's the path to the NSSDB that OpenLDAP (or gskit with IDSLDAP in AIX) is using.
* `-K path` is optional in **AIX** (if you use password stash with the keydb) and not really needed in Solaris; it's the path to a file containing only (no new line) the password to open the gskit kdb
* `-x path` is an optional file with a line separated list of users who will be immediately accepted (useful for root and functional accounts).

Status
------

| OS  | Status | Observations |
| --- |:------:| ------------ |
| Fedora 23 | Done | Just for fun, not really needed on modern IPA-ready native systems |
| Solaris 11.3 | Done | Remember to compile in 64 and 32 bits... |
| 7.1 TL5SP4 | Done | Remember to compile in 64 and 32 bits... |

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
