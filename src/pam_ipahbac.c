/*
    Copyright © 2015 Rui Miguel Silva Seabra

    This file is part of PAM IPA HBAC.

    PAM IPA HBAC is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    PAM IPA HBAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PAM IPA HBAC.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifdef HAVE_LDAP_H
# include <ldap.h>
#endif

#include "pam_ipahbac.h"

#define LEN 128

int ipa_check_hbac(const char* ldapservers, const char* binduser, const char* bindpw, const char* thishost, const char* username) {
	int matchuser=0;
	int matchhost=0;
	int retval=0;

#ifdef HAVE_LDAP_H
	LDAP* ld;
	int result;
	int auth_method=LDAP_AUTH_SIMPLE;
	int version=LDAP_VERSION3;
#endif
	// int matchsvc=0; FIXE

	if(strncmp("roque.1407.org", thishost, LEN) == 0) {
		matchhost=1;
	}

	if(strncmp("rms", username, LEN) == 0) {
		matchuser=1;
	}

	return (matchuser && matchhost);
}

/* credentials */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	int opt;
	char thishost[LEN];
	char binduser[LEN], sysaccount[LEN];
	char bindpw[LEN];
	char base[LEN];
	char ldapservers[LEN];
	const char* username=NULL;
	int gotuser=0,gotpass=0,gotbase=0,gotservers=0;

	retval = pam_get_user(pamh, &username, "Username: ");
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	optind=0;
	while( (opt = getopt(argc, (char * const*)argv, "u:p:b:l:") ) != -1 ) {
		switch(opt) {
			case 'u':
				binduser[LEN-1]='\0';
				strncpy(binduser, optarg, LEN-1);
				gotuser=1;
				break;
			case 'p':
				bindpw[LEN-1]='\0';
				strncpy(bindpw, optarg, LEN-1);
				gotpass=1;
				break;
			case 'b':
				base[LEN-1]='\0';
				strncpy(base, optarg, LEN-1);
				gotbase=1;
				break;
			case 'l':
				ldapservers[LEN-1]='\0';
				strncpy(ldapservers, optarg, LEN-1);
				gotservers=1;
				break;
		}
	}

	if( ! (gotuser && gotpass && gotbase && gotservers ) ) {
		printf("ERROR: missing -u, -p, -b or -l parameters (%d,%d,%d,%d). Please RTFM.\n", gotuser, gotpass, gotbase, gotservers);
		return(PAM_PERM_DENIED);
	}

	retval = snprintf(sysaccount, LEN-1, "cn=%s,cn=sysaccounts,cn=etc,%s", binduser, base);
	if( retval <= 0 ) {
		printf("ERROR: failure defining the sysaccount for %s in %s\n", binduser, base);
		return(PAM_PERM_DENIED);
	}

	thishost[LEN-1]='\0';
	gethostname(thishost, LEN-1);
	//printf("Hostname: %s\n", thishost);
	//printf("Binduser: %s\n", sysaccount);
	//printf("Bindpw: %s\n", bindpw);
	//printf("Base: %s\n", base);
	//printf("LDAP Servers: %s\n", ldapservers);

	if (ipa_check_hbac(ldapservers, sysaccount, bindpw, thishost, username))
		return PAM_SUCCESS;
	else
		return PAM_PERM_DENIED;
}
