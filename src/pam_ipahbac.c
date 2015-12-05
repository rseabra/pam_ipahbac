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

#include "pam_ipahbac.h"

#define LEN 128

int ipa_check_hbac(const char *thishost, const char *username) {
	int matchuser=0;
	int matchhost=0;
	int retval=0;
	// int matchsvc=0; FIXE

	if(strncmp("roque.1407.org", thishost, LEN) == 0) {
		matchhost=1;
	}

	if(strncmp("rms", username, LEN) == 0) {
		matchuser=1;
	}

	return (matchuser && matchhost);
}

/* expected hook */
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
	char binduser[LEN];
	char bindpw[LEN];
	char base[LEN];
	const char* username=NULL;

	retval = pam_get_user(pamh, &username, "Username: ");
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	while( (opt = getopt(argc, (char * const*)argv, "u:p:b:") ) != -1 ) {
		switch(opt) {
			case 'u':
				binduser[LEN-1]='\0';
				strncpy(binduser, optarg, LEN-1); break;
			case 'p':
				bindpw[LEN-1]='\0';
				strncpy(bindpw, optarg, LEN-1); break;
			case 'b':
				base[LEN-1]='\0';
				strncpy(base, optarg, LEN-1); break;
		}
	}

	thishost[LEN-1]='\0';
	gethostname(thishost, LEN-1);
	//printf("Hostname: %s\n", thishost);
	//printf("Binduser: %s\n", binduser);
	//printf("Bindpw: %s\n", bindpw);
	//printf("Base: %s\n", base);

	if (ipa_check_hbac(thishost, username))
		return PAM_SUCCESS;
	else
		return PAM_PERM_DENIED;
}
