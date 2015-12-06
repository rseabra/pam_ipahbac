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

#include <config.h>

#ifdef HAVE_LDAP_H
# include <ldap.h>
#endif

#include "pam_ipahbac.h"

#define LEN 128

#ifdef HAVE_LDAP_H

int hbac_check_memberhost(LDAP* ld, const char* base, LDAPMessage* entry, char* attr, const char* name) {
	int i,pos,retval;
	char** values=NULL;
	char dn[1024];
	int found=0;
	char groupbase[1024];
	char filter[1024];
	const char* attrs[] = { "member", NULL } ;
	char group[1024];
	char* index=NULL;
	LDAPMessage* msg=NULL;

	// create the user DN to match and the group base
	snprintf(dn, 1024, "fqdn=%s,cn=computers,cn=accounts,%s", name, base);
	snprintf(groupbase, 1024, "cn=hostgroups,cn=accounts,%s", base);
	values = ldap_get_values(ld, entry, attr);
	for(i=0; values[i] != NULL; i++) {
		index=strstr(values[i], "cn=hostgroups");
		if(index) {
			// find out the length of the group cn so it can be extracted into 'group'
			pos=0;
			while(values[i][3+pos++] != ',') ;
			snprintf(group, pos, "%s", values[i]+3);

			// search on ldap whether user dn is a member of the group
			snprintf(filter, 1024, "(&(objectclass=ipahostgroup)(cn=%s)(member=%s))", group, dn);
			if( (retval=ldap_search_s(ld, groupbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) != LDAP_SUCCESS) {
				printf("Error in LDAP search: %s\n", ldap_err2string(retval));
				ldap_unbind_s(ld);
				return 0;
			}
			if( ldap_count_entries(ld, msg) > 0 ) {
				//printf("MATCH HOST %s on group %s\n", dn, values[i]);
				found=1;
			}
		} else {
			index=strstr(values[i], "cn=computers");
			if(index && strncmp(values[i], dn, 1024) == 0 ) {
				//printf("MATCH HOST %s\n", dn);
				found=1;
			}
		}

	}

	return found;
}

int hbac_check_memberuser(LDAP* ld, const char* base, LDAPMessage* entry, char* attr, const char* name) {
	int i,pos,retval;
	char** values=NULL;
	char dn[1024];
	int found=0;
	char groupbase[1024];
	char filter[1024];
	const char* attrs[] = { "member", NULL } ;
	char group[1024];
	char* index=NULL;
	LDAPMessage* msg=NULL;

	// create the user DN to match and the group base
	snprintf(dn, 1024, "uid=%s,cn=users,cn=accounts,%s", name, base);
	snprintf(groupbase, 1024, "cn=groups,cn=accounts,%s", base);
	values = ldap_get_values(ld, entry, attr);
	for(i=0; values[i] != NULL; i++) {
		index=strstr(values[i], "cn=groups");
		if(index) {
			// find out the length of the group cn so it can be extracted into 'group'
			pos=0;
			while(values[i][3+pos++] != ',') ;
			snprintf(group, pos, "%s", values[i]+3);

			// search on ldap whether user dn is a member of the group
			snprintf(filter, 1024, "(&(objectclass=posixgroup)(cn=%s)(member=%s))", group, dn);
			if( (retval=ldap_search_s(ld, groupbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) != LDAP_SUCCESS) {
				printf("Error in LDAP search: %s\n", ldap_err2string(retval));
				ldap_unbind_s(ld);
				return 0;
			}
			if( ldap_count_entries(ld, msg) > 0 ) {
				//printf("MATCH USER %s on group %s\n", dn, values[i]);
				found=1;
			}
		} else {
			index=strstr(values[i], "cn=users");
			if(index && strncmp(values[i], dn, 1024) == 0 ) {
				//printf("MATCH USER %s\n", dn);
				found=1;
			}
		}

	}

	return found;
}

int ipa_check_hbac(const char* ldapservers, const char* base, const char* binduser, const char* bindpw, const char* thishost, const char* username) {
	int attruser;
	int attrhost;
	int attrsvc;
	int matchuser=0;
	int matchhost=0;
	int matchsvc=0;
	int retval=0;
	int i;

	char hbacbase[1024];
	const char* filter="(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))";
	const char* attrs[] = { "memberuser", "memberhost", "memberservice", NULL } ;
	int ldap_version=LDAP_VERSION3;
	LDAP* ld=NULL;
	LDAPMessage* msg=NULL;
	LDAPMessage* entry=NULL;
	char* attr=NULL;
	char** values=NULL;
	BerElement* ber=NULL;

	retval = ldap_initialize(&ld, ldapservers);
	if(retval != 0) {
		printf("Error initializing LDAP: %d\n", retval);
		return 0;
	}

	if( ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS ) {
		printf("Error setting LDAPv3\n");
		return 0;
	}

	if( (retval = ldap_bind_s(ld, binduser, bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS ) {
		printf("Error binding to LDAP: %s\n", ldap_err2string(retval));
		return 0;
	}

// ldapsearch -H ldaps://server/ -Z -D 'cn=directory manager' -W -b cn=hbac,dc=domain... '(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))' memberuser memberhost memberservice

	snprintf(hbacbase, 1024, "cn=hbac,%s", base);
	if( (retval=ldap_search_s(ld, hbacbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) != LDAP_SUCCESS) {
		printf("Error in LDAP search: %s\n", ldap_err2string(retval));
		ldap_unbind_s(ld);
		return 0;
	}
	//printf("Number of entries: %d\n", ldap_count_entries(ld, msg));

	for(entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
		attruser=0;
		attrhost=0;
		attrsvc=0;

		for(attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, msg, ber)) {
			if( strncmp(attr, "memberuser", 10) == 0) {
				attruser=1;
				matchuser = hbac_check_memberuser(ld, base, entry, attr, username);
			}
			if( strncmp(attr, "memberhost", 10) == 0) {
				attrhost=1;
				matchhost = hbac_check_memberhost(ld, base, entry, attr, thishost);
			}
/*
 * FIXME: test service ACLs
			if( strncmp(attr, "memberservice", 13) == 0) {
				attrsvc=1;
				printf("Services:\n");
				values = ldap_get_values(ld, entry, attr);
				for(i=0; values[i] != NULL; i++) {
					printf("\t%s\n", values[i]);
				}
			}
*/
		}
		if(!attruser) matchuser=1;
		if(!attrhost) matchhost=1;
		if(!attrsvc) matchsvc=1;

		if (matchuser && matchhost && matchsvc) {
			ldap_unbind_s(ld);
			return 1;
		}
	}

	ldap_unbind_s(ld);
	return 0;
}

#endif

/* credentials */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
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

	retval = snprintf(sysaccount, LEN-1, "uid=%s,cn=sysaccounts,cn=etc,%s", binduser, base);
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

	if (ipa_check_hbac(ldapservers, base, sysaccount, bindpw, thishost, username)) return PAM_SUCCESS;
	else return PAM_PERM_DENIED;
}
