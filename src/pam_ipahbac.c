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
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <config.h>

#include "pam_ipahbac.h"

#include <ldap.h>

#ifdef HAVE_LDAP_H
// shutup some idiot warnings from -Wall ;)
extern char ** ldap_get_values(	LDAP *ld, LDAPMessage *entry, char *attrs );
extern int ldap_bind_s(LDAP *ld, const char *who, const char *cred, int method);
extern int ldap_unbind_s(LDAP *ld);

int ldap_search_s(LDAP *ld, const char *base, int scope, const char *filter, char **attrs, int attrsonly, LDAPMessage **msg) {
	return ldap_search_ext_s(ld, base, scope, filter, attrs, attrsonly, NULL, NULL, NULL, 0, msg);
}

// yes, only supports ASCII for now
int is_dangerous_char(int c) {
	if(	(44 <= c && c <= 58) ||	// , - . / digits and :
		(64 <= c && c <= 90) ||	// @ and A-Z
		(97 <= c && c <= 122) || // a-z
		(95 == c) || (61 == c)	// _ and =
	  ) return 0;
	return 1;
}

// yes, only supports ASCII for now
int dangerous_str(char* str) {
	int i;
	int length = strlen(str);
	if(length >= LEN) return 0;
	//printf("Length of %s is %d\n", str, length);
	for(i=0; i < length; i++)
		if(is_dangerous_char((int)str[i])) {
			//printf("DANGER with %d!\n", str[i]);
			return 1;
		}
	return 0;
}

int hbac_check_memberservice(LDAP* ld, const char* base, LDAPMessage* entry, char* attr, const char* name) {
	int i,pos,retval;
	char** values=NULL;
	char dn[LEN];
	int found=0;
	char groupbase[LEN];
	char filter[LEN];
	char* attrs[] = { "member", NULL } ;
	char group[LEN];
	char* index=NULL;
	LDAPMessage* msg=NULL;

	// create the user DN to match and the group base
	if(0 > snprintf(dn, LEN, "cn=%s,cn=hbacservices,cn=hbac,%s", (char*)name, (char*)base)) return 0;
	if(0 > snprintf(groupbase, LEN, "cn=hbacservicegroups,cn=hbac,%s", (char*)base)) return 0;
	values = ldap_get_values(ld, entry, attr);
	for(i=0; values[i] != NULL; i++) {
		index=strstr(values[i], "cn=hbacservicegroups");
		if(index) {
			// find out the length of the group cn so it can be extracted into 'group'
			pos=0;
			while(values[i][3+pos++] != ',') ;
			if(0 > snprintf(group, pos, "%s", values[i]+3)) return 0;

			// search on ldap whether user dn is a member of the group
			if(0 > snprintf(filter, LEN, "(&(objectclass=*)(cn=%s)(member=%s))", group, dn)) return 0;
			if( (retval=ldap_search_s(ld, groupbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) == LDAP_SUCCESS) {
				if( ldap_count_entries(ld, msg) > 0 ) {
					//printf("MATCH SVC %s on group %s\n", dn, values[i]);
					found=1;
				}
			} else { printf("Error in LDAP search: %s\n", ldap_err2string(retval)); }
			if(msg != NULL) ldap_msgfree(msg);
		} else {
			index=strstr(values[i], "cn=hbacservices");
			if(index && strncmp(values[i], dn, LEN) == 0 ) {
				//printf("MATCH SVC %s\n", dn);
				found=1;
			}
		}

	}

	return found;
}

int hbac_check_memberhost(LDAP* ld, const char* base, LDAPMessage* entry, char* attr, const char* name) {
	int i,pos,retval;
	char** values=NULL;
	char dn[LEN];
	int found=0;
	char groupbase[LEN];
	char filter[LEN];
	char* attrs[] = { "member", NULL } ;
	char group[LEN];
	char* index=NULL;
	LDAPMessage* msg=NULL;

	// create the user DN to match and the group base
	if(0 > snprintf(dn, LEN, "fqdn=%s,cn=computers,cn=accounts,%s", (char*)name, (char*)base)) return 0;
	if(0 > snprintf(groupbase, LEN, "cn=hostgroups,cn=accounts,%s", (char*)base)) return 0;
	values = ldap_get_values(ld, entry, attr);
	for(i=0; values[i] != NULL; i++) {
		index=strstr(values[i], "cn=hostgroups");
		if(index) {
			// find out the length of the group cn so it can be extracted into 'group'
			pos=0;
			while(values[i][3+pos++] != ',') ;
			if(0 > snprintf(group, pos, "%s", values[i]+3)) return 0;

			// search on ldap whether user dn is a member of the group
			if(0 > snprintf(filter, LEN, "(&(objectclass=ipahostgroup)(cn=%s)(member=%s))", group, dn)) return 0;
			if( (retval=ldap_search_s(ld, groupbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) == LDAP_SUCCESS) {
				if( ldap_count_entries(ld, msg) > 0 ) {
					//printf("MATCH HOST %s on group %s\n", dn, values[i]);
					found=1;
				}
			} else { printf("Error in LDAP search: %s\n", ldap_err2string(retval)); }
			if(msg != NULL) ldap_msgfree(msg);
		} else {
			index=strstr(values[i], "cn=computers");
			if(index && strncmp(values[i], dn, LEN) == 0 ) {
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
	char dn[LEN];
	int found=0;
	char groupbase[LEN];
	char filter[LEN];
	char* attrs[] = { "member", NULL } ;
	char group[LEN];
	char* index=NULL;
	LDAPMessage* msg=NULL;

	// create the user DN to match and the group base
	if(0 > snprintf(dn, LEN, "uid=%s,cn=users,cn=accounts,%s", (char*)name, (char*)base)) return 0;
	if(0 > snprintf(groupbase, LEN, "cn=groups,cn=accounts,%s", (char*)base)) return 0;
	values = ldap_get_values(ld, entry, attr);
	for(i=0; values[i] != NULL; i++) {
		index=strstr(values[i], "cn=groups");
		if(index) {
			// find out the length of the group cn so it can be extracted into 'group'
			pos=0;
			while(values[i][3+pos++] != ',') ;
			if(0 > snprintf(group, pos, "%s", values[i]+3)) return 0;

			// search on ldap whether user dn is a member of the group
			if(0 > snprintf(filter, LEN, "(&(objectclass=posixgroup)(cn=%s)(member=%s))", group, dn)) return 0;
			if( (retval=ldap_search_s(ld, groupbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) == LDAP_SUCCESS) {
				if( ldap_count_entries(ld, msg) > 0 ) {
					//printf("MATCH USER %s on group %s\n", dn, values[i]);
					found=1;
				}
			} else { printf("Error in LDAP search: %s\n", ldap_err2string(retval)); }

			if(msg != NULL) ldap_msgfree(msg);
		} else {
			index=strstr(values[i], "cn=users");
			if(index && strncmp(values[i], dn, LEN) == 0 ) {
				//printf("MATCH USER %s\n", dn);
				found=1;
			}
		}

	}

	return found;
}

int ipa_check_hbac(char* ldapservers, const char* base, const char* binduser, const char* bindpw, const char* thishost, const char* svcname, const char* username, char* keydb) {
	int attruser;
	int attrhost;
	int attrsvc;
	int matchuser=0;
	int matchhost=0;
	int matchsvc=0;
	int retval=0;

	char hbacbase[LEN];
	const char* filter="(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))";
	char* attrs[] = { "memberuser", "memberhost", "memberservice", NULL } ;
	int ldap_version=LDAP_VERSION3;
	LDAP* ld=NULL;
	LDAPMessage* msg=NULL;
	LDAPMessage* entry=NULL;
	char* attr=NULL;
	BerElement* ber=NULL;

#if defined(SOLARIS_BUILD) || defined(AIX_BUILD)

# define LDAP_OPT_SUCCESS LDAP_SUCCESS

	int i,len;

	if(ldapssl_client_init(keydb, NULL) < 0) {
		printf("Error initializing ssl client\n");
		return 0;
	}

	len = strlen(ldapservers);
	for(i=0; i<=len; i++) {
		if(ldapservers[i]==',') ldapservers[i]=' ';
	}

	ld = ldapssl_init(ldapservers, 636, LDAPSSL_AUTH_CNCHECK);
	if(ld == NULL) {
		printf("Error initializing LDAP (ldapssl_init returned NULL)\n");
		return 0;
	}
#else
	retval = ldap_initialize(&ld, ldapservers);
	if(retval != 0) {
		printf("Error initializing LDAP: %d\n", retval);
		return 0;
	}
#endif

	if( ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS ) {
		printf("Error setting LDAPv3\n");
		return 0;
	}

	if( (retval = ldap_bind_s(ld, binduser, bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS ) {
		printf("Error binding to LDAP: %s\n", ldap_err2string(retval));
		return 0;
	}

// ldapsearch -H ldaps://server/ -Z -D 'cn=directory manager' -W -b cn=hbac,dc=domain... '(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))' memberuser memberhost memberservice

	if(0 > snprintf(hbacbase, LEN, "cn=hbac,%s", (char*)base)) return 0;
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
			if( strncmp(attr, "memberservice", 13) == 0) {
				attrsvc=1;
				matchsvc = hbac_check_memberservice(ld, base, entry, attr, svcname);
			}
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

int free_and_return(int retval, char* binduser, char* bindpw, char* base, char* ldapservers, char* keydb) {
	if(binduser) free(binduser);
	if(bindpw) free(bindpw);
	if(base) free(base);
	if(ldapservers) free(ldapservers);
	if(keydb) free(keydb);
	return retval;
}

int check_exceptions(const char* exceptions_file, const char* username) {
	int len;
	FILE* file=NULL;
	char line[LEN];
	file = fopen(exceptions_file, "r");
	if(!file) {
		printf("Error opening %s: %s\n", exceptions_file, strerror(errno));
		return 0;
	}

	while(fgets(line, LEN, file)) {
		len = strlen(line);
		if(line[len-1] == '\n')
			line[--len] = 0;
		if(line[len-1] == '\r')
			line[--len] = 0;
		if(0 == strcmp(line, username)) {
			fclose(file);
			return 1;
		}
	}
	fclose(file);
	return 0;
}

/* credentials */
#if defined(SOLARIS_BUILD) || defined(AIX_BUILD)
int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_IGNORE;
}

int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
#else
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
#endif
	int retval;
	int opt;
	char thishost[LEN];
	char* binduser=NULL;
	char* bindpw=NULL;
	FILE* bindpwfile=NULL;
	char* base=NULL;
	char* keydb=NULL;
	char* ldapservers=NULL;
#if defined(SOLARIS_BUILD) || defined(AIX_BUILD)
	char* username=NULL;
	char* svcname=NULL;
	int gotkeydb=0;
#endif
#ifdef GNULINUX_BUILD
	const char* username=NULL;
	const char* svcname=NULL;
#endif
	char sysaccount[LEN];
	int gotuser=0;
	int gotpass=0;
	int gotbase=0;
	int gotservers=0;

	retval = pam_get_user(pamh, &username, "Username: ");
	if (retval != PAM_SUCCESS || dangerous_str((char*)username)) {
		return PAM_PERM_DENIED;
	}

	retval = pam_get_item(pamh, PAM_SERVICE, (void*)&svcname);
	if (retval != PAM_SUCCESS || dangerous_str((char*)svcname)) {
		return PAM_PERM_DENIED;
	}

	thishost[LEN-1]='\0';
	gethostname(thishost, LEN-1);
	if(dangerous_str(thishost)) return PAM_PERM_DENIED;

	optind=0;
	while( (opt = getopt(argc, (char * const*)argv, "k:u:p:P:b:l:x:") ) != -1 ) {
		switch(opt) {
			case 'u':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				binduser=strndup(optarg, LEN-1);
				if(!binduser) {
					printf("Error reading binduser %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				gotuser=1;
				break;
			case 'p':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				bindpw=strndup(optarg, LEN-1);
				if(!bindpw) {
					printf("Error reading bindpw %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				gotpass=1;
				break;
			case 'P':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				bindpwfile=fopen(optarg, "r");
				if(!bindpwfile) {
					printf("Error opening bindpw from %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				bindpw=malloc(LEN);
				if(!bindpw) {
					printf("Not enough memory to create bindpw buffer: %s\n", strerror(errno));
					fclose(bindpwfile);
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				memset(bindpw, 0, LEN);
				if(!fgets(bindpw, LEN, bindpwfile)) {
					printf("Error reading bindpw from %s: %s\n", optarg, strerror(errno));
					fclose(bindpwfile);
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				fclose(bindpwfile);
				gotpass=1;
				break;
			case 'b':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				base=strndup(optarg, LEN-1);
				if(!base) {
					printf("Error reading base %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				gotbase=1;
				break;
			case 'l':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				ldapservers=strndup(optarg, LEN-1);
				if(!ldapservers) {
					printf("Error reading ldapservers %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				gotservers=1;
				break;
#ifdef SOLARIS_BUILD
			case 'k':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				keydb=strndup(optarg, LEN-1);
				if(!keydb) {
					printf("Error reading keydb %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				}
				gotkeydb=1;
				break;
#endif
			case 'x':
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
				if(check_exceptions(optarg, username) ) {
					return free_and_return(PAM_SUCCESS, binduser, bindpw, base, ldapservers, keydb);
				}
				break;
		}
	}

#ifdef SOLARIS_BUILD
	if( ! (gotuser && gotpass && gotbase && gotservers && gotkeydb) ) {
#endif
	if( ! (gotuser && gotpass && gotbase && gotservers ) ) {
		printf("ERROR: missing -u, -p, -b or -l parameters (%d,%d,%d,%d). Please RTFM.\n", gotuser, gotpass, gotbase, gotservers);
		return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
	}

	if( 0 > snprintf(sysaccount, LEN-1, "uid=%s,cn=sysaccounts,cn=etc,%s", binduser, base) ) {
		printf("ERROR: failure defining the sysaccount for %s in %s\n", binduser, base);
		return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
	}

	//printf("Hostname: %s\n", thishost);
	//printf("Binduser: %s\n", sysaccount);
	//printf("Bindpw: %s\n", bindpw);
	//printf("Base: %s\n", base);
	//printf("LDAP Servers: %s\n", ldapservers);

	if (ipa_check_hbac(ldapservers, base, sysaccount, bindpw, thishost, svcname, username, keydb))
		return free_and_return(PAM_SUCCESS, binduser, bindpw, base, ldapservers, keydb);
	else return free_and_return(PAM_PERM_DENIED, binduser, bindpw, base, ldapservers, keydb);
}
