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
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <config.h>

#include <ldap.h>

#include "pam_ipahbac.h"

// yes, only supports ASCII for now
int is_dangerous_char(char c) {
	if(33 <= c && c <= 126) return 0;
	return 1;
}

// yes, only supports ASCII for now
int dangerous_str(char* str) {
	size_t i;
	size_t length = strlen(str);
	if(length >= LEN) return 0;
	//if (debug) syslog(LOG_DEBUG, "Length of %s is %d\n", str, length);
	for(i=0; i < length; i++) {
		if(is_dangerous_char(str[i])) {
			//printf("DANGER with %d!\n", str[i]);
			if (debug) syslog(LOG_DEBUG, "Danger with %d!\n", str[i]);
			return 1;
		}
	}
	return 0;
}

#if defined(SOLARIS_BUILD)
 #if defined(SOLARIS_OLD)
	/* Written by Kaveh R. Ghazi <ghazi@caip.rutgers.edu> */
    char *
    strndup (const char *S, size_t n)
    {
        char *result;
        size_t len = strlen (S);

        if (n < len)
         len = n;

        result = (char *) malloc (len + 1);
        if (!result)
         return 0;

        memcpy (result, S, len);
        result[len] = '\0';
        return(result);
    }
 #endif
#endif

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
			} else { syslog(LOG_ERR,"Error in LDAP search: %s\n", ldap_err2string(retval)); }
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

int hbac_check_memberhost(LDAP* ld, const char* base, LDAPMessage* entry, char* attr, char* name) {
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
			} else { syslog(LOG_ERR,"Error in LDAP search: %s\n", ldap_err2string(retval)); }
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
			} else { syslog(LOG_ERR,"Error in LDAP search: %s\n", ldap_err2string(retval)); }

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

int ipa_check_hbac(char* ldapservers, const char* base, const char* binduser, const char* bindpw, char* fqdn, const char* svcname, const char* username, char* keydb) {
	int matchuser=0;
	int matchhost=0;
	int matchsvc=0;
	int retval=0;

	int i=0;
	char** values=NULL;

	char hbacbase[LEN];
	const char* filter="(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))";
	char* attrs[] = { "memberuser", "memberhost", "memberservice", "usercategory", "hostcategory", "servicecategory", NULL } ;
	int ldap_version=LDAP_VERSION3;
	int ldap_sizelimit=1000;
	LDAP* ld=NULL;
	LDAPMessage* msg=NULL;
	LDAPMessage* entry=NULL;
	char* attr=NULL;
	BerElement* ber=NULL;

	if (debug) syslog(LOG_DEBUG,"ldap_initialize(&ld, ldapservers)\n");
	retval = ldap_initialize(&ld, ldapservers);
	if(retval != 0) {
		syslog(LOG_ERR,"Error initializing LDAP (%d): %s\n", retval, ldapservers);
		return 0;
	}

	if (debug) syslog(LOG_DEBUG,"ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version)\n");
	if( ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS ) {
		syslog(LOG_ERR,"Error setting LDAPv3\n");
		return 0;
	}

	if (debug) syslog(LOG_DEBUG,"ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &ldap_sizelimit)\n");
	if( ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &ldap_sizelimit) != LDAP_OPT_SUCCESS ) {
		syslog(LOG_ERR,"Error setting LDAP sizelimit\n");
		return 0;
	}

	if (debug) syslog(LOG_DEBUG,"ldap_bind_s(ld, binduser, bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS )\n");
	if( (retval = ldap_bind_s(ld, binduser, bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS ) {
		syslog(LOG_ERR,"Error binding to LDAP: %s\n", ldap_err2string(retval));
		return 0;
	}

// ldapsearch -H ldaps://server/ -Z -D 'cn=directory manager' -W -b cn=hbac,dc=domain... '(&(objectclass=ipahbacrule)(ipaenabledflag=true)(accessruletype=allow))' memberuser memberhost memberservice

	if (debug) syslog(LOG_DEBUG,"ldap_search_s(ld, hbacbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)\n");
	if(0 > snprintf(hbacbase, LEN, "cn=hbac,%s", (char*)base)) return 0;
	if( (retval=ldap_search_s(ld, hbacbase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg)) != LDAP_SUCCESS) {
		syslog(LOG_ERR,"Error in LDAP search: %s\n", ldap_err2string(retval));
		ldap_unbind_s(ld);
		return 0;
	}
	if (debug) syslog(LOG_DEBUG,"Number of entries: %d\n", ldap_count_entries(ld, msg));

	for(entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
		for(attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, msg, ber)) {

			if( strncmp(attr, "usercategory", 12) == 0) {
				values = ldap_get_values(ld, entry, attr);
				for(i=0; values[i] != NULL; i++) {
					if(strncmp(values[i], "all", 3) == 0) matchuser=1;
				}
				if(debug) syslog(LOG_DEBUG,"CHECKING userCategory: %d\n", matchuser);
			}
			if( strncmp(attr, "memberuser", 10) == 0) {
				matchuser = hbac_check_memberuser(ld, base, entry, attr, username);
				if(debug) syslog(LOG_DEBUG,"CHECKING user: %d\n", matchuser);
			}

			if( strncmp(attr, "hostcategory", 12) == 0) {
				values = ldap_get_values(ld, entry, attr);
				for(i=0; values[i] != NULL; i++) {
					if(strncmp(values[i], "all", 3) == 0) matchhost=1;
				}
				if(debug) syslog(LOG_DEBUG,"CHECKING hostCategory: %d\n", matchhost);
			}
			if( strncmp(attr, "memberhost", 10) == 0) {
				matchhost = hbac_check_memberhost(ld, base, entry, attr, fqdn);
				if(debug) syslog(LOG_DEBUG,"CHECKING host: %d\n", matchhost);
			}
			if( strncmp(attr, "servicecategory", 15) == 0) {
				values = ldap_get_values(ld, entry, attr);
				for(i=0; values[i] != NULL; i++) {
					if(strncmp(values[i], "all", 3) == 0) matchsvc=1;
				}
				if(debug) syslog(LOG_DEBUG,"CHECKING serviceCategory: %d\n", matchsvc);
			}
			if( strncmp(attr, "memberservice", 13) == 0) {
				matchsvc = hbac_check_memberservice(ld, base, entry, attr, svcname);
				if(debug) syslog(LOG_DEBUG,"CHECKING service got %d\n", matchsvc);
			}
		}

		if (matchuser && matchhost && matchsvc) {
			ldap_unbind_s(ld);
			return 1;
		}
	}

	ldap_unbind_s(ld);
	return 0;
}

int free_and_return(int retval, char* binduser, char* bindpw, char* fqdn, char* domain, char* base, char* ldapservers, char* keydb) {
	if(binduser) free(binduser);
	if(bindpw) free(bindpw);
	if(fqdn) free(fqdn);
	if(domain) free(domain);
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
		syslog(LOG_ERR,"Error opening %s: %s\n", exceptions_file, strerror(errno));
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
int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
#else
PAM_EXTERN int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
#endif
	int retval;
	int opt;
	char thishost[LEN];
	char* fqdn=NULL;
	char* domain=NULL;
	char* binduser=NULL;
	char* bindpw=NULL;
	FILE* bindpwfile=NULL;
	char* base=NULL;
	char* keydb=NULL;
	char* ldapservers=NULL;
#if defined(SOLARIS_BUILD) || defined(AIX_BUILD)
	char* username=NULL;
	char* svcname=NULL;
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

	openlog("pam_ipahbac", LOG_PID, LOG_AUTH);
	if (debug) syslog(LOG_DEBUG, "starting user hbac test\n");

	/*
	retval = pam_get_user(pamh, &username, "Username: ");
	if (retval != PAM_SUCCESS || dangerous_str((char*)username)) {
		return PAM_PERM_DENIED;
	}
	*/

	retval = pam_get_item(pamh, PAM_USER, (void*)&username);
	if (retval != PAM_SUCCESS || dangerous_str((char*)username)) {
		return PAM_PERM_DENIED;
	}
	if (debug) syslog(LOG_DEBUG, "got user %s\n", username);

	retval = pam_get_item(pamh, PAM_SERVICE, (void*)&svcname);
	if (retval != PAM_SUCCESS || dangerous_str((char*)svcname)) {
		return PAM_PERM_DENIED;
	}
	if (debug) syslog(LOG_DEBUG, "got service %s\n", svcname);

	thishost[LEN-1]='\0';
	gethostname(thishost, LEN-1);
	if(dangerous_str(thishost)) return PAM_PERM_DENIED;
	if (debug) syslog(LOG_DEBUG, "got host %s\n", thishost);

	optind=0;
	while( (opt = getopt(argc, (char * const*)argv, "d:k:u:p:P:b:l:x:D:") ) != -1 ) {
		if (debug) syslog(LOG_DEBUG, "while cycle for opt %c\n", opt);
		switch(opt) {
			case 'd':
				if (debug) syslog(LOG_DEBUG, "debug enabled\n");
				debug=1;
				break;
			case 'u':
				if (debug) syslog(LOG_DEBUG, "parsing bind user\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				binduser=strndup(optarg, LEN-1);
				if(!binduser) {
					if (debug) syslog(LOG_DEBUG,"Error reading binduser %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				if (debug) syslog(LOG_DEBUG, "bind user: %s\n", binduser);
				gotuser=1;
				break;
			case 'p':
				if (debug) syslog(LOG_DEBUG, "parsing bind password\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				bindpw=strndup(optarg, LEN-1);
				if(!bindpw) {
					if (debug) syslog(LOG_DEBUG,"Error reading bindpw %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				if (debug) syslog(LOG_DEBUG, "got a bind password\n");
				gotpass=1;
				break;
			case 'P':
				if (debug) syslog(LOG_DEBUG, "parsing bind password file\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				bindpwfile=fopen(optarg, "r");
				if(!bindpwfile) {
					if (debug) syslog(LOG_DEBUG,"Error opening bindpw from %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				bindpw=malloc(LEN);
				if(!bindpw) {
					if (debug) syslog(LOG_DEBUG,"Not enough memory to create bindpw buffer: %s\n", strerror(errno));
					fclose(bindpwfile);
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				memset(bindpw, 0, LEN);
				if(!fgets(bindpw, LEN, bindpwfile)) {
					if (debug) syslog(LOG_DEBUG,"Error reading bindpw from %s: %s\n", optarg, strerror(errno));
					fclose(bindpwfile);
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				fclose(bindpwfile);
				if (debug) syslog(LOG_DEBUG, "got a bind password from a file\n");
				gotpass=1;
				break;
			case 'b':
				if (debug) syslog(LOG_DEBUG, "parsing ldap base\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				base=strndup(optarg, LEN-1);
				if(!base) {
					if (debug) syslog(LOG_DEBUG,"Error reading base %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				if (debug) syslog(LOG_DEBUG, "got an ldap base: %s\n", base);
				gotbase=1;
				break;
			case 'l':
				if (debug) syslog(LOG_DEBUG, "parsing ldap server list\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				ldapservers=strndup(optarg, LEN-1);
				if(!ldapservers) {
					if (debug) syslog(LOG_DEBUG,"Error reading ldapservers %s: %s\n", optarg, strerror(errno));
					return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				if (debug) syslog(LOG_DEBUG, "got an ldap serverlist: [ %s ]\n", ldapservers);
				gotservers=1;
				break;
			case 'x':
				if (debug) syslog(LOG_DEBUG, "parsing user check exclusions file\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				if (debug) syslog(LOG_DEBUG, "checking user check exclusions\n");
				if(check_exceptions(optarg, username) ) {
					return free_and_return(PAM_SUCCESS, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				}
				if (debug) syslog(LOG_DEBUG, "user not excluded from hbac\n");
				break;
			case 'D':
				if (debug) syslog(LOG_DEBUG, "parsing domain\n");
				if(dangerous_str(optarg)) return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
				domain=strndup(optarg, LEN-1);
				if (debug) syslog(LOG_DEBUG, "got a domain: %s\n", domain);
				break;
		}
	}

	if(strchr(thishost,'.')) {
		fqdn=strndup(thishost, LEN-1);
	} else {
		fqdn=(char*)malloc(strlen(thishost)+strlen(domain)+2);
		retval = snprintf(fqdn, LEN-1, "%s.%s", thishost, domain);
	}
	if (debug) syslog(LOG_DEBUG, "fqdn host: %s\n", fqdn);

	if( ! (gotuser && gotpass && gotbase && gotservers ) ) {
		syslog(LOG_AUTH|LOG_ERR,"ERROR: missing -u, -p/P, -b or -l parameters (%d,%d,%d,%d). Please RTFM.\n", gotuser, gotpass, gotbase, gotservers);
		return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
	}

	if (debug) syslog(LOG_DEBUG, "generating ldap bind dn\n", fqdn);
	if( 0 > snprintf(sysaccount, LEN-1, "uid=%s,cn=sysaccounts,cn=etc,%s", binduser, base) ) {
		syslog(LOG_ERR,"ERROR: failure defining the sysaccount for %s in %s\n", binduser, base);
		return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
	}
	syslog(LOG_DEBUG, "bind dn: %s\n", sysaccount);

	if(debug) {
/*
		printf("Hostname: %s\n", thishost);
		printf("Binduser: %s\n", sysaccount);
		//printf("Bindpw: %s\n", bindpw);
		printf("Base: %s\n", base);
		printf("LDAP Servers: %s\n", ldapservers);
		printf("ipa_check_hbac(%s, %s, %s, %s, %s, %s, %s, %s)\n", ldapservers, base, sysaccount, bindpw, fqdn, svcname, username, keydb);
*/
		syslog(LOG_DEBUG, "ipa_check_hbac(%s, %s, %s, %s, %s, %s, %s)\n", ldapservers, base, sysaccount, fqdn, svcname, username, keydb);
	}

	if ( (retval = ipa_check_hbac(ldapservers, base, sysaccount, bindpw, fqdn, svcname, username, keydb)) > 0 ) {
		syslog(LOG_AUTH|LOG_INFO, "%d = ipa_check_hbac(%s, %s, %s, %s, %s, %s, %s)\n", retval, ldapservers, base, sysaccount, fqdn, svcname, username, keydb);
		return free_and_return(PAM_SUCCESS, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
	} else {
		syslog(LOG_AUTH|LOG_WARNING, "user unauthorized: %s had no valid HBAC rule for this host\n", username);
		return free_and_return(PAM_PERM_DENIED, binduser, bindpw, fqdn, domain, base, ldapservers, keydb);
	}
}
