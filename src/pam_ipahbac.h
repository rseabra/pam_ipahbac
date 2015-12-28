#ifndef _PAM_IPAHBAC_H
# define _PAM_IPAHBAC_H

// shutup some idiot warnings from -Wall ;)
extern char ** ldap_get_values( LDAP *ld, LDAPMessage *entry, char *attrs );
extern int ldap_bind_s(LDAP *ld, const char *who, const char *cred, int method);
extern int ldap_unbind_s(LDAP *ld);

# define LEN 256

#endif
