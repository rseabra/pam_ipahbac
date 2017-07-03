#include <stdio.h>

#include <security/pam_appl.h>

#define ME "ipahbac_test"

#ifdef GNULINUX_BUILD
#include <security/pam_misc.h>

const struct pam_conv conv = {
	misc_conv,
	NULL
};

#else
const struct pam_conv conv = {
	NULL,
	NULL
};

#endif


int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;
	const char* user = "nobody";

	if(argc != 2) {
		printf("Usage: %s [username]\n", argv[0]);
		return 1;
	}

	user = argv[1];

	retval = pam_start(ME, user, &conv, &pamh);

	if (retval == PAM_SUCCESS) {
		retval = pam_acct_mgmt(pamh, 0);
	}

	// Can the accound be used at this time?
	if (retval != PAM_SUCCESS) {
		printf("Access denied.\n");
		return 1;
	}
	printf("Access allowed.\n");

	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("%s: failed to release authenticator\n", ME);
		return 1;
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}
