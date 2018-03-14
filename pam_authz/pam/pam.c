#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>


char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *message);


// PAM FUNCTIONS

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	char* secret_ptr = call_pam_conv(pamh, PAM_PROMPT_ECHO_ON, "What be thine secret? ");

	if (secret_ptr != NULL)
		free(secret_ptr);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}
































// UTILITY

struct pam_conv *get_pam_conv(pam_handle_t *pamh) {
	
	if (!pamh)
	return NULL;

	struct pam_conv *conv;
	if (pam_get_item(pamh, PAM_CONV, (const void**)&conv) != PAM_SUCCESS)
		return NULL;

	return conv;
}

char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *message) {
	// conv is always called with parameter num_msg == 1 as a way to
	// make it compatible with both Linux-PAM and Solaris' PAM,
	// see https://linux.die.net/man/3/pam_conv
	int num_msg = 1;

	fprintf(stderr, "%s\n", "sahi");

	// Create a struct pam_message array and populate it with a single object.
	// struct pam_message **msg = (struct pam_message**) malloc(sizeof(struct pam_message));
	// msg[0] = (struct pam_message*) malloc(sizeof(struct pam_message));
	// msg[0]->msg_style = msg_style;
	// msg[0]->msg = message;

	struct pam_message *msg_array = (struct pam_message *)(malloc(sizeof(struct pam_message)));
	msg_array[0].msg_style = msg_style;
	msg_array[0].msg = message;

	fprintf(stderr, "%s\n", "hai");

	// Create a struct pam_response array.
	struct pam_response *resp_array = NULL;

	struct pam_conv *obj = get_pam_conv(pamh);
	if (obj == NULL)
		return NULL;

	fprintf(stderr, "%s\n", "got the thing");

	if (obj->conv(num_msg, (const struct pam_message **)&msg_array, &resp_array, obj->appdata_ptr) != PAM_SUCCESS)
		return NULL;

	fprintf(stderr, "%s\n", "called the thing");

	char *resp = NULL;
	if (resp_array[0].resp != NULL) {
		resp = strdup(resp_array[0].resp);
		free((resp_array[0].resp));
	}

	fprintf(stderr, "%s\n", "boss");

	free(resp_array);
	free(msg_array);
	// free(msg[0]);
	// free(msg);

	return resp;
}