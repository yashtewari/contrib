#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <curl/curl.h>


char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *message);
// int get_url(const char* url_ptr);


// PAM FUNCTIONS

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	char* secret_ptr = call_pam_conv(pamh, PAM_PROMPT_ECHO_ON, "What be thine secret? ");

	if (secret_ptr != NULL)
		free(secret_ptr);

	return PAM_SUCCESS;

	// printf(">>>> Preparing to make HTTP call.");
	// int http_resp_code = get_url("http://opa:8181");
	// printf(">>>> HTTP call has completed with code %d", http_resp_code);

	// return PAM_SUCCESS;
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

static int get_url(const char* url_ptr) {
	// printf("Start stuff\n");

	CURL* curl_handle = curl_easy_init();

	if (!curl_handle) {
		return 0;
	}

	// TEST-start
	curl_easy_cleanup(curl_handle);
	// TEST-end

	// curl_easy_setopt(curl_handle, CURLOPT_URL, url_ptr);
	// curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	// curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1);
	// // we don't want to leave our user waiting at the login prompt forever
	// curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 1);

	// // synchronous, but we don't really care
	int http_resp_code = -1;
	// http_resp_code = curl_easy_perform(curl_handle);

	// curl_easy_cleanup(curl_handle);

	// printf(">>>> Response received from HTTP call: %d\n", http_resp_code);

	return http_resp_code;
}