#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <curl/curl.h>

#include <jansson.h>

char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *message);
static int get_url(const char* url_ptr);
int do_display(pam_handle_t *pamh, char *url);
int do_authz(const char *url);


// struct display_response holds the input entered by the user for a prompt,
// along with the key associated with that prompt.
struct display_response {
	char *key;
	char *input;
};

// PAM FUNCTIONS

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int http_resp_code = do_display(pamh, "http://opa:8181/v1/data/common/display");
	

	return do_authz("http://opa:8181/v1/data/common/authz");
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}


char GET[] = "GET";
char POST[] = "POST";

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

/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
      /* free buffer */
      free(p->payload);
      /* return */
      return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

static int http_request(const char * method, const char* url, char *req_body, char **resp_body) {
	CURL* curl_handle = curl_easy_init();

	if (!curl_handle) {
		return 0;
	}

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 5); // Set a 5 second timeout.

	// Set up the data object which will be populated by the callback.
	struct curl_fetch_st resp_data;
	resp_data.payload = (char *) malloc(1); // This will be realloced by libcurl.
	resp_data.size = 0;                     // Start with an empty payload.

	// Set headers.
	struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json"); // The request body is JSON.
	headers = curl_slist_append(headers, "Accept: application/json");       // The response body can be JSON.

	// Set the request body JSON.
	// This has the side effect of setting request headers to default, undesired values.
	// Ensure that proper headers are set afterwards.
	if (req_body != NULL) {
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, req_body);
	}

	// Specify that the data should be written to our object.
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&resp_data);

	// Specify that our callback should be used to write the data.
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_callback);

	// Perform a synchronous request.
	CURLcode resp_code = curl_easy_perform(curl_handle);
	if (resp_code != CURLE_OK) {
		fprintf(stderr, "HTTP request failed: %s\n", curl_easy_strerror(resp_code));
	}

	// Clean up request objects.
	if (req_body != NULL) { // Caller expects req_body to be freed.
		free(req_body);
	}
	curl_easy_cleanup(curl_handle); // Clean up curl objects.
	curl_slist_free_all(headers);	// Clean up headers.

	fprintf(stderr, ">>>> Response received from HTTP call: %d\n", resp_code);
	fprintf(stderr, ">>>> Data received from HTTP call: %s\n", resp_data.payload);

	if (resp_body != NULL) {
		*resp_body = resp_data.payload;
	}

	return resp_code;
}

static int json_error_ret(json_t *json_root, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Publish to standard error.
    vfprintf(stderr, fmt, args);

    // Free up JSON object memory.
	json_decref(json_root);

	return 1;
}

int do_display(pam_handle_t *pamh, char *url) {
	char *resp_body;
	http_request(GET, url, NULL, &resp_body);


	// Define object to store JSON errors in.
	json_error_t error;
	json_t *root = json_loads(resp_body, 0, &error);

	// The response data is not needed anymore.
	free(resp_body);

	if (!root) {
	    fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
	    return 1;
	}

	if (!json_is_object(root)) {
		return json_error_ret(root, "top level value of JSON response recieved is not type object");
	}

	json_t *result = json_object_get(root, "result");
	if (!json_is_object(result)) {
		return json_error_ret(root, "value of field 'result' does not have type object in JSON response");
	}

	json_t *display_spec = json_object_get(result, "display_spec");
	if (!json_is_array(display_spec)) {
		return json_error_ret(root, "value of field 'display_spec' does not have type array in JSON response");
	}

	int i;
	for (i = 0; i < json_array_size(display_spec); i++) {
		json_t *display_spec_elem, *message, *style, *key;

		display_spec_elem = json_array_get(display_spec, i);
		if (!json_is_object(display_spec_elem)) {
			return json_error_ret(root, "value of %dth element in 'display_spec' does not have type object in JSON response", i);
		}

		message = json_object_get(display_spec_elem, "message");
		if (!json_is_string(message)) {
			return json_error_ret(root, "value of 'message' in %dth element of 'display_spec' does not have type string in JSON response", i);
		}

		style = json_object_get(display_spec_elem, "style");
		if (!json_is_string(style)) {
			return json_error_ret(root, "value of 'style' in %dth element of 'display_spec' does not have type string in JSON response", i);
		}

		if (strcmp(json_string_value(style), "prompt_echo_on") == 0 || strcmp(json_string_value(style), "prompt_echo_off") == 0) {
			key = json_object_get(display_spec_elem, "key");
			if (!json_is_string(key)) {
				return json_error_ret(root, "value of 'key' in %dth element of 'display_spec' does not have type string in JSON response", i);
			}
		}

		fprintf(stderr, ">>>> Received message %s of type %s and key %s\n", json_string_value(message), json_string_value(style), json_string_value(key));
		char* user_resp = call_pam_conv(pamh, PAM_PROMPT_ECHO_ON, (char *)json_string_value(message));
		fprintf(stderr, ">>>> User response received: %s\n", user_resp);
	}

	json_decref(root); // Clean up.

	return 0;
}

int do_authz(const char *url) {
	json_t *req_body = json_object(), *input = json_object(), *display_responses = json_object();

	if (!json_object_set_new(display_responses, "user", json_string("yash"))) {
		fprintf(stderr, "%s\n", "could not set display_responses 'user' to 'yash'");
	}

	if (!json_object_set_new(display_responses, "secret", json_string("42"))) {
		fprintf(stderr, "%s\n", "could not set display_responses 'secret' to '42'");
	}

	if (!json_object_set_new(input, "display_responses", display_responses)) {
		fprintf(stderr, "%s\n", "could not set input 'display_responses'");
	}

	if (!json_object_set_new(req_body, "input", input)) {
		fprintf(stderr, "%s\n", "could not set req_body 'input'");
	}

	fprintf(stderr, ">>>> Sending JSON request%s\n", json_dumps(req_body, JSON_COMPACT));

	char *resp_body;
	http_request(POST, url, json_dumps(req_body, JSON_COMPACT), &resp_body);

	fprintf(stderr, ">>>> Received authz response: %s\n", resp_body);

	return PAM_SUCCESS;
}