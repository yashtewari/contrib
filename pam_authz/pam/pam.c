#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <curl/curl.h>

#include <jansson.h>

#define DISPLAY_STYLE_CT 4

// struct display_response holds the input entered by the user for a prompt,
// along with the key associated with that prompt.
struct display_response {
	const char *key;
	const char *input;
};

// struct display_responses holds an array of struct display_response,
// along with the the size of said array.
struct display_responses {
	int count;
	struct display_response *responses;
};

static const int DISPLAY_STYLE_INVALID = -1;

// Diplay constants.
static const char DISPLAY_STYLE_PROMPT_ECHO_ON[]  = "prompt_echo_on";
static const char DISPLAY_STYLE_PROMPT_ECHO_OFF[] = "prompt_echo_off";
static const char DISPLAY_STYLE_TEXT_INFO[]       = "info";
static const char DISPLAY_STYLE_ERROR_MSG[]       = "error";


struct display_style_to_pam_int {
	const char *style;
	const int pam_int;
} DISPLAY_STYLE_TO_PAM_INT[DISPLAY_STYLE_CT] = {
	{DISPLAY_STYLE_PROMPT_ECHO_ON, PAM_PROMPT_ECHO_ON},
	{DISPLAY_STYLE_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_OFF},
	{DISPLAY_STYLE_ERROR_MSG, PAM_ERROR_MSG},
	{DISPLAY_STYLE_TEXT_INFO, PAM_TEXT_INFO},
};

int pam_int_for_display_style(const char *style) {
	int i;
	for (i = 0; i < DISPLAY_STYLE_CT; i++) {
		fprintf(stderr, ">>>> Style resolver: comparing %s to %s\n", DISPLAY_STYLE_TO_PAM_INT[i].style, style);

		if (strcmp(DISPLAY_STYLE_TO_PAM_INT[i].style, style) == 0) {
			return DISPLAY_STYLE_TO_PAM_INT[i].pam_int;
		}
	}

	return DISPLAY_STYLE_INVALID;
}

char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *message);
static int get_url(const char* url_ptr);
int do_display(pam_handle_t *pamh, char *url, struct display_responses *display_responses_ptr);
int do_authz(const char *url, struct display_responses display_responses);

// PAM FUNCTIONS

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	struct display_responses display_responses;

	do_display(pamh, "http://opa:8181/v1/data/common/display", &display_responses);
	int authz = do_authz("http://opa:8181/v1/data/common/authz", display_responses);

	free(display_responses.responses);

	return authz;
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

	int conv_resp = obj->conv(num_msg, (const struct pam_message **)&msg_array, &resp_array, obj->appdata_ptr);
	if (conv_resp != PAM_SUCCESS) {
		fprintf(stderr, "recieved error from pam_conv: %s\n", pam_strerror(pamh, conv_resp));
		return NULL;
	}

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

static int json_error_ret(json_t *root_j, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Publish to standard error.
    vfprintf(stderr, fmt, args);

    // Free up JSON object memory.
	json_decref(root_j);

	return 1;
}

// TODO: don't always return on error. Accept an errors object and populate it.
int do_display(pam_handle_t *pamh, char *url, struct display_responses *display_responses_ptr) {
	// Initialize empty responses, then fill it up as the user responses come in.
	display_responses_ptr->count = 0;
	// An empty malloc here allows calling free() later without having to check anything.
	display_responses_ptr->responses = (struct display_response *)malloc(0);

	char *resp_body;
	http_request(GET, url, NULL, &resp_body);

	// Define object to store JSON errors in.
	json_error_t error;
	json_t *root_j = json_loads(resp_body, 0, &error);

	// The response data is not needed anymore.
	free(resp_body);

	if (!root_j) {
	    fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
	    return 1;
	}

	if (!json_is_object(root_j)) {
		return json_error_ret(root_j, "top level value of JSON response recieved is not type object");
	}

	json_t *result_j = json_object_get(root_j, "result");
	if (!json_is_object(result_j)) {
		return json_error_ret(root_j, "value of field 'result' does not have type object in JSON response");
	}

	json_t *display_spec_j = json_object_get(result_j, "display_spec");
	if (!json_is_array(display_spec_j)) {
		return json_error_ret(root_j, "value of field 'display_spec' does not have type array in JSON response");
	}

	int i;
	for (i = 0; i < json_array_size(display_spec_j); i++) {
		json_t *display_spec_elem_j, *message_j, *style_j, *key_j;

		display_spec_elem_j = json_array_get(display_spec_j, i);
		if (!json_is_object(display_spec_elem_j)) {
			return json_error_ret(root_j, "value of %dth element in 'display_spec' does not have type object in JSON response", i);
		}

		message_j = json_object_get(display_spec_elem_j, "message");
		if (!json_is_string(message_j)) {
			return json_error_ret(root_j, "value of 'message' in %dth element of 'display_spec' does not have type string in JSON response", i);
		}

		style_j = json_object_get(display_spec_elem_j, "style");
		if (!json_is_string(style_j)) {
			return json_error_ret(root_j, "value of 'style' in %dth element of 'display_spec' does not have type string in JSON response", i);
		}

		fprintf(stderr, ">>>> Received message %s of type %s\n", json_string_value(message_j), json_string_value(style_j));

		int pam_style = pam_int_for_display_style(json_string_value(style_j));

		fprintf(stderr, ">>>> Calling pam_conv with type %d\n", pam_style);		
		char* user_resp = call_pam_conv(pamh, pam_style, (char *)json_string_value(message_j));

		fprintf(stderr, ">>>> Received user input: %s\n", user_resp);

		if (pam_style == PAM_PROMPT_ECHO_ON || pam_style == PAM_PROMPT_ECHO_OFF) {
			key_j = json_object_get(display_spec_elem_j, "key");
			if (!json_is_string(key_j)) {
				return json_error_ret(root_j, "value of 'key' in %dth element of 'display_spec' does not have type string in JSON response", i);
			}

			// Extend the responses array.
			fprintf(stderr, ">>>> Current response count: %d\n", display_responses_ptr->count);

			display_responses_ptr->responses = (struct display_response *)realloc(display_responses_ptr->responses, ((display_responses_ptr->count)+1) * sizeof(struct display_response));
			if (display_responses_ptr->responses == NULL) {
				fprintf(stderr, "FAILED to REALLOC responses array!%s\n");
			}

			display_responses_ptr->responses[display_responses_ptr->count].key = json_string_value(key_j);
			display_responses_ptr->responses[display_responses_ptr->count].input = user_resp;

			display_responses_ptr->count++;

			fprintf(stderr, ">>>> Desired key %s input %s\n", json_string_value(key_j), user_resp);
			fprintf(stderr, ">>>> Actual key %s input %s count %d\n", display_responses_ptr->responses[0].key, display_responses_ptr->responses[0].input, display_responses_ptr->count);
		}
	}

	json_decref(root_j); // Clean up.

	return 0;
}

int do_authz(const char *url, struct display_responses display_responses) {
	json_t *req_body_j = json_object(), *input_j = json_object(), *display_responses_j = json_object();

	int i;
	for (i = 0; i < display_responses.count; i++) {
		// Try to add user's response values by specified key to the object.
		if (json_object_set_new(
			display_responses_j,
			display_responses.responses[i].key,
			json_string(display_responses.responses[i].input))) {

			fprintf(
				stderr,
				"could not set display_responses '%s' to '%s'",
				display_responses.responses[i].key,
				display_responses.responses[i].input);
		}
	}

	if (json_object_set_new(input_j, "display_responses", display_responses_j)) {
		fprintf(stderr, "%s\n", "could not set input 'display_responses'");
	}

	if (json_object_set_new(req_body_j, "input", input_j)) {
		fprintf(stderr, "%s\n", "could not set req_body 'input'");
	}

	fprintf(stderr, ">>>> Sending JSON request%s\n", json_dumps(req_body_j, JSON_COMPACT));

	char *resp_body;
	http_request(POST, url, json_dumps(req_body_j, JSON_COMPACT), &resp_body);

	fprintf(stderr, ">>>> Received authz response: %s\n", resp_body);

	// Only the top level JSON object needs to be cleaned up, because all other
	// objects should be added to it via stealing functions.
	json_decref(req_body_j);

	return PAM_SUCCESS;
}