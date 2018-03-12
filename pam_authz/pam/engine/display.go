package engine

/*
#include <security/pam_appl.h>
#include <stdlib.h>

// get_pam_conv pulls the associated struct pam_conv out of the pam handle.
//
// The returned value must be NOT freed by the caller.
struct pam_conv *get_pam_conv(pam_handle_t *pamh);

// call_pam_conv calls the function conv from the given pam handle's struct pam_conv.
// When applicable, the response from the user is returned.
// In case of error or when no response is expected, NULL is returned.
//
// The returned value must be freed by the caller.
char *call_pam_conv(pam_handle_t *pamh, int msg_style, char *msg);



char *get_pam_item_string(pam_handle_t *pamh, int item_type);
*/
import "C"
import (
	"net/http"
	// "runtime"
	"unsafe"

	"github.com/pkg/errors"
)

// DisplayStyle signifies how to display the given prompt on the user's screen.
type DisplayStyle string

const (
	// DisplayStyleEchoOn signifies that user input is required, and should be displayed on the screen.
	DisplayStylePromptEchoOn DisplayStyle = "prompt_echo_on"
	// DisplayStyleEchoOff signifies that sensitive user input is required, and should not be displayed on the screen.
	DisplayStylePromptEchoOff = "prompt_echo_off"
	// DisplayStyleErrorMessage signifies that the string should be displayed as an error message.
	DisplayStyleErrorMessage = "error"
	// PromptSyleTextInfo signifies that the string should simply be displayed.
	DisplayStyleTextInfo = "info"
)

// promptStyleC ties OPA display-style strings to equivalent C constants.
var DisplayStyleC = map[DisplayStyle]C.int{
	DisplayStylePromptEchoOn:  C.PAM_PROMPT_ECHO_ON,
	DisplayStylePromptEchoOff: C.PAM_PROMPT_ECHO_OFF,
	DisplayStyleErrorMessage:  C.PAM_ERROR_MSG,
	DisplayStyleTextInfo:      C.PAM_TEXT_INFO,
}

// DisplayItem signifies a single message to display on the screen.
// It contains details about how to display it and how to store user responses, where applicable.
type DisplayItem struct {
	// Message is the message to display.
	Message string       `json:"message"`
	Style   DisplayStyle `json:"style"`
	// Key is the key that the response to this message should be tied to.
	// Should only be non-empty when Style is DisplayStylePromptEchoOn or DisplayStylePromptEchoOff.
	Key string `json:"key"`
}

// DisplayPolicyResult is the expected format of the display specification in the policy engine.
type DisplayPolicyResult struct {
	DisplaySpec []DisplayItem `json:"display_spec"`
}

// DisplayResponses stores the user's responses to each prompt displayed,
// keyed by the key specified by the policy engine.
type DisplayResponses map[string]string

// DisplaySpec retrieves a list DisplayItems describing what to display to the user.
// It displays messages to the user as directed, and records the user responses and returns them.
func (e Engine) Display(pamh unsafe.Pointer) (DisplayResponses, []error) {
	// runtime.GOMAXPROCS(1_, err := http.Get("https://www.google.com")
	// log(logLevelError, "Calling GOOGLE")
	// _, err := http.Get("https://www.google.com")
	// log(logLevelError, "HTTP OUT PAM HUA %+v", err)

	item := C.get_pam_item_string((*C.pam_handle_t)(pamh), C.PAM_SERVICE)
	if item != nil {
		defer C.free(unsafe.Pointer(item))
	}
	itemSTR := C.GoString(item)
	log(logLevelError, "ITEM %s", itemSTR)
	if itemSTR == "sshd" {
		// panic("see this?")
	}

	errs := []error{}

	log(logLevelError, "1")

	if e.URL == "" {
		errs = append(errs, errors.New("OPA server url not known"))
		return nil, errs
	}
	if e.DisplayEndpoint == "" {
		errs = append(errs, errors.New("display policy endpoint not known"))
		return nil, errs
	}

	var engresp struct {
		Result DisplayPolicyResult `json:"result"`
	}
	log(logLevelError, "2")

	status, err := e.call(http.MethodGet, e.DisplayEndpoint, nil, nil, nil, &engresp)
	if err != nil {
		errs = append(errs, errors.Wrapf(err, "error calling policy engine %s endpoint %s", e.URL, e.DisplayEndpoint))
		return nil, errs
	}
	log(logLevelError, "3")

	if status != http.StatusOK {
		errs = append(errs, errors.Errorf("unexpected response status %d from policy engine %s endpoint %s", status, e.URL, e.DisplayEndpoint))
		return nil, errs
	}
	log(logLevelError, "4")

	// Display messages to the user as directed by policy engine.
	dresp := DisplayResponses{}
	for _, d := range engresp.Result.DisplaySpec {
		log(logLevelError, "5 %d", d)
		if cstyle, ok := DisplayStyleC[d.Style]; !ok {
			errs = append(errs, errors.Errorf("unexpected display style %s received from policy engine", d.Style))
		} else {
			resp := C.call_pam_conv((*C.pam_handle_t)(pamh), cstyle, C.CString(d.Message))
			defer C.free(unsafe.Pointer(resp))

			// Collect user reponse if it is expected.
			if d.Style == DisplayStylePromptEchoOff || d.Style == DisplayStylePromptEchoOn {
				if _, ok := dresp[d.Key]; ok {
					errs = append(errs, errors.Errorf("key %s occurs more than once in the display spec received from policy engine", d.Key))
				}

				dresp[d.Key] = C.GoString(resp)
			}
		}
	}

	return dresp, errs
}
