// +build darwin linux

package main

import (
	"unsafe"

	"github.com/open-policy-agent/contrib/pam_authz/pam/engine"
)

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <stdlib.h>

// disable_ptrace attempts to turn tracing off;
// core dumps cannot be produced.
int disable_ptrace();

// string_from_argv copies the string at argv index i into
// a new memory block and returns a pointer to it.
//
// The returned value must be freed by the caller.
char *string_from_argv(int i, char **argv);




char *get_pam_item_string2(pam_handle_t *pamh, int item_type);

*/
import "C"

// REMOVE THIS GARBAGE
import (
	"fmt"
	// "time"
)

func init() {
	// Try to disable ptrace.
	// if C.disable_ptrace() != C.int(0) {
	// 	log(logLevelError, "unable to disable ptrace")
	// }
}

// sliceFromArgv returns a slice constructed from C-style argc, argv.
func sliceFromArgv(argc C.int, argv **C.char) []string {
	r := make([]string, 0, argc)
	for i := 0; i < int(argc); i++ {
		s := C.string_from_argv(C.int(i), argv)
		defer C.free(unsafe.Pointer(s))

		r = append(r, C.GoString(s))
	}
	return r
}

// pam_sm_authenticate is the PAM modeule's authenticate function, called by a PAM application.
//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {

	log(logLevelError, "pam_sm_authenticate called")
	// return C.PAM_SUCCESS
	// _, err := http.Get("https://www.google.com")
	// log(logLevelError, "HTTP IN PAM HUA %+v", err)

	item := C.get_pam_item_string2((*C.pam_handle_t)(pamh), C.PAM_SERVICE)
	if item != nil {
		defer C.free(unsafe.Pointer(item))
	}
	itemSTR := C.GoString(item)
	log(logLevelError, "ITEM %s", itemSTR)
	// if itemSTR != "sudo" {
	// 	time.Sleep(20 * time.Second)
	// }

	//
	//
	//
	// ABOVE IS BS

	initialize(sliceFromArgv(argc, argv))

	fmt.Println("WHO")
	eng := engine.New(
		policyEngineURL,
		displayEndpoint,
		pullEndpoint,
		authzEndpoint,
	)

	log(logLevelError, "fetching display policy")
	display, errs := eng.Display(unsafe.Pointer(pamh))
	if len(errs) > 0 {
		for _, e := range errs {
			log(logLevelError, e.Error())
		}
	}

	log(logLevelError, "fetching pull policy")
	pull, errs := eng.Pull(unsafe.Pointer(pamh))
	if len(errs) > 0 {
		for _, e := range errs {
			log(logLevelError, e.Error())
		}
	}

	fmt.Println("LET")

	log(logLevelError, "fetching authz policy")
	authz, err := eng.Authorize(engine.NewAuthzPolicyInput(display, pull))
	if err != nil {
		log(logLevelError, err.Error())
	}

	return C.int(authz)

	// fmt.Println(display)

	// return C.PAM_SUCCESS

}

// pam_sm_acct_mgmt is the PAM module's authorization function, called by a PAM application.
//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	log(logLevelInfo, "pam_sm_acct_mgmt called")

	// Currently this module performs the same operation for both
	// authn (PAM: auth) and authz (PAM: account) calls.
	// pam_sm_authenticate(pamh, flags, argc, argv)
	return pam_sm_authenticate(pamh, flags, argc, argv)

	// return C.PAM_SUCCESS
}

// pam_sm_setcred is
//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	log(logLevelInfo, "pam_sm_setcred called")

	return C.PAM_SUCCESS
}

//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	log(logLevelInfo, "pam_sm_open_session called")
	return C.PAM_SUCCESS
}

//export pam_sm_close_session
func pam_sm_close_session(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	log(logLevelInfo, "pam_sm_close_session called")

	return C.PAM_SUCCESS
}
