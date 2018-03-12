package engine

/*
#include <security/pam_appl.h>
#include <stdlib.h>

// get_pam_item_string pulls the item_type out of the pam handle.
// item_type must be associated with a pam handle item that is a string,
// such as PAM_USER, PAM_SERVICE, PAM_RHOST etc.
//
// The returned value must be freed by the caller.
char *get_pam_item_string(pam_handle_t *pamh, int item_type);
*/
import "C"
import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"unsafe"

	"github.com/pkg/errors"
)

// FilePath is the path to a file.
// Only absolute paths are guaranteed to work.
type FilePath string

// EnvVar is the name of an environment variable.
type EnvVar string

// Sysinfo is a kind of system information.
type Sysinfo string

// Known Sysinfo values.
// These can be used in OPA to specify information desired.
const (
	SysinfoService            Sysinfo = "service"      // The PAM service.
	SysinfoUsername                   = "username"     // The user being authenticated.
	SysinfoRequestingUsername         = "req_username" // The user making the request.
	SysinfoRequestingHostname         = "req_hostname" // The host making the request.

	// Add more Sysinfo kinds here.
)

var (
	// PAMModuleDefaults are Sysinfo values that are always retrieved from
	// the PAM handle in a call to Pull().
	// PAMModuleDefaults should never refer to PAM items that cannot be represented as a string.
	PAMModuleDefaults = map[Sysinfo]C.int{
		SysinfoService:            C.PAM_SERVICE,
		SysinfoUsername:           C.PAM_USER,
		SysinfoRequestingUsername: C.PAM_RUSER,
		SysinfoRequestingHostname: C.PAM_RHOST,
	}
)

// PullPolicyResult is the expected format of the pull specification,
// i.e, the host information requested by the policy engine.
type PullPolicyResult struct {
	Files   []FilePath `json:"files"`    // JSON files to load from the host.
	EnvVars []EnvVar   `json:"env_vars"` // Environment names to load from the host.
	SysInfo []Sysinfo  `json:"sys_info"` // System information to load from the host.
}

// PullResponses stores the host info requested by the policy engine.
type PullResponses struct {
	Files   map[FilePath]interface{} `json:"files"`
	EnvVars map[EnvVar]string        `json:"env_vars"`
	SysInfo map[Sysinfo]string       `json:"sys_info"`
}

// Pull calls the policy engine to determine what information the engine
// wants to pull from the PAM module's host system. It retrieves the requested
// information where possible and returns it.
func (e Engine) Pull(pamh unsafe.Pointer) (PullResponses, []error) {
	pr, errs := PullResponses{}, []error{}

	if e.URL == "" {
		errs = append(errs, errors.New("OPA server url not known"))
		return pr, errs
	}
	if e.PullEndpoint == "" {
		errs = append(errs, errors.New("pull policy endpoint not known"))
		return pr, errs
	}

	var engResp struct {
		Result PullPolicyResult `json:"result"`
	}

	status, err := e.call(http.MethodGet, e.PullEndpoint, nil, nil, nil, &engResp)
	if err != nil {
		errs = append(errs, errors.Wrapf(err, "error calling policy engine %s endpoint %s", e.URL, e.PullEndpoint))
		return pr, errs
	}

	if status != http.StatusOK {
		errs = append(errs, errors.Wrapf(err, "unexpected response status %d from poplicy engine %s endpoint %s", status, e.URL, e.PullEndpoint))
		return pr, errs
	}

	// Load JSON file data from host.
	pr.Files = make(map[FilePath]interface{})
	for _, f := range engResp.Result.Files {
		if _, ok := pr.Files[f]; ok {
			// Skip if done already.
			continue
		}

		// Ensure empty entry for this file despite errors.
		pr.Files[f] = nil

		raw, err := ioutil.ReadFile(string(f))
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "error reading file: %s", f))
			continue
		}

		var i interface{}
		err = json.Unmarshal(raw, &i)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "error decoding file %s into JSON", f))
			continue
		}

		pr.Files[f] = i
	}

	// Load environment variables from host.
	pr.EnvVars = make(map[EnvVar]string)
	for _, e := range engResp.Result.EnvVars {
		pr.EnvVars[e] = os.Getenv(string(e))
	}

	// Load system information.
	pr.SysInfo = make(map[Sysinfo]string)

	// Add PAM module defaults.
	for key, itype := range PAMModuleDefaults {
		item := C.get_pam_item_string((*C.pam_handle_t)(pamh), itype)
		if item != nil {
			defer C.free(unsafe.Pointer(item))
		}

		pr.SysInfo[key] = C.GoString(item)
	}

	return pr, errs
}
