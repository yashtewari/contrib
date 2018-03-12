package engine

//#cgo LDFLAGS: -lpam -fPIC
//#include <security/pam_appl.h>
import "C"
import (
	"net/http"

	"github.com/pkg/errors"
)

// Input to the OPA policy
type AuthzPolicyInput struct {
	Input struct {
		DisplayResponses `json:"display_responses"`
		PullResponses    `json:"pull_responses"`
	} `json:"input"`
}

func NewAuthzPolicyInput(display DisplayResponses, pull PullResponses) *AuthzPolicyInput {
	ret := AuthzPolicyInput{}
	ret.Input.DisplayResponses = display
	ret.Input.PullResponses = pull

	return &ret
}

// The response from OPA is expected to have these fields.
// In other words, the policy should bind data to 'allow' and 'errors'
type AuthzPolicyResult struct {
	Allow  bool     `json:"allow"`
	Errors []string `json:"errors"`
}

// AuthzResult is the result of an authorization request.
type AuthzResult C.int

const (
	// AuthzError is a failure.
	AuthzError AuthzResult = C.PAM_AUTH_ERR
	// AuthzSuccess is a success.
	AuthzSuccess = C.PAM_SUCCESS
)

// Authorize calls the policy engine with input to determine if the user should be authorized,
// based on the info provided by the user and pulled from the system.
func (e Engine) Authorize(input *AuthzPolicyInput) (AuthzResult, error) {
	if e.URL == "" {
		return AuthzError, errors.New("OPA server url not known")
	}
	if e.AuthzEndpoint == "" {
		return AuthzError, errors.New("authz policy endpoint not known")
	}

	var engResp struct {
		Result AuthzPolicyResult `json:"result"`
	}

	status, err := e.call(http.MethodPost, e.AuthzEndpoint, nil, map[string]string{"Content-Type": "application/json"}, input, &engResp)
	if err != nil {
		return AuthzError, errors.Wrapf(err, "error calling policy engine %s endpoint %s", e.URL, e.AuthzEndpoint)
	}

	if status != http.StatusOK {
		return AuthzError, errors.Errorf("unexpected response status %d from policy engine %s endpoint %s", status, e.URL, e.AuthzEndpoint)
	}

	if engResp.Result.Allow {
		return AuthzSuccess, nil
	} else if len(engResp.Result.Errors) > 0 {
		return AuthzError, errors.Errorf("errors received from the policy engine: %s", engResp.Result.Errors)
	}

	return AuthzError, nil
}
