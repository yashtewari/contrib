package main

import (
	// "runtime"
	"strings"
)

var (
	// policyEngineURL is the address OPA is running on.
	policyEngineURL = "http://localhost:8181" // default value.

	// Endpoints of policy engine packages that determine what the PAM module should do.

	// Packages that determine input.
	displayEndpoint = "" // Package at displayEndpoint determines what to display/prompt the user.
	pullEndpoint    = "" // Package at pullEndpoint determines what to pull from the PAM module's host system.

	// Package determining authentication/authorization.
	authzEndpoint = ""

	// flagToVar specifies which flag's value to load to which variable.
	flagToVar = map[string]*string{
		// These strings specify the set of flags that can be passed to this module.
		"url": &policyEngineURL,
		"display_rule_endpoint": &displayEndpoint,
		"pull_rule_endpoint":    &pullEndpoint,
		"authz_rule_endpoint":   &authzEndpoint,
	}

	// flagsInitialized ensures that PAM flags are processed only once.
	flagsInitialized = false
)

// loadVarsFromArgv takes a map flagVars of flags to the vars that they should be assigned to,
// and looks for the flag-value pairs in argv to make the assignments.
func loadFlags(flagVars map[string]*string, argv []string) {
	for _, arg := range argv {
		opt := strings.Split(arg, "=")
		if pointer, ok := flagVars[opt[0]]; ok {
			*pointer = opt[1]
			log(logLevelInfo, "%s set to %s", arg, *pointer)
		} else {
			log(logLevelError, "unkown option: %s", opt[0])
		}
	}
}

// initalize prepares the module.
func initialize(args []string) {
	if !flagsInitialized {
		loadFlags(
			flagToVar,
			args,
		)

		flagsInitialized = true
	}

	// runtime.GOMAXPROCS(1)
}

// Shared object libraries in golang, like this PAM module,
// require an empty main function.
func main() {}
