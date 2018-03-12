package common.authz

import input.display_responses

default allow = false

allow {
	display_responses["user"] = "yash"
	display_responses["secret"] = "42"
}

errors["Not authorized"] {
	not allow
}