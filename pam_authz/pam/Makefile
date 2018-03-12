MODULE := pam_authz

module:
	echo ${PWD}
	echo $(shell go version)
	echo $(shell ls)
	GOPATH=/ go build -buildmode=c-shared -o ${MODULE}.so

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h
	-rm -rf .go/

.PHONY: module clean
