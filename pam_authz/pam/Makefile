MODULE := pam_authz

module:
	gcc -fPIC -fno-stack-protector -c pam.c -o ${MODULE}.o
	gcc -shared -lcurl -ljansson -Wl,-soname,${MODULE}.so -o ${MODULE}.so ${MODULE}.o

clean:
	-rm -f ${MODULE}.so ${MODULE}.o

.PHONY: module clean
