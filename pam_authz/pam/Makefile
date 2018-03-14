MODULE := pam_authz

module:
	gcc -fPIC -fno-stack-protector -c pam.c -o ${MODULE}.o
	ld -x --shared -o ${MODULE}.so ${MODULE}.o

clean:
	-rm -f ${MODULE}.so ${MODULE}.o

.PHONY: module clean
