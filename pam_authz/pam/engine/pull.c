#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

char *get_pam_item_string(pam_handle_t *pamh, int item_type) {
	if (!pamh)
		return NULL;

	char *str;
	if (pam_get_item(pamh, item_type, (const void**)&str) != PAM_SUCCESS)
		return NULL;

	if (str == NULL)
		return NULL;

	return strdup(str);
}