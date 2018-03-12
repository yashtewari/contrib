#include <security/pam_appl.h>


#include <stdlib.h>
#include <string.h>




#ifdef __APPLE__
  #include <sys/ptrace.h>
#elif __linux__
  #include <sys/prctl.h>
#endif

int disable_ptrace() {
#ifdef __APPLE__
  return ptrace(PT_DENY_ATTACH, 0, 0, 0);
#elif __linux__
  return prctl(PR_SET_DUMPABLE, 0);
#endif
  return 1;
}

char *string_from_argv(int i, char **argv) {
  return strdup(argv[i]);
}






char *get_pam_item_string2(pam_handle_t *pamh, int item_type) {
  if (!pamh)
    return NULL;

  char *str;
  if (pam_get_item(pamh, item_type, (const void**)&str) != PAM_SUCCESS)
    return NULL;

  if (str == NULL)
    return NULL;

  return strdup(str);
}
