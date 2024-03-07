#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

typedef int (*__libc_chown)(const char *pathname, uid_t owner, gid_t group);

/* silent gcc */
int chown(const char *pathname, uid_t owner, gid_t group);

int chown(const char *pathname, uid_t owner, gid_t group)
{
    __libc_chown original_chown;
    if (strlen(pathname) > 7 && strncmp(pathname, "/dev/pt", 7) == 0) {
        /* fake it! */
        return 0;
    }

    original_chown = (__libc_chown)dlsym(RTLD_NEXT, "chown");
    return (*original_chown)(pathname, owner, group);
}
