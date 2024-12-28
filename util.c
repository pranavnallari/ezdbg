//util.c

#include "defs.h"

void procmsg(const char* format, ...) {
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

int is_numeric(const char *str) {
    if (!str) return 0;
    for (int i = 0; str[i]; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}
