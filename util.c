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
    int start = 0;
    // Allow optional 0x / 0X prefix
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        start = 2;
        if (str[start] == '\0') return 0; // "0x" alone is not a valid address
    }
    for (int i = start; str[i]; i++) {
        if (!isxdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}
