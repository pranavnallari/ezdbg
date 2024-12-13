//util.c

#include "defs.h"

void procmsg(const char* format, ...) {
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}