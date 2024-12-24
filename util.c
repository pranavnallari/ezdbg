//util.c

#include "defs.h"

void procmsg(const char* format, ...) {
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}


unsigned long long get_target_ip(pid_t pid) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.rip;
}
