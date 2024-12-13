//run_program.c
#include "defs.h"

void run_program(const char *filename, int argc, char *argv[]) {
    procmsg("Started Running target program '%s' ...\n", filename);
    if (ptrace(PT_TRACE_ME, 0, 0, 0) < 0) {
        perror("ptrace error");
        return;
    }
    if (argc > 2) {
        char* new_argv[argc];
        new_argv[0] = (char *)filename;
        for (int i = 2; i < argc; i++) {
            new_argv[i-1] = argv[i];
        }
        new_argv[argc-1] = NULL;
        execv(filename, new_argv);
        perror("execv error");
    } else {
        execl(filename, filename, NULL);
        perror("execl error");
    }
}