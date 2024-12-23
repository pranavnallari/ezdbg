//run_debugger,c
#include "defs.h"

void run_debugger(const char *filename, pid_t child_pid) {
    procmsg("Started Debugger....\n");
    int status;
    waitpid(child_pid, &status, 0);

    if (WIFSTOPPED(status)) {
        printf("Program is ready for debugging...\n");
    } else {
        fprintf(stderr, "Program failed to stop\n");
        return;
    }

    init_dwarf(filename);
    // run repl here
    repl(child_pid);
    // cleanup
    cleanup_dwarf();
}