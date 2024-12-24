//run_debugger,c
#include "defs.h"

void run_debugger(const char *filename, pid_t child_pid) {
    procmsg("Started Debugger....\n");

    int status;
    waitpid(child_pid, &status, 0);
    
    if (WIFSTOPPED(status)) {
        printf("Program is ready for debugging...\n");
        init_dwarf(filename);
        repl(child_pid);
        cleanup_dwarf();
    } else {
        fprintf(stderr, "Program failed to stop properly\n");
    }
}
