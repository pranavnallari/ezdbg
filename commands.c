// commands.c

#include "defs.h"


void help() {
    
}


void start(pid_t pid) {
    if (bpmngr.count == 0) {
        procmsg("No BreakPoints encountered....Automatically resuming execution.\n");
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("ptrace failure while continuing execution");
            exit(EXIT_FAILURE);
        }

        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid failed");
            exit(EXIT_FAILURE);
        }
    } else {
        procmsg("Stopping at first breakpoint.\n");
        enable_bp(pid, &bpmngr.bps[0]);

        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("ptrace failure while continuing execution");
            exit(EXIT_FAILURE);
        }

        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid failed");
            exit(EXIT_FAILURE);
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            procmsg("Hit breakpoint at address: %p\n", bpmngr.bps[0].addr);
        } else {
            fprintf(stderr, "Unexpected stop: Status - %d\n", status);
        }
    }
}


void invalid() {
    procmsg("Invalid Usage... Type 'help' to see a list of all commands\n");
}