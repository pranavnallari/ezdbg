//ezdbg.c
#include "defs.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage : ezdbg <filename.c>\n");
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("Error Occurred while starting debugger....\n");
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        run_program((const)argv[1], argc, argv);
    } else {
        run_debugger((const)argv[1]);
    }
    return EXIT_SUCCESS;
}