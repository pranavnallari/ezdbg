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
    save_terminal();
    init_screen();
    if (pid == 0) {
        run_program((const char*)argv[1], argc, argv);
    } else {
        run_debugger((const char*)argv[1], pid);
    }
    restore_terminal();
    fflush(stdout);
    return EXIT_SUCCESS;
}