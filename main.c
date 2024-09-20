// ezdbg


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void run_program(char *filename) {}
void run_debugger(pid_t pid) {}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage : ezdbg <filename.c>\n");
	        return EXIT_FAILURE;
	}

	pid_t fork_id = fork();
	if (fork_id < 0) {
		perror("Error Occurred while starting debugger : ");
		return EXIT_FAILURE;
	}
	if (fork_id == 0) {
		// in the child process -> will now execute the target program here
		run_program(argv[1]);
	} else {
		// in parent process -> will start running the debugger program here
		run_debugger(fork_id);
	}
	return EXIT_SUCCESS;
}
