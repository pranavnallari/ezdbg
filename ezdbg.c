// ezdbg


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>

void run_program(char *filename);
void run_debugger(pid_t pid);
void procmsg(const char *format, ...);


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

void procmsg(const char *format, ...) {
	va_list ap;
	fprintf(stdout, "[%d] ", getpid());
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

void run_program(char *filename) {
	procmsg("Started running target program '%s'\n", filename);
	// allow tracing for this process to done by parent process. Any signal (except SIGKILL) sent to this process (child) will make the (child) stop and it's parent will be notified via 'wait()'. All subsequent calls to execl() by this process will cause a SIGTRAP to be sent to it, which gives the parent a chance to gain control before the new program begins execution.
	// PTRACE_TRACEME -> used only by child process (target program) to tell parent program (debugger) to trace it.
	// ptrace api -> (enum request operation, pid (thread ID of the calling thread), addr*, data*) {addr and data} are for data manipulation for other operations on ptrace 
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		perror("ptrace error");
		return;
	}
	// execl is a frontend for execve function
	// execl (path, arg[], ...) -> can be thought as arg0, arg1,.... argn i.e argument list to run that program
	// execve (pathname, argv[][], envp[][])
	execl(filename, filename, 0); // this line means that the function receives the path for the file in the first argument and we are calling 'filename'. Which is generally the first argument in the command line argument. To end the argument list we must terminate it with a 0.
	
}

void run_debugger(pid_t pid) {
	int w_status;
	unsigned ic = 0; // instruction counter to keep track of all instructions executed
	
	procmsg("Started Debugger...\n");

	// wait for child to stop on it's first instruction
	wait(&w_status); // receives wait signal from ptrace called on child (target)
	
	while(WIFSTOPPED(w_status)) { // int WIFSTOPPED (int status) -> returns a nonzero value if the child process is stopped
		ic++;
		struct user_regs_struct regs;
		ptrace(PTRACE_GETREGS, pid, 0, &regs); // getting the register values every step;
		unsigned long long instr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0); // peeking(seeing) the value stored at eip (instruction pointer) at that address
		procmsg("Instr Counter = %u.\tEIP = 0x%08x.\tinstr = 0x%08x\n", ic, regs.rip, instr);
		// make the child execute another instruction
		if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
			perror("ptrace single step");
			return;
		}

		// wait for child to stop on it's next instruction
		wait(&w_status);
	}

	procmsg("Child Executed ==> %u instructions\n", ic);
	
}
