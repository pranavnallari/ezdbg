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
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

void run_program(char *filename); // tracee process (runs the child process (target program)
void run_debugger(pid_t pid);		// runs debugger in the parent process
void procmsg(const char *format, ...);	// displays message prefixed by it's process ID
long get_target_ip(pid_t pid);		// returns target process current IP (RIP)
void disp_proc_mem(pid_t pid, unsigned from, unsigned to); // displays the contents of memory locations from [from:to] address
typedef struct {
	void *addr; // holds the address where the breakpoint is set
	unsigned orig_data; // hold the data that the address is holding before changing it to INT3
} debug_bp;

static void enable_bp(pid_t pid, debug_bp *bp); // enable breakpoint by replacing the current byte of the address pointed by the IP with INT3 and storing the original data
static void disable_bp(pid_t pid, debug_bp* bp); // disable breakpoints set by replacing the INT3 instruction set with the original data
debug_bp* create_bp(pid_t pid, void *addr);	// create a breakpoint at the address specified
void free_bp (debug_bp* bp);			// free breakpoint struct
int continue_after_bp (pid_t pid, debug_bp* bp);	// resume normal execution after encountering breakpoint



int main(int argc, char *argv[]) {
	if (argc < 2) { // usage
		fprintf(stderr, "Usage : ezdbg <filename.c>\n");
	        return EXIT_FAILURE;
	}

	pid_t fork_id = fork(); // calling a fork to run the debugger and the target process.
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
	execl(filename, filename, NULL); // this line means that the function receives the path for the file in the first argument and we are calling 'filename'. Which is generally the first argument in the command line argument. To end the argument list we must terminate it with a 0.
	
}


/*
	The whole concept of breakpoints is broken down as follows:
	To set a breakpoint at some target address in the target (traced) process, we need to do the following:
		1. Remember the data stored at that address location
		2. Replace the first byte at that location with INT3 instruction.
	
	What happens after that?
	->when debugger runs every instruction, at some point it will encounter the INT3 instruction. Then it will stop and the OS will send a signal to the parent process (in this case) and the parent process is notified that the child process (target program) was stopped. After that it can then :-
		1. Replace the INT3 instruction with the original instruction.
		2. move the instruction pointer of the target process back by 1. (calling the INT3 instruction automatically moves the IP forward, so we need to bring it back by 1)
		3. Now the process is halted perfectly at that instruction and the user can use the debugger to interact with the process.
*/



/*
 PTRACE_SINGLESTEP -> executes one instruction at a time.
 PTRACE_CONT -> Executes until it encounters an  interrupt instrcution.
*/
void run_debugger(pid_t pid) {	
	procmsg("Started Debugger...\n");

	// wait for child to stop on it's first instruction
	wait(0);
	procmsg("target now at RIP=0x%08X\n", get_target_ip(pid));
	debug_bp* bp = create_bp(pid, (void *)0x080483e4);
	procmsg("breakpoint set\n");
	ptrace(PTRACE_CONT, pid, 0, 0); // continue executing process until breakpoint is encountered
	wait(0); // waits for target process to stop until we hit the breakpoint

	while(1) {
		// target process is stopped at a breakpoint here, resume it's execution until it either exits or hits the breakpoint again
		procmsg("Child stopped at breakpoint, RIP=0x%08x\n", get_target_ip(pid));
		procmsg("Resuming...\n");
		int rc = continue_after_bp(pid, bp);

		if (rc == 0) {
			procmsg("Child exited...");
			break;
		}
		else if (rc == 1) {
			continue;
		}
		else {
			procmsg("Unexpected error : %d\n", rc);
			break;
		}
	}
}


long get_target_ip(pid_t pid) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.rip;
}


void disp_proc_mem(pid_t pid, unsigned from, unsigned to) {
	procmsg("Displaying PID : %d's memory [0x%08X - 0x%08X]\n", pid, from, to);
        for (unsigned curr = from; curr <= to; ++curr) {
		unsigned word = ptrace(PTRACE_PEEKTEXT, pid, curr, 0);
		printf("\t0x%08X:  %02X\n", curr, word & 0xFF);
	}
}

static void enable_bp(pid_t pid, debug_bp *bp) {
	assert(bp);
	bp->orig_data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
	ptrace(PTRACE_POKETEXT, pid, bp->addr,(bp->orig_data & 0xFFFFFF00) | 0xCC);
}

static void disable_bp(pid_t pid, debug_bp *bp) {
	assert(bp);
	unsigned check = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
	assert((check & 0xFF) == 0xCC);
	ptrace(PTRACE_POKETEXT, pid, bp->addr, (check & 0xFFFFFF00) | (bp->orig_data & 0xFF));
}

debug_bp* create_bp(pid_t pid, void *addr) {
	debug_bp *bp = malloc(sizeof(debug_bp *));
	bp->addr = addr;
	enable_bp(pid, bp); // replace instr with INT
	return bp;
}

void free_bp(debug_bp *bp) {
	free(bp);
}

int continue_after_bp(pid_t pid, debug_bp *bp) {
	struct user_regs_struct regs;
	int wait_status;

	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	// make sure we have actually stopped at bp
	assert(regs.rip == (long long unsigned) bp->addr + 1);

	// now disable breakpoint, rewind the IP one step back
	regs.rip = (long) bp->addr;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	disable_bp(pid, bp);
	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
		perror("ptrace");
		return -1;
	}
	wait(&wait_status);

	if (WIFEXITED(wait_status)) {
		return 0;
	}

	enable_bp(pid, bp);

	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
		perror("ptrace");
		return -1;
	}

	wait(&wait_status);

	if (WIFEXITED(wait_status)) return 0;
	else if (WIFSTOPPED(wait_status)) return 1;
	else return -1;
}


