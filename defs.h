//defs.h
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

// global info
typedef enum {HELP, SET_BP_ADDR, SET_BP_LINE, CLEAR_BP_ADDR, CLEAR_BP_LINE, CONTINUE, STEP_INTO, STEP_OVER, STEP_OUT, LIST_BP, INSPECT_REGS, SHOW_CALL_STACK, PRINT_VAR, MOD_MEM, DISS_ADDR, DISS_FUNC, PAUSE, QUIT} COMMANDS;

// run_program.c
extern void run_program(const char* filename, int argc, char* argv[]);
//run_debugger.c
extern void run_debugger(const char* filename);
//repl.c
extern void repl();
extern void welcome_message();
extern COMMANDS parse_command(char *command);
//commands.c
extern void help();
//util.c
extern void procmsg(const char* format, ...);