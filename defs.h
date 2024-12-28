//defs.h
#ifndef DEFS_H
#define DEFS_H
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <libelf.h>
/* GLOBAL */
typedef enum {HELP, START, BREAK, CLEAR, CONTINUE, STEP, LIST_BP, INSPECT_REGS, MEM_DUMP, QUIT, INVALID} COMMANDS;
typedef struct {
    void *addr;
    unsigned orig_data;
} S_Breakpoint;
#define MAX_BREAKPOINTS 100
typedef struct {
    S_Breakpoint bps[MAX_BREAKPOINTS];
    size_t count;
} S_brkpt_mngr;
/* VARIABLES */

// display.c
extern struct termios saved_attributes;
// dwarf.c
extern Dwarf_Debug dwarf_debug;
extern Elf *elf;
// breakpoints.c
extern S_brkpt_mngr bpmngr;

/* FUNCTIONS */

// run_program.c
extern void run_program(const char* filename, int argc, char* argv[]);
//run_debugger.c
extern void run_debugger(const char* filename, pid_t child_pid);
//repl.c
extern void repl(pid_t child_pid);
extern void welcome_message();
extern COMMANDS parse_command(char *command);
// commands.c
extern void help();
extern void start(pid_t pid);
extern void set_bp_addr(pid_t pid, void *addr);
extern void set_bp_by_func_name(pid_t pid, const char *func_name);
extern void cont(pid_t pid, S_Breakpoint *bp);
extern void clear_bp_by_addr(pid_t pid, void *addr);
extern void clear_bp_by_func_name(pid_t pid, const char *func_name);
extern void step(pid_t pid);
extern void list_bp();
extern void inspect_regs(pid_t pid);
void mem_dump(pid_t pid, unsigned from, unsigned to);
extern void invalid();
// display.c
extern void clear_screen();
extern int init_screen();
extern int getwinsize(struct winsize *w);
extern void save_terminal();
extern void restore_terminal();     
//dwarf.c
extern void init_dwarf(const char* filename);
extern void cleanup_dwarf();
// breakpoint.c
extern void enable_bp(pid_t pid, S_Breakpoint *bp);
extern void disable_bp(pid_t pid, S_Breakpoint *bp);
extern S_Breakpoint create_bp(pid_t pid, void *addr);
extern void free_bp(S_Breakpoint *bp);
extern void init_bpmngr();
extern void* get_func_addr(const char * func_name);
//util.c
extern void procmsg(const char* format, ...);
extern int is_numeric(const char *str);

#endif