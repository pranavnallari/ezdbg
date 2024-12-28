// commands.c

#include "defs.h"


void help() {
    printf("Available commands:\n");
    printf("help\t\t\tDisplay this help message with a list of commands.\n");
    printf("start\t\t\tStart the debugging process. Stops at 'main' by default if no breakpoints are set.\n");
    printf("break <addr>/<func>\tSet a breakpoint at the specified memory address or function name.\n");
    printf("clear <addr>/<func>\tClear the breakpoint at the specified memory address or function name.\n");
    printf("continue\t\tContinue execution from the current position until the next breakpoint or program termination.\n");
    printf("step\t\t\tExecute a single instruction and display the updated instruction pointer and memory at that address.\n");
    printf("list_bp\t\t\tList all currently set breakpoints with their addresses.\n");
    printf("inspect_regs\t\tDisplay the current values of all CPU registers.\n");
    printf("mem_dump <start> <end>\tDump the memory contents from the specified start to end addresses.\n");
    printf("quit\t\t\tExit the debugger.\n");
    printf("\n");
    printf("Usage Examples:\n");
    printf("  break 0x00400500\tSet a breakpoint at address 0x00400500.\n");
    printf("  break main\t\tSet a breakpoint at the 'main' function.\n");
    printf("  clear 0x00400500\tClear the breakpoint at address 0x00400500.\n");
    printf("  clear main\t\tClear the breakpoint at the 'main' function.\n");
    printf("  mem_dump 0x00400000 0x00401000\tDump memory from 0x00400000 to 0x00401000.\n");
}

void start(pid_t pid) {
    if (bpmngr.count == 0) {
        procmsg("No BreakPoints encountered....Automatically stopping at main(0x%X)..\n", get_func_addr("main"));
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

void set_bp_addr(pid_t pid, void *addr) {
    assert(addr);
    bpmngr.bps[bpmngr.count] = create_bp(pid, addr);
    bpmngr.count++;
}

void set_bp_by_func_name(pid_t pid, const char *func_name) {
    assert(func_name);
    void *addr = get_func_addr(func_name);
    set_bp_addr(pid, addr);
}

void cont(pid_t pid, S_Breakpoint *bp) {
    struct user_regs_struct regs;
    int wait_status;

    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    assert(regs.rip == (unsigned long long)bp->addr+1);

    regs.rip = (long)bp->addr;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    disable_bp(pid, bp);
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
        perror("ptrace");
        return;
    }

    wait(&wait_status);

    if (WIFEXITED(wait_status)) {
        return;
    }

    enable_bp(pid, bp);

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        perror("ptrace");
        return;
    }

    wait(&wait_status);
}

void clear_bp_by_func_name(pid_t pid, const char* func_name) {
    assert(func_name);
    void *addr = get_func_addr(func_name);
    clear_bp_by_addr(pid, addr);
}

void clear_bp_by_addr(pid_t pid, void *addr) {
    int found = -1;
    for (size_t i = 0; i < bpmngr.count; i++) {
        if (bpmngr.bps[i].addr == addr) {
            found = i;
            break;
        }
    }

    if (found == -1) {
        fprintf(stderr, "Error: No breakpoint found at address %p\n", addr);
        return;
    }

    long original_data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (original_data == -1) {
        perror("ptrace PEEKDATA failed");
        return;
    }

    long restored_data = (original_data & ~0xFF) | bpmngr.bps[found].orig_data;
    if (ptrace(PTRACE_POKEDATA, pid, addr, restored_data) == -1) {
        perror("ptrace POKEDATA failed");
        return;
    }

    for (size_t i = found; i < bpmngr.count - 1; i++) {
        bpmngr.bps[i] = bpmngr.bps[i + 1];
    }
    bpmngr.count--;

    procmsg("Breakpoint cleared at address %p\n", addr);
}

void step(pid_t pid) {
    int status;
    struct user_regs_struct regs;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace SINGLESTEP failed");
        return;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid failed");
        return;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace GETREGS failed");
            return;
        }

        unsigned long long rip = regs.rip;
        long memory_at_rip = ptrace(PTRACE_PEEKTEXT, pid, (void *)rip, NULL);
        if (memory_at_rip < 0 && errno != 0) {
            perror("ptrace PEEKTEXT failed");
            return;
        }

        printf("Single step executed successfully.\n");
        printf("Instruction pointer (RIP): 0x%016llX\n", rip);
        printf("Memory at RIP: 0x%08lX\n", memory_at_rip);
    } else {
        fprintf(stderr, "Unexpected stop during single step. Status: %d\n", status);
    }
}

void list_bp() {
    if (bpmngr.count == 0) {
        procmsg("No breakpoints set.\n");
        return;
    }

    procmsg("Listing all breakpoints:\n");
    printf("No.\tAddress\t\tFunction/Line\n");
    for (unsigned i = 0; i < bpmngr.count; ++i) {
        void *addr = bpmngr.bps[i].addr;
        const char *func_name = get_func_addr(addr);
        if (func_name) {
            printf("%d\t%p\t%s\n", i + 1, addr, func_name);
        } else {
            printf("%d\t%p\tUnknown\n", i + 1, addr);
        }
    }
}

void inspect_regs(pid_t pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
        perror("failed to get regs");
        return;
    }
    printf("\n");
    printf("CS\t0x%016llX\n", regs.cs);
    printf("DS\t0x%016llX\n", regs.ds);
    printf("EFLAGS\t0x%016llX\n", regs.eflags);
    printf("ES\t0x%016llX\n", regs.es);
    printf("FS\t0x%016llX\n", regs.fs);
    printf("FS_BASE\t0x%016llX\n", regs.fs_base);
    printf("GS\t0x%016llX\n", regs.gs);
    printf("GS_BASE\t0x%016llX\n", regs.gs_base);
    printf("ORIG_RAX\t0x%016llX\n", regs.orig_rax);
    printf("R8\t0x%016llX\n", regs.r8);
    printf("R9\t0x%016llX\n", regs.r9);
    printf("R10\t0x%016llX\n", regs.r10);
    printf("R11\t0x%016llX\n", regs.r11);
    printf("R12\t0x%016llX\n", regs.r12);
    printf("R13\t0x%016llX\n", regs.r13);
    printf("R14\t0x%016llX\n", regs.r14);
    printf("R15\t0x%016llX\n", regs.r15);
    printf("RAX\t0x%016llX\n", regs.rax);
    printf("RBP\t0x%016llX\n", regs.rbp);
    printf("RCX\t0x%016llX\n", regs.rcx);
    printf("RDI\t0x%016llX\n", regs.rdi);
    printf("RDX\t0x%016llX\n", regs.rdx);
    printf("RIP\t0x%016llX\n", regs.rip);
    printf("RSI\t0x%016llX\n", regs.rsi);
    printf("RSP\t0x%016llX\n", regs.rsp);
    printf("SS\t0x%016llX\n", regs.ss);

}

void mem_dump(pid_t pid, unsigned from, unsigned to) {
    procmsg("Displaying PID : %d's memory [0x%08X - 0x%08X]\n", pid, from, to);
    for (unsigned i = from; i <= to; ++i) {
        int word = ptrace(PTRACE_PEEKTEXT, pid, i, 0);
        if (word < 0) {
            procmsg("Error Occurred while reading memory at 0x%08X\n", i);
            break;
        }
    }
}

void invalid() {
    procmsg("Invalid Usage... Type 'help' to see a list of all commands\n");
}