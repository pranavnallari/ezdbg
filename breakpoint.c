// breakpoint.c

#include "defs.h"

S_brkpt_mngr bpmngr;

static void enable_bp(pid_t pid, S_Breakpoint *bp) {
    assert(bp);
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, (long)bp->addr, 0);
    if (errno != 0) {
        perror("ptrace PEEKTEXT failed during enable_bp");
        exit(EXIT_FAILURE);
    }

    bp->orig_data = (unsigned)data;
    unsigned new_data = (data & 0xFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, pid, (long)bp->addr, (long)new_data) < 0) {
        perror("ptrace POKETEXT failed during enable_bp");
        exit(EXIT_FAILURE);
    }
}

static void disable_bp(pid_t pid, S_Breakpoint *bp) {
    assert(bp);
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, (long)bp->addr, 0);
    if (errno != 0) {
        perror("ptrace PEEKTEXT failed during disable_bp");
        exit(EXIT_FAILURE);
    }

    if ((data & 0xFF) != 0xCC) {
        fprintf(stderr, "Error: No breakpoint instruction (0xCC) found at address %p\n", bp->addr);
        exit(EXIT_FAILURE);
    }

    unsigned restored_data = (data & 0xFFFFFF00) | (bp->orig_data & 0xFF);
    if (ptrace(PTRACE_POKETEXT, pid, (long)bp->addr, (long)restored_data) < 0) {
        perror("ptrace POKETEXT failed during disable_bp");
        exit(EXIT_FAILURE);
    }
}

S_Breakpoint* create_bp(pid_t pid, void *addr) {
    S_Breakpoint *bp = malloc(sizeof(S_Breakpoint));
    if (!bp) {
        perror("Failed to allocate memory for breakpoint");
        exit(EXIT_FAILURE);
    }

    bp->addr = addr;
    enable_bp(pid, bp);
    return bp;
}

void free_bp(S_Breakpoint *bp) {
    free(bp);
}

void init_bpmngr() {
    bpmngr.count = 0;
}

void set_bp_at_func(const char * func_name) {
    if (!dwarf_debug) {
        procmsg("libdwarf not initialized properly...\n");
        return;
    }

    Dwarf_Unsigned cu_header_len, abbrev_offset, next_cu_header;
    Dwarf_Half vers_stamp, addr_size;
    void *func_addr = NULL;

    Dwarf_Error err = NULL;
    Dwarf_Off die_offset = 0;
    Dwarf_Die no_die = NULL, cu_die = NULL;

    while (dwarf_next_cu_header(dwarf_debug, &cu_header_len, &vers_stamp, &abbrev_offset, &addr_size, &next_cu_header, &err) == DW_DLV_OK) {
        
    }
}