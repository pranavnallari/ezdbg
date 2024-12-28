// breakpoint.c

#include "defs.h"

S_brkpt_mngr bpmngr;

void enable_bp(pid_t pid,  S_Breakpoint *bp) {
    assert(bp);

    long data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (data == -1 && errno != 0) {
        perror("ptrace PEEKTEXT failed during enable_bp");
        fprintf(stderr, "Error details: Address: 0x%llx, PID: %d\n", (Dwarf_Addr)bp->addr, pid);
        return;
    }

    long data_with_bp = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, (void *)data_with_bp) == -1) {
        perror("ptrace POKETEXT failed during enable_bp");
        return;
    }

    procmsg("Breakpoint enabled at 0x%llx\n", (Dwarf_Addr)bp->addr);
}


void disable_bp(pid_t pid, S_Breakpoint *bp) {
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

S_Breakpoint create_bp(pid_t pid, void *addr) {
    S_Breakpoint bp = {.addr = addr, .orig_data = 0};
    enable_bp(pid, &bp);
    assert(&bp);
    return bp;
}

void free_bp(S_Breakpoint *bp) {
    free(bp);
}

void init_bpmngr() {
    bpmngr.count = 0;
}

void* get_func_addr(const char* func_name) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;

    while (dwarf_next_cu_header(
                dwarf_debug,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) == DW_DLV_OK) {
        
        if (dwarf_siblingof(dwarf_debug, no_die, &cu_die, &err) != DW_DLV_OK) {
            continue;
        }

        if (dwarf_child(cu_die, &child_die, &err) != DW_DLV_OK) {
            continue;
        }

        while (1) {
            char* die_name = 0;
            Dwarf_Error local_err;
            if (dwarf_diename(child_die, &die_name, &local_err) == DW_DLV_OK && die_name != NULL) {
                if (strcmp(func_name, die_name) == 0) {
                    Dwarf_Addr low_pc = 0;
                    if (dwarf_lowpc(child_die, &low_pc, &local_err) == DW_DLV_OK) {
                        dwarf_dealloc(dwarf_debug, die_name, DW_DLA_STRING);
                        return (void*)low_pc; // Return the function's starting address
                    }
                }
                dwarf_dealloc(dwarf_debug, die_name, DW_DLA_STRING);
            }
            
            int rc = dwarf_siblingof(dwarf_debug, child_die, &child_die, &err);
            if (rc == DW_DLV_ERROR || rc == DW_DLV_NO_ENTRY) {
                break;
            }
        }
    }

    return NULL; // Function not found
}
