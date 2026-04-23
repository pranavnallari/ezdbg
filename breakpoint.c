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

    bp->orig_data = (unsigned long)(data & 0xFF);

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

    long restored_data = (data & 0xFFFFFFFFFFFFFF00) | (bp->orig_data & 0xFF);
    if (ptrace(PTRACE_POKETEXT, pid, (long)bp->addr, (long)restored_data) < 0) {
        perror("ptrace POKETEXT failed during disable_bp");
        exit(EXIT_FAILURE);
    }
}

S_Breakpoint create_bp(pid_t pid, void *addr) {
    S_Breakpoint bp = {.addr = addr, .orig_data = 0};
    enable_bp(pid, &bp);
    return bp;
}

void free_bp(S_Breakpoint *bp) {
    (void)bp; // breakpoints live in bpmngr.bps[] (static array), nothing to free
}

void init_bpmngr() {
    bpmngr.count = 0;
}

// dwarf_next_cu_header is a stateful iterator — it must be drained to DW_DLV_NO_ENTRY
// before it will restart from the beginning. Call this before any fresh DWARF search.
static void reset_dwarf_cu(void) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    while (dwarf_next_cu_header(
                dwarf_debug,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) == DW_DLV_OK) {
        // drain until DW_DLV_NO_ENTRY so the iterator wraps to the beginning
    }
}

void* get_func_addr(const char* func_name) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;

    reset_dwarf_cu();

    while (dwarf_next_cu_header(
                dwarf_debug,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) == DW_DLV_OK) {

        if (dwarf_siblingof(dwarf_debug, no_die, &cu_die, &err) != DW_DLV_OK)
            continue;

        if (dwarf_child(cu_die, &child_die, &err) != DW_DLV_OK)
            continue;

        while (1) {
            char* die_name = 0;
            Dwarf_Error local_err;
            if (dwarf_diename(child_die, &die_name, &local_err) == DW_DLV_OK && die_name != NULL) {
                if (strcmp(func_name, die_name) == 0) {
                    Dwarf_Addr low_pc = 0;
                    if (dwarf_lowpc(child_die, &low_pc, &local_err) == DW_DLV_OK) {
                        dwarf_dealloc(dwarf_debug, die_name, DW_DLA_STRING);
                        return (void*)(low_pc + base_address);
                    }
                }
                dwarf_dealloc(dwarf_debug, die_name, DW_DLA_STRING);
            }

            int rc = dwarf_siblingof(dwarf_debug, child_die, &child_die, &err);
            if (rc == DW_DLV_ERROR || rc == DW_DLV_NO_ENTRY)
                break;
        }
    }

    return NULL;
}

// Reverse lookup: given an address, return the name of the function that contains it.
// Returns a malloc'd string — caller must free() it. Returns NULL if not found.
char* get_func_name_by_addr(void *target_addr) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;

    reset_dwarf_cu();

    while (dwarf_next_cu_header(
                dwarf_debug,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) == DW_DLV_OK) {

        if (dwarf_siblingof(dwarf_debug, no_die, &cu_die, &err) != DW_DLV_OK)
            continue;
        if (dwarf_child(cu_die, &child_die, &err) != DW_DLV_OK)
            continue;

        while (1) {
            Dwarf_Addr low_pc = 0;
            Dwarf_Addr high_pc_val = 0;
            Dwarf_Half high_pc_form = 0;
            enum Dwarf_Form_Class high_pc_class = DW_FORM_CLASS_UNKNOWN;
            Dwarf_Error local_err;

            if (dwarf_lowpc(child_die, &low_pc, &local_err) == DW_DLV_OK &&
                dwarf_highpc_b(child_die, &high_pc_val, &high_pc_form,
                               &high_pc_class, &local_err) == DW_DLV_OK) {

                // DWARF4+: high_pc may be a length (offset from low_pc)
                Dwarf_Addr high_pc = (high_pc_class == DW_FORM_CLASS_CONSTANT)
                    ? low_pc + high_pc_val
                    : high_pc_val;

                // target_addr is already absolute; low_pc/high_pc are also absolute for non-PIE
                if ((Dwarf_Addr)target_addr >= low_pc &&
                    (Dwarf_Addr)target_addr <  high_pc) {

                    char *die_name = NULL;
                    if (dwarf_diename(child_die, &die_name, &local_err) == DW_DLV_OK && die_name) {
                        char *result = strdup(die_name);
                        dwarf_dealloc(dwarf_debug, die_name, DW_DLA_STRING);
                        return result;
                    }
                }
            }

            int rc = dwarf_siblingof(dwarf_debug, child_die, &child_die, &err);
            if (rc == DW_DLV_ERROR || rc == DW_DLV_NO_ENTRY)
                break;
        }
    }

    return NULL;
}