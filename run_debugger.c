//run_debugger.c
#include "defs.h"
#include <limits.h>

uintptr_t base_address = 0;

// Read /proc/<pid>/maps to find the load address of the target binary.
// The base is the lowest mapped address for the binary (first entry in maps).
uintptr_t get_base_address(pid_t pid, const char *filename) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        perror("Failed to open /proc/<pid>/maps");
        return 0;
    }

    // Resolve to absolute path so we can match against maps entries
    char resolved[PATH_MAX];
    if (!realpath(filename, resolved)) {
        strncpy(resolved, filename, PATH_MAX - 1);
        resolved[PATH_MAX - 1] = '\0';
    }

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8], pathname[512];
        pathname[0] = '\0';
        sscanf(line, "%lx-%lx %7s %*s %*s %*s %511s", &start, &end, perms, pathname);

        if (strcmp(pathname, resolved) == 0) {
            // First match is always the lowest address (maps is sorted)
            base = start;
            break;
        }
    }

    fclose(f);
    return base;
}

void run_debugger(const char *filename, pid_t child_pid) {
    procmsg("Started Debugger....\n");

    int status;
    waitpid(child_pid, &status, 0);
    
    if (WIFSTOPPED(status)) {
        printf("Program is ready for debugging...\n");
        init_dwarf(filename);

        base_address = get_base_address(child_pid, filename);
        if (base_address) {
            // For non-PIE binaries, DWARF already contains absolute addresses
            // (e.g. low_pc = 0x401149, base = 0x400000).
            // For PIE binaries, DWARF contains offsets (e.g. low_pc = 0x1149, base = 0x555555554000).
            // Detect by checking if the DWARF main address already looks absolute.
            void *dwarf_main = get_func_addr("main");
            if (dwarf_main && (uintptr_t)dwarf_main >= base_address) {
                // DWARF already has absolute addresses — non-PIE, no offset needed
                procmsg("Non-PIE binary. Base: 0x%lx, DWARF addresses are absolute.\n", base_address);
                base_address = 0;
            } else {
                procmsg("PIE binary detected. Base address: 0x%lx\n", base_address);
            }
        }

        repl(child_pid);
        cleanup_dwarf();
    } else {
        fprintf(stderr, "Program failed to stop properly\n");
    }
}