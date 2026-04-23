// dwarf.c

#include "defs.h"

Dwarf_Debug dwarf_debug = NULL;
Elf *elf = NULL;
static int dwarf_fd = -1;


void init_dwarf(const char *filename) {
    int fd;
    int res;
    Dwarf_Error err;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    dwarf_fd = fd;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "invalid elf lib version\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "failed to initialize elf!\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "Provided file is not an elf file....");
        elf_end(elf);
        close(fd);
        exit(EXIT_FAILURE);
    }

    res = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dwarf_debug, &err);

    if (res != DW_DLV_OK) {
        fprintf(stderr, "Failed to initialize libdwarf: %s\n", (res==DW_DLV_ERROR)?dwarf_errmsg(err) : "No debug data");
        elf_end(elf);
        close(fd);
        exit(EXIT_FAILURE);
    }
    procmsg("DWARF intialized successfully...\n");
}


void cleanup_dwarf() {
    if (dwarf_debug) {
        dwarf_finish(dwarf_debug, NULL);
    }
    if (elf) {
        elf_end(elf);
    }
    if (dwarf_fd >= 0) {
        close(dwarf_fd);
        dwarf_fd = -1;
    }
}