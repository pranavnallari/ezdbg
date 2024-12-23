// commands.c

#include "defs.h"


void help() {
    
}


void start(pid_t pid) {
    if (bpmngr.count == 0) {
        // set bp at main
        printf("No BreakPoints encountered....Automatically stopping at main()\n");
    }
}