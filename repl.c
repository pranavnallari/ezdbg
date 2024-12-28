//repl.c
#include "defs.h"

#define INPUT_BUFFER_SIZE 1024

void welcome_message() {
    printf("Welcome to ezdbg\n");
    printf("To view a list of all commands type 'help'\nType 'quit' to exit the application at anytime\n");
}

COMMANDS parse_command(char *command) {
    if (strcmp("help", command) == 0) return HELP;
    else if (strcmp("break", command) == 0) return BREAK;
    else if (strcmp("start", command) == 0) return START;
    else if (strcmp("clear", command) == 0) return CLEAR;
    else if (strcmp("continue", command) == 0) return CONTINUE;
    else if (strcmp("step", command) == 0) return STEP;
    else if (strcmp("list_bp", command) == 0) return LIST_BP;
    else if (strcmp("inspect", command) == 0) return INSPECT_REGS;
    else if (strcmp("memory_dump", command) == 0) return MEM_DUMP;
    else if (strcmp("quit", command) == 0) return QUIT;
    else return INVALID;
}

void repl(pid_t child_pid) {
    welcome_message();

    while (1) {
        printf("ezdbg> ");
        char buffer[INPUT_BUFFER_SIZE];
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL) {
            perror("Error reading input");
            continue;
        }

        buffer[strcspn(buffer, "\n")] = '\0';

        if (buffer[0] == '\0') continue;

        char *command = strtok(buffer, " ");
        char *args = strtok(NULL, "");

        COMMANDS cmd = parse_command(command);

        switch (cmd) {
            case HELP:
                if (args) {
                    invalid();
                } else {
                    help();
                }
                break;

            case START:
                if (args) {
                    invalid();
                } else {
                    start(child_pid);
                }
                break;

            case BREAK:
                if (!args) {
                    printf("Error: 'break' command requires an address or function name.\n");
                } else if (is_numeric(args)) {
                    void *addr = (void *)strtol(args, NULL, 16);
                    set_bp_addr(child_pid, addr);
                } else {
                    set_bp_by_func_name(child_pid, args);
                }
                break;

            case CLEAR:
                if (!args) {
                    printf("Error: 'clear' command requires an address or function name.\n");
                } else if (is_numeric(args)) {
                    void *addr = (void *)strtol(args, NULL, 16);
                    clear_bp_by_addr(child_pid, addr);
                } else {
                    clear_bp_by_func_name(child_pid, args);
                }
                break;

            case CONTINUE:
                if (args) {
                    invalid();
                } else {
                    cont(child_pid, NULL);
                }
                break;

            case STEP:
                if (args) {
                    invalid();
                } else {
                    step(child_pid);
                }
                break;

            case LIST_BP:
                if (args) {
                    invalid();
                } else {
                    list_bp();
                }
                break;

            case INSPECT_REGS:
                if (args) {
                    invalid();
                } else {
                    inspect_regs(child_pid);
                }
                break;

            case MEM_DUMP:
                if (!args) {
                    printf("Error: 'memory_dump' command requires start and end addresses.\n");
                } else {
                    char *start_str = strtok(args, " ");
                    char *end_str = strtok(NULL, " ");

                    if (!start_str || !end_str) {
                        printf("Error: 'memory_dump' requires two arguments (start and end addresses).\n");
                    } else {
                        unsigned start = strtol(start_str, NULL, 16);
                        unsigned end = strtol(end_str, NULL, 16);

                        if (start > end) {
                            printf("Error: Start address cannot be greater than end address.\n");
                        } else {
                            mem_dump(child_pid, start, end);
                        }
                    }
                }
                break;

            case QUIT:
                printf("Exiting ezdbg. Goodbye!\n");
                return;

            case INVALID:
            default:
                invalid();
                break;
        }
    }
}
