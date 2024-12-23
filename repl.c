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
    else if (strcmp("step_into", command) == 0) return STEP_INTO;
    else if (strcmp("step", command) == 0) return STEP;
    else if (strcmp("list_bp", command) == 0) return LIST_BP;
    else if (strcmp("inspect", command) == 0) return INSPECT_REGS;
    else if (strcmp("show_call_stack", command) == 0) return SHOW_CALL_STACK;
    else if (strcmp("print_var", command) == 0) return PRINT_VAR;
    else if (strcmp("memory_dump", command) == 0) return MEM_DUMP;
    else if (strcmp("stop", command) == 0) return STOP;
    else if (strcmp("quit", command) == 0) return QUIT;
    else return INVALID;
}

void repl(pid_t child_pid) {
    int choice = 9999999;
    welcome_message();
    while (choice != 0) {
        printf("ezdbg>");
        char buffer[INPUT_BUFFER_SIZE];
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL) {
            perror("error reading input..");
            continue;
        }
        if (buffer[0] == '\n') continue;
        buffer[strcspn(buffer, "\n")] = '\0';

        char *command = strtok(buffer, " ");
        char *args = strtok(NULL, "");
        
        COMMANDS cmd = parse_command(command);
        switch(cmd) {
            case HELP:
            {
                break;
            }
            case START:
            {
                break;
            }
            case BREAK:
            {
                break;
            }
            case CLEAR:
            {
                break;
            }
            case CONTINUE:
            {
                break;
            }
            case STEP:
            {
                break;
            }
            case STEP_INTO:
            {
                break;
            }
            case LIST_BP:
            {
                break;
            }
            case INSPECT_REGS:
            {
                break;
            }
            case SHOW_CALL_STACK:
            {
                break;
            }
            case PRINT_VAR:
            {
                break;
            }
            case MEM_DUMP:
            {
                break;
            }
            case STOP:
            {
                break;
            }
            case QUIT:
            {
                break;
            }
            case INVALID:
            {
                break;
            }
            default:
            {
                break;
            }
        }    
    }
}