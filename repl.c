//repl.c
#include "defs.h"

#define INPUT_BUFFER_SIZE 1024

void welcome_message() {
    printf("Welcome to ezdbg\n");
    printf("To view a list of all commands type 'help'\nType 'quit' to exit the application at anytime\n");
}

COMMANDS parse_command(char *command) {
    
}

void repl() {
    int choice = 9999999;
    welcome_message();
    while (choice != 0) {
        printf("ezdbg>");
        char buffer[INPUT_BUFFER_SIZE];
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL) {
            perror("error reading input..");
            continue;
        }

        buffer[strcspn(buffer, "\n")] = '\0';

        char *command = strtok(buffer, " ");
        char *args = strtok(NULL, "");


    }
}