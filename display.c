// display.c

#include "defs.h"

struct termios saved_attributes;

int getwinsize(struct winsize *w) {
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, w) < 0) {
        perror("ioctl error");
        return -1;
    }
    return 0; 
}

void clear_screen() {
    printf("\033[2J");          // Clear the entire screen
    printf("\033[H");           // Move the cursor to the top-left corner (0,0)
    fflush(stdout);
}

void save_terminal() {
    if (tcgetattr(STDOUT_FILENO, &saved_attributes) < 0) {
        perror("failed to save terminal");
        return;
    }
    printf("\033[?1049h");  // save screen and switch to buffer
    fflush(stdout);
}

void restore_terminal() {
    if (tcsetattr(STDOUT_FILENO, TCSANOW, &saved_attributes) < 0) {
        perror("Failed to restore terminal");
        return;
    }

    printf("\033[?1049l");
    fflush(stdout);
}


int init_screen(){
    clear_screen();

    struct winsize w;
    if (getwinsize(&w) < 0) {
        return -1;
    }

    return 0;
}