#include <stdio.h>

int sum(int a, int b, int c) {
    int s = a + b + c;
    return s;
}

int main(void) {
    int a = 1;
    int b = 2;
    int c = 3;
    int s = sum(a, b, c);
    printf("Sum is : %d\n", s);
    return 0;
}