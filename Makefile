all:
	gcc *.c -o ezdbg -Wall -Wextra -pedantic

test:
	gcc -g tests/test.c -o test

clean:
	rm -rf ezdbg tests/test && clear
