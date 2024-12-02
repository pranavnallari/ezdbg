all:
	gcc *.c -o ezdbg -Wall -Wextra -pedantic

test:
	gcc tests/test.c -o test

clean:
	rm -rf ezdbg tests/test && clear
