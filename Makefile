all:
	gcc *.c -o ezdbg -Wall -Wextra -pedantic -ldwarf -lelf

test:
	gcc -g tests/test.c -o tests/test

clean:
	rm -rf ezdbg && clear

run:
	./ezdbg tests/test
