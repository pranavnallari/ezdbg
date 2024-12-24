all:
	gcc *.c -o ezdbg -Wall -Wextra -pedantic -ldwarf -lelf

test:
	gcc -g tests/test.c -o test

clean:
	rm -rf ezdbg && clear

run:
	sudo ./ezdbg ./test
