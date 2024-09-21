all:
	gcc ezdbg.c -o ezdbg -Wall -Wextra -pedantic

test:
	gcc test.c -o test

clean:
	rm -rf ezdbg test && clear
