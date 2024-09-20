all:
	gcc main.c -o main -Wall -Wextra -pedantic

test:
	gcc test.c -o test

clean:
	rm -rf main test && clear
