all:
	gcc *.c -o ezdbg -Wall -Wextra -pedantic -ldwarf -lelf

clean:
	rm -rf ezdbg && clear

