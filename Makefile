all: comp run

comp:
	@gcc -fsanitize=address -static-libasan  -Wall -L/usr/lib -lcrypto main.c -o main -g

cleancomp:
	@gcc -Wall -L/usr/lib -lcrypto main.c -o main

gdb:
	@gcc -Wall -Wextra -pedantic -L/usr/lib -g main.c -o main -lcrypto -lm
	-gdb --args ./main

run:
	-@rm data.bin
	./main