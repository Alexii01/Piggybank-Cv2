unix: comp
	./main

win: comp
	wine main.exe

comp:
	@gcc main.c -lcrypto -lssl -o main
	@x86_64-w64-mingw32-gcc main.c -o main.exe -static-libgcc -static -I/home/alex/Projects/C/rootfs/usr/local/include -L/home/alex/Projects/C/rootfs/usr/local/lib -L/home/alex/Projects/C/rootfs/usr/local/lib64 -lcrypto -lssl -lws2_32 -lz