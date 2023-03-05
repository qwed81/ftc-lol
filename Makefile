all: start patch
	clang -fuse-ld=lld -static-pie -nostdlib -target i386-unknown-linux-elf -o target/debug/patch target/debug/patch.o target/debug/_start.o

start: src/patch/_start.s
	nasm -o target/debug/_start.o -f elf32 src/patch/_start.s

patch: src/patch/patch.c
	clang -c -nostdlib -target i386-unknown-linux-elf -Wall -o target/debug/patch.o src/patch/patch.c