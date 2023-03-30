all: start patch
	clang -fuse-ld=lld -fPIE -nostdlib -target i386-unknown-linux-elf -o target/debug/patch \
		target/debug/bootstrap.o target/debug/patch.o

start: src/patch/bootstrap.s
	nasm -o target/debug/bootstrap.o -f elf32 src/patch/bootstrap.s

patch: src/patch/patch.c
	clang -c -nostdlib -fPIC -target i386-unknown-linux-elf -Wall -o target/debug/patch.o src/patch/patch.c
