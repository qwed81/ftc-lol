all: start patch as
	clang -fuse-ld=lld -static-pie -nostdlib -target i386-unknown-linux-elf -o target/debug/patch \
		target/debug/patch.o target/debug/bootstrap.o target/debug/as.o

start: src/patch/bootstrap.s
	nasm -o target/debug/bootstrap.o -f elf32 src/patch/bootstrap.s

as: src/patch/as.s
	nasm -o target/debug/as.o -f elf32 src/patch/as.s

patch: src/patch/patch.c
	clang -c -nostdlib -target i386-unknown-linux-elf -Wall -o target/debug/patch.o src/patch/patch.c