#!Makefile

CC = gcc
CFLAGS = -g -Iinclude

BIN = rv_emu
C_FILES = $(wildcard src/*.c)
OBJ_FILES = $(C_FILES:%.c=%.o)

$(BIN): $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@

src/%.o: src/%.c
	$(CC) -o $@ -c $(CFLAGS) $<

check:
	riscv32-unknown-linux-gnu-gcc -Wl,-Ttext=0x0 -nostdlib -march=rv32g -O0 test/fib.c -o test/fib.obj
	riscv32-unknown-linux-gnu-objcopy -O binary test/fib.obj test/fib.bin

clean:
	rm src/*.o rv_emu
