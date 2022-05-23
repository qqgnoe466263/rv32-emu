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

ARCH_TEST_DIR ?= riscv-arch-test
ARCH_TEST_BUILD ?= $(ARCH_TEST_DIR)/Makefile
export RISCV_TARGET = arch-test-target
export RISCV_PREFIX ?= riscv32-unknown-linux-gnu-
export TARGETDIR = $(shell pwd)
export XLEN = 32
export WORK = $(TARGETDIR)/arch-test

$(ARCH_TEST_BUILD):
	git submodule update --init

arch-test: $(BIN) $(ARCH_TEST_BUILD)
	make -C $(ARCH_TEST_DIR) clean
	make -C $(ARCH_TEST_DIR)

check:
	riscv32-unknown-linux-gnu-gcc -Wl,-Ttext=0x0 -nostdlib -march=rv32g -O0 test/fib.c -o test/fib.obj
	#riscv32-unknown-linux-gnu-objcopy -O binary test/fib.obj test/fib.bin

clean:
	rm src/*.o rv_emu
