#!Makefile

CC = gcc
CFLAGS = -g -Wall -O2
LDFLAGS = -lpthread
BIN = rv_emu
C_FILES = $(wildcard *.c)
OBJ_FILES = $(C_FILES: %.c=%.o)

CONFIG_ARCH_TEST ?= 0
ifeq ("$(CONFIG_ARCH_TEST)", "1")
CFLAGS += -DCONFIG_ARCH_TEST
endif

$(BIN): $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

%.o: %.c
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
	rm -rf $(TARGETDIR)/arch-test
	make -C $(ARCH_TEST_DIR) clean
	make -C $(ARCH_TEST_DIR)

clean:
	rm $(BIN)
