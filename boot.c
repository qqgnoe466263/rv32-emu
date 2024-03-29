#include "boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char dtb_filename[] = "./emu.dtb";

/*  The emulator should be compatible to QEMU RISC-V VirtIO Board:
 *  - https://github.com/qemu/qemu/blob/master/hw/riscv/virt.c
 *
 *  The codes are referenced to:
 *  - https://github.com/riscv/riscv-isa-sim/blob/master/riscv/dts.cc
 */

exception_t read_boot(u8 *ram, u32 addr, u32 size, u32 *result)
{
    u32 idx = (addr - BOOT_ROM_BASE), tmp = 0;

    switch (size) {
    case 32:
        tmp |= (u32)(ram[idx + 3]) << 24;
        tmp |= (u32)(ram[idx + 2]) << 16;
    case 16:
        tmp |= (u32)(ram[idx + 1]) << 8;
    case 8:
        tmp |= (u32)(ram[idx + 0]) << 0;
        *result = tmp;
        return OK;
    default:
        return LOAD_ACCESS_FAULT;
    }
}

// TODO: this might be incorrect for the emulating hw of this emulator
static bool make_dtb()
{
    char dts_str[] =
        "/dts-v1/; \n"
        "\n"
        "/ {\n"
        "    #address-cells = <0x02>;\n"
        "    #size-cells = <0x02>;\n"
        "    model = \"rv32-emu\";\n"
        "    compatible = \"riscv-virtio\";\n"
        "\n"
        "    chosen {\n"
        "        bootargs = \"root=/dev/vda rw console=ttyS0\";"
        "        stdout-path = \"/soc/uart@10000000\";\n"
        "    };\n"
        "\n"
        "    cpus {\n"
        "      #address-cells = <0x01>;\n"
        "      #size-cells = <0x00>;\n"
        "      timebase-frequency = <0x989680>;\n"
        "\n"
        "      CPU0: cpu@0 {\n"
        "        device_type = \"cpu\";\n"
        "        reg = <0x00>;\n"
        "        status = \"okay\";\n"
        "        compatible = \"riscv\";\n"
        "        riscv,isa = \"rv32imacsu\";\n"
        "        mmu-type = \"riscv,sv32\";\n"
        "        CPU0_intc: interrupt-controller {\n"
        "            #interrupt-cells = <0x01>;\n"
        "            interrupt-controller;\n"
        "            compatible = \"riscv,cpu-intc\";\n"
        "        };\n"
        "      };\n"
        "    };\n"
        "\n"
        "    memory@80000000 {\n"
        "      device_type = \"memory\";\n"
        "      reg = <0x0 0x80000000 0x0 0x8000000>;\n"
        "    };\n"
        "\n"
        "    soc {\n"
        "      #address-cells = <0x02>;\n"
        "      #size-cells = <0x02>;\n"
        "      compatible = \"simple-bus\";\n"
        "      ranges;\n"
        "\n"
        "      uart@10000000 {\n"
        "          interrupts = <0xa>;\n"
        "          interrupt-parent = <&PLIC>;\n"
        "          clock-frequency = <0x384000>;\n"
        "          reg = <0x0 0x10000000 0x0 0x100>;\n"
        "          compatible = \"ns16550a\";\n"
        "      };\n"
        "\n"
        "       PLIC: plic@c000000 {\n"
        "          compatible = \"riscv,plic0\";\n"
        "          interrupts-extended = <&CPU0_intc 0x0b &CPU0_intc 0x09>;\n"
        "          reg = <0x00 0xc000000 0x00 0x4000000>;\n"
        "          riscv,ndev = <0x35>;\n"
        "          interrupt-controller;\n"
        "          #interrupt-cells = <0x01>;\n"
        "          #address-cells = <0x00>;\n"
        "       };\n"
        "\n"
        "       clint@2000000 {\n"
        "          compatible = \"riscv,clint0\";\n"
        "          interrupts-extended = <&CPU0_intc 0x03 &CPU0_intc 0x07>;\n"
        "          reg = <0x00 0x2000000 0x00 0x10000>;\n"
        "       };\n"
        "    };"
        "\n"
        "};\n";

    size_t dts_len = sizeof(dts_str);

    // Convert the DTS to DTB
    int dts_pipe[2];
    pid_t dts_pid;

    fflush(NULL);  // flush stdout/stderr before forking

    if (pipe(dts_pipe) != 0 || (dts_pid = fork()) < 0) {
        printf("Failed to fork dts child\n");
        exit(1);
    }

    // Child process to output dts
    if (dts_pid == 0) {
        close(dts_pipe[0]);
        if (write(dts_pipe[1], dts_str, dts_len) == -1) {
            printf("Failed to write dts\n");
            exit(1);
        }
        close(dts_pipe[1]);

        /* FIXME:
         * 1. The allocated memory is implicitly free by OS.
         * 2. Will it be too inefficient to fork a process which already
         * allocated huge amount of memory? Considering to generate dtb before
         * initialize DRAM? */
        exit(0);
    }

    pid_t dtb_pid;

    if ((dtb_pid = fork()) < 0) {
        printf("Failed to fork dtb child\n");
        exit(1);
    }

    // Child process to output dtb
    if (dtb_pid == 0) {
        dup2(dts_pipe[0], STDIN_FILENO);  // redirect to stdin
        close(dts_pipe[0]);
        close(dts_pipe[1]);
        execlp("dtc", "dtc", "-O", "dtb", "-o", dtb_filename, (char *) 0);
        printf("Failed to run dtc\n");
        exit(1);
    }

    close(dts_pipe[1]);
    close(dts_pipe[0]);

    // Reap children
    int status;
    waitpid(dts_pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("Child dts process failed\n");
        exit(1);
    }
    waitpid(dtb_pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("Child dtb process failed\n");
        exit(1);
    }

    return true;
}

bool boot_init(struct rv32_boot *boot, u32 entry_addr, char *dtb)
{
    FILE *fp;

    if (!dtb) {
        if (!make_dtb())
            return false;
        fp = fopen(dtb_filename, "rb");
    } else
        fp = fopen(dtb, "rb");

    if (!fp) {
        printf("Invalid boot rom path.\n");
        return false;
    }
    fseek(fp, 0, SEEK_END);
    size_t sz = ftell(fp) * sizeof(u8);
    rewind(fp);

    u32 reset_vec[] = {
        0x00000297,             /* 1:  auipc  t0, %pcrel_hi(fw_dyn) */
        0x02828613,             /*     addi   a2, t0, %pcrel_lo(1b) */
        0xf1402573,             /*     csrr   a0, mhartid  */
        0x0202a583,             /*     lw     a1, 32(t0) */
        0x0182a283,             /*     lw     t0, 24(t0) */
        0x00028067,             /*     jr     t0 */
        entry_addr,             /* start: .dword */
        0x00000000, 0x00001028, /* fdt_laddr: .dword */
        0x00000000,
        /* fw_dyn: */
    };

    size_t boot_mem_size = sz + sizeof(reset_vec);
    boot->mem = malloc(boot_mem_size);
    if (!boot->mem) {
        printf("Error when allocating space through malloc for BOOT_DRAM\n");
        return false;
    }
    boot->size = boot_mem_size;
    // copy boot rom instruction to specific address
    memcpy(boot->mem, reset_vec, sizeof(reset_vec));
    // copy dtb to specific address
    size_t read_size = fread(boot->mem + sizeof(reset_vec), sizeof(u8), sz, fp);
    fclose(fp);
    if (read_size != sz) {
        printf("Error when reading binary through fread.\n");
        free(boot->mem);
        return false;
    }

    return true;
}

#if 0
void free_boot(riscv_boot *boot)
{
    free(boot->boot_mem);
}
#endif
