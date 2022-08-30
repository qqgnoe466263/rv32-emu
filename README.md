# rv32-emu

* This is a learning purpose project for myself and it is porting from [sysprog21/semu](https://github.com/jserv/semu). rv32-emu is a 32bits version of semu and currently supports basic RV32GC and it can boot the [xv6-rv32](https://github.com/michaelengel/xv6-rv32) kernel. It might be incomplete and have bugs, if somebody want to discussion about that, welcome to contact me :).
* These are my reference project and study resources.
    * [RinHizakura/riscv-emulator](https://github.com/RinHizakura/riscv-emulator)
    * [sysprog21/rv32emu](https://github.com/sysprog21/rv32emu)
    * [sysprog21/semu](https://github.com/jserv/semu)
    * [franzflasch/riscv_em](https://github.com/franzflasch/riscv_em)
* Support features
    * [DONE] RV32G
    * [WIP ] RV32C
    * [DONE] Privilege levels
    * [DONE] CSR
    * [DONE] Sv32
    * [DONE] UART
    * [DONE] CLINT
    * [DONE] PLIC
    * [DONE] VIRTIO
* Support Kernel
    * [DONE] xv6-rv32
    * [WIP ] Linux kernel v5.4

## Build

* Build the rv32-emu:
```shell
$ make
```

* Build the u-boot:
```shell
$ git clone https://github.com/u-boot/u-boot.git
$ export CROSS_COMPILE=/<pathto>/riscv32-unknown-linux-gnu-
$ make

```
* Build the Opensbi:
```shell
$ git clone https://github.com/starfive-tech/opensbi.git
$ cd opensbi
$ export CROSS_COMPILE=/<pathto>/riscv32-unknown-linux-gnu-
$ make PLATFORM="generic" FW_PAYLOAD_PATH=../u-boot/u-boot.bin
```

* Build the Linux Kernel(v5.4)
```shell
$ git clone https://github.com/torvalds/linux
$ cd linux
$ git checkout v5.4
$ make ARCH=riscv CROSS_COMPILE=/<pathto>/riscv32-unknown-linux-gnu- rv32_defconfig
$ make ARCH=riscv CROSS_COMPILE=/<pathto>/riscv32-unknown-linux-gnu- -j4

$ ls arch/riscv/boot/Image
```
### Run xv6-rv32

* Output (a little bit slow):
```shell
$ ./rv_emu --elf xv6-rv32/kernel --rootfs xv6-rv32/fs.img

xv6 kernel is booting

init: starting sh
$

```

### Run Opensbi with U-boot

* Output
```shell
$ ./rv_emu --bios fw_payload.bin

OpenSBI VF_SDK_510_V1.2.1
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name             : rv32-emu
Platform Features         : medeleg
Platform HART Count       : 1
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 10000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : ---
Platform Reboot Device    : ---
Platform Shutdown Device  : ---
Firmware Base             : 0x80000000
Firmware Size             : 204 KB
Runtime SBI Version       : 0.3

Domain0 Name              : root
Domain0 Boot HART         : 0
Domain0 HARTs             : 0*
Domain0 Region00          : 0x02000000-0x0200ffff (I)
Domain0 Region01          : 0x80000000-0x8003ffff ()
Domain0 Region02          : 0x00000000-0xffffffff (R,W,X)
Domain0 Next Address      : 0x80400000
Domain0 Next Arg1         : 0x82200000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes

Boot HART ID              : 0
Boot HART Domain          : root
Boot HART ISA             : rv32imacsu
Boot HART Features        : scounteren,mcounteren,mcountinhibit,sscofpmf,time
Boot HART PMP Count       : 64
Boot HART PMP Granularity : 4
Boot HART PMP Address Bits: 32
Boot HART MHPM Count      : 29
Boot HART MIDELEG         : 0x00002222
Boot HART MEDELEG         : 0x0000b109

U-Boot 2022.10-rc3-00062-g4e10c1227a-dirty (Sep 05 2022 - 00:46:20 +0800)

CPU:   rv32imacsu
Model: rv32-emu
DRAM:  128 MiB
Core:  13 devices, 9 uclasses, devicetree: board
Loading Environment from nowhere... OK
In:    uart@10000000
Out:   uart@10000000
Err:   uart@10000000
Net:   No ethernet found.
Hit any key to stop autoboot:  1
 0
=> bdinfo

......
```

### Run Linux with OpenSBI [WIP]

* Output
```shell
$ ./rv_emu --bios fw_jump.bin --kernel Image

...
[    3.964569] Key type dns_resolver registered
[    3.964569] Key type dns_resolver registered
[    3.993910] VFS: Cannot open root device "vda" or unknown-block(0,0): error -6
[    3.993910] VFS: Cannot open root device "vda" or unknown-block(0,0): error -6
[    3.998116] Please append a correct "root=" boot option; here are the available partitions:
[    3.998116] Please append a correct "root=" boot option; here are the available partitions:
[    4.003153] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    4.003153] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    4.008104] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-dirty #31
[    4.008104] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-dirty #31
[    4.011831] Call Trace:
[    4.011831] Call Trace:
[    4.013780] [<c0032602>] walk_stackframe+0x0/0xa6
[    4.013780] [<c0032602>] walk_stackframe+0x0/0xa6
[    4.016916] [<c0032776>] show_stack+0x28/0x32
[    4.016916] [<c0032776>] show_stack+0x28/0x32
[    4.019804] [<c05fbe4a>] dump_stack+0x6a/0x86
[    4.019804] [<c05fbe4a>] dump_stack+0x6a/0x86
[    4.022686] [<c0037300>] panic+0xdc/0x23c
[    4.022686] [<c0037300>] panic+0xdc/0x23c
[    4.025405] [<c0000efa>] mount_block_root+0x182/0x214
[    4.025405] [<c0000efa>] mount_block_root+0x182/0x214
[    4.028656] [<c0001076>] mount_root+0xea/0x100
[    4.028656] [<c0001076>] mount_root+0xea/0x100
[    4.031614] [<c0001190>] prepare_namespace+0x104/0x14c
[    4.031614] [<c0001190>] prepare_namespace+0x104/0x14c
[    4.034937] [<c0000b9a>] kernel_init_freeable+0x18a/0x1a6
[    4.034937] [<c0000b9a>] kernel_init_freeable+0x18a/0x1a6
[    4.038443] [<c0611520>] kernel_init+0x12/0xf0
[    4.038443] [<c0611520>] kernel_init+0x12/0xf0
[    4.041426] [<c0031400>] ret_from_exception+0x0/0xc
[    4.041426] [<c0031400>] ret_from_exception+0x0/0xc
[    4.044627] ---[ end Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0) ]---
[    4.044627] ---[ end Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0) ]---
```
## Compliance Test

* Passed Tests
    * `I` : Base Integer Instruction Set
    * `M` : Standard Extension for Integer Multiplication and Division

* Failed Tests
    * `C` : Standard Extension for Compressed Instruction
        * c.ebreak

* Build and test:
```shell
$ make clean

$ make CONFIG_ARCH_TEST=1 arch-test RISCV_DEVICE=I
$ make CONFIG_ARCH_TEST=1 arch-test RISCV_DEVICE=M
$ make CONFIG_ARCH_TEST=1 arch-test RISCV_DEVICE=C
```


