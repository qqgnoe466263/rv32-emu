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
    * [WIP ] RV32F
    * [DONE] Privilege levels
    * [DONE] CSR
    * [DONE] Sv32
    * [DONE] UART
    * [DONE] CLINT
    * [DONE] PLIC
    * [DONE] VIRTIO
* Support Kernel
    * [WIP ] xv6-rv32 (some bug for current commit)
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

* Reference Output
    * Linux's CONFIG_FPU=n.
    * busybox.bin is produced by myself and it has some d/f instructions.
```shell
$ ./rv_emu --bios fw_jump.bin --kernel Image --rootfs busybox.bin --dtb dts/riscv_em.dtb

[    3.734323] EXT4-fs (vda): mounting ext2 file system using the ext4 subsystem
[    3.785606] EXT4-fs (vda): warning: mounting unchecked fs, running e2fsck is recommended
[    3.799403] EXT4-fs (vda): mounted filesystem without journal. Opts: (null)
[    3.801502] VFS: Mounted root (ext2 filesystem) on device 254:0.
[    3.806203] devtmpfs: mounted
[    3.814009] Freeing unused kernel memory: 192K
[    3.814907] This architecture does not have kernel memory protection.
[    3.816059] Run /sbin/init as init process
[    3.891741] init[1]: unhandled signal 4 code 0x1 at 0x001813c6 in busybox[10000+18d000]
[    3.893712] CPU: 0 PID: 1 Comm: init Not tainted 5.4.0 #125
[    3.894879] sepc: 001813c6 ra : 000c3f5a sp : 9c9a1de0
[    3.895960]  gp : 001a07c0 tp : 00000000 t0 : 00000000
[    3.897027]  t1 : 00000000 t2 : 00000000 s0 : 00000000
[    3.898111]  s1 : 00000000 a0 : 9c9a1f28 a1 : 00000000
[    3.899196]  a2 : 00000000 a3 : 0018134c a4 : 0000001e
[    3.900276]  a5 : 001813c4 a6 : 00000000 a7 : 00000000
[    3.901343]  s2 : 00000000 s3 : 00000000 s4 : 00000000
[    3.902410]  s5 : 00000000 s6 : 00000000 s7 : 00000000
[    3.903477]  s8 : 00000000 s9 : 00000000 s10: 00000000
[    3.904544]  s11: 00000000 t3 : 00000000 t4 : 00000000
[    3.905561]  t5 : 00000000 t6 : 00000000
[    3.906505] sstatus: 00000020 sbadaddr: 00000010 scause: 00000002
[    3.912163] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000004
[    3.913665] CPU: 0 PID: 1 Comm: init Not tainted 5.4.0 #125
[    3.914660] Call Trace:
[    3.915606] [<c00322c6>] walk_stackframe+0x0/0xa6
[    3.916822] [<c003243a>] show_stack+0x28/0x32
[    3.917930] [<c05fb9f4>] dump_stack+0x6a/0x86
[    3.919031] [<c0036eae>] panic+0xdc/0x23c
[    3.920104] [<c0038cf8>] do_exit+0x6f6/0x71a
[    3.921221] [<c00397d6>] do_group_exit+0x2a/0x7a
[    3.922382] [<c00425d4>] get_signal+0x108/0x6c0
[    3.923575] [<c0031ae2>] do_notify_resume+0x42/0x270
[    3.924809] [<c00313f0>] ret_from_exception+0x0/0xc
[    3.926011] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000004 ]---
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


