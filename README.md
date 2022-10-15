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

* Build riscv32 toolchain:
    * Without Float/Double.
```shell
$ git clone https://github.com/riscv-collab/riscv-gnu-toolchain.git
$ cd riscv-gnu-toolchain
$ ./configure --prefix=/opt/riscv --with-arch=rv32imac --with-abi=ilp32
$ sudo make -j4
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
$ vim .config
...
CONFIG_FPU=n
...

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

### Run Linux with OpenSBI

* Reference Output
    * FIXME: UART has bugs.
```shell
$ ./rv_emu --bios fw_jump.bin --kernel Image --rootfs busybox.bin --dtb dts/riscv_em.dtb

[    3.433362] virtio_blk virtio0: [vda] 65536 512-byte logical blocks (33.6 MB/32.0 MiB)
[    3.477636] libphy: Fixed MDIO Bus: probed
[    3.503936] e1000e: Intel(R) PRO/1000 Network Driver - 3.2.6-k
[    3.505020] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
[    3.509911] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[    3.511084] ehci-pci: EHCI PCI platform driver
[    3.513450] ehci-platform: EHCI generic platform driver
[    3.516399] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[    3.517527] ohci-pci: OHCI PCI platform driver
[    3.519893] ohci-platform: OHCI generic platform driver
[    3.528264] usbcore: registered new interface driver uas
[    3.531347] usbcore: registered new interface driver usb-storage
[    3.536688] mousedev: PS/2 mouse device common for all mice
[    3.547580] usbcore: registered new interface driver usbhid
[    3.548594] usbhid: USB HID core driver
[    3.589643] NET: Registered protocol family 10
[    3.614942] Segment Routing with IPv6
[    3.618890] sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
[    3.643992] NET: Registered protocol family 17
[    3.654559] 9pnet: Installing 9P2000 support
[    3.656964] Key type dns_resolver registered
[    3.691009] EXT4-fs (vda): mounting ext2 file system using the ext4 subsystem
[    3.741424] EXT4-fs (vda): warning: mounting unchecked fs, running e2fsck is recommended
[    3.755032] EXT4-fs (vda): mounted filesystem without journal. Opts: (null)
[    3.757121] VFS: Mounted root (ext2 filesystem) on device 254:0.
[    3.761763] devtmpfs: mounted
[    3.769553] Freeing unused kernel memory: 192K
[    3.770454] This architecture does not have kernel memory protection.
[    3.771604] Run /sbin/init as init process
can't run '/etc 

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


