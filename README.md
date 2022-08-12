# rv32-emu

* This is a learning purpose project for myself and it is porting from [sysprog21/semu](https://github.com/jserv/semu) but semu is 64bits riscv emulator. Now it currently supports basic RV32G and it can boot the xv6-rv32 kernel. It might be incomplete and have bug, so if somebody want to discussion about that, welcome to contact me :).
* These are my reference project and study resources.
    * [RinHizakura/riscv-emulator](https://github.com/RinHizakura/riscv-emulator)
    * [sysprog21/rv32emu](https://github.com/sysprog21/rv32emu)
    * [sysprog21/semu](https://github.com/jserv/semu)
* Support features
    * [DONE] RV32G
    * [TODO] RV32C 
    * [DONE] Privilege levels
    * [DONE] CSR
    * [DONE] Sv32
    * [DONE] UART
    * [DONE] CLINT
    * [DONE] PLIC
    * [DONE] VIRTIO

## Build and Run

* Build the rv32-emu:
```shell
$ make
```

* Run the rv32-emu (a little bit slow):
```shell
$ ./rv32-emu kernel fs.img

xv6 kernel is booting

init: starting sh
$
```

## Compliance Test

* Build and test:
```shell
$ make CONFIG_ARCH_TEST=1 arch-test
```


