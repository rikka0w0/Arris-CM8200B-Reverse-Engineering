readme
======



This is a forked repo which contains the outcome of the reverse engineering work performed on Arris CM8200 __B__ __P2__.

# Files
* sb8200.bootlog - Dumped bootlog of SB8200 from [Re: SB8200 32x8 3.1 cable modem - Feedback and Results thread](https://www.dslreports.com/forum/r31438248-) provided by [mackey of DSLReports.com forums](https://www.dslreports.com/profile/1479488)
* spi.bin - Dumped from the SPI Flash (W25Q32)
* spi_decoded/ - Decoded structures of the spi.bin, sorted by address
* pictures/ - Contains pictures of CM8200B P2 and related products
* tools/ - Some of the tools which may help with reverse engineering
* docs/asuswrt-merlin.ng/release/src-rt-5.02hnd - Mirrored copy of [RMerl/asuswrt.ng/release/src-rt-5.02hnd](https://github.com/RMerl/asuswrt-merlin.ng/tree/master/release/src-rt-5.02hnd)
* oss/ - [Commscope 8200 Cable Modem OSS](https://sourceforge.net/projects/c8200-cable-modem.arris/files/) open source software. Directory contains `split` files