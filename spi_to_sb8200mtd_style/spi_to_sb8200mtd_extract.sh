#!/usr/bin/env bash
# Extract SPI flash data based on the offsets from SB8200
# 0x000000000000-0x000000100000 : "flash0.bolt"
dd if=spi8388.0.bin of=00-flash0.bolt bs=1 count=$((0x0100000))
# 0x000000100000-0x000000120000 : "flash0.macadr"
dd if=spi8388.0.bin of=01-flash0.macadr bs=1 skip=$((0x0100000)) count=$((0x0120000-0x0100000))
# 0x000000120000-0x000000140000 : "flash0.nvram"
dd if=spi8388.0.bin of=02-flash0.nvram bs=1 skip=$((0x0120000)) count=$((0x0140000-0x0120000))
# 0x000000140000-0x000000160000 : "flash0.nvram1"
dd if=spi8388.0.bin of=03-flash0.nvram1 bs=1 skip=$((0x0140000)) count=$((0x0160000-0x0140000))
# 0x000000160000-0x000000180000 : "flash0.devtree0"
dd if=spi8388.0.bin of=04-flash0.devtree0 bs=1 skip=$((0x0160000)) count=$((0x0180000-0x0160000))
# 0x000000180000-0x0000001a0000 : "flash0.devtree1"
dd if=spi8388.0.bin of=05-flash0.devtree1 bs=1 skip=$((0x0180000)) count=$((0x01a0000-0x0180000))
# 0x0000001a0000-0x000000200000 : "flash0.cmnonvol0"
dd if=spi8388.0.bin of=06-flash0.cmnonvol0 bs=1 skip=$((0x01a0000)) count=$((0x0200000-0x01a0000))
# 0x000000200000-0x000000260000 : "flash0.cmnonvol1"
dd if=spi8388.0.bin of=07-flash0.cmnonvol1 bs=1 skip=$((0x0200000)) count=$((0x0260000-0x0200000))
# 0x000000260000-0x000000930000 : "flash0.rgnonvol0"
dd if=spi8388.0.bin of=08-flash0.rgnonvol0 bs=1 skip=$((0x0260000)) count=$((0x0930000-0x0260000))
# 0x000000930000-0x000001000000 : "flash0.rgnonvol1"
dd if=spi8388.0.bin of=09-flash0.rgnonvol1 bs=1 skip=$((0x0930000)) count=$((0x01000000-0x00930000))
