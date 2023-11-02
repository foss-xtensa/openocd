# SPDX-License-Identifier: GPL-2.0-or-later

BIN2C = ../../../../src/helper/bin2char.sh

CROSS_COMPILE ?= xt-

CC=$(CROSS_COMPILE)clang
OBJCOPY=$(CROSS_COMPILE)objcopy
OBJDUMP=$(CROSS_COMPILE)objdump

AFLAGS = -c -static -nostartfiles -mlittle-endian -mtext-section-literals
CFLAGS = -c -nostdlib -nostartfiles -Os -g -fPIC

all: xtkcml705fl.inc

.PHONY: clean

%.elf: %.S
	$(CC) $(AFLAGS) $< -o $@

%.lst: %.elf
	$(OBJDUMP) -S $< > $@

%.bin: %.elf
	$(OBJCOPY) -Obinary $< $@

%.inc: %.bin
	$(BIN2C) < $< > $@

clean:
	-rm -f *.elf *.lst *.bin *.inc
