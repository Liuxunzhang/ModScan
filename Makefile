# ModScan Makefile
# Builds the modscan kernel module (.ko) and userspace CLI.
#
# Targets:
#   make              — build kernel module + CLI
#   make modules      — build kernel module only
#   make cli          — build userspace CLI only
#   make clean        — remove all build artefacts
#   make load         — build and insmod the kernel module (requires root)
#   make unload       — rmmod the kernel module (requires root)
#   make reload       — unload then load

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

# Kernel module object
obj-m := modscan.o

.PHONY: all modules cli clean load unload reload

all: modules cli

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

cli: modscan_cli
modscan_cli: modscan_cli.c
	$(CC) -O2 -Wall -Wextra -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f modscan_cli

load: all
	sudo insmod modscan.ko

unload:
	sudo rmmod modscan 2>/dev/null || true

reload: unload load
