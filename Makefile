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

.PHONY: all modules cli tools clean load unload reload check

# ── Default: build everything ─────────────────────────────────────────────────
all: modules cli tools

# ── Kernel module (.ko) ───────────────────────────────────────────────────────
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ── Userspace CLI (requires modscan.ko loaded) ────────────────────────────────
cli: modscan_cli
modscan_cli: modscan_cli.c
	$(CC) -O2 -Wall -Wextra -o $@ $<

# ── No-module-required tools ──────────────────────────────────────────────────
# Use when the rootkit has disabled module loading.
tools: modscan_kcore
	@chmod +x modscan_scan.sh

modscan_kcore: modscan_kcore.c
	$(CC) -O2 -Wall -Wextra -std=gnu99 -o $@ $<

# ── Load / unload helpers ─────────────────────────────────────────────────────
load: modules
	sudo insmod modscan.ko

unload:
	sudo rmmod modscan 2>/dev/null || true

reload: unload load

# ── Quick scan (no module loading required) ───────────────────────────────────
check: tools
	@echo "--- Shell scanner (no module needed) ---"
	sudo bash modscan_scan.sh; true
	@echo
	@echo "--- Kcore scanner (no module needed) ---"
	sudo ./modscan_kcore; true

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f modscan_cli modscan_kcore
