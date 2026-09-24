# LME2511 DTMB USB dongle Linux DVB driver — out-of-tree Makefile
#
# Build:  make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# Install: make install
# Clean:   make clean

obj-m += lme2511.o

lme2511-objs := src/lme2511_core.o \
		  src/lme2511_i2c.o \
		  src/lme2511_mcu.o \
		  src/lme2511_fw.o \
		  src/lgs8gl5.o \
		  src/max2165.o \
		  src/lme2511_status.o

# ── dvb_usb.h is a private kernel header (not exported by linux-headers).
# All its <...> dependencies are exported headers — only this file is missing.
# Run "make fetch-headers" once, or download manually:
#   wget -O dvb_usb.h https://raw.githubusercontent.com/torvalds/linux/\
#     master/drivers/media/usb/dvb-usb-v2/dvb_usb.h
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

ccflags-y := -Wno-declaration-after-statement -fno-ipa-sra \
	-DCONFIG_DVB_CORE_MODULE -DCONFIG_DVB_NET=1 \
	-DCONFIG_DVB_USB_V2_MODULE -DCONFIG_MEDIA_DIGITAL_TV_SUPPORT=1

FIRMWARE_SRC := firmware/rom.dat firmware/fw_new.bin
FIRMWARE_DST := dvb-usb-lme2511.fw
FIRMWARE_DIR  := /lib/firmware
MODPROBE_DIR  := /etc/modprobe.d
BLACKLIST_CONF := $(MODPROBE_DIR)/lme2511.conf

# ── Kernel module build ────────────────────────────────────────

all: modules

modules:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
	rm -f $(FIRMWARE_DST)

# ── Build firmware blob ─────────────────────────────────────────

$(FIRMWARE_DST): $(FIRMWARE_SRC)
	cat $^ > $@

# ── Install ─────────────────────────────────────────────────────

install: modules $(FIRMWARE_DST)
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules_install
	@echo "  INSTALL $(FIRMWARE_DIR)/$(FIRMWARE_DST)"
	install -m 0644 $(FIRMWARE_DST) $(FIRMWARE_DIR)/
	@echo "  INSTALL $(BLACKLIST_CONF)"
	@mkdir -p $(MODPROBE_DIR)
	@echo '# Blacklist lmedm04 — conflicts with lme2511 (same VID/PID)' \
		> $(BLACKLIST_CONF)
	@echo 'blacklist dvb_usb_lmedm04' >> $(BLACKLIST_CONF)
	@echo 'install dvb_usb_lmedm04 /bin/false' >> $(BLACKLIST_CONF)
	depmod -a
	@echo ""
	@echo "================================"
	@echo "  Install complete."
	@echo "  Firmware:  $(FIRMWARE_DIR)/$(FIRMWARE_DST)"
	@echo "  Blacklist: $(BLACKLIST_CONF)"
	@echo ""
	@echo "  To load the driver:"
	@echo "    sudo modprobe lme2511"
	@echo "================================"

uninstall:
	rm -f $(FIRMWARE_DIR)/$(FIRMWARE_DST)
	rm -f $(BLACKLIST_CONF)
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

# ── Fetch dvb_usb.h ──────────────────────────────────────────────
#
# dvb_usb.h lives in drivers/media/usb/dvb-usb-v2/ — a private header
# NOT shipped in linux-headers packages.  All 9 <...> deps inside it
# are exported headers, so only this one file is needed.
#
# Sources tried in order:
#   1. Local kernel source / headers tree
#   2. GitHub mirror (raw.githubusercontent.com/torvalds/linux)

DVB_USB_URL := https://raw.githubusercontent.com/torvalds/linux/\
	master/drivers/media/usb/dvb-usb-v2/dvb_usb.h

fetch-headers:
	@echo "==> Fetching dvb_usb.h..."
	@if [ -f "$(KERNEL_SRC)/drivers/media/usb/dvb-usb-v2/dvb_usb.h" ]; then \
		echo "  Found in local kernel tree, copying..."; \
		cp -v "$(KERNEL_SRC)/drivers/media/usb/dvb-usb-v2/dvb_usb.h" src/ ; \
	elif command -v wget >/dev/null 2>&1; then \
		echo "  Downloading from GitHub mirror..."; \
		wget -O src/dvb_usb.h "$(DVB_USB_URL)"; \
	elif command -v curl >/dev/null 2>&1; then \
		echo "  Downloading from GitHub mirror..."; \
		curl -L -o src/dvb_usb.h "$(DVB_USB_URL)"; \
	else \
		echo "ERROR: need wget or curl."; \
		exit 1; \
	fi
	@echo "  OK — dvb_usb.h is ready."

.PHONY: all modules clean install uninstall fetch-headers
