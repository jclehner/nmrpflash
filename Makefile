CC ?= gcc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
VERSION := $(shell if [ -d .git ] && which git 2>&1 > /dev/null; then git describe --always | tail -c +2; else echo $$STANDALONE_VERSION; fi)
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(VERSION)\"
LDFLAGS += -ldl
SUFFIX ?=
MACOS_SDK ?= macosx11.1

ifeq ($(shell uname -s),Linux)
	CFLAGS += $(shell $(PKG_CONFIG) libnl-route-3.0 --cflags)
	CFLAGS += $(shell $(PKG_CONFIG) libpcap --cflags)
	LDFLAGS += $(shell $(PKG_CONFIG) libnl-route-3.0 --libs)
	LDFLAGS += $(shell $(PKG_CONFIG) libpcap --libs)
else
	LDFLAGS += -lpcap
endif

ifeq ($(shell uname -s),Darwin)
	AFL=afl-clang
	SYSROOT ?= $(shell xcrun --sdk $(MACOS_SDK) --show-sdk-path)
else
	AFL=afl-gcc
endif

nmrpflash_OBJ = nmrp.o tftp.o ethsock.o main.o util.o

.PHONY: clean install release release/macos release/linux release/win32

nmrpflash$(SUFFIX): $(nmrpflash_OBJ)
	$(CC) $(CFLAGS) -o nmrpflash$(SUFFIX) $(nmrpflash_OBJ) $(LDFLAGS)

tftptest:
	CFLAGS=-DNMRPFLASH_TFTP_TEST make clean nmrpflash

%.o: %.c nmrpd.h
	$(CC) -c $(CFLAGS) $< -o $@

fuzz_nmrp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ $^ -o $@

fuzz_tftp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ -DNMRPFLASH_FUZZ_TFTP $^ -o $@

dofuzz_tftp: fuzz_tftp
	echo core | sudo tee /proc/sys/kernel/core_pattern
	echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	afl-fuzz -i fuzzin/tftp -o fuzzout/tftp -- ./fuzz_tftp fuzzin/tftp.bin
	echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

clean:
	rm -f $(nmrpflash_OBJ) nmrpflash nmrpflash.exe fuzz_nmrp fuzz_tftp

install: nmrpflash
	install -d $(PREFIX)/bin
	install -s -m 755 nmrpflash $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/nmrpflash

release/macos:
	CFLAGS="-isysroot $(SYSROOT) -target arm64-apple-macos11" SUFFIX=".arm64" make release
	CFLAGS="-isysroot $(SYSROOT) -target x86_64-apple-macos10.8" SUFFIX=".x86_64" make release
	lipo -create -output nmrpflash nmrpflash.x86_64 nmrpflash.arm64
	zip nmrpflash-$(VERSION)-macos.zip nmrpflash
	rm -f nmrpflash.x86_64 nmrpflash.arm64

release/linux: release
	zip nmrpflash-$(VERSION)-linux.zip nmrpflash

release/win32:
	zip nmrpflash-$(VERSION)-win32.zip nmrpflash.exe

release: clean nmrpflash$(SUFFIX)
	strip nmrpflash$(SUFFIX)

nmrpflash.ico: nmrpflash.svg
	convert -background transparent -define icon:auto-resize=256,64,48,32,16 $< $@
