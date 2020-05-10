CC ?= gcc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
VERSION = $(shell git describe --always | tail -c +2)
LIBS = -lpcap
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(VERSION)\"
LDFLAGS += $(LIBS)

ifeq ($(shell uname -s),Linux)
	CFLAGS += $(shell $(PKG_CONFIG) libnl-route-3.0 --cflags)
	LIBS += $(shell $(PKG_CONFIG) libnl-route-3.0 --libs)
endif

nmrpflash_OBJ = nmrp.o tftp.o ethsock.o main.o util.o

.PHONY: clean install release release/macos release/linux release/win32

nmrpflash: $(nmrpflash_OBJ)
	$(CC) $(CFLAGS) -o nmrpflash $(nmrpflash_OBJ) $(LDFLAGS)

tftptest:
	CFLAGS=-DNMRPFLASH_TFTP_TEST make clean nmrpflash

%.o: %.c nmrpd.h
	$(CC) -c $(CFLAGS) $< -o $@

fuzz: clean
	CC=afl-gcc CFLAGS=-DNMRPFLASH_FUZZ make nmrpflash
	mv nmrpflash fuzz

dofuzz: fuzz
	echo core | sudo tee /proc/sys/kernel/core_pattern
	echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	afl-fuzz -i fuzzin -o fuzzout -- ./fuzz
	echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
clean:
	rm -f $(nmrpflash_OBJ) nmrpflash

install: nmrpflash
	install -m 755 nmrpflash $(PREFIX)/bin

release/macos:
	CFLAGS="-mmacosx-version-min=10.6" make release
	zip nmrpflash-$(VERSION)-macos.zip nmrpflash

release/linux: release
	zip nmrpflash-$(VERSION)-linux.zip nmrpflash

release/win32:
	zip nmrpflash-$(VERSION)-win32.zip nmrpflash.exe

release: clean nmrpflash
	strip nmrpflash
