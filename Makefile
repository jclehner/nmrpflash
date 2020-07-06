CC ?= gcc
PREFIX ?= /usr/local
VERSION = $(shell git describe --always | tail -c +2)
LIBS = -lpcap
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(VERSION)\"
LDFLAGS += $(LIBS)

ifeq ($(shell uname -s),Linux)
	CFLAGS += $(shell pkg-config libnl-route-3.0 --cflags)
	LIBS += $(shell pkg-config libnl-route-3.0 --libs)
endif

ifeq ($(shell uname -s),Darwin)
	AFL=afl-clang
else
	AFL=afl-gcc
endif

nmrpflash_OBJ = nmrp.o tftp.o ethsock.o main.o util.o

.PHONY: clean install release release/macos release/linux release/win32

nmrpflash: $(nmrpflash_OBJ)
	$(CC) $(CFLAGS) -o nmrpflash $(nmrpflash_OBJ) $(LDFLAGS)

tftptest:
	CFLAGS=-DNMRPFLASH_TFTP_TEST make clean nmrpflash

%.o: %.c nmrpd.h
	$(CC) -c $(CFLAGS) $< -o $@

fuzz_nmrp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ $^ -o $@

fuzz_tftp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ -DNMRPFLASH_FUZZ_TFTP $^ -o $@

dofuzz_tftp: fuzz
	echo core | sudo tee /proc/sys/kernel/core_pattern
	echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	afl-fuzz -i fuzzin/nmrp -o fuzzout/nmrp -- ./fuzz_tftp
	echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

clean:
	rm -f $(nmrpflash_OBJ) nmrpflash fuzz_nmrp fuzz_tftp

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
