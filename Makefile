CC ?= gcc
PREFIX ?= /usr/local
VERSION = $(shell git describe --always | tail -c +2)
LIBS = -lpcap
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(VERSION)\"
LDFLAGS += $(LIBS)

nmrpflash_OBJ = nmrp.o tftp.o ethsock.o main.o util.o

.PHONY: clean install release release/osx release/linux release/win32

nmrpflash: $(nmrpflash_OBJ)
	$(CC) $(CFLAGS) -o nmrpflash $(nmrpflash_OBJ) $(LDFLAGS)

%.o: %.c nmrpd.h
	$(CC) -c $(CFLAGS) $< -o $@

fuzz: clean
	CC=afl-gcc CFLAGS=-DNMRPFLASH_FUZZ make nmrpflash
	mv nmrpflash fuzz

clean:
	rm -f nmrp.o tftp.o main.o ethsock.o nmrpflash

install: nmrpflash
	install -m 755 nmrpflash $(PREFIX)/bin

release/osx:
	CFLAGS="-arch i386 -arch x86_64 -mmacosx-version-min=10.6" make release
	zip nmrpflash-$(VERSION)-osx.zip nmrpflash

release/linux: release
	zip nmrpflash-$(VERSION)-linux.zip nmrpflash

release/win32:
	zip nmrpflash-$(VERSION)-win32.zip nmrpflash.exe

release: clean nmrpflash
	strip nmrpflash
