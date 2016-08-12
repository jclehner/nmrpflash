CC ?= gcc
PREFIX ?= /usr/local
VERSION = $(shell git describe --always | tail -c +2)
LIBS = -lpcap
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"v$(VERSION)\"
LDFLAGS += $(LIBS)

.PHONY: clean install release release/osx release/linux release/win32

nmrpflash: nmrp.o tftp.o ethsock.o main.o
	$(CC) $(CFLAGS) -o nmrpflash nmrp.o tftp.o ethsock.o main.o $(LDFLAGS)

nmrp.o: nmrp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o nmrp.o nmrp.c

tftp.o: tftp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o tftp.o tftp.c

ethsock.o: ethsock.c nmrpd.h
	$(CC) $(CFLAGS) -c -o ethsock.o ethsock.c

main.o: main.c nmrpd.h
	$(CC) $(CFLAGS) -c -o main.o main.c

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
