CC ?= gcc
PREFIX ?= /usr/local
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(shell git describe --always)\"
LIBS = -lpcap

.PHONY: clean install release release/osx release/linux

nmrpflash: nmrp.o tftp.o ethsock.o main.o
	$(CC) $(CFLAGS) -o nmrpflash nmrp.o tftp.o ethsock.o main.o $(LIBS)

nmrp.o: nmrp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o nmrp.o nmrp.c

tftp.o: tftp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o tftp.o tftp.c

ethsock.o: ethsock.c nmrpd.h
	$(CC) $(CFLAGS) -c -o ethsock.o ethsock.c

main.o: main.c nmrpd.h
	$(CC) $(CFLAGS) -c -o main.o main.c

clean:
	rm -f nmrp.o tftp.o main.o ethsock.o nmrpflash nmrpflash.exe

install: nmrpflash
	install -m 755 nmrpflash $(PREFIX)/bin

release/osx:
	CFLAGS="-arch i686 -arch x86_64" make release

release/linux: release
	cp nmrpflash binaries/linux/

release: clean nmrpflash
	strip nmrpflash
