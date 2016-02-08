CC ?= gcc
PREFIX ?= /usr/local
CFLAGS += -Wall -g
LIBS = -lpcap

.PHONY: clean install release release/osx release/linux

nmrp-flash: nmrp.o tftp.o ethsock.o main.o
	$(CC) $(CFLAGS) -o nmrp-flash nmrp.o tftp.o ethsock.o main.o $(LIBS)

nmrp.o: nmrp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o nmrp.o nmrp.c

tftp.o: tftp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o tftp.o tftp.c

ethsock.o: ethsock.c nmrpd.h
	$(CC) $(CFLAGS) -c -o ethsock.o ethsock.c

main.o: main.c nmrpd.h
	$(CC) $(CFLAGS) -c -o main.o main.c

clean:
	rm -f nmrp.o tftp.o main.o ethsock.o nmrp-flash nmrp-flash.exe

install: nmrp-flash
	install -m 755 nmrp-flash $(PREFIX)/bin

release/osx:
	make release CFLAGS="-arch i686 -arch x86_64"

release/linux: release

release: clean nmrp-flash
	strip nmrp-flash
