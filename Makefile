CC ?= gcc
PREFIX ?= /usr/local
CFLAGS = -Wall

.PHONY: clean install

nmrp-flash: nmrp.o tftp.o main.o
	$(CC) $(CFLAGS) -o nmrp-flash nmrp.o tftp.o main.o

nmrp.o: nmrp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o nmrp.o nmrp.c

tftp.o: tftp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o tftp.o tftp.c

main.o: main.c nmrpd.h
	$(CC) $(CFLAGS) -c -o main.o main.c

clean:
	rm -f nmrp.o tftp.o main.o nmrp-flash

install: nmrp-flash
	install -m 755 nmrp-flash $(PREFIX)/bin

