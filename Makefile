CC ?= gcc
CFLAGS = -Wall

nmrpd: nmrp.o tftp.o main.o
	$(CC) $(CFLAGS) -o nmrpd nmrp.o tftp.o main.o

nmrp.o: nmrp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o nmrp.o nmrp.c

tftp.o: tftp.c nmrpd.h
	$(CC) $(CFLAGS) -c -o tftp.o tftp.c

main.o: main.c nmrpd.h
	$(CC) $(CFLAGS) -c -o main.o main.c

clean:
	rm -f nmrp.o tftp.o main.o nmrpd

