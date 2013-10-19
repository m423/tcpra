CC=gcc
CFLAGS=-g -Wall -D_BSD_SOURCE
LDFLAGS=-lpcap
EXEC=tcpra

all: $(EXEC)

tcpra: tcpra.o tcpra_main.o
	$(CC) -o tcpra tcpra.o tcpra_main.o $(LDFLAGS)

tcpra.o: tcpra.c
	$(CC) -o tcpra.o -c tcpra.c $(CFLAGS)

tcpra_main.o: tcpra_main.c tcpra.h
	$(CC) -o tcpra_main.o -c tcpra_main.c $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)