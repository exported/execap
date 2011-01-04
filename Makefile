CC=gcc

CFLAGS=-Wall -march=native -O3
#CFLAGS=-Wall -march=native -O2 -pg
#CFLAGS=-Wall -march=native -O0 -g

LDLIBS=-lpcap -lssl

CFLAGS += -I/usr/include/pcap

main: execap


execap: execap.o pavl.o
	$(CC) $(CFLAGS) execap.o pavl.o -o execap ${LDLIBS}

execap.o: execap.c
	$(CC) $(CFLAGS) -c execap.c

pavl.o: pavl.c pavl.h
	$(CC) $(CFLAGS) -c pavl.c

clean:
	rm -f execap
	rm -f *.o
	rm -f *~
