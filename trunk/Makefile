CC=gcc

CFLAGS=-Wall -march=native -O3
#CFLAGS=-Wall -march=native -O2 -pg
#CFLAGS=-Wall -march=native -O0 -g

LDLIBS=-lpcap -lssl -lpthread

#CFLAGS += -I/usr/include/pcap
#CFLAGS += -DOLDPCAP

main: execap


execap: execap.o findexe.o pavl.o
	$(CC) $(CFLAGS) execap.o findexe.o pavl.o -o execap ${LDLIBS}

execap.o: execap.c execap.h
	$(CC) $(CFLAGS) -c execap.c

findexe.o: findexe.c execap.h
	$(CC) $(CFLAGS) -c findexe.c

pavl.o: pavl.c pavl.h
	$(CC) $(CFLAGS) -c pavl.c

clean:
	rm -f execap
	rm -f *.o
	rm -f *~
