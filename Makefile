default: spoofarp

CFLAGS+=	-O -ggdb -I/usr/local/include
LDFLAGS+=	-L/usr/local/lib -lnet -lpcap

spoofarp: spoofarp.o

clean:
	rm -f *.o spoofarp
