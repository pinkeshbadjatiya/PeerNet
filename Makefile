CC=gcc
CFLAGS=-pthread

all: CLIENT SERVER


CLIENT: client.c
	$(CC) $(CFLAGS) client.c sha256.c -o CLIENT

SERVER: server.c
	$(CC) $(CFLAGS) server.c sha256.c -o SERVER

withoutWarnings: client.c server.c
	$(CC) $(CFLAGS) -w server.c sha256.c -o SERVER
	$(CC) $(CFLAGS) -w client.c sha256.c -o CLIENT


.PHONY: clean

clean:
	rm -f *.o CLIENT SERVER
