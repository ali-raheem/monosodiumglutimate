CC=gcc
LIBS=-lsodium

msg:
	$(CC) $(LIBS) -o bin/msg src/msg.c
clean:
	rm msg signing.p*
