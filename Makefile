CC=gcc
CFLAGS=-Wall -O2 -Wno-deprecated-declarations
LIBS=-lcrypto -lsqlite3 -lz
OBJS=FileWatcher.o chunker.o dbutils.o verify.o restore.o list.o prune.o codec.o

FileWatcher: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) FileWatcher
