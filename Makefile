CC = gcc
LIBS = -lssl
WARNS = -Wall -Wextra -pedantic -Werror -Wno-unused-parameter
CFLAGS = $(WARNS) $(LIBS) -O3

all: tripcode sectrip tripfind secfind tripfind-regex secfind-regex

tripcode: tripcode.c
	$(CC) -o $@ $(CFLAGS) tripcode.c

sectrip: tripcode.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP tripcode.c

tripfind: tripfind.c
	$(CC) -o $@ $(CFLAGS) tripfind.c

secfind: tripfind.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP tripfind.c

tripfind-regex: tripfind.c
	$(CC) -o $@ $(CFLAGS) -DUSE_REGEX tripfind.c

secfind-regex: tripfind.c salt.h
	$(CC) -o $@ $(CFLAGS) -DUSE_REGEX -DSECURE_TRIP tripfind.c

clean:
	rm -f tripcode sectrip tripfind secfind tripfind-regex secfind-regex
