CC = gcc
LIBS = -lssl
WARNS = -Wall -Wextra -pedantic -Werror -Wno-unused-parameter
CFLAGS = $(WARNS) $(LIBS) -O3

all: tripcode sectrip tripfind secfind

tripcode: tripcode.c
	$(CC) -o $@ $(CFLAGS) tripcode.c

sectrip: tripcode.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP tripcode.c

tripfind: tripfind.c
	$(CC) -o $@ $(CFLAGS) tripfind.c

secfind: tripfind.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP tripfind.c
