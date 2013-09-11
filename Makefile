CC = gcc
LIBS = -lcrypto -lssl
WARNS = -Wall -Wextra -pedantic -Werror -Wno-unused-parameter
CFLAGS := $(WARNS) $(LIBS) -O3 $(CFLAGS)
TARGS = tripcode sectrip tripfind secfind tripfind-regex secfind-regex

ifdef NO_SJIS
TRIPFLAGS = $(CFLAGS)
else
TRIPFLAGS = $(CFLAGS) -DSJIS_CONVERT
endif

all: $(TARGS)

tripcode: tripcode.c
	$(CC) -o $@ $(TRIPFLAGS) $<

sectrip: tripcode.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP $<

tripfind: tripfind.c
	$(CC) -o $@ $(CFLAGS) $<

secfind: tripfind.c salt.h
	$(CC) -o $@ $(CFLAGS) -DSECURE_TRIP $<

tripfind-regex: tripfind.c
	$(CC) -o $@ $(CFLAGS) -DUSE_REGEX $<

secfind-regex: tripfind.c salt.h
	$(CC) -o $@ $(CFLAGS) -DUSE_REGEX -DSECURE_TRIP $<

.PHONY: clean
clean:
	rm -f $(TARGS)
