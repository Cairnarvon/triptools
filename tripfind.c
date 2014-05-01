#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifdef USE_REGEX

#include <regex.h>

#endif

#ifndef SECURE_TRIP

#include <openssl/des.h>

const char *salt = "................................"
                   ".............../0123456789ABCDEF"
                   "GABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
                   "fabcdefghijklmnopqrstuvwxyz.....";

#else

#include <openssl/sha.h>
#include "salt.h"

extern const unsigned char salt[];

const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                  "ghijklmnopqrstuvwxyz0123456789+/";

#endif

unsigned int p_id = 0;
unsigned long checked = 0;
struct timeval t_begin;


void usage(char*);
int validate_target(char*);
void done(int);


int main(int argc, char **argv)
{
    char *set = "!$%'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\"
                "]^_`abcdefghijklmnopqrstuvwxyz{|}~",
         *target = argv[argc - 1];

#ifndef SECURE_TRIP

    char cap[9],            /* capword */
         s[2],              /* salt */
         c_ret[14],         /* crypt return */
         *trip = c_ret + 3; /* tripcode */

#else

    char trip[16];                          /* tripcode */
    unsigned char  cap[8 + sizeof(salt)],   /* SHA1 input */
                  *sectrip_bin;             /* SHA1 return */

#endif

    int len_set = strlen(set),
        procs = 1,
        do_random = 0,
        srt, stp,               /* beginning and end of search processes */
        opt,
        i;
    char *c[8];

#ifdef USE_REGEX

    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;

#else

    char *(*matcher)(const char*, const char*) = &strstr;

#endif


    if (argc < 2) usage(argv[0]);

    /* Parse options */
    while ((opt = getopt(argc, argv, "rp:ih")) != -1) {
        switch (opt) {
        case 'r':
            do_random = 1;
            break;
        case 'p':
            procs = atoi(optarg);
            break;
        case 'i':

#ifndef USE_REGEX

#ifdef _GNU_SOURCE
            matcher = &strcasestr;
#else
            fprintf(stderr, "\033[1;31mOops!\033[0m Case insensitive matching "
                            "not supported!\nTo enable it, recompile with "
                            "\033[1m-D_GNU_SOURCE\033[0m (if you're using "
                            "glibc).\n");
#endif

#else
            cflags |= REG_ICASE;
#endif

            break;
        default:
            usage(argv[0]);
        }
    }

#ifndef USE_REGEX

    /* Validate target */
    if (!validate_target(target)) {
            fprintf(stderr,
                    "Invalid target \033[1m%s\033[0m: too long or not in "
#ifndef SECURE_TRIP
                    "[A-Za-z0-9./].\n",
#else
                    "[A-Za-z0-9+/].\n",
#endif
                    target);
            return 2;
    }

#else

    if (regcomp(&preg, target, cflags) != 0) {
        fprintf(stderr, "Malformed regular expression.\n");
        return 2;
    }

#endif


    /* Associate signal handler. */
    signal(SIGINT, *done);


    /* Determine the number of processes to use... */
    if (procs < 1) procs = 1;
    srt = stp = procs;

    /* ... and spawn them. */
    if (--procs) {
        i = fork();
        while (i != 0 && --procs) {
            ++p_id;
            i = fork();
        }
        if (i != 0) ++p_id;
    }


    /* Find a sensible starting point for the process's search. */
    srt = len_set / srt * p_id;
    stp = len_set / stp * (p_id + 1);
    if (do_random) {
        FILE *randf = fopen("/dev/urandom", "r");
       
        if (randf == NULL) {
            fprintf(stderr, "Error: no /dev/urandom.\n");
           
            srand((unsigned int)(time(NULL) + srt));
            srt = rand();
        } else {
            fread((void*)&srt, sizeof(int), 1, randf);
            fclose(randf);
        }
       
        srt = (unsigned int)srt % len_set;
        stp = len_set;
    }
    p_id = getpid();


#ifdef SECURE_TRIP
    /* $capcode . $salt */
    memcpy(cap + 8, salt, sizeof(salt));
#endif


    /* Almost ready to begin! */
    fprintf(stderr, "[%d] Starting at %c.\n", p_id, set[srt]);
    gettimeofday(&t_begin, NULL);


    /* Main loop */
#ifndef SECURE_TRIP

    for (c[1] = set + srt; c[1] < set + stp; ++c[1]) { cap[1] = *c[1];
                                                       s[0]   = salt[(int)*c[1]];
    for (c[2] = set; *c[2]; ++c[2]) {                  cap[2] = *c[2];
                                                       s[1]   = salt[(int)*c[2]];
    for (c[0] = set; *c[0]; ++c[0]) {                  cap[0] = *c[0];

#else

    for (c[0] = set + srt; c[0] < set + stp; ++c[0]) { cap[0] = *c[0];
    for (c[1] = set; *c[1]; ++c[1]) {                  cap[1] = *c[1];
    for (c[2] = set; *c[2]; ++c[2]) {                  cap[2] = *c[2];

#endif

    for (c[3] = set; *c[3]; ++c[3]) {                  cap[3] = *c[3];
    for (c[4] = set; *c[4]; ++c[4]) {                  cap[4] = *c[4];
    for (c[5] = set; *c[5]; ++c[5]) {                  cap[5] = *c[5];
    for (c[6] = set; *c[6]; ++c[6]) {                  cap[6] = *c[6];
    for (c[7] = set; *c[7]; ++c[7]) {                  cap[7] = *c[7];

#ifndef SECURE_TRIP

        DES_fcrypt(cap, s, c_ret);
        trip[10] = 0;

#else

        sectrip_bin = SHA1(cap, sizeof(salt) + 8, NULL);

        /* Base64 encoding */
        for (i = 0; i < 4; ++i) {
            trip[i * 4]     = b64[sectrip_bin[i * 3] >> 2];
            trip[i * 4 + 1] = b64[((sectrip_bin[i * 3] & 3) << 4) |
                                   (sectrip_bin[i * 3 + 1] >> 4)];
            trip[i * 4 + 2] = b64[((sectrip_bin[i * 3 + 1] & 15) << 2) |
                                   (sectrip_bin[i * 3 + 2] >> 6)];
            trip[i * 4 + 3] = b64[sectrip_bin[i * 3 + 2] & 63];
        }
        trip[15] = 0;

#endif

#ifndef USE_REGEX
        if (matcher(trip, target) != NULL) {
#else
        if (regexec(&preg, trip, 0, NULL, 0) == 0) {
#endif
            char capcode[9];

            strncpy(capcode, (char*) cap, 8);
            capcode[8] = 0;

            printf("%s -> %s\n", capcode, trip);
        }

        ++checked;

    }}}}}}}} /* FROZENVOID QUALITY */

    done(0);

    return 0;
}

void usage(char *execname)
{
    fprintf(stderr,
            "\033[1mUSAGE\033[0m\n\n"
            "\t%s [ \033[4mOPTIONS\033[0m... ] \033[4mTARGET\033[0m\n\n"
            "\033[1mOPTIONS\033[0m\n\n"
            "\t\033[1m-r\033[0m\n"
            "\t\tBegin search at random position.\n\n"
            "\t\033[1m-p\033[0m \033[4mPROCS\033[0m\n"
            "\t\tNumber of processes to use. (default: 1)\n\n"
            "\t\033[1m-i\033[0m\n"
            "\t\tIgnore case when matching.\n\n"
            "\t\033[1m-h\033[0m\n"
            "\t\tDisplay this message and exit.\n\n",
            execname);
    exit(1);
}

int validate_target(char *target)
{
    /* Ensures the target we're looking for is actually findable. */

    int i, l = strlen(target);

#ifndef SECURE_TRIP
    if (l > 10)
#else
    if (l > 15)
#endif
        return 0;

    for (i = 0; i < l; ++i) {
        if ((target[i] < 'A' || target[i] > 'Z') &&
            (target[i] < 'a' || target[i] > 'z') &&
            (target[i] < '0' || target[i] > '9') &&
#ifndef SECURE_TRIP
            target[i] != '.' &&
#else
            target[i] != '+' &&
#endif
            target[i] != '/') {
            return 0;
        }
    }

    return 1;
}

void done(int _)
{
    /* Signal handler. Performed upon SIGINT or when search is complete. */

    struct timeval t_end;
    int sec, usec;

    gettimeofday(&t_end, NULL);
    sec = t_end.tv_sec - t_begin.tv_sec;
    usec = 1000000 - t_begin.tv_usec + t_end.tv_usec;

    if (usec > 1000000) {
        usec -= 1000000;
        ++sec;
    }

    fprintf(stderr,
            "[%d] %ld tripcodes examined in %d.%03d seconds (%d per second).\n",
            p_id, checked, sec, usec / 1000, (int) checked / sec);
    exit(0);
}
